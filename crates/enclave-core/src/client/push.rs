//! Push registration (`docs/10-push.md` §2).
//!
//! The device seals its platform token (a UnifiedPush endpoint, or an APNs
//! or FCM token) to the push relay's key and hands the sealed token to its
//! own server for the account inbox. The server can't open it; the relay
//! can't tell which inbox or server it belongs to. A fresh sealing on every
//! registration keeps two registrations unlinkable.

use super::Client;
use crate::{CoreError, Result};
use enclave_push_relay::{Platform, RelayPublic, seal_token};
use enclave_rpc::api;
use enclave_wire::{Op, RequestHeader};

/// Setting holding the sealed push token last registered (empty: none).
const KEY_PUSH: &str = "push-sealed";

/// The plain registration, kept to seal afresh for each group mailbox:
/// `relay key ‖ u8 platform ‖ u8 dummies ‖ token`.
const KEY_PUSH_PLAIN: &str = "push-plain";
/// Group mailboxes given a registration: group ‖ mailbox → `u32 day`.
const NS_PUSH_GROUPS: &str = "push-groups";

fn today(now: u64) -> u32 {
    u32::try_from(now / 86_400).unwrap_or(u32::MAX)
}

impl Client {
    /// Ask for wakes when messages reach our inbox (and our groups'
    /// mailboxes), with the relay's key given.
    pub async fn register_push(
        &mut self,
        relay: &RelayPublic,
        platform: Platform,
        token: &[u8],
    ) -> Result<()> {
        self.register_push_with(relay, platform, token, false).await
    }

    /// [`Client::register_push`] with the current key of the push relay in
    /// the foundation's server list.
    pub async fn register_push_listed(
        &mut self,
        platform: Platform,
        token: &[u8],
        dummies: bool,
    ) -> Result<()> {
        let relay = self
            .listed_relay_key(self.now())
            .ok_or(CoreError::NotFound)?;
        self.register_push_with(&relay, platform, token, dummies)
            .await
    }

    /// The listed push relay's key for this epoch (or the newest before it).
    pub fn listed_relay_key(&self, now: u64) -> Option<RelayPublic> {
        let epoch = today(now) / enclave_push_relay::EPOCH_DAYS;
        self.server_list()?
            .push
            .iter()
            .flat_map(|p| p.keys.iter())
            .filter_map(|k| RelayPublic::decode(k).ok())
            .filter(|k| k.epoch <= epoch)
            .max_by_key(|k| k.epoch)
    }

    /// Ask for wakes, with `dummies`: the server also sends dummy wakes
    /// (Poisson, about one an hour), which the app ignores and nobody else
    /// can tell from real ones (for platforms where a wake's timing would
    /// otherwise say when messages come, `docs/10-push.md` §5).
    pub async fn register_push_with(
        &mut self,
        relay: &RelayPublic,
        platform: Platform,
        token: &[u8],
        dummies: bool,
    ) -> Result<()> {
        // Maximum privacy has no push at all (`docs/10-push.md`).
        if self.maximum() {
            return Err(CoreError::MaximumPrivacy);
        }
        let sealed =
            seal_token(relay, platform, token, 0, &mut self.rng).map_err(|_| CoreError::TooLong)?;
        let plain = [
            &relay.encode()[..],
            &[platform as u8, u8::from(dummies)],
            token,
        ]
        .concat();
        let plain_len = u32::try_from(relay.encode().len()).map_err(|_| CoreError::TooLong)?;
        let plain = [&plain_len.to_be_bytes()[..], &plain].concat();
        self.set_setting(KEY_PUSH_PLAIN, &plain)?;
        // Groups get a fresh registration at the next upkeep.
        for (k, _) in self.store.scan(NS_PUSH_GROUPS)? {
            self.store.delete(NS_PUSH_GROUPS, &k)?;
        }
        self.send_push_registration(&sealed).await
    }

    /// Stop wakes: the servers forget the sealed tokens.
    pub async fn unregister_push(&mut self) -> Result<()> {
        self.set_setting(KEY_PUSH_PLAIN, &[])?;
        let now = self.now();
        // Our registrations on today's group mailboxes go too.
        let marked: Vec<Vec<u8>> = self
            .store
            .scan(NS_PUSH_GROUPS)?
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        for k in marked {
            self.store.delete(NS_PUSH_GROUPS, &k)?;
            if let (Ok(gid), Ok(addr)) = (
                <[u8; 32]>::try_from(&k[..32]),
                <[u8; 32]>::try_from(&k[32..]),
            ) {
                let _ = self.push_group_at(&gid, &addr, &[], now).await;
            }
        }
        self.send_push_registration(&[]).await
    }

    fn push_plain(&self) -> Option<(RelayPublic, Platform, bool, Vec<u8>)> {
        let b = self.setting(KEY_PUSH_PLAIN).ok()??;
        let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
        let relay = RelayPublic::decode(b.get(4..4 + n)?).ok()?;
        let platform = match *b.get(4 + n)? {
            1 => Platform::UnifiedPush,
            2 => Platform::Apns,
            3 => Platform::Fcm,
            _ => return None,
        };
        let dummies = *b.get(5 + n)? == 1;
        Some((relay, platform, dummies, b.get(6 + n..)?.to_vec()))
    }

    async fn send_push_registration(&mut self, sealed: &[u8]) -> Result<()> {
        let now = self.now();
        // Kept, so each new weekly address gets it too.
        self.set_setting(KEY_PUSH, sealed)?;
        for week in self.profile.live_weeks(self.inbox_now(now)) {
            self.push_at(week, sealed, now).await?;
        }
        Ok(())
    }

    /// From `sync`: a registration on today's mailbox of each of our groups
    /// (sealed afresh for each, so they can't be linked), under this
    /// device's own id there.
    pub(crate) async fn push_groups(&mut self, now: u64) -> Result<()> {
        let Some((relay, platform, _, token)) = self.push_plain() else {
            return Ok(());
        };
        let d = today(now);
        for (k, v) in self.store.scan(NS_PUSH_GROUPS)? {
            let day = v
                .get(..4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_be_bytes);
            if day.is_none_or(|x| x + 1 < d) {
                self.store.delete(NS_PUSH_GROUPS, &k)?;
            }
        }
        let todo: Vec<([u8; 32], [u8; 32])> = self
            .groups
            .iter()
            .filter(|(_, e)| !e.left)
            .filter_map(|(g, e)| Some((*g, e.group.mailbox(d).ok()?)))
            .collect();
        for (gid, addr) in todo {
            let key = [&gid[..], &addr].concat();
            if self.store.get(NS_PUSH_GROUPS, &key)?.is_some() {
                continue;
            }
            let sealed = seal_token(&relay, platform, &token, 0, &mut self.rng)
                .map_err(|_| CoreError::TooLong)?;
            match self.push_group_at(&gid, &addr, &sealed, now).await {
                Ok(()) => self
                    .store
                    .put(NS_PUSH_GROUPS, &key, &d.to_be_bytes(), &mut self.rng)?,
                Err(e @ CoreError::Net(_)) => return Err(e),
                Err(_) => {}
            }
        }
        Ok(())
    }

    async fn push_group_at(
        &mut self,
        gid: &[u8; 32],
        addr: &[u8; 32],
        sealed: &[u8],
        now: u64,
    ) -> Result<()> {
        let (host, secret) = {
            let e = self.groups.get(gid).ok_or(CoreError::NotFound)?;
            let epoch = e.group.epoch();
            (
                e.group.state.host_for(today(now)),
                e.group.mailbox_secret(epoch, addr)?,
            )
        };
        // This device's id on that mailbox, so it can replace or remove
        // its own registration and no one else's.
        let id: [u8; 32] =
            enclave_crypto::kmac::kmac256(&self.device.id, addr, "enclave/v1/net/push-group-id");
        let payload = api::frame(&[&id[..8], sealed].concat(), &mut self.rng)?;
        let h = RequestHeader {
            op: Op::PushRegister,
            flags: api::FLAG_GROUP,
            mailbox: *addr,
            token: secret,
        };
        self.rpc
            .call_ok(&host, h, &payload, now, &mut self.rng)
            .await?;
        Ok(())
    }

    /// Give the address of `week` the push registration, if there is one.
    pub(crate) async fn reapply_push(&mut self, week: u32, now: u64) -> Result<()> {
        match self.setting(KEY_PUSH)? {
            Some(sealed) if !sealed.is_empty() => self.push_at(week, &sealed, now).await,
            _ => Ok(()),
        }
    }

    async fn push_at(&mut self, week: u32, sealed: &[u8], now: u64) -> Result<()> {
        let payload = api::frame(sealed, &mut self.rng)?;
        let dummies = self.push_plain().is_some_and(|p| p.2);
        let h = RequestHeader {
            op: Op::PushRegister,
            flags: if dummies && !sealed.is_empty() {
                api::FLAG_PUSH_DUMMIES
            } else {
                0
            },
            mailbox: self.profile.addr(week),
            token: self.profile.owner(week),
        };
        let server = self.profile.server;
        self.rpc
            .call_ok(&server, h, &payload, now, &mut self.rng)
            .await?;
        Ok(())
    }
}
