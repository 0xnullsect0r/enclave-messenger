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

impl Client {
    /// Ask for wakes when messages reach our inbox.
    pub async fn register_push(
        &mut self,
        relay: &RelayPublic,
        platform: Platform,
        token: &[u8],
    ) -> Result<()> {
        // Maximum privacy has no push at all (`docs/10-push.md`).
        if self.maximum() {
            return Err(CoreError::MaximumPrivacy);
        }
        let sealed =
            seal_token(relay, platform, token, 0, &mut self.rng).map_err(|_| CoreError::TooLong)?;
        self.send_push_registration(&sealed).await
    }

    /// Stop wakes: the server forgets the sealed token.
    pub async fn unregister_push(&mut self) -> Result<()> {
        self.send_push_registration(&[]).await
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

    /// Give the address of `week` the push registration, if there is one.
    pub(crate) async fn reapply_push(&mut self, week: u32, now: u64) -> Result<()> {
        match self.setting(KEY_PUSH)? {
            Some(sealed) if !sealed.is_empty() => self.push_at(week, &sealed, now).await,
            _ => Ok(()),
        }
    }

    async fn push_at(&mut self, week: u32, sealed: &[u8], now: u64) -> Result<()> {
        let payload = api::frame(sealed, &mut self.rng)?;
        let h = RequestHeader {
            op: Op::PushRegister,
            flags: 0,
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
