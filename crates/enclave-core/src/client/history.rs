//! Message history for a newly linked device (`03-identity.md` §4.4).
//!
//! History does not travel with the link itself. The device holding the root
//! sends it 24 hours after linking, or sooner when both devices confirm: the
//! new device asks ("Ask for history now", an own-sync item) and the person
//! then taps "Send history now" on the device holding the root. Someone who
//! tricks a person into linking their device doesn't get the past at once,
//! and the 7-day "new device" notice has time to be seen.
//!
//! The history is one sealed file (`files::seal_file`) in the blob store of
//! our home server; its reference goes to our devices as `Content::History`
//! over the pairwise sessions. Receivers merge it into conversations with
//! contacts they know, skipping messages they already have, and renumber each
//! conversation by time. Disappearing and deleted messages are never sent.
//! Group history is not sent.

use super::Client;
use crate::content::Content;
use crate::files::{self, Attachment};
use crate::persist::NS_SETTINGS;
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::manifest::Role;
use zeroize::Zeroizing;

/// Delay before history goes to a newly linked device on its own.
pub const HISTORY_DELAY_SECS: u64 = 24 * 3600;

fn sent_key(device: &[u8; 16]) -> Vec<u8> {
    [&b"history-sent/"[..], device].concat()
}

fn asked_key(device: &[u8; 16]) -> Vec<u8> {
    [&b"history-asked/"[..], device].concat()
}

impl Client {
    /// Send message history to our linked device `device` now, instead of
    /// waiting for the 24-hour delay. Only the device holding the root sends
    /// history, and only once that device has asked for it
    /// ([`Client::ask_history_now`]): both devices confirm.
    pub async fn send_history_now(&mut self, device: &[u8; 16]) -> Result<()> {
        if !self.can_link() || *device == self.device.id || self.manifest.device(device).is_none() {
            return Err(CoreError::NotFound);
        }
        if !self.history_asked(device) {
            return Err(CoreError::NotAccepted);
        }
        self.send_history(device, self.now()).await
    }

    /// On a linked device: ask the device holding the root for message
    /// history now; it goes once the person also confirms there.
    pub async fn ask_history_now(&mut self) -> Result<()> {
        if self.can_link() {
            return Err(CoreError::NotAccepted);
        }
        self.send_own_now(super::own_sync::SyncItem::HistoryAsk)
            .await?;
        let now = self.now();
        let key = asked_key(&self.device.id);
        self.store
            .put(NS_SETTINGS, &key, &now.to_be_bytes(), &mut self.rng)?;
        Ok(())
    }

    /// Whether linked device `device` asked for history (on the device
    /// holding the root), or this device did (on a linked one).
    pub fn history_asked(&self, device: &[u8; 16]) -> bool {
        matches!(self.store.get(NS_SETTINGS, &asked_key(device)), Ok(Some(_)))
    }

    /// Whether message history from the device holding the root has
    /// arrived here.
    pub fn history_received(&self) -> bool {
        matches!(
            self.store.get(NS_SETTINGS, b"history-received"),
            Ok(Some(_))
        )
    }

    /// Our device `device` asked for history (`own_sync.rs`).
    pub(crate) fn on_history_ask(&mut self, device: &[u8; 16]) -> Result<()> {
        let now = self.now();
        self.store.put(
            NS_SETTINGS,
            &asked_key(device),
            &now.to_be_bytes(),
            &mut self.rng,
        )?;
        Ok(())
    }

    /// Whether history has been sent to `device`.
    pub fn history_sent(&self, device: &[u8; 16]) -> bool {
        matches!(self.store.get(NS_SETTINGS, &sent_key(device)), Ok(Some(_)))
    }

    /// Send history to linked devices whose delay has passed.
    pub(crate) async fn send_due_history(&mut self, now: u64) -> Result<()> {
        if !self.can_link() {
            return Ok(());
        }
        let due: Vec<[u8; 16]> = self
            .manifest
            .devices
            .iter()
            .filter(|d| {
                d.id != self.device.id
                    && d.role == Role::Linked
                    && d.added_at + HISTORY_DELAY_SECS <= now
            })
            .map(|d| d.id)
            .filter(|id| !self.history_sent(id))
            .collect();
        for id in due {
            self.send_history(&id, now).await?;
        }
        Ok(())
    }

    async fn send_history(&mut self, device: &[u8; 16], now: u64) -> Result<()> {
        let mut w = Writer::new();
        w.u8(1);
        let roots: Vec<[u8; 64]> = self.contacts.keys().copied().collect();
        w.u32(roots.len() as u32);
        for root in &roots {
            let msgs: Vec<Vec<u8>> = self
                .messages(root)?
                .into_iter()
                .filter(|m| m.expires_secs == 0 && !m.deleted)
                .map(|m| m.encode())
                .collect();
            w.fixed(root).u32(msgs.len() as u32);
            for m in &msgs {
                w.bytes(m);
            }
        }
        let pkg = Zeroizing::new(w.finish());
        if pkg.len() > files::MAX_ATTACHMENT {
            return Err(CoreError::TooLong);
        }
        let host = self.profile.server;
        let (att, chunks) = files::seal_file(
            &pkg,
            "history",
            "application/x-enclave-history",
            host,
            &mut self.rng,
        )?;
        for (id, chunk) in &chunks {
            self.put_chunk(&host, *id, chunk, now).await?;
        }
        self.send_own(&Content::History(att.encode()).encode()?, now)
            .await?;
        self.store.put(
            NS_SETTINGS,
            &sent_key(device),
            &now.to_be_bytes(),
            &mut self.rng,
        )?;
        Ok(())
    }

    /// Fetch and merge history files announced during this sync.
    pub(crate) async fn import_pending_history(&mut self, now: u64) -> Result<usize> {
        let pending = std::mem::take(&mut self.pending_history);
        let mut imported = 0;
        for att in pending {
            let mut parts = Vec::with_capacity(att.chunks as usize);
            for i in 0..att.chunks {
                let chunk = match self
                    .rpc
                    .blob_get(&att.host, att.chunk_id(i), now, &mut self.rng)
                    .await
                {
                    Ok(c) => c,
                    Err(e @ CoreError::Net(_)) => {
                        self.pending_history.push(att);
                        return Err(e);
                    }
                    Err(_) => break,
                };
                parts.push(files::open_chunk(&att, i, &chunk)?);
            }
            if parts.len() != att.chunks as usize {
                continue;
            }
            let pkg = Zeroizing::new(files::finish(&att, &parts)?);
            imported += self.merge_history(&pkg)?;
            self.store.put(
                NS_SETTINGS,
                b"history-received",
                &now.to_be_bytes(),
                &mut self.rng,
            )?;
        }
        Ok(imported)
    }

    fn merge_history(&mut self, pkg: &[u8]) -> Result<usize> {
        let mut r = Reader::new(pkg);
        if r.u8()? != 1 {
            return Err(enclave_proto::ProtoError::Decode.into());
        }
        let mut imported = 0;
        let n = r.u32()?;
        for _ in 0..n {
            let root: [u8; 64] = r.array()?;
            let count = r.u32()?;
            let mut incoming = Vec::new();
            for _ in 0..count {
                let m = super::messages::Message::decode(r.bytes(1 << 20)?)?;
                incoming.push(m);
            }
            if self.contacts.contains_key(&root) {
                imported += self.merge_conversation(&root, incoming)?;
            }
        }
        r.end()?;
        Ok(imported)
    }

    /// Add messages we don't have and renumber the conversation by time.
    fn merge_conversation(
        &mut self,
        root: &[u8; 64],
        incoming: Vec<super::messages::Message>,
    ) -> Result<usize> {
        let mut all = self.messages(root)?;
        let before = all.len();
        for m in incoming {
            if m.expires_secs == 0 && !all.iter().any(|x| x.id == m.id) {
                all.push(m);
            }
        }
        let added = all.len() - before;
        if added == 0 {
            return Ok(0);
        }
        all.sort_by_key(|m| (m.at, m.seq));
        // Old positions may have gaps; clear them all before renumbering.
        let ns = crate::persist::msg_ns(root);
        for (k, _) in self.store.scan(&ns)? {
            self.store.delete(&ns, &k)?;
        }
        for (i, m) in all.iter_mut().enumerate() {
            m.seq = i as u64;
            self.put_message(root, m)?;
        }
        if let Some(c) = self.contacts.get_mut(root) {
            c.next_seq = all.len() as u64;
            let c = c.clone();
            self.save_contact(&c)?;
        }
        Ok(added)
    }
}

/// Parse a `Content::History` reference.
pub(crate) fn history_ref(b: &[u8]) -> Option<Attachment> {
    Attachment::decode(b).ok()
}
