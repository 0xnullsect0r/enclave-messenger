//! Message history for a newly linked device (`03-identity.md` §4.4).
//!
//! History does not travel with the link itself. The device holding the root
//! sends it 24 hours after linking, or sooner when both devices confirm: the
//! new device asks ("Ask for history now", an own-sync item) and the person
//! then taps "Send history now" on the device holding the root. Someone who
//! tricks a person into linking their device doesn't get the past at once,
//! and the 7-day "new device" notice has time to be seen.
//!
//! The history is one sealed file (`files::seal_file`). Where the app can
//! serve it on the local network ([`Client::set_history_lan`]), it goes
//! there first (`03-identity.md` §4.3 step 8): the sealed chunks are
//! handed to the window ([`Client::take_history_serve`]), which serves
//! them to the device that holds the one-time token, and the file's
//! reference, the token and the window's addresses go to that device
//! through own-device sync (`HistoryLan`). Its window fetches the chunks
//! and its vault opens them ([`Client::import_history_chunks`]); only
//! ciphertext crosses the network or either window. The receiver says
//! whether that worked (`HistoryDone`); if it didn't, or nothing is heard
//! within [`LAN_WAIT_SECS`], the chunks go to the blob store of our home
//! server and the reference as `Content::History`, as they always do
//! without the local network. Receivers merge it into conversations with
//! contacts they know, skipping messages they already have, and renumber
//! each conversation by time. Disappearing and deleted messages are never
//! sent. Group history is not sent.

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
/// How long an offer on the local network waits for the other device
/// before the history goes through the server instead.
pub const LAN_WAIT_SECS: u64 = 15 * 60;

/// History to serve on the local network: the window serves `chunks`, in
/// order, to whoever presents `token`.
#[derive(Clone, Debug)]
pub struct HistoryServe {
    /// The one-time token.
    pub token: [u8; 16],
    /// The sealed chunks, in order (ciphertext).
    pub chunks: Vec<Vec<u8>>,
}

/// History offered to this device on the local network: fetch `chunks`
/// chunks from one of `addrs` with `token`, then give them to
/// [`Client::import_history_chunks`].
#[derive(Clone, Debug)]
pub struct LanHistory {
    /// The sealed file's reference (its keys stay in the vault).
    pub attachment: Attachment,
    /// The one-time token.
    pub token: [u8; 16],
    /// Where the other device's window serves it.
    pub addrs: Vec<String>,
}

impl LanHistory {
    /// How many chunks to fetch.
    pub fn chunks(&self) -> u32 {
        self.attachment.chunks
    }
}

/// Sealed chunks with their ids.
type Chunks = Vec<([u8; 32], Vec<u8>)>;

/// An offer this device made.
struct Offer {
    device: [u8; 16],
    attachment: Attachment,
    chunks: Chunks,
    token: [u8; 16],
    /// When the other device was told (0: not yet, or to go by the
    /// server now).
    told_at: u64,
}

/// History on the local network: offers made, offers received, and what
/// the window is to serve or stop serving.
#[derive(Default)]
pub(crate) struct LanState {
    enabled: bool,
    offers: Vec<Offer>,
    serve: Vec<HistoryServe>,
    stop: Vec<[u8; 16]>,
    pub(crate) incoming: Vec<LanHistory>,
}

fn offered_key(device: &[u8; 16]) -> Vec<u8> {
    [&b"history-offered/"[..], device].concat()
}

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

    /// The app can serve history on the local network (its window listens
    /// for the other device) and fetch it from there.
    pub fn set_history_lan(&mut self, on: bool) {
        self.history_lan.enabled = on;
    }

    /// History the window should serve now.
    pub fn take_history_serve(&mut self) -> Vec<HistoryServe> {
        std::mem::take(&mut self.history_lan.serve)
    }

    /// Tokens whose history the window can stop serving.
    pub fn take_history_lan_stop(&mut self) -> Vec<[u8; 16]> {
        std::mem::take(&mut self.history_lan.stop)
    }

    /// History offered to this device on the local network, for the window
    /// to fetch.
    pub fn take_lan_history(&mut self) -> Vec<LanHistory> {
        std::mem::take(&mut self.history_lan.incoming)
    }

    /// The window serves the history for `token` at `addrs` (empty: it
    /// can't, so the history goes through the server): tell the device.
    pub fn history_lan_ready(&mut self, token: &[u8; 16], addrs: Vec<String>) -> Result<()> {
        let now = self.now();
        let Some(o) = self
            .history_lan
            .offers
            .iter_mut()
            .find(|o| &o.token == token)
        else {
            return Ok(());
        };
        if addrs.is_empty() {
            o.told_at = 0;
            return Ok(());
        }
        o.told_at = now;
        let item = super::own_sync::SyncItem::HistoryLan {
            device: o.device,
            attachment: o.attachment.encode(),
            token: o.token,
            addrs,
        };
        self.queue_own(item)
    }

    /// The window fetched the chunks of `att` over the local network:
    /// open, merge, and tell the device that sent it.
    pub fn import_history_chunks(&mut self, att: &Attachment, chunks: &[Vec<u8>]) -> Result<usize> {
        let now = self.now();
        let hash: [u8; 16] = att.hash[..16].try_into().unwrap_or_default();
        let opened = (|| -> Result<Zeroizing<Vec<u8>>> {
            if chunks.len() != att.chunks as usize {
                return Err(CoreError::NotFound);
            }
            let parts = chunks
                .iter()
                .enumerate()
                .map(|(i, c)| files::open_chunk(att, i as u32, c))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(Zeroizing::new(files::finish(att, &parts)?))
        })();
        let pkg = match opened {
            Ok(p) => p,
            Err(e) => {
                self.history_lan_failed(att)?;
                return Err(e);
            }
        };
        let n = self.merge_history(&pkg)?;
        self.store.put(
            NS_SETTINGS,
            b"history-received",
            &now.to_be_bytes(),
            &mut self.rng,
        )?;
        self.queue_own(super::own_sync::SyncItem::HistoryDone { hash, ok: true })?;
        Ok(n)
    }

    /// The window couldn't fetch `att` over the local network: the sender
    /// sends it through the server instead.
    pub fn history_lan_failed(&mut self, att: &Attachment) -> Result<()> {
        let hash: [u8; 16] = att.hash[..16].try_into().unwrap_or_default();
        self.queue_own(super::own_sync::SyncItem::HistoryDone { hash, ok: false })
    }

    /// Our device `device` got (or couldn't fetch) the history we offered.
    pub(crate) fn on_history_done(
        &mut self,
        device: &[u8; 16],
        hash: &[u8; 16],
        ok: bool,
    ) -> Result<()> {
        let Some(i) = self
            .history_lan
            .offers
            .iter()
            .position(|o| &o.device == device && &o.attachment.hash[..16] == hash)
        else {
            return Ok(());
        };
        let token = self.history_lan.offers[i].token;
        self.history_lan.stop.push(token);
        if ok {
            self.history_lan.offers.remove(i);
            let now = self.now();
            self.store.put(
                NS_SETTINGS,
                &sent_key(device),
                &now.to_be_bytes(),
                &mut self.rng,
            )?;
        } else {
            // Through the server at the next sync.
            self.history_lan.offers[i].told_at = 0;
        }
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
        // And every offer on the local network still open (sent early, by
        // both devices' choice): it waits, or falls back to the server.
        let mut due = due;
        for o in &self.history_lan.offers {
            if !due.contains(&o.device) {
                due.push(o.device);
            }
        }
        for id in due {
            self.send_history(&id, now).await?;
        }
        Ok(())
    }

    /// The history file: every 1:1 conversation's lasting messages, sealed.
    fn history_file(&mut self) -> Result<(Attachment, Chunks)> {
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
        Ok(files::seal_file(
            &pkg,
            "history",
            "application/x-enclave-history",
            host,
            &mut self.rng,
        )?)
    }

    async fn send_history(&mut self, device: &[u8; 16], now: u64) -> Result<()> {
        // An offer already made: wait for it, or (no answer in time, or
        // the other device couldn't fetch it) go through the server.
        if let Some(i) = self
            .history_lan
            .offers
            .iter()
            .position(|o| &o.device == device)
        {
            let o = &self.history_lan.offers[i];
            if o.told_at != 0 && now < o.told_at + LAN_WAIT_SECS {
                return Ok(());
            }
            let o = self.history_lan.offers.remove(i);
            self.history_lan.stop.push(o.token);
            return self
                .upload_history(device, o.attachment, &o.chunks, now)
                .await;
        }
        let (att, chunks) = self.history_file()?;
        // Offered on the local network first, once; a restart since then
        // (the offer forgotten) goes through the server.
        let offered = matches!(
            self.store.get(NS_SETTINGS, &offered_key(device)),
            Ok(Some(_))
        );
        if self.history_lan.enabled && !offered {
            let token: [u8; 16] = self.rng.array("core/history-lan-token")?;
            self.history_lan.serve.push(HistoryServe {
                token,
                chunks: chunks.iter().map(|(_, c)| c.clone()).collect(),
            });
            self.history_lan.offers.push(Offer {
                device: *device,
                attachment: att,
                chunks,
                token,
                told_at: now,
            });
            self.store.put(
                NS_SETTINGS,
                &offered_key(device),
                &now.to_be_bytes(),
                &mut self.rng,
            )?;
            return Ok(());
        }
        self.upload_history(device, att, &chunks, now).await
    }

    /// Put the chunks in our server's blob store and tell our devices.
    async fn upload_history(
        &mut self,
        device: &[u8; 16],
        att: Attachment,
        chunks: &[([u8; 32], Vec<u8>)],
        now: u64,
    ) -> Result<()> {
        let host = att.host;
        for (id, chunk) in chunks {
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
