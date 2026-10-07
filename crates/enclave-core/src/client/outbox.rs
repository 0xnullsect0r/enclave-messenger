//! Delivery over a mixnet that doesn't answer writes
//! (`docs/09-transport.md` §6.1).
//!
//! Messages go one way: the sender learns they arrived from the
//! recipient's delivery receipt (read receipts imply delivery). Receipts
//! ride in the padding of the next envelope to that contact
//! (`RECEIPTS ‖ u32 len ‖ content ‖ u8 n ‖ ids`, outside the gossip
//! wrapping), so a conversation costs no extra writes; when nothing is
//! going their way within [`RECEIPT_DELAY`], they go on their own as
//! `Content::Delivered`. Until then each outgoing message waits in the outbox with its
//! encoded content. A message with no receipt is sent again, as new
//! envelopes under the same message id (the recipient keeps one copy),
//! after 10 minutes, an hour and six hours; six hours after the third
//! re-send it is shown as not delivered yet, and stays in the conversation.
//! The mixnet already acknowledges every packet to the recipient's ingress,
//! so a re-send covers a server that refused or lost the write, not the
//! mixnet.

use super::{Client, Event};
use crate::content::{Content, MAX_RECEIPTS, MsgId};
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};

const NS_OUTBOX: &str = "outbox";
/// Marks a payload carrying receipts (content kinds are small numbers;
/// gossip uses 0xFE).
const RECEIPTS: u8 = 0xFD;
/// How long receipts wait for a message to ride on before going alone.
pub const RECEIPT_DELAY: u64 = 10;

/// `RECEIPTS ‖ u32 len ‖ content ‖ u8 n ‖ ids`, or `content` as it is.
pub(crate) fn wrap_receipts(content: &[u8], ids: &[MsgId]) -> Vec<u8> {
    if ids.is_empty() {
        return content.to_vec();
    }
    let mut w = Writer::new();
    w.u8(RECEIPTS).bytes(content).u8(ids.len() as u8);
    for id in ids {
        w.fixed(id);
    }
    w.finish()
}

/// Bytes [`wrap_receipts`] adds for `n` receipts.
pub(crate) fn receipts_overhead(n: usize) -> usize {
    if n == 0 { 0 } else { 1 + 4 + 1 + 16 * n }
}

/// Split a payload into its content and the receipts riding on it.
pub(crate) fn unwrap_receipts(b: &[u8]) -> Result<(Vec<u8>, Vec<MsgId>)> {
    if b.first() != Some(&RECEIPTS) {
        return Ok((b.to_vec(), Vec::new()));
    }
    let mut r = Reader::new(&b[1..]);
    let content = r.bytes(b.len())?.to_vec();
    let n = usize::from(r.u8()?);
    if n > MAX_RECEIPTS {
        return Err(enclave_proto::ProtoError::Decode.into());
    }
    let ids = (0..n)
        .map(|_| r.array())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    r.end()?;
    Ok((content, ids))
}
/// Waits before each re-send, and before giving up after the last one.
pub const RESEND_AFTER: [u64; 4] = [600, 3_600, 21_600, 21_600];

struct Entry {
    tries: u8,
    next_at: u64,
    content: Vec<u8>,
}

impl Entry {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .u8(self.tries)
            .u64(self.next_at)
            .bytes(&self.content);
        w.finish()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8().ok()? != 1 {
            return None;
        }
        let e = Self {
            tries: r.u8().ok()?,
            next_at: r.u64().ok()?,
            content: r.bytes(1 << 16).ok()?.to_vec(),
        };
        r.end().ok()?;
        Some(e)
    }
}

fn key(root: &[u8; 64], id: &MsgId) -> Vec<u8> {
    [&root[..], &id[..]].concat()
}

impl Client {
    /// Send message `id` to `root` and keep it until its receipt comes.
    /// `false`: held, because Maximum privacy waits for all three KEMs; it
    /// leaves from the outbox as soon as they protect the session.
    pub(crate) async fn send_tracked(
        &mut self,
        root: &[u8; 64],
        id: MsgId,
        content: &Content,
        now: u64,
    ) -> Result<bool> {
        match self.send_content(root, content, now).await {
            Ok(()) => {}
            Err(CoreError::Finishing) => {
                // Held whole (its write tokens haven't gone anywhere yet),
                // tried at every upkeep without using up a re-send.
                let e = Entry {
                    tries: 0,
                    next_at: now,
                    content: content.encode()?,
                };
                self.store
                    .put(NS_OUTBOX, &key(root, &id), &e.encode(), &mut self.rng)?;
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
        // A re-send carries no write tokens: those went with the first.
        let keep = match content {
            Content::Text {
                text, id, expires, ..
            } => Content::Text {
                tokens: Vec::new(),
                text: text.clone(),
                id: *id,
                expires: *expires,
            },
            c => c.clone(),
        };
        let e = Entry {
            tries: 0,
            next_at: now + RESEND_AFTER[0],
            content: keep.encode()?,
        };
        self.store
            .put(NS_OUTBOX, &key(root, &id), &e.encode(), &mut self.rng)?;
        Ok(true)
    }

    /// Message `id` to `root` arrived (or the conversation is gone).
    pub(crate) fn outbox_done(&mut self, root: &[u8; 64], id: &MsgId) -> Result<()> {
        Ok(self.store.delete(NS_OUTBOX, &key(root, id))?)
    }

    /// Messages waiting for their receipt.
    pub fn outbox_len(&self) -> Result<usize> {
        Ok(self.store.scan(NS_OUTBOX)?.len())
    }

    /// Re-send what is due, and mark what has run out of tries.
    pub(crate) async fn resend_outbox(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for (k, v) in self.store.scan(NS_OUTBOX)? {
            let (Ok(root), Ok(id)) = (
                <[u8; 64]>::try_from(&k[..k.len().min(64)]),
                <MsgId>::try_from(&k[k.len().min(64)..]),
            ) else {
                self.store.delete(NS_OUTBOX, &k)?;
                continue;
            };
            let Some(mut e) = Entry::decode(&v) else {
                self.store.delete(NS_OUTBOX, &k)?;
                continue;
            };
            if now < e.next_at {
                continue;
            }
            if !self.contacts.contains_key(&root) {
                self.store.delete(NS_OUTBOX, &k)?;
                continue;
            }
            if usize::from(e.tries) + 1 >= RESEND_AFTER.len() {
                // Out of tries: say so, and stop.
                self.store.delete(NS_OUTBOX, &k)?;
                if let Ok(mut m) = self.find(&root, &id)
                    && !m.delivered
                {
                    m.stalled = true;
                    self.put_message(&root, &m)?;
                    events.push(Event::MessageChanged { root, seq: m.seq });
                }
                continue;
            }
            let content = Content::decode(&e.content)?;
            match self.send_content(&root, &content, now).await {
                Ok(()) => {
                    // A held message has left at last.
                    if let Ok(mut m) = self.find(&root, &id)
                        && !m.sent
                    {
                        m.sent = true;
                        self.put_message(&root, &m)?;
                        events.push(Event::MessageChanged { root, seq: m.seq });
                    }
                }
                // Still waiting for all three KEMs: not a re-send.
                Err(CoreError::Finishing) => continue,
                // No way through right now: try again next time.
                Err(CoreError::Net(_)) | Err(CoreError::OutOfTokens) => continue,
                // Refused (blocked, the contact is gone…): count the try.
                Err(_) => {}
            }
            e.tries += 1;
            e.next_at = now + RESEND_AFTER[usize::from(e.tries)];
            self.store.put(NS_OUTBOX, &k, &e.encode(), &mut self.rng)?;
        }
        Ok(events)
    }

    /// Remember to acknowledge message `id` from `root`.
    pub(crate) fn note_receipt(&mut self, root: &[u8; 64], id: MsgId) {
        let now = self.now();
        let (_, ids) = self
            .pending_receipts
            .entry(*root)
            .or_insert((now, Vec::new()));
        if !ids.contains(&id) {
            ids.push(id);
        }
    }

    /// Receipts owed to `root` that fit in `room` bytes, taken to ride on
    /// an envelope going there.
    pub(crate) fn take_receipts(&mut self, root: &[u8; 64], room: usize) -> Vec<MsgId> {
        let Some((_, ids)) = self.pending_receipts.get_mut(root) else {
            return Vec::new();
        };
        let mut n = ids.len().min(MAX_RECEIPTS);
        while n > 0 && receipts_overhead(n) > room {
            n -= 1;
        }
        let taken: Vec<MsgId> = ids.drain(..n).collect();
        if ids.is_empty() {
            self.pending_receipts.remove(root);
        }
        taken
    }

    /// Receipts owed to `root`, not yet sent (tests, diagnostics).
    pub fn receipts_owed(&self, root: &[u8; 64]) -> usize {
        self.pending_receipts
            .get(root)
            .map_or(0, |(_, ids)| ids.len())
    }

    /// Send on their own the receipts that found nothing to ride on within
    /// [`RECEIPT_DELAY`]. What can't go now waits for the next sync.
    pub(crate) async fn flush_receipts(&mut self, now: u64) -> Result<()> {
        let due: Vec<[u8; 64]> = self
            .pending_receipts
            .iter()
            .filter(|(_, (since, _))| since.saturating_add(RECEIPT_DELAY) <= now)
            .map(|(r, _)| *r)
            .collect();
        for root in due {
            let Some((since, ids)) = self.pending_receipts.remove(&root) else {
                continue;
            };
            let mut left = Vec::new();
            for chunk in ids.chunks(MAX_RECEIPTS) {
                if !left.is_empty() {
                    left.extend_from_slice(chunk);
                    continue;
                }
                match self
                    .send_content(&root, &Content::Delivered(chunk.to_vec()), now)
                    .await
                {
                    Ok(()) => {}
                    Err(CoreError::Net(_)) | Err(CoreError::OutOfTokens) => {
                        left.extend_from_slice(chunk);
                    }
                    // Not a contact we can answer (blocked, not accepted):
                    // nothing to keep.
                    Err(_) => {}
                }
            }
            if !left.is_empty() {
                self.pending_receipts
                    .entry(root)
                    .or_insert((since, Vec::new()))
                    .1
                    .extend(left);
            }
        }
        Ok(())
    }
}
