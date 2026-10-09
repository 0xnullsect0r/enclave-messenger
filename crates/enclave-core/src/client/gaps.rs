//! Gaps, late messages and held units (`docs/05-ratchet.md` §11, RT-24).
//!
//! - **Gap notice.** When a contact's message keys were skipped (later
//!   messages arrived first) and the missing one hasn't come for
//!   [`super::GAP_SECS`], the conversation says "A message from … may not
//!   have arrived" ([`Client::gap`], `Event::Gap` once). The notice goes when
//!   the message arrives, and after a day (the sender's outbox has re-sent
//!   it as a new message, or given up and said so on its side).
//! - **Delivered late.** A message whose key was skipped more than
//!   [`super::GAP_SECS`] before it arrived is marked late
//!   (`Message::late`).
//! - **Held units.** An envelope from the account inbox that no session
//!   opens yet (its sender's greeting not processed yet, a race between
//!   devices) is kept, at most [`HELD_MAX`] for [`HELD_SECS`], and tried
//!   again after each sync's inboxes instead of being lost.

use super::{Client, Event, GAP_SECS};
use crate::{CoreError, Result};
use enclave_proto::ProtoError;

const NS_GAP_SHOWN: &str = "gap-shown";
const NS_HELD: &str = "held-units";

/// Most envelopes held for a later try.
pub const HELD_MAX: usize = 64;
/// How long an envelope is held.
pub const HELD_SECS: u64 = 7 * 86_400;
/// A gap is pointed out for at most this long.
const GAP_SHOWN_SECS: u64 = 86_400;

impl Client {
    /// When the oldest message from `root` that seems missing was first
    /// noticed missing.
    fn missing_since(&self, root: &[u8; 64]) -> Option<u64> {
        self.sessions
            .iter()
            .filter(|((r, _), _)| r == root)
            .filter_map(|(_, s)| s.oldest_skipped())
            .min()
    }

    /// Whether a message from `root` may not have arrived: later ones did,
    /// over a minute ago (and less than a day ago).
    pub fn gap(&self, root: &[u8; 64]) -> bool {
        let now = self.now();
        self.missing_since(root).is_some_and(|at| {
            let age = now.saturating_sub(at);
            age > GAP_SECS && age < GAP_SHOWN_SECS
        })
    }

    /// Gaps newly found since the last sync, each reported once.
    pub(crate) fn check_gaps(&mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let roots: Vec<[u8; 64]> = self.contacts.keys().copied().collect();
        for root in roots {
            if !self.gap(&root) {
                continue;
            }
            let since = self.missing_since(&root).unwrap_or(0);
            let shown = self
                .store
                .get(NS_GAP_SHOWN, &root)?
                .and_then(|b| b.try_into().ok())
                .map(u64::from_be_bytes);
            if shown == Some(since) {
                continue;
            }
            self.store
                .put(NS_GAP_SHOWN, &root, &since.to_be_bytes(), &mut self.rng)?;
            events.push(Event::Gap { root });
        }
        Ok(events)
    }

    /// Keep an envelope no session opens yet, for a later try.
    pub(crate) fn hold_unit(&mut self, env: &[u8], now: u64) -> Result<()> {
        if self.store.scan(NS_HELD)?.len() >= HELD_MAX {
            return Ok(());
        }
        let id: [u8; 16] = self.rng.array("core/held-id")?;
        let v = [&now.to_be_bytes()[..], env].concat();
        self.store.put(NS_HELD, &id, &v, &mut self.rng)?;
        Ok(())
    }

    /// Try the held envelopes again (after a sync's inboxes, which may have
    /// brought the sessions they need).
    pub(crate) fn retry_held(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for (k, v) in self.store.scan(NS_HELD)? {
            let at = v
                .get(..8)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u64::from_be_bytes);
            match self.handle_direct_from(&v[8.min(v.len())..], None, now) {
                Ok(mut e) => {
                    events.append(&mut e);
                    self.store.delete(NS_HELD, &k)?;
                }
                Err(CoreError::Proto(ProtoError::NoSession)) if at + HELD_SECS > now => {}
                Err(_) => self.store.delete(NS_HELD, &k)?,
            }
        }
        Ok(events)
    }
}
