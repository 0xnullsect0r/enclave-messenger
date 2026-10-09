//! The McEliece braid for people met through a group (`docs/04-eqxdh.md`
//! §7).
//!
//! A session with someone we know only from a group starts on two KEMs:
//! fetching their 1.36 MB vault key for every member of every group would
//! cost too much at once. The contact is remembered as **due**, and each
//! upkeep round fetches one due contact's vault key, checks it against
//! their manifest, and schedules the braid on every session with them that
//! lacks it; the next PQ step carries it, and both sides then hold all
//! three KEMs. On a metered network (`Client::set_metered`) the fetch waits,
//! but never past [`BRAID_DEADLINE_SECS`] after the session started.
//! Maximum privacy fetches the key before the first message instead.

use super::Client;
use crate::{CoreError, Result};

const NS_BRAID: &str = "braid-due";

/// A two-KEM session gets its third KEM within this long, metered network
/// or not.
pub const BRAID_DEADLINE_SECS: u64 = 7 * 86_400;

impl Client {
    /// Whether the network is metered (the platform says so); vault keys
    /// for braids then wait until [`BRAID_DEADLINE_SECS`].
    pub fn set_metered(&mut self, metered: bool) {
        self.metered = metered;
    }

    /// Remember that the sessions with `root` need the braid.
    pub(crate) fn braid_due(&mut self, root: &[u8; 64], now: u64) -> Result<()> {
        if self.store.get(NS_BRAID, root)?.is_none() {
            self.store
                .put(NS_BRAID, root, &now.to_be_bytes(), &mut self.rng)?;
        }
        Ok(())
    }

    /// Whether `root`'s sessions are waiting for their vault key.
    pub fn braid_pending(&self, root: &[u8; 64]) -> bool {
        matches!(self.store.get(NS_BRAID, root), Ok(Some(_)))
    }

    /// One upkeep step: fetch a due contact's vault key and schedule the
    /// braid. Network errors end the round; anything else (a contact gone,
    /// a key that doesn't match) drops the entry.
    pub(crate) async fn upgrade_braids(&mut self, now: u64) -> Result<()> {
        for (root, v) in self.store.scan(NS_BRAID)? {
            let Ok(root): std::result::Result<[u8; 64], _> = root.as_slice().try_into() else {
                self.store.delete(NS_BRAID, &root)?;
                continue;
            };
            let since = v.as_slice().try_into().map_or(0, u64::from_be_bytes);
            let missing = self
                .sessions
                .iter()
                .any(|((r, _), s)| *r == root && !s.three_kem());
            let card = self
                .contacts
                .get(&root)
                .and_then(|c| c.card.clone().map(|card| (card, c.manifest.clone())));
            let Some((card, manifest)) = card.filter(|_| missing) else {
                self.store.delete(NS_BRAID, &root)?;
                continue;
            };
            if self.metered && now < since.saturating_add(BRAID_DEADLINE_SECS) {
                continue;
            }
            let vault = match self.fetch_vault(&card, &manifest, now).await {
                Ok(v) => v,
                Err(e @ CoreError::Net(_)) => return Err(e),
                Err(_) => {
                    self.store.delete(NS_BRAID, &root)?;
                    continue;
                }
            };
            let keys: Vec<_> = self
                .sessions
                .iter()
                .filter(|((r, _), s)| *r == root && !s.three_kem())
                .map(|(k, _)| *k)
                .collect();
            for k in keys {
                if let Some(s) = self.sessions.get_mut(&k) {
                    s.schedule_braid(vault.clone());
                    let s = s.clone();
                    self.save_session(&k.0, &k.1, &s)?;
                }
            }
            self.store.delete(NS_BRAID, &root)?;
            // The braid rides the next PQ step; ask for one now, since
            // people who share only a group may not write to each other.
            if let Err(e @ CoreError::Net(_)) = self
                .send_content(&root, &crate::content::Content::PqStep { reply: true }, now)
                .await
            {
                return Err(e);
            }
            // One 1.36 MB fetch a round.
            return Ok(());
        }
        Ok(())
    }
}
