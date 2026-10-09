//! Blocking (`docs/09-transport.md` §3.2, RT-25).
//!
//! Blocking someone is local and silent: they are not told. Their write
//! tokens still outstanding at our server are revoked and they get no new
//! ones, so they can no longer reach our inbox; anything that still
//! arrives from them (a message already in flight, a new request through
//! the request inbox, their messages in a group we share) is dropped
//! without a trace. Unblocking sends them fresh tokens.

use super::{Client, ContactState};
use crate::content::Content;
use crate::{CoreError, Result};
use enclave_rpc::api::FLAG_REVOKE;

pub(crate) const NS_BLOCKED: &str = "blocked";
/// Tokens sent on unblocking.
const UNBLOCK_TOKENS: usize = 32;

impl Client {
    /// Whether `root` is blocked.
    pub fn is_blocked(&self, root: &[u8; 64]) -> bool {
        matches!(self.store.get(NS_BLOCKED, root), Ok(Some(_)))
    }

    /// Everyone we blocked.
    pub fn blocked(&self) -> Vec<[u8; 64]> {
        self.store
            .scan(NS_BLOCKED)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, _)| k.try_into().ok())
            .collect()
    }

    /// Block `root`: revoke their write tokens and drop anything they send.
    pub async fn block(&mut self, root: &[u8; 64]) -> Result<()> {
        if *root == self.account.root_public.0 {
            return Err(CoreError::NotAccepted);
        }
        let now = self.now();
        self.store.put(NS_BLOCKED, root, &[1], &mut self.rng)?;
        // Revoked at every address they could write to now; the next
        // weekly addresses never get them.
        let tokens = self.issued(root);
        if !tokens.is_empty() {
            for week in self.profile.live_weeks(self.inbox_now(now)) {
                self.register_at(week, &tokens, 0, FLAG_REVOKE, now).await?;
            }
            self.store.delete(crate::persist::NS_ISSUERS, root)?;
        }
        if let Some(c) = self.contacts.get_mut(root) {
            c.unread = 0;
            c.received_since_refill = 0;
            let c = c.clone();
            self.save_contact(&c)?;
        }
        Ok(())
    }

    /// Unblock `root`. A contact we were talking with gets fresh tokens so
    /// they can write again.
    pub async fn unblock(&mut self, root: &[u8; 64]) -> Result<()> {
        if !self.is_blocked(root) {
            return Ok(());
        }
        self.store.delete(NS_BLOCKED, root)?;
        let accepted = self
            .contacts
            .get(root)
            .is_some_and(|c| c.state == ContactState::Accepted);
        if accepted {
            let now = self.now();
            let tokens = self.issue_tokens(root, UNBLOCK_TOKENS, now).await?;
            self.send_content(root, &Content::Tokens(tokens), now)
                .await?;
        }
        Ok(())
    }
}
