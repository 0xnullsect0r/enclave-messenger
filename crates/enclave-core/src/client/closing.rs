//! Contacts who closed their account (`docs/03-identity.md` §8.5).
//!
//! A [`Content::Closed`](crate::content::Content::Closed) from a contact says
//! they deleted their account: the conversation stays, read-only, with
//! "… closed their account", and nothing more is sent to them (their inbox
//! is gone).

use super::{Client, Event};
use crate::Result;

const NS_CLOSED: &str = "closed-contacts";

impl Client {
    /// Whether `root` closed their account.
    pub fn is_closed(&self, root: &[u8; 64]) -> bool {
        self.store.get(NS_CLOSED, root).ok().flatten().is_some()
    }

    /// `root` told us they closed their account.
    pub(crate) fn on_closed(&mut self, root: &[u8; 64]) -> Result<Vec<Event>> {
        if self.is_closed(root) {
            return Ok(Vec::new());
        }
        self.store.put(NS_CLOSED, root, &[], &mut self.rng)?;
        Ok(vec![Event::ContactClosed { root: *root }])
    }

    /// Forget that `root` closed their account (the contact was removed).
    pub(crate) fn forget_closed(&mut self, root: &[u8; 64]) -> Result<()> {
        self.store.delete(NS_CLOSED, root)?;
        Ok(())
    }
}
