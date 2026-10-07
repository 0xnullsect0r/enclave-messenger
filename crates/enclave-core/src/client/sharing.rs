//! Sharing a contact (`docs/16-features.md`, `docs/03-identity.md` §9).
//!
//! A shared contact is the person's contact card (root, server, request
//! inbox, vault-key locator, name) sent inside the session, never their
//! invite secret. The recipient can add them from it like from a scanned
//! code: a message request, trusted on first use, with a reminder to check
//! their security code when they meet. Sharing proves nothing about the
//! person beyond what their card says, and the card's name is only what
//! they typed.

use super::{Client, ContactState, Event, Message, sanitize_name};
use crate::card::ContactCard;
use crate::content::{Content, MAX_CARD, MsgId};
use crate::{CoreError, Result};
use std::collections::HashMap;

fn shared_ns(root: &[u8; 64]) -> String {
    let mut s = String::from("shared/");
    for b in &root[..16] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl Client {
    /// Share `who` (an accepted contact who gave us their card) with `to`.
    pub async fn share_contact(&mut self, to: &[u8; 64], who: &[u8; 64]) -> Result<Message> {
        let target = self.contacts.get(to).ok_or(CoreError::NotFound)?;
        if target.state != ContactState::Accepted || to == who {
            return Err(CoreError::NotAccepted);
        }
        let shared = self.contacts.get(who).ok_or(CoreError::NotFound)?;
        if shared.state != ContactState::Accepted {
            return Err(CoreError::NotAccepted);
        }
        let mut card = shared.card.clone().ok_or(CoreError::NotFound)?;
        card.invite = None;
        let card = card.encode();
        let now = self.now();
        let id: MsgId = self.rng.array("core/msg-id")?;
        let mut m = self.new_message(to, id, true, "", 0, now)?;
        self.keep_shared_card(to, &id, &card)?;
        let content = Content::ContactShare {
            id,
            card: card.clone(),
        };
        let sent = self.send_tracked(to, id, &content, now).await?;
        self.send_self_copy(to, &content, now).await?;
        m.sent = sent;
        self.put_message(to, &m)?;
        Ok(m)
    }

    fn keep_shared_card(&mut self, root: &[u8; 64], id: &MsgId, card: &[u8]) -> Result<()> {
        self.store.put(&shared_ns(root), id, card, &mut self.rng)?;
        Ok(())
    }

    pub(crate) fn forget_shared_contacts(&mut self, root: &[u8; 64]) -> Result<()> {
        let ns = shared_ns(root);
        for (k, _) in self.store.scan(&ns)? {
            self.store.delete(&ns, &k)?;
        }
        Ok(())
    }

    /// Contacts shared in the conversation with `root`, by message id.
    pub fn shared_contacts(&self, root: &[u8; 64]) -> HashMap<MsgId, ContactCard> {
        self.store
            .scan(&shared_ns(root))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v)| Some((k.try_into().ok()?, ContactCard::decode(&v).ok()?)))
            .map(|(k, mut c): (MsgId, ContactCard)| {
                c.name = sanitize_name(&c.name);
                (k, c)
            })
            .collect()
    }

    /// A contact card that arrived in a conversation (theirs or, from our
    /// other device, ours). Returns the stored message if it is new.
    pub(crate) fn on_contact_share(
        &mut self,
        root: &[u8; 64],
        id: MsgId,
        card: &[u8],
        outgoing: bool,
        now: u64,
    ) -> Result<Option<Event>> {
        if card.len() > MAX_CARD || self.find(root, &id).is_ok() {
            return Ok(None);
        }
        let Ok(mut parsed) = ContactCard::decode(card) else {
            return Ok(None);
        };
        parsed.invite = None;
        let mut m = self.new_message(root, id, outgoing, "", 0, now)?;
        self.keep_shared_card(root, &id, &parsed.encode())?;
        if outgoing {
            m.sent = true;
            self.put_message(root, &m)?;
        }
        Ok(Some(Event::Message {
            root: *root,
            message: m,
        }))
    }
}
