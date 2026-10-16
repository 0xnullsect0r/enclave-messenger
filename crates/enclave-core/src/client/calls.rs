//! Call signalling between contacts (`docs/11-calls.md` §2).
//!
//! Offers, answers and the rest (`enclave_calls::message::CallMessage`) are
//! ordinary ratchet messages to an accepted contact, so they get the
//! conversation's protection and travel over the mixnet like any other.
//! Incoming ones come out of a sync as [`Event::Call`](super::Event::Call);
//! the vault runs the call. Nothing about a call is kept here but the line
//! the conversation shows afterwards ([`Client::add_call_line`]).

use super::{Client, ContactState};
use crate::content::Content;
use crate::{CoreError, Result};

impl Client {
    /// Send call signalling to an accepted contact.
    pub async fn send_call(&mut self, root: &[u8; 64], message: &[u8]) -> Result<()> {
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != ContactState::Accepted {
            return Err(CoreError::NotAccepted);
        }
        self.require_not_held()?;
        self.require_current()?;
        let now = self.now();
        self.send_content(root, &Content::Call(message.to_vec()), now)
            .await
    }

    /// The id that binds a call's keys to this conversation: the same on
    /// both sides.
    pub fn call_conversation(&self, root: &[u8; 64]) -> [u8; 32] {
        enclave_proto::otr::conv_id(&self.account.root_public.0, root)
    }

    /// Write a call's line into the conversation ("Missed call", "Call,
    /// 3:02"): this device's own record, sent to no one.
    pub fn add_call_line(
        &mut self,
        root: &[u8; 64],
        outgoing: bool,
        text: &str,
    ) -> Result<super::Message> {
        let id = self.rng.array("core/msg-id")?;
        let now = self.now();
        let mut m = self.new_message(root, id, outgoing, text, 0, now)?;
        m.notice = true;
        m.signed = None;
        m.evidence = None;
        m.late = false;
        m.read = true;
        m.sent = true;
        self.put_message(root, &m)?;
        Ok(m)
    }
}
