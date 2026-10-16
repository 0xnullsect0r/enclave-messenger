//! Note to self (`docs/16-features.md`, `docs/06-multidevice.md` §4).
//!
//! Notes are messages to nobody: kept in the sealed store under our own
//! root, and copied to our other devices over the self-copy path, so every
//! linked device has them. Nothing reaches anyone else's inbox.

use super::Client;
use super::messages::wipe;
use crate::content::{Content, MAX_TEXT, MsgId};
use crate::{CoreError, Message, Result};

const NOTE_SEQ: &str = "note-seq";

impl Client {
    /// Our notes, oldest first.
    pub fn notes(&self) -> Result<Vec<Message>> {
        let own = self.account.root_public.0;
        self.messages(&own)
    }

    fn next_note_seq(&mut self) -> Result<u64> {
        let seq = self
            .setting(NOTE_SEQ)?
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        self.set_setting(NOTE_SEQ, &(seq + 1).to_be_bytes())?;
        Ok(seq)
    }

    fn store_note(&mut self, id: MsgId, text: &str, now: u64) -> Result<Message> {
        let own = self.account.root_public.0;
        let seq = self.next_note_seq()?;
        let mut m = Message::new(seq, id, true, now, text.to_string());
        m.sent = true;
        m.delivered = true;
        m.read = true;
        self.put_message(&own, &m)?;
        Ok(m)
    }

    /// Write a note (copied to our other devices).
    pub async fn send_note(&mut self, text: &str) -> Result<Message> {
        if text.trim().is_empty() || text.len() > MAX_TEXT {
            return Err(CoreError::TooLong);
        }
        let now = self.now();
        let id: MsgId = self.rng.array("core/msg-id")?;
        let m = self.store_note(id, text, now)?;
        let own = self.account.root_public.0;
        let content = Content::Text {
            tokens: Vec::new(),
            text: text.to_string(),
            id,
            expires: 0,
            reply: None,
            forwarded: false,
            link: None,
        };
        self.send_self_copy(&own, &content, now).await?;
        Ok(m)
    }

    /// Delete a note, here and on our other devices.
    pub async fn delete_note(&mut self, seq: u64) -> Result<()> {
        let own = self.account.root_public.0;
        let mut m = self.get_message(&own, seq)?;
        if m.deleted {
            return Ok(());
        }
        let now = self.now();
        self.send_self_copy(&own, &Content::Delete { target: m.id }, now)
            .await?;
        wipe(&mut m);
        self.put_message(&own, &m)
    }

    /// A note from another of our devices. Returns whether anything changed.
    pub(crate) fn on_note_copy(&mut self, content: Content, now: u64) -> Result<bool> {
        let own = self.account.root_public.0;
        match content {
            Content::Text { text, id, .. } => {
                if self.find(&own, &id).is_ok() || text.len() > MAX_TEXT {
                    return Ok(false);
                }
                self.store_note(id, &text, now)?;
                Ok(true)
            }
            Content::Delete { target } => {
                let Ok(mut m) = self.find(&own, &target) else {
                    return Ok(false);
                };
                wipe(&mut m);
                self.put_message(&own, &m)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
