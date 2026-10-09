//! Reactions, edits and deletes in groups (`docs/07-groups.md` §7.6,
//! `docs/16-features.md`).
//!
//! Each is a `FLAG_RICH` group message naming its target by the message id
//! every member stored, so it is sealed and MAC-authenticated like any
//! other: outsiders learn nothing, and members can't prove to others who
//! reacted or what was said before an edit. As in 1:1 conversations, edits
//! and deletes are advisory: only the author's own messages, edits within
//! 24 hours, and a member whose app doesn't cooperate may keep the original.

use super::polls::Rich;
use super::search::Place;
use super::{Client, EDIT_WINDOW, Event, GroupMessage};
use crate::content::{MAX_REACTION, MAX_TEXT};
use crate::{CoreError, Result};

impl Client {
    fn group_message_at(&self, gid: &[u8; 32], seq: u64) -> Result<GroupMessage> {
        self.group_messages(gid)?
            .into_iter()
            .find(|m| m.seq == seq)
            .ok_or(CoreError::NotFound)
    }

    fn group_message_by_id(&self, gid: &[u8; 32], id: &[u8; 16]) -> Result<Option<GroupMessage>> {
        Ok(self.group_messages(gid)?.into_iter().find(|m| m.id == *id))
    }

    fn changed(gid: &[u8; 32], seq: u64) -> Option<Event> {
        Some(Event::GroupMessageChanged {
            group_id: *gid,
            seq,
        })
    }

    /// React to message `seq` of group `gid` (an empty `emoji` removes our
    /// reaction).
    pub async fn react_group(&mut self, gid: &[u8; 32], seq: u64, emoji: &str) -> Result<()> {
        if emoji.len() > MAX_REACTION {
            return Err(CoreError::TooLong);
        }
        let mut m = self.group_message_at(gid, seq)?;
        if m.deleted {
            return Err(CoreError::NotAccepted);
        }
        let rich = Rich::React {
            id: m.id,
            emoji: emoji.to_string(),
        };
        self.post_group_rich(gid, &rich).await?;
        set_reaction(&mut m, None, emoji);
        self.put_group_message(gid, &m)
    }

    /// Edit one of our group messages (within 24 hours).
    pub async fn edit_group_message(&mut self, gid: &[u8; 32], seq: u64, text: &str) -> Result<()> {
        let now = self.now();
        let mut m = self.group_message_at(gid, seq)?;
        if m.from.is_some()
            || m.deleted
            || m.poll.is_some()
            || text.trim().is_empty()
            || text.len() > MAX_TEXT
            || now.saturating_sub(m.at) > EDIT_WINDOW
        {
            return Err(CoreError::NotAccepted);
        }
        let rich = Rich::Edit {
            id: m.id,
            text: text.to_string(),
        };
        self.post_group_rich(gid, &rich).await?;
        m.text = text.to_string();
        m.edited = true;
        self.put_group_message(gid, &m)
    }

    /// Delete one of our group messages for everyone.
    pub async fn delete_group_message(&mut self, gid: &[u8; 32], seq: u64) -> Result<()> {
        let mut m = self.group_message_at(gid, seq)?;
        if m.from.is_some() {
            return Err(CoreError::NotAccepted);
        }
        if m.deleted {
            return Ok(());
        }
        self.post_group_rich(gid, &Rich::Delete { id: m.id })
            .await?;
        wipe(&mut m);
        self.put_group_message(gid, &m)?;
        self.apply_pin(&Place::Group(*gid), &m.id, false)?;
        Ok(())
    }

    pub(crate) fn on_group_react(
        &mut self,
        gid: &[u8; 32],
        from: &[u8; 64],
        id: &[u8; 16],
        emoji: String,
    ) -> Result<Option<Event>> {
        let Some(mut m) = self.group_message_by_id(gid, id)? else {
            return Ok(None);
        };
        if m.deleted {
            return Ok(None);
        }
        set_reaction(&mut m, self.group_author(from), &emoji);
        self.put_group_message(gid, &m)?;
        Ok(Self::changed(gid, m.seq))
    }

    pub(crate) fn on_group_edit(
        &mut self,
        gid: &[u8; 32],
        from: &[u8; 64],
        id: &[u8; 16],
        text: String,
        now: u64,
    ) -> Result<Option<Event>> {
        let Some(mut m) = self.group_message_by_id(gid, id)? else {
            return Ok(None);
        };
        if m.from != self.group_author(from)
            || m.deleted
            || m.poll.is_some()
            || text.trim().is_empty()
            || now.saturating_sub(m.at) > EDIT_WINDOW
        {
            return Ok(None);
        }
        m.text = text;
        m.edited = true;
        self.put_group_message(gid, &m)?;
        Ok(Self::changed(gid, m.seq))
    }

    pub(crate) fn on_group_delete(
        &mut self,
        gid: &[u8; 32],
        from: &[u8; 64],
        id: &[u8; 16],
    ) -> Result<Option<Event>> {
        let Some(mut m) = self.group_message_by_id(gid, id)? else {
            return Ok(None);
        };
        if m.from != self.group_author(from) || m.deleted {
            return Ok(None);
        }
        wipe(&mut m);
        self.put_group_message(gid, &m)?;
        self.apply_pin(&Place::Group(*gid), id, false)?;
        Ok(Self::changed(gid, m.seq))
    }
}

/// Replace `who`'s reaction (empty `emoji`: remove it).
fn set_reaction(m: &mut GroupMessage, who: Option<[u8; 64]>, emoji: &str) {
    m.reactions.retain(|r| r.from != who);
    if !emoji.is_empty() {
        m.reactions.push(super::groups::GroupReaction {
            from: who,
            emoji: emoji.to_string(),
        });
    }
}

fn wipe(m: &mut GroupMessage) {
    m.text.clear();
    m.attachment = None;
    m.sticker = None;
    m.reactions.clear();
    m.deleted = true;
    m.edited = false;
}
