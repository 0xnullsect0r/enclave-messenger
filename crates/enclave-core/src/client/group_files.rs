//! Photos and files in groups (`docs/07-groups.md` §7.6,
//! `docs/08-envelope.md` §9).
//!
//! Exactly as in 1:1 conversations: the file is sealed in chunks padded to
//! a size bucket and uploaded at random chunk IDs to the sender's own
//! server; the group message (`FLAG_RICH` kind 8) carries only the sealed
//! reference (where, the key, the hash) and a caption. Each member
//! downloads every chunk of the bucket when they choose to, so the server
//! learns neither the size nor who in the group looked.

use super::messages::NS_FILES;
use super::polls::Rich;
use super::{Client, Event, GroupMessage};
use crate::content::MAX_TEXT;
use crate::files::{self, Attachment};
use crate::{CoreError, Result};

impl Client {
    /// Send a file to group `gid` (pictures should be re-encoded first).
    pub async fn send_group_file(
        &mut self,
        gid: &[u8; 32],
        name: &str,
        mime: &str,
        data: &[u8],
        caption: &str,
    ) -> Result<GroupMessage> {
        self.send_group_file_message(gid, name, mime, data, caption, false)
            .await
    }

    /// Send a file each member can open once
    /// ([`Client::open_group_view_once`]); we keep no copy.
    pub async fn send_group_view_once(
        &mut self,
        gid: &[u8; 32],
        name: &str,
        mime: &str,
        data: &[u8],
        caption: &str,
    ) -> Result<GroupMessage> {
        self.send_group_file_message(gid, name, mime, data, caption, true)
            .await
    }

    async fn send_group_file_message(
        &mut self,
        gid: &[u8; 32],
        name: &str,
        mime: &str,
        data: &[u8],
        caption: &str,
        view_once: bool,
    ) -> Result<GroupMessage> {
        if caption.len() > MAX_TEXT {
            return Err(CoreError::TooLong);
        }
        let now = self.now();
        self.prepare_group_send(gid, now).await?;
        let host = self.profile.server;
        let (att, chunks) = files::seal_file(data, name, mime, host, &mut self.rng)?;
        for (id, chunk) in &chunks {
            self.put_chunk(&host, *id, chunk, now).await?;
        }
        let id: [u8; 16] = self.rng.array("core/group-msg-id")?;
        let mut m = self.store_group_message(gid, id, None, caption, now)?;
        if view_once {
            m.view_once = true;
        } else {
            // Keep our own copy so we never download what we sent.
            self.store
                .put(NS_FILES, &att.hash[..32], data, &mut self.rng)?;
            m.attachment = Some(att.clone());
        }
        self.put_group_message(gid, &m)?;
        let rich = Rich::Attachment {
            id,
            attachment: att.encode(),
            caption: caption.to_string(),
            view_once,
        };
        self.post_group_rich(gid, &rich).await?;
        m.delivered = true;
        self.put_group_message(gid, &m)?;
        Ok(m)
    }

    /// The file of group message `seq`: cached, or downloaded and verified.
    pub async fn fetch_group_attachment(&mut self, gid: &[u8; 32], seq: u64) -> Result<Vec<u8>> {
        let att = self
            .group_messages(gid)?
            .into_iter()
            .find(|m| m.seq == seq && !m.deleted)
            .and_then(|m| m.attachment)
            .ok_or(CoreError::NotFound)?;
        self.fetch_file(&att).await
    }

    /// Open group message `seq`'s view-once file, once, as
    /// [`Client::open_view_once`] does.
    pub async fn open_group_view_once(&mut self, gid: &[u8; 32], seq: u64) -> Result<Vec<u8>> {
        let mut m = self
            .group_messages(gid)?
            .into_iter()
            .find(|m| m.seq == seq && !m.deleted)
            .ok_or(CoreError::NotFound)?;
        let att = m.once.take().ok_or(CoreError::NotFound)?;
        self.put_group_message(gid, &m)?;
        self.queue_viewed(&super::search::Place::Group(*gid), m.id)?;
        let now = self.now();
        let parts = self.fetch_chunks(&att, now).await?;
        Ok(files::finish(&att, &parts)?)
    }

    /// A group's view-once file opened on another of our devices.
    pub(crate) fn group_viewed_elsewhere(&mut self, gid: &[u8; 32], id: &[u8; 16]) -> Result<bool> {
        let Some(mut m) = self.group_messages(gid)?.into_iter().find(|m| m.id == *id) else {
            return Ok(false);
        };
        if m.once.take().is_none() {
            return Ok(false);
        }
        self.put_group_message(gid, &m)?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_group_attachment(
        &mut self,
        gid: &[u8; 32],
        from: &[u8; 64],
        name: String,
        id: [u8; 16],
        attachment: &[u8],
        caption: &str,
        view_once: bool,
        now: u64,
    ) -> Result<Option<Event>> {
        let Ok(att) = Attachment::decode(attachment) else {
            return Ok(None);
        };
        if self.group_messages(gid)?.iter().any(|m| m.id == id) {
            return Ok(None);
        }
        let mut m = self.store_group_message(gid, id, Some((*from, name)), caption, now)?;
        if view_once {
            m.view_once = true;
            // Ours, from another device: nothing to open here.
            if *from != self.account.root_public.0 {
                m.once = Some(att);
            }
        } else {
            m.attachment = Some(att);
        }
        self.put_group_message(gid, &m)?;
        self.bump_group_unread(gid, from)?;
        Ok(Some(Event::GroupMessage {
            group_id: *gid,
            message: m,
        }))
    }
}
