//! The media gallery across every conversation (`docs/16-features.md` §4):
//! a local list over the sealed store, nothing sent or asked for.

use super::Client;
use super::search::Place;
use crate::Result;
use crate::files::Attachment;

/// A file in one of our conversations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GalleryItem {
    /// Where it was sent.
    pub place: Place,
    /// The conversation's name.
    pub name: String,
    /// The message's position in it.
    pub seq: u64,
    /// The file.
    pub attachment: Attachment,
    /// When it was sent or received.
    pub at: u64,
    /// We sent it.
    pub outgoing: bool,
}

impl Client {
    /// Every file in every conversation, newest first: not deleted, not a
    /// sticker (its attachment is the pack), and never a view-once file
    /// (held apart, `Message::once`).
    pub fn all_files(&self) -> Result<Vec<GalleryItem>> {
        let mut out = Vec::new();
        for c in self.contacts() {
            for m in self.messages(&c.root)? {
                if m.deleted || m.sticker.is_some() {
                    continue;
                }
                if let Some(a) = m.attachment {
                    out.push(GalleryItem {
                        place: Place::Contact(c.root),
                        name: c.name.clone(),
                        seq: m.seq,
                        attachment: a,
                        at: m.at,
                        outgoing: m.outgoing,
                    });
                }
            }
        }
        for g in self.groups() {
            for m in self.group_messages(&g.id)? {
                if m.deleted || m.sticker.is_some() {
                    continue;
                }
                if let Some(a) = m.attachment {
                    out.push(GalleryItem {
                        place: Place::Group(g.id),
                        name: g.name.clone(),
                        seq: m.seq,
                        attachment: a,
                        at: m.at,
                        outgoing: m.from.is_none(),
                    });
                }
            }
        }
        out.sort_by(|a, b| b.at.cmp(&a.at).then(b.seq.cmp(&a.seq)));
        Ok(out)
    }
}
