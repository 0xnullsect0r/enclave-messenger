//! Stories (`docs/16-features.md`, "Stories"): a few words or a picture
//! that the poster's accepted contacts can see for 24 hours.
//!
//! A story goes to each person in its audience inside their own session,
//! as [`Content::Story`], like any message: never in a group. A group would
//! show every viewer who else is in the audience and hand them each other's
//! cards; one-by-one delivery shows each viewer only the poster. Upkeep
//! sends a few each round ([`PER_ROUND`]), so a story doesn't burst out to
//! everyone at once, and its age goes with it so the receiver's 24 hours
//! end when the poster's do. A picture is a sealed file on the poster's
//! server (`08-envelope.md` §9), fetched by a viewer when they open the
//! story. The audience is every accepted contact but those the poster hides
//! stories from (kept on this device). Our other devices get our stories as
//! self-copies. Viewing sends nothing back. Deleting one tells those it
//! reached; a story is gone everywhere after 24 hours.

use super::Client;
use super::messages::NS_FILES;
use crate::content::{Content, MAX_ATTACHMENT_REF};
use crate::files::{self, Attachment};
use crate::{CoreError, Event, Result};
use enclave_proto::codec::{Reader, Writer};

/// How long a story is shown.
pub const STORY_SECS: u64 = 86_400;
/// Longest story text, in bytes.
pub const MAX_STORY_TEXT: usize = 700;
/// Most stories kept from one contact (older ones go first).
pub const MAX_STORIES_PER_CONTACT: usize = 30;
/// Where stories are kept: `from ‖ id` (our own root for ours).
pub(crate) const NS_STORIES: &str = "stories";
/// The contacts hidden from our stories (first 16 bytes of each root),
/// this device only.
const HIDDEN: &str = "story-hidden";
/// Audience members a story goes to per upkeep round.
const PER_ROUND: usize = 8;

/// A story: ours or a contact's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Story {
    /// Who posted it (`None`: we did).
    pub from: Option<[u8; 64]>,
    /// Its id.
    pub id: [u8; 16],
    /// Its words (may be empty with a picture).
    pub text: String,
    /// Its picture or clip, sealed on the poster's server.
    pub attachment: Option<Attachment>,
    /// When it was posted, by our clock.
    pub at: u64,
    /// We opened it.
    pub viewed: bool,
    /// Ours: who it still has to go to (with `gone`, who still has to hear
    /// it was deleted).
    left: Vec<[u8; 64]>,
    /// Ours: who it went to.
    sent: Vec<[u8; 64]>,
    /// Ours, deleted: kept only to tell those it reached.
    gone: bool,
}

impl Story {
    /// When it stops being shown.
    pub fn expires_at(&self) -> u64 {
        self.at + STORY_SECS
    }

    /// How many people it reached (ours).
    pub fn reached(&self) -> usize {
        self.sent.len()
    }

    /// How many it still has to go to (ours).
    pub fn waiting(&self) -> usize {
        if self.gone { 0 } else { self.left.len() }
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1);
        match &self.from {
            Some(r) => w.u8(1).fixed(r),
            None => w.u8(0),
        };
        w.fixed(&self.id)
            .bytes(self.text.as_bytes())
            .bytes(
                &self
                    .attachment
                    .as_ref()
                    .map(Attachment::encode)
                    .unwrap_or_default(),
            )
            .u64(self.at)
            .u8(u8::from(self.viewed) | (u8::from(self.gone) << 1));
        for list in [&self.left, &self.sent] {
            w.u32(list.len() as u32);
            for r in list {
                w.fixed(r);
            }
        }
        w.finish()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8().ok()? != 1 {
            return None;
        }
        let from = match r.u8().ok()? {
            0 => None,
            1 => Some(r.array().ok()?),
            _ => return None,
        };
        let id = r.array().ok()?;
        let text = String::from_utf8(r.bytes(MAX_STORY_TEXT).ok()?.to_vec()).ok()?;
        let a = r.bytes(MAX_ATTACHMENT_REF).ok()?;
        let attachment = if a.is_empty() {
            None
        } else {
            Some(Attachment::decode(a).ok()?)
        };
        let at = r.u64().ok()?;
        let flags = r.u8().ok()?;
        let mut lists = [Vec::new(), Vec::new()];
        for list in &mut lists {
            let n = r.u32().ok()? as usize;
            if n > 100_000 {
                return None;
            }
            for _ in 0..n {
                list.push(r.array().ok()?);
            }
        }
        r.end().ok()?;
        let [left, sent] = lists;
        Some(Story {
            from,
            id,
            text,
            attachment,
            at,
            viewed: flags & 1 != 0,
            left,
            sent,
            gone: flags & 2 != 0,
        })
    }

    fn content(&self, now: u64) -> Content {
        Content::Story {
            id: self.id,
            text: if self.gone {
                String::new()
            } else {
                self.text.clone()
            },
            attachment: if self.gone {
                Vec::new()
            } else {
                self.attachment
                    .as_ref()
                    .map(Attachment::encode)
                    .unwrap_or_default()
            },
            age: u32::try_from(now.saturating_sub(self.at)).unwrap_or(u32::MAX),
            gone: self.gone,
        }
    }
}

fn key(from: &[u8; 64], id: &[u8; 16]) -> Vec<u8> {
    [&from[..], &id[..]].concat()
}

/// A picture for a story (file name, MIME type, bytes), already
/// re-encoded (the app does it in mediad).
pub struct StoryPicture<'a> {
    /// File name.
    pub name: &'a str,
    /// MIME type.
    pub mime: &'a str,
    /// The file.
    pub bytes: &'a [u8],
}

impl Client {
    fn me(&self) -> [u8; 64] {
        self.account.root_public.0
    }

    fn put_story(&mut self, s: &Story) -> Result<()> {
        let from = s.from.unwrap_or(self.me());
        self.store
            .put(NS_STORIES, &key(&from, &s.id), &s.encode(), &mut self.rng)?;
        Ok(())
    }

    fn all_stories(&self) -> Vec<Story> {
        self.store
            .scan(NS_STORIES)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, v)| Story::decode(&v))
            .collect()
    }

    /// The stories showing now, newest first: ours and our accepted
    /// contacts'.
    pub fn stories(&self) -> Vec<Story> {
        let now = self.now();
        let mut out: Vec<Story> = self
            .all_stories()
            .into_iter()
            .filter(|s| !s.gone && s.expires_at() > now)
            .filter(|s| {
                s.from.is_none_or(|r| {
                    self.contact(&r)
                        .is_some_and(|c| c.state == super::ContactState::Accepted)
                        && !self.is_blocked(&r)
                })
            })
            .collect();
        out.sort_by_key(|s| std::cmp::Reverse(s.at));
        out
    }

    /// The contacts our stories are hidden from.
    pub fn story_hidden(&self) -> Vec<[u8; 16]> {
        self.setting(HIDDEN)
            .ok()
            .flatten()
            .map(|b| {
                b.chunks_exact(16)
                    .filter_map(|c| <[u8; 16]>::try_from(c).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Hide our stories from `root`, or show them to them again (from the
    /// next story on).
    pub fn set_story_hidden(&mut self, root: &[u8; 64], hidden: bool) -> Result<()> {
        let mut id = [0u8; 16];
        id.copy_from_slice(&root[..16]);
        let mut list = self.story_hidden();
        list.retain(|h| *h != id);
        if hidden {
            list.push(id);
        }
        self.set_setting(HIDDEN, &list.concat())
    }

    /// Who a story posted now goes to: accepted contacts, not blocked, not
    /// hidden from our stories.
    pub fn story_audience(&self) -> Vec<[u8; 64]> {
        let hidden = self.story_hidden();
        self.contacts()
            .into_iter()
            .filter(|c| c.state == super::ContactState::Accepted)
            .map(|c| c.root)
            .filter(|r| !self.is_blocked(r) && !hidden.iter().any(|h| r[..16] == h[..]))
            .collect()
    }

    /// Post a story: words, a picture, or both. It reaches our audience
    /// over the next upkeep rounds.
    pub async fn post_story(
        &mut self,
        text: &str,
        picture: Option<StoryPicture<'_>>,
    ) -> Result<Story> {
        let text = text.trim();
        if text.len() > MAX_STORY_TEXT || (text.is_empty() && picture.is_none()) {
            return Err(CoreError::TooLong);
        }
        let now = self.now();
        let attachment = match picture {
            Some(p) => {
                let host = self.profile.server;
                let (att, chunks) = files::seal_file(p.bytes, p.name, p.mime, host, &mut self.rng)?;
                for (id, chunk) in &chunks {
                    self.put_chunk(&host, *id, chunk, now).await?;
                }
                // Our copy: shown here without a download.
                self.store
                    .put(NS_FILES, &att.hash[..32], p.bytes, &mut self.rng)?;
                Some(att)
            }
            None => None,
        };
        let story = Story {
            from: None,
            id: self.rng.array("core/story-id")?,
            text: text.to_string(),
            attachment,
            at: now,
            viewed: true,
            left: self.story_audience(),
            sent: Vec::new(),
            gone: false,
        };
        self.put_story(&story)?;
        let own = self.me();
        let copy = Story {
            left: Vec::new(),
            ..story.clone()
        };
        self.send_self_copy(&own, &copy.content(now), now).await?;
        Ok(story)
    }

    /// Delete one of our stories: gone here, and those it reached are told.
    pub async fn delete_story(&mut self, id: &[u8; 16]) -> Result<()> {
        let own = self.me();
        let Some(mut s) = self
            .store
            .get(NS_STORIES, &key(&own, id))?
            .and_then(|b| Story::decode(&b))
        else {
            return Ok(());
        };
        s.gone = true;
        s.left = std::mem::take(&mut s.sent);
        self.put_story(&s)?;
        let now = self.now();
        self.send_self_copy(&own, &s.content(now), now).await
    }

    /// We opened a contact's story (nothing is sent).
    pub fn mark_story_viewed(&mut self, from: &[u8; 64], id: &[u8; 16]) -> Result<()> {
        if let Some(mut s) = self
            .store
            .get(NS_STORIES, &key(from, id))?
            .and_then(|b| Story::decode(&b))
            && !s.viewed
        {
            s.viewed = true;
            self.put_story(&s)?;
        }
        Ok(())
    }

    /// A story's picture: ours from our copy, a contact's from their
    /// server.
    pub async fn story_picture(&mut self, story: &Story) -> Result<Vec<u8>> {
        let a = story.attachment.as_ref().ok_or(CoreError::NotFound)?;
        if story.from.is_none()
            && let Some(b) = self.store.get(NS_FILES, &a.hash[..32])?
        {
            return Ok(b);
        }
        self.fetch_file(a).await
    }

    /// A story from a contact (or, `own`, from another of our devices).
    pub(crate) fn on_story(
        &mut self,
        from: Option<&[u8; 64]>,
        story: (&[u8; 16], String, &[u8], u32, bool),
        now: u64,
    ) -> Result<Vec<Event>> {
        let (id, text, attachment, age, gone) = story;
        if let Some(r) = from
            && (self.contact(r).map(|c| c.state) != Some(super::ContactState::Accepted)
                || self.is_blocked(r))
        {
            return Ok(Vec::new());
        }
        let owner = from.copied().unwrap_or(self.me());
        let k = key(&owner, id);
        if gone {
            // Taken down by its poster (or, ours, on another device).
            if from.is_some() || self.store.get(NS_STORIES, &k)?.is_some() {
                self.store.delete(NS_STORIES, &k)?;
                return Ok(vec![Event::StoriesChanged]);
            }
            return Ok(Vec::new());
        }
        if u64::from(age) >= STORY_SECS || text.len() > MAX_STORY_TEXT {
            return Ok(Vec::new());
        }
        if self.store.get(NS_STORIES, &k)?.is_some() {
            return Ok(Vec::new()); // a repeat
        }
        let attachment = if attachment.is_empty() {
            None
        } else {
            match Attachment::decode(attachment) {
                Ok(a) => Some(a),
                Err(_) => return Ok(Vec::new()),
            }
        };
        if text.is_empty() && attachment.is_none() {
            return Ok(Vec::new());
        }
        let s = Story {
            from: from.copied(),
            id: *id,
            text,
            attachment,
            at: now.saturating_sub(u64::from(age)),
            viewed: from.is_none(),
            left: Vec::new(),
            sent: Vec::new(),
            gone: false,
        };
        self.put_story(&s)?;
        // At most a few from one contact: the oldest go.
        if let Some(r) = from {
            let mut theirs: Vec<Story> = self
                .all_stories()
                .into_iter()
                .filter(|x| x.from.as_ref() == Some(r))
                .collect();
            theirs.sort_by_key(|x| std::cmp::Reverse(x.at));
            for old in theirs.iter().skip(MAX_STORIES_PER_CONTACT) {
                self.store.delete(NS_STORIES, &key(r, &old.id))?;
            }
        }
        Ok(vec![Event::StoriesChanged])
    }

    /// Drop stories past their 24 hours; send ours, and deletions of ours,
    /// to a few more of their audience.
    pub(crate) async fn story_upkeep(&mut self, now: u64) -> Result<()> {
        let own = self.me();
        let mut budget = PER_ROUND;
        for mut s in self.all_stories() {
            if s.expires_at() <= now {
                let from = s.from.unwrap_or(own);
                self.store.delete(NS_STORIES, &key(&from, &s.id))?;
                continue;
            }
            if s.from.is_some() || s.left.is_empty() || budget == 0 {
                continue;
            }
            let content = s.content(now);
            while budget > 0
                && let Some(root) = s.left.first().copied()
            {
                budget -= 1;
                s.left.remove(0);
                // Someone who stopped being a contact is skipped.
                if self.contact(&root).is_some() && !self.is_blocked(&root) {
                    match self.send_content(&root, &content, now).await {
                        Ok(_) => {
                            if !s.gone {
                                s.sent.push(root);
                            }
                        }
                        Err(e) => {
                            // Tried again next round.
                            s.left.push(root);
                            self.put_story(&s)?;
                            return Err(e);
                        }
                    }
                }
            }
            if s.gone && s.left.is_empty() {
                self.store.delete(NS_STORIES, &key(&own, &s.id))?;
            } else {
                self.put_story(&s)?;
            }
        }
        Ok(())
    }
}
