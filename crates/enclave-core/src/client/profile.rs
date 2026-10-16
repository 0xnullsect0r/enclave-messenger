//! Our profile and our contacts' (`docs/16-features.md`, "Encrypted
//! profile"): a display name, a few words "about", and a photo.
//!
//! A profile goes only inside sessions, to accepted contacts, as
//! [`Content::Profile`]; never to a server, a card or a group. The photo is
//! a sealed file like any attachment (`08-envelope.md` §9) on our server,
//! and the profile carries its reference. Each change bumps a version, so a
//! late or replayed copy can't put an older profile back. A contact who
//! accepts us later gets the current one at the next upkeep; a photo whose
//! chunks are near their server lifetime (30 days) is uploaded again first,
//! from the copy we keep. Our other devices get the profile with the
//! synced settings.

use super::Client;
use super::messages::NS_FILES;
use crate::content::{Content, MAX_ABOUT, MAX_ATTACHMENT_REF};
use crate::files::{self, Attachment};
use crate::{CoreError, Event, Result};
use enclave_proto::codec::{Reader, Writer};

/// The setting that holds our profile (synced to our other devices).
pub(crate) const SETTING: &str = "profile";
/// Where a contact's profile is kept: this prefix and their root, hex.
const THEIRS: &str = "profile-of/";
/// Where the version last sent to a contact is kept.
const SENT: &str = "profile-sent/";
/// A photo older than this is uploaded again before it is sent (the
/// server keeps chunks 30 days).
pub const PHOTO_REFRESH_SECS: u64 = 25 * 86_400;
/// Contacts told about a change per upkeep round, so a change doesn't
/// burst out to everyone at once.
const PER_ROUND: usize = 8;

/// A profile: ours, or a contact's as they sent it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileInfo {
    /// Display name.
    pub name: String,
    /// A few words about them.
    pub about: String,
    /// Their photo, sealed on their server (download with
    /// [`Client::fetch_file`]).
    pub photo: Option<Attachment>,
    /// Increases with every change.
    pub version: u64,
    /// Ours: when the photo was uploaded; theirs: when the profile came.
    pub photo_at: u64,
}

impl ProfileInfo {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .bytes(self.name.as_bytes())
            .bytes(self.about.as_bytes())
            .bytes(
                &self
                    .photo
                    .as_ref()
                    .map(Attachment::encode)
                    .unwrap_or_default(),
            )
            .u64(self.version)
            .u64(self.photo_at);
        w.finish()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8().ok()? != 1 {
            return None;
        }
        let s = |r: &mut Reader<'_>, n| String::from_utf8(r.bytes(n).ok()?.to_vec()).ok();
        let name = s(&mut r, crate::card::MAX_NAME)?;
        let about = s(&mut r, MAX_ABOUT)?;
        let photo = r.bytes(MAX_ATTACHMENT_REF).ok()?;
        let photo = if photo.is_empty() {
            None
        } else {
            Some(Attachment::decode(photo).ok()?)
        };
        let p = ProfileInfo {
            name,
            about,
            photo,
            version: r.u64().ok()?,
            photo_at: r.u64().ok()?,
        };
        r.end().ok()?;
        Some(p)
    }

    fn content(&self) -> Content {
        Content::Profile {
            name: self.name.clone(),
            about: self.about.clone(),
            photo: self
                .photo
                .as_ref()
                .map(Attachment::encode)
                .unwrap_or_default(),
            version: self.version,
        }
    }
}

fn hex(root: &[u8; 64]) -> String {
    root.iter().map(|b| format!("{b:02x}")).collect()
}

/// A new photo for [`Client::set_profile`]: a picture already re-encoded
/// (the app does it in mediad), or none.
pub enum Photo<'a> {
    /// Keep the photo we have.
    Keep,
    /// No photo.
    Remove,
    /// This picture (file name, MIME type, bytes).
    New(&'a str, &'a str, &'a [u8]),
}

impl Client {
    /// Our profile (the name is our display name).
    pub fn profile(&self) -> Result<ProfileInfo> {
        let mut p = self
            .setting(SETTING)?
            .and_then(|b| ProfileInfo::decode(&b))
            .unwrap_or_default();
        p.name = self.profile.name.clone();
        Ok(p)
    }

    /// Change what our contacts see: "about" and the photo (the name is
    /// changed with the display name). The photo is uploaded sealed; our
    /// contacts get the profile at the next upkeep rounds.
    pub async fn set_profile(&mut self, about: &str, photo: Photo<'_>) -> Result<ProfileInfo> {
        if about.len() > MAX_ABOUT {
            return Err(CoreError::TooLong);
        }
        let now = self.now();
        let mut p = self.profile()?;
        p.about = about.trim().to_string();
        match photo {
            Photo::Keep => {}
            Photo::Remove => {
                p.photo = None;
                p.photo_at = 0;
            }
            Photo::New(name, mime, data) => {
                p.photo = Some(self.upload_photo(name, mime, data, now).await?);
                p.photo_at = now;
            }
        }
        p.version += 1;
        self.set_setting(SETTING, &p.encode())?;
        Ok(p)
    }

    async fn upload_photo(
        &mut self,
        name: &str,
        mime: &str,
        data: &[u8],
        now: u64,
    ) -> Result<Attachment> {
        let host = self.profile.server;
        let (att, chunks) = files::seal_file(data, name, mime, host, &mut self.rng)?;
        for (id, chunk) in &chunks {
            self.put_chunk(&host, *id, chunk, now).await?;
        }
        // Our own copy: shown here, and uploaded again when it ages.
        self.store
            .put(NS_FILES, &att.hash[..32], data, &mut self.rng)?;
        Ok(att)
    }

    /// Change our display name: new cards and invites carry it, and our
    /// contacts get it with the profile.
    pub fn set_display_name(&mut self, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.len() > crate::card::MAX_NAME {
            return Err(CoreError::TooLong);
        }
        if name == self.profile.name {
            return Ok(());
        }
        self.profile.name = name.to_string();
        self.save_profile()?;
        let mut p = self.profile()?;
        p.version += 1;
        self.set_setting(SETTING, &p.encode())
    }

    /// A contact's profile, as they last sent it.
    pub fn contact_profile(&self, root: &[u8; 64]) -> Result<Option<ProfileInfo>> {
        Ok(self
            .setting(&format!("{THEIRS}{}", hex(root)))?
            .and_then(|b| ProfileInfo::decode(&b)))
    }

    /// A profile from a contact: kept if it is newer than the one we have.
    pub(crate) fn on_profile(
        &mut self,
        root: &[u8; 64],
        name: String,
        about: String,
        photo: &[u8],
        version: u64,
    ) -> Result<Vec<Event>> {
        if self.contact(root).is_none() {
            return Ok(Vec::new());
        }
        if self
            .contact_profile(root)?
            .is_some_and(|p| p.version >= version)
        {
            return Ok(Vec::new());
        }
        let photo = if photo.is_empty() {
            None
        } else {
            match Attachment::decode(photo) {
                Ok(a) => Some(a),
                Err(_) => return Ok(Vec::new()),
            }
        };
        // Theirs: when it arrived (the photo is fetched some time after,
        // RT-17).
        let p = ProfileInfo {
            name,
            about,
            photo,
            version,
            photo_at: self.now(),
        };
        self.set_setting(&format!("{THEIRS}{}", hex(root)), &p.encode())?;
        Ok(vec![Event::ProfileChanged { root: *root }])
    }

    /// Send our profile to the accepted contacts that don't have this
    /// version yet, a few each round; first upload the photo again if it is
    /// near its server lifetime.
    pub(crate) async fn profile_upkeep(&mut self, now: u64) -> Result<()> {
        let mut p = self.profile()?;
        if p.version == 0 {
            return Ok(());
        }
        let due: Vec<[u8; 64]> = self
            .contacts()
            .into_iter()
            .filter(|c| c.state == super::ContactState::Accepted)
            .map(|c| c.root)
            .filter(|r| {
                self.setting(&format!("{SENT}{}", hex(r)))
                    .ok()
                    .flatten()
                    .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
                    .map(u64::from_be_bytes)
                    != Some(p.version)
            })
            .take(PER_ROUND)
            .collect();
        if due.is_empty() {
            return Ok(());
        }
        if let Some(old) = p.photo.clone()
            && p.photo_at + PHOTO_REFRESH_SECS <= now
        {
            let Some(data) = self.store.get(NS_FILES, &old.hash[..32])? else {
                // Our copy is gone: no photo rather than a dead link.
                p.photo = None;
                p.version += 1;
                self.set_setting(SETTING, &p.encode())?;
                return Ok(());
            };
            p.photo = Some(self.upload_photo(&old.name, &old.mime, &data, now).await?);
            p.photo_at = now;
            p.version += 1;
            self.set_setting(SETTING, &p.encode())?;
        }
        let content = p.content();
        for root in due {
            self.send_content(&root, &content, now).await?;
            self.set_setting(&format!("{SENT}{}", hex(&root)), &p.version.to_be_bytes())?;
        }
        Ok(())
    }
}
