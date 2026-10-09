//! Sticker packs (`docs/16-features.md`: "Packs are blobs keyed by pack
//! secret"; `docs/08-envelope.md` §9).
//!
//! A pack is a title and up to [`MAX_STICKERS`] pictures (re-encoded by the
//! app first), sealed as one file: chunks padded to a size bucket at random
//! IDs on its creator's server, under a key only holders of its reference
//! have. Sending a sticker sends that reference and an index, so the server
//! sees one more ordinary unit; a recipient downloads the whole pack once
//! (every chunk of its bucket) and decodes the one picture. Anyone who
//! received a sticker can add its pack, as they could keep any file sent
//! to them.

use super::messages::NS_FILES;
use super::polls::Rich;
use super::{Client, ContactState, Event, GroupMessage, Message};
use crate::content::{Content, MAX_ATTACHMENT_REF, MsgId};
use crate::files::{self, Attachment};
use crate::{CoreError, Result};
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};

const NS_PACKS: &str = "sticker-packs";
const PACK_MAGIC: &[u8; 4] = b"ESP1";
/// MIME type of a pack file.
pub const PACK_MIME: &str = "application/x-enclave-stickers";
/// Most stickers in a pack.
pub const MAX_STICKERS: usize = 40;
/// Largest sticker picture, in bytes.
pub const MAX_STICKER_BYTES: usize = 512 << 10;
/// Largest pack, in bytes.
pub const MAX_PACK_BYTES: usize = 8 << 20;
/// Longest pack title, in bytes.
pub const MAX_PACK_TITLE: usize = 64;

/// A pack's contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickerPack {
    /// Its name.
    pub title: String,
    /// The pictures (JPEG or PNG).
    pub stickers: Vec<Vec<u8>>,
}

impl StickerPack {
    /// `"ESP1" ‖ bytes(title) ‖ u8 n ‖ n × bytes(picture)`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.title.len() > MAX_PACK_TITLE
            || self.stickers.is_empty()
            || self.stickers.len() > MAX_STICKERS
            || self.stickers.iter().any(|s| s.len() > MAX_STICKER_BYTES)
        {
            return Err(CoreError::TooLong);
        }
        let mut w = Writer::new();
        w.fixed(PACK_MAGIC)
            .bytes(self.title.as_bytes())
            .u8(self.stickers.len() as u8);
        for s in &self.stickers {
            w.bytes(s);
        }
        let b = w.finish();
        if b.len() > MAX_PACK_BYTES {
            return Err(CoreError::TooLong);
        }
        Ok(b)
    }

    /// Decode (strict).
    pub fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        if &r.array::<4>()? != PACK_MAGIC {
            return Err(ProtoError::Decode);
        }
        let title =
            String::from_utf8(r.bytes(MAX_PACK_TITLE)?.to_vec()).map_err(|_| ProtoError::Decode)?;
        let n = usize::from(r.u8()?);
        if n == 0 || n > MAX_STICKERS {
            return Err(ProtoError::Decode);
        }
        let stickers = (0..n)
            .map(|_| Ok(r.bytes(MAX_STICKER_BYTES)?.to_vec()))
            .collect::<enclave_proto::Result<_>>()?;
        r.end()?;
        Ok(Self { title, stickers })
    }
}

/// A pack this device has added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledPack {
    /// Its key here (the first 32 bytes of the file hash).
    pub key: [u8; 32],
    /// Its name.
    pub title: String,
    /// How many stickers.
    pub count: u8,
    /// Where the sealed pack is, and its key.
    pub file: Attachment,
}

impl InstalledPack {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .bytes(self.title.as_bytes())
            .u8(self.count)
            .bytes(&self.file.encode());
        w.finish()
    }

    fn decode(key: [u8; 32], b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let title =
            String::from_utf8(r.bytes(MAX_PACK_TITLE)?.to_vec()).map_err(|_| ProtoError::Decode)?;
        let count = r.u8()?;
        let file = Attachment::decode(r.bytes(MAX_ATTACHMENT_REF)?)?;
        r.end()?;
        Ok(Self {
            key,
            title,
            count,
            file,
        })
    }
}

fn pack_key(att: &Attachment) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&att.hash[..32]);
    k
}

impl Client {
    /// Make a pack from pictures the app has already re-encoded, upload it
    /// and add it here.
    pub async fn create_sticker_pack(
        &mut self,
        title: &str,
        stickers: Vec<Vec<u8>>,
    ) -> Result<InstalledPack> {
        let pack = StickerPack {
            title: title.trim().to_string(),
            stickers,
        };
        let data = pack.encode()?;
        let now = self.now();
        let host = self.profile.server;
        let (att, chunks) = files::seal_file(&data, "stickers", PACK_MIME, host, &mut self.rng)?;
        for (id, chunk) in &chunks {
            self.rpc
                .blob_put(&host, *id, chunk, now, &mut self.rng)
                .await?;
        }
        self.store
            .put(NS_FILES, &att.hash[..32], &data, &mut self.rng)?;
        self.keep_pack(&att, &pack)
    }

    fn keep_pack(&mut self, att: &Attachment, pack: &StickerPack) -> Result<InstalledPack> {
        let p = InstalledPack {
            key: pack_key(att),
            title: pack.title.clone(),
            count: pack.stickers.len() as u8,
            file: att.clone(),
        };
        self.store
            .put(NS_PACKS, &p.key, &p.encode(), &mut self.rng)?;
        Ok(p)
    }

    /// Packs added here, by title.
    pub fn sticker_packs(&self) -> Vec<InstalledPack> {
        let mut v: Vec<InstalledPack> = self
            .store
            .scan(NS_PACKS)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, b)| InstalledPack::decode(k.try_into().ok()?, &b).ok())
            .collect();
        v.sort_by(|a, b| a.title.cmp(&b.title));
        v
    }

    /// Remove a pack from this device.
    pub fn remove_sticker_pack(&mut self, key: &[u8; 32]) -> Result<()> {
        self.store.delete(NS_PACKS, key)?;
        Ok(())
    }

    /// Whether the pack behind `att` is added here.
    pub fn has_sticker_pack(&self, att: &Attachment) -> bool {
        matches!(self.store.get(NS_PACKS, &pack_key(att)), Ok(Some(_)))
    }

    /// Download (or read from the cache) and check a pack.
    pub async fn fetch_sticker_pack(&mut self, att: &Attachment) -> Result<StickerPack> {
        if att.mime != PACK_MIME {
            return Err(CoreError::NotAccepted);
        }
        let data = self.fetch_file(att).await?;
        Ok(StickerPack::decode(&data)?)
    }

    /// Add the pack a received sticker came from.
    pub async fn add_sticker_pack(&mut self, att: &Attachment) -> Result<InstalledPack> {
        let pack = self.fetch_sticker_pack(att).await?;
        self.keep_pack(att, &pack)
    }

    /// The picture of sticker `index` in the pack behind `att`.
    pub async fn sticker_picture(&mut self, att: &Attachment, index: u8) -> Result<Vec<u8>> {
        self.fetch_sticker_pack(att)
            .await?
            .stickers
            .into_iter()
            .nth(usize::from(index))
            .ok_or(CoreError::NotFound)
    }

    fn installed(&self, key: &[u8; 32], index: u8) -> Result<InstalledPack> {
        let b = self.store.get(NS_PACKS, key)?.ok_or(CoreError::NotFound)?;
        let p = InstalledPack::decode(*key, &b)?;
        if index >= p.count {
            return Err(CoreError::NotFound);
        }
        Ok(p)
    }

    /// Send sticker `index` of an added pack to `root`.
    pub async fn send_sticker(
        &mut self,
        root: &[u8; 64],
        key: &[u8; 32],
        index: u8,
    ) -> Result<Message> {
        let p = self.installed(key, index)?;
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != ContactState::Accepted {
            return Err(CoreError::NotAccepted);
        }
        let timer = c.timer;
        let now = self.now();
        let id: MsgId = self.rng.array("core/msg-id")?;
        let mut m = self.new_message(root, id, true, "", timer, now)?;
        m.attachment = Some(p.file.clone());
        m.sticker = Some(index);
        self.put_message(root, &m)?;
        let content = Content::Sticker {
            id,
            pack: p.file.encode(),
            index,
            expires: timer,
        };
        let sent = self.send_tracked(root, id, &content, now).await?;
        self.send_self_copy(root, &content, now).await?;
        m.sent = sent;
        self.put_message(root, &m)?;
        Ok(m)
    }

    /// Send sticker `index` of an added pack to group `gid`.
    pub async fn send_group_sticker(
        &mut self,
        gid: &[u8; 32],
        key: &[u8; 32],
        index: u8,
    ) -> Result<GroupMessage> {
        let p = self.installed(key, index)?;
        let now = self.now();
        self.prepare_group_send(gid, now).await?;
        let id: [u8; 16] = self.rng.array("core/group-msg-id")?;
        let mut m = self.store_group_message(gid, id, None, "", now)?;
        m.attachment = Some(p.file.clone());
        m.sticker = Some(index);
        self.put_group_message(gid, &m)?;
        let rich = Rich::Sticker {
            id,
            pack: p.file.encode(),
            index,
        };
        self.post_group_rich(gid, &rich).await?;
        m.delivered = true;
        self.put_group_message(gid, &m)?;
        Ok(m)
    }

    /// A sticker from `root` (or, from our other device, ours to `root`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_sticker(
        &mut self,
        root: &[u8; 64],
        id: MsgId,
        pack: &[u8],
        index: u8,
        expires: u32,
        outgoing: bool,
        now: u64,
    ) -> Result<Option<Event>> {
        if self.find(root, &id).is_ok() || usize::from(index) >= MAX_STICKERS {
            return Ok(None);
        }
        let Ok(att) = Attachment::decode(pack) else {
            return Ok(None);
        };
        let mut m = self.new_message(root, id, outgoing, "", expires, now)?;
        m.attachment = Some(att);
        m.sticker = Some(index);
        m.sent = outgoing;
        self.put_message(root, &m)?;
        Ok(Some(Event::Message {
            root: *root,
            message: m,
        }))
    }

    /// A sticker from a group member.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_group_sticker(
        &mut self,
        gid: &[u8; 32],
        from: &[u8; 64],
        name: String,
        id: [u8; 16],
        pack: &[u8],
        index: u8,
        now: u64,
    ) -> Result<Option<Event>> {
        let Ok(att) = Attachment::decode(pack) else {
            return Ok(None);
        };
        if usize::from(index) >= MAX_STICKERS
            || self.group_messages(gid)?.iter().any(|m| m.id == id)
        {
            return Ok(None);
        }
        let mut m = self.store_group_message(gid, id, Some((*from, name)), "", now)?;
        m.attachment = Some(att);
        m.sticker = Some(index);
        self.put_group_message(gid, &m)?;
        self.bump_group_unread(gid, from)?;
        Ok(Some(Event::GroupMessage {
            group_id: *gid,
            message: m,
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn pack_codec_and_limits() {
        let p = StickerPack {
            title: "Cats".into(),
            stickers: vec![vec![1; 100], vec![2; 200]],
        };
        assert_eq!(StickerPack::decode(&p.encode().unwrap()).unwrap(), p);
        let empty = StickerPack {
            title: "x".into(),
            stickers: vec![],
        };
        assert!(empty.encode().is_err());
        let many = StickerPack {
            title: "x".into(),
            stickers: vec![vec![0; 1]; MAX_STICKERS + 1],
        };
        assert!(many.encode().is_err());
        let mut b = p.encode().unwrap();
        b[0] = b'X';
        assert!(StickerPack::decode(&b).is_err());
    }
}
