//! 1:1 messages: storage, disappearing messages, attachments, reactions,
//! edits, deletes and read receipts (`docs/16-features.md`).
//!
//! * Every message has a 16-byte id chosen by its sender, so later messages
//!   can refer to it.
//! * A disappearing message is sealed under the conversation's crypto-shred
//!   key for the day it expires. Its timer starts when it is sent (ours) or
//!   read (theirs) and runs on the timer clock (`Rpc::timer_now`), which
//!   setting the device clock back doesn't stop (RT-23). Each sync shreds the
//!   keys of past days, so expired messages are unrecoverable even from an
//!   image of the disk taken later.
//! * Edits and deletes for everyone are advisory: they apply only to the
//!   author's own messages, edits only within 24 hours.

use super::location::Location;
use super::record::Evidence;
use super::search::Place;
use super::search_index::Conv;
use super::{Client, ContactState, Event};
use crate::content::{Content, MAX_TEXT, MsgId};
use crate::files::{self, Attachment};
use crate::{CoreError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};
use enclave_rpc::api::Status;
use enclave_store::shred::Shredder;
use enclave_wire::{Op, RequestHeader};

/// Edits are accepted this long after the original.
pub const EDIT_WINDOW: u64 = 24 * 3600;
/// Unread disappearing messages are kept at most this long.
const UNREAD_HOLD_DAYS: u64 = 30;
const SEALED: u8 = 0xDE;
pub(crate) const NS_FILES: &str = "files";

/// A reaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reaction {
    /// Ours (else theirs).
    pub from_us: bool,
    /// The emoji.
    pub emoji: String,
}

/// Most bytes of a transcript kept with a voice note.
pub const MAX_TRANSCRIPT: usize = 16_384;

/// A stored message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Position in the conversation.
    pub seq: u64,
    /// Id chosen by the sender.
    pub id: MsgId,
    /// Sent by us.
    pub outgoing: bool,
    /// On its way: sent (one way over the mixnet) or accepted by the
    /// recipient's server (outgoing only).
    pub sent: bool,
    /// The recipient's device has it: their delivery receipt came
    /// (outgoing only).
    pub delivered: bool,
    /// No receipt after every re-send: "Not delivered yet" (outgoing only).
    pub stalled: bool,
    /// Arrived more than a minute after messages they sent later: "Delivered
    /// late" (incoming only; `05-ratchet.md` §11, RT-24).
    pub late: bool,
    /// On the record (`client/record.rs`): `Some(true)` signed by its
    /// sender's device, `Some(false)` should have been and wasn't ("Not
    /// signed"), `None` off the record.
    pub signed: Option<bool>,
    /// An incoming message's verified signature, for a report.
    pub evidence: Option<Evidence>,
    /// Ours: they read it. Theirs: we read it.
    pub read: bool,
    /// Unix time (local clock) when sent or received.
    pub at: u64,
    /// Text (the caption, for attachments).
    pub text: String,
    /// Attached file.
    pub attachment: Option<Attachment>,
    /// Reactions (at most one per side).
    pub reactions: Vec<Reaction>,
    /// Edited by its author.
    pub edited: bool,
    /// Deleted by its author.
    pub deleted: bool,
    /// Disappearing timer (0 = off).
    pub expires_secs: u32,
    /// When it disappears, once the timer has started.
    pub expires_at: Option<u64>,
    /// A shared place. Kept in the message record itself, so it is
    /// sealed and shredded with it.
    pub location: Option<Location>,
    /// A sticker: its index in the pack, which is `attachment`.
    pub sticker: Option<u8>,
    /// A line this device wrote into the conversation (a call: "Missed
    /// call", "Call, 3:02"), not a message anyone sent.
    pub notice: bool,
    /// A voice note's words, transcribed on this device (empty: not
    /// transcribed). Kept in the record, so shredded with it.
    pub transcript: String,
    /// The message this one answers (its id), if any.
    pub reply_to: Option<MsgId>,
    /// Forwarded from another conversation.
    pub forwarded: bool,
    /// A group message that mentions us (`@` and our name).
    pub mentions_me: bool,
    /// The poll this message asks ([`Client::poll_in`]).
    pub poll: Option<MsgId>,
    /// View once: the file can be opened once ([`Client::open_view_once`]),
    /// by its recipient only.
    pub view_once: bool,
    /// A view-once file not opened yet. It is never in `attachment`, so
    /// nothing else downloads, previews or keeps it; gone once opened.
    pub once: Option<Attachment>,
}

/// How a text is sent: as an answer to another message, or forwarded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TextOptions {
    /// The message it answers (its id, in the same conversation).
    pub reply: Option<MsgId>,
    /// Forwarded from another conversation.
    pub forwarded: bool,
}

impl Message {
    pub(crate) fn new(seq: u64, id: MsgId, outgoing: bool, at: u64, text: String) -> Self {
        Self {
            seq,
            id,
            outgoing,
            sent: false,
            delivered: false,
            stalled: false,
            late: false,
            signed: None,
            evidence: None,
            read: false,
            at,
            text,
            attachment: None,
            reactions: Vec::new(),
            edited: false,
            deleted: false,
            expires_secs: 0,
            expires_at: None,
            location: None,
            sticker: None,
            notice: false,
            transcript: String::new(),
            reply_to: None,
            forwarded: false,
            mentions_me: false,
            poll: None,
            view_once: false,
            once: None,
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(9).u64(self.seq).fixed(&self.id);
        w.u8(u8::from(self.outgoing))
            .u8(u8::from(self.delivered))
            .u8(u8::from(self.read))
            .u64(self.at);
        w.bytes(self.text.as_bytes());
        w.bytes(
            &self
                .attachment
                .as_ref()
                .map(Attachment::encode)
                .unwrap_or_default(),
        );
        w.u8(self.reactions.len() as u8);
        for r in &self.reactions {
            w.u8(u8::from(r.from_us)).bytes(r.emoji.as_bytes());
        }
        w.u8(u8::from(self.edited))
            .u8(u8::from(self.deleted))
            .u32(self.expires_secs)
            .u64(self.expires_at.unwrap_or(0));
        w.bytes(
            &self
                .location
                .as_ref()
                .map(Location::encode)
                .unwrap_or_default(),
        );
        match self.sticker {
            Some(i) => w.u8(1).u8(i),
            None => w.u8(0),
        };
        w.u8(u8::from(self.sent)
            | (u8::from(self.stalled) << 1)
            | (u8::from(self.late) << 2)
            | (u8::from(self.signed.is_some()) << 3)
            | (u8::from(self.signed == Some(true)) << 4)
            | (u8::from(self.notice) << 5));
        w.bytes(
            &self
                .evidence
                .as_ref()
                .map(Evidence::encode)
                .unwrap_or_default(),
        );
        w.bytes(self.transcript.as_bytes());
        match &self.reply_to {
            Some(r) => w.u8(1).fixed(r),
            None => w.u8(0),
        };
        w.u8(u8::from(self.forwarded)
            | (u8::from(self.mentions_me) << 1)
            | (u8::from(self.view_once) << 2));
        match &self.poll {
            Some(p) => w.u8(1).fixed(p),
            None => w.u8(0),
        };
        w.bytes(
            &self
                .once
                .as_ref()
                .map(Attachment::encode)
                .unwrap_or_default(),
        );
        w.finish()
    }

    pub(crate) fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        let version = r.u8()?;
        if !(2..=9).contains(&version) {
            return Err(ProtoError::Decode);
        }
        let s = |r: &mut Reader<'_>, n| {
            String::from_utf8(r.bytes(n)?.to_vec()).map_err(|_| ProtoError::Decode)
        };
        let seq = r.u64()?;
        let id = r.array()?;
        let (outgoing, delivered, read) = (r.u8()? == 1, r.u8()? == 1, r.u8()? == 1);
        let at = r.u64()?;
        let text = s(&mut r, 1 << 16)?;
        let att = r.bytes(crate::content::MAX_ATTACHMENT_REF)?;
        let attachment = if att.is_empty() {
            None
        } else {
            Some(Attachment::decode(att)?)
        };
        let mut reactions = Vec::new();
        for _ in 0..r.u8()?.min(2) {
            reactions.push(Reaction {
                from_us: r.u8()? == 1,
                emoji: s(&mut r, 64)?,
            });
        }
        let (edited, deleted, expires_secs) = (r.u8()? == 1, r.u8()? == 1, r.u32()?);
        let expires_at = Some(r.u64()?).filter(|t| *t != 0);
        let location = if version >= 3 {
            let l = r.bytes(512)?;
            if l.is_empty() {
                None
            } else {
                Some(Location::decode(l)?)
            }
        } else {
            None
        };
        let sticker = if version >= 4 && r.u8()? == 1 {
            Some(r.u8()?)
        } else {
            None
        };
        // Before receipts, "delivered" meant accepted by the server.
        let (sent, stalled, late, signed, notice) = if version >= 5 {
            let f = r.u8()?;
            let signed = (f & 8 != 0).then_some(f & 16 != 0);
            (f & 1 != 0, f & 2 != 0, f & 4 != 0, signed, f & 32 != 0)
        } else {
            (delivered, false, false, None, false)
        };
        let evidence = if version >= 6 {
            let e = r.bytes(crate::content::MAX_SIG + crate::content::MAX_SPLIT_CONTENT + 64)?;
            if e.is_empty() {
                None
            } else {
                Some(Evidence::decode(e)?)
            }
        } else {
            None
        };
        let transcript = if version >= 7 {
            s(&mut r, MAX_TRANSCRIPT)?
        } else {
            String::new()
        };
        let (reply_to, forwarded, mentions_me, view_once) = if version >= 8 {
            let reply = match r.u8()? {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(ProtoError::Decode),
            };
            let f = r.u8()?;
            (reply, f & 1 != 0, f & 2 != 0, f & 4 != 0)
        } else {
            (None, false, false, false)
        };
        let poll = if version >= 8 && r.u8()? == 1 {
            Some(r.array()?)
        } else {
            None
        };
        let once = if version >= 9 {
            let b = r.bytes(crate::content::MAX_ATTACHMENT_REF)?;
            if b.is_empty() {
                None
            } else {
                Some(Attachment::decode(b)?)
            }
        } else {
            None
        };
        r.end()?;
        Ok(Self {
            seq,
            id,
            outgoing,
            sent,
            delivered,
            stalled,
            late,
            signed,
            evidence,
            read,
            at,
            text,
            attachment,
            reactions,
            edited,
            deleted,
            expires_secs,
            expires_at,
            location,
            sticker,
            notice,
            transcript,
            reply_to,
            forwarded,
            mentions_me,
            poll,
            view_once,
            once,
        })
    }

    /// What search looks at: the text and an attachment's name (nothing,
    /// once deleted).
    pub(crate) fn search_text(&self) -> String {
        if self.deleted {
            return String::new();
        }
        match &self.attachment {
            Some(a) if self.text.is_empty() => a.name.clone(),
            Some(a) => format!("{} {}", a.name, self.text),
            None => self.text.clone(),
        }
    }

    /// The shred day the record is sealed under, if it disappears.
    pub(crate) fn sealed_day(&self) -> Option<u64> {
        (self.expires_secs > 0).then(|| self.shred_day())
    }

    /// The shred day this message's record is sealed under.
    fn shred_day(&self) -> u64 {
        match self.expires_at {
            Some(t) => t / 86_400,
            None => self.at / 86_400 + UNREAD_HOLD_DAYS,
        }
    }
}

fn msg_ns(root: &[u8; 64]) -> String {
    crate::persist::msg_ns(root)
}

pub(crate) fn id_ns(root: &[u8; 64]) -> String {
    let mut s = String::from("mid/");
    for b in &root[..16] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn conv(root: &[u8; 64]) -> &[u8] {
    &root[..32]
}

impl Client {
    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    /// Messages with `root`, oldest first. Expired messages are skipped.
    pub fn messages(&self, root: &[u8; 64]) -> Result<Vec<Message>> {
        let now = self.rpc.timer_now();
        let mut rng = HedgedRng::new()?;
        let shred = Shredder::open(&self.store, &mut rng)?;
        let mut v: Vec<Message> = self
            .store
            .scan(&msg_ns(root))?
            .into_iter()
            .filter_map(|(_, b)| Self::decode_record(&shred, root, &b))
            .filter(|m| m.expires_at.is_none_or(|t| t > now))
            .collect();
        v.sort_by_key(|m| m.seq);
        Ok(v)
    }

    fn decode_record(shred: &Shredder<'_>, root: &[u8; 64], b: &[u8]) -> Option<Message> {
        if b.first() == Some(&SEALED) {
            let day = u64::from_be_bytes(b.get(1..9)?.try_into().ok()?);
            let pt = shred.open_msg(conv(root), day, b.get(9..)?).ok()?;
            Message::decode(&pt).ok()
        } else {
            Message::decode(b).ok()
        }
    }

    pub(crate) fn put_message(&mut self, root: &[u8; 64], m: &Message) -> Result<()> {
        // The version it replaces, for the search index.
        let old = match self.store.get(&msg_ns(root), &m.seq.to_be_bytes())? {
            Some(b) => {
                let shred = Shredder::open(&self.store, &mut self.rng)?;
                Self::decode_record(&shred, root, &b)
            }
            None => None,
        };
        let rec = if m.expires_secs > 0 {
            let day = m.shred_day();
            let mut shred = Shredder::open(&self.store, &mut self.rng)?;
            let sealed = shred.seal(conv(root), day, &m.encode(), &mut self.rng)?;
            [&[SEALED][..], &day.to_be_bytes(), &sealed].concat()
        } else {
            m.encode()
        };
        self.store
            .put(&msg_ns(root), &m.seq.to_be_bytes(), &rec, &mut self.rng)?;
        self.store
            .put(&id_ns(root), &m.id, &m.seq.to_be_bytes(), &mut self.rng)?;
        let before = old.map(|o| (o.search_text(), o.sealed_day()));
        let (old_text, old_day) = before.unwrap_or_default();
        self.index_message(
            Conv::Contact(*root),
            m.seq,
            (&old_text, old_day),
            (&m.search_text(), m.sealed_day()),
        )?;
        Ok(())
    }

    /// The message at `seq` with `root`, if it is there and hasn't expired.
    pub(crate) fn message_at(&self, root: &[u8; 64], seq: u64) -> Result<Option<Message>> {
        let Some(b) = self.store.get(&msg_ns(root), &seq.to_be_bytes())? else {
            return Ok(None);
        };
        let mut rng = HedgedRng::new()?;
        let shred = Shredder::open(&self.store, &mut rng)?;
        let now = self.rpc.timer_now();
        Ok(Self::decode_record(&shred, root, &b).filter(|m| m.expires_at.is_none_or(|t| t > now)))
    }

    pub(crate) fn get_message(&mut self, root: &[u8; 64], seq: u64) -> Result<Message> {
        let b = self
            .store
            .get(&msg_ns(root), &seq.to_be_bytes())?
            .ok_or(CoreError::NotFound)?;
        let shred = Shredder::open(&self.store, &mut self.rng)?;
        Self::decode_record(&shred, root, &b).ok_or(CoreError::NotFound)
    }

    pub(crate) fn find(&mut self, root: &[u8; 64], id: &MsgId) -> Result<Message> {
        let b = self
            .store
            .get(&id_ns(root), id)?
            .ok_or(CoreError::NotFound)?;
        let seq = u64::from_be_bytes(b.as_slice().try_into().map_err(|_| CoreError::NotFound)?);
        self.get_message(root, seq)
    }

    /// Store a new message and assign its position.
    pub(crate) fn new_message(
        &mut self,
        root: &[u8; 64],
        id: MsgId,
        outgoing: bool,
        text: &str,
        expires_secs: u32,
        now: u64,
    ) -> Result<Message> {
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        let seq = c.next_seq;
        c.next_seq += 1;
        let c = c.clone();
        self.save_contact(&c)?;
        let mut m = Message::new(seq, id, outgoing, now, text.to_string());
        m.late = !outgoing && self.late_unit;
        if outgoing {
            m.signed = self.on_the_record(root).then_some(true);
        } else if let Some(sig) = self.unit_signature.clone() {
            m.signed = Some(sig.is_some());
            m.evidence = sig;
        }
        m.expires_secs = expires_secs;
        if outgoing && expires_secs > 0 {
            m.expires_at = Some(self.rpc.timer_now() + u64::from(expires_secs));
        }
        self.put_message(root, &m)?;
        Ok(m)
    }

    /// Store one of our messages with a fresh id.
    pub(crate) fn store_message(
        &mut self,
        root: &[u8; 64],
        outgoing: bool,
        text: &str,
        now: u64,
    ) -> Result<Message> {
        if outgoing {
            self.require_not_held()?;
        }
        let id: MsgId = self.rng.array("core/msg-id")?;
        let timer = if outgoing {
            self.contacts.get(root).map_or(0, |c| c.timer)
        } else {
            0
        };
        self.new_message(root, id, outgoing, text, timer, now)
    }

    /// Delete expired messages and shred the keys of past days, by the
    /// timer clock.
    pub(crate) fn purge_expired(&mut self) -> Result<usize> {
        let now = self.rpc.timer_now();
        let today = now / 86_400;
        let roots: Vec<[u8; 64]> = self.contacts.keys().copied().collect();
        let mut removed = 0;
        for root in roots {
            let ns = msg_ns(&root);
            let mut dead = Vec::new();
            {
                let shred = Shredder::open(&self.store, &mut self.rng)?;
                for (k, b) in self.store.scan(&ns)? {
                    if b.first() != Some(&SEALED) {
                        continue;
                    }
                    match Self::decode_record(&shred, &root, &b) {
                        Some(m) if m.expires_at.is_none_or(|t| t > now) => {}
                        Some(m) => dead.push((k, Some(m))),
                        None => dead.push((k, None)),
                    }
                }
            }
            for (k, m) in dead {
                self.store.delete(&ns, &k)?;
                if let Some(m) = m {
                    self.store.delete(&id_ns(&root), &m.id)?;
                    self.index_message(
                        Conv::Contact(root),
                        m.seq,
                        (&m.search_text(), m.sealed_day()),
                        ("", None),
                    )?;
                }
                removed += 1;
            }
            let mut shred = Shredder::open(&self.store, &mut self.rng)?;
            shred.shred(conv(&root), today, &mut self.rng)?;
            self.drop_index_days(Conv::Contact(root), today)?;
        }
        Ok(removed)
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    /// Mark a conversation read: starts disappearing timers of their
    /// messages and sends read receipts (unless turned off in settings).
    pub async fn mark_read(&mut self, root: &[u8; 64]) -> Result<()> {
        let now = self.now();
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        c.unread = 0;
        let c = c.clone();
        self.save_contact(&c)?;
        let mut ids = Vec::new();
        for mut m in self
            .messages(root)?
            .into_iter()
            .filter(|m| !m.outgoing && !m.read)
        {
            m.read = true;
            if m.expires_secs > 0 && m.expires_at.is_none() {
                m.expires_at = Some(self.rpc.timer_now() + u64::from(m.expires_secs));
                // Re-seal under the new day, then drop the old record's day.
            }
            self.put_message(root, &m)?;
            ids.push(m.id);
        }
        // Read on our other devices too.
        self.queue_read(root, &ids)?;
        if self.receipts_enabled() && !ids.is_empty() && c.state == ContactState::Accepted {
            for chunk in ids.chunks(crate::content::MAX_RECEIPTS) {
                self.send_content(root, &Content::Read(chunk.to_vec()), now)
                    .await?;
            }
        }
        Ok(())
    }

    /// Set the conversation's disappearing timer (0 turns it off).
    pub async fn set_timer(&mut self, root: &[u8; 64], secs: u32) -> Result<()> {
        if secs > crate::content::MAX_TIMER {
            return Err(CoreError::TooLong);
        }
        let now = self.now();
        self.send_content(root, &Content::Timer(secs), now).await?;
        self.send_self_copy(root, &Content::Timer(secs), now)
            .await?;
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        c.timer = secs;
        let c = c.clone();
        self.save_contact(&c)
    }

    /// React to a message (empty `emoji` removes our reaction).
    pub async fn react(&mut self, root: &[u8; 64], seq: u64, emoji: &str) -> Result<()> {
        let mut m = self.get_message(root, seq)?;
        let content = Content::React {
            target: m.id,
            emoji: emoji.to_string(),
        };
        self.send_content(root, &content, self.now()).await?;
        self.send_self_copy(root, &content, self.now()).await?;
        m.reactions.retain(|r| !r.from_us);
        if !emoji.is_empty() {
            m.reactions.push(Reaction {
                from_us: true,
                emoji: emoji.to_string(),
            });
        }
        self.put_message(root, &m)
    }

    /// Edit one of our messages (within 24 hours).
    pub async fn edit_message(&mut self, root: &[u8; 64], seq: u64, text: &str) -> Result<()> {
        let now = self.now();
        let mut m = self.get_message(root, seq)?;
        if !m.outgoing
            || m.deleted
            || now.saturating_sub(m.at) > EDIT_WINDOW
            || text.len() > MAX_TEXT
        {
            return Err(CoreError::NotAccepted);
        }
        let content = Content::Edit {
            target: m.id,
            text: text.to_string(),
        };
        self.send_content(root, &content, now).await?;
        self.send_self_copy(root, &content, now).await?;
        m.text = text.to_string();
        m.edited = true;
        self.put_message(root, &m)
    }

    /// Delete one of our messages for everyone.
    pub async fn delete_for_everyone(&mut self, root: &[u8; 64], seq: u64) -> Result<()> {
        let mut m = self.get_message(root, seq)?;
        if !m.outgoing {
            return Err(CoreError::NotAccepted);
        }
        let content = Content::Delete { target: m.id };
        self.send_content(root, &content, self.now()).await?;
        self.send_self_copy(root, &content, self.now()).await?;
        wipe(&mut m);
        self.put_message(root, &m)
    }

    /// Send a file. It is sealed, padded to a size bucket and uploaded to our
    /// home server before the message that points to it is sent.
    pub async fn send_attachment(
        &mut self,
        root: &[u8; 64],
        name: &str,
        mime: &str,
        data: &[u8],
        caption: &str,
    ) -> Result<Message> {
        self.send_file_message(root, name, mime, data, caption, false)
            .await
    }

    /// Send a file to be viewed once: the recipient can open it once
    /// ([`Client::open_view_once`]) and keeps nothing; we keep no copy
    /// either, so our message only says it was sent.
    pub async fn send_view_once(
        &mut self,
        root: &[u8; 64],
        name: &str,
        mime: &str,
        data: &[u8],
        caption: &str,
    ) -> Result<Message> {
        self.send_file_message(root, name, mime, data, caption, true)
            .await
    }

    async fn send_file_message(
        &mut self,
        root: &[u8; 64],
        name: &str,
        mime: &str,
        data: &[u8],
        caption: &str,
        view_once: bool,
    ) -> Result<Message> {
        if caption.len() > MAX_TEXT {
            return Err(CoreError::TooLong);
        }
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != ContactState::Accepted {
            return Err(CoreError::NotAccepted);
        }
        let timer = c.timer;
        self.require_not_held()?;
        let now = self.now();
        let host = self.profile.server;
        let (att, chunks) = files::seal_file(data, name, mime, host, &mut self.rng)?;
        for (id, chunk) in &chunks {
            self.put_chunk(&host, *id, chunk, now).await?;
        }
        let id: MsgId = self.rng.array("core/msg-id")?;
        let mut m = self.new_message(root, id, true, caption, timer, now)?;
        if view_once {
            m.view_once = true;
        } else {
            m.attachment = Some(att.clone());
            // Keep our own copy so we never download what we sent.
            self.store
                .put(NS_FILES, &att.hash[..32], data, &mut self.rng)?;
        }
        self.put_message(root, &m)?;
        let content = Content::Attachment {
            id,
            attachment: att.encode(),
            caption: caption.to_string(),
            expires: timer,
            view_once,
        };
        let sent = self.send_tracked(root, id, &content, now).await?;
        self.send_self_copy(root, &content, now).await?;
        m.sent = sent;
        self.put_message(root, &m)?;
        Ok(m)
    }

    /// The file of a message: from the local cache, or downloaded (every
    /// chunk of its bucket, so the server learns nothing about the size),
    /// verified against its hash and cached.
    pub async fn fetch_attachment(&mut self, root: &[u8; 64], seq: u64) -> Result<Vec<u8>> {
        let m = self.get_message(root, seq)?;
        let att = m.attachment.ok_or(CoreError::NotFound)?;
        self.fetch_file(&att).await
    }

    /// Open a view-once file, once: downloaded and verified but never
    /// cached, then its reference is dropped here and on our other devices,
    /// so it can't be opened again. Screenshots and cameras remain possible;
    /// the app says so.
    pub async fn open_view_once(&mut self, root: &[u8; 64], seq: u64) -> Result<Vec<u8>> {
        let mut m = self.get_message(root, seq)?;
        let att = m.once.take().ok_or(CoreError::NotFound)?;
        // Gone before the download: a crash or a second tap can't reopen it.
        self.put_message(root, &m)?;
        self.queue_viewed(&Place::Contact(*root), m.id)?;
        let now = self.now();
        let parts = self.fetch_chunks(&att, now).await?;
        Ok(files::finish(&att, &parts)?)
    }

    /// A view-once file opened on another of our devices.
    pub(crate) fn viewed_elsewhere(&mut self, root: &[u8; 64], id: &MsgId) -> Result<bool> {
        let Ok(mut m) = self.find(root, id) else {
            return Ok(false);
        };
        if m.once.take().is_none() {
            return Ok(false);
        }
        self.put_message(root, &m)?;
        Ok(true)
    }

    /// A file's bytes: from the local cache, or downloaded (every chunk of
    /// its bucket), verified against its hash and cached.
    pub async fn fetch_file(&mut self, att: &Attachment) -> Result<Vec<u8>> {
        if let Some(b) = self.store.get(NS_FILES, &att.hash[..32])? {
            return Ok(b);
        }
        let now = self.now();
        let parts = self.fetch_chunks(att, now).await?;
        let data = files::finish(att, &parts)?;
        self.store
            .put(NS_FILES, &att.hash[..32], &data, &mut self.rng)?;
        Ok(data)
    }

    // ------------------------------------------------------------------
    // Incoming
    // ------------------------------------------------------------------

    /// Handle the content types this module owns. Returns the events and
    /// whether the content counts as a message the sender used a token for.
    pub(crate) fn on_message_content(
        &mut self,
        root: &[u8; 64],
        content: Content,
        now: u64,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let is_read = matches!(content, Content::Read(_));
        match content {
            Content::Text {
                text,
                id,
                expires,
                reply,
                forwarded,
                ..
            } => {
                self.note_receipt(root, id);
                if self.find(root, &id).is_ok() {
                    return Ok(events); // duplicate
                }
                let mut m = self.new_message(root, id, false, &text, expires, now)?;
                if reply.is_some() || forwarded {
                    m.reply_to = reply;
                    m.forwarded = forwarded;
                    self.put_message(root, &m)?;
                }
                self.bump_unread(root)?;
                events.push(Event::Message {
                    root: *root,
                    message: m,
                });
            }
            Content::Attachment {
                id,
                attachment,
                caption,
                expires,
                view_once,
            } => {
                self.note_receipt(root, id);
                if self.find(root, &id).is_ok() {
                    return Ok(events);
                }
                let att = Attachment::decode(&attachment)?;
                let mut m = self.new_message(root, id, false, &caption, expires, now)?;
                if view_once {
                    m.view_once = true;
                    m.once = Some(att);
                } else {
                    m.attachment = Some(att);
                }
                self.put_message(root, &m)?;
                self.bump_unread(root)?;
                events.push(Event::Message {
                    root: *root,
                    message: m,
                });
            }
            Content::React { target, emoji } => {
                if let Ok(mut m) = self.find(root, &target) {
                    m.reactions.retain(|r| r.from_us);
                    if !emoji.is_empty() {
                        m.reactions.push(Reaction {
                            from_us: false,
                            emoji,
                        });
                    }
                    self.put_message(root, &m)?;
                    events.push(Event::MessageChanged {
                        root: *root,
                        seq: m.seq,
                    });
                }
            }
            Content::Edit { target, text } => {
                if let Ok(mut m) = self.find(root, &target)
                    && !m.outgoing
                    && !m.deleted
                    && now.saturating_sub(m.at) <= EDIT_WINDOW
                {
                    m.text = text;
                    m.edited = true;
                    self.put_message(root, &m)?;
                    events.push(Event::MessageChanged {
                        root: *root,
                        seq: m.seq,
                    });
                }
            }
            Content::Delete { target } => {
                if let Ok(mut m) = self.find(root, &target)
                    && !m.outgoing
                {
                    wipe(&mut m);
                    self.put_message(root, &m)?;
                    events.push(Event::MessageChanged {
                        root: *root,
                        seq: m.seq,
                    });
                }
            }
            Content::Read(ids) | Content::Delivered(ids) => {
                // Read implies delivered. With our receipts off we don't
                // show theirs either (both ways, as typing indicators).
                let read = is_read && self.receipts_enabled();
                for id in ids {
                    self.outbox_done(root, &id)?;
                    if let Ok(mut m) = self.find(root, &id)
                        && m.outgoing
                        && !(m.delivered && (m.read || !read))
                    {
                        m.sent = true;
                        m.delivered = true;
                        m.stalled = false;
                        m.read |= read;
                        self.put_message(root, &m)?;
                        events.push(Event::MessageChanged {
                            root: *root,
                            seq: m.seq,
                        });
                    }
                }
            }
            Content::Timer(secs) => {
                let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
                c.timer = secs;
                let c = c.clone();
                self.save_contact(&c)?;
                events.push(Event::TimerChanged { root: *root, secs });
            }
            Content::PqStep { reply } => {
                if reply {
                    self.queue_pq_reply(root)?;
                }
            }
            Content::Typing { on } => {
                events.extend(self.on_typing(root, on));
            }
            Content::Sticker {
                id,
                pack,
                index,
                expires,
            } => {
                self.note_receipt(root, id);
                if let Some(ev) = self.on_sticker(root, id, &pack, index, expires, false, now)? {
                    self.bump_unread(root)?;
                    events.push(ev);
                }
            }
            Content::ContactShare { id, card } => {
                self.note_receipt(root, id);
                if let Some(ev) = self.on_contact_share(root, id, &card, false, now)? {
                    self.bump_unread(root)?;
                    events.push(ev);
                }
            }
            Content::Location {
                id,
                location,
                expires,
            } => {
                self.note_receipt(root, id);
                if let Some(ev) = self.on_location(root, id, &location, expires, false, now)? {
                    self.bump_unread(root)?;
                    events.push(ev);
                }
            }
            Content::Pin { target, on } => {
                let place = Place::Contact(*root);
                if self.find(root, &target).is_ok() && self.apply_pin(&place, &target, on)? {
                    events.push(Event::PinsChanged { place });
                }
            }
            Content::Poll(b) => events.extend(self.on_contact_poll(root, false, &b, now)?),
            _ => return Err(ProtoError::Decode.into()),
        }
        Ok(events)
    }

    /// Apply a copy of something another of our devices sent to `to`.
    pub(crate) fn on_self_copy(
        &mut self,
        to: &[u8; 64],
        inner: &[u8],
        now: u64,
    ) -> Result<Vec<Event>> {
        if *to == self.account.root_public.0 {
            let changed = self.on_note_copy(Content::decode(inner)?, now)?;
            return Ok(if changed {
                vec![Event::NotesChanged]
            } else {
                Vec::new()
            });
        }
        if !self.contacts.contains_key(to) {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        match Content::decode(inner)? {
            Content::Text {
                text,
                id,
                expires,
                reply,
                forwarded,
                ..
            } => {
                if self.find(to, &id).is_err() {
                    let mut m = self.new_message(to, id, true, &text, expires, now)?;
                    m.sent = true;
                    m.reply_to = reply;
                    m.forwarded = forwarded;
                    self.put_message(to, &m)?;
                    events.push(Event::Message {
                        root: *to,
                        message: m,
                    });
                }
            }
            Content::Attachment {
                id,
                attachment,
                caption,
                expires,
                view_once,
            } => {
                if self.find(to, &id).is_err() {
                    let mut m = self.new_message(to, id, true, &caption, expires, now)?;
                    // Sent as view once from another of our devices: nothing
                    // to open here either.
                    m.view_once = view_once;
                    if !view_once {
                        m.attachment = Some(Attachment::decode(&attachment)?);
                    }
                    m.sent = true;
                    self.put_message(to, &m)?;
                    events.push(Event::Message {
                        root: *to,
                        message: m,
                    });
                }
            }
            Content::React { target, emoji } => {
                if let Ok(mut m) = self.find(to, &target) {
                    m.reactions.retain(|r| !r.from_us);
                    if !emoji.is_empty() {
                        m.reactions.push(Reaction {
                            from_us: true,
                            emoji,
                        });
                    }
                    self.put_message(to, &m)?;
                    events.push(Event::MessageChanged {
                        root: *to,
                        seq: m.seq,
                    });
                }
            }
            Content::Edit { target, text } => {
                if let Ok(mut m) = self.find(to, &target)
                    && m.outgoing
                {
                    m.text = text;
                    m.edited = true;
                    self.put_message(to, &m)?;
                    events.push(Event::MessageChanged {
                        root: *to,
                        seq: m.seq,
                    });
                }
            }
            Content::Delete { target } => {
                if let Ok(mut m) = self.find(to, &target)
                    && m.outgoing
                {
                    wipe(&mut m);
                    self.put_message(to, &m)?;
                    events.push(Event::MessageChanged {
                        root: *to,
                        seq: m.seq,
                    });
                }
            }
            Content::ModeChange { on_record, seq } => {
                events.extend(self.on_mode_change(to, on_record, seq, true)?);
            }
            Content::Timer(secs) => {
                let c = self.contacts.get_mut(to).ok_or(CoreError::NotFound)?;
                c.timer = secs;
                let c = c.clone();
                self.save_contact(&c)?;
                events.push(Event::TimerChanged { root: *to, secs });
            }
            Content::ContactShare { id, card } => {
                events.extend(self.on_contact_share(to, id, &card, true, now)?);
            }
            Content::Sticker {
                id,
                pack,
                index,
                expires,
            } => {
                events.extend(self.on_sticker(to, id, &pack, index, expires, true, now)?);
            }
            Content::Location {
                id,
                location,
                expires,
            } => {
                events.extend(self.on_location(to, id, &location, expires, true, now)?);
            }
            Content::Pin { target, on } => {
                let place = Place::Contact(*to);
                if self.find(to, &target).is_ok() && self.apply_pin(&place, &target, on)? {
                    events.push(Event::PinsChanged { place });
                }
            }
            Content::Poll(b) => events.extend(self.on_contact_poll(to, true, &b, now)?),
            _ => {}
        }
        Ok(events)
    }

    pub(crate) fn bump_unread(&mut self, root: &[u8; 64]) -> Result<()> {
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        c.unread = c.unread.saturating_add(1);
        let c = c.clone();
        self.save_contact(&c)?;
        self.unarchive_on_message(&Place::Contact(*root))
    }
}

pub(crate) fn wipe(m: &mut Message) {
    m.deleted = true;
    m.location = None;
    m.sticker = None;
    m.text.clear();
    m.attachment = None;
    m.reactions.clear();
}

impl crate::rpc::Rpc {
    /// Upload one blob chunk under an allocation (`client/blobs.rs`).
    pub(crate) async fn blob_put(
        &mut self,
        server: &[u8; 16],
        id: [u8; 32],
        chunk: &[u8],
        alloc: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let h = RequestHeader {
            op: Op::BlobPut,
            flags: 0,
            mailbox: id,
            token: alloc,
        };
        match self.call(server, h, chunk, now, rng).await?.status {
            Status::Ok => Ok(()),
            s => Err(CoreError::Server(s)),
        }
    }

    /// A `BlobAlloc` request: issue (`mailbox` and `token` an inbox here
    /// and its owner secret), redeem or ask the key (random ones).
    pub(crate) async fn blob_alloc(
        &mut self,
        server: &[u8; 16],
        mailbox: [u8; 32],
        token: [u8; 32],
        req: &enclave_rpc::api::BlobAlloc,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<enclave_rpc::api::BlobAllocReply> {
        let env = enclave_rpc::api::frame(&req.encode(), rng)?;
        let h = RequestHeader {
            op: Op::BlobAlloc,
            flags: 0,
            mailbox,
            token,
        };
        let r = self.call(server, h, &env, now, rng).await?;
        if r.status != Status::Ok {
            return Err(CoreError::Server(r.status));
        }
        let p = enclave_rpc::api::unframe(&r.envelope)?;
        Ok(enclave_rpc::api::BlobAllocReply::decode(p)?)
    }

    /// Download one blob chunk.
    pub(crate) async fn blob_get(
        &mut self,
        server: &[u8; 16],
        id: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<u8>> {
        let h = RequestHeader {
            op: Op::BlobGet,
            flags: 0,
            mailbox: id,
            token: [0; 32],
        };
        Ok(self.call_ok(server, h, &[], now, rng).await?.envelope)
    }
}
