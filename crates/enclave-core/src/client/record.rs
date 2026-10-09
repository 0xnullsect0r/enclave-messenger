//! On the record (`docs/05-ratchet.md` §9, RT-07).
//!
//! A conversation is off the record (deniable) until either person puts it
//! on. A [`Content::ModeChange`] tells the other side and our other devices;
//! it is authenticated like any content of the session, so nobody outside
//! the conversation can switch its mode, and both sides show who changed it
//! ([`Event::ModeChanged`]). Changes are numbered: the higher number wins,
//! and of two with the same number (both changed at once) "off" wins.
//!
//! While on, everything a person writes ([`Content::is_personal`]) goes as
//! [`Content::Signed`]: the encoded content, with any write tokens taken out
//! (they ride beside it), and the sending device's composite signature over
//! [`otr::message_payload`] (the conversation id, the device, the
//! recipient's root hash, the device's counter in this conversation, the
//! mode and SHA3-512 of the content). The receiver checks it against that
//! device's entry in the sender's manifest. Personal content that arrives
//! unsigned in a conversation on the record, or whose signature fails, is
//! still shown but marked "Not signed" (`Message::signed`). Each verified
//! signature is kept in its message's record (`Message::evidence`, sealed
//! and shredded with it), so a report can carry it
//! (`docs/13-operators.md` §2).

use super::{Client, Event};
use crate::content::Content;
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::otr;

const NS_RECORD: &str = "on-record";

/// A conversation's mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Record {
    /// On the record.
    pub on: bool,
    /// The latest change's number.
    pub seq: u32,
    /// Messages this device has signed in the conversation.
    pub counter: u64,
}

/// A message's signature, kept for a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// The sending device.
    pub device: [u8; 16],
    /// Its counter.
    pub counter: u64,
    /// The composite signature.
    pub sig: Vec<u8>,
    /// The signed content (encoded).
    pub content: Vec<u8>,
}

impl Evidence {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.device)
            .u64(self.counter)
            .bytes(&self.sig)
            .bytes(&self.content);
        w.finish()
    }

    pub(crate) fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        let e = Self {
            device: r.array()?,
            counter: r.u64()?,
            sig: r.bytes(crate::content::MAX_SIG)?.to_vec(),
            content: r.bytes(crate::content::MAX_SPLIT_CONTENT)?.to_vec(),
        };
        r.end()?;
        Ok(e)
    }
}

impl Client {
    /// Whether the conversation with `root` is on the record.
    pub fn on_the_record(&self, root: &[u8; 64]) -> bool {
        self.record(root).is_ok_and(|r| r.on)
    }

    pub(crate) fn record(&self, root: &[u8; 64]) -> Result<Record> {
        let Some(b) = self.store.get(NS_RECORD, root)? else {
            return Ok(Record::default());
        };
        let mut r = Reader::new(&b);
        let rec = Record {
            on: r.u8()? == 1,
            seq: r.u32()?,
            counter: r.u64()?,
        };
        r.end()?;
        Ok(rec)
    }

    fn save_record(&mut self, root: &[u8; 64], rec: &Record) -> Result<()> {
        let mut w = Writer::new();
        w.u8(u8::from(rec.on)).u32(rec.seq).u64(rec.counter);
        self.store
            .put(NS_RECORD, root, &w.finish(), &mut self.rng)?;
        Ok(())
    }

    /// Put the conversation with `root` on the record, or take it off.
    pub async fn set_on_the_record(&mut self, root: &[u8; 64], on: bool) -> Result<()> {
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != super::ContactState::Accepted {
            return Err(CoreError::NotAccepted);
        }
        let mut rec = self.record(root)?;
        if rec.on == on {
            return Ok(());
        }
        rec.on = on;
        rec.seq = rec.seq.saturating_add(1);
        self.save_record(root, &rec)?;
        let now = self.now();
        let change = Content::ModeChange {
            on_record: on,
            seq: rec.seq,
        };
        self.send_content(root, &change, now).await?;
        self.send_self_copy(root, &change, now).await?;
        Ok(())
    }

    /// A `ModeChange` from `root` (`by_us`: from another device of ours).
    pub(crate) fn on_mode_change(
        &mut self,
        root: &[u8; 64],
        on: bool,
        seq: u32,
        by_us: bool,
    ) -> Result<Vec<Event>> {
        let mut rec = self.record(root)?;
        // The higher number wins; at the same number, off wins.
        let wins = seq > rec.seq || (seq == rec.seq && !on && rec.on);
        if !wins {
            return Ok(Vec::new());
        }
        let changed = rec.on != on;
        rec.on = on;
        rec.seq = seq;
        self.save_record(root, &rec)?;
        Ok(if changed {
            vec![Event::ModeChanged {
                root: *root,
                on_record: on,
                by_us,
            }]
        } else {
            Vec::new()
        })
    }

    /// `content` as it goes to `root`: signed if the conversation is on
    /// the record and a person wrote it.
    pub(crate) fn sign_for(&mut self, root: &[u8; 64], content: &Content) -> Result<Content> {
        if !content.is_personal() {
            return Ok(content.clone());
        }
        let mut rec = self.record(root)?;
        if !rec.on {
            return Ok(content.clone());
        }
        rec.counter = rec.counter.saturating_add(1);
        self.save_record(root, &rec)?;
        let mut inner = content.clone();
        let tokens = inner.take_tokens();
        let bytes = inner.encode()?;
        let conv = otr::conv_id(&self.account.root_public.0, root);
        let payload = otr::message_payload(&conv, &self.device.id, root, rec.counter, &bytes);
        let sig = otr::sign(
            &self.device.signing,
            otr::Kind::Message,
            &payload,
            &mut self.rng,
        )?;
        Ok(Content::Signed {
            counter: rec.counter,
            sig,
            content: bytes,
            tokens,
        })
    }

    /// Signed content from `root`'s device `dev`: the content, with its
    /// tokens back, and the signature if it checks against their manifest.
    pub(crate) fn open_signed(
        &self,
        root: &[u8; 64],
        dev: &[u8; 16],
        counter: u64,
        sig: Vec<u8>,
        content: Vec<u8>,
        tokens: Vec<[u8; 32]>,
    ) -> Result<(Content, Option<Evidence>)> {
        let mut inner = Content::decode(&content)?;
        if !inner.is_personal() {
            return Err(CoreError::Proto(enclave_proto::ProtoError::Decode));
        }
        let evidence = self
            .check_signature(root, dev, counter, &sig, &content)
            .then_some(Evidence {
                device: *dev,
                counter,
                sig,
                content,
            });
        inner.put_tokens(tokens);
        Ok((inner, evidence))
    }

    fn check_signature(
        &self,
        root: &[u8; 64],
        dev: &[u8; 16],
        counter: u64,
        sig: &[u8],
        content: &[u8],
    ) -> bool {
        let Some(c) = self.contacts.get(root) else {
            return false;
        };
        let Some(d) = c.manifest.devices.iter().find(|d| &d.id == dev) else {
            return false;
        };
        let conv = otr::conv_id(root, &self.account.root_public.0);
        let payload =
            otr::message_payload(&conv, dev, &self.account.root_public.0, counter, content);
        otr::verify(&d.signing, otr::Kind::Message, &payload, sig).is_ok()
    }

    /// Forget the conversation's mode (the contact was removed).
    pub(crate) fn forget_record(&mut self, root: &[u8; 64]) -> Result<()> {
        self.store.delete(NS_RECORD, root)?;
        Ok(())
    }
}
