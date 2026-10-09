//! Archive, pin to the top and mute, per conversation
//! (`docs/16-features.md`; `docs/06-multidevice.md` §5).
//!
//! These are local choices about how this device lists a conversation; the
//! other people in it never learn them. A new message from someone brings
//! an archived conversation back, unless it is muted. At most
//! [`MAX_PINNED_CONVERSATIONS`] stay pinned to the top.
//!
//! Not synced between our own devices yet: each device keeps its own.

use super::Client;
use super::search::Place;
use crate::{CoreError, Result};
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};

pub(crate) const NS_PREFS: &str = "conv-prefs";
/// Most conversations pinned to the top.
pub const MAX_PINNED_CONVERSATIONS: usize = 4;

/// How this device lists a conversation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConvPrefs {
    /// Out of the main list until a new message arrives (unless muted).
    pub archived: bool,
    /// Listed above the others.
    pub pinned: bool,
    /// New messages don't count toward attention (and don't unarchive).
    pub muted: bool,
}

impl ConvPrefs {
    fn encode(self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(u8::from(self.archived) | u8::from(self.pinned) << 1 | u8::from(self.muted) << 2);
        w.finish()
    }

    fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        let f = r.u8()?;
        r.end()?;
        if f & !0b111 != 0 {
            return Err(ProtoError::Decode);
        }
        Ok(Self {
            archived: f & 1 != 0,
            pinned: f & 2 != 0,
            muted: f & 4 != 0,
        })
    }
}

fn key(place: &Place) -> Vec<u8> {
    match place {
        Place::Contact(r) => [&b"c"[..], &r[..]].concat(),
        Place::Group(g) => [&b"g"[..], &g[..]].concat(),
    }
}

impl Client {
    /// How this device lists a conversation.
    pub fn conv_prefs(&self, place: &Place) -> ConvPrefs {
        match self.store.get(NS_PREFS, &key(place)) {
            Ok(Some(b)) => ConvPrefs::decode(&b).unwrap_or_default(),
            _ => ConvPrefs::default(),
        }
    }

    /// Change how this device lists a conversation. Pinning a fifth
    /// conversation is refused ([`CoreError::TooLong`]).
    pub fn set_conv_prefs(&mut self, place: &Place, prefs: ConvPrefs) -> Result<()> {
        if prefs.pinned && !self.conv_prefs(place).pinned {
            let pinned = self
                .store
                .scan(NS_PREFS)?
                .into_iter()
                .filter(|(_, b)| ConvPrefs::decode(b).is_ok_and(|p| p.pinned))
                .count();
            if pinned >= MAX_PINNED_CONVERSATIONS {
                return Err(CoreError::TooLong);
            }
        }
        if prefs == ConvPrefs::default() {
            self.store.delete(NS_PREFS, &key(place))?;
        } else {
            self.store
                .put(NS_PREFS, &key(place), &prefs.encode(), &mut self.rng)?;
        }
        // The same on our other devices (`own_sync.rs`).
        self.queue_own(super::own_sync::SyncItem::Prefs {
            place: key(place),
            prefs: prefs.encode(),
        })
    }

    /// Another device of ours changed how a conversation is listed. A pin
    /// past the limit here is dropped (the archive and mute still apply).
    pub(crate) fn apply_synced_prefs(&mut self, place: &[u8], prefs: &[u8]) -> Result<()> {
        if !matches!(place.first(), Some(b'c' | b'g')) {
            return Ok(());
        }
        let Ok(mut p) = ConvPrefs::decode(prefs) else {
            return Ok(());
        };
        if p.pinned {
            let pinned = self
                .store
                .scan(NS_PREFS)?
                .into_iter()
                .filter(|(k, b)| k != place && ConvPrefs::decode(b).is_ok_and(|p| p.pinned))
                .count();
            if pinned >= MAX_PINNED_CONVERSATIONS {
                p.pinned = false;
            }
        }
        if p == ConvPrefs::default() {
            self.store.delete(NS_PREFS, place)?;
        } else {
            self.store
                .put(NS_PREFS, place, &p.encode(), &mut self.rng)?;
        }
        Ok(())
    }

    /// Someone else's message arrived in `place`: bring it back from the
    /// archive unless it is muted.
    pub(crate) fn unarchive_on_message(&mut self, place: &Place) -> Result<()> {
        let p = self.conv_prefs(place);
        if p.archived && !p.muted {
            self.set_conv_prefs(
                place,
                ConvPrefs {
                    archived: false,
                    ..p
                },
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn codec() {
        for f in 0..8u8 {
            let p = ConvPrefs {
                archived: f & 1 != 0,
                pinned: f & 2 != 0,
                muted: f & 4 != 0,
            };
            assert_eq!(ConvPrefs::decode(&p.encode()).unwrap(), p);
        }
        assert!(ConvPrefs::decode(&[8]).is_err());
        assert!(ConvPrefs::decode(&[1, 0]).is_err());
    }
}
