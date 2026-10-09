//! Notification keys and capsules (`docs/10-push.md` §4).
//!
//! Every direct envelope carries a 1,024-byte capsule. It is random bytes
//! unless the recipient asked for previews: then the sender seals its name
//! and up to 600 bytes of preview under the day's notification key, which
//! only the recipient's devices (and their iOS notification extension) can
//! open. Neither the server nor Apple can tell a filled capsule from an
//! empty one.
//!
//! The recipient gives each contact a chain root `nk_0` (with the day it
//! starts on); both step it daily, `nk_d = KMAC256(nk_{d−1}, u32(d),
//! "enclave/v1/proto/notify-key")`, and forget old keys. A group's key for
//! a day is `KMAC256(epoch_secret, u32(d), "enclave/v1/proto/grp-notify")`.

use crate::codec::{Reader, Writer};
use crate::{ProtoError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use zeroize::Zeroizing;

/// Capsule length.
pub const CAPSULE_LEN: usize = enclave_wire::CAPSULE_LEN;
/// Longest sender name in a capsule (bytes).
pub const MAX_NAME: usize = 64;
/// Longest preview in a capsule (bytes).
pub const MAX_PREVIEW: usize = 600;
/// Most days a chain is stepped at once (a contact silent for longer
/// starts again from the key it was given).
pub const MAX_STEPS: u32 = 400;

const L_STEP: &str = "enclave/v1/proto/notify-key";
const L_GROUP: &str = "enclave/v1/proto/grp-notify";
const AD: &[u8] = b"enclave/v1/wire/ad-capsule";

/// One step of a contact's chain: day `day`'s key from the day before's.
pub fn step(key: &[u8; 32], day: u32) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(key, &day.to_be_bytes(), L_STEP)
}

/// A chain position: the key for `day`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    /// The day of `key`.
    pub day: u32,
    /// That day's key.
    pub key: [u8; 32],
}

impl Chain {
    /// The key for `day`, stepping forward (a past day: `None`, its key is
    /// gone).
    pub fn key_for(&self, day: u32) -> Option<[u8; 32]> {
        if day < self.day || day - self.day > MAX_STEPS {
            return None;
        }
        let mut k = self.key;
        for d in self.day + 1..=day {
            k = step(&k, d);
        }
        Some(k)
    }

    /// Move to `day`, forgetting earlier keys.
    pub fn advance(&mut self, day: u32) -> bool {
        match self.key_for(day) {
            Some(k) => {
                self.key = k;
                self.day = day;
                true
            }
            None => false,
        }
    }

    /// `u32 day ‖ key`.
    pub fn encode(&self) -> Vec<u8> {
        [&self.day.to_be_bytes()[..], &self.key].concat()
    }

    /// Inverse of [`Chain::encode`].
    pub fn decode(b: &[u8]) -> Option<Self> {
        Some(Self {
            day: u32::from_be_bytes(b.get(..4)?.try_into().ok()?),
            key: b.get(4..36)?.try_into().ok()?,
        })
    }
}

/// A group's notification key for `day`.
pub fn group_key(epoch_secret: &[u8; 32], day: u32) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(epoch_secret, &day.to_be_bytes(), L_GROUP)
}

fn ad(day: u32) -> Vec<u8> {
    [AD, &day.to_be_bytes()].concat()
}

/// The longest prefix of `s` within `max` bytes, cut at a character.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Seal `name` and `preview` (cut to [`MAX_NAME`] and [`MAX_PREVIEW`]
/// bytes) under `key` for `day`.
pub fn seal_capsule(
    key: &[u8; 32],
    day: u32,
    name: &str,
    preview: &str,
    rng: &mut HedgedRng,
) -> Result<[u8; CAPSULE_LEN]> {
    let (name, preview) = (cut(name, MAX_NAME), cut(preview, MAX_PREVIEW));
    let mut w = Writer::new();
    w.u8(name.len() as u8)
        .fixed(name.as_bytes())
        .u16(preview.len() as u16)
        .fixed(preview.as_bytes());
    let mut pt = Zeroizing::new(w.finish());
    pt.resize(CAPSULE_LEN - seal::OVERHEAD, 0);
    let sealed = seal::seal(&SealKey::from_bytes(*key), &ad(day), &pt, rng)?;
    sealed.try_into().map_err(|_| ProtoError::Decode)
}

/// Open a capsule sealed under `key` for `day`: the sender's name and the
/// preview.
pub fn open_capsule(key: &[u8; 32], day: u32, capsule: &[u8]) -> Option<(String, String)> {
    let pt = Zeroizing::new(seal::open(&SealKey::from_bytes(*key), &ad(day), capsule).ok()?);
    let mut r = Reader::new(&pt);
    let n = usize::from(r.u8().ok()?);
    let name = String::from_utf8(r.fixed(n).ok()?.to_vec()).ok()?;
    let p = usize::from(r.u16().ok()?);
    let preview = String::from_utf8(r.fixed(p).ok()?.to_vec()).ok()?;
    Some((name, preview))
}

/// What the notification extension holds (`10-push.md` §5.1): for each
/// conversation a label (shown if the capsule's name is empty) and its keys
/// for `day` and the day before. No ratchet or identity key is in it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyTable {
    /// The day the keys are for.
    pub day: u32,
    /// `(label, today's key, yesterday's key)`.
    pub entries: Vec<(String, [u8; 32], Option<[u8; 32]>)>,
}

impl KeyTable {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.day).u32(self.entries.len() as u32);
        for (label, today, yesterday) in &self.entries {
            w.bytes(label.as_bytes()).fixed(today);
            match yesterday {
                Some(y) => w.u8(1).fixed(y),
                None => w.u8(0),
            };
        }
        w.finish()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let day = r.u32()?;
        let n = r.u32()? as usize;
        if n > 100_000 {
            return Err(ProtoError::Limit);
        }
        let mut entries = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let label =
                String::from_utf8(r.bytes(256)?.to_vec()).map_err(|_| ProtoError::Decode)?;
            let today = r.array()?;
            let yesterday = match r.u8()? {
                1 => Some(r.array()?),
                _ => None,
            };
            entries.push((label, today, yesterday));
        }
        r.end()?;
        Ok(Self { day, entries })
    }

    /// Try every key on `capsule` (the extension's algorithm): the name to
    /// show (the capsule's, or the conversation's label) and the preview.
    pub fn open(&self, capsule: &[u8]) -> Option<(String, String)> {
        for (label, today, yesterday) in &self.entries {
            // The sender's day may be ahead of ours (clocks around
            // midnight): tomorrow's key follows from today's.
            let tomorrow = self.day.wrapping_add(1);
            let tries = [
                (Some(*today), self.day),
                (*yesterday, self.day.wrapping_sub(1)),
                (Some(step(today, tomorrow)), tomorrow),
            ];
            for (k, d) in tries {
                if let Some(k) = k
                    && let Some((name, preview)) = open_capsule(&k, d, capsule)
                {
                    let name = if name.is_empty() { label.clone() } else { name };
                    return Some((name, preview));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsules() {
        let mut rng = HedgedRng::new().unwrap();
        let root = [7u8; 32];
        let chain = Chain {
            day: 100,
            key: root,
        };
        let k102 = chain.key_for(102).unwrap();
        assert_eq!(k102, step(&step(&root, 101), 102));
        let mut c = chain.clone();
        assert!(c.advance(102));
        assert_eq!(c.key, k102);
        assert_eq!(c.key_for(101), None, "yesterday's is gone");
        assert_eq!(Chain::decode(&c.encode()), Some(c));

        let long = "é".repeat(400);
        let cap = seal_capsule(&k102, 102, "Ben", &long, &mut rng).unwrap();
        assert_eq!(cap.len(), CAPSULE_LEN);
        let (name, preview) = open_capsule(&k102, 102, &cap).unwrap();
        assert_eq!(name, "Ben");
        assert_eq!(preview.len(), MAX_PREVIEW, "cut at a character");
        assert!(open_capsule(&k102, 103, &cap).is_none(), "the day is bound");
        assert!(open_capsule(&[8; 32], 102, &cap).is_none());
        let mut random = [0u8; CAPSULE_LEN];
        rng.fill("test", &mut random).unwrap();
        assert!(open_capsule(&k102, 102, &random).is_none());

        let g = group_key(&[3; 32], 102);
        assert_ne!(g, group_key(&[3; 32], 103));

        // The extension's table: yesterday's key still opens.
        let cap = seal_capsule(&chain.key_for(101).unwrap(), 101, "", "late", &mut rng).unwrap();
        let t = KeyTable {
            day: 102,
            entries: vec![
                ("Cy".into(), [1; 32], None),
                ("Ben".into(), k102, chain.key_for(101)),
            ],
        };
        let t = KeyTable::decode(&t.encode()).unwrap();
        assert_eq!(t.open(&cap), Some(("Ben".into(), "late".into())));
        assert_eq!(t.open(&random), None);
    }
}
