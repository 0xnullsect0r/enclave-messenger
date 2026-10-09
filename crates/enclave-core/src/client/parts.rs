//! Continuation units: content larger than one envelope
//! (`docs/08-envelope.md` §5.6).
//!
//! Content whose encoding doesn't fit one direct envelope (with room left
//! for receipts, gossip and, on the record, a signature) travels as
//! `Content::Part`s: the same random id, an index and a total, and a slice
//! of the encoded content each, at most [`MAX_PARTS`] of them (64 KiB).
//! Each part is an ordinary envelope with its own write token, so the
//! server sees units like any others. The receiver keeps parts in the
//! sealed store until all have arrived, then handles the whole as if it
//! had come in one envelope; parts of content that never completes are
//! dropped after [`PART_TTL_SECS`].

use super::Client;
use crate::Result;
use crate::content::{Content, MsgId};
use enclave_proto::codec::{Reader, Writer};

const NS_PARTS: &str = "parts";

/// Most parts of one content.
pub const MAX_PARTS: usize = 8;
/// Bytes of encoded content in one part.
pub const PART_LEN: usize = 8_192;
/// Largest content sent in parts.
pub const MAX_SPLIT: usize = MAX_PARTS * PART_LEN;
/// Parts of content that hasn't completed are dropped after this long.
pub const PART_TTL_SECS: u64 = 7 * 86_400;

/// Split encoded `bytes` into parts, if it's longer than `limit`.
pub(crate) fn split(bytes: &[u8], limit: usize, id: MsgId) -> Option<Vec<Content>> {
    if bytes.len() <= limit || bytes.len() > MAX_SPLIT {
        return None;
    }
    let per = PART_LEN.min(limit);
    let total = bytes.len().div_ceil(per);
    if total > MAX_PARTS {
        return None;
    }
    Some(
        bytes
            .chunks(per)
            .enumerate()
            .map(|(i, c)| Content::Part {
                id,
                index: i as u8,
                total: total as u8,
                data: c.to_vec(),
            })
            .collect(),
    )
}

fn key(root: &[u8; 64], id: &MsgId) -> Vec<u8> {
    [&root[..], &id[..]].concat()
}

impl Client {
    /// A part from `root`: kept, and when it completes its content, the
    /// whole content's encoding.
    pub(crate) fn take_part(
        &mut self,
        root: &[u8; 64],
        id: MsgId,
        index: u8,
        total: u8,
        data: &[u8],
        now: u64,
    ) -> Result<Option<Vec<u8>>> {
        let total = usize::from(total);
        if !(2..=MAX_PARTS).contains(&total) || usize::from(index) >= total || data.len() > PART_LEN
        {
            return Ok(None);
        }
        let k = key(root, &id);
        // `u64 first seen ‖ u8 total ‖ total × bytes(part or empty)`.
        let mut parts: Vec<Vec<u8>> = vec![Vec::new(); total];
        let mut since = now;
        if let Some(b) = self.store.get(NS_PARTS, &k)? {
            let mut r = Reader::new(&b);
            since = r.u64()?;
            if usize::from(r.u8()?) != total {
                return Ok(None);
            }
            for p in parts.iter_mut() {
                *p = r.bytes(PART_LEN)?.to_vec();
            }
        }
        parts[usize::from(index)] = data.to_vec();
        if parts.iter().all(|p| !p.is_empty()) {
            self.store.delete(NS_PARTS, &k)?;
            return Ok(Some(parts.concat()));
        }
        let mut w = Writer::new();
        w.u64(since).u8(total as u8);
        for p in &parts {
            w.bytes(p);
        }
        self.store.put(NS_PARTS, &k, &w.finish(), &mut self.rng)?;
        Ok(None)
    }

    /// Drop parts of content that never completed.
    pub(crate) fn expire_parts(&mut self, now: u64) -> Result<()> {
        for (k, v) in self.store.scan(NS_PARTS)? {
            let since = v
                .get(..8)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u64::from_be_bytes);
            if since.saturating_add(PART_TTL_SECS) < now {
                self.store.delete(NS_PARTS, &k)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_sizes() {
        assert!(split(&[1; 100], 9_000, [0; 16]).is_none(), "fits");
        let parts = split(&vec![7; 20_000], 9_000, [1; 16]).unwrap();
        assert_eq!(parts.len(), 3);
        assert!(
            split(&vec![7; MAX_SPLIT + 1], 9_000, [1; 16]).is_none(),
            "too long"
        );
        let small = split(&vec![7; 9_000], 4_000, [1; 16]).unwrap();
        assert_eq!(small.len(), 3, "on the record, parts are smaller");
    }
}
