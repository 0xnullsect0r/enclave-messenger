//! Encrypted backups (`docs/14-storage.md` §4).
//!
//! A backup is every record of the chosen namespaces outside the excluded
//! ones (ratchet sessions, sender keys, shred keyring, prekeys), sealed
//! under a key derived from the 256-bit recovery secret. Restoring onto a
//! new device re-establishes sessions; old session state never comes back,
//! so a restored backup cannot cause key reuse.
//!
//! An archive (version 2) is
//!
//! ```text
//! "ENCLBAK2" ‖ u64 sequence ‖ u64 created ‖ u8 flags (1: media) ‖ SealChunked(key, "enclave-backup-v2" ‖ header, records)
//! records = (u32 len ‖ namespace ‖ u32 len ‖ key ‖ u32 len ‖ value)*
//! ```
//!
//! The header is readable without the key (to say which backup a file is)
//! and bound into the sealing. Archives from before (no header, AD
//! `"enclave-backup-v1"`) still import.

use crate::store::{Store, open_chunked, seal_chunked};
use crate::{Result, StoreError};
use enclave_crypto::kmac::kmac256;
use enclave_crypto::labels;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::SealKey;

/// Namespaces that are never backed up.
pub const EXCLUDED: &[&str] = &["sessions", "sender-keys", "__shred", "prekeys"];

/// The backup key: `KMAC256(recovery, "", 256, "enclave/v1/backup/key")`.
pub fn backup_key(recovery: &[u8; 32]) -> SealKey {
    SealKey::from_bytes(kmac256(recovery, b"", labels::BACKUP_KEY))
}

const MAGIC: &[u8; 8] = b"ENCLBAK2";
const HEADER_LEN: usize = 8 + 8 + 8 + 1;
const AD_V1: &[u8] = b"enclave-backup-v1";
const AD_V2: &[u8] = b"enclave-backup-v2";

/// What a version 2 archive says about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Counts up with every backup the account makes.
    pub sequence: u64,
    /// When it was made (Unix seconds).
    pub created_at: u64,
    /// Photos and files are in it.
    pub media: bool,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..8].copy_from_slice(MAGIC);
        h[8..16].copy_from_slice(&self.sequence.to_be_bytes());
        h[16..24].copy_from_slice(&self.created_at.to_be_bytes());
        h[24] = u8::from(self.media);
        h
    }
}

/// The header of an archive, read without the key (`None`: an archive
/// from before headers, or not an archive).
pub fn header(archive: &[u8]) -> Option<Header> {
    let h = archive.get(..HEADER_LEN)?;
    if &h[..8] != MAGIC || h[24] > 1 {
        return None;
    }
    Some(Header {
        sequence: u64::from_be_bytes(h[8..16].try_into().ok()?),
        created_at: u64::from_be_bytes(h[16..24].try_into().ok()?),
        media: h[24] == 1,
    })
}

/// One record of an archive: namespace, key, value.
pub type Record = (String, Vec<u8>, Vec<u8>);

/// Export the listed namespaces into an encrypted archive.
pub fn export(
    store: &Store,
    namespaces: &[&str],
    key: &SealKey,
    header: &Header,
    rng: &mut HedgedRng,
) -> Result<Vec<u8>> {
    let mut pt = zeroize::Zeroizing::new(Vec::new());
    for ns in namespaces {
        if EXCLUDED.contains(ns) {
            continue;
        }
        for (k, v) in store.scan(ns)? {
            for part in [ns.as_bytes(), &k, &v] {
                pt.extend_from_slice(&(part.len() as u32).to_be_bytes());
                pt.extend_from_slice(part);
            }
        }
    }
    let h = header.encode();
    let ad = [AD_V2, &h[..]].concat();
    let sealed = seal_chunked(key, &ad, &pt, rng)?;
    Ok([&h[..], &sealed].concat())
}

/// Open an archive: its header (none for one from before headers) and
/// records, excluded namespaces left out.
pub fn read(archive: &[u8], key: &SealKey) -> Result<(Option<Header>, Vec<Record>)> {
    let (hdr, pt) = match header(archive) {
        Some(h) => {
            let ad = [AD_V2, &h.encode()[..]].concat();
            (Some(h), open_chunked(key, &ad, &archive[HEADER_LEN..])?)
        }
        None => (None, open_chunked(key, AD_V1, archive)?),
    };
    let pt = zeroize::Zeroizing::new(pt);
    let mut off = 0usize;
    let next = |off: &mut usize| -> Result<Vec<u8>> {
        let l = u32::from_be_bytes(
            pt.get(*off..*off + 4)
                .ok_or(StoreError::Malformed)?
                .try_into()
                .map_err(|_| StoreError::Malformed)?,
        ) as usize;
        *off += 4;
        let v = pt
            .get(*off..*off + l)
            .ok_or(StoreError::Malformed)?
            .to_vec();
        *off += l;
        Ok(v)
    };
    let mut out = Vec::new();
    while off < pt.len() {
        let ns = String::from_utf8(next(&mut off)?).map_err(|_| StoreError::Malformed)?;
        let k = next(&mut off)?;
        let v = next(&mut off)?;
        if !EXCLUDED.contains(&ns.as_str()) {
            out.push((ns, k, v));
        }
    }
    Ok((hdr, out))
}

/// Import an archive into `store`: its header and how many records.
pub fn import(
    store: &Store,
    archive: &[u8],
    key: &SealKey,
    rng: &mut HedgedRng,
) -> Result<(Option<Header>, usize)> {
    let (hdr, records) = read(archive, key)?;
    for (ns, k, v) in &records {
        store.put(ns, k, v, rng)?;
    }
    Ok((hdr, records.len()))
}
