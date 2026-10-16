//! Enclave fixed-layout wire formats (`docs/08-envelope.md`).
//!
//! Every object that crosses the network has one of a few fixed sizes, so an
//! observer learns nothing from lengths:
//!
//! | Object                     | Size (bytes) |
//! |----------------------------|--------------|
//! | Wire unit (request/reply)  | 16,384       |
//! | Stored envelope / blob chunk | 14,336     |
//! | Poll request               | 2,048        |
//!
//! This crate only frames bytes. Sealing happens in `enclave-proto` with
//! EnclaveSeal; the constants here reserve exactly the space that sealing adds
//! (`SEAL_OVERHEAD`) so the arithmetic is checked at compile time.
//!
//! Wire unit layout:
//!
//! | Offset | Len    | Field                                          |
//! |--------|--------|------------------------------------------------|
//! | 0      | 2      | version (u16 BE)                               |
//! | 2      | 2      | suite (u16 BE)                                 |
//! | 4      | 56     | X448 ephemeral public key (server seal)        |
//! | 60     | 1,568  | ML-KEM-1024 ciphertext (server seal)           |
//! | 1,628  | 14,472 | sealed(request header 72 ‖ envelope 14,336)    |
//! | 16,100 | 284    | random padding (bound into the seal's AD)      |
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use thiserror::Error;

/// Wire format version carried in every unit.
pub const VERSION: u16 = 1;
/// Suite identifier for X448 + ML-KEM-1024 server sealing with EnclaveSeal-v1.
pub const SUITE_V1: u16 = 1;

/// Bytes EnclaveSeal adds (32-byte nonce + 32-byte tag).
pub const SEAL_OVERHEAD: usize = 64;
/// X448 public key length.
pub const X448_LEN: usize = 56;
/// ML-KEM-1024 ciphertext length.
pub const MLKEM_CT_LEN: usize = 1568;
/// ML-KEM-1024 encapsulation key length.
pub const MLKEM_PK_LEN: usize = 1568;

/// Every wire unit is exactly this long.
pub const UNIT_LEN: usize = 16_384;
/// Every stored envelope and blob chunk is exactly this long.
pub const ENVELOPE_LEN: usize = 14_336;
/// Every poll request is exactly this long (one Sphinx payload).
pub const POLL_LEN: usize = 2_048;
/// Request header length (inside the server seal).
pub const REQUEST_HEADER_LEN: usize = 72;

const UNIT_PREFIX_LEN: usize = 4;
const UNIT_SEALED_OFFSET: usize = UNIT_PREFIX_LEN + X448_LEN + MLKEM_CT_LEN;
/// Length of the sealed region inside a unit.
pub const UNIT_SEALED_LEN: usize = REQUEST_HEADER_LEN + ENVELOPE_LEN + SEAL_OVERHEAD;
const UNIT_PADDING_OFFSET: usize = UNIT_SEALED_OFFSET + UNIT_SEALED_LEN;
/// Random padding at the end of each unit.
pub const UNIT_PADDING_LEN: usize = UNIT_LEN - UNIT_PADDING_OFFSET;

const _: () = assert!(UNIT_SEALED_OFFSET == 1_628);
const _: () = assert!(UNIT_SEALED_LEN == 14_472);
const _: () = assert!(UNIT_PADDING_LEN == 284);

/// Length of the sealed region inside a poll request (header only, no envelope).
pub const POLL_SEALED_LEN: usize = REQUEST_HEADER_LEN + SEAL_OVERHEAD;
/// Random padding at the end of each poll request.
pub const POLL_PADDING_LEN: usize = POLL_LEN - UNIT_SEALED_OFFSET - POLL_SEALED_LEN;
const _: () = assert!(POLL_PADDING_LEN == 284);

/// Errors from decoding wire objects.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum WireError {
    /// Input is not exactly the required size.
    #[error("wrong length: expected {expected}, got {got}")]
    Length {
        /// Required length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// Unknown version or suite.
    #[error("unsupported version or suite")]
    Unsupported,
    /// A field holds a value outside its range.
    #[error("malformed field")]
    Malformed,
}

/// Fill a buffer with random bytes. Callers pass the hedged RNG from
/// `enclave-crypto`; tests may pass a deterministic function.
pub type FillRandom<'a> = &'a mut dyn FnMut(&mut [u8]);

fn exact<const N: usize>(b: &[u8]) -> Result<&[u8; N], WireError> {
    b.try_into().map_err(|_| WireError::Length {
        expected: N,
        got: b.len(),
    })
}

// ---------------------------------------------------------------------------
// Request header (72 bytes, sealed to the server)
// ---------------------------------------------------------------------------

/// Operation carried by a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    /// Cover traffic. The server drops it after authenticating the seal.
    Cover = 0,
    /// Write an envelope to an inbox (needs a single-use token).
    Write = 1,
    /// Write to a request inbox (needs a proof of work or an invite capability).
    WriteRequest = 2,
    /// Poll a mailbox from a cursor.
    Poll = 3,
    /// Advance the deletion watermark of the caller's inbox.
    Ack = 4,
    /// Upload one blob chunk.
    BlobPut = 5,
    /// Fetch one blob chunk.
    BlobGet = 6,
    /// Publish or fetch directory objects (manifest, bundle, prekeys).
    Directory = 7,
    /// Register write-token hashes for the caller's inbox.
    RegisterTokens = 8,
    /// Key-transparency query.
    KeyTransparency = 9,
    /// Register (or, empty, remove) the sealed push token for the caller's
    /// inbox (`docs/10-push.md` §2).
    PushRegister = 10,
    /// Report an account to this server's operator (`docs/13-operators.md`
    /// §2); needs a proof of work.
    Report = 11,
    /// Fetch the answer to an earlier request sent one way with
    /// `FLAG_DEFER` (poll-sized; `mailbox` is the request's status id,
    /// `docs/09-transport.md` §6.1).
    Status = 12,
    /// Privacy Pass tokens for blob uploads, and allocations bought with
    /// them (`docs/09-transport.md` §9).
    BlobAlloc = 13,
}

impl Op {
    fn from_u8(v: u8) -> Result<Self, WireError> {
        Ok(match v {
            0 => Op::Cover,
            1 => Op::Write,
            2 => Op::WriteRequest,
            3 => Op::Poll,
            4 => Op::Ack,
            5 => Op::BlobPut,
            6 => Op::BlobGet,
            7 => Op::Directory,
            8 => Op::RegisterTokens,
            9 => Op::KeyTransparency,
            10 => Op::PushRegister,
            11 => Op::Report,
            12 => Op::Status,
            13 => Op::BlobAlloc,
            _ => return Err(WireError::Malformed),
        })
    }
}

/// Request header: `op(1) ‖ flags(1) ‖ reserved(6) ‖ mailbox(32) ‖ token(32)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeader {
    /// Operation.
    pub op: Op,
    /// Operation-specific flags.
    pub flags: u8,
    /// Target mailbox address (random for cover).
    pub mailbox: [u8; 32],
    /// Single-use write token, read credential or proof reference.
    pub token: [u8; 32],
}

impl RequestHeader {
    /// Encode to 72 bytes.
    pub fn encode(&self) -> [u8; REQUEST_HEADER_LEN] {
        let mut out = [0u8; REQUEST_HEADER_LEN];
        out[0] = self.op as u8;
        out[1] = self.flags;
        out[8..40].copy_from_slice(&self.mailbox);
        out[40..72].copy_from_slice(&self.token);
        out
    }

    /// Decode from 72 bytes. Reserved bytes must be zero.
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let b = exact::<REQUEST_HEADER_LEN>(b)?;
        if b[2..8] != [0u8; 6] {
            return Err(WireError::Malformed);
        }
        let mut mailbox = [0u8; 32];
        let mut token = [0u8; 32];
        mailbox.copy_from_slice(&b[8..40]);
        token.copy_from_slice(&b[40..72]);
        Ok(Self {
            op: Op::from_u8(b[0])?,
            flags: b[1],
            mailbox,
            token,
        })
    }
}

// ---------------------------------------------------------------------------
// Wire unit (16,384 bytes)
// ---------------------------------------------------------------------------

/// Parsed wire unit. The sealed region is opaque here.
#[derive(Clone, PartialEq, Eq)]
pub struct WireUnit {
    /// Suite identifier.
    pub suite: u16,
    /// Client ephemeral X448 public key for the server seal.
    pub eph_x448: [u8; X448_LEN],
    /// ML-KEM-1024 ciphertext to the server's daily key.
    pub kem_ct: Box<[u8; MLKEM_CT_LEN]>,
    /// EnclaveSeal output over `request header ‖ envelope`.
    pub sealed: Box<[u8; UNIT_SEALED_LEN]>,
}

impl core::fmt::Debug for WireUnit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WireUnit")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl WireUnit {
    /// Encode to exactly [`UNIT_LEN`] bytes, filling the tail with random padding.
    pub fn encode(&self, fill: FillRandom<'_>) -> Vec<u8> {
        let mut out = vec![0u8; UNIT_LEN];
        out[0..2].copy_from_slice(&VERSION.to_be_bytes());
        out[2..4].copy_from_slice(&self.suite.to_be_bytes());
        out[4..60].copy_from_slice(&self.eph_x448);
        out[60..UNIT_SEALED_OFFSET].copy_from_slice(&self.kem_ct[..]);
        out[UNIT_SEALED_OFFSET..UNIT_PADDING_OFFSET].copy_from_slice(&self.sealed[..]);
        fill(&mut out[UNIT_PADDING_OFFSET..]);
        out
    }

    /// Decode a unit. Rejects anything that is not exactly [`UNIT_LEN`] bytes.
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let b = exact::<UNIT_LEN>(b)?;
        let version = u16::from_be_bytes([b[0], b[1]]);
        let suite = u16::from_be_bytes([b[2], b[3]]);
        if version != VERSION || suite != SUITE_V1 {
            return Err(WireError::Unsupported);
        }
        let mut eph_x448 = [0u8; X448_LEN];
        eph_x448.copy_from_slice(&b[4..60]);
        let mut kem_ct = Box::new([0u8; MLKEM_CT_LEN]);
        kem_ct.copy_from_slice(&b[60..UNIT_SEALED_OFFSET]);
        let mut sealed = Box::new([0u8; UNIT_SEALED_LEN]);
        sealed.copy_from_slice(&b[UNIT_SEALED_OFFSET..UNIT_PADDING_OFFSET]);
        Ok(Self {
            suite,
            eph_x448,
            kem_ct,
            sealed,
        })
    }
}

/// Parsed poll request (2,048 bytes): same prefix as a unit, sealed header only.
#[derive(Clone, PartialEq, Eq)]
pub struct PollRequest {
    /// Client ephemeral X448 public key.
    pub eph_x448: [u8; X448_LEN],
    /// ML-KEM-1024 ciphertext to the server's daily key.
    pub kem_ct: Box<[u8; MLKEM_CT_LEN]>,
    /// EnclaveSeal output over the request header.
    pub sealed: [u8; POLL_SEALED_LEN],
}

impl core::fmt::Debug for PollRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PollRequest").finish_non_exhaustive()
    }
}

impl PollRequest {
    /// Encode to exactly [`POLL_LEN`] bytes.
    pub fn encode(&self, fill: FillRandom<'_>) -> Vec<u8> {
        let mut out = vec![0u8; POLL_LEN];
        out[0..2].copy_from_slice(&VERSION.to_be_bytes());
        out[2..4].copy_from_slice(&SUITE_V1.to_be_bytes());
        out[4..60].copy_from_slice(&self.eph_x448);
        out[60..UNIT_SEALED_OFFSET].copy_from_slice(&self.kem_ct[..]);
        let end = UNIT_SEALED_OFFSET + POLL_SEALED_LEN;
        out[UNIT_SEALED_OFFSET..end].copy_from_slice(&self.sealed);
        fill(&mut out[end..]);
        out
    }

    /// Decode. Rejects anything that is not exactly [`POLL_LEN`] bytes.
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let b = exact::<POLL_LEN>(b)?;
        if u16::from_be_bytes([b[0], b[1]]) != VERSION
            || u16::from_be_bytes([b[2], b[3]]) != SUITE_V1
        {
            return Err(WireError::Unsupported);
        }
        let mut eph_x448 = [0u8; X448_LEN];
        eph_x448.copy_from_slice(&b[4..60]);
        let mut kem_ct = Box::new([0u8; MLKEM_CT_LEN]);
        kem_ct.copy_from_slice(&b[60..UNIT_SEALED_OFFSET]);
        let mut sealed = [0u8; POLL_SEALED_LEN];
        sealed.copy_from_slice(&b[UNIT_SEALED_OFFSET..UNIT_SEALED_OFFSET + POLL_SEALED_LEN]);
        Ok(Self {
            eph_x448,
            kem_ct,
            sealed,
        })
    }
}

// ---------------------------------------------------------------------------
// Stored envelopes (14,336 bytes)
// ---------------------------------------------------------------------------

/// Envelope kinds (first byte after the version).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeKind {
    /// 1:1 message (wrap table + PQ slot).
    Direct = 1,
    /// Group message (MAC vector + causal frontier).
    Group = 2,
    /// Blob chunk (attachment data).
    Blob = 3,
    /// Cover envelope (indistinguishable once sealed).
    Cover = 4,
    /// First-contact envelope in a request inbox.
    Request = 5,
}

/// Header length at the start of every stored envelope.
pub const ENV_HEADER_LEN: usize = 16;
/// Number of device slots in a 1:1 envelope (the per-account device cap).
pub const DEVICE_SLOTS: usize = 5;
/// Length of one device slot.
pub const DEVICE_SLOT_LEN: usize = 160;
/// Length of the sealed PQ slot.
pub const PQ_SLOT_LEN: usize = 3_264;
/// Length of the notification capsule (random when unused).
pub const CAPSULE_LEN: usize = 1_024;
/// Inner framing before content: an 8-byte content length.
pub const CONTENT_FRAMING: usize = 8;
/// Body overhead: seal + content length framing.
pub const BODY_OVERHEAD: usize = SEAL_OVERHEAD + CONTENT_FRAMING;

/// Offsets inside a 1:1 envelope.
pub mod direct {
    use super::*;
    /// Device-slot table offset.
    pub const SLOTS: usize = ENV_HEADER_LEN;
    /// PQ slot offset.
    pub const PQ: usize = SLOTS + DEVICE_SLOTS * DEVICE_SLOT_LEN;
    /// Capsule offset.
    pub const CAPSULE: usize = PQ + PQ_SLOT_LEN;
    /// Sealed body offset.
    pub const BODY: usize = CAPSULE + CAPSULE_LEN;
    /// Sealed body length.
    pub const BODY_LEN: usize = ENVELOPE_LEN - BODY;
    /// Content capacity in "Off the record" mode.
    pub const CONTENT_CAPACITY: usize = BODY_LEN - BODY_OVERHEAD;
    const _: () = assert!(PQ == 816 && CAPSULE == 4_080 && BODY == 5_104);
    const _: () = assert!(CONTENT_CAPACITY == 9_160);
}

/// Offsets inside a group envelope.
pub mod group {
    use super::*;
    /// Sender header length.
    pub const SENDER_HEADER_LEN: usize = 88;
    /// State hash length.
    pub const STATE_HASH_LEN: usize = 32;
    /// Causal frontier length (100 members × 8 bytes).
    pub const FRONTIER_LEN: usize = 800;
    /// MAC vector length (99 entries × 16 bytes).
    pub const MAC_VECTOR_LEN: usize = 99 * 16;
    /// Sender header offset (the envelope header is folded into it).
    pub const SENDER: usize = 0;
    /// State hash offset.
    pub const STATE: usize = SENDER + SENDER_HEADER_LEN;
    /// Frontier offset.
    pub const FRONTIER: usize = STATE + STATE_HASH_LEN;
    /// MAC vector offset.
    pub const MACS: usize = FRONTIER + FRONTIER_LEN;
    /// Capsule offset.
    pub const CAPSULE: usize = MACS + MAC_VECTOR_LEN;
    /// Sealed body offset.
    pub const BODY: usize = CAPSULE + CAPSULE_LEN;
    /// Sealed body length.
    pub const BODY_LEN: usize = ENVELOPE_LEN - BODY;
    /// Content capacity.
    pub const CONTENT_CAPACITY: usize = BODY_LEN - BODY_OVERHEAD;
    const _: () = assert!(BODY == 3_528);
    const _: () = assert!(CONTENT_CAPACITY == 10_736);
}

/// Blob chunk payload capacity (one sealed chunk per envelope).
pub const BLOB_CHUNK_CAPACITY: usize = ENVELOPE_LEN - ENV_HEADER_LEN - BODY_OVERHEAD;

/// Frame `content` as `len(8) ‖ content ‖ random padding` to exactly `capacity + 8`
/// bytes. Returns an error if the content does not fit.
pub fn pad_content(
    content: &[u8],
    capacity: usize,
    fill: FillRandom<'_>,
) -> Result<Vec<u8>, WireError> {
    if content.len() > capacity {
        return Err(WireError::Length {
            expected: capacity,
            got: content.len(),
        });
    }
    let mut out = vec![0u8; CONTENT_FRAMING + capacity];
    out[..8].copy_from_slice(&(content.len() as u64).to_be_bytes());
    out[8..8 + content.len()].copy_from_slice(content);
    fill(&mut out[8 + content.len()..]);
    Ok(out)
}

/// Inverse of [`pad_content`].
pub fn unpad_content(framed: &[u8]) -> Result<&[u8], WireError> {
    if framed.len() < CONTENT_FRAMING {
        return Err(WireError::Malformed);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&framed[..8]);
    let len = usize::try_from(u64::from_be_bytes(len_bytes)).map_err(|_| WireError::Malformed)?;
    if len > framed.len() - CONTENT_FRAMING {
        return Err(WireError::Malformed);
    }
    Ok(&framed[8..8 + len])
}

// ---------------------------------------------------------------------------
// Attachment size buckets
// ---------------------------------------------------------------------------

/// Attachment size buckets. An attachment is padded to the smallest bucket
/// that holds it; larger than the last bucket is refused.
pub const BUCKETS: [usize; 7] = [
    64 * 1024,
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
    16 * 1024 * 1024,
    64 * 1024 * 1024,
    128 * 1024 * 1024,
];

/// Largest attachment users may send (100 MiB).
pub const MAX_ATTACHMENT: usize = 100 * 1024 * 1024;

/// Bucket for an attachment of `len` bytes, or `None` if it is too large.
pub fn bucket_for(len: usize) -> Option<usize> {
    if len > MAX_ATTACHMENT {
        return None;
    }
    BUCKETS.iter().copied().find(|b| len <= *b)
}

/// Number of blob chunks needed for a bucket.
pub fn chunks_for_bucket(bucket: usize) -> usize {
    bucket.div_ceil(BLOB_CHUNK_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_fill(b: &mut [u8]) {
        b.fill(0xAA);
    }

    #[test]
    fn unit_roundtrip_and_exact_size() {
        let u = WireUnit {
            suite: SUITE_V1,
            eph_x448: [1; 56],
            kem_ct: Box::new([2; MLKEM_CT_LEN]),
            sealed: Box::new([3; UNIT_SEALED_LEN]),
        };
        let enc = u.encode(&mut zero_fill);
        assert_eq!(enc.len(), UNIT_LEN);
        assert_eq!(WireUnit::decode(&enc).unwrap(), u);
        assert!(WireUnit::decode(&enc[..UNIT_LEN - 1]).is_err());
        let mut bad = enc.clone();
        bad[1] = 9;
        assert_eq!(WireUnit::decode(&bad), Err(WireError::Unsupported));
    }

    #[test]
    fn poll_roundtrip() {
        let p = PollRequest {
            eph_x448: [4; 56],
            kem_ct: Box::new([5; MLKEM_CT_LEN]),
            sealed: [6; POLL_SEALED_LEN],
        };
        let enc = p.encode(&mut zero_fill);
        assert_eq!(enc.len(), POLL_LEN);
        assert_eq!(PollRequest::decode(&enc).unwrap(), p);
    }

    #[test]
    fn header_roundtrip_and_reserved_check() {
        let h = RequestHeader {
            op: Op::Write,
            flags: 3,
            mailbox: [7; 32],
            token: [8; 32],
        };
        let e = h.encode();
        assert_eq!(RequestHeader::decode(&e).unwrap(), h);
        let mut bad = e;
        bad[4] = 1;
        assert_eq!(RequestHeader::decode(&bad), Err(WireError::Malformed));
        bad = e;
        bad[0] = 200;
        assert_eq!(RequestHeader::decode(&bad), Err(WireError::Malformed));
    }

    #[test]
    fn padding_roundtrip() {
        let framed = pad_content(b"hello", direct::CONTENT_CAPACITY, &mut zero_fill).unwrap();
        assert_eq!(framed.len(), direct::CONTENT_CAPACITY + CONTENT_FRAMING);
        assert_eq!(unpad_content(&framed).unwrap(), b"hello");
        assert!(
            pad_content(
                &vec![0; direct::CONTENT_CAPACITY + 1],
                direct::CONTENT_CAPACITY,
                &mut zero_fill
            )
            .is_err()
        );
        let mut bad = framed.clone();
        bad[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(unpad_content(&bad).is_err());
    }

    #[test]
    fn body_fits_sealed_region() {
        // A sealed 1:1 body is exactly BODY_LEN bytes.
        assert_eq!(direct::CONTENT_CAPACITY + BODY_OVERHEAD, direct::BODY_LEN);
        assert_eq!(group::CONTENT_CAPACITY + BODY_OVERHEAD, group::BODY_LEN);
    }

    #[test]
    fn buckets() {
        assert_eq!(bucket_for(0), Some(64 * 1024));
        assert_eq!(bucket_for(64 * 1024), Some(64 * 1024));
        assert_eq!(bucket_for(64 * 1024 + 1), Some(256 * 1024));
        assert_eq!(bucket_for(MAX_ATTACHMENT), Some(128 * 1024 * 1024));
        assert_eq!(bucket_for(MAX_ATTACHMENT + 1), None);
        assert_eq!(chunks_for_bucket(64 * 1024), 5);
    }
}
