//! Attachments (`docs/08-envelope.md` §9, `docs/02b-key-schedule.md` §9).
//!
//! A file is sealed in 14,248-byte chunks under a random blob secret and
//! padded to a size bucket, so the server learns only the bucket. Chunk IDs
//! are derived from the secret, so they are random to the server and cannot
//! be linked to each other or to the message. The message carries the
//! secret, the size and a SHA3-512 hash inside its end-to-end encrypted
//! body.

use enclave_crypto::hash::sha3_512;
use enclave_crypto::kmac::kmac256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::{ProtoError, Result};
use enclave_wire::{
    BLOB_CHUNK_CAPACITY, ENV_HEADER_LEN, ENVELOPE_LEN, EnvelopeKind, pad_content, unpad_content,
};

/// Largest attachment.
pub const MAX_ATTACHMENT: usize = 100 * 1024 * 1024;
/// Size buckets.
pub const BUCKETS: [usize; 7] = [
    64 << 10,
    256 << 10,
    1 << 20,
    4 << 20,
    16 << 20,
    64 << 20,
    128 << 20,
];

const L_CHUNK_KEY: &str = "enclave/v1/wire/chunk-key";
const L_CHUNK_ID: &str = "enclave/v1/wire/chunk-id";
const L_AD_CHUNK: &str = "enclave/v1/wire/ad-chunk";

/// A chunk's associated data: `"enclave/v1/wire/ad-chunk" ‖ header ‖ u32 i
/// ‖ u32 n`, so a chunk can't be moved to another position or blob, nor
/// opened as anything but a chunk.
fn chunk_ad(i: u32, n: u32) -> Vec<u8> {
    [
        L_AD_CHUNK.as_bytes(),
        &header()[..],
        &i.to_be_bytes(),
        &n.to_be_bytes(),
    ]
    .concat()
}

/// Reference to an uploaded file, carried in a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    /// Server holding the chunks.
    pub host: [u8; 16],
    /// Blob secret (chunk keys and IDs).
    pub secret: [u8; 32],
    /// True size.
    pub size: u64,
    /// Chunks (the bucket's, not the file's).
    pub chunks: u32,
    /// SHA3-512 of the file.
    pub hash: [u8; 64],
    /// File name (untrusted; shown sanitized).
    pub name: String,
    /// MIME type (untrusted; only used to pick a viewer, never to parse).
    pub mime: String,
}

impl Attachment {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.host)
            .fixed(&self.secret)
            .u64(self.size)
            .u32(self.chunks)
            .fixed(&self.hash);
        w.bytes(self.name.as_bytes()).bytes(self.mime.as_bytes());
        w.finish()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let s = |r: &mut Reader<'_>, n| {
            String::from_utf8(r.bytes(n)?.to_vec()).map_err(|_| ProtoError::Decode)
        };
        let a = Self {
            host: r.array()?,
            secret: r.array()?,
            size: r.u64()?,
            chunks: r.u32()?,
            hash: r.array()?,
            name: s(&mut r, 255)?,
            mime: s(&mut r, 127)?,
        };
        r.end()?;
        if a.size as usize > MAX_ATTACHMENT
            || a.chunks as usize != chunks_for(bucket_for(a.size as usize)?)
        {
            return Err(ProtoError::Decode);
        }
        Ok(a)
    }

    /// Chunk ID `i`.
    pub fn chunk_id(&self, i: u32) -> [u8; 32] {
        chunk_id(&self.secret, i)
    }
}

/// The bucket a size pads to.
pub fn bucket_for(size: usize) -> Result<usize> {
    BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= size.max(1))
        .filter(|_| size <= MAX_ATTACHMENT)
        .ok_or(ProtoError::TooLarge)
}

fn chunks_for(bucket: usize) -> usize {
    bucket.div_ceil(BLOB_CHUNK_CAPACITY)
}

fn chunk_key(secret: &[u8; 32]) -> SealKey {
    SealKey::from_bytes(kmac256(secret, b"", L_CHUNK_KEY))
}

fn chunk_id(secret: &[u8; 32], i: u32) -> [u8; 32] {
    kmac256(secret, &i.to_be_bytes(), L_CHUNK_ID)
}

fn header() -> [u8; ENV_HEADER_LEN] {
    let mut h = [0u8; ENV_HEADER_LEN];
    h[0] = 1;
    h[1] = EnvelopeKind::Blob as u8;
    h
}

/// Sealed chunks, each with its ID.
pub type Chunks = Vec<([u8; 32], Vec<u8>)>;

/// Seal `data` into bucket-padded chunks. Returns the reference (without
/// the host) and `(chunk_id, 14,336-byte chunk)` pairs.
pub fn seal_file(
    data: &[u8],
    name: &str,
    mime: &str,
    host: [u8; 16],
    rng: &mut HedgedRng,
) -> Result<(Attachment, Chunks)> {
    let bucket = bucket_for(data.len())?;
    let n = chunks_for(bucket);
    let secret: [u8; 32] = rng.array("blob/secret")?;
    let key = chunk_key(&secret);
    let hdr = header();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let part = data
            .get(i * BLOB_CHUNK_CAPACITY..((i + 1) * BLOB_CHUNK_CAPACITY).min(data.len()))
            .unwrap_or(&[]);
        let mut fill = |b: &mut [u8]| {
            if rng.fill("blob/padding", b).is_err() {
                b.fill(0);
            }
        };
        let framed = pad_content(part, BLOB_CHUNK_CAPACITY, &mut fill)?;
        let ad = chunk_ad(i as u32, n as u32);
        let sealed = seal::seal(&key, &ad, &framed, rng)?;
        let chunk = [&hdr[..], &sealed].concat();
        if chunk.len() != ENVELOPE_LEN {
            return Err(ProtoError::Decode);
        }
        out.push((chunk_id(&secret, i as u32), chunk));
    }
    let a = Attachment {
        host,
        secret,
        size: data.len() as u64,
        chunks: n as u32,
        hash: sha3_512(data),
        name: name.chars().take(120).collect(),
        mime: mime.chars().take(100).collect(),
    };
    Ok((a, out))
}

/// Open chunk `i` of `a`.
pub fn open_chunk(a: &Attachment, i: u32, chunk: &[u8]) -> Result<Vec<u8>> {
    if chunk.len() != ENVELOPE_LEN || chunk[..ENV_HEADER_LEN] != header() {
        return Err(ProtoError::Decode);
    }
    let key = chunk_key(&a.secret);
    let body = &chunk[ENV_HEADER_LEN..];
    // Chunks sealed before the label was added had no prefix.
    let framed = seal::open(&key, &chunk_ad(i, a.chunks), body).or_else(|_| {
        let legacy = [&header()[..], &i.to_be_bytes(), &a.chunks.to_be_bytes()].concat();
        seal::open(&key, &legacy, body)
    })?;
    Ok(unpad_content(&framed)?.to_vec())
}

/// Reassemble and verify the file from all its chunks' plaintexts.
pub fn finish(a: &Attachment, parts: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut data: Vec<u8> = parts.concat();
    if data.len() < a.size as usize {
        return Err(ProtoError::Decode);
    }
    data.truncate(a.size as usize);
    if sha3_512(&data) != a.hash {
        return Err(ProtoError::Crypto);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn buckets_and_roundtrip() {
        assert_eq!(bucket_for(0).unwrap(), 64 << 10);
        assert_eq!(bucket_for(300_000).unwrap(), 1 << 20);
        assert!(bucket_for(MAX_ATTACHMENT + 1).is_err());
        let mut rng = HedgedRng::new().unwrap();
        let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7) as u8).collect();
        let (a, chunks) = seal_file(&data, "photo.jpg", "image/jpeg", [1; 16], &mut rng).unwrap();
        assert_eq!(
            chunks.len(),
            (256usize << 10).div_ceil(BLOB_CHUNK_CAPACITY),
            "padded to the bucket"
        );
        let a = Attachment::decode(&a.encode()).unwrap();
        let parts: Vec<Vec<u8>> = chunks
            .iter()
            .enumerate()
            .map(|(i, (id, c))| {
                assert_eq!(*id, a.chunk_id(i as u32));
                open_chunk(&a, i as u32, c).unwrap()
            })
            .collect();
        assert_eq!(finish(&a, &parts).unwrap(), data);
        // Chunks cannot be swapped.
        assert!(open_chunk(&a, 1, &chunks[0].1).is_err());
        // A wrong hash is caught.
        let mut b = a.clone();
        b.hash[0] ^= 1;
        assert!(finish(&b, &parts).is_err());
    }

    /// Files of different sizes in one bucket upload the same: as many
    /// chunks, each exactly one stored envelope long (RT-17).
    #[test]
    fn rt17_attachment_padded_to_bucket() {
        let mut rng = HedgedRng::new().unwrap();
        let (_, small) = seal_file(&[1; 70_000], "a", "", [1; 16], &mut rng).unwrap();
        let (_, large) = seal_file(&[2; 250_000], "b", "", [1; 16], &mut rng).unwrap();
        assert_eq!(small.len(), large.len());
        assert!(
            small
                .iter()
                .chain(&large)
                .all(|(_, c)| c.len() == ENVELOPE_LEN)
        );
    }

    /// Blob secrets and chunk IDs are random: the same file sealed twice
    /// shares nothing the server could match (RT-17).
    #[test]
    fn rt17_blob_ids_not_content_derived() {
        let mut rng = HedgedRng::new().unwrap();
        let data = vec![9u8; 5_000];
        let (a, x) = seal_file(&data, "f", "", [1; 16], &mut rng).unwrap();
        let (b, y) = seal_file(&data, "f", "", [1; 16], &mut rng).unwrap();
        assert_ne!(a.secret, b.secret);
        for ((i, c), (j, d)) in x.iter().zip(&y) {
            assert_ne!(i, j);
            assert_ne!(c, d);
        }
    }

    /// A chunk sealed before the `wire/ad-chunk` prefix still opens.
    #[test]
    fn legacy_chunks_open() {
        let mut rng = HedgedRng::new().unwrap();
        let (a, _) = seal_file(b"old", "f", "", [1; 16], &mut rng).unwrap();
        let framed = pad_content(b"old", BLOB_CHUNK_CAPACITY, &mut |b| b.fill(0)).unwrap();
        let legacy = [&header()[..], &0u32.to_be_bytes(), &a.chunks.to_be_bytes()].concat();
        let sealed = seal::seal(&chunk_key(&a.secret), &legacy, &framed, &mut rng).unwrap();
        let chunk = [&header()[..], &sealed].concat();
        assert_eq!(open_chunk(&a, 0, &chunk).unwrap(), b"old");
    }
}
