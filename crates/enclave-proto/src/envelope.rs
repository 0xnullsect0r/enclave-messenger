//! Building and opening stored envelopes (`docs/06-multidevice.md`,
//! `docs/08-envelope.md`).
//!
//! A **direct** envelope carries one message to every device of one account:
//! the body is sealed once under a fresh key, and each device pair gets a
//! 160-byte slot (lookup tag + sealed header with the wrapped body key). The
//! slot table is always padded to the five-device cap with random bytes and
//! shuffled, so neither the server nor the network learns how many devices an
//! account has. One PQ slot per envelope carries ML-KEM material for one
//! device pair.
//!
//! A **request** envelope carries an EQXDH initial message plus the first
//! message to one device.

use crate::eqxdh::{INITIAL_BLOCK_LEN, InitialMessage};
use crate::error::{ProtoError, Result};
use crate::ratchet::{Session, TAG_LEN};
use enclave_crypto::hash::sha3_512;
use enclave_crypto::kem::McElieceSecret;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_wire::{
    CAPSULE_LEN, DEVICE_SLOT_LEN, DEVICE_SLOTS, ENV_HEADER_LEN, ENVELOPE_LEN, EnvelopeKind,
    PQ_SLOT_LEN, direct, pad_content, unpad_content,
};

const VERSION: u8 = 1;

fn header(kind: EnvelopeKind) -> [u8; ENV_HEADER_LEN] {
    let mut h = [0u8; ENV_HEADER_LEN];
    h[0] = VERSION;
    h[1] = kind as u8;
    h
}

fn fill(rng: &mut HedgedRng) -> impl FnMut(&mut [u8]) + '_ {
    move |b: &mut [u8]| {
        // Padding only needs to be unpredictable; an RNG failure here would be
        // caught by the next keyed operation, so fall back to zeros.
        if rng.fill("envelope/padding", b).is_err() {
            b.fill(0);
        }
    }
}

/// Seal `content` into a body region of `body_len` bytes.
fn seal_body(
    content: &[u8],
    body_len: usize,
    ad: &[u8],
    rng: &mut HedgedRng,
) -> Result<([u8; 32], Vec<u8>)> {
    let capacity = body_len - seal::OVERHEAD - enclave_wire::CONTENT_FRAMING;
    if content.len() > capacity {
        return Err(ProtoError::TooLarge);
    }
    let body_key: [u8; 32] = rng.array("envelope/body-key")?;
    let mut f = fill(rng);
    let framed = pad_content(content, capacity, &mut f)?;
    drop(f);
    let sealed = seal::seal(&SealKey::from_bytes(body_key), ad, &framed, rng)?;
    debug_assert_eq!(sealed.len(), body_len);
    Ok((body_key, sealed))
}

fn open_body(body_key: &[u8; 32], ad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let framed = seal::open(&SealKey::from_bytes(*body_key), ad, sealed)?;
    Ok(unpad_content(&framed)?.to_vec())
}

/// Maximum content in a direct envelope.
pub const DIRECT_CAPACITY: usize = direct::CONTENT_CAPACITY;

/// Build a direct envelope for up to five sessions (one per device pair).
///
/// `pq_carrier` picks which session gets the PQ slot (index into `sessions`);
/// callers rotate it. Sessions that cannot send yet are rejected.
pub fn seal_direct(
    sessions: &mut [&mut Session],
    content: &[u8],
    pq_carrier: Option<usize>,
    rng: &mut HedgedRng,
) -> Result<Vec<u8>> {
    if sessions.is_empty() || sessions.len() > DEVICE_SLOTS {
        return Err(ProtoError::Limit);
    }
    let hdr = header(EnvelopeKind::Direct);
    let (body_key, body) = seal_body(content, direct::BODY_LEN, &hdr, rng)?;
    let body_hash = sha3_512(&body);

    let mut slots: Vec<Vec<u8>> = Vec::with_capacity(DEVICE_SLOTS);
    let mut pq_slot: Option<Vec<u8>> = None;
    for (i, s) in sessions.iter_mut().enumerate() {
        let carry = pq_carrier == Some(i);
        let out = s.seal(&body_key, &body_hash, &hdr, carry, rng)?;
        let mut slot = Vec::with_capacity(DEVICE_SLOT_LEN);
        slot.extend_from_slice(&out.tag);
        slot.extend_from_slice(&out.header);
        if slot.len() != DEVICE_SLOT_LEN {
            return Err(ProtoError::Decode);
        }
        slots.push(slot);
        if let Some(p) = out.pq_slot {
            pq_slot = Some(p);
        }
    }
    while slots.len() < DEVICE_SLOTS {
        let mut r = vec![0u8; DEVICE_SLOT_LEN];
        rng.fill("envelope/dummy-slot", &mut r)?;
        slots.push(r);
    }
    // Shuffle so slot position reveals nothing (Fisher-Yates).
    for i in (1..slots.len()).rev() {
        let r: [u8; 4] = rng.array("envelope/shuffle")?;
        let j = (u32::from_be_bytes(r) as usize) % (i + 1);
        slots.swap(i, j);
    }

    let mut env = Vec::with_capacity(ENVELOPE_LEN);
    env.extend_from_slice(&hdr);
    for s in &slots {
        env.extend_from_slice(s);
    }
    match pq_slot {
        Some(p) if p.len() == PQ_SLOT_LEN => env.extend_from_slice(&p),
        Some(_) => return Err(ProtoError::Decode),
        None => {
            let mut r = vec![0u8; PQ_SLOT_LEN];
            rng.fill("envelope/dummy-pq", &mut r)?;
            env.extend_from_slice(&r);
        }
    }
    let mut capsule = vec![0u8; CAPSULE_LEN];
    rng.fill("envelope/capsule", &mut capsule)?;
    env.extend_from_slice(&capsule);
    env.extend_from_slice(&body);
    if env.len() != ENVELOPE_LEN {
        return Err(ProtoError::Decode);
    }
    Ok(env)
}

/// A direct envelope nobody can open: random slots, PQ slot and capsule,
/// and a body sealed under a random key over empty content. It has the
/// form and length of a real one; a single-device account writes it as its
/// self-copy (`06-multidevice.md` §4), so the server sees two writes per
/// message whatever the number of devices.
pub fn cover_direct(rng: &mut HedgedRng) -> Result<Vec<u8>> {
    let hdr = header(EnvelopeKind::Direct);
    let (_, body) = seal_body(&[], direct::BODY_LEN, &hdr, rng)?;
    let mut env = Vec::with_capacity(ENVELOPE_LEN);
    env.extend_from_slice(&hdr);
    let mut r = vec![0u8; DEVICE_SLOTS * DEVICE_SLOT_LEN];
    rng.fill("envelope/dummy-slot", &mut r)?;
    env.extend_from_slice(&r);
    let mut r = vec![0u8; PQ_SLOT_LEN];
    rng.fill("envelope/dummy-pq", &mut r)?;
    env.extend_from_slice(&r);
    let mut capsule = vec![0u8; CAPSULE_LEN];
    rng.fill("envelope/capsule", &mut capsule)?;
    env.extend_from_slice(&capsule);
    env.extend_from_slice(&body);
    if env.len() != ENVELOPE_LEN {
        return Err(ProtoError::Decode);
    }
    Ok(env)
}

/// Result of opening an envelope.
pub struct OpenedEnvelope {
    /// Index of the session (in the caller's list) that matched.
    pub session_index: usize,
    /// Decrypted content.
    pub content: Vec<u8>,
    /// When its key was first seen skipped, if it arrived after later
    /// messages ([`crate::ratchet::Opened::skipped_at`]).
    pub skipped_at: Option<u64>,
}

/// Open a direct envelope with the first of `sessions` that owns one of its
/// slots. State changes are committed only after the body authenticates.
pub fn open_direct(
    sessions: &mut [&mut Session],
    env: &[u8],
    vault: Option<&McElieceSecret>,
    rng: &mut HedgedRng,
) -> Result<OpenedEnvelope> {
    if env.len() != ENVELOPE_LEN || env[0] != VERSION || env[1] != EnvelopeKind::Direct as u8 {
        return Err(ProtoError::Decode);
    }
    let hdr = &env[..ENV_HEADER_LEN];
    let pq_slot = &env[direct::PQ..direct::PQ + PQ_SLOT_LEN];
    let body = &env[direct::BODY..];
    let body_hash = sha3_512(body);
    for k in 0..DEVICE_SLOTS {
        let off = direct::SLOTS + k * DEVICE_SLOT_LEN;
        let slot = &env[off..off + DEVICE_SLOT_LEN];
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&slot[..TAG_LEN]);
        for (si, s) in sessions.iter_mut().enumerate() {
            if !s.matches(&tag) {
                continue;
            }
            let opened = s.open(
                &tag,
                &slot[TAG_LEN..],
                Some(pq_slot),
                &body_hash,
                hdr,
                vault,
                rng,
            )?;
            let content = open_body(&opened.body_key, hdr, body)?;
            let skipped_at = opened.skipped_at;
            s.commit(opened.next);
            return Ok(OpenedEnvelope {
                session_index: si,
                content,
                skipped_at,
            });
        }
    }
    Err(ProtoError::NoSession)
}

/// Offset of the device slot in a request envelope.
const REQ_SLOT: usize = ENV_HEADER_LEN + INITIAL_BLOCK_LEN;
/// Offset of the sealed body in a request envelope.
const REQ_BODY: usize = REQ_SLOT + DEVICE_SLOT_LEN;
/// Maximum content in the first message of a request envelope.
pub const REQUEST_CAPACITY: usize =
    ENVELOPE_LEN - REQ_BODY - seal::OVERHEAD - enclave_wire::CONTENT_FRAMING;

/// Build a request envelope: EQXDH initial message + first message.
pub fn seal_request(
    initial: &InitialMessage,
    session: &mut Session,
    content: &[u8],
    rng: &mut HedgedRng,
) -> Result<Vec<u8>> {
    let hdr = header(EnvelopeKind::Request);
    let block = initial.encode();
    if block.len() != INITIAL_BLOCK_LEN {
        return Err(ProtoError::Decode);
    }
    // The body AD also binds the initial block, so it cannot be swapped.
    let ad = [&hdr[..], &block[..]].concat();
    let (body_key, body) = seal_body(content, ENVELOPE_LEN - REQ_BODY, &ad, rng)?;
    let body_hash = sha3_512(&body);
    let out = session.seal(&body_key, &body_hash, &ad, false, rng)?;
    let mut env = Vec::with_capacity(ENVELOPE_LEN);
    env.extend_from_slice(&hdr);
    env.extend_from_slice(&block);
    env.extend_from_slice(&out.tag);
    env.extend_from_slice(&out.header);
    env.extend_from_slice(&body);
    if env.len() != ENVELOPE_LEN {
        return Err(ProtoError::Decode);
    }
    Ok(env)
}

/// Parse the initial-message block of a request envelope.
pub fn request_initial(env: &[u8]) -> Result<InitialMessage> {
    if env.len() != ENVELOPE_LEN || env[0] != VERSION || env[1] != EnvelopeKind::Request as u8 {
        return Err(ProtoError::Decode);
    }
    InitialMessage::decode(&env[ENV_HEADER_LEN..REQ_SLOT])
}

/// Open the first message of a request envelope with the session that
/// [`crate::eqxdh::respond`] produced.
pub fn open_request(session: &mut Session, env: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>> {
    if env.len() != ENVELOPE_LEN || env[1] != EnvelopeKind::Request as u8 {
        return Err(ProtoError::Decode);
    }
    let ad = &env[..REQ_SLOT];
    let slot = &env[REQ_SLOT..REQ_BODY];
    let body = &env[REQ_BODY..];
    let body_hash = sha3_512(body);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&slot[..TAG_LEN]);
    let opened = session.open(&tag, &slot[TAG_LEN..], None, &body_hash, ad, None, rng)?;
    let content = open_body(&opened.body_key, ad, body)?;
    session.commit(opened.next);
    Ok(content)
}
