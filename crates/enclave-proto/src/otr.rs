//! On-the-record signatures (`docs/05-ratchet.md` §9, `docs/07-groups.md`
//! §3 and §7).
//!
//! In a conversation or group on the record, what a person writes carries
//! a composite (ML-DSA-87 and Ed448) signature of their device, which the
//! recipient — and anyone the recipient shows it to, such as a server
//! operator receiving a report — can check against the account's
//! root-signed manifest. Off the record nothing is signed: messages are
//! authenticated only to the people in the conversation, and deniable.

use crate::labels;
use crate::{ProtoError, Result};
use enclave_crypto::hash::{sha3_512, shake256};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{CompositePublic, CompositeSigningKey};

/// `root_hash = ID256("enclave/v1/proto/root-hash", root_pk)`.
pub fn root_hash(root_pk: &[u8; 64]) -> [u8; 32] {
    shake256(&[labels::ROOT_HASH.as_bytes(), root_pk].concat())
}

/// A 1:1 conversation's id: the same on both sides,
/// `ID256("enclave/v1/proto/conv-id", lower root hash ‖ higher root hash)`.
pub fn conv_id(a: &[u8; 64], b: &[u8; 64]) -> [u8; 32] {
    conv_id_of(&root_hash(a), &root_hash(b))
}

/// [`conv_id`] from the two root hashes (what someone shown a signed
/// message, such as an operator reading a report, can compute).
pub fn conv_id_of(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if x <= y { (x, y) } else { (y, x) };
    shake256(&[labels::CONV_ID.as_bytes(), lo, hi].concat())
}

/// What a 1:1 message signature covers (`05-ratchet.md` §9):
/// `conv_id ‖ sender_device_id ‖ recipient_root_hash ‖ u64 counter ‖
/// u8 mode ‖ SHA3-512(content)`.
pub fn message_payload(
    conv_id: &[u8; 32],
    sender_device: &[u8; 16],
    recipient_root: &[u8; 64],
    counter: u64,
    content: &[u8],
) -> Vec<u8> {
    message_payload_of(
        conv_id,
        sender_device,
        &root_hash(recipient_root),
        counter,
        content,
    )
}

/// [`message_payload`] with the recipient's root hash.
pub fn message_payload_of(
    conv_id: &[u8; 32],
    sender_device: &[u8; 16],
    recipient_root_hash: &[u8; 32],
    counter: u64,
    content: &[u8],
) -> Vec<u8> {
    [
        &conv_id[..],
        sender_device,
        recipient_root_hash,
        &counter.to_be_bytes(),
        &[1u8],
        &sha3_512(content),
    ]
    .concat()
}

/// What a group message signature covers (`07-groups.md` §3):
/// `group_id ‖ u32 epoch ‖ sender_device_id ‖ u8 generation ‖ u32 counter
/// ‖ state_hash ‖ SHA3-512(content)`.
pub fn group_payload(
    group_id: &[u8; 32],
    epoch: u32,
    sender_device: &[u8; 16],
    generation: u8,
    counter: u32,
    state_hash: &[u8; 32],
    content: &[u8],
) -> Vec<u8> {
    [
        &group_id[..],
        &epoch.to_be_bytes(),
        sender_device,
        &[generation],
        &counter.to_be_bytes(),
        state_hash,
        &sha3_512(content),
    ]
    .concat()
}

/// What an admin's signature on a group state update covers (`07-groups.md`
/// §7.3): `group_id ‖ state_hash_{n-1} ‖ SHA3-512(update_n)`.
pub fn admin_payload(group_id: &[u8; 32], parent: &[u8; 32], update: &[u8]) -> Vec<u8> {
    [&group_id[..], parent, &sha3_512(update)].concat()
}

/// What a poll creator's tally signature covers: `group_id ‖ poll_id ‖
/// tally_hash`.
pub fn tally_payload(group_id: &[u8; 32], poll_id: &[u8; 16], tally_hash: &[u8; 64]) -> Vec<u8> {
    [&group_id[..], poll_id, tally_hash].concat()
}

/// Which signature: the context each is made under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A 1:1 message.
    Message,
    /// A group message.
    Group,
    /// An admin's group state update.
    Admin,
    /// A poll creator's tally.
    Tally,
}

impl Kind {
    fn ctx(self) -> &'static [u8] {
        match self {
            Kind::Message => labels::CTX_SIGNED_MESSAGE.as_bytes(),
            Kind::Group => labels::GRP_SIGNED_MSG.as_bytes(),
            Kind::Admin => labels::GRP_ADMIN_SIG.as_bytes(),
            Kind::Tally => labels::POLL_TALLY.as_bytes(),
        }
    }
}

/// Sign `payload` with a device's composite key.
pub fn sign(
    device: &CompositeSigningKey,
    kind: Kind,
    payload: &[u8],
    rng: &mut HedgedRng,
) -> Result<Vec<u8>> {
    Ok(device.sign(kind.ctx(), payload, rng)?)
}

/// Check a device's signature on `payload`.
pub fn verify(device: &CompositePublic, kind: Kind, payload: &[u8], sig: &[u8]) -> Result<()> {
    device
        .verify(kind.ctx(), payload, sig)
        .map_err(|_| ProtoError::BadSignature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn ids_and_signatures() {
        let (a, b) = ([1u8; 64], [2u8; 64]);
        assert_eq!(conv_id(&a, &b), conv_id(&b, &a), "the same on both sides");
        assert_ne!(conv_id(&a, &b), conv_id(&a, &[3; 64]));
        let mut rng = HedgedRng::new().unwrap();
        let key = CompositeSigningKey::generate(&mut rng).unwrap();
        let p = message_payload(&conv_id(&a, &b), &[4; 16], &b, 7, b"hello");
        let sig = sign(&key, Kind::Message, &p, &mut rng).unwrap();
        verify(key.public(), Kind::Message, &p, &sig).unwrap();
        assert!(
            verify(key.public(), Kind::Group, &p, &sig).is_err(),
            "context"
        );
        let other = message_payload(&conv_id(&a, &b), &[4; 16], &b, 8, b"hello");
        assert!(
            verify(key.public(), Kind::Message, &other, &sig).is_err(),
            "counter"
        );
    }
}
