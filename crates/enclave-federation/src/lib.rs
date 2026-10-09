//! The signed objects that tie Enclave's federation together
//! (`docs/12-servers.md` §4).
//!
//! * [`KeyCert`] / [`KeyBundle`]: a server's daily request key, signed by
//!   the server's identity key. A server id is a hash of that identity key
//!   ([`server_id`]), so a client holding only an id can check a key
//!   certificate it fetched over an untrusted path.
//! * [`ServerDescriptor`]: what a server says about itself (domain,
//!   operator and family, Nym address, policy, key-transparency keys,
//!   request-key certificates), signed by its identity key.
//! * [`WitnessDescriptor`] and [`RelayDescriptor`]: the same for
//!   key-transparency witnesses and call relays.
//! * [`ServerList`]: the foundation's list of vetted servers, witnesses,
//!   relays and push relays, signed with both SLH-DSA-SHAKE-256s and the
//!   composite Ed448 + ML-DSA-87 key, with a sequence number clients only
//!   ever move forward.
//!
//! Every encoding is canonical (the rules of `enclave_proto::codec`): one byte string
//! per value, trailing bytes refused, every signature over every byte
//! before it.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;
pub mod descriptor;
pub mod keycert;
pub mod list;
pub mod relay;
pub mod witness;

pub use descriptor::{BlobIssuer, KtKeys, Policy, ServerDescriptor};
pub use keycert::{KeyBundle, KeyCert};
pub use list::{
    CredGateEntry, FoundationKey, FoundationPublic, ListedRelay, ListedServer, ListedWitness,
    PushRelayEntry, ServerList,
};
pub use relay::{RelayDescriptor, relay_id};
pub use witness::{WitnessDescriptor, witness_id};

use enclave_crypto::hash::shake256;
use enclave_crypto::sig::CompositePublic;

/// Label of the server id.
pub const SERVER_ID_LABEL: &str = "enclave/v1/net/server-id";

/// Longest domain name.
pub const MAX_DOMAIN: usize = 253;
/// Longest operator or family name.
pub const MAX_NAME: usize = 128;
/// Longest network address (Nym address, onion address, URL).
pub const MAX_ADDRESS: usize = 512;

/// The server id: the first 16 bytes of
/// `SHAKE256("enclave/v1/net/server-id" ‖ identity public key)`.
pub fn server_id(identity: &CompositePublic) -> [u8; 16] {
    let h: [u8; 32] = shake256(&[SERVER_ID_LABEL.as_bytes(), &identity.to_bytes()].concat());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

/// Why a federation object was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FedError {
    /// Not a valid encoding.
    #[error("malformed")]
    Malformed,
    /// A signature didn't verify.
    #[error("bad signature")]
    Signature,
    /// Signed by a key that isn't the expected server's.
    #[error("not the expected server")]
    WrongId,
    /// Outside its validity window.
    #[error("expired or not yet valid")]
    Expired,
    /// Older than (or the same as) what the client already holds.
    #[error("not newer than the list held")]
    Stale,
    /// Not what the server's key-transparency log commits to (or the log's
    /// answer didn't verify under the pinned keys and witnesses).
    #[error("not the descriptor the server's log commits to")]
    NotLogged,
    /// Signing failed.
    #[error("signing failed")]
    Crypto,
}

/// Result alias.
pub type Result<T> = core::result::Result<T, FedError>;

pub(crate) fn utf8(b: &[u8]) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| FedError::Malformed)
}

pub(crate) fn read_composite(r: &mut crate::codec::Reader<'_>) -> Result<CompositePublic> {
    CompositePublic::from_slice(r.fixed(enclave_crypto::sig::COMPOSITE_PK_LEN)?)
        .map_err(|_| FedError::Malformed)
}

pub(crate) fn read_sig<'a>(r: &mut crate::codec::Reader<'a>) -> Result<&'a [u8]> {
    r.fixed(enclave_crypto::sig::COMPOSITE_SIG_LEN)
}
