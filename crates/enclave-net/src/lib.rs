//! Enclave networking (`docs/09-transport.md`).
//!
//! * [`transport`]: how sealed requests reach servers. Production uses Nym over
//!   Tor; development uses plain TCP; tests use an in-memory network.
//! * [`schedule`]: the cover-traffic scheduler. Every client in a given
//!   profile emits exactly the same traffic shape whatever the user does: real
//!   messages *replace* cover slots, polls rotate through mailboxes one per
//!   request, and only three global profiles exist, because any per-user
//!   tuning would become a fingerprint.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod monitor;
pub mod schedule;
pub mod shaped;
pub mod transport;

/// Errors from the network layer.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Could not reach the server.
    #[error("unreachable: {0}")]
    Unreachable(String),
    /// The reply was malformed or failed to authenticate.
    #[error("bad reply")]
    BadReply,
    /// I/O error.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The requested transport is not compiled in or not available.
    #[error("transport unavailable: {0}")]
    Unavailable(&'static str),
    /// A droppable request found no free slot in time (`shaped`).
    #[error("dropped: no free slot")]
    Dropped,
    /// The server's request key isn't certified by the identity its id
    /// names (`enclave_federation::KeyBundle`): someone else answered.
    #[error("server key not certified: {0}")]
    Untrusted(enclave_federation::FedError),
}

/// Result alias.
pub type Result<T> = core::result::Result<T, NetError>;
