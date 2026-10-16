//! Voice and video calls (`docs/11-calls.md`).
//!
//! * [`message`]: the signalling messages (offer, answer, ringing, end…) as
//!   they ride in ratchet messages.
//! * [`signal`]: the offer/answer exchange carried in ratchet messages. Every
//!   call does a fresh X448 + ML-KEM-1024 exchange, so call keys are
//!   independent of chat keys.
//! * [`sframe`]: media encryption. SFrame (RFC 9605) with the private-use
//!   EnclaveSeal suite; per-sender base keys ratchet every 5 s; a sliding
//!   replay window per key.
//! * [`shape`]: constant-rate traffic shaping. Every packet of a stream has
//!   the same size and leaves at the same rate whatever the content, and
//!   quality only ever steps down.
//! * [`ticket`]: relay tickets and the per-period link keys derived from them.
//! * [`route`]: choosing the two relays of a call from distinct operator
//!   families.
//!
//! No call state is ever persisted.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod link;
pub mod message;
pub mod route;
pub mod sframe;
pub mod shape;
pub mod signal;
pub mod ticket;

/// KMAC labels (`docs/label-registry.md`).
pub mod labels {
    /// Call transcript prefix.
    pub const TRANSCRIPT: &str = "enclave/v1/calls/transcript";
    /// Call secret.
    pub const SECRET: &str = "enclave/v1/calls/secret";
    /// Initial per-sender SFrame base key.
    pub const SFRAME_BASE: &str = "enclave/v1/calls/sframe-base";
    /// SFrame base-key ratchet step.
    pub const SFRAME_RATCHET: &str = "enclave/v1/calls/sframe-ratchet";
    /// SFrame key and salt for one KID.
    pub const SFRAME_KEY: &str = "enclave/v1/calls/sframe-key";
    /// SFrame associated-data prefix.
    pub const AD_SFRAME: &str = "enclave/v1/calls/ad-sframe";
    /// Two-word call check.
    pub const CHECK_WORDS: &str = "enclave/v1/calls/check-words";
    /// Direct-mode tunnel PSK.
    pub const DIRECT_PSK: &str = "enclave/v1/calls/direct-psk";
    /// Relay-ticket transcript prefix.
    pub const TICKET_TRANSCRIPT: &str = "enclave/v1/calls/ticket-transcript";
    /// Relay ticket secret.
    pub const TICKET_SECRET: &str = "enclave/v1/calls/ticket-secret";
    /// Relay ticket request sealing key.
    pub const TICKET_SEAL: &str = "enclave/v1/calls/ticket-seal";
    /// Relay ticket associated-data prefix.
    pub const AD_TICKET: &str = "enclave/v1/calls/ad-ticket";
    /// Per-period link PSK.
    pub const WG_PSK: &str = "enclave/v1/calls/wg-psk";
    /// Relay rendezvous id joining the two legs of a call.
    pub const RENDEZVOUS: &str = "enclave/v1/calls/rendezvous";
    /// Per-direction link key from a period PSK.
    pub const LINK_DIR: &str = "enclave/v1/calls/link-dir";
    /// Relay-to-relay link key.
    pub const RELAY_LINK: &str = "enclave/v1/calls/relay-link";
    /// A day's ticket-key material from that day's chain seed.
    pub const TICKET_KEY: &str = "enclave/v1/calls/ticket-key";
    /// Stepping the ticket-key chain to the next day.
    pub const TICKET_CHAIN: &str = "enclave/v1/calls/ticket-chain";
}

/// Errors from calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// Authentication or decryption failed.
    #[error("cryptographic failure")]
    Crypto,
    /// Malformed input.
    #[error("malformed")]
    Malformed,
    /// A frame was replayed or is too old.
    #[error("replayed or too old")]
    Replay,
    /// Key for this frame is gone (older than the grace period) or unknown.
    #[error("unknown key")]
    UnknownKey,
    /// Payload too large for the stream's fixed packet size.
    #[error("payload too large")]
    TooLarge,
    /// The offer expired or the answer does not match.
    #[error("offer expired or does not match")]
    Stale,
    /// A relay's storage failed; the request may be retried.
    #[error("storage unavailable")]
    Unavailable,
}

impl From<enclave_crypto::Error> for CallError {
    fn from(_: enclave_crypto::Error) -> Self {
        CallError::Crypto
    }
}

/// Result alias.
pub type Result<T> = core::result::Result<T, CallError>;
