//! Key transparency (`docs/12-servers.md` §12.2).
//!
//! Each Enclave server runs an append-only verifiable map from usernames to
//! account root keys, built on Meta's audited `akd` library with an Enclave
//! configuration that hashes with SHAKE256 (SHA-3 family). On top of `akd`:
//!
//! * **Signed tree heads**: `(server, epoch, root, time)` signed with the
//!   server's composite Ed448 + ML-DSA-87 key.
//! * **Witnesses** cosign a head only after checking an append-only proof from
//!   the last head they cosigned, so a server cannot show different users
//!   different histories without a quorum of witnesses colluding.
//! * **Clients** accept a lookup only with the server signature and at least
//!   `threshold` cosignatures from their pinned witness list. The median witness
//!   timestamp is Enclave's trusted time.
//! * **Gossip**: a 32-byte digest of the latest head rides in message padding
//!   between contacts, so split views surface even without witnesses.
//!
//! Label privacy uses akd's classical ECVRF (Ed25519). That only hides
//! usernames from enumeration; binding is hash-based and post-quantum.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod c2sp;
pub mod config;
pub mod head;
pub mod log;
pub mod service;
pub mod store;
pub mod username;
pub mod wire;

pub use config::EnclaveKtConfig;
pub use head::{Cosignature, Equivocation, SignedHead, TreeHead, WitnessPolicy};
pub use log::{
    ACCOUNT_RECORD_LEN, ACCOUNT_TAG, AbsenceProof, KtLog, Witness, WitnessClient, account_label,
    account_record, migration_record, tombstone_record, verify_absence, verify_descriptor_lookup,
    verify_label_lookup, verify_lookup,
};
pub use service::KtService;
pub use store::KtStore;
pub use wire::{KtInfo, KtPolicy, LookupReply, NameAnswer, UsernameClaim};

/// Errors from key transparency.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum KtError {
    /// A signature or cosignature did not verify.
    #[error("bad signature")]
    Signature,
    /// Not enough valid witness cosignatures.
    #[error("witness quorum not met")]
    Quorum,
    /// The append-only proof failed: the server rewrote history.
    #[error("history is not append-only")]
    NotAppendOnly,
    /// The log was proven to sign two trees for one epoch.
    #[error("the log equivocated")]
    Equivocated,
    /// A lookup proof failed.
    #[error("lookup proof failed")]
    Lookup,
    /// The head is too old or from the future.
    #[error("stale head")]
    Stale,
    /// The username is not allowed.
    #[error("username not allowed")]
    Username,
    /// An encoding could not be parsed.
    #[error("malformed")]
    Malformed,
    /// The key-transparency service has stopped.
    #[error("service stopped")]
    Stopped,
    /// Internal akd error.
    #[error("directory error: {0}")]
    Directory(String),
}

/// Result alias.
pub type Result<T> = core::result::Result<T, KtError>;
