//! Enclave's update channel (`docs/19-ops.md` §1, milestone R2).
//!
//! A release is described by four signed documents, TUF's roles in
//! Enclave's own encoding and signatures (ADR 0005, `docs/rfcs`):
//!
//! - **root**: the maintainers' keys, which keys sign each role and how
//!   many must, and the Sigsum policy; signed by enough of its own root
//!   keys, and a new root also by enough of the previous one's;
//! - **targets**: every release file (name, length, SHA-256, SHA3-512);
//!   co-signed by at least 2 of the 3 maintainers;
//! - **snapshot**: the targets document's version and hash;
//! - **timestamp**: the snapshot's version and hash, short-lived, so a
//!   client notices when it is kept from new releases (freeze).
//!
//! Every signature is a maintainer signature: SLH-DSA-SHAKE-256s and
//! composite Ed448 + ML-DSA-87, both under context `enclave/v1/update/release`
//! over `role ‖ body`, both required. Versions never go back (rollback),
//! documents expire. A file is installed only if its hashes are in the
//! targets and Sigsum logs its SHA-256 with enough witness cosignatures
//! ([`sigsum`]); [`Client::check`] does all of it (`VerifyUpdate`, 19 §1.5).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod metadata;
pub mod sigsum;

pub use metadata::{
    Client, MaintainerKey, MaintainerPublic, Role, RoleKeys, Root, Signed, Snapshot, Target,
    Targets, Timestamp, UpdateError,
};
