//! Platform code that needs `unsafe` (`docs/15-client.md` §4): the one
//! crate, with `enclave-sandbox` and `enclave-nse`, allowed it. Every
//! unsafe block has a SAFETY comment and needs two reviews.
//!
//! - [`dit`]: data-independent timing on AArch64 (FEAT_DIT) while crypto
//!   runs (`docs/02-cryptography.md` §12).
//! - [`mem`]: locked, zeroized memory for long-term secrets, so key pages
//!   are never written to swap.
//!
//! The desktop and mobile shims (keystores, capture exclusion, audio,
//! camera) join this crate with the desktop and mobile milestones, behind
//! features, so `enclave-crypto` keeps depending on only these two.

pub mod dit;
pub mod mem;
