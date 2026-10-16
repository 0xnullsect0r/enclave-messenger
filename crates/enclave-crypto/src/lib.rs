//! Enclave cryptographic core.
//!
//! Everything here follows `docs/02-cryptography.md`. The public surface is
//! small on purpose:
//!
//! * [`kmac`]: KMAC256 / KMACXOF256, the only KDF, PRF and MAC.
//! * [`seal`]: EnclaveSeal-v1, the only authenticated encryption.
//! * [`kem`]: X448, ML-KEM-1024, Classic McEliece-8192128 and EnclaveCombine.
//! * [`sig`]: composite Ed448 + ML-DSA-87 signatures and the SLH-DSA root.
//! * [`rng`]: hedged randomness.
//! * [`pwhash`]: Argon2id for optional passphrases.
//! * [`hash`]: SHA3-512, SHAKE256, fingerprints and security codes.
//! * `hqc` (feature `hqc`): HQC-256, for the four-KEM suite once FIPS 207
//!   is final.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod hash;
#[cfg(feature = "hqc")]
pub mod hqc;
pub mod kem;
pub mod kmac;
pub mod labels;
pub mod pwhash;
pub mod rng;
pub mod seal;
pub mod sig;
mod x448_ladder;

pub use error::{Error, Result};
