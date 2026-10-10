//! Platform code that needs `unsafe` (`docs/15-client.md` §4): the one
//! crate, with `enclave-sandbox` and `enclave-nse`, allowed it. Every
//! unsafe block has a SAFETY comment and needs two reviews.
//!
//! - [`dit`]: data-independent timing on AArch64 (FEAT_DIT) while crypto
//!   runs (`docs/02-cryptography.md` §12).
//! - [`mem`]: locked, zeroized memory for long-term secrets, so key pages
//!   are never written to swap.
//! - [`backup`]: keeping the profile directory out of OS backups.
//! - [`process`]: no console windows on Windows.
//! - [`keystore`] (feature `keystores`): the Keychain, DPAPI and the
//!   Secret Service.
//! - [`window`] (feature `window`): keeping the window out of screen
//!   capture.
//! - [`biometric`] (feature `biometric`): Touch ID and Windows Hello for
//!   the app lock.
//!
//! The desktop and mobile shims (keystores, capture exclusion, audio,
//! camera) join this crate with the desktop and mobile milestones, behind
//! features, so `enclave-crypto` keeps depending on only these two.

pub mod backup;
#[cfg(feature = "biometric")]
pub mod biometric;
pub mod dit;
#[cfg(feature = "keystores")]
pub mod keystore;
pub mod mem;
pub mod process;
#[cfg(feature = "window")]
pub mod window;
