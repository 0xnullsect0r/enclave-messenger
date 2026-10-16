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
//! - [`fatal`]: a scrubbed record of a native crash.
//! - [`keystore`] (feature `keystores`): the Keychain, DPAPI and the
//!   Secret Service.
//! - [`window`] (feature `window`): keeping the window out of screen
//!   capture.
//! - [`biometric`] (feature `biometric`): Touch ID and Windows Hello for
//!   the app lock.
//! - `phone` (feature `phone`, Android and iOS): file pickers, the camera,
//!   notifications, the clipboard, screen security.
//! - `seatbelt` (macOS): each helper process confines itself.
//! - `appcontainer` (Windows): mediad starts in an AppContainer.
//!
//! The desktop and mobile shims (keystores, capture exclusion, audio,
//! camera) join this crate with the desktop and mobile milestones, behind
//! features, so `enclave-crypto` keeps depending on only these two.

#[cfg(windows)]
pub mod appcontainer;
pub mod backup;
#[cfg(feature = "biometric")]
pub mod biometric;
pub mod dit;
pub mod fatal;
#[cfg(all(target_os = "android", any(feature = "keystores", feature = "phone")))]
mod jvm;
#[cfg(feature = "keystores")]
pub mod keystore;
pub mod mem;
#[cfg(all(feature = "phone", any(target_os = "android", target_os = "ios")))]
pub mod phone;
pub mod process;
#[cfg(target_os = "macos")]
pub mod seatbelt;
#[cfg(feature = "window")]
pub mod window;
