//! The Enclave app. The UI (Slint) never touches key material: it sends
//! commands to the vault ([`enclave_vault`]), which owns `enclave_core::Client`,
//! and receives plain display data back. On Unix desktops the vault is a
//! separate process ([`vault`]); elsewhere it is a thread.

pub mod camera;
pub mod format;
pub mod i18n;
pub mod lan;
pub mod shell;
pub mod vault;
pub mod view;

/// Code generated from `ui/*.slint`. The only place `unsafe` is allowed.
#[allow(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo
)]
mod ui {
    slint::include_modules!();
}
pub use ui::*;
