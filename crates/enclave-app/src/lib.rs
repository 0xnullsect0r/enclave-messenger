//! The Enclave app. The UI (Slint) never touches key material: it sends
//! commands to the vault ([`enclave_vault`]), which owns `enclave_core::Client`,
//! and receives plain display data back. On Unix desktops the vault is a
//! separate process ([`vault`]); elsewhere it is a thread.

pub mod audio;
#[cfg(desktop)]
pub mod background;
pub mod camera;
pub mod format;
#[cfg(desktop)]
pub mod handoff;
pub mod i18n;
pub mod lan;
pub mod screen;
pub mod shell;
#[cfg(desktop)]
pub mod updater;
pub mod vault;
pub mod video;
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
