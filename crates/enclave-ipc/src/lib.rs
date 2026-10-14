//! Messages between the UI process and the vault process
//! (`docs/15-client.md` §1, process split).
//!
//! The vault process owns every key and runs the client engine; the UI process
//! renders and never sees key material. They exchange exactly three things:
//!
//! * [`Cmd`]: what the person did (UI → vault);
//! * [`Snapshot`]: everything the window shows, as plain display data
//!   (vault → UI);
//! * [`Effect`]: a few one-off UI resets, such as closing a sheet after a
//!   request succeeded (vault → UI).
//!
//! Framing is `u32 BE length ‖ body` with a hard size cap, and a connection
//! starts with a 32-byte token the UI passed to the vault it spawned, so no
//! other local process can pose as the vault. Every decoder rejects trailing
//! bytes and oversize fields; the UI treats the vault's output as data, and
//! the vault treats commands as untrusted input.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;
pub mod frame;
pub mod media;
mod model;
pub mod net;
pub mod stdio;

pub use model::*;

/// Bytes of `width × height` RGBA, if that doesn't overflow.
pub(crate) fn rgba_len(width: u32, height: u32) -> Option<usize> {
    (width as usize)
        .checked_mul(height as usize)?
        .checked_mul(4)
}

/// Errors.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// A message could not be decoded.
    #[error("malformed message")]
    Malformed,
    /// A frame exceeded [`frame::MAX_FRAME`].
    #[error("frame too large")]
    TooLarge,
    /// The peer did not present the expected token.
    #[error("peer not authenticated")]
    Unauthenticated,
    /// I/O failure (the peer went away).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias.
pub type Result<T> = core::result::Result<T, IpcError>;
