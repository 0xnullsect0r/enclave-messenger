//! Enclave over the Nym mixnet (`docs/09-transport.md` §1, §7).
//!
//! A client sends each sealed request to the destination server's Nym
//! address with fresh single-use reply blocks (SURBs) and a fresh sender
//! tag; the server's ingress (`enclave-ingress`) forwards it to the server
//! and answers over those SURBs. Everything here is independent of
//! nym-sdk: the frames that cross the mixnet ([`frame`]), the interface a
//! mixnet client offers ([`MixnetDriver`]), and an in-process mixnet with
//! loss, delay and reordering for tests ([`fake::FakeMixnet`]).
//!
//! The nym-sdk driver lives in the separate `nym/` workspace: nym-sdk and
//! arti (Tor) link different, conflicting versions of SQLite, so they can't
//! share one lockfile, and the processes that run them are separate anyway
//! (the stack's ingress; the client's mixnet process beside netd).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod fake;
pub mod frame;
pub mod pipe;

/// Errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum NymError {
    /// A frame that doesn't parse.
    #[error("malformed frame")]
    Malformed,
    /// The destination isn't on the mixnet (unknown address).
    #[error("unknown recipient")]
    UnknownRecipient,
    /// The reply blocks for this tag are used up (or it never had any).
    #[error("no reply blocks left")]
    NoSurbs,
    /// The client is shut down.
    #[error("mixnet client closed")]
    Closed,
    /// Anything the mixnet client reported.
    #[error("mixnet: {0}")]
    Client(String),
}

/// Result type.
pub type Result<T> = core::result::Result<T, NymError>;

/// The handle a received message gives for answering it: the sender's
/// anonymous tag (16 bytes in Nym), which maps to its SURBs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReplyTag(pub [u8; 16]);

/// A message out of the mixnet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    /// The bytes.
    pub data: Vec<u8>,
    /// How to answer it, if it came with reply blocks.
    pub reply: Option<ReplyTag>,
}

/// How a device's mixnet client paces what it sends
/// (`docs/09-transport.md` §6.3), from its traffic profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pacing {
    /// The tick a unit and a poll are sent in: their packets leave evenly
    /// across it.
    pub tick: std::time::Duration,
    /// A bulk transfer is under way: packets leave at the bulk cap instead.
    pub bulk: bool,
    /// Mean delay between loop cover packets.
    pub loop_cover: std::time::Duration,
}

impl Pacing {
    /// Most packets per second in bulk (`docs/09-transport.md` §6.4).
    pub const BULK_PACKETS_PER_SEC: u32 = 40;

    /// `u32 tick_ms ‖ u8 bulk ‖ u32 loop_cover_ms`.
    pub fn encode(&self) -> [u8; 9] {
        let ms = |d: std::time::Duration| u32::try_from(d.as_millis()).unwrap_or(u32::MAX);
        let mut b = [0u8; 9];
        b[..4].copy_from_slice(&ms(self.tick).to_be_bytes());
        b[4] = u8::from(self.bulk);
        b[5..].copy_from_slice(&ms(self.loop_cover).to_be_bytes());
        b
    }

    /// Strict inverse of [`Pacing::encode`].
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b: &[u8; 9] = b.try_into().ok()?;
        let ms = |x: &[u8]| -> Option<std::time::Duration> {
            Some(std::time::Duration::from_millis(u64::from(
                u32::from_be_bytes(x.try_into().ok()?),
            )))
        };
        Some(Self {
            tick: ms(&b[..4])?,
            bulk: match b[4] {
                0 => false,
                1 => true,
                _ => return None,
            },
            loop_cover: ms(&b[5..])?,
        })
    }
}

/// What Enclave needs from a mixnet client: its own address, sending to an
/// address with reply blocks for an answer of `reply_len` bytes, answering
/// over a tag's reply blocks, and receiving.
#[async_trait::async_trait]
pub trait MixnetDriver: Send + Sync {
    /// This client's address (what a server descriptor publishes).
    fn address(&self) -> String;
    /// Send `data` to `to` with enough fresh SURBs (under a fresh sender
    /// tag) for one answer of `reply_len` bytes; 0 for none.
    async fn send(&self, to: &str, data: Vec<u8>, reply_len: usize) -> Result<()>;
    /// Answer a message over its sender's SURBs.
    async fn reply(&self, tag: ReplyTag, data: Vec<u8>) -> Result<()>;
    /// The next message for this client; `None` once it's shut down.
    async fn recv(&self) -> Option<Incoming>;
    /// Wait until everything sent so far has left and reached the far
    /// gateway, for at most `within`: a client about to exit calls this, as
    /// a one-way send still queued in the client is lost with the process.
    /// `false` if time ran out first.
    async fn flush(&self, within: std::time::Duration) -> bool {
        let _ = within;
        true
    }
    /// Pace what is sent from now on (a device's client; the ingress
    /// doesn't pace).
    fn set_pacing(&self, pacing: Pacing) {
        let _ = pacing;
    }
}

#[cfg(test)]
mod pacing_tests {
    #![allow(clippy::unwrap_used)]
    use super::Pacing;
    use std::time::Duration;

    #[test]
    fn pacing_codec() {
        let p = Pacing {
            tick: Duration::from_secs(3),
            bulk: false,
            loop_cover: Duration::from_secs(120),
        };
        assert_eq!(Pacing::decode(&p.encode()), Some(p));
        let mut b = p.encode();
        b[4] = 2;
        assert_eq!(Pacing::decode(&b), None);
        assert_eq!(Pacing::decode(&b[..8]), None);
    }
}
