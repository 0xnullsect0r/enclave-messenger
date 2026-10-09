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
    /// Mean delay between self-loop probes (RT-02). Probes and loop cover
    /// together keep the profile's rate of packets to the device itself.
    pub probe: std::time::Duration,
}

impl Pacing {
    /// Most packets per second in bulk (`docs/09-transport.md` §6.4).
    pub const BULK_PACKETS_PER_SEC: u32 = 40;

    /// Encoded length.
    pub const LEN: usize = 13;

    /// `u32 tick_ms ‖ u8 bulk ‖ u32 loop_cover_ms ‖ u32 probe_ms`.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let ms = |d: std::time::Duration| u32::try_from(d.as_millis()).unwrap_or(u32::MAX);
        let mut b = [0u8; Self::LEN];
        b[..4].copy_from_slice(&ms(self.tick).to_be_bytes());
        b[4] = u8::from(self.bulk);
        b[5..9].copy_from_slice(&ms(self.loop_cover).to_be_bytes());
        b[9..].copy_from_slice(&ms(self.probe).to_be_bytes());
        b
    }

    /// Strict inverse of [`Pacing::encode`].
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b: &[u8; Self::LEN] = b.try_into().ok()?;
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
            loop_cover: ms(&b[5..9])?,
            probe: ms(&b[9..])?,
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
    /// The gateway this client is connected to (on Nym, the part of its
    /// address after `@`).
    fn gateway(&self) -> Option<String> {
        self.address().split_once('@').map(|(_, g)| g.to_string())
    }
    /// Connect through another gateway (RT-02, `docs/09-transport.md`
    /// §6.3), returning it. The address may change; replies already on
    /// their way to the old one may be lost.
    async fn switch_gateway(&self) -> Result<String> {
        Err(NymError::Client("this client can't switch gateway".into()))
    }
    /// HTTP through the client's proxy (Tor on a device): the status and
    /// the body. For the credential gate (`docs/09-transport.md` §7).
    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        let _ = (method, url, body);
        Err(NymError::Client("this client can't fetch".into()))
    }
    /// Buy a zk-nym ticketbook from the credential gate at `gate` with one
    /// Privacy Pass token: a [`Held`] (nothing spent) encoded, to keep.
    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
        let _ = (gate, token);
        Err(NymError::Client("this client can't buy tickets".into()))
    }
    /// zk-nym tickets this client's process has spent with gateways so
    /// far ([`advance`] says from which ticketbooks).
    async fn tickets_spent(&self) -> Result<u64> {
        Ok(0)
    }
}

/// A zk-nym ticketbook a device holds (`docs/09-transport.md` §7): how
/// many tickets it has, how many are spent, and nym's stored form
/// (`ImportableTicketBook`, opaque here). Encoded `u32 total ‖ u32 spent ‖
/// book`, in pipe frame 6 and netd's `Connect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    /// Tickets in the book.
    pub total: u32,
    /// Tickets spent.
    pub spent: u32,
    /// nym's stored form.
    pub book: Vec<u8>,
}

impl Held {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        [
            &self.total.to_be_bytes()[..],
            &self.spent.to_be_bytes(),
            &self.book,
        ]
        .concat()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < 8 {
            return Err(NymError::Malformed);
        }
        let total = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let spent = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        if spent > total {
            return Err(NymError::Malformed);
        }
        Ok(Self {
            total,
            spent,
            book: b[8..].to_vec(),
        })
    }

    /// Tickets left.
    pub fn left(&self) -> u32 {
        self.total - self.spent
    }
}

/// `held` after `n` more tickets were spent: a client spends them from
/// its ticketbooks in the order they were imported (our patched
/// nym-credential-storage), each from where it was.
pub fn advance(held: &[Held], n: u64) -> Vec<Held> {
    let mut n = n;
    held.iter()
        .map(|h| {
            let take = u64::from(h.left()).min(n);
            n -= take;
            Held {
                spent: h.spent + take as u32,
                ..h.clone()
            }
        })
        .collect()
}

#[cfg(test)]
mod held_tests {
    use super::*;

    #[test]
    fn spending_goes_through_the_books_in_order() {
        let h = |total, spent| Held {
            total,
            spent,
            book: vec![1, 2],
        };
        let books = [h(10, 8), h(5, 0), h(3, 0)];
        let after = advance(&books, 4);
        assert_eq!(
            after.iter().map(|b| b.spent).collect::<Vec<_>>(),
            vec![10, 2, 0]
        );
        assert_eq!(
            advance(&books, 100).iter().map(|b| b.left()).sum::<u32>(),
            0
        );
        let e = h(7, 3).encode();
        assert_eq!(Held::decode(&e), Ok(h(7, 3)));
        assert!(Held::decode(&e[..7]).is_err());
        assert!(Held::decode(&h(2, 3).encode()).is_err());
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
            loop_cover: Duration::from_secs(160),
            probe: Duration::from_secs(480),
        };
        assert_eq!(Pacing::decode(&p.encode()), Some(p));
        let mut b = p.encode();
        b[4] = 2;
        assert_eq!(Pacing::decode(&b), None);
        assert_eq!(Pacing::decode(&b[..12]), None);
    }
}
