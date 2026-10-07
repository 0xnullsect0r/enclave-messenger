//! Frames on the mixnet (`docs/09-transport.md` §1).
//!
//! ```text
//! request = u8(1) ‖ u8 kind ‖ req_id (16) ‖ body
//!     kind 1: a sealed unit, body 16,384 B
//!     kind 2: a sealed poll, body 2,048 B
//!     kind 3: the server's key bundle, body 2,048 zero bytes
//!     kind 5: a sealed unit sent one way, body 16,384 B: no reply blocks,
//!             and the ingress drops the server's answer (writes and cover,
//!             `docs/09-transport.md` §6.1)
//! reply   = u8(1) ‖ u8 status ‖ req_id (16) ‖ u32 len ‖ data ‖ zeros   = 16,406 B
//!     status 0: data is the server's answer; 1: the server didn't answer
//! wake    = u8(1) ‖ u8(4) ‖ u16 len ‖ data ‖ zeros                     = 3,074 B
//!     a push wake from a server's push egress to the push relay's
//!     ingress (`docs/10-push.md`), one way: no reply blocks
//! ```
//!
//! Every request of a size class has the same length, and a key fetch looks
//! like a poll; every reply has one length. `req_id` is random per request:
//! it matches a reply to its request at the client, and means nothing to
//! anyone else.

use crate::{NymError, Result};
use enclave_wire::{POLL_LEN, UNIT_LEN};

const VERSION: u8 = 1;
/// Header: version, kind or status, request id.
pub const HEADER_LEN: usize = 18;
/// Every reply frame's length.
pub const REPLY_LEN: usize = HEADER_LEN + 4 + UNIT_LEN;

/// What a request carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A sealed unit (16,384 B).
    Unit = 1,
    /// A sealed poll (2,048 B).
    Poll = 2,
    /// The server's key bundle (a zero-length request on the server's own
    /// framing).
    Key = 3,
    /// A sealed unit sent one way: nobody answers it.
    Oneway = 5,
    /// A self-loop probe: a header only, sent by a device to its own
    /// address to measure its gateway path (`docs/09-transport.md` §6.3).
    Probe = 6,
}

/// A request on the mixnet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// What it is.
    pub kind: Kind,
    /// Matches the reply.
    pub id: [u8; 16],
    /// The sealed bytes (empty for [`Kind::Key`]).
    pub body: Vec<u8>,
}

impl Request {
    /// A request for these sealed bytes: a unit, a poll, or (empty) a key
    /// fetch.
    pub fn for_sealed(id: [u8; 16], sealed: Vec<u8>) -> Result<Self> {
        let kind = match sealed.len() {
            0 => Kind::Key,
            UNIT_LEN => Kind::Unit,
            POLL_LEN => Kind::Poll,
            _ => return Err(NymError::Malformed),
        };
        Ok(Self {
            kind,
            id,
            body: sealed,
        })
    }

    /// A sealed unit sent one way ([`Kind::Oneway`]).
    pub fn oneway(id: [u8; 16], sealed: Vec<u8>) -> Result<Self> {
        if sealed.len() != UNIT_LEN {
            return Err(NymError::Malformed);
        }
        Ok(Self {
            kind: Kind::Oneway,
            id,
            body: sealed,
        })
    }

    /// A self-loop probe with this id ([`Kind::Probe`]).
    pub fn probe(id: [u8; 16]) -> Self {
        Self {
            kind: Kind::Probe,
            id,
            body: Vec::new(),
        }
    }

    /// Encode, padded to its class.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN + UNIT_LEN);
        v.push(VERSION);
        v.push(self.kind as u8);
        v.extend_from_slice(&self.id);
        match self.kind {
            Kind::Key => v.resize(HEADER_LEN + POLL_LEN, 0),
            Kind::Probe => {}
            _ => v.extend_from_slice(&self.body),
        }
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let (&version, rest) = b.split_first().ok_or(NymError::Malformed)?;
        let (&kind, rest) = rest.split_first().ok_or(NymError::Malformed)?;
        if version != VERSION || rest.len() < 16 {
            return Err(NymError::Malformed);
        }
        let (id, body) = rest.split_at(16);
        let id: [u8; 16] = id.try_into().map_err(|_| NymError::Malformed)?;
        let (kind, body) = match (kind, body.len()) {
            (1, UNIT_LEN) => (Kind::Unit, body.to_vec()),
            (2, POLL_LEN) => (Kind::Poll, body.to_vec()),
            (3, POLL_LEN) => (Kind::Key, Vec::new()),
            (5, UNIT_LEN) => (Kind::Oneway, body.to_vec()),
            (6, 0) => (Kind::Probe, Vec::new()),
            _ => return Err(NymError::Malformed),
        };
        Ok(Self { kind, id, body })
    }
}

/// Room in a [`Wake`] (a sealed push token of 1,952 B now, and a 1,024 B
/// preview capsule later, `docs/10-push.md`), length prefix included.
pub const WAKE_LEN: usize = 3_072;

/// A push wake on the mixnet, one way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wake(pub Vec<u8>);

impl Wake {
    /// Encode, padded to `2 + WAKE_LEN`. Too long is refused.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let n = u16::try_from(self.0.len()).map_err(|_| NymError::Malformed)?;
        if self.0.len() > WAKE_LEN - 2 {
            return Err(NymError::Malformed);
        }
        let mut v = Vec::with_capacity(2 + WAKE_LEN);
        v.extend_from_slice(&[VERSION, 4]);
        v.extend_from_slice(&n.to_be_bytes());
        v.extend_from_slice(&self.0);
        v.resize(2 + WAKE_LEN, 0);
        Ok(v)
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != 2 + WAKE_LEN || b[0] != VERSION || b[1] != 4 {
            return Err(NymError::Malformed);
        }
        let n = usize::from(u16::from_be_bytes([b[2], b[3]]));
        if n > WAKE_LEN - 2 {
            return Err(NymError::Malformed);
        }
        Ok(Self(b[4..4 + n].to_vec()))
    }
}

/// A reply on the mixnet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Matches the request.
    pub id: [u8; 16],
    /// The server's answer, or `None` if it didn't answer.
    pub data: Option<Vec<u8>>,
}

impl Reply {
    /// Encode, padded to [`REPLY_LEN`]. An answer longer than a unit is
    /// refused.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let data = self.data.as_deref().unwrap_or_default();
        if data.len() > UNIT_LEN {
            return Err(NymError::Malformed);
        }
        let mut v = Vec::with_capacity(REPLY_LEN);
        v.push(VERSION);
        v.push(u8::from(self.data.is_none()));
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_be_bytes());
        v.extend_from_slice(data);
        v.resize(REPLY_LEN, 0);
        Ok(v)
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != REPLY_LEN || b[0] != VERSION || b[1] > 1 {
            return Err(NymError::Malformed);
        }
        let id: [u8; 16] = b[2..18].try_into().map_err(|_| NymError::Malformed)?;
        let n = u32::from_be_bytes(b[18..22].try_into().map_err(|_| NymError::Malformed)?) as usize;
        if n > UNIT_LEN {
            return Err(NymError::Malformed);
        }
        let data = (b[1] == 0).then(|| b[22..22 + n].to_vec());
        Ok(Self { id, data })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn classes_and_round_trips() {
        let unit = Request::for_sealed([1; 16], vec![7; UNIT_LEN]).unwrap();
        let poll = Request::for_sealed([2; 16], vec![8; POLL_LEN]).unwrap();
        let key = Request::for_sealed([3; 16], Vec::new()).unwrap();
        assert_eq!(unit.encode().len(), HEADER_LEN + UNIT_LEN);
        assert_eq!(
            poll.encode().len(),
            key.encode().len(),
            "a key fetch looks like a poll"
        );
        let oneway = Request::oneway([4; 16], vec![9; UNIT_LEN]).unwrap();
        assert_eq!(
            oneway.encode().len(),
            unit.encode().len(),
            "a one-way unit is a unit's size"
        );
        assert!(Request::oneway([0; 16], vec![0; POLL_LEN]).is_err());
        let probe = Request::probe([5; 16]);
        assert_eq!(
            probe.encode().len(),
            HEADER_LEN,
            "a probe is one small packet"
        );
        let mut long = probe.encode();
        long.push(0);
        assert!(Request::decode(&long).is_err());
        for r in [unit, poll, key, oneway, probe] {
            assert_eq!(Request::decode(&r.encode()).unwrap(), r);
        }
        assert!(Request::for_sealed([0; 16], vec![0; 100]).is_err());
        let mut bad = Request::for_sealed([3; 16], Vec::new()).unwrap().encode();
        bad.pop();
        assert!(Request::decode(&bad).is_err());

        for data in [
            Some(vec![5; UNIT_LEN]),
            Some(vec![]),
            None,
            Some(vec![1, 2, 3]),
        ] {
            let r = Reply { id: [9; 16], data };
            let e = r.encode().unwrap();
            assert_eq!(e.len(), REPLY_LEN, "one length for every reply");
            assert_eq!(Reply::decode(&e).unwrap(), r);
        }
        assert!(
            Reply {
                id: [0; 16],
                data: Some(vec![0; UNIT_LEN + 1])
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn wakes_have_one_length() {
        let a = Wake(vec![7; 1_952]).encode().unwrap();
        let b = Wake(vec![8; 2_976]).encode().unwrap();
        assert_eq!(a.len(), b.len());
        assert_eq!(Wake::decode(&a).unwrap(), Wake(vec![7; 1_952]));
        assert!(Wake(vec![0; WAKE_LEN - 1]).encode().is_err());
        assert!(Wake::decode(&a[..a.len() - 1]).is_err());
        // Not a request, and a request isn't a wake.
        assert!(Request::decode(&a).is_err());
        let poll = Request::for_sealed([2; 16], vec![8; POLL_LEN]).unwrap();
        assert!(Wake::decode(&poll.encode()).is_err());
    }
}
