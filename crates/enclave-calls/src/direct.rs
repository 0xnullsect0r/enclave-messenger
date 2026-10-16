//! Direct mode's candidates (`docs/11-calls.md` §4): where each side can
//! be reached, and the WireGuard key its end of the direct link uses. Sent
//! in a ratchet message (`CallMessage::Candidates`), the callee's first and
//! only once it chose to answer directly, the caller's only after the
//! callee's arrived: neither address goes out before both people agreed.
//!
//! ```text
//! 1 ‖ wg public key (32) ‖ n ‖ n × (len ‖ "IP:PORT")
//! ```

use crate::{CallError, Result};
use std::net::SocketAddr;

/// Most addresses one side names.
pub const MAX_ADDRS: usize = 8;

/// One side's candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidates {
    /// Its WireGuard public key for this call.
    pub wg: [u8; 32],
    /// Addresses to try: as its relay saw it (through the NAT), then its
    /// own on the local network.
    pub addrs: Vec<SocketAddr>,
}

impl Candidates {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![1];
        v.extend_from_slice(&self.wg);
        let addrs = &self.addrs[..self.addrs.len().min(MAX_ADDRS)];
        v.push(addrs.len() as u8);
        for a in addrs {
            let s = a.to_string();
            v.push(s.len() as u8);
            v.extend_from_slice(s.as_bytes());
        }
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let [1, rest @ ..] = b else {
            return Err(CallError::Malformed);
        };
        let wg: [u8; 32] = rest
            .get(..32)
            .and_then(|k| k.try_into().ok())
            .ok_or(CallError::Malformed)?;
        let n = usize::from(*rest.get(32).ok_or(CallError::Malformed)?);
        if n > MAX_ADDRS {
            return Err(CallError::Malformed);
        }
        let mut at = 33;
        let mut addrs = Vec::with_capacity(n);
        for _ in 0..n {
            let len = usize::from(*rest.get(at).ok_or(CallError::Malformed)?);
            let s = rest
                .get(at + 1..at + 1 + len)
                .and_then(|s| std::str::from_utf8(s).ok())
                .ok_or(CallError::Malformed)?;
            addrs.push(s.parse().map_err(|_| CallError::Malformed)?);
            at += 1 + len;
        }
        if at != rest.len() {
            return Err(CallError::Malformed);
        }
        Ok(Self { wg, addrs })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn candidates_round_trip_and_refuse_garbage() {
        let c = Candidates {
            wg: [5; 32],
            addrs: vec![
                "203.0.113.7:40000".parse().unwrap(),
                "[2001:db8::7]:40001".parse().unwrap(),
                "192.168.1.20:40000".parse().unwrap(),
            ],
        };
        assert_eq!(Candidates::decode(&c.encode()).unwrap(), c);
        let mut long = c.encode();
        long.push(0);
        assert!(Candidates::decode(&long).is_err());
        assert!(Candidates::decode(&[1, 2, 3]).is_err());
        assert!(Candidates::decode(&[]).is_err());
        let mut many = c.clone();
        many.addrs = vec![c.addrs[0]; 20];
        assert_eq!(
            Candidates::decode(&many.encode()).unwrap().addrs.len(),
            MAX_ADDRS
        );
    }
}
