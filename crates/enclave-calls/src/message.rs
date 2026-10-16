//! Call signalling as it rides in ratchet messages (`docs/11-calls.md` §2):
//! one byte for what it is, then its body.
//!
//! ```text
//! 1 ‖ Offer      the caller's keys, media, route and relay
//! 2 ‖ Answer     the callee's keys and relay
//! 3 ‖ call_id    ringing (the callee's device has the offer)
//! 4 ‖ call_id    declined
//! 5 ‖ call_id    busy (already in a call)
//! 6 ‖ call_id    ended (either side, at any time)
//! 7 ‖ call_id ‖ bytes   direct-mode candidates (§4)
//! ```

use crate::signal::{Answer, Offer};
use crate::{CallError, Result};

/// One signalling message.
#[derive(Clone, PartialEq, Eq)]
pub enum CallMessage {
    /// A new call.
    Offer(Offer),
    /// The call was taken.
    Answer(Answer),
    /// The callee's device is ringing.
    Ringing([u8; 16]),
    /// The callee said no.
    Decline([u8; 16]),
    /// The callee is in another call.
    Busy([u8; 16]),
    /// Hung up, or the caller gave up before an answer.
    End([u8; 16]),
    /// Addresses to try for a direct call.
    Candidates([u8; 16], Vec<u8>),
}

impl std::fmt::Debug for CallMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, id) = match self {
            CallMessage::Offer(o) => ("Offer", o.call_id),
            CallMessage::Answer(a) => ("Answer", a.call_id),
            CallMessage::Ringing(id) => ("Ringing", *id),
            CallMessage::Decline(id) => ("Decline", *id),
            CallMessage::Busy(id) => ("Busy", *id),
            CallMessage::End(id) => ("End", *id),
            CallMessage::Candidates(id, _) => ("Candidates", *id),
        };
        write!(f, "{name}({:02x}{:02x}…)", id[0], id[1])
    }
}

/// Most bytes of direct-mode candidates.
pub const MAX_CANDIDATES: usize = 1024;

impl CallMessage {
    /// The call it is about.
    pub fn call_id(&self) -> [u8; 16] {
        match self {
            CallMessage::Offer(o) => o.call_id,
            CallMessage::Answer(a) => a.call_id,
            CallMessage::Ringing(id)
            | CallMessage::Decline(id)
            | CallMessage::Busy(id)
            | CallMessage::End(id)
            | CallMessage::Candidates(id, _) => *id,
        }
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            CallMessage::Offer(o) => {
                out.push(1);
                out.extend_from_slice(&o.encode());
            }
            CallMessage::Answer(a) => {
                out.push(2);
                out.extend_from_slice(&a.encode());
            }
            CallMessage::Ringing(id) => {
                out.push(3);
                out.extend_from_slice(id);
            }
            CallMessage::Decline(id) => {
                out.push(4);
                out.extend_from_slice(id);
            }
            CallMessage::Busy(id) => {
                out.push(5);
                out.extend_from_slice(id);
            }
            CallMessage::End(id) => {
                out.push(6);
                out.extend_from_slice(id);
            }
            CallMessage::Candidates(id, c) => {
                out.push(7);
                out.extend_from_slice(id);
                out.extend_from_slice(c);
            }
        }
        out
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let (&tag, rest) = b.split_first().ok_or(CallError::Malformed)?;
        let id = || -> Result<[u8; 16]> {
            rest.get(..16)
                .and_then(|s| s.try_into().ok())
                .ok_or(CallError::Malformed)
        };
        let only_id = || -> Result<[u8; 16]> {
            if rest.len() == 16 {
                id()
            } else {
                Err(CallError::Malformed)
            }
        };
        Ok(match tag {
            1 => CallMessage::Offer(Offer::decode(rest)?),
            2 => CallMessage::Answer(Answer::decode(rest)?),
            3 => CallMessage::Ringing(only_id()?),
            4 => CallMessage::Decline(only_id()?),
            5 => CallMessage::Busy(only_id()?),
            6 => CallMessage::End(only_id()?),
            7 => {
                let c = &rest[16.min(rest.len())..];
                if c.len() > MAX_CANDIDATES {
                    return Err(CallError::Malformed);
                }
                CallMessage::Candidates(id()?, c.to_vec())
            }
            _ => return Err(CallError::Malformed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{Media, Route};
    use enclave_crypto::rng::HedgedRng;

    #[test]
    fn messages_round_trip() {
        let mut rng = HedgedRng::new().unwrap_or_else(|_| unreachable!());
        let pending =
            crate::signal::offer(Media::Audio, Route::Relay, b"relay".to_vec(), 7, &mut rng)
                .unwrap_or_else(|_| unreachable!());
        let offer = pending.offer().clone();
        let id = offer.call_id;
        let (answer, _) = crate::signal::answer(&offer, b"r2".to_vec(), b"conv", 8, &mut rng)
            .unwrap_or_else(|_| unreachable!());
        for m in [
            CallMessage::Offer(offer),
            CallMessage::Answer(answer),
            CallMessage::Ringing(id),
            CallMessage::Decline(id),
            CallMessage::Busy(id),
            CallMessage::End(id),
            CallMessage::Candidates(id, vec![1, 2, 3]),
        ] {
            let e = m.encode();
            assert_eq!(CallMessage::decode(&e).ok().as_ref(), Some(&m), "{m:?}");
            assert_eq!(m.call_id(), id);
        }
        assert!(CallMessage::decode(&[3; 16]).is_err());
        assert!(CallMessage::decode(&[9; 17]).is_err());
        assert!(CallMessage::decode(&[]).is_err());
    }
}
