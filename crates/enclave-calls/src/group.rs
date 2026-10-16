//! Group calls (`docs/11-calls.md` §8): signalling, carried in the group's
//! own messages (end to end encrypted to its members), so the call's secret
//! reaches exactly the group.
//!
//! ```text
//! 1 ‖ call_id ‖ secret (64) ‖ sfu relay id (16) ‖ u8 video ‖ u64 started (ms)   a call started
//! 2 ‖ call_id                                                                    someone joined
//! 3 ‖ call_id                                                                    someone left
//! 4 ‖ call_id                                                                    the call ended (its starter)
//! ```
//!
//! Every participant sends its media to its own relay, which forwards it to
//! the call's SFU relay; the SFU sends each packet on to the other
//! participants' relays. Senders are told apart by their id
//! ([`crate::signal::CallKeys::participant`]); SFrame epochs count from the
//! call's start, so someone joining late reads everyone.

use crate::{CallError, Result};
use zeroize::Zeroizing;

/// Most people in a group call (`docs/11-calls.md` §8: 64 audio, 32 video).
pub const MAX_PARTICIPANTS: usize = 64;
/// Most video tiles.
pub const MAX_VIDEO: usize = 32;

/// One group call message.
#[derive(Clone, PartialEq, Eq)]
pub enum GroupCallMessage {
    /// A call started.
    Start {
        /// Call id.
        call_id: [u8; 16],
        /// The call's secret (its keys, rendezvous and participant ids).
        secret: Zeroizing<[u8; 64]>,
        /// The SFU relay's id.
        sfu: [u8; 16],
        /// With video.
        video: bool,
        /// When it started (Unix ms): SFrame epochs count from here.
        started_ms: u64,
    },
    /// The sender joined.
    Joined([u8; 16]),
    /// The sender left.
    Left([u8; 16]),
    /// The call ended.
    End([u8; 16]),
}

impl std::fmt::Debug for GroupCallMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, id) = match self {
            Self::Start { call_id, .. } => ("Start", call_id),
            Self::Joined(id) => ("Joined", id),
            Self::Left(id) => ("Left", id),
            Self::End(id) => ("End", id),
        };
        write!(f, "{name}({:02x}{:02x}…)", id[0], id[1])
    }
}

impl GroupCallMessage {
    /// The call it is about.
    pub fn call_id(&self) -> [u8; 16] {
        match self {
            Self::Start { call_id, .. } => *call_id,
            Self::Joined(id) | Self::Left(id) | Self::End(id) => *id,
        }
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Start {
                call_id,
                secret,
                sfu,
                video,
                started_ms,
            } => [
                &[1][..],
                call_id,
                &secret[..],
                sfu,
                &[u8::from(*video)],
                &started_ms.to_be_bytes(),
            ]
            .concat(),
            Self::Joined(id) => [&[2][..], id].concat(),
            Self::Left(id) => [&[3][..], id].concat(),
            Self::End(id) => [&[4][..], id].concat(),
        }
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let id = |b: &[u8]| -> Result<[u8; 16]> { b.try_into().map_err(|_| CallError::Malformed) };
        match b {
            [1, rest @ ..] if rest.len() == 16 + 64 + 16 + 1 + 8 => {
                let mut secret = Zeroizing::new([0u8; 64]);
                secret.copy_from_slice(&rest[16..80]);
                Ok(Self::Start {
                    call_id: id(&rest[..16])?,
                    secret,
                    sfu: id(&rest[80..96])?,
                    video: match rest[96] {
                        0 => false,
                        1 => true,
                        _ => return Err(CallError::Malformed),
                    },
                    started_ms: u64::from_be_bytes(
                        rest[97..105].try_into().map_err(|_| CallError::Malformed)?,
                    ),
                })
            }
            [2, rest @ ..] => Ok(Self::Joined(id(rest)?)),
            [3, rest @ ..] => Ok(Self::Left(id(rest)?)),
            [4, rest @ ..] => Ok(Self::End(id(rest)?)),
            _ => Err(CallError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::signal::CallKeys;

    #[test]
    fn messages_round_trip_and_participants_are_per_call() {
        let start = GroupCallMessage::Start {
            call_id: [1; 16],
            secret: Zeroizing::new([2; 64]),
            sfu: [3; 16],
            video: true,
            started_ms: 1_790_000_000_000,
        };
        for m in [
            start,
            GroupCallMessage::Joined([4; 16]),
            GroupCallMessage::Left([5; 16]),
            GroupCallMessage::End([6; 16]),
        ] {
            assert!(GroupCallMessage::decode(&m.encode()).unwrap() == m);
        }
        assert!(GroupCallMessage::decode(&[1, 2, 3]).is_err());
        assert!(GroupCallMessage::decode(&[9; 17]).is_err());
        let a = CallKeys::group([1; 16], &[7; 64]);
        let b = CallKeys::group([1; 16], &[8; 64]);
        assert_eq!(a.participant(b"ada"), a.participant(b"ada"));
        assert_ne!(a.participant(b"ada"), a.participant(b"ben"));
        assert_ne!(
            a.participant(b"ada"),
            b.participant(b"ada"),
            "ids are per call"
        );
    }
}
