//! Call links (`docs/11-calls.md` §8.2): a link anyone can use to join a
//! group call, with or without a lobby where the host lets people in.
//!
//! ```text
//! link    1 ‖ flags (bit 0 video, bit 1 open) ‖ link secret (64) ‖ sfu (16)
//!           ‖ created (u64 ms) [‖ call id (16) ‖ call secret (64) ‖ started (u64 ms)]   open only
//! knock   'K' ‖ x448 (56) ‖ ml-kem-1024 (1568) ‖ name
//! admit   'A' ‖ knocker (u32) ‖ x448 (56) ‖ ml-kem ct (1568) ‖ seal(call id ‖ call secret ‖ started)
//! refuse  'D' ‖ knocker (u32)
//! ```
//!
//! An open link carries the call's secret: whoever has it is in. A lobby
//! link carries only the link secret, which keys the lobby: a session at
//! the call's SFU like a call's (`CallKeys::group(lobby id, link secret)`),
//! where nothing but these messages goes. A knocker sends one-time keys and
//! a name; the host admits by sealing the call's secret to those keys
//! (X448 and ML-KEM-1024 combined), so someone else with the link who
//! listens in the lobby learns nothing of the call.

use crate::signal::CallKeys;
use crate::{CallError, Result, labels};
use enclave_crypto::kem::{
    MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448Public, X448Secret, combine,
};
use enclave_crypto::kmac::kmac256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal;
use zeroize::Zeroizing;

const X448_LEN: usize = 56;
const MLKEM_PK_LEN: usize = 1568;
const MLKEM_CT_LEN: usize = 1568;
/// Most bytes of a knocker's name.
pub const MAX_NAME: usize = 64;
const F_VIDEO: u8 = 1;
const F_OPEN: u8 = 2;

/// The call itself, as an open link or an admission gives it.
#[derive(Clone, PartialEq, Eq)]
pub struct CallSecret {
    /// Call id.
    pub call_id: [u8; 16],
    /// The call's secret (`CallKeys::group`).
    pub secret: Zeroizing<[u8; 64]>,
    /// When it started (Unix ms).
    pub started_ms: u64,
}

impl CallSecret {
    fn encode(&self) -> Vec<u8> {
        [
            &self.call_id[..],
            &self.secret[..],
            &self.started_ms.to_be_bytes(),
        ]
        .concat()
    }

    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != 16 + 64 + 8 {
            return Err(CallError::Malformed);
        }
        let mut secret = Zeroizing::new([0u8; 64]);
        secret.copy_from_slice(&b[16..80]);
        Ok(Self {
            call_id: b[..16].try_into().map_err(|_| CallError::Malformed)?,
            secret,
            started_ms: u64::from_be_bytes(b[80..88].try_into().map_err(|_| CallError::Malformed)?),
        })
    }
}

/// A call link.
#[derive(Clone, PartialEq, Eq)]
pub struct CallLink {
    /// Keys the lobby.
    pub secret: Zeroizing<[u8; 64]>,
    /// The call's SFU relay id.
    pub sfu: [u8; 16],
    /// A video call.
    pub video: bool,
    /// When the link was made (Unix ms): the lobby's epochs count from here.
    pub created_ms: u64,
    /// An open link: the call itself, no lobby.
    pub open: Option<CallSecret>,
}

impl std::fmt::Debug for CallLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CallLink(open: {})", self.open.is_some())
    }
}

impl CallLink {
    /// A new link for a call: open (the call's secret in the link) or with
    /// a lobby.
    pub fn new(
        call: &CallSecret,
        sfu: [u8; 16],
        video: bool,
        lobby: bool,
        now_ms: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let secret = Zeroizing::new(
            rng.array::<64>("calls/link-secret")
                .map_err(|_| CallError::Malformed)?,
        );
        Ok(Self {
            secret,
            sfu,
            video,
            created_ms: now_ms,
            open: (!lobby).then(|| call.clone()),
        })
    }

    /// The link's capability: the lobby's id (its first 16 bytes).
    pub fn cap(&self) -> [u8; 32] {
        kmac256(&self.secret[..], b"", labels::LINK_CAP)
    }

    /// The lobby's keys (a session like a call's, at the SFU).
    pub fn lobby_keys(&self) -> CallKeys {
        let cap = self.cap();
        let mut id = [0u8; 16];
        id.copy_from_slice(&cap[..16]);
        CallKeys::group(id, &self.secret)
    }

    /// Encode (the part after `#`).
    pub fn encode(&self) -> Vec<u8> {
        let flags =
            if self.video { F_VIDEO } else { 0 } | if self.open.is_some() { F_OPEN } else { 0 };
        let mut v = [
            &[1u8, flags][..],
            &self.secret[..],
            &self.sfu,
            &self.created_ms.to_be_bytes(),
        ]
        .concat();
        if let Some(o) = &self.open {
            v.extend_from_slice(&o.encode());
        }
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        const FIXED: usize = 2 + 64 + 16 + 8;
        let [1, flags, rest @ ..] = b else {
            return Err(CallError::Malformed);
        };
        if flags & !(F_VIDEO | F_OPEN) != 0 || rest.len() < FIXED - 2 {
            return Err(CallError::Malformed);
        }
        let mut secret = Zeroizing::new([0u8; 64]);
        secret.copy_from_slice(&rest[..64]);
        let sfu = rest[64..80].try_into().map_err(|_| CallError::Malformed)?;
        let created_ms =
            u64::from_be_bytes(rest[80..88].try_into().map_err(|_| CallError::Malformed)?);
        let tail = &rest[88..];
        let open = if flags & F_OPEN != 0 {
            Some(CallSecret::decode(tail)?)
        } else if tail.is_empty() {
            None
        } else {
            return Err(CallError::Malformed);
        };
        Ok(Self {
            secret,
            sfu,
            video: flags & F_VIDEO != 0,
            created_ms,
            open,
        })
    }
}

/// A lobby message.
#[derive(Clone, PartialEq, Eq)]
pub enum LobbyMessage {
    /// Someone asks to join: their one-time keys and name.
    Knock {
        /// X448 public key.
        x448: [u8; X448_LEN],
        /// ML-KEM-1024 public key.
        mlkem: Box<[u8; MLKEM_PK_LEN]>,
        /// Their name.
        name: String,
    },
    /// The host let a knocker in: the call's secret, sealed to them.
    Admit {
        /// The knocker (their lobby participant id).
        to: u32,
        /// The host's one-time X448 key.
        x448: [u8; X448_LEN],
        /// ML-KEM ciphertext to the knocker's key.
        ct: Box<[u8; MLKEM_CT_LEN]>,
        /// The sealed [`CallSecret`].
        sealed: Vec<u8>,
    },
    /// The host turned a knocker away.
    Refuse {
        /// The knocker.
        to: u32,
    },
}

impl std::fmt::Debug for LobbyMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Knock { .. } => write!(f, "Knock"),
            Self::Admit { to, .. } => write!(f, "Admit({to})"),
            Self::Refuse { to } => write!(f, "Refuse({to})"),
        }
    }
}

impl LobbyMessage {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Knock { x448, mlkem, name } => {
                [&b"K"[..], x448, &mlkem[..], name.as_bytes()].concat()
            }
            Self::Admit {
                to,
                x448,
                ct,
                sealed,
            } => [&b"A"[..], &to.to_be_bytes(), x448, &ct[..], sealed].concat(),
            Self::Refuse { to } => [&b"D"[..], &to.to_be_bytes()].concat(),
        }
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let m = |_| CallError::Malformed;
        match b {
            [b'K', rest @ ..] if rest.len() >= X448_LEN + MLKEM_PK_LEN => {
                let name = &rest[X448_LEN + MLKEM_PK_LEN..];
                if name.len() > MAX_NAME {
                    return Err(CallError::Malformed);
                }
                Ok(Self::Knock {
                    x448: rest[..X448_LEN].try_into().map_err(m)?,
                    mlkem: Box::new(
                        rest[X448_LEN..X448_LEN + MLKEM_PK_LEN]
                            .try_into()
                            .map_err(m)?,
                    ),
                    name: String::from_utf8(name.to_vec()).map_err(|_| CallError::Malformed)?,
                })
            }
            [b'A', rest @ ..] if rest.len() > 4 + X448_LEN + MLKEM_CT_LEN => Ok(Self::Admit {
                to: u32::from_be_bytes(rest[..4].try_into().map_err(m)?),
                x448: rest[4..4 + X448_LEN].try_into().map_err(m)?,
                ct: Box::new(
                    rest[4 + X448_LEN..4 + X448_LEN + MLKEM_CT_LEN]
                        .try_into()
                        .map_err(m)?,
                ),
                sealed: rest[4 + X448_LEN + MLKEM_CT_LEN..].to_vec(),
            }),
            [b'D', rest @ ..] if rest.len() == 4 => Ok(Self::Refuse {
                to: u32::from_be_bytes(rest.try_into().map_err(m)?),
            }),
            _ => Err(CallError::Malformed),
        }
    }
}

/// The key that seals an admission: X448 and ML-KEM-1024 combined over
/// both sides' keys and the lobby's id.
fn admit_key(
    lobby: &[u8; 32],
    dh: &[u8],
    kem: &[u8],
    knock_x448: &[u8],
    knock_mlkem: &[u8],
    host_x448: &[u8],
    ct: &[u8],
) -> seal::SealKey {
    let k = combine(
        Suite::TwoKem,
        &[dh, kem],
        &[lobby, knock_x448, knock_mlkem, host_x448, ct],
        None,
    );
    seal::derive_key(&k[..], lobby, labels::LINK_ADMIT)
}

/// Someone waiting in a lobby: their one-time keys.
pub struct Knocker {
    x448: X448Secret,
    x448_pk: X448Public,
    mlkem: MlKemSecret,
    mlkem_pk: MlKemPublic,
}

impl Knocker {
    /// Fresh one-time keys.
    pub fn new(rng: &mut HedgedRng) -> Result<Self> {
        let (x448, x448_pk) = X448Secret::generate(rng).map_err(|_| CallError::Malformed)?;
        let (mlkem, mlkem_pk) = MlKemSecret::generate(rng).map_err(|_| CallError::Malformed)?;
        Ok(Self {
            x448,
            x448_pk,
            mlkem,
            mlkem_pk,
        })
    }

    /// Our id in the lobby.
    pub fn id(&self, link: &CallLink) -> u32 {
        link.lobby_keys().participant(&self.x448_pk.0)
    }

    /// The knock to send.
    pub fn knock(&self, name: &str) -> LobbyMessage {
        let mut name = name.to_string();
        while name.len() > MAX_NAME {
            name.pop();
        }
        LobbyMessage::Knock {
            x448: self.x448_pk.0,
            mlkem: self.mlkem_pk.0.clone(),
            name,
        }
    }

    /// The call, from the host's admission.
    pub fn open(&self, link: &CallLink, admit: &LobbyMessage) -> Result<CallSecret> {
        let LobbyMessage::Admit {
            to,
            x448,
            ct,
            sealed,
        } = admit
        else {
            return Err(CallError::Malformed);
        };
        if *to != self.id(link) {
            return Err(CallError::Malformed);
        }
        let dh = self
            .x448
            .diffie_hellman(&X448Public(*x448))
            .map_err(|_| CallError::Malformed)?;
        let kem = self
            .mlkem
            .decapsulate(&MlKemCiphertext::from_slice(&ct[..]).map_err(|_| CallError::Malformed)?);
        let key = admit_key(
            &link.cap(),
            &dh[..],
            &kem[..],
            &self.x448_pk.0,
            &self.mlkem_pk.0[..],
            x448,
            &ct[..],
        );
        let pt = Zeroizing::new(
            seal::open(&key, labels::LINK_ADMIT.as_bytes(), sealed)
                .map_err(|_| CallError::Malformed)?,
        );
        CallSecret::decode(&pt)
    }
}

/// The host's answer letting a knocker in: the knocker's id and the
/// admission.
pub fn admit(
    link: &CallLink,
    knock: &LobbyMessage,
    call: &CallSecret,
    rng: &mut HedgedRng,
) -> Result<(u32, LobbyMessage)> {
    let LobbyMessage::Knock { x448, mlkem, .. } = knock else {
        return Err(CallError::Malformed);
    };
    let to = link.lobby_keys().participant(x448);
    let their_x = X448Public(*x448);
    let their_k = MlKemPublic::from_slice(&mlkem[..]).map_err(|_| CallError::Malformed)?;
    let (eph, eph_pk) = X448Secret::generate(rng).map_err(|_| CallError::Malformed)?;
    let dh = eph
        .diffie_hellman(&their_x)
        .map_err(|_| CallError::Malformed)?;
    let (ct, kem) = their_k.encapsulate(rng).map_err(|_| CallError::Malformed)?;
    let key = admit_key(
        &link.cap(),
        &dh[..],
        &kem[..],
        x448,
        &mlkem[..],
        &eph_pk.0,
        &ct.0[..],
    );
    let sealed = seal::seal(
        &key,
        labels::LINK_ADMIT.as_bytes(),
        &Zeroizing::new(call.encode()),
        rng,
    )
    .map_err(|_| CallError::Malformed)?;
    Ok((
        to,
        LobbyMessage::Admit {
            to,
            x448: eph_pk.0,
            ct: ct.0,
            sealed,
        },
    ))
}

/// A knock's sender id in the lobby.
pub fn knocker_id(link: &CallLink, knock: &LobbyMessage) -> Option<u32> {
    match knock {
        LobbyMessage::Knock { x448, .. } => Some(link.lobby_keys().participant(x448)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn call() -> CallSecret {
        CallSecret {
            call_id: [3; 16],
            secret: Zeroizing::new([4; 64]),
            started_ms: 1_790_000_000_000,
        }
    }

    #[test]
    fn links_round_trip() {
        let mut rng = HedgedRng::new().unwrap();
        for lobby in [true, false] {
            let l = CallLink::new(&call(), [5; 16], true, lobby, 7, &mut rng).unwrap();
            let back = CallLink::decode(&l.encode()).unwrap();
            assert!(back == l);
            assert_eq!(back.open.is_some(), !lobby);
        }
        assert!(CallLink::decode(&[1, 4]).is_err());
        assert!(CallLink::decode(&[2; 90]).is_err());
    }

    #[test]
    fn only_the_admitted_knocker_opens_the_call() {
        let mut rng = HedgedRng::new().unwrap();
        let link = CallLink::new(&call(), [5; 16], false, true, 7, &mut rng).unwrap();
        let ana = Knocker::new(&mut rng).unwrap();
        let eve = Knocker::new(&mut rng).unwrap();
        let knock = LobbyMessage::decode(&ana.knock("Ana").encode()).unwrap();
        assert_eq!(knocker_id(&link, &knock), Some(ana.id(&link)));
        let (to, admit_msg) = admit(&link, &knock, &call(), &mut rng).unwrap();
        assert_eq!(to, ana.id(&link));
        let wire = LobbyMessage::decode(&admit_msg.encode()).unwrap();
        assert!(ana.open(&link, &wire).unwrap() == call());
        // Someone else in the lobby, with the same link, can't.
        assert!(eve.open(&link, &wire).is_err());
        let LobbyMessage::Admit {
            x448, ct, sealed, ..
        } = wire
        else {
            panic!()
        };
        let forged = LobbyMessage::Admit {
            to: eve.id(&link),
            x448,
            ct,
            sealed,
        };
        assert!(eve.open(&link, &forged).is_err());
        assert!(
            LobbyMessage::decode(&LobbyMessage::Refuse { to: 9 }.encode()).unwrap()
                == LobbyMessage::Refuse { to: 9 }
        );
    }
}
