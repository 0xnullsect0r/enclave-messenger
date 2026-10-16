//! Offer/answer and call keys (`docs/11-calls.md` §2).

use crate::{CallError, Result, labels};
use enclave_crypto::kem::{
    MLKEM_CT_LEN, MLKEM_PK_LEN, MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448_LEN,
    X448Public, X448Secret, combine,
};
use enclave_crypto::kmac::kmac256;
use enclave_crypto::rng::HedgedRng;
use enclave_proto::codec::{Reader, Writer};
use zeroize::Zeroizing;

/// Offers expire after this long (seconds).
pub const OFFER_TTL: u64 = 60;

/// What the call carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Media {
    /// Audio only.
    Audio,
    /// Video at a tier chosen at call start (index into `shape::VIDEO_TIERS`).
    Video(u8),
}

/// Relay or direct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Through two relays (default, "Private route").
    Relay,
    /// Peer to peer (opt-in; reveals the IP address).
    Direct,
}

/// The caller's offer.
#[derive(Clone, PartialEq, Eq)]
pub struct Offer {
    /// Random call id.
    pub call_id: [u8; 16],
    /// Caller's X448 share.
    pub x448: X448Public,
    /// Caller's ML-KEM-1024 encapsulation key.
    pub mlkem: MlKemPublic,
    /// Media.
    pub media: Media,
    /// Route the caller asks for.
    pub route: Route,
    /// Caller's relay descriptor (opaque here).
    pub relay: Vec<u8>,
    /// When the offer was made.
    pub created_at: u64,
}

/// The callee's answer.
#[derive(Clone, PartialEq, Eq)]
pub struct Answer {
    /// Same call id.
    pub call_id: [u8; 16],
    /// Callee's X448 share.
    pub x448: X448Public,
    /// ML-KEM-1024 ciphertext to the caller's key.
    pub ct: MlKemCiphertext,
    /// Callee's relay descriptor.
    pub relay: Vec<u8>,
}

/// Caller state kept until the answer arrives.
pub struct Pending {
    offer: Offer,
    x: X448Secret,
    k: MlKemSecret,
}

/// Keys of an established call.
pub struct CallKeys {
    /// Call id.
    pub call_id: [u8; 16],
    secret: Zeroizing<[u8; 64]>,
}

fn media_byte(m: Media) -> u8 {
    match m {
        Media::Audio => 0,
        Media::Video(t) => 1 + t,
    }
}

impl Offer {
    /// Encode for a ratchet message.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.call_id)
            .fixed(&self.x448.0)
            .fixed(&self.mlkem.0[..]);
        w.u8(media_byte(self.media))
            .u8(u8::from(self.route == Route::Direct))
            .bytes(&self.relay)
            .u64(self.created_at);
        w.finish()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let m = |_| CallError::Malformed;
        if r.u8().map_err(m)? != 1 {
            return Err(CallError::Malformed);
        }
        let call_id = r.array().map_err(m)?;
        let x448 = X448Public(r.array::<X448_LEN>().map_err(m)?);
        let mlkem = MlKemPublic::from_slice(r.fixed(MLKEM_PK_LEN).map_err(m)?)?;
        let media = match r.u8().map_err(m)? {
            0 => Media::Audio,
            t @ 1..=3 => Media::Video(t - 1),
            _ => return Err(CallError::Malformed),
        };
        let route = if r.u8().map_err(m)? == 1 {
            Route::Direct
        } else {
            Route::Relay
        };
        let relay = r.bytes(1024).map_err(m)?.to_vec();
        let created_at = r.u64().map_err(m)?;
        r.end().map_err(m)?;
        Ok(Self {
            call_id,
            x448,
            mlkem,
            media,
            route,
            relay,
            created_at,
        })
    }
}

impl Answer {
    /// Encode for a ratchet message.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.call_id)
            .fixed(&self.x448.0)
            .fixed(&self.ct.0[..])
            .bytes(&self.relay);
        w.finish()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let m = |_| CallError::Malformed;
        if r.u8().map_err(m)? != 1 {
            return Err(CallError::Malformed);
        }
        let a = Self {
            call_id: r.array().map_err(m)?,
            x448: X448Public(r.array::<X448_LEN>().map_err(m)?),
            ct: MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN).map_err(m)?)?,
            relay: r.bytes(1024).map_err(m)?.to_vec(),
        };
        r.end().map_err(m)?;
        Ok(a)
    }
}

fn derive(
    offer: &Offer,
    answer: &Answer,
    conv_id: &[u8],
    dh: &[u8],
    ss_m: &[u8],
) -> Zeroizing<[u8; 64]> {
    let transcript = [labels::TRANSCRIPT.as_bytes(), &offer.call_id, conv_id].concat();
    let ss = combine(
        Suite::TwoKem,
        &[dh, ss_m],
        &[
            &offer.x448.0,
            &offer.mlkem.0[..],
            &answer.x448.0,
            &answer.ct.0[..],
            &transcript,
            &offer.encode(),
        ],
        None,
    );
    Zeroizing::new(kmac256(&ss[..], b"", labels::SECRET))
}

/// Caller: make an offer. `conv_id` binds the call to the conversation.
pub fn offer(
    media: Media,
    route: Route,
    relay: Vec<u8>,
    now: u64,
    rng: &mut HedgedRng,
) -> Result<Pending> {
    let (x, x_pub) = X448Secret::generate(rng)?;
    let (k, k_pub) = MlKemSecret::generate(rng)?;
    let offer = Offer {
        call_id: rng.array("calls/id")?,
        x448: x_pub,
        mlkem: k_pub,
        media,
        route,
        relay,
        created_at: now,
    };
    Ok(Pending { offer, x, k })
}

impl Pending {
    /// The offer to send.
    pub fn offer(&self) -> &Offer {
        &self.offer
    }

    /// Caller: finish with the callee's answer.
    pub fn finish(self, answer: &Answer, conv_id: &[u8], now: u64) -> Result<CallKeys> {
        if answer.call_id != self.offer.call_id || now > self.offer.created_at + OFFER_TTL {
            return Err(CallError::Stale);
        }
        let dh = self.x.diffie_hellman(&answer.x448)?;
        let ss_m = self.k.decapsulate(&answer.ct);
        Ok(CallKeys {
            call_id: self.offer.call_id,
            secret: derive(&self.offer, answer, conv_id, &dh[..], &ss_m[..]),
        })
    }
}

/// Callee: answer an offer.
pub fn answer(
    offer: &Offer,
    relay: Vec<u8>,
    conv_id: &[u8],
    now: u64,
    rng: &mut HedgedRng,
) -> Result<(Answer, CallKeys)> {
    if now > offer.created_at + OFFER_TTL {
        return Err(CallError::Stale);
    }
    let (y, y_pub) = X448Secret::generate(rng)?;
    let dh = y.diffie_hellman(&offer.x448)?;
    let (ct, ss_m) = offer.mlkem.encapsulate(rng)?;
    let ans = Answer {
        call_id: offer.call_id,
        x448: y_pub,
        ct,
        relay,
    };
    let secret = derive(offer, &ans, conv_id, &dh[..], &ss_m[..]);
    Ok((
        ans,
        CallKeys {
            call_id: offer.call_id,
            secret,
        },
    ))
}

/// Participant index of the caller and the callee in a 1:1 call.
pub const CALLER: u32 = 0;
/// See [`CALLER`].
pub const CALLEE: u32 = 1;

impl CallKeys {
    /// A group call's keys, from the secret its starter sent the group
    /// (`crate::group`).
    pub fn group(call_id: [u8; 16], secret: &[u8; 64]) -> Self {
        Self {
            call_id,
            secret: Zeroizing::new(*secret),
        }
    }

    /// A group participant's id in the call: from the call's secret and
    /// their root, so only members know who is who.
    pub fn participant(&self, root: &[u8]) -> u32 {
        let id: [u8; 4] = kmac256(&self.secret[..], root, labels::PARTICIPANT);
        u32::from_be_bytes(id)
    }

    /// `base_{p,0}` for participant `p` at join generation `gen`.
    pub fn sframe_base(&self, participant: u32, join_gen: u32) -> Zeroizing<[u8; 32]> {
        let mut w = Writer::new();
        w.bytes(&participant.to_be_bytes()).u32(join_gen);
        Zeroizing::new(kmac256(&self.secret[..], w.as_slice(), labels::SFRAME_BASE))
    }

    /// The optional two-word call check, as BIP-39 English words.
    pub fn check_words(&self) -> [String; 2] {
        let h: [u8; 32] = kmac256(&self.secret[..], b"", labels::CHECK_WORDS);
        let a = (u16::from(h[0]) << 3 | u16::from(h[1]) >> 5) as usize;
        let b = ((u16::from(h[1]) & 0x1f) << 6 | u16::from(h[2]) >> 2) as usize;
        let list = bip39::Language::English.word_list();
        [list[a].to_string(), list[b].to_string()]
    }

    /// Tunnel PSK for direct mode.
    pub fn direct_psk(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(kmac256(&self.secret[..], b"", labels::DIRECT_PSK))
    }

    /// Rendezvous id both relays use to join the two legs of this call.
    pub fn rendezvous(&self) -> [u8; 16] {
        kmac256(&self.secret[..], b"", labels::RENDEZVOUS)
    }
}
