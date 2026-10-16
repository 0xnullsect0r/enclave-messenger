//! Relay tickets (`docs/11-calls.md` §3.3).
//!
//! A client obtains a ticket from a relay's ticket service with an
//! X448 + ML-KEM-1024 exchange to the relay's daily ticket key. Both ends
//! derive `ticket_secret`, and from it the WireGuard pre-shared key for
//! each 120 s period (`crate::wg`). The request carries nothing about the
//! account: it is paid with proof of work bound to the request, which any
//! relay can check whoever runs it (ADR 0006), and the relay burns each
//! request's ephemeral key so a proof is spent once.
//!
//! ```text
//! request = u32 epoch ‖ X448 eph ‖ ML-KEM ct ‖ bytes(Seal(k_seal, ad("request"),
//!           wg_public 32 ‖ u32 duration)) ‖ pow 32
//! pow     over ticket-pow ‖ relay_id ‖ u32 epoch ‖ eph ‖ ct
//! reply   = Seal(k_seal, ad("reply"), session 16 ‖ u64 t0 ‖ u64 expiry ‖
//!           relay WireGuard public 32 ‖ u64 relay now)
//! ```

use crate::{CallError, Result, labels};
use enclave_crypto::kem::{
    MLKEM_CT_LEN, MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448_LEN, X448Public,
    X448Secret, combine,
};
use enclave_crypto::kmac::kmac256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_proto::codec::{Reader, Writer};
use zeroize::Zeroizing;

/// Link keys change every this many seconds.
pub const PERIOD_SECS: u64 = 120;

/// A relay's public ticket key for one day.
#[derive(Clone, PartialEq, Eq)]
pub struct TicketKey {
    /// Relay id.
    pub relay_id: [u8; 16],
    /// Key epoch (day).
    pub epoch: u32,
    /// X448 part.
    pub x448: X448Public,
    /// ML-KEM-1024 part.
    pub mlkem: MlKemPublic,
}

/// The relay's secret half.
pub struct TicketSecretKey {
    public: TicketKey,
    x: X448Secret,
    k: MlKemSecret,
}

impl TicketSecretKey {
    /// Fresh key for `epoch`.
    pub fn generate(relay_id: [u8; 16], epoch: u32, rng: &mut HedgedRng) -> Result<Self> {
        let (x, xp) = X448Secret::generate(rng)?;
        let (k, kp) = MlKemSecret::generate(rng)?;
        Ok(Self {
            public: TicketKey {
                relay_id,
                epoch,
                x448: xp,
                mlkem: kp,
            },
            x,
            k,
        })
    }

    /// The key for `epoch` (a day) from that day's chain seed: a relay that
    /// restarts holds the key it published, and erasing old seeds erases
    /// old keys.
    pub fn from_seed(relay_id: [u8; 16], epoch: u32, seed: &[u8; 32]) -> Self {
        let m: Zeroizing<[u8; X448_LEN + 64]> =
            Zeroizing::new(kmac256(seed, &epoch.to_be_bytes(), labels::TICKET_KEY));
        let mut xb = [0u8; X448_LEN];
        xb.copy_from_slice(&m[..X448_LEN]);
        let x = X448Secret::from_bytes(xb);
        xb.fill(0);
        let mut ms = Zeroizing::new([0u8; 64]);
        ms.copy_from_slice(&m[X448_LEN..]);
        let (k, kp) = MlKemSecret::from_seed(&ms);
        Self {
            public: TicketKey {
                relay_id,
                epoch,
                x448: x.public(),
                mlkem: kp,
            },
            x,
            k,
        }
    }

    /// The chain seed of the day after `seed`'s.
    pub fn next_seed(seed: &[u8; 32]) -> [u8; 32] {
        kmac256(seed, b"", labels::TICKET_CHAIN)
    }

    /// Public half.
    pub fn public(&self) -> &TicketKey {
        &self.public
    }

    /// Relay: open a ticket request paid with proof of work at `effort`.
    /// Returns the client's WireGuard key, the requested duration, the id
    /// to burn (so a request is spent once), and a responder that issues
    /// the ticket.
    pub fn accept(&self, req: &[u8], effort: u32) -> Result<Accepted> {
        let mut r = Reader::new(req);
        let m = |_| CallError::Malformed;
        let epoch = r.u32().map_err(m)?;
        if epoch != self.public.epoch {
            return Err(CallError::UnknownKey);
        }
        let eph = X448Public(r.array::<X448_LEN>().map_err(m)?);
        let ct = MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN).map_err(m)?)?;
        let sealed = r.bytes(256).map_err(m)?;
        let pow = enclave_tokens::PowProof(r.array::<32>().map_err(m)?);
        r.end().map_err(m)?;
        // The work first: it is cheap to check and costly to fake.
        if !enclave_tokens::verify(&pow_context(&self.public, &eph, &ct), effort, &pow) {
            return Err(CallError::Crypto);
        }
        let dh = self.x.diffie_hellman(&eph)?;
        let ss_m = self.k.decapsulate(&ct);
        let (secret, k_seal) = derive(&self.public, &eph, &ct, &dh[..], &ss_m[..]);
        let pt = Zeroizing::new(seal::open(&k_seal, &ad(&self.public, b"request"), sealed)?);
        if pt.len() != 36 {
            return Err(CallError::Malformed);
        }
        let mut wg_public = [0u8; 32];
        wg_public.copy_from_slice(&pt[..32]);
        let duration = u32::from_be_bytes([pt[32], pt[33], pt[34], pt[35]]);
        let mut spend = [0u8; 32];
        spend.copy_from_slice(&kmac256::<32>(&eph.0, b"", labels::TICKET_POW)[..]);
        Ok(Accepted {
            wg_public,
            duration,
            spend,
            secret,
            k_seal,
            public: self.public.clone(),
        })
    }
}

/// What the proof of work of a request is over.
fn pow_context(key: &TicketKey, eph: &X448Public, ct: &MlKemCiphertext) -> Vec<u8> {
    [
        labels::TICKET_POW.as_bytes(),
        &key.relay_id,
        &key.epoch.to_be_bytes(),
        &eph.0,
        &ct.0[..],
    ]
    .concat()
}

fn ad(key: &TicketKey, what: &[u8]) -> Vec<u8> {
    [
        labels::AD_TICKET.as_bytes(),
        &key.relay_id,
        &key.epoch.to_be_bytes(),
        what,
    ]
    .concat()
}

fn derive(
    key: &TicketKey,
    eph: &X448Public,
    ct: &MlKemCiphertext,
    dh: &[u8],
    ss_m: &[u8],
) -> (Zeroizing<[u8; 32]>, SealKey) {
    let transcript = [
        labels::TICKET_TRANSCRIPT.as_bytes(),
        &key.relay_id,
        &key.epoch.to_be_bytes(),
    ]
    .concat();
    let ss = combine(
        Suite::TwoKem,
        &[dh, ss_m],
        &[
            &key.x448.0,
            &key.mlkem.0[..],
            &eph.0,
            &ct.0[..],
            &transcript,
        ],
        None,
    );
    let secret = Zeroizing::new(kmac256(&ss[..], b"", labels::TICKET_SECRET));
    let k_seal = seal::derive_key(&ss[..], b"", labels::TICKET_SEAL);
    (secret, k_seal)
}

/// Client: ask `key`'s relay for a ticket for the WireGuard key
/// `wg_public`, paying with proof of work at the relay's `effort`.
pub fn request(
    key: &TicketKey,
    wg_public: [u8; 32],
    duration: u32,
    effort: u32,
    rng: &mut HedgedRng,
) -> Result<(Vec<u8>, TicketClient)> {
    let (eph, eph_pub) = X448Secret::generate(rng)?;
    let dh = eph.diffie_hellman(&key.x448)?;
    let (ct, ss_m) = key.mlkem.encapsulate(rng)?;
    let (secret, k_seal) = derive(key, &eph_pub, &ct, &dh[..], &ss_m[..]);
    let body = [&wg_public[..], &duration.to_be_bytes()].concat();
    let sealed = seal::seal(&k_seal, &ad(key, b"request"), &body, rng)?;
    let pow = enclave_tokens::solve(&pow_context(key, &eph_pub, &ct), effort, rng)?;
    let mut w = Writer::new();
    w.u32(key.epoch)
        .fixed(&eph_pub.0)
        .fixed(&ct.0[..])
        .bytes(&sealed)
        .fixed(&pow.0);
    Ok((
        w.finish(),
        TicketClient {
            secret,
            k_seal,
            key: key.clone(),
        },
    ))
}

/// Client state until the reply arrives.
pub struct TicketClient {
    secret: Zeroizing<[u8; 32]>,
    k_seal: SealKey,
    key: TicketKey,
}

/// A ticket as the client gets it.
pub struct Issued {
    /// The ticket.
    pub ticket: Ticket,
    /// The relay's WireGuard key.
    pub relay_wg: [u8; 32],
    /// The relay's clock minus ours (seconds), for counting periods.
    pub offset: i64,
}

impl TicketClient {
    /// Finish with the relay's reply, received at `now` (our clock).
    pub fn finish(self, reply: &[u8], now: u64) -> Result<Issued> {
        let pt = seal::open(&self.k_seal, &ad(&self.key, b"reply"), reply)?;
        if pt.len() != 72 {
            return Err(CallError::Malformed);
        }
        let u64_at = |i: usize| -> Result<u64> {
            Ok(u64::from_be_bytes(
                pt[i..i + 8].try_into().map_err(|_| CallError::Malformed)?,
            ))
        };
        let mut session = [0u8; 16];
        session.copy_from_slice(&pt[..16]);
        let (t0, expiry) = (u64_at(16)?, u64_at(24)?);
        let mut relay_wg = [0u8; 32];
        relay_wg.copy_from_slice(&pt[32..64]);
        let relay_now = u64_at(64)?;
        Ok(Issued {
            ticket: Ticket {
                session,
                t0,
                expiry,
                secret: self.secret,
            },
            relay_wg,
            offset: relay_now as i64 - now as i64,
        })
    }
}

/// A request the relay has opened.
pub struct Accepted {
    /// The client's WireGuard key for this call.
    pub wg_public: [u8; 32],
    /// Requested duration in seconds.
    pub duration: u32,
    /// Burn this, so the request (and its work) is spent once.
    pub spend: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
    k_seal: SealKey,
    public: TicketKey,
}

impl Accepted {
    /// Relay: issue the ticket, naming the relay's WireGuard key and its
    /// clock. Returns the reply for the client and the relay's copy.
    pub fn issue(
        self,
        session: [u8; 16],
        now: u64,
        expiry: u64,
        relay_wg: [u8; 32],
        rng: &mut HedgedRng,
    ) -> Result<(Vec<u8>, Ticket)> {
        let pt = [
            &session[..],
            &now.to_be_bytes(),
            &expiry.to_be_bytes(),
            &relay_wg,
            &now.to_be_bytes(),
        ]
        .concat();
        let reply = seal::seal(&self.k_seal, &ad(&self.public, b"reply"), &pt, rng)?;
        Ok((
            reply,
            Ticket {
                session,
                t0: now,
                expiry,
                secret: self.secret,
            },
        ))
    }
}

/// A ticket, as both the client and the relay hold it.
pub struct Ticket {
    /// Session id on the relay.
    pub session: [u8; 16],
    /// Start of period 0.
    pub t0: u64,
    /// Expiry.
    pub expiry: u64,
    secret: Zeroizing<[u8; 32]>,
}

impl Ticket {
    /// A ticket from parts (tests of the link).
    #[cfg(test)]
    pub(crate) fn for_test(session: [u8; 16], t0: u64, expiry: u64, secret: [u8; 32]) -> Self {
        Self {
            session,
            t0,
            expiry,
            secret: Zeroizing::new(secret),
        }
    }

    /// Period index at `now`.
    pub fn period(&self, now: u64) -> u32 {
        (now.saturating_sub(self.t0) / PERIOD_SECS) as u32
    }

    /// `psk_i = KMAC256(ticket_secret, u32(i), "wg-psk")`.
    pub fn psk(&self, period: u32) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(kmac256(
            &self.secret[..],
            &period.to_be_bytes(),
            labels::WG_PSK,
        ))
    }
}
