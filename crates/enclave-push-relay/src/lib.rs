//! The push relay (`docs/10-push.md`).
//!
//! APNs and FCM accept only the app publisher's credentials, so the project
//! runs this relay. It never sees an inbox or a message: servers hand it
//! **sealed push tokens** (a device's platform token, sealed to the relay's
//! key by the device and re-randomized on every registration, so the server
//! can't read it and two registrations can't be linked), and it opens them
//! and sends a content-free wake.
//!
//! Wakes are shaped twice. The server schedules at most one wake per sealed
//! token per 60-second window, at a random offset of 0–30 s into it; the
//! relay enforces one wake per *platform token* per window again, so a
//! server can't learn anything by flooding. The relay keeps no logs, only
//! counts.
//!
//! Keys: one X448 + ML-KEM-1024 key per 30-day epoch, derived from a
//! forward-secure seed chain ([`keys::RelayKeys`]). The previous epoch's key
//! stays for 7 days so tokens sealed just before a rotation still open; the
//! next epoch's key is published ahead of time.
//!
//! Delivery ([`deliver::Deliverer`]): APNs (HTTP/2, an ES256 provider
//! token), FCM (HTTP v1, an OAuth token from the service account) and
//! UnifiedPush (a content-free `POST` to the device's endpoint, over TLS).
//! The project's APNs and FCM credentials are an External Gate (G6).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use enclave_crypto::kem::{
    self, MLKEM_CT_LEN, MLKEM_PK_LEN, MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448_LEN,
    X448Public, X448Secret,
};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal;
use std::collections::HashMap;

/// KMAC label of the token seal key.
const L_SEAL: &str = "enclave/v1/net/push-seal";
/// Transcript prefix of the token encapsulation.
const L_TRANSCRIPT: &str = "enclave/v1/net/push-transcript";
/// AD prefix of a sealed token.
const L_AD: &str = "enclave/v1/wire/ad-push-token";
/// KMAC label deriving an epoch's key material from its chain seed.
pub const L_RELAY_KEY: &str = "enclave/v1/push/relay-key";
/// KMAC label stepping the key chain to the next epoch.
pub const L_RELAY_CHAIN: &str = "enclave/v1/push/relay-chain";
/// Days per key epoch.
pub const EPOCH_DAYS: u32 = 30;
/// Days into a new epoch that the previous epoch's key is still accepted.
pub const OVERLAP_DAYS: u32 = 7;

pub mod deliver;
pub mod keys;

/// Longest platform token (a UnifiedPush endpoint URL, an APNs or FCM
/// token), padded to this so every sealed token has one size.
pub const MAX_TOKEN: usize = 256;
/// Plaintext of a sealed token: platform, length, token (padded), class.
const PLAIN_LEN: usize = 1 + 2 + MAX_TOKEN + 1;
/// Bytes of every sealed token.
pub const SEALED_LEN: usize = 4 + X448_LEN + MLKEM_CT_LEN + PLAIN_LEN + seal::OVERHEAD;
/// Width of a wake window, in seconds.
pub const WINDOW_SECS: u64 = 60;
/// Latest offset of a wake into its window.
pub const JITTER_SECS: u64 = 30;
/// Length of a notification capsule.
pub const CAPSULE_LEN: usize = 1_024;
/// A wake from a server: the sealed token and the newest envelope's
/// capsule.
pub const WAKE_LEN: usize = SEALED_LEN + CAPSULE_LEN;

/// Why something failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PushError {
    /// Malformed or not for a key we hold.
    #[error("not a sealed token for this relay")]
    Sealed,
    /// Token too long or of an unknown platform.
    #[error("bad token")]
    Token,
    /// Randomness or key generation failed.
    #[error("cryptographic failure")]
    Crypto,
}

/// Result alias.
pub type Result<T> = core::result::Result<T, PushError>;

impl From<enclave_crypto::Error> for PushError {
    fn from(_: enclave_crypto::Error) -> Self {
        PushError::Crypto
    }
}

/// Where a wake goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Platform {
    /// A UnifiedPush endpoint (the token is its URL).
    UnifiedPush = 1,
    /// Apple Push Notification service.
    Apns = 2,
    /// Firebase Cloud Messaging.
    Fcm = 3,
}

impl Platform {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::UnifiedPush),
            2 => Some(Self::Apns),
            3 => Some(Self::Fcm),
            _ => None,
        }
    }
}

/// The relay's public key for one epoch (in the foundation's signed list).
#[derive(Clone)]
pub struct RelayPublic {
    /// Key epoch (rotates every 30 days).
    pub epoch: u32,
    /// X448 part.
    pub x448: X448Public,
    /// ML-KEM-1024 part.
    pub mlkem: MlKemPublic,
}

impl RelayPublic {
    /// `u32 epoch ‖ x448 ‖ mlkem`.
    pub fn encode(&self) -> Vec<u8> {
        [
            &self.epoch.to_be_bytes()[..],
            &self.x448.0,
            &self.mlkem.0[..],
        ]
        .concat()
    }

    /// Inverse of [`encode`](Self::encode).
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != 4 + X448_LEN + MLKEM_PK_LEN {
            return Err(PushError::Sealed);
        }
        let epoch = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let mut x = [0u8; X448_LEN];
        x.copy_from_slice(&b[4..4 + X448_LEN]);
        let mut m = Box::new([0u8; MLKEM_PK_LEN]);
        m.copy_from_slice(&b[4 + X448_LEN..]);
        Ok(Self {
            epoch,
            x448: X448Public(x),
            mlkem: MlKemPublic(m),
        })
    }
}

/// The relay's secret key for one epoch.
pub struct RelaySecret {
    x448: X448Secret,
    mlkem: MlKemSecret,
    public: RelayPublic,
}

impl RelaySecret {
    /// A new key for `epoch`.
    pub fn generate(epoch: u32, rng: &mut HedgedRng) -> Result<Self> {
        let (x448, xp) = X448Secret::generate(rng)?;
        let (mlkem, mp) = MlKemSecret::generate(rng)?;
        Ok(Self {
            x448,
            mlkem,
            public: RelayPublic {
                epoch,
                x448: xp,
                mlkem: mp,
            },
        })
    }

    /// The key for `epoch` from that epoch's chain seed (deterministic, so
    /// a restarted relay holds the key it published).
    pub fn from_seed(epoch: u32, seed: &[u8; 32]) -> Self {
        let m: zeroize::Zeroizing<[u8; X448_LEN + 64]> = zeroize::Zeroizing::new(
            enclave_crypto::kmac::kmac256(seed, &epoch.to_be_bytes(), L_RELAY_KEY),
        );
        let mut x = [0u8; X448_LEN];
        x.copy_from_slice(&m[..X448_LEN]);
        let x448 = X448Secret::from_bytes(x);
        x.fill(0);
        let mut ms = zeroize::Zeroizing::new([0u8; 64]);
        ms.copy_from_slice(&m[X448_LEN..]);
        let (mlkem, mp) = MlKemSecret::from_seed(&ms);
        let xp = x448.public();
        Self {
            x448,
            mlkem,
            public: RelayPublic {
                epoch,
                x448: xp,
                mlkem: mp,
            },
        }
    }

    /// The chain seed of the epoch after `seed`'s.
    pub fn next_seed(seed: &[u8; 32]) -> [u8; 32] {
        enclave_crypto::kmac::kmac256(seed, b"", L_RELAY_CHAIN)
    }

    /// Public half.
    pub fn public(&self) -> &RelayPublic {
        &self.public
    }
}

/// The key epoch `day` falls in.
pub fn epoch_of(day: u32) -> u32 {
    day / EPOCH_DAYS
}

fn seal_key(dh: &[u8], ss: &[u8], eph: &[u8], ct: &[u8], relay: &RelayPublic) -> seal::SealKey {
    let epoch = relay.epoch.to_be_bytes();
    let s = kem::combine(
        Suite::TwoKem,
        &[dh, ss],
        &[
            L_TRANSCRIPT.as_bytes(),
            eph,
            ct,
            &relay.x448.0,
            &relay.mlkem.0[..],
            &epoch,
        ],
        None,
    );
    seal::derive_key(&s[..], b"", L_SEAL)
}

fn ad(epoch: u32) -> Vec<u8> {
    [L_AD.as_bytes(), &epoch.to_be_bytes()].concat()
}

/// Device: seal `token` for `relay`. Fresh encapsulation and hedged nonce
/// each time, so two sealings of one token look unrelated.
pub fn seal_token(
    relay: &RelayPublic,
    platform: Platform,
    token: &[u8],
    wake_class: u8,
    rng: &mut HedgedRng,
) -> Result<Vec<u8>> {
    if token.is_empty() || token.len() > MAX_TOKEN {
        return Err(PushError::Token);
    }
    let (eph, eph_pub) = X448Secret::generate(rng)?;
    let dh = eph.diffie_hellman(&relay.x448)?;
    let (ct, ss) = relay.mlkem.encapsulate(rng)?;
    let key = seal_key(&dh[..], &ss[..], &eph_pub.0, &ct.0[..], relay);
    let mut plain = zeroize::Zeroizing::new(vec![0u8; PLAIN_LEN]);
    plain[0] = platform as u8;
    plain[1..3].copy_from_slice(&(token.len() as u16).to_be_bytes());
    plain[3..3 + token.len()].copy_from_slice(token);
    plain[PLAIN_LEN - 1] = wake_class;
    let sealed = seal::seal(&key, &ad(relay.epoch), &plain, rng)?;
    Ok([
        &relay.epoch.to_be_bytes()[..],
        &eph_pub.0,
        &ct.0[..],
        &sealed,
    ]
    .concat())
}

/// What a sealed token opens to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Platform.
    pub platform: Platform,
    /// Platform token (for UnifiedPush, the endpoint URL).
    pub token: Vec<u8>,
    /// Wake class (0 message; others reserved: calls).
    pub wake_class: u8,
    /// The notification capsule the wake carries (1,024 B; empty if it
    /// carried none), passed on for previews (`10-push.md` §4).
    pub capsule: Vec<u8>,
}

/// The relay's state.
pub struct Relay {
    keys: Vec<RelaySecret>,
    /// Last window each platform token was woken in (hashed tokens only).
    last: HashMap<[u8; 32], u64>,
    /// Wakes forwarded and refused, for per-minute counters.
    pub forwarded: u64,
    /// Wakes dropped by the window rule.
    pub shaped: u64,
}

impl Relay {
    /// A relay holding `keys` (the current epoch and any in overlap).
    pub fn new(keys: Vec<RelaySecret>) -> Self {
        Self {
            keys,
            last: HashMap::new(),
            forwarded: 0,
            shaped: 0,
        }
    }

    /// Replace the keys (after a rotation).
    pub fn set_keys(&mut self, keys: Vec<RelaySecret>) {
        self.keys = keys;
    }

    /// Epochs of the keys held, newest first.
    pub fn epochs(&self) -> Vec<u32> {
        self.keys.iter().map(|k| k.public.epoch).collect()
    }

    /// Open a sealed token.
    pub fn open(&self, sealed: &[u8]) -> Result<Delivery> {
        if sealed.len() != SEALED_LEN {
            return Err(PushError::Sealed);
        }
        let epoch = u32::from_be_bytes([sealed[0], sealed[1], sealed[2], sealed[3]]);
        let key = self
            .keys
            .iter()
            .find(|k| k.public.epoch == epoch)
            .ok_or(PushError::Sealed)?;
        let mut eph = [0u8; X448_LEN];
        eph.copy_from_slice(&sealed[4..4 + X448_LEN]);
        let eph = X448Public(eph);
        let mut ct = Box::new([0u8; MLKEM_CT_LEN]);
        ct.copy_from_slice(&sealed[4 + X448_LEN..4 + X448_LEN + MLKEM_CT_LEN]);
        let ct = MlKemCiphertext(ct);
        let dh = key
            .x448
            .diffie_hellman(&eph)
            .map_err(|_| PushError::Sealed)?;
        let ss = key.mlkem.decapsulate(&ct);
        let k = seal_key(&dh[..], &ss[..], &eph.0, &ct.0[..], &key.public);
        let plain = zeroize::Zeroizing::new(
            seal::open(&k, &ad(epoch), &sealed[4 + X448_LEN + MLKEM_CT_LEN..])
                .map_err(|_| PushError::Sealed)?,
        );
        let platform = Platform::from_u8(plain[0]).ok_or(PushError::Token)?;
        let len = usize::from(u16::from_be_bytes([plain[1], plain[2]]));
        if len == 0 || len > MAX_TOKEN {
            return Err(PushError::Token);
        }
        Ok(Delivery {
            platform,
            token: plain[3..3 + len].to_vec(),
            wake_class: plain[PLAIN_LEN - 1],
            capsule: Vec::new(),
        })
    }

    /// A wake (a sealed token, with or without the capsule after it) at
    /// `now`: the delivery to make, or `None` if the token doesn't open or
    /// was already woken in this window.
    pub fn wake(&mut self, wake: &[u8], now: u64) -> Option<Delivery> {
        let (sealed, capsule) = match wake.len() {
            SEALED_LEN => (wake, &[][..]),
            WAKE_LEN => wake.split_at(SEALED_LEN),
            _ => return None,
        };
        let mut d = self.open(sealed).ok()?;
        d.capsule = capsule.to_vec();
        let id = enclave_crypto::kmac::kmac256(&d.token, &[d.platform as u8], L_SEAL);
        let window = now / WINDOW_SECS;
        if self.last.get(&id) == Some(&window) {
            self.shaped += 1;
            return None;
        }
        self.last.insert(id, window);
        // Forget windows long past, so the table only holds recent tokens.
        self.last.retain(|_, w| *w + 2 >= window);
        self.forwarded += 1;
        Some(d)
    }
}
