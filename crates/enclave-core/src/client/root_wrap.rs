//! The wrapped recovery secret (`docs/14-storage.md` §1.3).
//!
//! On the device that holds the recovery words, the recovery secret (and
//! so the account root) is never stored as it is: it is sealed under
//!
//! ```text
//! kek = KMAC256(root_secret, Argon2id(PIN, salt) or "", 256, "enclave/v1/store/root-wrap")
//! ```
//!
//! where `root_secret` is a keystore secret of its own (`enclave-root-secret`,
//! which platform keystores release only with the device unlocked, never to
//! biometrics alone). Without a PIN the device can unwrap it whenever it
//! needs the root; with one, only [`Client::unlock_root`] can, and the
//! unwrapped root is dropped again when the unlock lapses: the PIN is needed
//! to *have* the root, not just to use it. The record binds its own header:
//!
//! ```text
//! u8 version (1) ‖ u8 pin (0/1) ‖ u32 memory ‖ u32 iterations ‖ u32 parallelism ‖ salt (32)
//!   ‖ Seal(kek, "enclave/v1/store/ad-root" ‖ header, recovery secret)
//! ```
//!
//! A crypto-erase destroys `root_secret` with the device secret.

use super::Client;
use crate::persist::NS_SECRETS;
use crate::{CoreError, Result};
use enclave_crypto::pwhash::{self, PwParams};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_crypto::sig::RootSigningKey;
use enclave_proto::recovery::RecoverySecret;
use enclave_store::keystore::ROOT_SECRET;
use enclave_store::{Keystore, Store};
use zeroize::Zeroizing;

/// `NS_SECRETS` key of the wrapped recovery secret.
pub(crate) const KEY_ROOT_WRAP: &[u8] = b"root-wrap";
/// The old, unwrapped record (profiles from before the wrap).
const KEY_PLAIN: &[u8] = b"recovery";
const LABEL: &str = "enclave/v1/store/root-wrap";
const AD: &[u8] = b"enclave/v1/store/ad-root";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 2 + 12 + 32;

/// A wrapped recovery secret.
pub(crate) struct Wrapped {
    /// The PIN's Argon2id parameters and salt, if a PIN is part of the key.
    pub pin: Option<(PwParams, [u8; 32])>,
    sealed: Vec<u8>,
}

impl Wrapped {
    fn header(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0] = VERSION;
        if let Some((p, salt)) = &self.pin {
            h[1] = 1;
            h[2..6].copy_from_slice(&p.memory_kib.to_be_bytes());
            h[6..10].copy_from_slice(&p.iterations.to_be_bytes());
            h[10..14].copy_from_slice(&p.parallelism.to_be_bytes());
            h[14..46].copy_from_slice(salt);
        }
        h
    }

    pub fn encode(&self) -> Vec<u8> {
        [&self.header()[..], &self.sealed].concat()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() <= HEADER_LEN || b[0] != VERSION || b[1] > 1 {
            return Err(CoreError::NotFound);
        }
        let u = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let pin = (b[1] == 1).then(|| {
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&b[14..46]);
            (
                PwParams {
                    memory_kib: u(2),
                    iterations: u(6),
                    parallelism: u(10),
                },
                salt,
            )
        });
        Ok(Self {
            pin,
            sealed: b[HEADER_LEN..].to_vec(),
        })
    }

    fn ad(&self) -> Vec<u8> {
        [AD, &self.header()[..]].concat()
    }

    /// Seal `rs` under `kek`, with `pin` in the header.
    pub fn seal(
        kek: &SealKey,
        pin: Option<(PwParams, [u8; 32])>,
        rs: &RecoverySecret,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let mut w = Self {
            pin,
            sealed: Vec::new(),
        };
        w.sealed = seal::seal(kek, &w.ad(), rs.as_bytes(), rng)?;
        Ok(w)
    }

    /// Open with `kek`; a wrong PIN (or root secret) fails.
    pub fn open(&self, kek: &SealKey) -> Result<RecoverySecret> {
        let pt = Zeroizing::new(seal::open(kek, &self.ad(), &self.sealed)?);
        let arr: [u8; 32] = pt.as_slice().try_into().map_err(|_| CoreError::NotFound)?;
        Ok(RecoverySecret::from_bytes(arr))
    }
}

/// The key-encryption key from the keystore's root secret and, if there is
/// one, the PIN (stretched with `params` and `salt`). Given `create`, the
/// root secret is made if the keystore has none.
pub(crate) fn kek(
    ks: &dyn Keystore,
    pin: Option<(&str, PwParams, &[u8; 32])>,
    create: Option<&mut HedgedRng>,
) -> Result<SealKey> {
    let hw = match (ks.load(ROOT_SECRET), create) {
        (Ok(s), _) => s,
        (Err(e), None) => return Err(e.into()),
        (Err(_), Some(rng)) => {
            let s: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("store/root-secret")?);
            ks.create(ROOT_SECRET, &s)?;
            s
        }
    };
    let pw = match pin {
        Some((pin, params, salt)) => Some(pwhash::derive(pin.as_bytes(), salt, params)?),
        None => None,
    };
    let data: &[u8] = pw.as_ref().map_or(&[], |p| &p[..]);
    Ok(SealKey::from_bytes(enclave_crypto::kmac::kmac256(
        &hw[..],
        data,
        LABEL,
    )))
}

/// Wrap `rs` for a new profile (no PIN yet).
pub(crate) fn initial(store: &Store, rs: &RecoverySecret, rng: &mut HedgedRng) -> Result<Vec<u8>> {
    let k = kek(store.keystore().as_ref(), None, Some(&mut *rng))?;
    Ok(Wrapped::seal(&k, None, rs, rng)?.encode())
}

/// The stored record, if this device holds the words.
pub(crate) fn record(store: &Store) -> Result<Option<Wrapped>> {
    store
        .get(NS_SECRETS, KEY_ROOT_WRAP)?
        .map(|b| Wrapped::decode(&b))
        .transpose()
}

/// Profiles from before the wrap kept the recovery secret only under the
/// store's own sealing: wrap it now (without a PIN) and drop the old record.
pub(crate) fn upgrade(store: &Store, rng: &mut HedgedRng) -> Result<()> {
    let Some(b) = store.get(NS_SECRETS, KEY_PLAIN)? else {
        return Ok(());
    };
    let b = Zeroizing::new(b);
    if store.get(NS_SECRETS, KEY_ROOT_WRAP)?.is_none() {
        let arr: [u8; 32] = b.as_slice().try_into().map_err(|_| CoreError::NotFound)?;
        let w = initial(store, &RecoverySecret::from_bytes(arr), rng)?;
        store.put(NS_SECRETS, KEY_ROOT_WRAP, &w, rng)?;
    }
    store.delete(NS_SECRETS, KEY_PLAIN)?;
    Ok(())
}

/// The recovery secret when no PIN guards it (for `Client::open`).
pub(crate) fn without_pin(store: &Store) -> Result<Option<RecoverySecret>> {
    match record(store)? {
        Some(w) if w.pin.is_none() => {
            let k = kek(store.keystore().as_ref(), None, None)?;
            Ok(Some(w.open(&k)?))
        }
        _ => Ok(None),
    }
}

impl Client {
    /// This device holds the recovery words (whether or not the root is
    /// unlocked right now).
    pub fn holds_recovery_words(&self) -> bool {
        matches!(self.store.get(NS_SECRETS, KEY_ROOT_WRAP), Ok(Some(_)))
    }

    /// The key-encryption key now: the one the last unlock left, or, with
    /// no PIN, the keystore's alone. With a PIN and no unlock in force:
    /// `PinRequired`.
    fn current_kek(&self, w: &Wrapped) -> Result<SealKey> {
        if w.pin.is_some() {
            if self.root_unlocked <= self.now() {
                return Err(CoreError::PinRequired);
            }
            return self.root_kek.clone().ok_or(CoreError::PinRequired);
        }
        kek(self.store.keystore().as_ref(), None, None)
    }

    /// Unwrap the recovery secret (with a PIN, only while unlocked).
    pub(crate) fn recovery_secret(&self) -> Result<RecoverySecret> {
        let w = record(&self.store)?.ok_or(CoreError::NotAccepted)?;
        let k = self.current_kek(&w)?;
        w.open(&k)
    }

    /// Wrap `rs` the way the words are wrapped now (with the PIN if there
    /// is one), for a new set of words. On a device that didn't hold the
    /// words, without a PIN.
    pub(crate) fn wrap_recovery(&mut self, rs: &RecoverySecret) -> Result<Vec<u8>> {
        match record(&self.store)? {
            Some(w) => {
                let k = self.current_kek(&w)?;
                Ok(Wrapped::seal(&k, w.pin, rs, &mut self.rng)?.encode())
            }
            None => initial(&self.store, rs, &mut self.rng),
        }
    }

    /// Make sure the root key is in memory to sign with: unwrapping it if
    /// need be (with a PIN, only while unlocked). Not on a device without
    /// the words.
    pub(crate) fn load_root(&mut self) -> Result<()> {
        let pinned = record(&self.store)?.is_some_and(|w| w.pin.is_some());
        if pinned && self.root_unlocked <= self.now() {
            self.forget_root();
            return Err(CoreError::PinRequired);
        }
        if self.account.root.is_none() {
            let rs = self.recovery_secret()?;
            self.account.root = Some(RootSigningKey::from_recovery_secret(rs.as_bytes()));
        }
        Ok(())
    }

    /// Drop the unwrapped root and the key that unwraps it, where a PIN
    /// guards them.
    pub(crate) fn forget_root(&mut self) {
        if matches!(record(&self.store), Ok(Some(w)) if w.pin.is_some()) {
            self.root_kek = None;
            self.account.root = None;
        }
    }

    /// Drop them if the unlock has lapsed (each sync calls this).
    pub(crate) fn relock_root_if_due(&mut self) {
        if (self.root_kek.is_some() || self.account.root.is_some())
            && self.root_unlocked <= self.now()
        {
            self.forget_root();
        }
    }
}
