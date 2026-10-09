//! The PIN that guards the root (`docs/03-identity.md` §5,
//! `docs/14-storage.md` §1.3).
//!
//! Removing a device, changing or replacing the recovery words, taking a
//! recovery share back, securing the account and deleting it all act with
//! the root. Once a PIN is set the recovery secret is wrapped under it
//! (`root_wrap`), so those need [`Client::unlock_root`] first: it unwraps
//! the root, which stays in memory for [`UNLOCK_SECS`] and is then dropped.
//! The PIN is stretched with Argon2id; a wrong one simply fails to unwrap.
//! Wrong PINs cost time: after [`FREE_TRIES`] the next try waits 30
//! seconds, doubling each time up to an hour. (Profiles that set a PIN
//! before the wrap kept only a check value, `KMAC256(Argon2id(PIN, salt),
//! "", "enclave/v1/store/pin-check")`; their next good unlock wraps the
//! root under the PIN and drops it.)

use super::Client;
use super::root_wrap::{self, KEY_ROOT_WRAP, Wrapped};
use crate::persist::{NS_PROFILE, NS_SECRETS};
use crate::{CoreError, Result};
use enclave_crypto::pwhash::{self, PwParams};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// `NS_SECRETS` key of the old check value: `u32 memory ‖ u32 iterations
/// ‖ u32 parallelism ‖ salt (32) ‖ check (32)`.
const KEY_PIN: &[u8] = b"root-pin";
/// `NS_PROFILE` key: `u32 failures ‖ u64 next try`.
const KEY_TRIES: &[u8] = b"root-pin-tries";
/// How long an unlock lasts.
pub const UNLOCK_SECS: u64 = 120;
/// Wrong PINs allowed before tries are spaced out.
pub const FREE_TRIES: u32 = 3;
/// Shortest PIN.
pub const MIN_PIN_LEN: usize = 6;

fn check_value(pin: &str, salt: &[u8; 32], params: PwParams) -> Result<[u8; 32]> {
    let k = pwhash::derive(pin.as_bytes(), salt, params)?;
    Ok(enclave_crypto::kmac::kmac256(
        &k[..],
        b"",
        "enclave/v1/store/pin-check",
    ))
}

impl Client {
    /// Whether root actions need the PIN.
    pub fn has_root_pin(&self) -> bool {
        matches!(root_wrap::record(&self.store), Ok(Some(w)) if w.pin.is_some())
            || matches!(self.store.get(NS_SECRETS, KEY_PIN), Ok(Some(_)))
    }

    /// Set (or change) the PIN for root actions, stretched with `params`:
    /// the recovery secret is wrapped again under it. Changing it needs the
    /// root unlocked with the old one. Only on the device that holds the
    /// words.
    pub fn set_root_pin(&mut self, pin: &str, params: PwParams) -> Result<()> {
        self.require_root_unlocked()?;
        if pin.chars().count() < MIN_PIN_LEN {
            return Err(CoreError::TooLong);
        }
        self.wrap_under_pin(pin, params)?;
        self.store.delete(NS_PROFILE, KEY_TRIES)?;
        Ok(())
    }

    fn wrap_under_pin(&mut self, pin: &str, params: PwParams) -> Result<()> {
        let rs = self.recovery_secret()?;
        let salt: [u8; 32] = self.rng.array("core/pin-salt")?;
        let kek = root_wrap::kek(
            self.store.keystore().as_ref(),
            Some((pin, params, &salt)),
            Some(&mut self.rng),
        )?;
        let w = Wrapped::seal(&kek, Some((params, salt)), &rs, &mut self.rng)?;
        self.store
            .put(NS_SECRETS, KEY_ROOT_WRAP, &w.encode(), &mut self.rng)?;
        self.store.delete(NS_SECRETS, KEY_PIN)?;
        self.root_kek = Some(kek);
        Ok(())
    }

    /// Unlock root actions for [`UNLOCK_SECS`] with the PIN, unwrapping the
    /// root. A wrong one is `PinWrong`; too many in a row, `PinWait(until)`.
    pub fn unlock_root(&mut self, pin: &str) -> Result<()> {
        let now = self.now();
        if !self.has_root_pin() {
            self.root_unlocked = now + UNLOCK_SECS;
            return Ok(());
        }
        let (failures, next) = self.pin_tries()?;
        if next > now {
            return Err(CoreError::PinWait(next));
        }
        let good = if let Some(v) = self.store.get(NS_SECRETS, KEY_PIN)? {
            self.legacy_check(&Zeroizing::new(v), pin)?
        } else {
            let w = root_wrap::record(&self.store)?.ok_or(CoreError::NotFound)?;
            let (params, salt) = w.pin.ok_or(CoreError::NotFound)?;
            let kek = root_wrap::kek(
                self.store.keystore().as_ref(),
                Some((pin, params, &salt)),
                None,
            )?;
            match w.open(&kek) {
                Ok(rs) => {
                    self.root_kek = Some(kek);
                    self.account.root = Some(
                        enclave_crypto::sig::RootSigningKey::from_recovery_secret(rs.as_bytes()),
                    );
                    true
                }
                Err(_) => false,
            }
        };
        if good {
            self.store.delete(NS_PROFILE, KEY_TRIES)?;
            self.root_unlocked = now + UNLOCK_SECS;
            return Ok(());
        }
        let failures = failures + 1;
        let wait = if failures < FREE_TRIES {
            0
        } else {
            (30u64 << (failures - FREE_TRIES).min(7)).min(3600)
        };
        let rec = [&failures.to_be_bytes()[..], &(now + wait).to_be_bytes()].concat();
        self.store.put(NS_PROFILE, KEY_TRIES, &rec, &mut self.rng)?;
        Err(CoreError::PinWrong)
    }

    /// A PIN set before the wrap: check it against the stored value and, if
    /// right, wrap the root under it.
    fn legacy_check(&mut self, v: &[u8], pin: &str) -> Result<bool> {
        if v.len() != 76 {
            return Err(CoreError::NotFound);
        }
        let u = |i: usize| u32::from_be_bytes([v[i], v[i + 1], v[i + 2], v[i + 3]]);
        let params = PwParams {
            memory_kib: u(0),
            iterations: u(4),
            parallelism: u(8),
        };
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&v[12..44]);
        let check = check_value(pin, &salt, params)?;
        if !bool::from(check.ct_eq(&v[44..76])) {
            return Ok(false);
        }
        self.wrap_under_pin(pin, params)?;
        Ok(true)
    }

    /// Lock root actions again (with a PIN, the unwrapped root goes).
    pub fn lock_root(&mut self) {
        self.root_unlocked = 0;
        self.forget_root();
    }

    fn pin_tries(&self) -> Result<(u32, u64)> {
        Ok(match self.store.get(NS_PROFILE, KEY_TRIES)? {
            Some(b) if b.len() == 12 => (
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                u64::from_be_bytes(b[4..12].try_into().map_err(|_| CoreError::NotFound)?),
            ),
            _ => (0, 0),
        })
    }

    /// Root actions call this first: with a PIN set, it must have been
    /// entered in the last [`UNLOCK_SECS`].
    pub(crate) fn require_root_unlocked(&self) -> Result<()> {
        if !self.has_root_pin() || self.root_unlocked > self.now() {
            Ok(())
        } else {
            Err(CoreError::PinRequired)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Options;
    use enclave_sim::LocalTransport;
    use enclave_store::MemoryKeystore;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn root_actions_need_the_pin() {
        let net = LocalTransport::new();
        net.add_server(enclave_server::Config {
            id: [1; 16],
            effort_inbox: 1,
            effort_request: 1,
            effort_claim: 1,
            ..Default::default()
        })
        .unwrap();
        let opts = Options {
            path: None,
            keystore: Arc::new(MemoryKeystore::default()),
            passphrase: None,
            pw_params: PwParams::FLOOR,
        };
        let (mut c, _) = Client::create(opts, Arc::new(net.clone()), [1; 16], "Ada")
            .await
            .unwrap();
        // No PIN: root actions go ahead.
        assert!(!c.has_root_pin());
        c.require_root_unlocked().unwrap();
        assert!(matches!(
            c.set_root_pin("12345", PwParams::FLOOR),
            Err(CoreError::TooLong)
        ));
        c.set_root_pin("482913", PwParams::FLOOR).unwrap();
        assert!(c.has_root_pin());
        c.lock_root();
        assert!(matches!(
            c.require_root_unlocked(),
            Err(CoreError::PinRequired)
        ));
        assert!(matches!(
            c.change_recovery_words().await,
            Err(CoreError::PinRequired)
        ));
        assert!(matches!(
            c.delete_account().await,
            Err(CoreError::PinRequired)
        ));
        // Changing the PIN needs the old one.
        assert!(matches!(
            c.set_root_pin("111111", PwParams::FLOOR),
            Err(CoreError::PinRequired)
        ));
        // Wrong PINs: three free, then waits that grow.
        for _ in 0..FREE_TRIES - 1 {
            assert!(matches!(c.unlock_root("000000"), Err(CoreError::PinWrong)));
        }
        assert!(matches!(c.unlock_root("000000"), Err(CoreError::PinWrong)));
        let before = c.now();
        let Err(CoreError::PinWait(until)) = c.unlock_root("482913") else {
            panic!("the right PIN waits too")
        };
        // 30 s from the third wrong try (the clock may tick during Argon2id).
        assert!(
            (before + 28..=before + 30).contains(&until),
            "{until} {before}"
        );
        net.advance(31);
        c.unlock_root("482913").unwrap();
        c.require_root_unlocked().unwrap();
        // The unlock lapses.
        net.advance(UNLOCK_SECS + 1);
        assert!(matches!(
            c.require_root_unlocked(),
            Err(CoreError::PinRequired)
        ));
        c.unlock_root("482913").unwrap();
        c.set_root_pin("111111", PwParams::FLOOR).unwrap();
        c.lock_root();
        assert!(matches!(c.unlock_root("482913"), Err(CoreError::PinWrong)));
        c.unlock_root("111111").unwrap();
    }

    /// Behind a PIN the root itself is wrapped: locked, there is no root in
    /// memory and the words can't be read; unlocked, they can, until the
    /// unlock lapses. A PIN from before the wrap (a check value only) wraps
    /// the root at its next good unlock.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_pin_wraps_the_root() {
        let net = LocalTransport::new();
        net.add_server(enclave_server::Config {
            id: [1; 16],
            effort_inbox: 1,
            effort_request: 1,
            effort_claim: 1,
            ..Default::default()
        })
        .unwrap();
        let opts = Options {
            path: None,
            keystore: Arc::new(MemoryKeystore::default()),
            passphrase: None,
            pw_params: PwParams::FLOOR,
        };
        let (mut c, words) = Client::create(opts, Arc::new(net.clone()), [1; 16], "Ada")
            .await
            .unwrap();
        assert!(c.holds_recovery_words());
        assert!(
            c.store.get(NS_SECRETS, b"recovery").unwrap().is_none(),
            "never as it is"
        );
        assert_eq!(
            c.recovery_words().unwrap(),
            words,
            "no PIN: the device unwraps it"
        );
        c.set_root_pin("246810", PwParams::FLOOR).unwrap();
        c.lock_root();
        assert!(c.account.root.is_none() && c.root_kek.is_none(), "dropped");
        assert!(c.holds_recovery_words());
        assert!(matches!(c.recovery_words(), Err(CoreError::PinRequired)));
        assert!(matches!(c.load_root(), Err(CoreError::PinRequired)));
        c.unlock_root("246810").unwrap();
        assert!(c.account.root.is_some());
        assert_eq!(c.recovery_words().unwrap(), words);
        net.advance(UNLOCK_SECS + 1);
        c.relock_root_if_due();
        assert!(c.account.root.is_none(), "lapsed");
        assert!(matches!(c.recovery_words(), Err(CoreError::PinRequired)));

        // A profile from before: the words under the store's sealing only,
        // and a check value for the PIN.
        let rs = {
            c.unlock_root("246810").unwrap();
            c.recovery_secret().unwrap()
        };
        let salt = [5u8; 32];
        let check = check_value("135791", &salt, PwParams::FLOOR).unwrap();
        let mut v = Vec::new();
        for x in [
            PwParams::FLOOR.memory_kib,
            PwParams::FLOOR.iterations,
            PwParams::FLOOR.parallelism,
        ] {
            v.extend_from_slice(&x.to_be_bytes());
        }
        v.extend_from_slice(&salt);
        v.extend_from_slice(&check);
        c.store.put(NS_SECRETS, KEY_PIN, &v, &mut c.rng).unwrap();
        c.store
            .put(NS_SECRETS, b"recovery", rs.as_bytes(), &mut c.rng)
            .unwrap();
        c.store.delete(NS_SECRETS, KEY_ROOT_WRAP).unwrap();
        c.lock_root();
        root_wrap::upgrade(&c.store, &mut c.rng).unwrap();
        assert!(c.store.get(NS_SECRETS, b"recovery").unwrap().is_none());
        assert!(c.has_root_pin());
        assert!(matches!(c.unlock_root("246810"), Err(CoreError::PinWrong)));
        c.unlock_root("135791").unwrap();
        assert!(
            c.store.get(NS_SECRETS, KEY_PIN).unwrap().is_none(),
            "check value gone"
        );
        assert!(
            root_wrap::record(&c.store).unwrap().unwrap().pin.is_some(),
            "wrapped under it"
        );
        c.lock_root();
        assert!(matches!(c.recovery_words(), Err(CoreError::PinRequired)));
        c.unlock_root("135791").unwrap();
        assert_eq!(c.recovery_words().unwrap(), words);
    }
}
