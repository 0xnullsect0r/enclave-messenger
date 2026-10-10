//! The app lock and the emergency PIN (`docs/14-storage.md` §5).
//!
//! Both are checked before the profile is open (a profile with a
//! passphrase is closed while locked), so they live in a small file next to
//! it, `lock.bin`:
//!
//! ```text
//! u8 version (1) ‖ u8 app PIN set ‖ u32 memory ‖ u32 iterations ‖ u32 parallelism
//!   ‖ salt (32) ‖ app check (32) ‖ emergency check (32) ‖ u32 timeout (seconds; 0 = never)
//! check = KMAC256(Argon2id(PIN, salt), "", 256, label)
//!   labels "enclave/v1/store/app-lock", "enclave/v1/store/emergency-pin"
//! ```
//!
//! A PIN that isn't set has random bytes in its place, so the file doesn't
//! say whether there is an emergency PIN (whether there is an app PIN shows
//! anyway: the window locks). One Argon2id run checks a PIN
//! against both. The app PIN locks the window of a profile without a
//! passphrase (the passphrase is the lock of one that has it); the
//! emergency PIN works wherever a PIN or the passphrase is asked for, and
//! crypto-erases the profile.

use enclave_crypto::pwhash::{self, PwParams};
use enclave_crypto::rng::HedgedRng;
use subtle::ConstantTimeEq;

const VERSION: u8 = 1;
const LEN: usize = 2 + 12 + 32 + 32 + 32 + 4;
const L_APP: &str = "enclave/v1/store/app-lock";
const L_EMERGENCY: &str = "enclave/v1/store/emergency-pin";
/// Shortest app or emergency PIN.
pub const MIN_PIN: usize = 4;
/// The default time without use before the app locks (5 minutes).
pub const DEFAULT_TIMEOUT: u32 = 300;

/// What a PIN entered at the lock screen is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entered {
    /// The app PIN.
    App,
    /// The emergency PIN: erase.
    Emergency,
    /// Neither (perhaps the profile's passphrase).
    Neither,
}

/// The lock settings.
#[derive(Clone)]
pub struct LockFile {
    params: PwParams,
    salt: [u8; 32],
    app: [u8; 32],
    emergency: [u8; 32],
    /// An app PIN is set.
    pub app_set: bool,
    /// Seconds without use before locking (0: never).
    pub timeout: u32,
}

fn check(pin: &str, salt: &[u8; 32], params: PwParams, label: &str) -> Option<[u8; 32]> {
    let k = pwhash::derive(pin.as_bytes(), salt, params).ok()?;
    Some(enclave_crypto::kmac::kmac256(&k[..], b"", label))
}

impl LockFile {
    /// No PINs, the default timeout.
    pub fn new(params: PwParams, rng: &mut HedgedRng) -> Option<Self> {
        Some(Self {
            params,
            salt: rng.array("app/lock-salt").ok()?,
            app: rng.array("app/lock-fill").ok()?,
            emergency: rng.array("app/lock-fill").ok()?,
            app_set: false,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(LEN);
        v.push(VERSION);
        v.push(u8::from(self.app_set));
        v.extend_from_slice(&self.params.memory_kib.to_be_bytes());
        v.extend_from_slice(&self.params.iterations.to_be_bytes());
        v.extend_from_slice(&self.params.parallelism.to_be_bytes());
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.app);
        v.extend_from_slice(&self.emergency);
        v.extend_from_slice(&self.timeout.to_be_bytes());
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != LEN || b[0] != VERSION || b[1] > 1 {
            return None;
        }
        let u = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let arr = |i: usize| -> Option<[u8; 32]> { b.get(i..i + 32)?.try_into().ok() };
        Some(Self {
            params: PwParams {
                memory_kib: u(2),
                iterations: u(6),
                parallelism: u(10),
            },
            salt: arr(14)?,
            app: arr(46)?,
            emergency: arr(78)?,
            app_set: b[1] == 1,
            timeout: u(110),
        })
    }

    /// Set the app PIN (`None`: none).
    pub fn set_app(&mut self, pin: Option<&str>, rng: &mut HedgedRng) -> Option<()> {
        self.app = match pin {
            Some(p) => check(p, &self.salt, self.params, L_APP)?,
            None => rng.array("app/lock-fill").ok()?,
        };
        self.app_set = pin.is_some();
        Some(())
    }

    /// Set the emergency PIN (`None`: none).
    pub fn set_emergency(&mut self, pin: Option<&str>, rng: &mut HedgedRng) -> Option<()> {
        self.emergency = match pin {
            Some(p) => check(p, &self.salt, self.params, L_EMERGENCY)?,
            None => rng.array("app/lock-fill").ok()?,
        };
        Some(())
    }

    /// What `pin` is (one Argon2id run for both).
    pub fn entered(&self, pin: &str) -> Entered {
        let Ok(k) = pwhash::derive(pin.as_bytes(), &self.salt, self.params) else {
            return Entered::Neither;
        };
        let app: [u8; 32] = enclave_crypto::kmac::kmac256(&k[..], b"", L_APP);
        let em: [u8; 32] = enclave_crypto::kmac::kmac256(&k[..], b"", L_EMERGENCY);
        if bool::from(em.ct_eq(&self.emergency)) {
            Entered::Emergency
        } else if self.app_set && bool::from(app.ct_eq(&self.app)) {
            Entered::App
        } else {
            Entered::Neither
        }
    }
}

/// Erase the profile in `dir` without opening it (the panic wipe, also
/// from the command line: `enclave --panic-wipe`): every keystore secret
/// is destroyed, in the platform keystore or overwritten in files (which
/// alone makes the database unreadable), then the database and the lock
/// settings go.
pub fn erase_profile(dir: &std::path::Path) -> std::io::Result<()> {
    crate::keystore::erase(dir)?;
    for f in ["profile.redb", "profile.redb.pre-migration", "lock.bin"] {
        match std::fs::remove_file(dir.join(f)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_are_told_apart() {
        let mut rng = HedgedRng::new().unwrap();
        let mut f = LockFile::new(PwParams::FLOOR, &mut rng).unwrap();
        assert_eq!(f.entered("1234"), Entered::Neither);
        f.set_app(Some("1234"), &mut rng).unwrap();
        f.set_emergency(Some("9999"), &mut rng).unwrap();
        f.timeout = 60;
        let g = LockFile::decode(&f.encode()).unwrap();
        assert_eq!(g.entered("1234"), Entered::App);
        assert_eq!(g.entered("9999"), Entered::Emergency);
        assert_eq!(g.entered("0000"), Entered::Neither);
        assert_eq!(g.timeout, 60);
        // Without an emergency PIN the file is the same size and its slot
        // random.
        let mut h = g.clone();
        h.set_emergency(None, &mut rng).unwrap();
        assert_eq!(h.encode().len(), g.encode().len());
        assert_eq!(h.entered("9999"), Entered::Neither);
        assert!(LockFile::decode(&h.encode()[1..]).is_none());
        assert!(g.app_set);
    }

    #[test]
    fn panic_wipe_from_outside() {
        use enclave_store::Keystore as _;
        let dir = std::env::temp_dir().join(format!("enclave-wipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ks = enclave_store::FileKeystore::new(dir.join("keys")).unwrap();
        ks.create("enclave-profile-secret", &[7; 32]).unwrap();
        ks.create("enclave-shred-3", &[8; 32]).unwrap();
        std::fs::write(dir.join("profile.redb"), b"db").unwrap();
        std::fs::write(dir.join("lock.bin"), b"lock").unwrap();
        erase_profile(&dir).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "nothing left");
        erase_profile(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
