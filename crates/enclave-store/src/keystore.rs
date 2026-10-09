//! Keystore adapters.
//!
//! The platform keystore holds one random 256-bit *device secret* per profile.
//! Production adapters live in `enclave-platform` (Secure Enclave + Keychain on
//! Apple, StrongBox/Keystore on Android, CNG/TPM on Windows, Secret Service on
//! Linux). This module defines the interface and two portable adapters:
//! [`MemoryKeystore`] for tests and [`FileKeystore`], which stores the secret
//! in a file and is only acceptable on desktops with full-disk encryption.

use crate::{Result, StoreError};
use enclave_crypto::rng::HedgedRng;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// A place to keep device secrets that the platform protects.
pub trait Keystore: Send + Sync {
    /// Create (or replace) the secret under `name` and return it.
    fn create(&self, name: &str, secret: &[u8; 32]) -> Result<()>;
    /// Load the secret under `name`.
    fn load(&self, name: &str) -> Result<Zeroizing<[u8; 32]>>;
    /// Destroy the secret under `name` (crypto-erase).
    fn destroy(&self, name: &str) -> Result<()>;
}

/// Keystore name of the secret that wraps the recovery secret on the device
/// that holds it (`docs/14-storage.md` §1.3). Platform keystores give it a
/// policy of its own: it needs the device unlocked, and biometrics alone
/// can't release it.
pub const ROOT_SECRET: &str = "enclave-root-secret";

/// Keystore name of the device's hedge secret (`docs/02-cryptography.md`
/// §6.1).
pub const HEDGE_SECRET: &str = "enclave-hedge-secret";

/// The device's hedged RNG. Its hedge secret lives in the keystore (so in
/// hardware where the keystore is, and never in the database: a copied
/// profile can't predict it) and is refreshed every time it is taken: the
/// new one is drawn from fresh OS entropy hedged with the old one, purpose
/// `store/hedge`, and replaces it. If the keystore has none, or can't be
/// read, a new one is made from the OS.
pub fn device_rng(keystore: &dyn Keystore) -> Result<HedgedRng> {
    let next: Zeroizing<[u8; 32]> = Zeroizing::new(match keystore.load(HEDGE_SECRET) {
        Ok(old) => HedgedRng::with_hedge(*old).array("store/hedge")?,
        Err(_) => HedgedRng::new()?.array("store/hedge")?,
    });
    keystore.create(HEDGE_SECRET, &next)?;
    Ok(HedgedRng::with_hedge(*next))
}

/// In-memory keystore (tests).
#[derive(Default)]
pub struct MemoryKeystore {
    items: Mutex<HashMap<String, Zeroizing<[u8; 32]>>>,
}

impl Keystore for MemoryKeystore {
    fn create(&self, name: &str, secret: &[u8; 32]) -> Result<()> {
        let mut m = self
            .items
            .lock()
            .map_err(|_| StoreError::Keystore("poisoned".into()))?;
        m.insert(name.to_string(), Zeroizing::new(*secret));
        Ok(())
    }
    fn load(&self, name: &str) -> Result<Zeroizing<[u8; 32]>> {
        let m = self
            .items
            .lock()
            .map_err(|_| StoreError::Keystore("poisoned".into()))?;
        m.get(name).cloned().ok_or(StoreError::NotFound)
    }
    fn destroy(&self, name: &str) -> Result<()> {
        let mut m = self
            .items
            .lock()
            .map_err(|_| StoreError::Keystore("poisoned".into()))?;
        m.remove(name);
        Ok(())
    }
}

/// File keystore: one file per secret, overwritten with zeros before removal.
/// Flash wear levelling makes overwriting unreliable, which is why production
/// uses hardware keystores; this adapter exists for development and for Linux
/// desktops without a Secret Service.
pub struct FileKeystore {
    dir: PathBuf,
}

impl FileKeystore {
    /// Use `dir` (created if missing).
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| StoreError::Keystore(e.to_string()))?;
        Ok(Self { dir })
    }

    fn path(&self, name: &str) -> PathBuf {
        let safe: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        self.dir.join(format!("{safe}.key"))
    }
}

impl Keystore for FileKeystore {
    fn create(&self, name: &str, secret: &[u8; 32]) -> Result<()> {
        std::fs::write(self.path(name), secret).map_err(|e| StoreError::Keystore(e.to_string()))
    }
    fn load(&self, name: &str) -> Result<Zeroizing<[u8; 32]>> {
        let b = Zeroizing::new(std::fs::read(self.path(name)).map_err(|_| StoreError::NotFound)?);
        let arr: [u8; 32] = b.as_slice().try_into().map_err(|_| StoreError::Malformed)?;
        Ok(Zeroizing::new(arr))
    }
    fn destroy(&self, name: &str) -> Result<()> {
        let p = self.path(name);
        if p.exists() {
            let _ = std::fs::write(&p, [0u8; 32]);
            std::fs::remove_file(&p).map_err(|e| StoreError::Keystore(e.to_string()))?;
        }
        Ok(())
    }
}
