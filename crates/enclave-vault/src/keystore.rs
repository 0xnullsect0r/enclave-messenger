//! Where a profile's keystore secrets live (`docs/14-storage.md` §1.1):
//! the platform keystore when there is one (`enclave_platform::keystore`:
//! the login Keychain on macOS, DPAPI on Windows, the Secret Service or the
//! Flatpak secret portal on Linux), else files in the profile
//! (`FileKeystore`).
//!
//! A profile keeps its choice in a `keystore` file next to the database:
//! `file`, `dpapi`, `keychain ID` or `secret-service ID`, where `ID` (16
//! random bytes, hex) keeps one profile's secrets apart from another's.
//! A new profile takes the platform keystore if it answers; a profile made
//! with files moves its secrets into the platform keystore when it opens
//! and the keystore is there (each copied and read back, the choice
//! recorded, then the files overwritten and removed). Names are kept as
//! `FileKeystore` spells them (anything but ASCII letters and digits
//! becomes `_`), so the move is exact.

use enclave_store::{FileKeystore, Keystore, MemoryKeystore, Result, StoreError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// The file in the profile that names its keystore.
pub const MARKER: &str = "keystore";

static FILES_ONLY: AtomicBool = AtomicBool::new(false);

/// Keep secrets in files whatever the platform has (tests, so they never
/// touch the person's keychain; or `ENCLAVE_KEYSTORE=file`).
pub fn use_files_only() {
    FILES_ONLY.store(true, Ordering::SeqCst);
}

fn files_only() -> bool {
    FILES_ONLY.load(Ordering::SeqCst)
        || std::env::var("ENCLAVE_KEYSTORE").is_ok_and(|v| v == "file")
}

fn spelled(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn secret32(b: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let arr: [u8; 32] = b.try_into().map_err(|_| StoreError::Malformed)?;
    Ok(Zeroizing::new(arr))
}

fn ks_err(e: enclave_platform::keystore::Error) -> StoreError {
    match e {
        enclave_platform::keystore::Error::NotFound => StoreError::NotFound,
        enclave_platform::keystore::Error::Unavailable(why) => StoreError::Keystore(why),
    }
}

/// A platform keystore for one profile.
enum Platform {
    #[cfg(target_os = "macos")]
    Keychain { prefix: String },
    #[cfg(windows)]
    Dpapi { dir: PathBuf },
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    SecretService {
        ring: &'static enclave_platform::keystore::secret_service::Keyring,
        prefix: String,
    },
}

impl Platform {
    /// The platform keystore for a profile with this `id`, if it works
    /// here.
    #[allow(unused_variables)]
    fn open(kind: &str, id: &str, profile: &Path) -> Option<Self> {
        match kind {
            #[cfg(target_os = "macos")]
            "keychain" => Some(Platform::Keychain {
                prefix: format!("{id}/"),
            }),
            #[cfg(windows)]
            "dpapi" => Some(Platform::Dpapi {
                dir: profile.join("keys"),
            }),
            #[cfg(all(
                unix,
                not(any(target_os = "macos", target_os = "ios", target_os = "android"))
            ))]
            "secret-service" => enclave_platform::keystore::secret_service::shared().map(|ring| {
                Platform::SecretService {
                    ring,
                    prefix: format!("{id}/"),
                }
            }),
            _ => None,
        }
    }

    /// This platform's keystore kind, if it answers a probe.
    fn best() -> Option<&'static str> {
        #[cfg(target_os = "macos")]
        return enclave_platform::keystore::keychain::available().then_some("keychain");
        #[cfg(windows)]
        return enclave_platform::keystore::dpapi::protect(b"probe", b"probe")
            .is_ok()
            .then_some("dpapi");
        #[cfg(all(
            unix,
            not(any(target_os = "macos", target_os = "ios", target_os = "android"))
        ))]
        return enclave_platform::keystore::secret_service::shared()
            .is_some()
            .then_some("secret-service");
        #[allow(unreachable_code)]
        None
    }

    /// Every name it holds for the profile (spelled).
    fn names(&self) -> Result<Vec<String>> {
        match self {
            #[cfg(target_os = "macos")]
            Platform::Keychain { prefix } => {
                Ok(enclave_platform::keystore::keychain::accounts(prefix)
                    .map_err(ks_err)?
                    .into_iter()
                    .filter_map(|a| a.strip_prefix(prefix.as_str()).map(String::from))
                    .collect())
            }
            #[cfg(windows)]
            Platform::Dpapi { dir } => Ok(std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .strip_suffix(".dpapi")
                        .map(String::from)
                })
                .collect()),
            #[cfg(all(
                unix,
                not(any(target_os = "macos", target_os = "ios", target_os = "android"))
            ))]
            Platform::SecretService { ring, prefix } => Ok(ring
                .accounts(prefix)
                .map_err(ks_err)?
                .into_iter()
                .filter_map(|a| a.strip_prefix(prefix.as_str()).map(String::from))
                .collect()),
        }
    }
}

impl Keystore for Platform {
    fn create(&self, name: &str, secret: &[u8; 32]) -> Result<()> {
        let name = spelled(name);
        match self {
            #[cfg(target_os = "macos")]
            Platform::Keychain { prefix } => {
                enclave_platform::keystore::keychain::set(&format!("{prefix}{name}"), secret)
                    .map_err(ks_err)
            }
            #[cfg(windows)]
            Platform::Dpapi { dir } => {
                let sealed = enclave_platform::keystore::dpapi::protect(secret, name.as_bytes())
                    .map_err(ks_err)?;
                std::fs::create_dir_all(dir).map_err(|e| StoreError::Keystore(e.to_string()))?;
                std::fs::write(dir.join(format!("{name}.dpapi")), sealed)
                    .map_err(|e| StoreError::Keystore(e.to_string()))
            }
            #[cfg(all(
                unix,
                not(any(target_os = "macos", target_os = "ios", target_os = "android"))
            ))]
            Platform::SecretService { ring, prefix } => {
                ring.set(&format!("{prefix}{name}"), secret).map_err(ks_err)
            }
        }
    }

    fn load(&self, name: &str) -> Result<Zeroizing<[u8; 32]>> {
        let name = spelled(name);
        let bytes = match self {
            #[cfg(target_os = "macos")]
            Platform::Keychain { prefix } => {
                enclave_platform::keystore::keychain::get(&format!("{prefix}{name}"))
                    .map_err(ks_err)?
            }
            #[cfg(windows)]
            Platform::Dpapi { dir } => {
                let sealed = std::fs::read(dir.join(format!("{name}.dpapi")))
                    .map_err(|_| StoreError::NotFound)?;
                enclave_platform::keystore::dpapi::unprotect(&sealed, name.as_bytes())
                    .map_err(ks_err)?
            }
            #[cfg(all(
                unix,
                not(any(target_os = "macos", target_os = "ios", target_os = "android"))
            ))]
            Platform::SecretService { ring, prefix } => {
                ring.get(&format!("{prefix}{name}")).map_err(ks_err)?
            }
        };
        secret32(&bytes)
    }

    fn destroy(&self, name: &str) -> Result<()> {
        let name = spelled(name);
        match self {
            #[cfg(target_os = "macos")]
            Platform::Keychain { prefix } => {
                enclave_platform::keystore::keychain::delete(&format!("{prefix}{name}"))
                    .map_err(ks_err)
            }
            #[cfg(windows)]
            Platform::Dpapi { dir } => {
                let p = dir.join(format!("{name}.dpapi"));
                if p.exists() {
                    let _ = std::fs::write(&p, vec![0u8; 512]);
                    std::fs::remove_file(&p).map_err(|e| StoreError::Keystore(e.to_string()))?;
                }
                Ok(())
            }
            #[cfg(all(
                unix,
                not(any(target_os = "macos", target_os = "ios", target_os = "android"))
            ))]
            Platform::SecretService { ring, prefix } => {
                ring.delete(&format!("{prefix}{name}")).map_err(ks_err)
            }
        }
    }
}

/// What the profile's marker says: (kind, id).
fn marker(profile: &Path) -> Option<(String, String)> {
    let text = std::fs::read_to_string(profile.join(MARKER)).ok()?;
    let mut parts = text.split_whitespace();
    let kind = parts.next()?.to_string();
    Some((kind, parts.next().unwrap_or_default().to_string()))
}

fn write_marker(profile: &Path, kind: &str, id: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(profile)?;
    let tmp = profile.join(format!("{MARKER}.new"));
    std::fs::write(&tmp, format!("{kind} {id}\n").trim_start())?;
    std::fs::rename(tmp, profile.join(MARKER))
}

fn new_id() -> String {
    enclave_crypto::rng::HedgedRng::new()
        .and_then(|mut r| r.array::<16>("app/keystore-id"))
        .map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
        .unwrap_or_default()
}

/// The `*.key` files a file keystore holds (spelled names).
fn file_names(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".key")
                .map(String::from)
        })
        .collect()
}

/// Copy a file keystore's secrets into `to`, each read back; true when all
/// went.
fn copy_files(files: &FileKeystore, names: &[String], to: &dyn Keystore) -> bool {
    names.iter().all(|n| {
        files
            .load(n)
            .and_then(|s| to.create(n, &s).map(|()| s))
            .and_then(|s| to.load(n).map(|back| back == s))
            .unwrap_or(false)
    })
}

/// The keystore of the profile in `profile`, chosen (and the profile's
/// file secrets moved) as described above.
pub fn open(profile: &Path) -> Arc<dyn Keystore> {
    let keys = profile.join("keys");
    let fallback = || -> Arc<dyn Keystore> {
        match FileKeystore::new(&keys) {
            Ok(k) => Arc::new(k),
            Err(_) => Arc::new(MemoryKeystore::default()),
        }
    };
    let held = marker(profile);
    if let Some((kind, id)) = &held
        && kind != "file"
    {
        match Platform::open(kind, id, profile) {
            Some(p) => {
                // A move that stopped after the marker: the files go now.
                if let Ok(f) = FileKeystore::new(&keys) {
                    for n in file_names(&keys) {
                        let _ = f.destroy(&n);
                    }
                }
                return Arc::new(p);
            }
            // Recorded but not reachable now (a locked keyring, no
            // Secret Service this session): the profile can't open, and
            // says so, rather than starting over in files.
            None => return Arc::new(Unreachable(kind.clone())),
        }
    }
    if files_only() {
        return fallback();
    }
    let Some(kind) = Platform::best() else {
        if held.is_none() {
            let _ = write_marker(profile, "file", "");
        }
        return fallback();
    };
    let id = new_id();
    let Some(platform) = Platform::open(kind, &id, profile) else {
        return fallback();
    };
    // New, or made with files: move what there is, then record the choice.
    let names = file_names(&keys);
    if !names.is_empty() {
        let Ok(files) = FileKeystore::new(&keys) else {
            return fallback();
        };
        if !copy_files(&files, &names, &platform) {
            for n in &names {
                let _ = platform.destroy(n);
            }
            return fallback();
        }
        if write_marker(profile, kind, &id).is_err() {
            return fallback();
        }
        for n in &names {
            let _ = files.destroy(n);
        }
    } else if write_marker(profile, kind, &id).is_err() {
        return fallback();
    }
    Arc::new(platform)
}

/// Connect to the platform keystore now, while this process can (the vault
/// calls it before it confines itself: afterwards it can't open the
/// Secret Service's bus socket). Elsewhere, and with files only, nothing.
pub fn prepare() {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    if !files_only() {
        let _ = enclave_platform::keystore::secret_service::shared();
    }
}

/// Paths the confined vault must still write for its keystore: the secret
/// portal's keyring file in a Flatpak.
pub fn writable_paths() -> Vec<PathBuf> {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    if !files_only() {
        return enclave_platform::keystore::secret_service::sandbox_keyrings()
            .into_iter()
            .collect();
    }
    Vec::new()
}

/// Destroy every keystore secret of the profile in `profile`, wherever
/// they are (the panic wipe and the emergency PIN). Files are overwritten
/// before they are removed.
pub fn erase(profile: &Path) -> std::io::Result<()> {
    let keys = profile.join("keys");
    if let Some((kind, id)) = marker(profile)
        && let Some(p) = Platform::open(&kind, &id, profile)
    {
        for n in p
            .names()
            .map_err(|e| std::io::Error::other(e.to_string()))?
        {
            p.destroy(&n)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
    }
    if let Ok(f) = FileKeystore::new(&keys) {
        for n in file_names(&keys) {
            let _ = f.destroy(&n);
        }
    }
    match std::fs::remove_dir_all(&keys) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    match std::fs::remove_file(profile.join(MARKER)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// A profile whose recorded keystore can't be reached now: every call
/// fails, so the profile doesn't open (and nothing is made elsewhere).
struct Unreachable(String);

impl Keystore for Unreachable {
    fn create(&self, _: &str, _: &[u8; 32]) -> Result<()> {
        Err(StoreError::Keystore(format!(
            "the {} isn't available",
            self.0
        )))
    }
    fn load(&self, _: &str) -> Result<Zeroizing<[u8; 32]>> {
        Err(StoreError::Keystore(format!(
            "the {} isn't available",
            self.0
        )))
    }
    fn destroy(&self, _: &str) -> Result<()> {
        Err(StoreError::Keystore(format!(
            "the {} isn't available",
            self.0
        )))
    }
}

/// Whether the profile in `profile` keeps (or, not made yet, will keep) its
/// secrets in files: no platform keystore answers here. A probe; the
/// engine asks once.
pub fn uses_files(profile: &Path) -> bool {
    match marker(profile) {
        Some((kind, _)) => kind == "file",
        None => files_only() || Platform::best().is_none(),
    }
}

/// Which keystore a profile uses, for `--report` and Settings.
pub fn describe(profile: &Path) -> &'static str {
    match marker(profile).map(|m| m.0).as_deref() {
        Some("keychain") => "keychain",
        Some("dpapi") => "dpapi",
        Some("secret-service") => "secret-service",
        _ => "file",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("enclave-ks-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// The platform keystore where this machine has one (the CI runners
    /// for macOS and Windows do; Linux CI has no Secret Service, so files):
    /// a profile's file secrets move into it, it keeps them across opens,
    /// and erasing leaves nothing.
    #[test]
    fn profiles_move_into_the_platform_keystore() {
        let dir = tmp("move");
        let files = FileKeystore::new(dir.join("keys")).unwrap();
        files.create("enclave-profile-secret", &[7; 32]).unwrap();
        files.create("enclave-shred-3", &[8; 32]).unwrap();
        let ks = open(&dir);
        assert_eq!(*ks.load("enclave-profile-secret").unwrap(), [7; 32]);
        assert_eq!(*ks.load("enclave-shred-3").unwrap(), [8; 32]);
        let kind = describe(&dir);
        if kind != "file" {
            assert!(file_names(&dir.join("keys")).is_empty(), "the files went");
        }
        ks.create("enclave-root-secret", &[9; 32]).unwrap();
        drop(ks);
        let again = open(&dir);
        assert_eq!(describe(&dir), kind, "the choice holds");
        assert_eq!(*again.load("enclave-root-secret").unwrap(), [9; 32]);
        drop(again);
        erase(&dir).unwrap();
        assert!(!dir.join(MARKER).exists());
        let after = open(&dir);
        assert!(after.load("enclave-profile-secret").is_err(), "erased");
        let _ = erase(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
