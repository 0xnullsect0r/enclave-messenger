//! The platform keystores, under the vault's `Keystore` adapters
//! (`docs/14-storage.md` §1.1): small secrets kept by the operating system
//! for the logged-in user, rather than in files in the profile.
//!
//! - macOS: the login Keychain (generic passwords, service
//!   [`SERVICE`]), readable only while the user is logged in and the
//!   keychain unlocked, and by this app without asking.
//! - Windows: DPAPI. A secret is sealed to the user's logon credentials
//!   (`CryptProtectData`, with the secret's name as extra entropy) and the
//!   sealed blob is kept in the profile; another user, or the same files
//!   on another machine, can't open it.
//! - iOS: the same Keychain code (each item sealed to a Secure Enclave
//!   key; the app's profile gives it its access group).
//! - Android: the Android Keystore, through the app's activity.
//! - Linux and the BSDs: the Secret Service (GNOME Keyring, KWallet), or in
//!   a Flatpak the secret portal, through `oo7`; items carry the attributes
//!   `application` = [`SERVICE`] and `account`.
//!
//! Each call blocks; the vault makes few of them (at open, at a shred).

/// The service name the secrets are kept under.
pub const SERVICE: &str = "com.aricummings.Enclave";

/// Why a keystore call failed.
#[derive(Debug)]
pub enum Error {
    /// No secret under that name.
    NotFound,
    /// The keystore isn't there or refused (no Secret Service running, a
    /// locked keychain the user didn't open, …).
    Unavailable(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotFound => f.write_str("no such secret"),
            Error::Unavailable(why) => write!(f, "keystore unavailable: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// macOS: the login Keychain, and where the build is signed with a
/// keychain access group, a Secure Enclave key around each secret.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod keychain {
    use super::{Error, SERVICE};
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use zeroize::Zeroizing;

    const NOT_FOUND: i32 = -25300; // errSecItemNotFound
    /// The item holds the secret as it is.
    const PLAIN: u8 = 0;
    /// The item holds the secret sealed to a Secure Enclave key.
    const WRAPPED: u8 = 1;
    const ALG: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

    fn map(e: security_framework::base::Error) -> Error {
        if e.code() == NOT_FOUND {
            Error::NotFound
        } else {
            Error::Unavailable(e.to_string())
        }
    }

    fn label(account: &str) -> String {
        format!("{SERVICE} {account}")
    }

    /// The Secure Enclave key for `account`, made if `create` and there
    /// is none. `None` where there is no Secure Enclave, or the build has
    /// no keychain access group (unsigned builds, tests): the item then
    /// holds the secret as it is, under the Keychain's own protection.
    fn enclave_key(account: &str, create: bool) -> Option<SecKey> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
        let found = ItemSearchOptions::new()
            .class(ItemClass::key())
            .label(&label(account))
            .load_refs(true)
            .search()
            .unwrap_or_default();
        for r in found {
            if let SearchResult::Ref(Reference::Key(k)) = r {
                return Some(k);
            }
        }
        if !create {
            return None;
        }
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        // Usable only while the Mac is unlocked, never leaves it, and its
        // private key only decrypts (no user presence: the app asks for
        // that itself where it wants it).
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            1 << 30, // kSecAccessControlPrivateKeyUsage
        )
        .ok()?;
        let mut o = GenerateKeyOptions::default();
        o.set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(label(account))
            .set_location(security_framework::item::Location::DataProtectionKeychain)
            .set_access_control(access);
        SecKey::new(&o).ok()
    }

    /// Keep `secret` under `account` (replacing what was there).
    pub fn set(account: &str, secret: &[u8]) -> Result<(), Error> {
        let item = match enclave_key(account, true)
            .and_then(|k| k.public_key())
            .and_then(|p| p.encrypt_data(ALG, secret).ok())
        {
            Some(sealed) => [&[WRAPPED][..], &sealed].concat(),
            None => [&[PLAIN][..], secret].concat(),
        };
        let item = Zeroizing::new(item);
        security_framework::passwords::set_generic_password(SERVICE, account, &item).map_err(map)
    }

    /// The secret under `account`.
    pub fn get(account: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let item = Zeroizing::new(
            security_framework::passwords::get_generic_password(SERVICE, account).map_err(map)?,
        );
        match item.split_first() {
            Some((&PLAIN, s)) => Ok(Zeroizing::new(s.to_vec())),
            Some((&WRAPPED, sealed)) => {
                let k = enclave_key(account, false)
                    .ok_or_else(|| Error::Unavailable("its Secure Enclave key is gone".into()))?;
                k.decrypt_data(ALG, sealed)
                    .map(Zeroizing::new)
                    .map_err(|e| Error::Unavailable(e.to_string()))
            }
            _ => Err(Error::Unavailable("an item this version can't read".into())),
        }
    }

    /// Delete the secret under `account` (none there is fine), and its
    /// Secure Enclave key.
    pub fn delete(account: &str) -> Result<(), Error> {
        if let Some(k) = enclave_key(account, false) {
            let _ = k.delete();
        }
        match security_framework::passwords::delete_generic_password(SERVICE, account) {
            Err(e) if e.code() != NOT_FOUND => Err(map(e)),
            _ => Ok(()),
        }
    }

    /// Every account under [`SERVICE`] that starts with `prefix`.
    pub fn accounts(prefix: &str) -> Result<Vec<String>, Error> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
        let found = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .load_attributes(true)
            .limit(Limit::All)
            .search();
        let found = match found {
            Ok(f) => f,
            Err(e) if e.code() == NOT_FOUND => return Ok(Vec::new()),
            Err(e) => return Err(map(e)),
        };
        Ok(found
            .iter()
            .filter_map(|r| r.simplify_dict()?.get("acct").cloned())
            .filter(|a| a.starts_with(prefix))
            .collect())
    }

    /// A test item can be written, read and removed.
    pub fn available() -> bool {
        let probe = "enclave-probe";
        set(probe, b"probe").is_ok() && get(probe).is_ok() && delete(probe).is_ok()
    }
}

/// iOS: items the app shares with its notification service extension,
/// in the app group's Keychain access group: readable from the first
/// unlock after a restart (a notification can come while the phone is
/// locked), never backed up or synced off the device (`docs/10-push.md`
/// §5.1). Only the notification key table goes here.
#[cfg(target_os = "ios")]
pub mod shared {
    use super::{Error, SERVICE};
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{self, PasswordOptions};

    /// The app group (the app's and the extension's profiles both carry
    /// it).
    pub const APP_GROUP: &str = "group.com.aricummings.enclave";
    /// The notification key table (`enclave_proto::notify::KeyTable`).
    pub const NOTIFY_TABLE: &str = "notify-table";

    fn options(account: &str) -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(SERVICE, account);
        o.set_access_group(APP_GROUP);
        o.set_access_synchronized(Some(false));
        o
    }

    fn map(e: security_framework::base::Error) -> Error {
        if e.code() == -25300 {
            Error::NotFound
        } else {
            Error::Unavailable(e.to_string())
        }
    }

    /// Keep `data` under `account` (replacing what was there).
    pub fn set(account: &str, data: &[u8]) -> Result<(), Error> {
        let _ = passwords::delete_generic_password_options(options(account));
        let mut o = options(account);
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .map_err(map)?;
        o.set_access_control(access);
        passwords::set_generic_password_options(data, o).map_err(map)
    }

    /// What is under `account`.
    pub fn get(account: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        passwords::generic_password(options(account))
            .map(zeroize::Zeroizing::new)
            .map_err(map)
    }

    /// Remove `account` (none there is fine).
    pub fn delete(account: &str) {
        let _ = passwords::delete_generic_password_options(options(account));
    }
}

/// Windows: DPAPI, bound to the user's logon credentials.
#[cfg(windows)]
pub mod dpapi {
    use super::Error;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use zeroize::Zeroizing;

    fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: b.len() as u32,
            pbData: b.as_ptr().cast_mut(),
        }
    }

    /// Copy out and free a blob DPAPI allocated.
    ///
    /// # Safety
    /// `out` must be a blob DPAPI filled (`pbData` from `LocalAlloc`, valid
    /// for `cbData` bytes), not used afterwards.
    unsafe fn take(out: &CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        // SAFETY: by the contract above, pbData points to cbData readable
        // bytes.
        let v = Zeroizing::new(unsafe {
            std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec()
        });
        // SAFETY: wipe the system's copy before handing it back; it is
        // writable memory of cbData bytes we own until LocalFree.
        unsafe { std::ptr::write_bytes(out.pbData, 0, out.cbData as usize) };
        // SAFETY: pbData came from LocalAlloc inside DPAPI and is freed once.
        unsafe { LocalFree(out.pbData.cast()) };
        v
    }

    /// Seal `data` to this user, with `entropy` (the secret's name) needed
    /// to open it.
    pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, Error> {
        let input = blob(data);
        let extra = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: the input blobs point into live slices for the call; the
        // description, reserved and prompt arguments may be null; DPAPI
        // fills `out` with a LocalAlloc'd buffer on success.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(Error::Unavailable(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        // SAFETY: filled by the successful call above.
        Ok(unsafe { take(&out) }.to_vec())
    }

    /// Open what [`protect`] sealed, with the same `entropy`.
    pub fn unprotect(sealed: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let input = blob(sealed);
        let extra = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`; the description out-pointer is null.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(Error::Unavailable(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        // SAFETY: filled by the successful call above.
        Ok(unsafe { take(&out) })
    }
}

/// Linux and the BSDs: the Secret Service, or the secret portal in a
/// Flatpak.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
pub mod secret_service {
    use super::{Error, SERVICE};
    use zeroize::Zeroizing;

    fn map(e: oo7::Error) -> Error {
        Error::Unavailable(e.to_string())
    }

    /// The user's default keyring, unlocked (the desktop may ask for its
    /// password).
    pub struct Keyring(oo7::Keyring);

    static SHARED: std::sync::OnceLock<Option<Keyring>> = std::sync::OnceLock::new();

    /// The keyring, connected once per process: the first call connects
    /// (a sandboxed process makes it before it confines itself, as it
    /// can't open the bus socket afterwards), later ones reuse it. `None`
    /// without a Secret Service (or portal).
    pub fn shared() -> Option<&'static Keyring> {
        SHARED.get_or_init(|| Keyring::open().ok()).as_ref()
    }

    /// Where the secret portal's keyring file is, in a Flatpak (it must
    /// stay writable to a confined process); `None` outside one.
    pub fn sandbox_keyrings() -> Option<std::path::PathBuf> {
        if !std::path::Path::new("/.flatpak-info").exists() {
            return None;
        }
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share"))
            })?;
        Some(data.join("keyrings"))
    }

    impl Keyring {
        /// Connect; fails without a Secret Service (or portal).
        fn open() -> Result<Self, Error> {
            pollster::block_on(async {
                let k = oo7::Keyring::new().await.map_err(map)?;
                k.unlock().await.map_err(map)?;
                Ok(Self(k))
            })
        }

        /// Keep `secret` under `account` (replacing what was there).
        pub fn set(&self, account: &str, secret: &[u8]) -> Result<(), Error> {
            pollster::block_on(self.0.create_item(
                &format!("Enclave ({account})"),
                &[("application", SERVICE), ("account", account)],
                secret,
                true,
            ))
            .map_err(map)
        }

        /// The secret under `account`.
        pub fn get(&self, account: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
            pollster::block_on(async {
                let items = self
                    .0
                    .search_items(&[("application", SERVICE), ("account", account)])
                    .await
                    .map_err(map)?;
                let item = items.first().ok_or(Error::NotFound)?;
                let s = item.secret().await.map_err(map)?;
                Ok(Zeroizing::new(s.as_bytes().to_vec()))
            })
        }

        /// Delete the secret under `account` (none there is fine).
        pub fn delete(&self, account: &str) -> Result<(), Error> {
            pollster::block_on(
                self.0
                    .delete(&[("application", SERVICE), ("account", account)]),
            )
            .map_err(map)
        }

        /// Every account under [`SERVICE`] that starts with `prefix`.
        pub fn accounts(&self, prefix: &str) -> Result<Vec<String>, Error> {
            pollster::block_on(async {
                let items = self
                    .0
                    .search_items(&[("application", SERVICE)])
                    .await
                    .map_err(map)?;
                let mut out = Vec::new();
                for i in items {
                    if let Some(a) = i.attributes().await.map_err(map)?.get("account")
                        && a.starts_with(prefix)
                    {
                        out.push(a.clone());
                    }
                }
                Ok(out)
            })
        }
    }

    impl std::fmt::Debug for Keyring {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Keyring")
        }
    }
}

/// Android: the Android Keystore, through the app's activity (`Keys.java`
/// in `apps/android`): each secret sealed with AES-256-GCM under its own
/// key held by the secure hardware (StrongBox where the phone has one),
/// the sealed bytes in the app's no-backup files.
#[cfg(target_os = "android")]
pub mod android {
    use super::Error;
    use crate::jvm::{strings, with_any as with};
    use jni::objects::{JByteArray, JObjectArray, JValue};
    use zeroize::Zeroizing;

    fn refused() -> Error {
        Error::Unavailable("the Android Keystore refused".into())
    }

    /// Whether the keystore answers.
    pub fn available() -> bool {
        with(|env, a| env.call_method(a, "keyAvailable", "()Z", &[])?.z()).unwrap_or(false)
    }

    /// Keep `secret` under `account` (replacing what was there).
    pub fn set(account: &str, secret: &[u8]) -> Result<(), Error> {
        let ok = with(|env, a| {
            let acc = env.new_string(account)?;
            let data = env.byte_array_from_slice(secret)?;
            env.call_method(
                a,
                "keySet",
                "(Ljava/lang/String;[B)Z",
                &[JValue::Object(&acc), JValue::Object(&data)],
            )?
            .z()
        });
        if ok == Some(true) {
            Ok(())
        } else {
            Err(refused())
        }
    }

    /// The secret under `account`.
    pub fn get(account: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let got = with(|env, a| {
            let acc = env.new_string(account)?;
            let out = env
                .call_method(
                    a,
                    "keyGet",
                    "(Ljava/lang/String;)[B",
                    &[JValue::Object(&acc)],
                )?
                .l()?;
            if out.is_null() {
                return Ok(None);
            }
            let array = JByteArray::from(out);
            let bytes = env.convert_byte_array(&array)?;
            // Then the JVM's copy is overwritten, not left for the collector.
            let zeros = vec![0i8; bytes.len()];
            env.set_byte_array_region(&array, 0, &zeros)?;
            Ok(Some(bytes))
        });
        match got {
            Some(Some(bytes)) => Ok(Zeroizing::new(bytes)),
            Some(None) => Err(Error::NotFound),
            None => Err(refused()),
        }
    }

    /// Delete the secret under `account` and its key.
    pub fn delete(account: &str) -> Result<(), Error> {
        let ok = with(|env, a| {
            let acc = env.new_string(account)?;
            env.call_method(
                a,
                "keyDelete",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&acc)],
            )?
            .z()
        });
        if ok == Some(true) {
            Ok(())
        } else {
            Err(refused())
        }
    }

    /// Every account kept whose name starts with `prefix`.
    pub fn accounts(prefix: &str) -> Result<Vec<String>, Error> {
        with(|env, a| {
            let p = env.new_string(prefix)?;
            let arr = env
                .call_method(
                    a,
                    "keyList",
                    "(Ljava/lang/String;)[Ljava/lang/String;",
                    &[JValue::Object(&p)],
                )?
                .l()?;
            Ok(strings(env, &JObjectArray::from(arr)))
        })
        .ok_or_else(refused)
    }
}
