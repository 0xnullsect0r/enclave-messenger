//! Encrypted local storage (`docs/14-storage.md`).
//!
//! * **Master key** = `KMAC256(device-wrapped secret ‖ Argon2id(passphrase)?)`.
//!   The device-wrapped secret lives in a platform [`Keystore`] (Secure
//!   Enclave + Keychain, StrongBox/Keystore, TPM/CNG, Secret Service).
//! * **Records**: one redb database. Every key is blinded with KMAC so the file
//!   reveals no names; every value is sealed with EnclaveSeal under its own
//!   per-record key, with the blinded key as associated data, so records cannot
//!   be swapped.
//! * **Crypto-shredding**: disappearing messages and deletions are sealed under
//!   per-conversation, per-day *shred keys* kept in a small keyring. Shredding
//!   removes the key from the keyring and re-wraps the keyring under a fresh
//!   device key, deleting the old one, so the data is unrecoverable even from an
//!   image of the disk taken afterwards.
//! * **Backups** never contain ratchet or sender-key state; restoring creates a
//!   new device that re-establishes sessions.
//! * **Rollback**: mobile platforms give apps no usable monotonic counter, so
//!   the store makes no rollback claim; EnclaveSeal's hedged nonces keep a
//!   rolled-back state from ever reusing a keystream.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backup;
pub mod keystore;
pub mod shred;
pub mod store;

pub use keystore::{FileKeystore, Keystore, MemoryKeystore, device_rng};
pub use store::Store;

/// Errors from storage.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Cryptographic failure (wrong passphrase, tampered record).
    #[error("cryptographic failure")]
    Crypto,
    /// Database error.
    #[error("database: {0}")]
    Db(String),
    /// Keystore error.
    #[error("keystore: {0}")]
    Keystore(String),
    /// Not found.
    #[error("not found")]
    NotFound,
    /// The database is open in another process (another copy of Enclave
    /// still running, or still closing): nothing is wrong with it.
    #[error("the profile is open in another copy of Enclave")]
    InUse,
    /// Malformed data.
    #[error("malformed data")]
    Malformed,
}

impl From<enclave_crypto::Error> for StoreError {
    fn from(_: enclave_crypto::Error) -> Self {
        StoreError::Crypto
    }
}

macro_rules! db_err {
    ($($t:ty),*) => {$(
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self {
                StoreError::Db(e.to_string())
            }
        }
    )*};
}
impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self {
        match e {
            redb::DatabaseError::DatabaseAlreadyOpen => StoreError::InUse,
            e => StoreError::Db(e.to_string()),
        }
    }
}
db_err!(
    redb::Error,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

/// Result alias.
pub type Result<T> = core::result::Result<T, StoreError>;
