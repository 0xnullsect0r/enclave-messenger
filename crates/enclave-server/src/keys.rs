//! The server's long-term keys on disk (`docs/12-servers.md` §1.4).
//!
//! * **Identity:** a composite (Ed448 + ML-DSA-87) signing key. The server
//!   id is derived from its public half, so an id in a contact card pins
//!   the key that signs the server's descriptor and request-key
//!   certificates (`server_id`).
//! * **Request-key chain:** the daily X448 + ML-KEM-1024 request keys are
//!   derived from a seed that steps forward once a day
//!   (`ServerSecret::from_seed`, `ServerSecret::next_seed`). Only today's
//!   and yesterday's seeds are on disk; stepping overwrites the file, so a
//!   seized disk doesn't open requests recorded before yesterday.
//! * **Key transparency:** the head-signing key (composite) and the VRF
//!   secret of the username log. Clients pin both, so they never change
//!   for the life of the log.
//!
//! Files are created by `enclave-server init` in a 0700 directory with
//! mode 0600 and replaced atomically (`enclave_service::keyfile`).

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_SEED_LEN, CompositeSigningKey};
use enclave_rpc::ServerSecret;
use enclave_service::SeedChain;
use enclave_service::keyfile::{create_key_dir, create_secret, read_array};
use std::path::Path;
use zeroize::Zeroizing;

pub use enclave_service::KeyError;

pub use enclave_federation::{SERVER_ID_LABEL, server_id};

const IDENTITY_FILE: &str = "identity.key";
const CHAIN_FILE: &str = "request-chain.key";
const KT_HEAD_FILE: &str = "kt-head.key";
const KT_VRF_FILE: &str = "kt-vrf.key";

/// The request-key chain: a [`SeedChain`] with one period per day.
pub struct RequestChain(SeedChain);

impl RequestChain {
    /// The day the chain is at.
    pub fn day(&self) -> u32 {
        self.0.period()
    }

    /// Request keys, newest first: today's, and yesterday's if kept.
    pub fn keys(&self) -> Vec<ServerSecret> {
        let day = self.day();
        let mut v = vec![ServerSecret::from_seed(day, self.0.current())];
        if let Some(p) = self.0.previous() {
            v.push(ServerSecret::from_seed(day.saturating_sub(1), p));
        }
        v
    }

    /// The key for `day + 1`, published ahead in the descriptor.
    pub fn next_key(&self) -> ServerSecret {
        ServerSecret::from_seed(self.day() + 1, &self.0.next())
    }

    /// Step the chain to `today` and persist it. Returns whether it moved.
    /// Seeds older than yesterday are gone afterwards.
    pub fn advance_to(&mut self, today: u32) -> Result<bool, KeyError> {
        self.0.advance_to(today)
    }
}

/// The server's keys.
pub struct ServerKeys {
    /// Identity signing key (descriptor, request-key certificates).
    pub identity: CompositeSigningKey,
    /// Daily request keys.
    pub chain: RequestChain,
    /// Key-transparency head-signing key.
    pub kt_head: CompositeSigningKey,
    /// Key-transparency VRF secret.
    pub kt_vrf: Zeroizing<[u8; 32]>,
}

impl ServerKeys {
    /// The server id.
    pub fn id(&self) -> [u8; 16] {
        server_id(self.identity.public())
    }

    /// Create fresh keys in `dir`, starting the chain at `today`. Refuses
    /// to overwrite keys that exist.
    pub fn init(dir: &Path, today: u32) -> Result<Self, KeyError> {
        if [IDENTITY_FILE, CHAIN_FILE, KT_HEAD_FILE, KT_VRF_FILE]
            .iter()
            .any(|f| dir.join(f).exists())
        {
            return Err(KeyError::Exists(dir.to_path_buf()));
        }
        create_key_dir(dir)?;
        let crypto = |_| KeyError::Crypto;
        let mut rng = HedgedRng::new().map_err(crypto)?;
        let identity = CompositeSigningKey::generate(&mut rng).map_err(crypto)?;
        let seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(rng.array("server/request-chain").map_err(crypto)?);
        let kt_head = CompositeSigningKey::generate(&mut rng).map_err(crypto)?;
        let kt_vrf: Zeroizing<[u8; 32]> =
            Zeroizing::new(rng.array("server/kt-vrf").map_err(crypto)?);
        create_secret(&dir.join(IDENTITY_FILE), identity.seed().as_slice())?;
        create_secret(&dir.join(KT_HEAD_FILE), kt_head.seed().as_slice())?;
        create_secret(&dir.join(KT_VRF_FILE), &kt_vrf[..])?;
        let chain = SeedChain::create(&dir.join(CHAIN_FILE), today, seed, ServerSecret::next_seed)?;
        Ok(Self {
            identity,
            chain: RequestChain(chain),
            kt_head,
            kt_vrf,
        })
    }

    /// Load the keys in `dir`.
    pub fn load(dir: &Path) -> Result<Self, KeyError> {
        Ok(Self {
            identity: load_signing(&dir.join(IDENTITY_FILE))?,
            chain: RequestChain(SeedChain::load(
                &dir.join(CHAIN_FILE),
                ServerSecret::next_seed,
            )?),
            kt_head: load_signing(&dir.join(KT_HEAD_FILE))?,
            kt_vrf: read_array::<32>(&dir.join(KT_VRF_FILE))?,
        })
    }

    /// Seed of the blob-token issuer keys:
    /// `KMAC256(identity seed, "", "enclave/v1/tokens/blob-issuer-seed")`,
    /// so it needs no file of its own and lasts as long as the identity.
    pub fn blob_seed(&self) -> [u8; 32] {
        enclave_crypto::kmac::kmac256(
            self.identity.seed().as_slice(),
            b"",
            "enclave/v1/tokens/blob-issuer-seed",
        )
    }

    /// A copy of the head-signing key (the log runs on its own thread).
    pub fn kt_head_copy(&self) -> Result<CompositeSigningKey, KeyError> {
        CompositeSigningKey::from_seed(self.kt_head.seed()).map_err(|_| KeyError::Crypto)
    }
}

/// A composite signing key stored as its seed.
pub fn load_signing(path: &Path) -> Result<CompositeSigningKey, KeyError> {
    let seed = read_array::<COMPOSITE_SEED_LEN>(path)?;
    CompositeSigningKey::from_seed(&seed).map_err(|_| KeyError::Damaged(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::path::PathBuf;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("enclave-keys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn init_load_and_advance() {
        let d = dir("a");
        let k = ServerKeys::init(&d, 100).unwrap();
        assert!(ServerKeys::init(&d, 100).is_err(), "never overwrites");
        let id = k.id();
        let today = k.chain.keys()[0].public().clone();
        let tomorrow = k.chain.next_key().public().clone();
        let mut l = ServerKeys::load(&d).unwrap();
        assert_eq!(l.id(), id, "the id survives a restart");
        assert_eq!(l.chain.keys()[0].public(), &today, "so does today's key");
        assert_eq!(l.kt_head.public(), k.kt_head.public(), "and the KT pins");
        assert_eq!(*l.kt_vrf, *k.kt_vrf);
        assert!(l.chain.advance_to(101).unwrap());
        let keys = l.chain.keys();
        assert_eq!(keys[0].public(), &tomorrow, "the published next key");
        assert_eq!(keys[1].public(), &today, "yesterday's is kept");
        // Several days later: only the newest two remain, and the file
        // holds nothing older.
        assert!(l.chain.advance_to(105).unwrap());
        let reloaded = ServerKeys::load(&d).unwrap();
        assert_eq!(reloaded.chain.day(), 105);
        assert_eq!(reloaded.chain.keys().len(), 2);
        assert!(reloaded.chain.keys().iter().all(|k| k.public() != &today));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn damaged_files_refused() {
        let d = dir("b");
        ServerKeys::init(&d, 1).unwrap();
        std::fs::write(d.join(CHAIN_FILE), b"short").unwrap();
        assert!(matches!(ServerKeys::load(&d), Err(KeyError::Damaged(_))));
        let d = dir("c");
        ServerKeys::init(&d, 1).unwrap();
        std::fs::write(d.join(KT_VRF_FILE), [0u8; 31]).unwrap();
        assert!(matches!(ServerKeys::load(&d), Err(KeyError::Damaged(_))));
        let _ = std::fs::remove_dir_all(&d);
        let d = dir("b");
        let _ = std::fs::remove_dir_all(&d);
    }
}
