//! The relay's long-term keys on disk.
//!
//! | File | Contents |
//! |---|---|
//! | `identity.key` | Composite (Ed448 + ML-DSA-87) signing key; the relay id is derived from it and it signs the relay's descriptor |
//! | `link.key` | X448 secret for relay↔relay links (56 B) |
//! | `ticket-chain.key` | Daily ticket-key seed chain (`enclave_service::SeedChain`) |
//!
//! The link key is published in the relay's descriptor and must not change;
//! ticket keys rotate daily, derived from the chain
//! (`TicketSecretKey::from_seed`), and yesterday's is kept a day for
//! requests sealed just before midnight.

use enclave_calls::ticket::TicketSecretKey;
use enclave_crypto::kem::{X448_LEN, X448Secret};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_SEED_LEN, CompositeSigningKey};
use enclave_service::keyfile::{create_key_dir, create_secret, read_array};
use enclave_service::{KeyError, SeedChain};
use std::path::Path;
use zeroize::Zeroizing;

const IDENTITY_FILE: &str = "identity.key";
const LINK_FILE: &str = "link.key";
const CHAIN_FILE: &str = "ticket-chain.key";

/// The relay's keys.
pub struct RelayKeys {
    /// Relay id (`enclave_federation::relay_id` of the identity key).
    pub id: [u8; 16],
    /// Identity key.
    pub identity: CompositeSigningKey,
    link: Zeroizing<[u8; X448_LEN]>,
    chain: SeedChain,
}

impl RelayKeys {
    /// Create the key directory and fresh keys, starting the ticket chain
    /// at `day`. Refuses to overwrite keys.
    pub fn init(dir: &Path, day: u32) -> Result<Self, KeyError> {
        if [IDENTITY_FILE, LINK_FILE, CHAIN_FILE]
            .iter()
            .any(|f| dir.join(f).exists())
        {
            return Err(KeyError::Exists(dir.to_path_buf()));
        }
        create_key_dir(dir)?;
        let crypto = |_| KeyError::Crypto;
        let mut rng = HedgedRng::new().map_err(crypto)?;
        let identity = CompositeSigningKey::generate(&mut rng).map_err(crypto)?;
        let id = enclave_federation::relay_id(identity.public());
        let link = Zeroizing::new(rng.array::<X448_LEN>("relay/link-key").map_err(crypto)?);
        let seed = Zeroizing::new(rng.array::<32>("relay/ticket-chain").map_err(crypto)?);
        create_secret(&dir.join(IDENTITY_FILE), identity.seed().as_slice())?;
        create_secret(&dir.join(LINK_FILE), &link[..])?;
        let chain =
            SeedChain::create(&dir.join(CHAIN_FILE), day, seed, TicketSecretKey::next_seed)?;
        Ok(Self {
            id,
            identity,
            link,
            chain,
        })
    }

    /// Load the keys in `dir`.
    pub fn load(dir: &Path) -> Result<Self, KeyError> {
        let path = dir.join(IDENTITY_FILE);
        let seed = read_array::<COMPOSITE_SEED_LEN>(&path)?;
        let identity =
            CompositeSigningKey::from_seed(&seed).map_err(|_| KeyError::Damaged(path))?;
        Ok(Self {
            id: enclave_federation::relay_id(identity.public()),
            identity,
            link: read_array::<X448_LEN>(&dir.join(LINK_FILE))?,
            chain: SeedChain::load(&dir.join(CHAIN_FILE), TicketSecretKey::next_seed)?,
        })
    }

    /// The link secret.
    pub fn link_secret(&self) -> X448Secret {
        X448Secret::from_bytes(*self.link)
    }

    /// Step the ticket chain to `day`. Returns whether it moved.
    pub fn advance(&mut self, day: u32) -> Result<bool, KeyError> {
        self.chain.advance_to(day)
    }

    /// Ticket keys, newest first: today's, and yesterday's if kept.
    pub fn tickets(&self) -> Vec<TicketSecretKey> {
        let day = self.chain.period();
        let mut v = vec![TicketSecretKey::from_seed(
            self.id,
            day,
            self.chain.current(),
        )];
        if let Some(p) = self.chain.previous() {
            v.push(TicketSecretKey::from_seed(
                self.id,
                day.saturating_sub(1),
                p,
            ));
        }
        v
    }

    /// The relay's static WireGuard key, from the link key (as
    /// [`crate::Relay`] derives it).
    pub fn wg_public(&self) -> [u8; 32] {
        enclave_calls::wg::public_key(crate::wg_secret(&self.link_secret()))
    }

    /// Tomorrow's ticket key (published ahead in the relay descriptor).
    pub fn next_ticket(&self) -> TicketSecretKey {
        TicketSecretKey::from_seed(self.id, self.chain.period() + 1, &self.chain.next())
    }

    /// A signed descriptor (`enclave_federation::RelayDescriptor`) with
    /// today's and tomorrow's ticket keys, valid two days from `now`.
    pub fn descriptor(
        &self,
        operator: &str,
        family: &str,
        addr: &str,
        effort: u32,
        now: u64,
    ) -> Result<enclave_federation::RelayDescriptor, KeyError> {
        let ticket = |k: &TicketSecretKey| {
            let p = k.public();
            [&p.epoch.to_be_bytes()[..], &p.x448.0, &p.mlkem.0[..]].concat()
        };
        let mut rng = HedgedRng::new().map_err(|_| KeyError::Crypto)?;
        enclave_federation::RelayDescriptor::sign(
            &self.identity,
            operator,
            family,
            addr,
            self.link_secret().public().0,
            crate::kem_secret(&self.link_secret()).1.0.to_vec(),
            self.wg_public(),
            vec![ticket(&self.tickets()[0]), ticket(&self.next_ticket())],
            effort,
            now,
            now + 2 * 86_400,
            &mut rng,
        )
        .map_err(|_| KeyError::Crypto)
    }
}
