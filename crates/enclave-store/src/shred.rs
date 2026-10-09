//! Crypto-shredding keyring for disappearing messages and deletions.

use crate::store::{Store, open_chunked, seal_chunked};
use crate::{Result, StoreError};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const NS: &str = "__shred";

/// The keyring. Keys are per `(conversation, day)`.
pub struct Shredder<'s> {
    store: &'s Store,
    generation: u64,
    keys: BTreeMap<(Vec<u8>, u64), Zeroizing<[u8; 32]>>,
}

fn wrap_name(generation: u64) -> String {
    format!("enclave-shred-{generation}")
}

impl<'s> Shredder<'s> {
    /// Load (or create) the keyring.
    pub fn open(store: &'s Store, rng: &mut HedgedRng) -> Result<Self> {
        let Some(meta) = store.get(NS, b"generation")? else {
            let mut s = Self {
                store,
                generation: 0,
                keys: BTreeMap::new(),
            };
            s.rewrap(rng)?;
            return Ok(s);
        };
        let generation = u64::from_be_bytes(
            meta.as_slice()
                .try_into()
                .map_err(|_| StoreError::Malformed)?,
        );
        let wrap = store.keystore().load(&wrap_name(generation))?;
        let sealed = store.get(NS, b"keyring")?.ok_or(StoreError::Malformed)?;
        let pt = open_chunked(&SealKey::from_bytes(*wrap), b"keyring", &sealed)?;
        let mut keys = BTreeMap::new();
        let mut off = 0usize;
        while off < pt.len() {
            let n = u32::from_be_bytes(
                pt.get(off..off + 4)
                    .ok_or(StoreError::Malformed)?
                    .try_into()
                    .map_err(|_| StoreError::Malformed)?,
            ) as usize;
            off += 4;
            let conv = pt.get(off..off + n).ok_or(StoreError::Malformed)?.to_vec();
            off += n;
            let day = u64::from_be_bytes(
                pt.get(off..off + 8)
                    .ok_or(StoreError::Malformed)?
                    .try_into()
                    .map_err(|_| StoreError::Malformed)?,
            );
            off += 8;
            let k: [u8; 32] = pt
                .get(off..off + 32)
                .ok_or(StoreError::Malformed)?
                .try_into()
                .map_err(|_| StoreError::Malformed)?;
            off += 32;
            keys.insert((conv, day), Zeroizing::new(k));
        }
        Ok(Self {
            store,
            generation,
            keys,
        })
    }

    /// Write the keyring under a fresh wrap key and destroy the previous one.
    fn rewrap(&mut self, rng: &mut HedgedRng) -> Result<()> {
        let mut pt = Zeroizing::new(Vec::new());
        for ((conv, day), k) in &self.keys {
            pt.extend_from_slice(&(conv.len() as u32).to_be_bytes());
            pt.extend_from_slice(conv);
            pt.extend_from_slice(&day.to_be_bytes());
            pt.extend_from_slice(&k[..]);
        }
        let old = self.generation;
        let next = old + 1;
        let wrap: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("store/shred-wrap")?);
        self.store.keystore().create(&wrap_name(next), &wrap)?;
        let sealed = seal_chunked(&SealKey::from_bytes(*wrap), b"keyring", &pt, rng)?;
        // The keyring and its generation in one transaction: a crash can't
        // leave a keyring sealed under a generation not yet recorded.
        self.store.write_batch(
            NS,
            &[
                (b"keyring".to_vec(), Some(sealed)),
                (b"generation".to_vec(), Some(next.to_be_bytes().to_vec())),
            ],
            rng,
        )?;
        self.store.keystore().destroy(&wrap_name(old))?;
        self.generation = next;
        Ok(())
    }

    /// Key for `(conversation, day)`, created on first use.
    pub fn key(&mut self, conversation: &[u8], day: u64, rng: &mut HedgedRng) -> Result<SealKey> {
        let id = (conversation.to_vec(), day);
        if let Some(k) = self.keys.get(&id) {
            return Ok(SealKey::from_bytes(**k));
        }
        let k: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("store/shred-key")?);
        self.keys.insert(id, k.clone());
        self.rewrap(rng)?;
        Ok(SealKey::from_bytes(*k))
    }

    /// Seal a message body under its shred key.
    pub fn seal(
        &mut self,
        conversation: &[u8],
        day: u64,
        pt: &[u8],
        rng: &mut HedgedRng,
    ) -> Result<Vec<u8>> {
        let k = self.key(conversation, day, rng)?;
        Ok(seal::seal(&k, conversation, pt, rng)?)
    }

    /// Open a message body; fails once its day has been shredded.
    pub fn open_msg(&self, conversation: &[u8], day: u64, sealed: &[u8]) -> Result<Vec<u8>> {
        let k = self
            .keys
            .get(&(conversation.to_vec(), day))
            .ok_or(StoreError::NotFound)?;
        Ok(seal::open(&SealKey::from_bytes(**k), conversation, sealed)?)
    }

    /// Shred every key of `conversation` for days `< before_day`.
    pub fn shred(
        &mut self,
        conversation: &[u8],
        before_day: u64,
        rng: &mut HedgedRng,
    ) -> Result<usize> {
        let before = self.keys.len();
        self.keys
            .retain(|(c, d), _| !(c == conversation && *d < before_day));
        let removed = before - self.keys.len();
        if removed > 0 {
            self.rewrap(rng)?;
        }
        Ok(removed)
    }
}
