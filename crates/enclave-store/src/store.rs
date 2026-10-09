//! The sealed record store.

use crate::keystore::Keystore;
use crate::{Result, StoreError};
use enclave_crypto::kmac::{Kmac256, kmac256};
use enclave_crypto::pwhash::{self, PwParams};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use redb::{Database, ReadableDatabase, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

const RECORDS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("records");
const META: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("meta");

/// Label: master key.
pub const LABEL_MASTER: &str = "enclave/v1/store/master";
/// Label: index-blinding key.
pub const LABEL_INDEX: &str = "enclave/v1/store/index";
/// Label: namespace tag.
pub const LABEL_NS: &str = "enclave/v1/store/namespace";

/// Keystore name of the profile's device secret.
pub const DEVICE_SECRET: &str = "enclave-profile-secret";
/// Associated data for the wrapped master key.
const WRAP_AD: &[u8] = b"wrapped-master";

/// An open, unlocked store.
pub struct Store {
    db: Database,
    master: SealKey,
    index: Zeroizing<[u8; 32]>,
    salt: [u8; 32],
    keystore: Arc<dyn Keystore>,
}

fn derive_master(device_secret: &[u8; 32], pw: Option<&[u8; 32]>) -> SealKey {
    let mut k = Kmac256::new(device_secret, LABEL_MASTER.as_bytes());
    match pw {
        Some(p) => k.update_framed(p),
        None => k.update_framed(&[]),
    };
    let mut out = Zeroizing::new([0u8; 32]);
    k.finalize_into(&mut out[..]);
    SealKey::from_bytes(*out)
}

impl Store {
    /// Create a new store at `path` (or in memory if `None`), with a fresh device
    /// secret in `keystore` and an optional passphrase.
    pub fn create(
        path: Option<&Path>,
        keystore: Arc<dyn Keystore>,
        passphrase: Option<(&[u8], PwParams)>,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let device_secret: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("store/device-secret")?);
        keystore.create(DEVICE_SECRET, &device_secret)?;
        let salt: [u8; 32] = rng.array("store/salt")?;
        let db = open_db(path)?;
        let pw = match passphrase {
            Some((p, params)) => Some(pwhash::derive(p, &salt, params)?),
            None => None,
        };
        let master = derive_master(&device_secret, pw.as_deref());
        // A verifier record lets `open` distinguish a wrong passphrase.
        let check = seal::seal(&master, b"verifier", b"enclave", rng)?;
        let params_bytes = passphrase
            .map(|(_, p)| encode_params(p))
            .unwrap_or_default();
        let w = db.begin_write()?;
        {
            let mut t = w.open_table(META)?;
            t.insert("salt", salt.as_slice())?;
            t.insert("verifier", check.as_slice())?;
            t.insert("pwparams", params_bytes.as_slice())?;
        }
        w.commit()?;
        let index = Zeroizing::new(kmac256(master.as_bytes(), b"", LABEL_INDEX));
        Ok(Self {
            db,
            master,
            index,
            salt,
            keystore,
        })
    }

    /// Open an existing store.
    pub fn open(
        path: &Path,
        keystore: Arc<dyn Keystore>,
        passphrase: Option<&[u8]>,
    ) -> Result<Self> {
        let db = Database::open(path)?;
        let (salt, verifier, params, wrapped, pwsalt) = {
            let r = db.begin_read()?;
            let t = r.open_table(META)?;
            let salt: [u8; 32] = t
                .get("salt")?
                .ok_or(StoreError::Malformed)?
                .value()
                .try_into()
                .map_err(|_| StoreError::Malformed)?;
            let verifier = t
                .get("verifier")?
                .ok_or(StoreError::Malformed)?
                .value()
                .to_vec();
            let params = t
                .get("pwparams")?
                .map(|v| v.value().to_vec())
                .unwrap_or_default();
            let wrapped = t.get("wrapped")?.map(|v| v.value().to_vec());
            let pwsalt: Option<[u8; 32]> = t.get("pwsalt")?.and_then(|v| v.value().try_into().ok());
            (salt, verifier, params, wrapped, pwsalt)
        };
        let device_secret = keystore.load(DEVICE_SECRET)?;
        // After a passphrase change the master key is wrapped under a key
        // from the device secret and the new passphrase (with its own salt);
        // before one, it is derived from them directly.
        let pw_salt = match (&wrapped, pwsalt) {
            (Some(_), Some(s)) => s,
            (Some(_), None) => return Err(StoreError::Malformed),
            (None, _) => salt,
        };
        let pw = match (passphrase, decode_params(&params)) {
            (Some(p), Some(params)) => Some(pwhash::derive(p, &pw_salt, params)?),
            (None, None) => None,
            _ => return Err(StoreError::Crypto),
        };
        let kek = derive_master(&device_secret, pw.as_deref());
        let master = match wrapped {
            Some(w) => {
                let raw =
                    Zeroizing::new(seal::open(&kek, WRAP_AD, &w).map_err(|_| StoreError::Crypto)?);
                let key: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Malformed)?;
                SealKey::from_bytes(key)
            }
            None => kek,
        };
        seal::open(&master, b"verifier", &verifier).map_err(|_| StoreError::Crypto)?;
        let index = Zeroizing::new(kmac256(master.as_bytes(), b"", LABEL_INDEX));
        Ok(Self {
            db,
            master,
            index,
            salt,
            keystore,
        })
    }

    fn ns_tag(&self, ns: &str) -> [u8; 8] {
        let t: [u8; 32] = kmac256(&self.index[..], ns.as_bytes(), LABEL_NS);
        let mut o = [0u8; 8];
        o.copy_from_slice(&t[..8]);
        o
    }

    fn blind(&self, ns: &str, key: &[u8]) -> [u8; 40] {
        let mut k = Kmac256::new(&self.index[..], b"enclave/v1/store/blind");
        k.update_framed(ns.as_bytes());
        k.update_framed(key);
        let mut b = [0u8; 32];
        k.finalize_into(&mut b);
        let mut out = [0u8; 40];
        out[..8].copy_from_slice(&self.ns_tag(ns));
        out[8..].copy_from_slice(&b);
        out
    }

    /// Store `value` under `(namespace, key)`.
    pub fn put(&self, ns: &str, key: &[u8], value: &[u8], rng: &mut HedgedRng) -> Result<()> {
        let bk = self.blind(ns, key);
        let rk = seal::record_key(&self.master, &self.salt, &bk);
        // The plaintext key is stored inside the sealed value so scans can
        // return it; the blinded key is the associated data.
        let mut pt = Vec::with_capacity(4 + key.len() + value.len());
        pt.extend_from_slice(&(key.len() as u32).to_be_bytes());
        pt.extend_from_slice(key);
        pt.extend_from_slice(value);
        let sealed = seal_chunked(&rk, &bk, &pt, rng)?;
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(RECORDS)?;
            t.insert(bk.as_slice(), sealed.as_slice())?;
        }
        w.commit()?;
        Ok(())
    }

    /// Load a value.
    pub fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let bk = self.blind(ns, key);
        let r = self.db.begin_read()?;
        let t = match r.open_table(RECORDS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(v) = t.get(bk.as_slice())? else {
            return Ok(None);
        };
        let pt = self.open_record(&bk, v.value())?;
        Ok(Some(pt.1))
    }

    fn open_record(&self, bk: &[u8], sealed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let rk = seal::record_key(&self.master, &self.salt, bk);
        let pt = open_chunked(&rk, bk, sealed)?;
        if pt.len() < 4 {
            return Err(StoreError::Malformed);
        }
        let n = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]) as usize;
        let key = pt.get(4..4 + n).ok_or(StoreError::Malformed)?.to_vec();
        Ok((key, pt[4 + n..].to_vec()))
    }

    /// Delete a record.
    pub fn delete(&self, ns: &str, key: &[u8]) -> Result<()> {
        let bk = self.blind(ns, key);
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(RECORDS)?;
            t.remove(bk.as_slice())?;
        }
        w.commit()?;
        Ok(())
    }

    /// All `(key, value)` pairs in a namespace.
    pub fn scan(&self, ns: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tag = self.ns_tag(ns);
        let mut hi = [0xffu8; 40];
        hi[..8].copy_from_slice(&tag);
        let mut lo = [0u8; 40];
        lo[..8].copy_from_slice(&tag);
        let r = self.db.begin_read()?;
        let t = match r.open_table(RECORDS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for item in t.range(lo.as_slice()..=hi.as_slice())? {
            let (k, v) = item?;
            out.push(self.open_record(k.value(), v.value())?);
        }
        Ok(out)
    }

    /// Set, change or remove the passphrase. The master key (and so every
    /// record) stays the same: it is wrapped under a key from the device
    /// secret and the new passphrase, with a fresh salt, in one transaction.
    pub fn change_passphrase(
        &mut self,
        new: Option<(&[u8], PwParams)>,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let device_secret = self.keystore.load(DEVICE_SECRET)?;
        let pw_salt: [u8; 32] = rng.array("store/pw-salt")?;
        let pw = match new {
            Some((p, params)) => Some(pwhash::derive(p, &pw_salt, params)?),
            None => None,
        };
        let kek = derive_master(&device_secret, pw.as_deref());
        let wrapped = seal::seal(&kek, WRAP_AD, self.master.as_bytes(), rng)?;
        let params = new.map(|(_, p)| encode_params(p)).unwrap_or_default();
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(META)?;
            t.insert("wrapped", wrapped.as_slice())?;
            t.insert("pwsalt", pw_salt.as_slice())?;
            t.insert("pwparams", params.as_slice())?;
        }
        w.commit()?;
        Ok(())
    }

    /// Crypto-erase this profile: destroy the device secret. The database file
    /// becomes unreadable noise. (The emergency PIN and panic wipe call this.)
    /// The hedge secret goes too.
    pub fn crypto_erase(self) -> Result<()> {
        let _ = self.keystore.destroy(crate::keystore::HEDGE_SECRET);
        self.keystore.destroy(DEVICE_SECRET)
    }

    /// The keystore in use.
    pub fn keystore(&self) -> &Arc<dyn Keystore> {
        &self.keystore
    }
}

fn open_db(path: Option<&Path>) -> Result<Database> {
    Ok(match path {
        Some(p) => Database::create(p)?,
        None => Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?,
    })
}

fn encode_params(p: PwParams) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&p.memory_kib.to_be_bytes());
    v.extend_from_slice(&p.iterations.to_be_bytes());
    v.extend_from_slice(&p.parallelism.to_be_bytes());
    v
}

fn decode_params(b: &[u8]) -> Option<PwParams> {
    if b.len() != 12 {
        return None;
    }
    let u = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    Some(PwParams {
        memory_kib: u(0),
        iterations: u(4),
        parallelism: u(8),
    })
}

/// Seal data of any size as 60 KB EnclaveSeal segments.
pub(crate) fn seal_chunked(
    key: &SealKey,
    ad: &[u8],
    pt: &[u8],
    rng: &mut HedgedRng,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(pt.len() + 128);
    let segs: Vec<&[u8]> = if pt.is_empty() {
        vec![&[]]
    } else {
        pt.chunks(60_000).collect()
    };
    for (i, seg) in segs.iter().enumerate() {
        let a = [
            ad,
            &(i as u64).to_be_bytes(),
            &[u8::from(i + 1 == segs.len())],
        ]
        .concat();
        let s = seal::seal(key, &a, seg, rng)?;
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(&s);
    }
    Ok(out)
}

/// Inverse of [`seal_chunked`]. Truncation is detected by the last-segment flag.
pub(crate) fn open_chunked(key: &SealKey, ad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut i = 0u64;
    loop {
        let len_b = sealed.get(off..off + 4).ok_or(StoreError::Malformed)?;
        let n = u32::from_be_bytes([len_b[0], len_b[1], len_b[2], len_b[3]]) as usize;
        off += 4;
        let seg = sealed.get(off..off + n).ok_or(StoreError::Malformed)?;
        off += n;
        let last = off == sealed.len();
        let a = [ad, &i.to_be_bytes(), &[u8::from(last)]].concat();
        out.extend_from_slice(&seal::open(key, &a, seg).map_err(|_| StoreError::Crypto)?);
        if last {
            return Ok(out);
        }
        i += 1;
    }
}
