//! Prekey bundles (`docs/04-eqxdh.md`).
//!
//! Each device publishes:
//! * a **signed prekey**: X448 SPK + ML-KEM-1024 PQSPK, 14-day expiry, one
//!   composite signature;
//! * a **batch of one-time prekeys** (X448 + ML-KEM-1024) under a single
//!   composite signature over a Merkle root, so a batch of 100 costs one
//!   signature instead of 100; each served prekey carries its Merkle path;
//! * a **last-resort PQ prekey** (7-day expiry) for when one-time prekeys run out.
//!
//! Every signature also covers the **bundle epoch** of the device's
//! manifest, which the manifest commits to and the prekeys don't carry: a
//! verifier supplies the epoch from the verified manifest, so prekeys signed
//! for another epoch (a directory replaying ones from before the account
//! moved its epoch on) don't verify (RT-05).

use crate::codec::{Reader, Writer};
use crate::error::{ProtoError, Result};
use crate::identity::{DeviceId, DeviceKeys};
use crate::labels;
use enclave_crypto::hash::shake256;
use enclave_crypto::kem::{MLKEM_PK_LEN, MlKemPublic, MlKemSecret, X448Public, X448Secret};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_SIG_LEN, CompositePublic};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Signed-prekey lifetime.
pub const SPK_LIFETIME_SECS: u64 = 14 * 24 * 3600;
/// Last-resort prekey lifetime.
pub const LAST_RESORT_LIFETIME_SECS: u64 = 7 * 24 * 3600;
/// One-time prekeys per batch.
pub const OPK_BATCH: usize = 100;
/// Merkle tree depth for a batch (2^7 = 128 ≥ 100).
pub const MERKLE_DEPTH: usize = 7;

fn merkle_leaf(batch_id: u32, index: u16, x: &X448Public, pq: &[u8; MLKEM_PK_LEN]) -> [u8; 32] {
    let mut w = Writer::new();
    w.u8(0)
        .fixed(labels::MERKLE.as_bytes())
        .u32(batch_id)
        .u16(index)
        .fixed(&x.0)
        .fixed(pq);
    shake256(w.as_slice())
}

fn merkle_empty(index: u16) -> [u8; 32] {
    let mut w = Writer::new();
    w.u8(2).fixed(labels::MERKLE.as_bytes()).u16(index);
    shake256(w.as_slice())
}

fn merkle_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut w = Writer::new();
    w.u8(1).fixed(labels::MERKLE.as_bytes()).fixed(l).fixed(r);
    shake256(w.as_slice())
}

/// Build all tree levels from leaves (padded to 2^MERKLE_DEPTH).
fn merkle_levels(mut leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let width = 1usize << MERKLE_DEPTH;
    for i in leaves.len()..width {
        leaves.push(merkle_empty(i as u16));
    }
    let mut levels = vec![leaves];
    while levels.last().map_or(0, Vec::len) > 1 {
        let prev = levels.last().cloned().unwrap_or_default();
        let next = prev
            .chunks_exact(2)
            .map(|c| merkle_node(&c[0], &c[1]))
            .collect();
        levels.push(next);
    }
    levels
}

fn merkle_verify(leaf: [u8; 32], index: u16, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if path.len() != MERKLE_DEPTH {
        return false;
    }
    let mut h = leaf;
    let mut i = index as usize;
    for sib in path {
        h = if i.is_multiple_of(2) {
            merkle_node(&h, sib)
        } else {
            merkle_node(sib, &h)
        };
        i /= 2;
    }
    &h == root
}

/// Public signed prekey.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedPrekey {
    /// Owning device.
    pub device: DeviceId,
    /// Prekey identifier.
    pub id: u32,
    /// X448 part.
    pub x448: X448Public,
    /// ML-KEM-1024 part.
    pub pq: PqKeyBytes,
    /// Expiry (Unix seconds).
    pub expires_at: u64,
    /// Composite signature by the device key.
    pub signature: Vec<u8>,
}

/// ML-KEM public key bytes (validated on use).
#[derive(Clone, PartialEq, Eq)]
pub struct PqKeyBytes(pub Box<[u8; MLKEM_PK_LEN]>);

impl core::fmt::Debug for PqKeyBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PqKey(..)")
    }
}

impl PqKeyBytes {
    /// Validate and convert.
    pub fn to_key(&self) -> Result<MlKemPublic> {
        Ok(MlKemPublic::from_slice(&self.0[..])?)
    }
}

impl SignedPrekey {
    fn signed_bytes(&self, bundle_epoch: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.device)
            .u32(self.id)
            .fixed(&self.x448.0)
            .fixed(&self.pq.0[..])
            .u64(self.expires_at)
            .u64(bundle_epoch);
        w.finish()
    }

    /// Verify against the device's composite key, the bundle epoch of its
    /// manifest and the current time.
    pub fn verify(&self, signer: &CompositePublic, bundle_epoch: u64, now: u64) -> Result<()> {
        signer
            .verify(
                labels::CTX_SIGNED_PREKEY.as_bytes(),
                &self.signed_bytes(bundle_epoch),
                &self.signature,
            )
            .map_err(|_| ProtoError::BadSignature)?;
        if now > self.expires_at {
            return Err(ProtoError::Expired);
        }
        Ok(())
    }
}

/// Header of a one-time prekey batch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpkBatchHeader {
    /// Owning device.
    pub device: DeviceId,
    /// Batch identifier.
    pub batch_id: u32,
    /// Number of prekeys in the batch.
    pub count: u16,
    /// Merkle root.
    pub root: [u8; 32],
    /// Composite signature by the device key.
    pub signature: Vec<u8>,
}

impl OpkBatchHeader {
    fn signed_bytes(&self, bundle_epoch: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.device)
            .u32(self.batch_id)
            .u16(self.count)
            .fixed(&self.root)
            .u64(bundle_epoch);
        w.finish()
    }

    /// Verify the batch signature for the manifest's bundle epoch.
    pub fn verify(&self, signer: &CompositePublic, bundle_epoch: u64) -> Result<()> {
        signer
            .verify(
                labels::CTX_OPK_BATCH.as_bytes(),
                &self.signed_bytes(bundle_epoch),
                &self.signature,
            )
            .map_err(|_| ProtoError::BadSignature)
    }
}

/// A one-time prekey as served by the directory.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OneTimePrekey {
    /// Batch it belongs to.
    pub batch_id: u32,
    /// Index within the batch.
    pub index: u16,
    /// X448 part.
    pub x448: X448Public,
    /// ML-KEM-1024 part.
    pub pq: PqKeyBytes,
    /// Merkle path to the batch root.
    pub path: Vec<[u8; 32]>,
}

impl OneTimePrekey {
    /// Verify membership in a signed batch.
    pub fn verify(&self, batch: &OpkBatchHeader) -> Result<()> {
        if batch.batch_id != self.batch_id || self.index >= batch.count {
            return Err(ProtoError::BadSignature);
        }
        let leaf = merkle_leaf(self.batch_id, self.index, &self.x448, &self.pq.0);
        if merkle_verify(leaf, self.index, &self.path, &batch.root) {
            Ok(())
        } else {
            Err(ProtoError::BadSignature)
        }
    }

    /// Stable identifier `(batch_id << 16) | index`.
    pub fn id(&self) -> u64 {
        (u64::from(self.batch_id) << 16) | u64::from(self.index)
    }
}

/// Last-resort PQ prekey.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LastResortPrekey {
    /// Owning device.
    pub device: DeviceId,
    /// Identifier.
    pub id: u32,
    /// ML-KEM-1024 key.
    pub pq: PqKeyBytes,
    /// Expiry.
    pub expires_at: u64,
    /// Composite signature.
    pub signature: Vec<u8>,
}

impl LastResortPrekey {
    fn signed_bytes(&self, bundle_epoch: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.device)
            .u32(self.id)
            .fixed(&self.pq.0[..])
            .u64(self.expires_at)
            .u64(bundle_epoch);
        w.finish()
    }

    /// Verify against the device key, the manifest's bundle epoch and the
    /// current time.
    pub fn verify(&self, signer: &CompositePublic, bundle_epoch: u64, now: u64) -> Result<()> {
        signer
            .verify(
                labels::CTX_LAST_RESORT.as_bytes(),
                &self.signed_bytes(bundle_epoch),
                &self.signature,
            )
            .map_err(|_| ProtoError::BadSignature)?;
        if now > self.expires_at {
            return Err(ProtoError::Expired);
        }
        Ok(())
    }
}

/// What a directory hands an initiator for one device.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Bundle {
    /// Signed prekey.
    pub spk: SignedPrekey,
    /// One-time prekey and its batch header, if any remain.
    pub opk: Option<(OpkBatchHeader, OneTimePrekey)>,
    /// Last-resort PQ prekey.
    pub last_resort: LastResortPrekey,
}

impl Bundle {
    /// Verify every part against the device's composite key and the bundle
    /// epoch of the verified manifest that lists the device.
    pub fn verify(&self, signer: &CompositePublic, bundle_epoch: u64, now: u64) -> Result<()> {
        self.spk.verify(signer, bundle_epoch, now)?;
        self.last_resort.verify(signer, bundle_epoch, now)?;
        if let Some((h, o)) = &self.opk {
            h.verify(signer, bundle_epoch)?;
            o.verify(h)?;
            if h.device != self.spk.device {
                return Err(ProtoError::BadSignature);
            }
        }
        if self.last_resort.device != self.spk.device {
            return Err(ProtoError::BadSignature);
        }
        Ok(())
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let s = &self.spk;
        w.fixed(&s.device)
            .u32(s.id)
            .fixed(&s.x448.0)
            .fixed(&s.pq.0[..])
            .u64(s.expires_at)
            .fixed(&s.signature);
        match &self.opk {
            None => {
                w.u8(0);
            }
            Some((h, o)) => {
                w.u8(1)
                    .fixed(&h.device)
                    .u32(h.batch_id)
                    .u16(h.count)
                    .fixed(&h.root)
                    .fixed(&h.signature);
                w.u16(o.index).fixed(&o.x448.0).fixed(&o.pq.0[..]);
                for p in &o.path {
                    w.fixed(p);
                }
            }
        }
        let l = &self.last_resort;
        w.fixed(&l.device)
            .u32(l.id)
            .fixed(&l.pq.0[..])
            .u64(l.expires_at)
            .fixed(&l.signature);
        w.finish()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let pq = |r: &mut Reader<'_>| -> Result<PqKeyBytes> {
            let mut a = Box::new([0u8; MLKEM_PK_LEN]);
            a.copy_from_slice(r.fixed(MLKEM_PK_LEN)?);
            Ok(PqKeyBytes(a))
        };
        let spk = SignedPrekey {
            device: r.array()?,
            id: r.u32()?,
            x448: X448Public(r.array()?),
            pq: pq(&mut r)?,
            expires_at: r.u64()?,
            signature: r.fixed(COMPOSITE_SIG_LEN)?.to_vec(),
        };
        let opk = match r.u8()? {
            0 => None,
            1 => {
                let h = OpkBatchHeader {
                    device: r.array()?,
                    batch_id: r.u32()?,
                    count: r.u16()?,
                    root: r.array()?,
                    signature: r.fixed(COMPOSITE_SIG_LEN)?.to_vec(),
                };
                let index = r.u16()?;
                let x448 = X448Public(r.array()?);
                let pqk = pq(&mut r)?;
                let mut path = Vec::with_capacity(MERKLE_DEPTH);
                for _ in 0..MERKLE_DEPTH {
                    path.push(r.array()?);
                }
                let o = OneTimePrekey {
                    batch_id: h.batch_id,
                    index,
                    x448,
                    pq: pqk,
                    path,
                };
                Some((h, o))
            }
            _ => return Err(ProtoError::Decode),
        };
        let last_resort = LastResortPrekey {
            device: r.array()?,
            id: r.u32()?,
            pq: pq(&mut r)?,
            expires_at: r.u64()?,
            signature: r.fixed(COMPOSITE_SIG_LEN)?.to_vec(),
        };
        r.end()?;
        Ok(Self {
            spk,
            opk,
            last_resort,
        })
    }
}

/// Secret half of one prekey (X448 and/or ML-KEM).
pub struct PrekeySecret {
    /// X448 secret, if the prekey has one.
    pub x448: Option<X448Secret>,
    /// ML-KEM secret.
    pub pq: MlKemSecret,
}

/// A device's prekey secrets, indexed by public identifier.
#[derive(Default)]
pub struct PrekeyStore {
    /// Signed prekeys by id.
    pub signed: BTreeMap<u32, (PrekeySecret, u64)>,
    /// One-time prekeys by `(batch_id << 16) | index`. Deleted on use.
    pub one_time: BTreeMap<u64, PrekeySecret>,
    /// Last-resort prekeys by id.
    pub last_resort: BTreeMap<u32, (PrekeySecret, u64)>,
    next_id: u32,
}

/// Everything a device publishes in one go.
pub struct Publication {
    /// Signed prekey.
    pub spk: SignedPrekey,
    /// Batch header.
    pub batch: OpkBatchHeader,
    /// All one-time prekeys of the batch (the directory serves one per fetch).
    pub opks: Vec<OneTimePrekey>,
    /// Last-resort prekey.
    pub last_resort: LastResortPrekey,
}

impl Publication {
    /// Canonical encoding (what a device uploads to its directory).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let s = &self.spk;
        w.fixed(&s.device)
            .u32(s.id)
            .fixed(&s.x448.0)
            .fixed(&s.pq.0[..])
            .u64(s.expires_at)
            .fixed(&s.signature);
        let h = &self.batch;
        w.fixed(&h.device)
            .u32(h.batch_id)
            .u16(h.count)
            .fixed(&h.root)
            .fixed(&h.signature);
        w.u16(self.opks.len() as u16);
        for o in &self.opks {
            w.u16(o.index).fixed(&o.x448.0).fixed(&o.pq.0[..]);
            for p in &o.path {
                w.fixed(p);
            }
        }
        let l = &self.last_resort;
        w.fixed(&l.device)
            .u32(l.id)
            .fixed(&l.pq.0[..])
            .u64(l.expires_at)
            .fixed(&l.signature);
        w.finish()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let pq = |r: &mut Reader<'_>| -> Result<PqKeyBytes> {
            let mut a = Box::new([0u8; MLKEM_PK_LEN]);
            a.copy_from_slice(r.fixed(MLKEM_PK_LEN)?);
            Ok(PqKeyBytes(a))
        };
        let spk = SignedPrekey {
            device: r.array()?,
            id: r.u32()?,
            x448: X448Public(r.array()?),
            pq: pq(&mut r)?,
            expires_at: r.u64()?,
            signature: r.fixed(COMPOSITE_SIG_LEN)?.to_vec(),
        };
        let batch = OpkBatchHeader {
            device: r.array()?,
            batch_id: r.u32()?,
            count: r.u16()?,
            root: r.array()?,
            signature: r.fixed(COMPOSITE_SIG_LEN)?.to_vec(),
        };
        let n = r.u16()? as usize;
        if n > OPK_BATCH {
            return Err(ProtoError::Limit);
        }
        let mut opks = Vec::with_capacity(n);
        for _ in 0..n {
            let index = r.u16()?;
            let x448 = X448Public(r.array()?);
            let pqk = pq(&mut r)?;
            let mut path = Vec::with_capacity(MERKLE_DEPTH);
            for _ in 0..MERKLE_DEPTH {
                path.push(r.array()?);
            }
            opks.push(OneTimePrekey {
                batch_id: batch.batch_id,
                index,
                x448,
                pq: pqk,
                path,
            });
        }
        let last_resort = LastResortPrekey {
            device: r.array()?,
            id: r.u32()?,
            pq: pq(&mut r)?,
            expires_at: r.u64()?,
            signature: r.fixed(COMPOSITE_SIG_LEN)?.to_vec(),
        };
        r.end()?;
        Ok(Self {
            spk,
            batch,
            opks,
            last_resort,
        })
    }

    /// Verify every part against the device key and the manifest's bundle
    /// epoch.
    pub fn verify(&self, signer: &CompositePublic, bundle_epoch: u64, now: u64) -> Result<()> {
        self.spk.verify(signer, bundle_epoch, now)?;
        self.last_resort.verify(signer, bundle_epoch, now)?;
        self.batch.verify(signer, bundle_epoch)?;
        for o in &self.opks {
            o.verify(&self.batch)?;
        }
        if self.batch.device != self.spk.device || self.last_resort.device != self.spk.device {
            return Err(ProtoError::BadSignature);
        }
        Ok(())
    }
}

fn put_prekey(w: &mut Writer, k: &PrekeySecret) {
    match &k.x448 {
        Some(x) => w.u8(1).fixed(&x.to_bytes()[..]),
        None => w.u8(0),
    };
    w.bytes(k.pq.as_bytes());
}

fn get_prekey(r: &mut Reader<'_>) -> Result<PrekeySecret> {
    let x448 = match r.u8()? {
        0 => None,
        1 => Some(X448Secret::from_bytes(r.array()?)),
        _ => return Err(ProtoError::Decode),
    };
    Ok(PrekeySecret {
        x448,
        pq: MlKemSecret::from_slice(r.bytes(8192)?)?,
    })
}

impl PrekeyStore {
    /// Serialize all prekey secrets for sealed local storage.
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(1).u32(self.next_id);
        w.u32(self.signed.len() as u32);
        for (id, (k, exp)) in &self.signed {
            w.u32(*id).u64(*exp);
            put_prekey(&mut w, k);
        }
        w.u32(self.one_time.len() as u32);
        for (id, k) in &self.one_time {
            w.u64(*id);
            put_prekey(&mut w, k);
        }
        w.u32(self.last_resort.len() as u32);
        for (id, (k, exp)) in &self.last_resort {
            w.u32(*id).u64(*exp);
            put_prekey(&mut w, k);
        }
        Zeroizing::new(w.finish())
    }

    /// Inverse of [`PrekeyStore::export`].
    pub fn import(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let mut s = Self {
            next_id: r.u32()?,
            ..Default::default()
        };
        for _ in 0..r.u32()?.min(4096) {
            let (id, exp) = (r.u32()?, r.u64()?);
            s.signed.insert(id, (get_prekey(&mut r)?, exp));
        }
        for _ in 0..r.u32()?.min(1 << 16) {
            let id = r.u64()?;
            s.one_time.insert(id, get_prekey(&mut r)?);
        }
        for _ in 0..r.u32()?.min(4096) {
            let (id, exp) = (r.u32()?, r.u64()?);
            s.last_resort.insert(id, (get_prekey(&mut r)?, exp));
        }
        r.end()?;
        Ok(s)
    }

    /// Drop signed and last-resort prekeys that expired more than `grace`
    /// seconds ago (late initial messages may still use them until then).
    pub fn expire(&mut self, now: u64, grace: u64) {
        self.signed
            .retain(|_, (_, exp)| exp.saturating_add(grace) > now);
        self.last_resort
            .retain(|_, (_, exp)| exp.saturating_add(grace) > now);
    }
}

impl PrekeyStore {
    fn next(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    /// Generate a fresh signed prekey, one-time batch and last-resort
    /// prekey, signed for `bundle_epoch` (the device's current manifest's).
    pub fn publish(
        &mut self,
        device: &DeviceKeys,
        bundle_epoch: u64,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Publication> {
        // Signed prekey.
        let (x_sk, x_pk) = X448Secret::generate(rng)?;
        let (q_sk, q_pk) = MlKemSecret::generate(rng)?;
        let id = self.next();
        let mut spk = SignedPrekey {
            device: device.id,
            id,
            x448: x_pk,
            pq: PqKeyBytes(q_pk.0.clone()),
            expires_at: now + SPK_LIFETIME_SECS,
            signature: Vec::new(),
        };
        spk.signature = device.signing.sign(
            labels::CTX_SIGNED_PREKEY.as_bytes(),
            &spk.signed_bytes(bundle_epoch),
            rng,
        )?;
        self.signed.insert(
            id,
            (
                PrekeySecret {
                    x448: Some(x_sk),
                    pq: q_sk,
                },
                spk.expires_at,
            ),
        );

        // One-time batch.
        let batch_id = self.next();
        let mut pubs = Vec::with_capacity(OPK_BATCH);
        let mut leaves = Vec::with_capacity(OPK_BATCH);
        for index in 0..OPK_BATCH as u16 {
            let (xs, xp) = X448Secret::generate(rng)?;
            let (qs, qp) = MlKemSecret::generate(rng)?;
            leaves.push(merkle_leaf(batch_id, index, &xp, &qp.0));
            self.one_time.insert(
                (u64::from(batch_id) << 16) | u64::from(index),
                PrekeySecret {
                    x448: Some(xs),
                    pq: qs,
                },
            );
            pubs.push((index, xp, qp));
        }
        let levels = merkle_levels(leaves);
        let root = levels
            .last()
            .and_then(|l| l.first())
            .copied()
            .ok_or(ProtoError::Decode)?;
        let mut batch = OpkBatchHeader {
            device: device.id,
            batch_id,
            count: OPK_BATCH as u16,
            root,
            signature: Vec::new(),
        };
        batch.signature = device.signing.sign(
            labels::CTX_OPK_BATCH.as_bytes(),
            &batch.signed_bytes(bundle_epoch),
            rng,
        )?;
        let opks = pubs
            .into_iter()
            .map(|(index, xp, qp)| {
                let mut path = Vec::with_capacity(MERKLE_DEPTH);
                let mut i = index as usize;
                for level in &levels[..MERKLE_DEPTH] {
                    path.push(level[i ^ 1]);
                    i /= 2;
                }
                OneTimePrekey {
                    batch_id,
                    index,
                    x448: xp,
                    pq: PqKeyBytes(qp.0),
                    path,
                }
            })
            .collect();

        // Last-resort.
        let (lq_sk, lq_pk) = MlKemSecret::generate(rng)?;
        let lid = self.next();
        let mut last_resort = LastResortPrekey {
            device: device.id,
            id: lid,
            pq: PqKeyBytes(lq_pk.0),
            expires_at: now + LAST_RESORT_LIFETIME_SECS,
            signature: Vec::new(),
        };
        last_resort.signature = device.signing.sign(
            labels::CTX_LAST_RESORT.as_bytes(),
            &last_resort.signed_bytes(bundle_epoch),
            rng,
        )?;
        self.last_resort.insert(
            lid,
            (
                PrekeySecret {
                    x448: None,
                    pq: lq_sk,
                },
                last_resort.expires_at,
            ),
        );

        Ok(Publication {
            spk,
            batch,
            opks,
            last_resort,
        })
    }

    /// Delete expired prekeys (keeping a grace period for in-flight messages).
    pub fn prune(&mut self, now: u64, grace: u64) {
        self.signed.retain(|_, (_, exp)| now <= *exp + grace);
        self.last_resort.retain(|_, (_, exp)| now <= *exp + grace);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_verify_and_merkle() {
        let mut rng = HedgedRng::new().unwrap();
        let dev = DeviceKeys::generate(&mut rng).unwrap();
        let mut store = PrekeyStore::default();
        let p = store.publish(&dev, 1, 1_000, &mut rng).unwrap();
        assert_eq!(p.opks.len(), OPK_BATCH);
        for o in [&p.opks[0], &p.opks[57], &p.opks[99]] {
            let b = Bundle {
                spk: p.spk.clone(),
                opk: Some((p.batch.clone(), o.clone())),
                last_resort: p.last_resort.clone(),
            };
            b.verify(dev.signing.public(), 1, 2_000).unwrap();
            let enc = b.encode();
            assert_eq!(Bundle::decode(&enc).unwrap(), b);
        }
        // Path for a different index fails.
        let mut wrong = p.opks[3].clone();
        wrong.index = 4;
        assert!(wrong.verify(&p.batch).is_err());
        // Expired signed prekey fails.
        assert_eq!(
            p.spk
                .verify(dev.signing.public(), 1, 1_000 + SPK_LIFETIME_SECS + 1),
            Err(ProtoError::Expired)
        );
        // Tampered key fails.
        let mut t = p.spk.clone();
        t.x448.0[0] ^= 1;
        assert_eq!(
            t.verify(dev.signing.public(), 1, 2_000),
            Err(ProtoError::BadSignature)
        );
    }
}
