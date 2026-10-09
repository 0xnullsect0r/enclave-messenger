//! Signatures.
//!
//! * [`CompositeSigningKey`]: Ed448 + ML-DSA-87. Both component signatures
//!   must verify (AND-combiner), so forging needs a break of both. Used for
//!   signed prekeys, On-the-record messages, key-transparency heads and witness
//!   cosignatures.
//! * [`RootSigningKey`]: SLH-DSA-SHAKE-256s, derived deterministically from
//!   the 256-bit recovery secret. Signs only the account manifest, migration and
//!   recovery records, and releases.
//!
//! Composite message representative (pinned at M0, modelled on
//! draft-ietf-lamps-pq-composite-sigs):
//!
//! ```text
//! M' = "CompositeAlgorithmSignatures2025" ‖ "COMPSIG-MLDSA87-Ed448-SHAKE256"
//!      ‖ u8(len(ctx)) ‖ ctx ‖ SHAKE256(M, 64)
//! sig = Ed448.Sign(M') ‖ ML-DSA-87.Sign(M', ctx = "enclave/v1/sig/composite")
//! ```

use crate::error::{Error, Result};
use crate::hash::shake256;
use crate::kmac::Kmac256;
use crate::labels;
use crate::rng::HedgedRng;
use ed448_goldilocks::{
    Signature as EdSignature, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use enclave_platform::mem::{Locked, Secret};
use slh_dsa::{
    Shake256s, Signature as SlhSignature, SigningKey as SlhSigningKey,
    VerifyingKey as SlhVerifyingKey,
};
use zeroize::Zeroizing;

/// Ed448 public key length.
pub const ED448_PK_LEN: usize = 57;
/// Ed448 signature length.
pub const ED448_SIG_LEN: usize = 114;
/// ML-DSA-87 verification key length.
pub const MLDSA_PK_LEN: usize = 2592;
/// ML-DSA-87 signature length.
pub const MLDSA_SIG_LEN: usize = 4627;
/// Composite public key length (Ed448 ‖ ML-DSA-87).
pub const COMPOSITE_PK_LEN: usize = ED448_PK_LEN + MLDSA_PK_LEN;
/// Composite signature length (Ed448 ‖ ML-DSA-87).
pub const COMPOSITE_SIG_LEN: usize = ED448_SIG_LEN + MLDSA_SIG_LEN;
/// Composite secret seed length (Ed448 seed ‖ ML-DSA-87 seed).
pub const COMPOSITE_SEED_LEN: usize = 57 + 32;
/// SLH-DSA-SHAKE-256s public key length.
pub const ROOT_PK_LEN: usize = 64;
/// SLH-DSA-SHAKE-256s signature length.
pub const ROOT_SIG_LEN: usize = 29_792;
/// Maximum context length (FIPS 204/205 limit).
pub const MAX_CTX_LEN: usize = 255;

const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const COMPOSITE_LABEL: &[u8] = b"COMPSIG-MLDSA87-Ed448-SHAKE256";

fn composite_representative(ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    if ctx.len() > MAX_CTX_LEN {
        return Err(Error::TooLarge);
    }
    let ph: [u8; 64] = shake256(msg);
    let mut m =
        Vec::with_capacity(COMPOSITE_PREFIX.len() + COMPOSITE_LABEL.len() + 1 + ctx.len() + 64);
    m.extend_from_slice(COMPOSITE_PREFIX);
    m.extend_from_slice(COMPOSITE_LABEL);
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(&ph);
    Ok(m)
}

/// Composite (Ed448 + ML-DSA-87) public key.
#[derive(Clone, PartialEq, Eq)]
pub struct CompositePublic {
    ed: [u8; ED448_PK_LEN],
    ml: Box<[u8; MLDSA_PK_LEN]>,
}

impl core::fmt::Debug for CompositePublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CompositePublic({:02x?}…)", &self.ed[..8])
    }
}

impl CompositePublic {
    /// Encode as `Ed448 pk ‖ ML-DSA-87 pk` (2,649 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(COMPOSITE_PK_LEN);
        v.extend_from_slice(&self.ed);
        v.extend_from_slice(&self.ml[..]);
        v
    }

    /// Decode and validate the Ed448 point.
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        if b.len() != COMPOSITE_PK_LEN {
            return Err(Error::Malformed);
        }
        let mut ed = [0u8; ED448_PK_LEN];
        ed.copy_from_slice(&b[..ED448_PK_LEN]);
        EdVerifyingKey::from_bytes(&ed).map_err(|_| Error::InvalidKey)?;
        let mut ml = Box::new([0u8; MLDSA_PK_LEN]);
        ml.copy_from_slice(&b[ED448_PK_LEN..]);
        Ok(Self { ed, ml })
    }

    /// Verify a composite signature. Both components must verify.
    pub fn verify(&self, ctx: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() != COMPOSITE_SIG_LEN {
            return Err(Error::Auth);
        }
        let m = composite_representative(ctx, msg)?;
        let ed_vk = EdVerifyingKey::from_bytes(&self.ed).map_err(|_| Error::Auth)?;
        let ed_sig = EdSignature::try_from(&sig[..ED448_SIG_LEN]).map_err(|_| Error::Auth)?;
        let ed_ok = ed_vk.verify_raw(&ed_sig, &m).is_ok();

        let ml_vk = libcrux_ml_dsa::ml_dsa_87::MLDSA87VerificationKey::new(*self.ml);
        let mut ml_sig_arr = [0u8; MLDSA_SIG_LEN];
        ml_sig_arr.copy_from_slice(&sig[ED448_SIG_LEN..]);
        let ml_sig = libcrux_ml_dsa::ml_dsa_87::MLDSA87Signature::new(ml_sig_arr);
        let ml_ok = libcrux_ml_dsa::ml_dsa_87::verify(
            &ml_vk,
            &m,
            labels::SIG_COMPOSITE.as_bytes(),
            &ml_sig,
        )
        .is_ok();
        // Evaluate both before deciding, and never report which one failed.
        if ed_ok & ml_ok {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
}

/// Composite (Ed448 + ML-DSA-87) signing key, stored as its 89-byte seed.
/// The seed and both expanded keys are in locked memory.
pub struct CompositeSigningKey {
    seed: Secret<COMPOSITE_SEED_LEN>,
    ed: Locked<EdSigningKey>,
    ml: Locked<libcrux_ml_dsa::ml_dsa_87::MLDSA87SigningKey>,
    public: CompositePublic,
}

impl CompositeSigningKey {
    /// Generate a fresh key.
    pub fn generate(rng: &mut HedgedRng) -> Result<Self> {
        let seed: Zeroizing<[u8; COMPOSITE_SEED_LEN]> =
            Zeroizing::new(rng.array("sig/composite/keygen")?);
        Self::from_seed(&seed)
    }

    /// Rebuild from the stored seed.
    pub fn from_seed(seed: &[u8; COMPOSITE_SEED_LEN]) -> Result<Self> {
        let _dit = enclave_platform::dit::Guard::new();
        let ed = EdSigningKey::try_from(&seed[..57]).map_err(|_| Error::Malformed)?;
        let mut ml_seed = Zeroizing::new([0u8; 32]);
        ml_seed.copy_from_slice(&seed[57..]);
        let kp = libcrux_ml_dsa::ml_dsa_87::generate_key_pair(*ml_seed);
        let ed_pk: [u8; ED448_PK_LEN] = ed.verifying_key().to_bytes();
        let ml_pk: [u8; MLDSA_PK_LEN] = *kp.verification_key.as_ref();
        Ok(Self {
            seed: Secret::from_ref(seed),
            ed: Locked::new(ed),
            ml: Locked::new(kp.signing_key),
            public: CompositePublic {
                ed: ed_pk,
                ml: Box::new(ml_pk),
            },
        })
    }

    /// The stored seed.
    pub fn seed(&self) -> &[u8; COMPOSITE_SEED_LEN] {
        &self.seed
    }

    /// Public key.
    pub fn public(&self) -> &CompositePublic {
        &self.public
    }

    /// Sign `msg` in context `ctx` (hedged ML-DSA randomness).
    pub fn sign(&self, ctx: &[u8], msg: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>> {
        let _dit = enclave_platform::dit::Guard::new();
        let m = composite_representative(ctx, msg)?;
        let ed_sig = self.ed.sign_raw(&m);
        let r: [u8; 32] = rng.array("sig/composite/sign")?;
        let ml_sig =
            libcrux_ml_dsa::ml_dsa_87::sign(&self.ml, &m, labels::SIG_COMPOSITE.as_bytes(), r)
                .map_err(|_| Error::Malformed)?;
        let mut out = Vec::with_capacity(COMPOSITE_SIG_LEN);
        out.extend_from_slice(&ed_sig.to_bytes());
        out.extend_from_slice(ml_sig.as_ref());
        Ok(out)
    }
}

/// ML-DSA-44 verification key length.
pub const MLDSA44_PK_LEN: usize = 1312;
/// ML-DSA-44 signature length.
pub const MLDSA44_SIG_LEN: usize = 2420;

/// An ML-DSA-44 key, only for the C2SP ML-DSA cosignatures witnesses publish
/// for other transparency tools (`enclave_kt::c2sp`). Nothing in Enclave
/// relies on it; Enclave's own signatures are composite (ML-DSA-87 + Ed448).
pub struct MlDsa44SigningKey {
    sk: Locked<libcrux_ml_dsa::ml_dsa_44::MLDSA44SigningKey>,
    pk: [u8; MLDSA44_PK_LEN],
}

impl MlDsa44SigningKey {
    /// The key from a 32-byte seed (FIPS 204 key generation randomness).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let _dit = enclave_platform::dit::Guard::new();
        let kp = libcrux_ml_dsa::ml_dsa_44::generate_key_pair(*seed);
        Self {
            pk: *kp.verification_key.as_ref(),
            sk: Locked::new(kp.signing_key),
        }
    }

    /// The verification key.
    pub fn public(&self) -> &[u8; MLDSA44_PK_LEN] {
        &self.pk
    }

    /// Sign `msg` with an empty context (hedged randomness).
    pub fn sign(&self, msg: &[u8], rng: &mut HedgedRng) -> Result<[u8; MLDSA44_SIG_LEN]> {
        let _dit = enclave_platform::dit::Guard::new();
        let r: [u8; 32] = rng.array("sig/mldsa44/sign")?;
        let s =
            libcrux_ml_dsa::ml_dsa_44::sign(&self.sk, msg, b"", r).map_err(|_| Error::Malformed)?;
        Ok(*s.as_ref())
    }
}

/// Verify an ML-DSA-44 signature with an empty context.
pub fn mldsa44_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <[u8; MLDSA44_PK_LEN]>::try_from(public),
        <[u8; MLDSA44_SIG_LEN]>::try_from(sig),
    ) else {
        return false;
    };
    libcrux_ml_dsa::ml_dsa_44::verify(
        &libcrux_ml_dsa::ml_dsa_44::MLDSA44VerificationKey::new(pk),
        msg,
        b"",
        &libcrux_ml_dsa::ml_dsa_44::MLDSA44Signature::new(sig),
    )
    .is_ok()
}

/// SLH-DSA-SHAKE-256s root public key (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct RootPublic(pub [u8; ROOT_PK_LEN]);

impl RootPublic {
    /// Verify a root signature (29,792 bytes) over `msg` in context `ctx`.
    pub fn verify(&self, ctx: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() != ROOT_SIG_LEN || ctx.len() > MAX_CTX_LEN {
            return Err(Error::Auth);
        }
        let vk = SlhVerifyingKey::<Shake256s>::try_from(&self.0[..]).map_err(|_| Error::Auth)?;
        let s = SlhSignature::<Shake256s>::try_from(sig).map_err(|_| Error::Auth)?;
        vk.try_verify_with_context(msg, ctx, &s)
            .map_err(|_| Error::Auth)
    }
}

/// SLH-DSA-SHAKE-256s root signing key, derived from the recovery secret,
/// in locked memory.
pub struct RootSigningKey {
    sk: Locked<SlhSigningKey<Shake256s>>,
    public: RootPublic,
}

impl RootSigningKey {
    /// Derive the root key from the 256-bit recovery secret:
    /// `SK.seed ‖ SK.prf ‖ PK.seed = KMAC256(recovery, "", 768, "enclave/v1/root/keygen")`.
    pub fn from_recovery_secret(recovery: &[u8; 32]) -> Self {
        Self::derive(recovery, labels::ROOT_KEYGEN)
    }

    /// Derive an SLH-DSA-SHAKE-256s key from a 256-bit secret under
    /// `label` (`SK.seed ‖ SK.prf ‖ PK.seed = KMAC256(secret, "", 768,
    /// label)`). Account roots use `enclave/v1/root/keygen`; the
    /// foundation's list key uses its own label.
    pub fn derive(secret: &[u8; 32], label: &str) -> Self {
        let _dit = enclave_platform::dit::Guard::new();
        let mut seeds = Zeroizing::new([0u8; 96]);
        Kmac256::new(secret, label.as_bytes()).finalize_into(&mut seeds[..]);
        let sk = SlhSigningKey::<Shake256s>::slh_keygen_internal(
            &seeds[..32],
            &seeds[32..64],
            &seeds[64..],
        );
        let vk: &SlhVerifyingKey<Shake256s> = sk.as_ref();
        let mut pk = [0u8; ROOT_PK_LEN];
        pk.copy_from_slice(&vk.to_bytes());
        Self {
            sk: Locked::new(sk),
            public: RootPublic(pk),
        }
    }

    /// Public key.
    pub fn public(&self) -> RootPublic {
        self.public
    }

    /// Sign (hedged: fresh randomness per FIPS 205 §10.2). Slow: expect about a
    /// second on a desktop and several on a phone. Call from a background task.
    pub fn sign(&self, ctx: &[u8], msg: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>> {
        let _dit = enclave_platform::dit::Guard::new();
        if ctx.len() > MAX_CTX_LEN {
            return Err(Error::TooLarge);
        }
        let r: [u8; 32] = rng.array("sig/root/sign")?;
        let s = self
            .sk
            .try_sign_with_context(msg, ctx, Some(&r))
            .map_err(|_| Error::Malformed)?;
        Ok(s.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_sign_verify() {
        let mut rng = HedgedRng::new().unwrap();
        let k = CompositeSigningKey::generate(&mut rng).unwrap();
        let sig = k.sign(b"prekey", b"hello", &mut rng).unwrap();
        assert_eq!(sig.len(), COMPOSITE_SIG_LEN);
        let pk = CompositePublic::from_slice(&k.public().to_bytes()).unwrap();
        pk.verify(b"prekey", b"hello", &sig).unwrap();
        assert!(pk.verify(b"prekey", b"hellp", &sig).is_err());
        assert!(pk.verify(b"prekez", b"hello", &sig).is_err());
    }

    #[test]
    fn composite_needs_both_components() {
        let mut rng = HedgedRng::new().unwrap();
        let k = CompositeSigningKey::generate(&mut rng).unwrap();
        let other = CompositeSigningKey::generate(&mut rng).unwrap();
        let sig = k.sign(b"c", b"m", &mut rng).unwrap();
        let sig2 = other.sign(b"c", b"m", &mut rng).unwrap();
        // Valid Ed448 half + foreign ML-DSA half, and the reverse.
        let mut mix1 = sig[..ED448_SIG_LEN].to_vec();
        mix1.extend_from_slice(&sig2[ED448_SIG_LEN..]);
        let mut mix2 = sig2[..ED448_SIG_LEN].to_vec();
        mix2.extend_from_slice(&sig[ED448_SIG_LEN..]);
        assert!(k.public().verify(b"c", b"m", &mix1).is_err());
        assert!(k.public().verify(b"c", b"m", &mix2).is_err());
    }

    #[test]
    fn composite_seed_roundtrip() {
        let mut rng = HedgedRng::new().unwrap();
        let k = CompositeSigningKey::generate(&mut rng).unwrap();
        let k2 = CompositeSigningKey::from_seed(k.seed()).unwrap();
        assert_eq!(k.public(), k2.public());
    }

    #[test]
    fn root_is_deterministic_and_verifies() {
        let mut rng = HedgedRng::new().unwrap();
        let a = RootSigningKey::from_recovery_secret(&[42u8; 32]);
        let b = RootSigningKey::from_recovery_secret(&[42u8; 32]);
        assert_eq!(a.public(), b.public());
        assert_ne!(
            a.public(),
            RootSigningKey::from_recovery_secret(&[43u8; 32]).public()
        );
        let sig = a.sign(b"manifest", b"device list v1", &mut rng).unwrap();
        assert_eq!(sig.len(), ROOT_SIG_LEN);
        a.public()
            .verify(b"manifest", b"device list v1", &sig)
            .unwrap();
        assert!(
            a.public()
                .verify(b"manifest", b"device list v2", &sig)
                .is_err()
        );
        assert!(
            a.public()
                .verify(b"other", b"device list v1", &sig)
                .is_err()
        );
    }
}
