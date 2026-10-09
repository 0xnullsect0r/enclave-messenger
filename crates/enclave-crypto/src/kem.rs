//! Key encapsulation: X448, ML-KEM-1024, Classic McEliece-8192128, and the
//! EnclaveCombine combiner that turns their shared secrets into one key.
//!
//! EnclaveCombine (see `docs/02-cryptography.md`):
//!
//! ```text
//! prk = KMAC256(suite_id, frame(ss_1) ‖ … ‖ frame(ss_n) ‖ frame(psk or 0^32), 512, EXTRACT)
//! th  = SHA3-512(frame(pk/ct/transcript items…) ‖ frame(psk_flag) ‖ frame(suite_id))
//! out = KMAC256(prk, th, 512, COMBINE)
//! ```
//!
//! Every public key and ciphertext is bound through `th`, which is what makes
//! the output IND-CCA secure as long as any one component KEM is (the
//! GHP18 / KitchenSink argument). The 2-KEM and 3-KEM variants use different
//! labels and suite identifiers so a stripped McEliece component can never be
//! confused with a legitimate 2-KEM session.

use crate::error::{Error, Result};
use crate::hash::sha3_512_parts;
use crate::kmac::Kmac256;
use crate::labels;
use crate::rng::HedgedRng;
use enclave_platform::mem::{Locked, Secret, SecretBytes};
use zeroize::Zeroizing;

/// X448 key and shared-secret length.
pub const X448_LEN: usize = 56;
/// ML-KEM-1024 encapsulation key length.
pub const MLKEM_PK_LEN: usize = 1568;
/// ML-KEM-1024 decapsulation key length.
pub const MLKEM_SK_LEN: usize = 3168;
/// ML-KEM-1024 ciphertext length.
pub const MLKEM_CT_LEN: usize = 1568;
/// Classic McEliece-8192128 public key length.
pub const MCELIECE_PK_LEN: usize = classic_mceliece_rust::CRYPTO_PUBLICKEYBYTES;
/// Classic McEliece-8192128 secret key length.
pub const MCELIECE_SK_LEN: usize = classic_mceliece_rust::CRYPTO_SECRETKEYBYTES;
/// Classic McEliece-8192128 ciphertext length.
pub const MCELIECE_CT_LEN: usize = classic_mceliece_rust::CRYPTO_CIPHERTEXTBYTES;
/// Shared-secret length of the post-quantum KEMs.
pub const SS_LEN: usize = 32;
/// Output length of EnclaveCombine.
pub const COMBINED_LEN: usize = 64;

// ---------------------------------------------------------------------------
// X448
// ---------------------------------------------------------------------------

/// X448 secret scalar, in locked memory and zeroized on drop.
#[derive(Clone)]
pub struct X448Secret(Secret<X448_LEN>);

/// X448 public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct X448Public(pub [u8; X448_LEN]);

impl X448Secret {
    /// Generate a key pair.
    pub fn generate(rng: &mut HedgedRng) -> Result<(Self, X448Public)> {
        let sk = Self(Secret::new(rng.array("x448/keygen")?));
        let pk = sk.public();
        Ok((sk, pk))
    }

    /// Rebuild from stored bytes.
    pub fn from_bytes(bytes: [u8; X448_LEN]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Stored form.
    pub fn to_bytes(&self) -> Zeroizing<[u8; X448_LEN]> {
        Zeroizing::new(*self.0)
    }

    /// Public key for this secret.
    pub fn public(&self) -> X448Public {
        let _dit = enclave_platform::dit::Guard::new();
        X448Public(crate::x448_ladder::x448(
            &self.0,
            &crate::x448_ladder::BASEPOINT,
        ))
    }

    /// Diffie-Hellman. Fails on low-order or all-zero results.
    pub fn diffie_hellman(&self, peer: &X448Public) -> Result<Zeroizing<[u8; X448_LEN]>> {
        let _dit = enclave_platform::dit::Guard::new();
        let ss = Zeroizing::new(crate::x448_ladder::x448(&self.0, &peer.0));
        // Constant-time all-zero check (a low-order point gives zero).
        let zero = ss.iter().fold(0u8, |acc, b| acc | b);
        if subtle::ConstantTimeEq::ct_eq(&zero, &0).into() {
            return Err(Error::InvalidKey);
        }
        Ok(ss)
    }
}

// ---------------------------------------------------------------------------
// ML-KEM-1024 (libcrux, formally verified)
// ---------------------------------------------------------------------------

/// ML-KEM-1024 encapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemPublic(pub Box<[u8; MLKEM_PK_LEN]>);

/// ML-KEM-1024 decapsulation key, in locked memory and zeroized on drop.
pub struct MlKemSecret(SecretBytes);

/// ML-KEM-1024 ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemCiphertext(pub Box<[u8; MLKEM_CT_LEN]>);

impl MlKemPublic {
    /// Parse and validate (FIPS 203 modulus check).
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        let arr: [u8; MLKEM_PK_LEN] = b.try_into().map_err(|_| Error::Malformed)?;
        let pk = libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::from(arr);
        if !libcrux_ml_kem::mlkem1024::validate_public_key(&pk) {
            return Err(Error::InvalidKey);
        }
        Ok(Self(Box::new(arr)))
    }
}

impl MlKemCiphertext {
    /// Parse a ciphertext.
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        let arr: [u8; MLKEM_CT_LEN] = b.try_into().map_err(|_| Error::Malformed)?;
        Ok(Self(Box::new(arr)))
    }
}

impl MlKemSecret {
    /// Generate a key pair from hedged randomness.
    pub fn generate(rng: &mut HedgedRng) -> Result<(Self, MlKemPublic)> {
        let seed: Zeroizing<[u8; 64]> = Zeroizing::new(rng.array("mlkem/keygen")?);
        Ok(Self::from_seed(&seed))
    }

    /// Deterministic key generation from the 64-byte FIPS 203 seed `(d, z)`.
    pub fn from_seed(seed: &[u8; 64]) -> (Self, MlKemPublic) {
        let _dit = enclave_platform::dit::Guard::new();
        let kp = libcrux_ml_kem::mlkem1024::generate_key_pair(*seed);
        let (sk, pk) = kp.into_parts();
        let mut sk_arr: [u8; MLKEM_SK_LEN] = sk.into();
        let pk_arr: [u8; MLKEM_PK_LEN] = pk.into();
        let sk_vec = SecretBytes::from_slice(&sk_arr);
        zeroize::Zeroize::zeroize(&mut sk_arr);
        (Self(sk_vec), MlKemPublic(Box::new(pk_arr)))
    }

    /// Rebuild from stored bytes.
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        if b.len() != MLKEM_SK_LEN {
            return Err(Error::Malformed);
        }
        Ok(Self(SecretBytes::from_slice(b)))
    }

    /// Stored form.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decapsulate. ML-KEM uses implicit rejection, so a bad ciphertext yields a
    /// pseudorandom secret rather than an error.
    pub fn decapsulate(&self, ct: &MlKemCiphertext) -> Zeroizing<[u8; SS_LEN]> {
        let _dit = enclave_platform::dit::Guard::new();
        let arr: &[u8; MLKEM_SK_LEN] = match self.0[..].try_into() {
            Ok(a) => a,
            Err(_) => unreachable!("length checked at construction"),
        };
        let sk = libcrux_ml_kem::mlkem1024::MlKem1024PrivateKey::from(arr);
        let c = libcrux_ml_kem::mlkem1024::MlKem1024Ciphertext::from(&*ct.0);
        Zeroizing::new(libcrux_ml_kem::mlkem1024::decapsulate(&sk, &c))
    }
}

impl MlKemPublic {
    /// Encapsulate to this key.
    pub fn encapsulate(
        &self,
        rng: &mut HedgedRng,
    ) -> Result<(MlKemCiphertext, Zeroizing<[u8; SS_LEN]>)> {
        let r: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("mlkem/encaps")?);
        Ok(self.encapsulate_deterministic(&r))
    }

    /// Encapsulate with explicit randomness (for test vectors only).
    pub fn encapsulate_deterministic(
        &self,
        r: &[u8; 32],
    ) -> (MlKemCiphertext, Zeroizing<[u8; SS_LEN]>) {
        let _dit = enclave_platform::dit::Guard::new();
        let pk = libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::from(&*self.0);
        let (ct, ss) = libcrux_ml_kem::mlkem1024::encapsulate(&pk, *r);
        let ct_arr: [u8; MLKEM_CT_LEN] = ct.into();
        (MlKemCiphertext(Box::new(ct_arr)), Zeroizing::new(ss))
    }
}

// ---------------------------------------------------------------------------
// Classic McEliece-8192128
// ---------------------------------------------------------------------------

/// Stack size for McEliece operations. The reference-derived implementation
/// keeps large matrices on the stack.
pub const MCELIECE_STACK: usize = 32 * 1024 * 1024;

fn on_large_stack<T: Send>(f: impl FnOnce() -> T + Send) -> Result<T> {
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .name("enclave-mceliece".into())
            .stack_size(MCELIECE_STACK)
            .spawn_scoped(s, || {
                let _dit = enclave_platform::dit::Guard::new();
                f()
            })
            .map_err(|_| Error::Rng)?
            .join()
            .map_err(|_| Error::Malformed)
    })
}

/// McEliece public key (1,357,824 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct McEliecePublic(pub Box<[u8; MCELIECE_PK_LEN]>);

/// McEliece secret key, in locked memory and zeroized on drop.
pub struct McElieceSecret(SecretBytes);

/// McEliece ciphertext (208 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct McElieceCiphertext(pub [u8; MCELIECE_CT_LEN]);

impl McEliecePublic {
    /// Parse a public key.
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        if b.len() != MCELIECE_PK_LEN {
            return Err(Error::Malformed);
        }
        let mut arr = vec![0u8; MCELIECE_PK_LEN].into_boxed_slice();
        arr.copy_from_slice(b);
        let arr: Box<[u8; MCELIECE_PK_LEN]> = arr.try_into().map_err(|_| Error::Malformed)?;
        Ok(Self(arr))
    }

    /// Encapsulate to this key.
    pub fn encapsulate(
        &self,
        rng: &mut HedgedRng,
    ) -> Result<(McElieceCiphertext, Zeroizing<[u8; SS_LEN]>)> {
        on_large_stack(|| {
            let pk = classic_mceliece_rust::PublicKey::from(self.0.clone());
            let (ct, ss) = classic_mceliece_rust::encapsulate_boxed(&pk, rng);
            (
                McElieceCiphertext(*ct.as_array()),
                Zeroizing::new(*ss.as_array()),
            )
        })
    }
}

impl McElieceSecret {
    /// Generate a key pair. Slow (hundreds of milliseconds to seconds); call
    /// from a background task.
    pub fn generate(rng: &mut HedgedRng) -> Result<(Self, McEliecePublic)> {
        on_large_stack(|| {
            let (pk, sk) = classic_mceliece_rust::keypair_boxed(rng);
            let pk_box: Box<[u8; MCELIECE_PK_LEN]> = Box::new(*pk.as_array());
            let sk_vec = SecretBytes::from_slice(sk.as_array());
            (Self(sk_vec), McEliecePublic(pk_box))
        })
    }

    /// Rebuild from stored bytes.
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        if b.len() != MCELIECE_SK_LEN {
            return Err(Error::Malformed);
        }
        Ok(Self(SecretBytes::from_slice(b)))
    }

    /// Stored form.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decapsulate (implicit rejection).
    pub fn decapsulate(&self, ct: &McElieceCiphertext) -> Result<Zeroizing<[u8; SS_LEN]>> {
        on_large_stack(|| {
            // The library wants the key as a mutable array: a locked copy,
            // zeroized when it goes.
            let mut buf = Locked::new([0u8; MCELIECE_SK_LEN]);
            buf.copy_from_slice(&self.0);
            let sk = classic_mceliece_rust::SecretKey::from(&mut *buf);
            let c = classic_mceliece_rust::Ciphertext::from(ct.0);
            let ss = classic_mceliece_rust::decapsulate_boxed(&c, &sk);
            Zeroizing::new(*ss.as_array())
        })
    }
}

// ---------------------------------------------------------------------------
// EnclaveCombine
// ---------------------------------------------------------------------------

/// Which combiner suite is in use. Bound into every derived key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suite {
    /// X448 + ML-KEM-1024 (before the McEliece braid, or group-only peers).
    TwoKem,
    /// X448 + ML-KEM-1024 + Classic McEliece-8192128.
    ThreeKem,
}

impl Suite {
    /// One-byte identifier used in transcripts.
    pub fn id(self) -> u8 {
        match self {
            Suite::TwoKem => 0x02,
            Suite::ThreeKem => 0x03,
        }
    }

    fn labels(self) -> (&'static str, &'static str) {
        match self {
            Suite::TwoKem => (labels::KEM2_EXTRACT, labels::KEM2_COMBINE),
            Suite::ThreeKem => (labels::KEM_EXTRACT, labels::KEM_COMBINE),
        }
    }
}

/// Combine KEM and DH shared secrets into a 64-byte key.
///
/// * `secrets`: every shared secret, in protocol order.
/// * `public`: every public key, ciphertext and transcript item, in protocol
///   order. For McEliece, pass SHA3-512 of the public key rather than the key.
/// * `psk`: optional 32-byte pre-shared key (in-person QR or invite secret).
pub fn combine(
    suite: Suite,
    secrets: &[&[u8]],
    public: &[&[u8]],
    psk: Option<&[u8; 32]>,
) -> Zeroizing<[u8; COMBINED_LEN]> {
    let (extract_label, combine_label) = suite.labels();
    let suite_key = [b'E', b'N', b'C', b'L', suite.id()];

    let mut prk = Zeroizing::new([0u8; 64]);
    let mut k = Kmac256::new(&suite_key, extract_label.as_bytes());
    for s in secrets {
        k.update_framed(s);
    }
    match psk {
        Some(p) => k.update_framed(p),
        None => k.update_framed(&[0u8; 32]),
    };
    k.finalize_into(&mut prk[..]);

    let psk_flag = [u8::from(psk.is_some())];
    let suite_id = [suite.id()];
    let mut items: Vec<&[u8]> = public.to_vec();
    items.push(&psk_flag);
    items.push(&suite_id);
    let th = sha3_512_parts(&items);

    let mut out = Zeroizing::new([0u8; COMBINED_LEN]);
    let mut k = Kmac256::new(&prk[..], combine_label.as_bytes());
    k.update(&th);
    k.finalize_into(&mut out[..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x448_agreement_and_low_order_rejection() {
        let mut rng = HedgedRng::new().unwrap();
        let (a, ap) = X448Secret::generate(&mut rng).unwrap();
        let (b, bp) = X448Secret::generate(&mut rng).unwrap();
        assert_eq!(
            *a.diffie_hellman(&bp).unwrap(),
            *b.diffie_hellman(&ap).unwrap()
        );
        assert!(a.diffie_hellman(&X448Public([0u8; 56])).is_err());
    }

    #[test]
    fn x448_rfc7748_vector() {
        // RFC 7748 §6.2 Alice's key pair.
        let sk = hex_literal::hex!(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5"
            "74a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        );
        let pk = hex_literal::hex!(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb"
            "c836647241d953d40c5b12da88120d53177f80e532c41fa0"
        );
        assert_eq!(X448Secret::from_bytes(sk).public().0, pk);
    }

    #[test]
    fn mlkem_roundtrip_and_implicit_rejection() {
        let mut rng = HedgedRng::new().unwrap();
        let (sk, pk) = MlKemSecret::generate(&mut rng).unwrap();
        let (ct, ss) = pk.encapsulate(&mut rng).unwrap();
        assert_eq!(*sk.decapsulate(&ct), *ss);
        let mut bad = ct.clone();
        bad.0[0] ^= 1;
        assert_ne!(*sk.decapsulate(&bad), *ss);
        assert!(MlKemPublic::from_slice(&pk.0[..]).is_ok());
        assert!(MlKemPublic::from_slice(&[0xffu8; MLKEM_PK_LEN]).is_err());
    }

    #[test]
    fn mceliece_roundtrip_and_implicit_rejection() {
        let mut rng = HedgedRng::new().unwrap();
        let (sk, pk) = McElieceSecret::generate(&mut rng).unwrap();
        assert_eq!(pk.0.len(), 1_357_824);
        assert_eq!(sk.as_bytes().len(), 14_120);
        let (ct, ss) = pk.encapsulate(&mut rng).unwrap();
        assert_eq!(ct.0.len(), 208);
        assert_eq!(*sk.decapsulate(&ct).unwrap(), *ss);
        let mut bad = ct;
        bad.0[5] ^= 0x10;
        assert_ne!(*sk.decapsulate(&bad).unwrap(), *ss);
        let restored = McElieceSecret::from_slice(sk.as_bytes()).unwrap();
        assert_eq!(*restored.decapsulate(&ct).unwrap(), *ss);
    }

    #[test]
    fn combine_binds_everything() {
        let base = combine(Suite::ThreeKem, &[b"a", b"b", b"c"], &[b"pk", b"ct"], None);
        assert_ne!(
            *base,
            *combine(Suite::TwoKem, &[b"a", b"b", b"c"], &[b"pk", b"ct"], None)
        );
        assert_ne!(
            *base,
            *combine(Suite::ThreeKem, &[b"a", b"b", b"d"], &[b"pk", b"ct"], None)
        );
        assert_ne!(
            *base,
            *combine(Suite::ThreeKem, &[b"a", b"b", b"c"], &[b"pk", b"cu"], None)
        );
        assert_ne!(
            *base,
            *combine(
                Suite::ThreeKem,
                &[b"a", b"b", b"c"],
                &[b"pk", b"ct"],
                Some(&[0u8; 32])
            )
        );
        // Zero PSK and no PSK differ because of psk_flag.
        assert_eq!(
            *base,
            *combine(Suite::ThreeKem, &[b"a", b"b", b"c"], &[b"pk", b"ct"], None)
        );
    }
}
