//! HQC-256 (FIPS 207 initial public draft), the code-based KEM NIST chose
//! as the second post-quantum KEM next to ML-KEM: a fourth input to
//! EnclaveCombine ([`crate::kem::Suite::FourKem`]) for when a structural
//! break of lattices *and* of Goppa codes is the worry.
//!
//! Behind the `hqc` feature and used by no protocol yet: it is switched on
//! when FIPS 207 is final (External Gate G12), since the draft's encoding
//! can still change. Implementation: RustCrypto's `hqc-kem`, checked here
//! against the official known-answer vectors (`tests/hqc.rs`).

use crate::error::{Error, Result};
use crate::rng::HedgedRng;
use enclave_platform::mem::SecretBytes;
use hqc_kem::hqc256;
use zeroize::Zeroizing;

/// Public key length.
pub const HQC_PK_LEN: usize = 7_237;
/// Secret key length.
pub const HQC_SK_LEN: usize = 7_333;
/// Ciphertext length.
pub const HQC_CT_LEN: usize = 14_421;
/// Shared secret length.
pub const HQC_SS_LEN: usize = 32;

/// An HQC-256 public (encapsulation) key.
#[derive(Clone, PartialEq, Eq)]
pub struct HqcPublic(pub Vec<u8>);

/// An HQC-256 secret (decapsulation) key, in locked memory.
pub struct HqcSecret(SecretBytes);

/// An HQC-256 ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct HqcCiphertext(pub Vec<u8>);

impl HqcSecret {
    /// A fresh key pair.
    pub fn generate(rng: &mut HedgedRng) -> Result<(Self, HqcPublic)> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("hqc/keygen")?);
        Ok(Self::from_seed(&seed))
    }

    /// The key pair FIPS 207 derives from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> (Self, HqcPublic) {
        let _dit = enclave_platform::dit::Guard::new();
        let (ek, dk) = hqc256::generate_key_deterministic(seed);
        (
            Self(SecretBytes::from_slice(dk.as_ref())),
            HqcPublic(ek.as_ref().to_vec()),
        )
    }

    /// A stored secret key.
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        if b.len() != HQC_SK_LEN {
            return Err(Error::InvalidKey);
        }
        Ok(Self(SecretBytes::from_slice(b)))
    }

    /// The raw key, for storing it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decapsulate (implicit rejection: a bad ciphertext gives a
    /// pseudorandom secret, not an error).
    pub fn decapsulate(&self, ct: &HqcCiphertext) -> Result<Zeroizing<[u8; HQC_SS_LEN]>> {
        let _dit = enclave_platform::dit::Guard::new();
        let dk = hqc256::DecapsulationKey::try_from(&self.0[..]).map_err(|_| Error::InvalidKey)?;
        let c = hqc256::Ciphertext::try_from(&ct.0[..]).map_err(|_| Error::Malformed)?;
        let ss = dk.decapsulate(&c);
        let mut out = Zeroizing::new([0u8; HQC_SS_LEN]);
        out.copy_from_slice(ss.as_ref());
        Ok(out)
    }
}

impl HqcPublic {
    /// A public key received from someone (its length checked).
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        hqc256::EncapsulationKey::try_from(b).map_err(|_| Error::InvalidKey)?;
        Ok(Self(b.to_vec()))
    }

    /// Encapsulate to this key.
    pub fn encapsulate(
        &self,
        rng: &mut HedgedRng,
    ) -> Result<(HqcCiphertext, Zeroizing<[u8; HQC_SS_LEN]>)> {
        let m: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("hqc/encaps")?);
        let salt: [u8; 16] = rng.array("hqc/salt")?;
        self.encapsulate_deterministic(&m, &salt)
    }

    /// Encapsulate with explicit randomness (known-answer tests only).
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; 32],
        salt: &[u8; 16],
    ) -> Result<(HqcCiphertext, Zeroizing<[u8; HQC_SS_LEN]>)> {
        let _dit = enclave_platform::dit::Guard::new();
        let ek = hqc256::EncapsulationKey::try_from(&self.0[..]).map_err(|_| Error::InvalidKey)?;
        let (ct, ss) = ek
            .encapsulate_deterministic(m, salt)
            .map_err(|_| Error::Malformed)?;
        let mut out = Zeroizing::new([0u8; HQC_SS_LEN]);
        out.copy_from_slice(ss.as_ref());
        Ok((HqcCiphertext(ct.as_ref().to_vec()), out))
    }
}

impl HqcCiphertext {
    /// A received ciphertext (its length checked).
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        if b.len() != HQC_CT_LEN {
            return Err(Error::Malformed);
        }
        Ok(Self(b.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_round_trip_and_implicit_rejection() {
        let mut rng = HedgedRng::new().unwrap();
        let (sk, pk) = HqcSecret::generate(&mut rng).unwrap();
        assert_eq!(pk.0.len(), HQC_PK_LEN);
        assert_eq!(sk.as_bytes().len(), HQC_SK_LEN);
        let (ct, ss) = pk.encapsulate(&mut rng).unwrap();
        assert_eq!(ct.0.len(), HQC_CT_LEN);
        assert_eq!(*sk.decapsulate(&ct).unwrap(), *ss);
        let mut bad = ct.clone();
        bad.0[9] ^= 1;
        assert_ne!(*sk.decapsulate(&bad).unwrap(), *ss);
        assert!(HqcCiphertext::from_slice(&ct.0[1..]).is_err());
        assert!(HqcPublic::from_slice(&pk.0[1..]).is_err());
    }
}
