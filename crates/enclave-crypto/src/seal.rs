//! EnclaveSeal-v1: a two-cipher cascade with a separate KMAC256 tag.
//!
//! ```text
//! r      <- hedged random 32 bytes
//! N      = KMAC256(K, frame(r) ‖ frame(AD) ‖ SHA3-512(P), 256, "enclave/v1/seal/nonce")
//! k_x ‖ k_a ‖ k_m ‖ n_x ‖ iv_a
//!        = KMAC256(K, N, 1088, "enclave/v1/seal/keys")        (32+32+32+24+16 bytes)
//! C      = AES-256-CTR(k_a, iv_a) ⊕ XChaCha20(k_x, n_x) ⊕ P
//! T      = KMAC256(k_m, frame(AD) ‖ N ‖ C, 256, "enclave/v1/seal/tag")
//! output = N ‖ C ‖ T
//! ```
//!
//! Properties (proved in `docs/02-cryptography.md`, checked by tests here):
//! * Confidentiality holds if either XChaCha20 or AES-256 is a secure stream
//!   cipher (independent subkeys, XOR of keystreams).
//! * Integrity rests on KMAC256 as a PRF; the tag is checked in constant time
//!   before any keystream is generated.
//! * Key-committing: the tag key is a KMAC of `K`, so one ciphertext cannot
//!   verify under two keys without a KMAC collision.
//! * Hedged nonce: reusing `K` (for example after a state rollback) only repeats
//!   a keystream if the randomness, the associated data and the plaintext all
//!   repeat, in which case the ciphertext is identical and reveals nothing new.

use crate::error::{Error, Result};
use crate::hash::sha3_512;
use crate::kmac::{Kmac256, kmac256};
use crate::labels;
use crate::rng::HedgedRng;
use aes::Aes256;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use enclave_platform::mem::Secret;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Seal key length.
pub const KEY_LEN: usize = 32;
/// Nonce length at the front of every sealed object.
pub const NONCE_LEN: usize = 32;
/// Tag length at the end of every sealed object.
pub const TAG_LEN: usize = 32;
/// Total bytes added by sealing.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;
/// Largest plaintext accepted in one seal. Larger data is chunked by callers.
pub const MAX_PLAINTEXT: usize = 64 * 1024;

const SUBKEY_LEN: usize = 32 + 32 + 32 + 24 + 16;

/// A 256-bit EnclaveSeal key, in locked memory and zeroized on drop.
#[derive(Clone)]
pub struct SealKey(Secret<KEY_LEN>);

impl SealKey {
    /// Wrap raw key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Generate a fresh random key.
    pub fn generate(rng: &mut HedgedRng) -> Result<Self> {
        Ok(Self::from_bytes(rng.array("seal/key")?))
    }

    /// Borrow the raw key.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

struct Subkeys {
    k_x: [u8; 32],
    k_a: [u8; 32],
    k_m: [u8; 32],
    n_x: [u8; 24],
    iv_a: [u8; 16],
}

impl Drop for Subkeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k_x.zeroize();
        self.k_a.zeroize();
        self.k_m.zeroize();
    }
}

fn subkeys(key: &SealKey, nonce: &[u8; NONCE_LEN]) -> Subkeys {
    let mut buf = Zeroizing::new([0u8; SUBKEY_LEN]);
    let mut k = Kmac256::new(key.as_bytes(), labels::SEAL_KEYS.as_bytes());
    k.update(nonce);
    k.finalize_into(&mut buf[..]);
    let mut s = Subkeys {
        k_x: [0; 32],
        k_a: [0; 32],
        k_m: [0; 32],
        n_x: [0; 24],
        iv_a: [0; 16],
    };
    s.k_x.copy_from_slice(&buf[0..32]);
    s.k_a.copy_from_slice(&buf[32..64]);
    s.k_m.copy_from_slice(&buf[64..96]);
    s.n_x.copy_from_slice(&buf[96..120]);
    s.iv_a.copy_from_slice(&buf[120..136]);
    s
}

fn tag(k_m: &[u8; 32], ad: &[u8], nonce: &[u8; NONCE_LEN], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut out = [0u8; TAG_LEN];
    let mut k = Kmac256::new(k_m, labels::SEAL_TAG.as_bytes());
    k.update_framed(ad);
    k.update(nonce);
    k.update_framed(ct);
    k.finalize_into(&mut out);
    out
}

fn apply_keystreams(s: &Subkeys, data: &mut [u8]) {
    let mut x = XChaCha20::new(&s.k_x.into(), &s.n_x.into());
    x.apply_keystream(data);
    let mut a = Aes256Ctr::new(&s.k_a.into(), &s.iv_a.into());
    a.apply_keystream(data);
}

/// Derive the hedged nonce.
fn hedged_nonce(key: &SealKey, rand: &[u8; 32], ad: &[u8], pt: &[u8]) -> [u8; NONCE_LEN] {
    let digest = sha3_512(pt);
    let mut k = Kmac256::new(key.as_bytes(), labels::SEAL_NONCE.as_bytes());
    k.update_framed(rand);
    k.update_framed(ad);
    k.update(&digest);
    let mut out = [0u8; NONCE_LEN];
    k.finalize_into(&mut out);
    out
}

/// Seal `pt` under `key` with associated data `ad`, writing `N ‖ C ‖ T`.
pub fn seal(key: &SealKey, ad: &[u8], pt: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>> {
    let rand: [u8; 32] = rng.array("seal/nonce")?;
    seal_with_randomness(key, ad, pt, &rand)
}

/// Seal with caller-supplied nonce randomness. Exposed for test vectors and for
/// callers that must be deterministic given their inputs; the hedging still
/// binds the plaintext and associated data.
pub fn seal_with_randomness(
    key: &SealKey,
    ad: &[u8],
    pt: &[u8],
    rand: &[u8; 32],
) -> Result<Vec<u8>> {
    if pt.len() > MAX_PLAINTEXT {
        return Err(Error::TooLarge);
    }
    let _dit = enclave_platform::dit::Guard::new();
    let nonce = hedged_nonce(key, rand, ad, pt);
    let s = subkeys(key, &nonce);
    let mut out = Vec::with_capacity(pt.len() + OVERHEAD);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(pt);
    apply_keystreams(&s, &mut out[NONCE_LEN..]);
    let t = tag(&s.k_m, ad, &nonce, &out[NONCE_LEN..]);
    out.extend_from_slice(&t);
    Ok(out)
}

/// Open a sealed object. Returns the plaintext or [`Error::Auth`].
pub fn open(key: &SealKey, ad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < OVERHEAD {
        return Err(Error::Auth);
    }
    if sealed.len() - OVERHEAD > MAX_PLAINTEXT {
        return Err(Error::TooLarge);
    }
    let _dit = enclave_platform::dit::Guard::new();
    let (nonce_bytes, rest) = sealed.split_at(NONCE_LEN);
    let (ct, t) = rest.split_at(rest.len() - TAG_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);
    let s = subkeys(key, &nonce);
    let expect = tag(&s.k_m, ad, &nonce, ct);
    if !bool::from(expect.ct_eq(t)) {
        return Err(Error::Auth);
    }
    let mut pt = ct.to_vec();
    apply_keystreams(&s, &mut pt);
    Ok(pt)
}

/// Seal without transmitting a nonce ("compact" form): output is `C ‖ T`.
///
/// The nonce is `KMAC256(K, frame(nonce_material) ‖ frame(AD), 256, NONCE label)`,
/// so `nonce_material` must never repeat under one key with different plaintext.
/// Callers pass a value that is unique per message *and* depends on the content
/// (for example a ratchet lookup tag plus the hash of the sealed body), which keeps
/// the hedging property: a rolled-back state that reuses the counter with other
/// content gets a different keystream. Used for device slots and PQ slots, where
/// every byte counts.
pub fn seal_compact(key: &SealKey, nonce_material: &[u8], ad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let _dit = enclave_platform::dit::Guard::new();
    if pt.len() > MAX_PLAINTEXT {
        return Err(Error::TooLarge);
    }
    let nonce = compact_nonce(key, nonce_material, ad);
    let s = subkeys(key, &nonce);
    let mut out = Vec::with_capacity(pt.len() + TAG_LEN);
    out.extend_from_slice(pt);
    apply_keystreams(&s, &mut out);
    let t = tag(&s.k_m, ad, &nonce, &out);
    out.extend_from_slice(&t);
    Ok(out)
}

/// Open a compact seal produced by [`seal_compact`].
pub fn open_compact(
    key: &SealKey,
    nonce_material: &[u8],
    ad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let _dit = enclave_platform::dit::Guard::new();
    if sealed.len() < TAG_LEN || sealed.len() - TAG_LEN > MAX_PLAINTEXT {
        return Err(Error::Auth);
    }
    let (ct, t) = sealed.split_at(sealed.len() - TAG_LEN);
    let nonce = compact_nonce(key, nonce_material, ad);
    let s = subkeys(key, &nonce);
    let expect = tag(&s.k_m, ad, &nonce, ct);
    if !bool::from(expect.ct_eq(t)) {
        return Err(Error::Auth);
    }
    let mut pt = ct.to_vec();
    apply_keystreams(&s, &mut pt);
    Ok(pt)
}

fn compact_nonce(key: &SealKey, nonce_material: &[u8], ad: &[u8]) -> [u8; NONCE_LEN] {
    let mut k = Kmac256::new(key.as_bytes(), labels::SEAL_NONCE.as_bytes());
    k.update_framed(b"compact");
    k.update_framed(nonce_material);
    k.update_framed(ad);
    let mut out = [0u8; NONCE_LEN];
    k.finalize_into(&mut out);
    out
}

/// Derive a per-record storage key: `KMAC256(master, frame(salt) ‖ frame(id))`.
pub fn record_key(master: &SealKey, salt: &[u8], record_id: &[u8]) -> SealKey {
    let mut k = Kmac256::new(master.as_bytes(), labels::STORE_RECORD.as_bytes());
    k.update_framed(salt);
    k.update_framed(record_id);
    let mut out = [0u8; KEY_LEN];
    k.finalize_into(&mut out);
    SealKey::from_bytes(out)
}

/// Derive a subkey from any 32-byte secret under a registered label.
pub fn derive_key(secret: &[u8], context: &[u8], label: &str) -> SealKey {
    let mut out: [u8; KEY_LEN] = kmac256(secret, context, label);
    let k = SealKey::from_bytes(out);
    use zeroize::Zeroize;
    out.zeroize();
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SealKey {
        SealKey::from_bytes([b; 32])
    }

    #[test]
    fn roundtrip() {
        let mut rng = HedgedRng::new().unwrap();
        let k = key(1);
        for len in [0usize, 1, 31, 32, 33, 1000, MAX_PLAINTEXT] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let c = seal(&k, b"ad", &pt, &mut rng).unwrap();
            assert_eq!(c.len(), len + OVERHEAD);
            assert_eq!(open(&k, b"ad", &c).unwrap(), pt);
        }
    }

    #[test]
    fn too_large_rejected() {
        let mut rng = HedgedRng::new().unwrap();
        let pt = vec![0u8; MAX_PLAINTEXT + 1];
        assert_eq!(seal(&key(1), b"", &pt, &mut rng), Err(Error::TooLarge));
    }

    #[test]
    fn every_bit_flip_rejected() {
        let k = key(2);
        let c = seal_with_randomness(&k, b"ad", b"hello enclave", &[9; 32]).unwrap();
        for i in 0..c.len() {
            for bit in 0..8 {
                let mut m = c.clone();
                m[i] ^= 1 << bit;
                assert_eq!(open(&k, b"ad", &m), Err(Error::Auth), "byte {i} bit {bit}");
            }
        }
    }

    #[test]
    fn wrong_ad_or_key_rejected() {
        let c = seal_with_randomness(&key(3), b"ad", b"x", &[1; 32]).unwrap();
        assert_eq!(open(&key(3), b"ae", &c), Err(Error::Auth));
        assert_eq!(open(&key(4), b"ad", &c), Err(Error::Auth));
        assert_eq!(open(&key(3), b"ad", &c[..10]), Err(Error::Auth));
    }

    #[test]
    fn hedging_same_key_same_randomness_different_plaintext() {
        // Simulated rollback: same key and same randomness, different plaintext.
        // Nonces (and therefore keystreams) must differ.
        let k = key(5);
        let a = seal_with_randomness(&k, b"", &[0u8; 64], &[7; 32]).unwrap();
        let b = seal_with_randomness(&k, b"", &[1u8; 64], &[7; 32]).unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        // XOR of the two ciphertexts must not equal XOR of the plaintexts.
        let xor_ct: Vec<u8> = a[NONCE_LEN..NONCE_LEN + 64]
            .iter()
            .zip(&b[NONCE_LEN..NONCE_LEN + 64])
            .map(|(x, y)| x ^ y)
            .collect();
        assert_ne!(xor_ct, vec![1u8; 64]);
    }

    #[test]
    fn identical_inputs_give_identical_output() {
        let k = key(6);
        let a = seal_with_randomness(&k, b"a", b"m", &[3; 32]).unwrap();
        let b = seal_with_randomness(&k, b"a", b"m", &[3; 32]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn compact_roundtrip_and_tamper() {
        let k = key(9);
        let c = seal_compact(&k, b"tag-1", b"ad", b"device slot").unwrap();
        assert_eq!(c.len(), 11 + TAG_LEN);
        assert_eq!(
            open_compact(&k, b"tag-1", b"ad", &c).unwrap(),
            b"device slot"
        );
        assert_eq!(open_compact(&k, b"tag-2", b"ad", &c), Err(Error::Auth));
        assert_eq!(open_compact(&k, b"tag-1", b"ae", &c), Err(Error::Auth));
        let mut m = c.clone();
        m[0] ^= 1;
        assert_eq!(open_compact(&k, b"tag-1", b"ad", &m), Err(Error::Auth));
    }

    #[test]
    fn record_keys_are_distinct() {
        let m = key(8);
        let a = record_key(&m, b"salt", b"1");
        let b = record_key(&m, b"salt", b"2");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
