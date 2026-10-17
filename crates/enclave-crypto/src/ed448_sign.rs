//! Ed448 signing (RFC 8032 §5.2, PureEdDSA with an empty context) in
//! constant time, on fiat-crypto's formally verified p448 field arithmetic
//! (the field X448 uses, `x448_ladder.rs`).
//!
//! ctgrind (`tests/ctgrind.rs`, `ed448_signing_is_constant_time`) found
//! the signing in `ed448-goldilocks` 0.14.0-pre.15 branching on secrets:
//! the field arithmetic of `crypto-bigint` 0.7.5 compiles a doubling's
//! conditional subtraction and a negation's zero test into jumps inside the
//! scalar multiplication, and the secret nonce is reduced with a loop
//! whose branches follow its bits. So signing is done here, and
//! `ed448-goldilocks` keeps only verification, whose inputs are public.
//!
//! * Points are projective `(X : Y : Z)` on `x² + y² = 1 + d·x²·y²`,
//!   `d = −39081`. The addition formula (Bernstein–Lange, "add-2007-bl",
//!   `a = 1`) is complete because `d` is not a square, so doubling is the
//!   same formula and no input is exceptional.
//! * `[k]B` is double-and-add-always over all 448 bits, the add's result
//!   taken or not with fiat-crypto's constant-time select.
//! * Scalars mod ℓ are reduced byte by byte (Horner), each step followed
//!   by eight conditional subtractions of `ℓ·2^j` done with masks; products
//!   are schoolbook on `u128`.
//!
//! Tests: RFC 8032 §7.4's vectors, and the same signatures and public keys
//! as `ed448-goldilocks` (itself checked against OpenSSL in
//! `tests/differential.rs`) on random keys.

use crate::hash::shake256;
use fiat_crypto::p448_solinas_64::{
    fiat_p448_add, fiat_p448_carry, fiat_p448_carry_mul, fiat_p448_carry_square,
    fiat_p448_from_bytes, fiat_p448_loose_field_element as Loose, fiat_p448_relax,
    fiat_p448_selectznz, fiat_p448_sub, fiat_p448_tight_field_element as Tight,
    fiat_p448_to_bytes,
};
use std::hint::black_box;
use zeroize::{Zeroize, Zeroizing};

/// A public key or a point encoding.
pub(crate) const POINT_LEN: usize = 57;
/// A signature.
pub(crate) const SIG_LEN: usize = 114;

/// The base point's coordinates (RFC 8032 §5.2), little-endian.
const BX: [u8; 56] = hex56("5ec00cc72ba826268e93008be1803b431165b62af71aae1264a4d3a324e36dea67170f477065149eda36bf22a6151d22ed0ded6bc670194f");
const BY: [u8; 56] = hex56("14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f69");
/// `d = −39081 mod p`.
const D: [u8; 56] = hex56("5667fffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff");
/// ℓ = 2^446 − 13818066809895115352007386748515426880336692474882178609894547503885,
/// as 64-bit limbs, least significant first.
const L: [u64; 7] = limbs_of(&hex56(
    "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
));

const fn hex56(s: &str) -> [u8; 56] {
    let b = s.as_bytes();
    let mut out = [0u8; 56];
    let mut i = 0;
    while i < 56 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

const fn limbs_of(b: &[u8; 56]) -> [u64; 7] {
    let mut out = [0u64; 7];
    let mut i = 0;
    while i < 56 {
        out[i / 8] |= (b[i] as u64) << (8 * (i % 8));
        i += 1;
    }
    out
}

// ------------------------------------------------------------------ field

fn fe(b: &[u8; 56]) -> Tight {
    let mut t = Tight([0; 8]);
    fiat_p448_from_bytes(&mut t, b);
    t
}

fn relax(t: &Tight) -> Loose {
    let mut l = Loose([0; 8]);
    fiat_p448_relax(&mut l, t);
    l
}

fn carry(l: &Loose) -> Tight {
    let mut t = Tight([0; 8]);
    fiat_p448_carry(&mut t, l);
    t
}

fn add(a: &Tight, b: &Tight) -> Tight {
    let mut l = Loose([0; 8]);
    fiat_p448_add(&mut l, a, b);
    carry(&l)
}

fn sub(a: &Tight, b: &Tight) -> Tight {
    let mut l = Loose([0; 8]);
    fiat_p448_sub(&mut l, a, b);
    carry(&l)
}

fn mul(a: &Tight, b: &Tight) -> Tight {
    let mut t = Tight([0; 8]);
    fiat_p448_carry_mul(&mut t, &relax(a), &relax(b));
    t
}

fn square(a: &Tight) -> Tight {
    let mut t = Tight([0; 8]);
    fiat_p448_carry_square(&mut t, &relax(a));
    t
}

fn square_n(a: &Tight, n: usize) -> Tight {
    let mut r = *a;
    for _ in 0..n {
        r = square(&r);
    }
    r
}

/// `z^(p−2)`, the same chain as `x448_ladder::invert` (the exponent is
/// public).
fn invert(z: &Tight) -> Tight {
    let e1 = *z;
    let e2 = mul(&square_n(&e1, 1), &e1);
    let e3 = mul(&square_n(&e2, 1), &e1);
    let e6 = mul(&square_n(&e3, 3), &e3);
    let e12 = mul(&square_n(&e6, 6), &e6);
    let e24 = mul(&square_n(&e12, 12), &e12);
    let e48 = mul(&square_n(&e24, 24), &e24);
    let e96 = mul(&square_n(&e48, 48), &e48);
    let e192 = mul(&square_n(&e96, 96), &e96);
    let e216 = mul(&square_n(&e192, 24), &e24);
    let e222 = mul(&square_n(&e216, 6), &e6);
    let e223 = mul(&square_n(&e222, 1), &e1);
    let hi = mul(&square_n(&e223, 223), &e222);
    mul(&square_n(&hi, 2), &e1)
}

fn to_bytes(t: &Tight) -> [u8; 56] {
    let mut b = [0u8; 56];
    fiat_p448_to_bytes(&mut b, t);
    b
}

/// `if c == 1 { b } else { a }`, in constant time.
fn select(c: u8, a: &Tight, b: &Tight) -> Tight {
    let mut out = [0u64; 8];
    fiat_p448_selectznz(&mut out, c, &a.0, &b.0);
    Tight(out)
}

// ----------------------------------------------------------------- points

#[derive(Clone, Copy)]
struct Point {
    x: Tight,
    y: Tight,
    z: Tight,
}

impl Point {
    fn identity() -> Self {
        let mut one = [0u8; 56];
        one[0] = 1;
        Self {
            x: Tight([0; 8]),
            y: fe(&one),
            z: fe(&one),
        }
    }

    fn base() -> Self {
        let mut one = [0u8; 56];
        one[0] = 1;
        Self {
            x: fe(&BX),
            y: fe(&BY),
            z: fe(&one),
        }
    }

    /// The complete addition (also the doubling).
    fn add(&self, q: &Point) -> Point {
        let d = fe(&D);
        let a = mul(&self.z, &q.z);
        let b = square(&a);
        let c = mul(&self.x, &q.x);
        let dd = mul(&self.y, &q.y);
        let e = mul(&mul(&d, &c), &dd);
        let f = sub(&b, &e);
        let g = add(&b, &e);
        let h = mul(&add(&self.x, &self.y), &add(&q.x, &q.y));
        Point {
            x: mul(&mul(&a, &f), &sub(&sub(&h, &c), &dd)),
            y: mul(&mul(&a, &g), &sub(&dd, &c)),
            z: mul(&f, &g),
        }
    }

    fn select(c: u8, a: &Point, b: &Point) -> Point {
        Point {
            x: select(c, &a.x, &b.x),
            y: select(c, &a.y, &b.y),
            z: select(c, &a.z, &b.z),
        }
    }

    /// RFC 8032 §5.2.2: y, then the low bit of x in the top bit.
    fn encode(&self) -> [u8; POINT_LEN] {
        let zi = invert(&self.z);
        let x = to_bytes(&mul(&self.x, &zi));
        let y = to_bytes(&mul(&self.y, &zi));
        let mut out = [0u8; POINT_LEN];
        out[..56].copy_from_slice(&y);
        out[56] = (x[0] & 1) << 7;
        out
    }
}

/// `[k]B` for a 448-bit little-endian `k`, every bit the same work.
fn base_mul(k: &[u8; 56]) -> Point {
    let b = Point::base();
    let mut r = Point::identity();
    for i in (0..448).rev() {
        r = r.add(&r);
        let t = r.add(&b);
        let bit = black_box((k[i / 8] >> (i % 8)) & 1);
        r = Point::select(bit, &r, &t);
    }
    r
}

// ---------------------------------------------------------------- scalars

/// `x mod ℓ` for a little-endian `x` of any length, in constant time
/// (the length is public).
fn reduce(x: &[u8]) -> [u64; 7] {
    // acc < ℓ always holds between steps; acc·256 + byte < 2^455 fits 8 limbs.
    let mut acc = [0u64; 8];
    for &byte in x.iter().rev() {
        // acc = acc·256 + byte
        let mut c = u64::from(byte);
        for limb in acc.iter_mut() {
            let v = (u128::from(*limb) << 8) | u128::from(c);
            *limb = v as u64;
            c = (v >> 64) as u64;
        }
        // acc < 256·ℓ: subtract ℓ·2^j where it fits, j = 7 … 0.
        for j in (0..8).rev() {
            let m = shifted_l(j);
            let mut t = [0u64; 8];
            let mut borrow = 0u64;
            for k in 0..8 {
                let v = u128::from(acc[k])
                    .wrapping_sub(u128::from(m[k]))
                    .wrapping_sub(u128::from(borrow));
                t[k] = v as u64;
                borrow = ((v >> 64) as u64) & 1;
            }
            // borrow = 1: acc < ℓ·2^j, keep acc.
            let keep = black_box(borrow).wrapping_neg();
            for k in 0..8 {
                acc[k] = (acc[k] & keep) | (t[k] & !keep);
            }
            t.zeroize();
        }
    }
    let mut out = [0u64; 7];
    out.copy_from_slice(&acc[..7]);
    acc.zeroize();
    out
}

/// ℓ·2^j as 8 limbs (j ≤ 7).
fn shifted_l(j: u32) -> [u64; 8] {
    let mut out = [0u64; 8];
    let mut c = 0u64;
    for k in 0..7 {
        let v = (u128::from(L[k]) << j) | u128::from(c);
        out[k] = v as u64;
        c = (v >> 64) as u64;
    }
    out[7] = c;
    out
}

fn limbs_to_bytes(l: &[u64]) -> Vec<u8> {
    l.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// `(r + k·s) mod ℓ`, as RFC 8032 §5.2.6's S.
fn mul_add(k: &[u64; 7], s: &[u64; 7], r: &[u64; 7]) -> [u8; 57] {
    let mut prod = [0u64; 15];
    for (i, &ki) in k.iter().enumerate() {
        let mut c = 0u128;
        for (j, &sj) in s.iter().enumerate() {
            let v = u128::from(prod[i + j]) + u128::from(ki) * u128::from(sj) + c;
            prod[i + j] = v as u64;
            c = v >> 64;
        }
        // The carry runs to the end whatever its value (no early stop).
        for slot in prod.iter_mut().skip(i + 7) {
            let v = u128::from(*slot) + c;
            *slot = v as u64;
            c = v >> 64;
        }
    }
    let mut c = 0u128;
    for (i, slot) in prod.iter_mut().enumerate() {
        let v = u128::from(*slot) + u128::from(if i < 7 { r[i] } else { 0 }) + c;
        *slot = v as u64;
        c = v >> 64;
    }
    let mut bytes = Zeroizing::new(limbs_to_bytes(&prod));
    prod.zeroize();
    let s = reduce(&bytes);
    bytes.zeroize();
    let mut out = [0u8; 57];
    out[..56].copy_from_slice(&limbs_to_bytes(&s));
    out
}

// -------------------------------------------------------------------- keys

/// "SigEd448" ‖ phflag 0 ‖ context length 0: `dom4(0, "")`.
const DOM4: &[u8] = b"SigEd448\x00\x00";

/// An expanded Ed448 secret key.
pub(crate) struct ExpandedKey {
    /// `s mod ℓ`, `s` the clamped scalar.
    s_mod: Zeroizing<[u64; 7]>,
    /// The second half of SHAKE256(seed), hashed into each nonce.
    prefix: Zeroizing<[u8; 57]>,
    public: [u8; POINT_LEN],
}

impl ExpandedKey {
    /// RFC 8032 §5.2.5 from the 57-byte private key.
    pub(crate) fn from_seed(seed: &[u8; 57]) -> Self {
        let _dit = enclave_platform::dit::Guard::new();
        let h: Zeroizing<[u8; 114]> = Zeroizing::new(shake256(seed));
        let mut s = Zeroizing::new([0u8; 56]);
        s.copy_from_slice(&h[..56]);
        s[0] &= 0xfc;
        s[55] |= 0x80;
        // h[56] is the clamped scalar's 57th byte, set to 0: ignored.
        let mut prefix = Zeroizing::new([0u8; 57]);
        prefix.copy_from_slice(&h[57..]);
        let public = base_mul(&s).encode();
        let s_mod = Zeroizing::new(reduce(&s[..]));
        Self {
            s_mod,
            prefix,
            public,
        }
    }

    /// The public key `[s]B`, encoded.
    pub(crate) fn public(&self) -> [u8; POINT_LEN] {
        self.public
    }

    /// A signature over `msg` (RFC 8032 §5.2.6).
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; SIG_LEN] {
        let _dit = enclave_platform::dit::Guard::new();
        let mut input = Zeroizing::new(Vec::with_capacity(DOM4.len() + 57 + msg.len()));
        input.extend_from_slice(DOM4);
        input.extend_from_slice(&self.prefix[..]);
        input.extend_from_slice(msg);
        let rh: Zeroizing<[u8; 114]> = Zeroizing::new(shake256(&input));
        let r = Zeroizing::new(reduce(&rh[..]));
        let mut r_bytes = Zeroizing::new([0u8; 56]);
        r_bytes.copy_from_slice(&Zeroizing::new(limbs_to_bytes(&r[..])));
        let big_r = base_mul(&r_bytes).encode();
        // k is public: it hashes R, A and the message.
        let mut kin = Vec::with_capacity(DOM4.len() + 2 * POINT_LEN + msg.len());
        kin.extend_from_slice(DOM4);
        kin.extend_from_slice(&big_r);
        kin.extend_from_slice(&self.public);
        kin.extend_from_slice(msg);
        let k = reduce(&shake256::<114>(&kin));
        let s = mul_add(&k, &self.s_mod, &r);
        let mut sig = [0u8; SIG_LEN];
        sig[..POINT_LEN].copy_from_slice(&big_r);
        sig[POINT_LEN..].copy_from_slice(&s);
        sig
    }
}

impl Drop for ExpandedKey {
    fn drop(&mut self) {
        self.public.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.4, "Blank" and "1 octet".
    #[test]
    fn rfc8032_vectors() {
        let cases = [
            (
                "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3
                 528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
                "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778
                 edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
                "",
                "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f
                 2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a
                 9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db
                 b61149f05a7363268c71d95808ff2e652600",
            ),
            (
                "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a
                 fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
                "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086
                 6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
                "03",
                "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435
                 2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb
                 cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f
                 f3348ab21aa4adafd1d234441cf807c03a00",
            ),
        ];
        for (sk, pk, msg, sig) in cases {
            let seed: [u8; 57] = unhex(sk).try_into().unwrap();
            let key = ExpandedKey::from_seed(&seed);
            assert_eq!(key.public().to_vec(), unhex(pk), "public key");
            assert_eq!(key.sign(&unhex(msg)).to_vec(), unhex(sig), "signature");
        }
    }

    /// The same keys and signatures as ed448-goldilocks.
    #[test]
    fn matches_ed448_goldilocks() {
        let mut rng = crate::rng::HedgedRng::new().unwrap();
        for i in 0..8u8 {
            let seed: [u8; 57] = rng.array("test").unwrap();
            let msg = vec![i; usize::from(i) * 37];
            let ours = ExpandedKey::from_seed(&seed);
            let theirs = ed448_goldilocks::SigningKey::try_from(&seed[..]).unwrap();
            assert_eq!(ours.public(), theirs.verifying_key().to_bytes());
            let sig = ours.sign(&msg);
            assert_eq!(sig, theirs.sign_raw(&msg).to_bytes());
            let vk = ed448_goldilocks::VerifyingKey::from_bytes(&ours.public()).unwrap();
            let s = ed448_goldilocks::Signature::try_from(&sig[..]).unwrap();
            assert!(vk.verify_raw(&s, &msg).is_ok());
        }
    }

    #[test]
    fn reduction_matches_the_definition() {
        // ℓ itself and ℓ+5 reduce to 0 and 5; 2^912 − 1 to its residue.
        let mut l = limbs_to_bytes(&L);
        assert_eq!(reduce(&l), [0; 7]);
        l[0] += 5;
        assert_eq!(reduce(&l)[0], 5);
        assert_eq!(reduce(&[0xff; 114]), reduce(&limbs_to_bytes(&reduce(&[0xff; 114]))));
    }
}

/// Under Valgrind (`cargo xtask ctgrind`): key expansion and signing with a
/// poisoned seed reach no branch or address on it. ed448-goldilocks fails
/// this (its scalar multiplication and reduction branch on the scalar),
/// which is why the composite signature signs here.
#[cfg(test)]
mod ctgrind {
    use super::ExpandedKey;
    use enclave_platform::ctgrind;
    use std::hint::black_box;

    #[test]
    #[ignore = "run under Valgrind with `cargo xtask ctgrind`"]
    fn ed448_signing_is_constant_time() {
        assert!(ctgrind::on_valgrind(), "run with `cargo xtask ctgrind`");
        let seed = black_box([0x24u8; 57]);
        let before = ctgrind::errors();
        ctgrind::poison(&seed);
        let key = ExpandedKey::from_seed(&seed);
        let public = key.public();
        // The public key and the signature are public.
        ctgrind::unpoison(black_box(&public));
        let sig = key.sign(b"a message");
        ctgrind::unpoison(black_box(&sig));
        ctgrind::unpoison(&seed);
        assert_eq!(ctgrind::errors() - before, 0, "Ed448 signing depends on the key");
        let theirs = ed448_goldilocks::SigningKey::try_from(&seed[..]).unwrap();
        assert_eq!(sig, theirs.sign_raw(b"a message").to_bytes());
    }
}
