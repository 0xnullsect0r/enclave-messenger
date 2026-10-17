//! X448 (RFC 7748 §5) on fiat-crypto's formally verified p448 field
//! arithmetic (`p448_solinas_64`, generated from Coq proofs).
//!
//! The `x448` crate computes the same function on generic Montgomery
//! big-integer arithmetic, about eight times slower; every server request
//! does one X448, so that cost is most of a request's. This module is only
//! the RFC's Montgomery ladder: field operations are fiat-crypto's, the
//! conditional swap is fiat-crypto's constant-time select, and the ladder
//! runs all 448 steps whatever the scalar. Tests check it against the RFC's
//! vectors (including the 1,000-iteration one) and against the `x448`
//! crate on random inputs.

use fiat_crypto::p448_solinas_64::{
    fiat_p448_add, fiat_p448_carry_mul, fiat_p448_carry_square, fiat_p448_from_bytes,
    fiat_p448_loose_field_element as Loose, fiat_p448_relax, fiat_p448_selectznz, fiat_p448_sub,
    fiat_p448_tight_field_element as Tight, fiat_p448_to_bytes,
};
use zeroize::Zeroize;

/// The u-coordinate of the base point (5).
pub(crate) const BASEPOINT: [u8; 56] = {
    let mut b = [0u8; 56];
    b[0] = 5;
    b
};

fn from_bytes(b: &[u8; 56]) -> Tight {
    let mut t = Tight([0; 8]);
    fiat_p448_from_bytes(&mut t, b);
    t
}

fn loose(t: &Tight) -> Loose {
    let mut l = Loose([0; 8]);
    fiat_p448_relax(&mut l, t);
    l
}

/// `a + b`, not carried: fine as an input to a multiplication.
fn add(a: &Tight, b: &Tight) -> Loose {
    let mut l = Loose([0; 8]);
    fiat_p448_add(&mut l, a, b);
    l
}

/// `a − b`, not carried.
fn sub(a: &Tight, b: &Tight) -> Loose {
    let mut l = Loose([0; 8]);
    fiat_p448_sub(&mut l, a, b);
    l
}

fn mul(a: &Loose, b: &Loose) -> Tight {
    let mut t = Tight([0; 8]);
    fiat_p448_carry_mul(&mut t, a, b);
    t
}

fn square(a: &Loose) -> Tight {
    let mut t = Tight([0; 8]);
    fiat_p448_carry_square(&mut t, a);
    t
}

/// `a^(2^n)`.
fn square_n(a: &Tight, n: usize) -> Tight {
    let mut r = *a;
    for _ in 0..n {
        r = square(&loose(&r));
    }
    r
}

/// Swap `a` and `b` if `swap` is 1, in constant time.
fn cswap(swap: u8, a: &mut Tight, b: &mut Tight) {
    let (mut x, mut y) = ([0u64; 8], [0u64; 8]);
    fiat_p448_selectznz(&mut x, swap, &a.0, &b.0);
    fiat_p448_selectznz(&mut y, swap, &b.0, &a.0);
    a.0 = x;
    b.0 = y;
    x.zeroize();
    y.zeroize();
}

/// `z^(p−2)`: the inverse of `z` (0 for 0), with
/// `p − 2 = 2^448 − 2^224 − 3 = (2^223 − 1)·2^225 + (2^222 − 1)·2^2 + 1`.
/// The chain builds `z^(2^k − 1)` by doubling `k`; it depends only on the
/// public exponent.
fn invert(z: &Tight) -> Tight {
    let m = |a: &Tight, b: &Tight| mul(&loose(a), &loose(b));
    // e_k = z^(2^k − 1)
    let e1 = *z;
    let e2 = m(&square_n(&e1, 1), &e1);
    let e3 = m(&square_n(&e2, 1), &e1);
    let e6 = m(&square_n(&e3, 3), &e3);
    let e12 = m(&square_n(&e6, 6), &e6);
    let e24 = m(&square_n(&e12, 12), &e12);
    let e48 = m(&square_n(&e24, 24), &e24);
    let e96 = m(&square_n(&e48, 48), &e48);
    let e192 = m(&square_n(&e96, 96), &e96);
    let e216 = m(&square_n(&e192, 24), &e24);
    let e222 = m(&square_n(&e216, 6), &e6);
    let e223 = m(&square_n(&e222, 1), &e1);
    // (2^223 − 1)·2^223 + (2^222 − 1) = the top part, then ·4 + 1.
    let hi = m(&square_n(&e223, 223), &e222);
    m(&square_n(&hi, 2), &e1)
}

/// X448(scalar, u): the u-coordinate of `scalar · u`, RFC 7748 §5 (the
/// scalar is clamped; a non-canonical u is taken modulo p).
pub(crate) fn x448(scalar: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let mut k = *scalar;
    k[0] &= 252;
    k[55] |= 128;
    let x1t = from_bytes(u);
    let x1 = loose(&x1t);
    let one = from_bytes(&{
        let mut b = [0u8; 56];
        b[0] = 1;
        b
    });
    let a24 = loose(&from_bytes(&{
        let mut b = [0u8; 56];
        b[..2].copy_from_slice(&39_081u16.to_le_bytes());
        b
    }));
    let (mut x2, mut z2) = (one, Tight([0; 8]));
    let (mut x3, mut z3) = (x1t, one);
    let mut swap = 0u8;
    for t in (0..448).rev() {
        let kt = (k[t / 8] >> (t % 8)) & 1;
        swap ^= kt;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt;
        let a = add(&x2, &z2);
        let aa = square(&a);
        let b = sub(&x2, &z2);
        let bb = square(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        x3 = square(&add(&da, &cb));
        z3 = mul(&x1, &loose(&square(&sub(&da, &cb))));
        x2 = mul(&loose(&aa), &loose(&bb));
        z2 = mul(&e, &add(&aa, &mul(&a24, &e)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    let out = mul(&loose(&x2), &loose(&invert(&z2)));
    let mut bytes = [0u8; 56];
    fiat_p448_to_bytes(&mut bytes, &out);
    k.zeroize();
    x2.0.zeroize();
    z2.0.zeroize();
    x3.0.zeroize();
    z3.0.zeroize();
    bytes
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(s: &str) -> [u8; 56] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    /// RFC 7748 §5.2.
    #[test]
    fn rfc7748_vectors() {
        let k = h(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let u = h(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        assert_eq!(
            x448(&k, &u),
            h(
                "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
            )
        );
        let k = h(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        );
        let u = h(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        );
        assert_eq!(
            x448(&k, &u),
            h(
                "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
            )
        );
    }

    /// RFC 7748 §5.2, iterated: after 1 and 1,000 iterations.
    #[test]
    fn rfc7748_iterated() {
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        for i in 1..=1000 {
            let r = x448(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    k,
                    h(
                        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"
                    )
                );
            }
        }
        assert_eq!(
            k,
            h(
                "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"
            )
        );
    }

    /// The same function as the `x448` crate, on random inputs (including
    /// non-canonical u-coordinates).
    #[test]
    fn matches_the_x448_crate() {
        let mut rng = crate::rng::HedgedRng::new().unwrap();
        for i in 0..200 {
            let k: [u8; 56] = rng.array("test").unwrap();
            let mut u: [u8; 56] = rng.array("test").unwrap();
            if i % 10 == 0 {
                u = [0xff; 56]; // ≥ p
            }
            assert_eq!(x448(&k, &u), x448::x448_unchecked(k, u), "case {i}");
        }
    }
}
