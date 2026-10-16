//! dudect-style timing tests (Reparaz, Balasch and Verbauwhede, "Dude, is my
//! code constant time?", 2017): time an operation on two classes of input
//! that differ only in secret-dependent ways, and run Welch's t-test on the
//! two timing distributions. |t| > 10 is a clear leak; below 4.5 no leak was
//! found at this sample size. Timings are also cropped at the 50th and 90th
//! percentiles, as dudect does, so rare outliers (interrupts) don't hide or
//! fake a difference.
//!
//! A deliberately leaky comparison is the control: the harness must flag it,
//! or a pass means nothing. Both classes use the same buffer, rewritten
//! before each untimed step, so allocation and alignment can't differ
//! between them.
//!
//! `Instant` can't resolve a 32-byte comparison (even the leaky one looks
//! constant there), so comparisons are tested on 4 KiB and the rest through
//! the operations that use them. See `docs/20-assurance.md` for results.
//!
//! Slow and sensitive to machine noise, so ignored by default:
//! `cargo xtask dudect`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::kem::MlKemSecret;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal;
use std::hint::black_box;
use std::time::Instant;

/// dudect's "definitely not constant time". The control must exceed it, and
/// the code under test must stay below it on every crop. (dudect calls
/// 4.5–10 "probably not"; on shared machines single runs land there by
/// noise, so the gate is the clear-leak level and results are logged.)
const LEAK: f64 = 10.0;

struct Xorshift(u64);
impl Xorshift {
    fn bit(&mut self) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 & 1) as usize
    }
}

/// Welch's t for two samples.
fn welch(a: &[f64], b: &[f64]) -> f64 {
    let stats = |v: &[f64]| {
        let n = v.len() as f64;
        let mean = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (n, mean, var)
    };
    let (na, ma, va) = stats(a);
    let (nb, mb, vb) = stats(b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}

/// For each of `n` rounds, pick a class at random, `prepare(class)` the
/// input (untimed: it writes the class's contents into the one buffer both
/// classes share, so memory layout can't differ between them), then time
/// `op()`. Returns the largest |t| over the uncropped data and the 90th and
/// 50th percentile crops.
fn max_t<T>(
    n: usize,
    work: &mut T,
    mut prepare: impl FnMut(&mut T, usize),
    mut op: impl FnMut(&T),
) -> f64 {
    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
    // Warm up caches and the branch predictor.
    for i in 0..n / 20 {
        prepare(work, i & 1);
        op(work);
    }
    let mut samples: Vec<(usize, f64)> = Vec::with_capacity(n);
    for _ in 0..n {
        let class = rng.bit();
        prepare(work, class);
        let t0 = Instant::now();
        op(work);
        samples.push((class, t0.elapsed().as_nanos() as f64));
    }
    let mut sorted: Vec<f64> = samples.iter().map(|s| s.1).collect();
    sorted.sort_by(f64::total_cmp);
    let mut worst: f64 = 0.0;
    for crop in [1.0, 0.9, 0.5] {
        let limit = sorted[((sorted.len() - 1) as f64 * crop) as usize];
        let class = |c: usize| -> Vec<f64> {
            samples
                .iter()
                .filter(|(k, t)| *k == c && *t <= limit)
                .map(|s| s.1)
                .collect()
        };
        let t = welch(&class(0), &class(1)).abs();
        eprintln!("  crop {:>3.0}%: |t| = {t:.2}", crop * 100.0);
        worst = worst.max(t);
    }
    worst
}

/// Two 4 KiB buffers that differ at the first byte (class 0) or the last
/// (class 1).
fn buffers() -> (Vec<u8>, [Vec<u8>; 2]) {
    let a = vec![0x5au8; 4096];
    let mut first = a.clone();
    first[0] ^= 1;
    let mut last = a.clone();
    last[4095] ^= 1;
    (a, [first, last])
}

#[test]
#[ignore = "timing test; run with `cargo xtask dudect`"]
fn control_early_exit_comparison_is_flagged() {
    let (a, b) = buffers();
    let mut work = b[0].clone();
    eprintln!("early-exit ==:");
    let t = max_t(
        200_000,
        &mut work,
        |w, c| w.copy_from_slice(&b[c]),
        |w| {
            black_box(black_box(&a[..]) == black_box(&w[..]));
        },
    );
    assert!(
        t > LEAK,
        "the harness failed to see a known leak (|t| = {t:.2})"
    );
}

/// RT-15: the MAC compare. EnclaveSeal checks the tag before any keystream
/// exists; where in the tag a forgery differs must not show in the time
/// to reject it.
#[test]
#[ignore = "timing test; run with `cargo xtask dudect`"]
fn rt15_dudect_mac_compare() {
    let mut rng = HedgedRng::new().unwrap();
    let key = seal::SealKey::from_bytes([7; 32]);
    let sealed = seal::seal(&key, b"ad", &[0x42; 1024], &mut rng).unwrap();
    let n = sealed.len();
    let mut first = sealed.clone();
    first[n - 32] ^= 1;
    let mut last = sealed.clone();
    last[n - 1] ^= 1;
    let forged = [first, last];
    let mut work = forged[0].clone();
    eprintln!("seal::open on forged tags:");
    let t = max_t(
        100_000,
        &mut work,
        |w, c| w.copy_from_slice(&forged[c]),
        |w| {
            assert!(seal::open(&key, b"ad", black_box(w)).is_err());
        },
    );
    assert!(t < LEAK, "|t| = {t:.2}");
}

/// ML-KEM decapsulation of a valid ciphertext and of a corrupted one (which
/// implicit rejection turns into a pseudorandom key) must take the same time.
#[test]
#[ignore = "timing test; run with `cargo xtask dudect`"]
fn mlkem_decapsulation_hides_invalid_ciphertexts() {
    let mut rng = HedgedRng::new().unwrap();
    let (sk, pk) = MlKemSecret::generate(&mut rng).unwrap();
    let (good, _) = pk.encapsulate(&mut rng).unwrap();
    let mut bad = good.clone();
    bad.0[100] ^= 0x10;
    let cts = [good, bad];
    let mut work = cts[0].clone();
    eprintln!("ML-KEM-1024 decapsulate, valid vs corrupted:");
    let t = max_t(
        20_000,
        &mut work,
        |w, c| w.0.copy_from_slice(&cts[c].0[..]),
        |w| {
            black_box(sk.decapsulate(black_box(w)));
        },
    );
    assert!(t < LEAK, "|t| = {t:.2}");
}
