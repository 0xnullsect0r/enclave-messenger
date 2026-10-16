//! Constant-time checks under Valgrind (RT-15, `docs/02-cryptography.md`
//! §12): each test poisons a secret key (Memcheck treats its bytes as
//! undefined), runs the operation, and asserts Memcheck reported nothing,
//! so no branch and no memory address depended on the key. Results are
//! unpoisoned before they are looked at. Run with `cargo xtask ctgrind`,
//! which builds them optimised and runs each under Memcheck; outside
//! Valgrind they refuse to pass.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::kem::{McElieceSecret, MlKemSecret};
use enclave_crypto::rng::HedgedRng;
use enclave_platform::ctgrind;
use std::hint::black_box;

/// Run `f` and return how many errors Memcheck reported meanwhile.
fn reported(f: impl FnOnce()) -> usize {
    assert!(
        ctgrind::on_valgrind(),
        "run under Valgrind: cargo xtask ctgrind"
    );
    let before = ctgrind::errors();
    f();
    ctgrind::errors() - before
}

/// The harness sees a known leak: a branch on a poisoned byte.
#[test]
#[ignore = "run under Valgrind with `cargo xtask ctgrind`"]
fn control_a_secret_branch_is_reported() {
    let secret = black_box([0x5au8; 32]);
    let n = reported(|| {
        ctgrind::poison(&secret);
        if black_box(secret[3]) == 0x5a {
            black_box(1);
        }
        ctgrind::unpoison(&secret);
    });
    assert!(n > 0, "Memcheck missed a branch on a secret");
}

/// ML-KEM-1024 decapsulation, of a valid ciphertext and of a corrupted one
/// (implicit rejection), touches the secret key only in constant time.
#[test]
#[ignore = "run under Valgrind with `cargo xtask ctgrind`"]
fn rt15_ctgrind_mlkem_decap() {
    let mut rng = HedgedRng::new().unwrap();
    let (sk, pk) = MlKemSecret::generate(&mut rng).unwrap();
    let (good, want) = pk.encapsulate(&mut rng).unwrap();
    let mut bad = good.clone();
    bad.0[100] ^= 0x10;
    // The decapsulation key is dk_PKE (the secret vector) ‖ ek ‖ H(ek) ‖ z
    // (FIPS 203 §7.3). ek and H(ek) are public: re-encryption samples the
    // matrix from ek's seed by rejection, variable time by design. The
    // secret vector and the implicit-rejection seed z are poisoned.
    let dk = sk.as_bytes();
    let (secret, z) = (&dk[..1536], &dk[dk.len() - 32..]);
    let mut got = Vec::new();
    let n = reported(|| {
        ctgrind::poison(secret);
        ctgrind::poison(z);
        for ct in [&good, &bad] {
            let ss = sk.decapsulate(ct);
            ctgrind::unpoison(&ss[..]);
            got.push(*ss);
        }
        ctgrind::unpoison(secret);
        ctgrind::unpoison(z);
    });
    assert_eq!(n, 0, "ML-KEM decapsulation depends on the secret key");
    assert_eq!(
        got[0], *want,
        "the valid ciphertext gives the shared secret"
    );
    assert_ne!(got[1], *want, "the corrupted one gives another");
}

/// Classic McEliece-8192128 decapsulation likewise.
#[test]
#[ignore = "run under Valgrind with `cargo xtask ctgrind`"]
fn rt15_ctgrind_mceliece_decap() {
    let mut rng = HedgedRng::new().unwrap();
    let (sk, pk) = McElieceSecret::generate(&mut rng).unwrap();
    let (good, want) = pk.encapsulate(&mut rng).unwrap();
    let mut bad = good;
    bad.0[7] ^= 0x01;
    let mut got = Vec::new();
    let n = reported(|| {
        ctgrind::poison(sk.as_bytes());
        for ct in [&good, &bad] {
            let ss = sk.decapsulate(ct).unwrap();
            ctgrind::unpoison(&ss[..]);
            got.push(*ss);
        }
        ctgrind::unpoison(sk.as_bytes());
    });
    assert_eq!(n, 0, "McEliece decapsulation depends on the secret key");
    assert_eq!(got[0], *want);
    assert_ne!(got[1], *want);
}

/// X448 (the fiat-crypto ladder) with a poisoned private key. Through
/// `public()`: `diffie_hellman` then checks the result isn't all zero (a
/// low-order peer), a branch on purpose whose outcome is public.
#[test]
#[ignore = "run under Valgrind with `cargo xtask ctgrind`"]
fn x448_ladder_is_constant_time() {
    use enclave_crypto::kem::X448Secret;
    let mut rng = HedgedRng::new().unwrap();
    let (a, a_pub) = X448Secret::generate(&mut rng).unwrap();
    let bytes = a.to_bytes();
    let mut got = [0u8; 56];
    let n = reported(|| {
        ctgrind::poison(&bytes[..]);
        let p = X448Secret::from_bytes(*bytes).public();
        ctgrind::unpoison(&p.0);
        got = p.0;
        ctgrind::unpoison(&bytes[..]);
    });
    assert_eq!(n, 0, "X448 depends on the private key");
    assert_eq!(got, a_pub.0);
}

/// EnclaveSeal (KMAC256 subkeys, XChaCha20 and AES-256-CTR keystreams,
/// the KMAC tag) under a poisoned key: only the output is secret-dependent.
#[test]
#[ignore = "run under Valgrind with `cargo xtask ctgrind`"]
fn seal_is_constant_time_in_the_key() {
    use enclave_crypto::seal::{SealKey, seal_with_randomness};
    let key_bytes = [0x42u8; 32];
    let mut out = Vec::new();
    let n = reported(|| {
        ctgrind::poison(&key_bytes);
        let key = SealKey::from_bytes(key_bytes);
        let sealed = seal_with_randomness(&key, b"ad", &[7u8; 2048], &[9u8; 32]);
        if let Ok(s) = sealed {
            ctgrind::unpoison(&s);
            out = s;
        }
        ctgrind::unpoison(&key_bytes);
    });
    assert_eq!(n, 0, "EnclaveSeal depends on the key");
    let again = seal_with_randomness(
        &SealKey::from_bytes(key_bytes),
        b"ad",
        &[7u8; 2048],
        &[9u8; 32],
    )
    .unwrap();
    assert_eq!(out, again);
}

/// The tag compare (`subtle` on 32 bytes): the answer is the only thing
/// that depends on the tags.
#[test]
#[ignore = "run under Valgrind with `cargo xtask ctgrind`"]
fn mac_compare_is_constant_time() {
    use subtle::ConstantTimeEq;
    let expect = [0x11u8; 32];
    let mut forged = expect;
    forged[31] ^= 1;
    let mut same = [0u8; 2];
    let n = reported(|| {
        ctgrind::poison(&expect);
        for (i, t) in [expect, forged].iter().enumerate() {
            same[i] = expect.ct_eq(t).unwrap_u8();
        }
        // The answers are what may depend on the tags: looked at only now.
        ctgrind::unpoison(black_box(&same));
        ctgrind::unpoison(&expect);
    });
    assert_eq!(n, 0, "the tag compare depends on the tag");
    assert_eq!(same, [1, 0]);
}
