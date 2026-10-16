//! HQC-256 against the official known-answer vectors (the first two of
//! `hqc-5.rsp` from the HQC reference implementation at commit 161cd4f,
//! as shipped with `hqc-kem`), and the four-KEM EnclaveCombine suite.
//! Run with `--features hqc`.
#![cfg(feature = "hqc")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::hash::shake256;
use enclave_crypto::hqc::{HqcCiphertext, HqcPublic, HqcSecret};
use enclave_crypto::kem::{Suite, combine};

/// The vectors' randomness: SHAKE256(seed ‖ 0x00), read in order: the
/// key's 32-byte seed, then the 32-byte message, then the 16-byte salt.
fn kat_stream(seed: &[u8]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let out: [u8; 80] = shake256(&[seed, &[0x00]].concat());
    let (mut k, mut m, mut salt) = ([0u8; 32], [0u8; 32], [0u8; 16]);
    k.copy_from_slice(&out[..32]);
    m.copy_from_slice(&out[32..64]);
    salt.copy_from_slice(&out[64..]);
    (k, m, salt)
}

fn field(block: &str, name: &str) -> Vec<u8> {
    let line = block
        .lines()
        .find_map(|l| l.trim().strip_prefix(&format!("{name} = ")))
        .expect("every vector has the field");
    hex::decode(line).unwrap()
}

#[test]
fn hqc256_known_answers() {
    let text = include_str!("data/hqc-5-kat.rsp");
    let blocks: Vec<&str> = text.split("count = ").skip(1).collect();
    assert_eq!(blocks.len(), 2);
    for block in blocks {
        let (seed, m, salt) = kat_stream(&field(block, "seed"));
        let (sk, pk) = HqcSecret::from_seed(&seed);
        assert_eq!(pk.0, field(block, "pk"), "public key");
        assert_eq!(sk.as_bytes(), &field(block, "sk")[..], "secret key");
        let (ct, ss) = pk.encapsulate_deterministic(&m, &salt).unwrap();
        assert_eq!(ct.0, field(block, "ct"), "ciphertext");
        assert_eq!(&ss[..], &field(block, "ss")[..], "shared secret");
        // And back, through the wire forms.
        let sk = HqcSecret::from_slice(sk.as_bytes()).unwrap();
        let ct = HqcCiphertext::from_slice(&ct.0).unwrap();
        assert_eq!(&sk.decapsulate(&ct).unwrap()[..], &field(block, "ss")[..]);
        assert!(HqcPublic::from_slice(&pk.0).is_ok());
    }
}

#[test]
fn four_kem_suite_is_separate() {
    let secrets: [&[u8]; 4] = [b"x448", b"mlkem", b"mceliece", b"hqc"];
    let public: [&[u8]; 2] = [b"pk", b"ct"];
    let four = combine(Suite::FourKem, &secrets, &public, None);
    assert_eq!(Suite::FourKem.id(), 0x04);
    // Other suites with the same inputs give unrelated keys.
    assert_ne!(*four, *combine(Suite::ThreeKem, &secrets, &public, None));
    assert_ne!(*four, *combine(Suite::TwoKem, &secrets, &public, None));
    // The HQC secret counts.
    let other: [&[u8]; 4] = [b"x448", b"mlkem", b"mceliece", b"hqd"];
    assert_ne!(*four, *combine(Suite::FourKem, &other, &public, None));
}
