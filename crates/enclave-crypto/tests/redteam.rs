//! Red-team checks on the hedged nonce and RNG (`docs/redteam-matrix.md`
//! RT-08; `docs/02-cryptography.md` §4, §6).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::hash::sha3_512;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, NONCE_LEN, SealKey, TAG_LEN};

/// The keystream a seal used: its ciphertext XOR the plaintext.
fn keystream(ct: &[u8], pt: &[u8]) -> Vec<u8> {
    ct.iter().zip(pt).map(|(c, p)| c ^ p).collect()
}

/// Whether two keystreams share any 16-byte block at the same position.
fn overlap(a: &[u8], b: &[u8]) -> bool {
    a.chunks(16).zip(b.chunks(16)).any(|(x, y)| x == y)
}

/// A device restored from an old snapshot or backup repeats its key and its
/// generator's state, and then seals something new. It never reuses a
/// keystream (RT-08): the restored generator draws fresh OS entropy, and
/// even when that repeats too the nonce depends on the plaintext, so only
/// a byte-for-byte identical seal comes out the same. The compact form,
/// keyed by a ratchet's lookup tag and the body hash, gets the same
/// protection from the body.
#[test]
fn rt08_rollback_no_keystream_reuse() {
    let key = SealKey::from_bytes([7; 32]);
    let ad = b"conversation";
    let first = vec![0x11u8; 4096];
    let mut second = first.clone();
    second[4095] ^= 1;

    // The same hedge secret and counter, as after restoring one snapshot
    // twice: the draws still differ, and so do the seals of one plaintext.
    let mut a = HedgedRng::with_hedge([9; 32]);
    let mut b = HedgedRng::with_hedge([9; 32]);
    assert_ne!(
        a.array::<32>("seal/nonce").unwrap(),
        b.array::<32>("seal/nonce").unwrap()
    );
    let sa = seal::seal(&key, ad, &first, &mut a).unwrap();
    let sb = seal::seal(&key, ad, &first, &mut b).unwrap();
    assert_ne!(sa[..NONCE_LEN], sb[..NONCE_LEN]);
    assert!(!overlap(
        &keystream(&sa[NONCE_LEN..], &first),
        &keystream(&sb[NONCE_LEN..], &first)
    ));

    // Worst case, the OS entropy repeats as well: the randomness is the
    // same, but a different plaintext (one bit) gets a different nonce
    // and an unrelated keystream.
    let r = [3u8; 32];
    let s1 = seal::seal_with_randomness(&key, ad, &first, &r).unwrap();
    let s2 = seal::seal_with_randomness(&key, ad, &second, &r).unwrap();
    assert_ne!(s1[..NONCE_LEN], s2[..NONCE_LEN]);
    let k1 = keystream(&s1[NONCE_LEN..s1.len() - TAG_LEN], &first);
    let k2 = keystream(&s2[NONCE_LEN..s2.len() - TAG_LEN], &second);
    assert!(!overlap(&k1, &k2), "keystream reused after a rollback");
    // Only an identical seal repeats, which reveals nothing new.
    assert_eq!(
        seal::seal_with_randomness(&key, ad, &first, &r).unwrap(),
        s1
    );
    assert_eq!(seal::open(&key, ad, &s2).unwrap(), second);

    // Compact seals as the ratchet makes them (`05-ratchet.md` §6): a
    // rolled-back sender repeats the lookup tag, but the nonce material
    // also holds the hash of the body it seals, so new content gets a new
    // keystream.
    let tag = [0x42u8; 16];
    let material = |body: &[u8]| [&tag[..], &sha3_512(body)[..]].concat();
    let header = vec![0x5au8; 160];
    let c1 = seal::seal_compact(&key, &material(b"body one"), ad, &header).unwrap();
    let c2 = seal::seal_compact(&key, &material(b"body two"), ad, &header).unwrap();
    assert!(!overlap(
        &keystream(&c1[..header.len()], &header),
        &keystream(&c2[..header.len()], &header)
    ));
    assert_eq!(
        seal::open_compact(&key, &material(b"body two"), ad, &c2).unwrap(),
        header
    );
}
