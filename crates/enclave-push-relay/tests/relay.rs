//! Sealed tokens, window shaping and key rotation (delivery: `deliver/tests.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_push_relay::*;

#[test]
fn tokens_seal_open_and_look_unrelated() {
    let mut rng = HedgedRng::new().unwrap();
    let key = RelaySecret::generate(7, &mut rng).unwrap();
    let public = RelayPublic::decode(&key.public().encode()).unwrap();
    let url = b"http://push.example/up/AbC123";
    let a = seal_token(&public, Platform::UnifiedPush, url, 0, &mut rng).unwrap();
    let b = seal_token(&public, Platform::UnifiedPush, url, 0, &mut rng).unwrap();
    assert_eq!(a.len(), SEALED_LEN);
    assert_eq!(SEALED_LEN, 1952, "docs/10-push.md §7");
    assert_eq!(b.len(), SEALED_LEN, "every token has one size");
    assert_ne!(a[4..], b[4..], "re-randomized");
    let short = seal_token(&public, Platform::Apns, b"x", 0, &mut rng).unwrap();
    assert_eq!(short.len(), SEALED_LEN);

    let relay = Relay::new(vec![key]);
    let d = relay.open(&a).unwrap();
    assert_eq!(d.platform, Platform::UnifiedPush);
    assert_eq!(d.token, url);
    assert_eq!(relay.open(&short).unwrap().token, b"x");

    // Another relay's key, a tampered byte, a wrong length: refused.
    let other = Relay::new(vec![RelaySecret::generate(7, &mut rng).unwrap()]);
    assert!(other.open(&a).is_err());
    let mut t = a.clone();
    t[SEALED_LEN - 5] ^= 1;
    assert!(relay.open(&t).is_err());
    assert!(relay.open(&a[..100]).is_err());
    assert!(seal_token(&public, Platform::Fcm, &[0; MAX_TOKEN + 1], 0, &mut rng).is_err());
}

/// RT-20: every registration seals the token afresh, so two of them share
/// no bytes past the epoch, and only the relay opens them.
#[test]
fn rt20_sealed_token_differs_per_registration() {
    let mut rng = HedgedRng::new().unwrap();
    let key = RelaySecret::generate(3, &mut rng).unwrap();
    let public = key.public().clone();
    let token = b"apns-device-token-0123456789";
    let sealed: Vec<Vec<u8>> = (0..8)
        .map(|_| seal_token(&public, Platform::Apns, token, 0, &mut rng).unwrap())
        .collect();
    for (i, a) in sealed.iter().enumerate() {
        assert_eq!(a.len(), SEALED_LEN);
        assert!(!a.windows(token.len()).any(|w| w == token), "sealed");
        for b in &sealed[i + 1..] {
            assert_eq!(a[..4], b[..4], "the epoch is all they share");
            assert_ne!(a[4..4 + 56], b[4..4 + 56], "fresh ephemeral key");
            assert_ne!(a[a.len() - 64..], b[b.len() - 64..]);
        }
    }
    let relay = Relay::new(vec![key]);
    for s in &sealed {
        assert_eq!(relay.open(s).unwrap().token, token);
    }
}

#[test]
fn one_wake_per_token_per_window() {
    let mut rng = HedgedRng::new().unwrap();
    let key = RelaySecret::generate(1, &mut rng).unwrap();
    let public = key.public().clone();
    let mut relay = Relay::new(vec![key]);
    // Two different sealings of one platform token count as one.
    let a = seal_token(&public, Platform::Fcm, b"device-token", 0, &mut rng).unwrap();
    let b = seal_token(&public, Platform::Fcm, b"device-token", 0, &mut rng).unwrap();
    let other = seal_token(&public, Platform::Fcm, b"another-device", 0, &mut rng).unwrap();
    let t = 1_000 * WINDOW_SECS;
    assert!(relay.wake(&a, t + 5).is_some());
    assert!(relay.wake(&b, t + 40).is_none(), "same token, same window");
    assert!(
        relay.wake(&other, t + 41).is_some(),
        "other tokens unaffected"
    );
    assert!(relay.wake(&b, t + WINDOW_SECS + 1).is_some(), "next window");
    assert_eq!((relay.forwarded, relay.shaped), (3, 1));
    assert!(relay.wake(b"garbage", t).is_none());
}

#[test]
fn keys_persist_rotate_and_overlap() {
    use enclave_push_relay::keys::RelayKeys;
    let dir = std::env::temp_dir().join(format!("enclave-push-keys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut rng = HedgedRng::new().unwrap();
    let day0 = 300 * EPOCH_DAYS + 3; // epoch 300, day 3 into it
    let keys = RelayKeys::init(&dir.join("k"), day0).unwrap();
    assert!(
        RelayKeys::init(&dir.join("k"), day0).is_err(),
        "never overwrites"
    );
    let [current, next] = keys.published();
    assert_eq!((current.epoch, next.epoch), (300, 301));
    let old_token = seal_token(&current, Platform::Fcm, b"dev-1", 0, &mut rng).unwrap();
    let early = seal_token(&next, Platform::Fcm, b"dev-2", 0, &mut rng).unwrap();

    // A restart holds the same key: tokens sealed before it still open.
    let mut keys = RelayKeys::load(&dir.join("k")).unwrap();
    let mut relay = Relay::new(keys.secrets());
    assert_eq!(relay.open(&old_token).unwrap().token, b"dev-1");
    assert!(!keys.advance(day0).unwrap());

    // Into the next epoch: the key published ahead takes over, and the old
    // one is still held for the overlap.
    assert!(keys.advance(301 * EPOCH_DAYS).unwrap());
    relay.set_keys(keys.secrets());
    assert_eq!(relay.epochs(), [301, 300]);
    assert_eq!(relay.open(&early).unwrap().token, b"dev-2");
    assert_eq!(relay.open(&old_token).unwrap().token, b"dev-1");
    let reloaded = RelayKeys::load(&dir.join("k")).unwrap();
    assert_eq!(Relay::new(reloaded.secrets()).epochs(), [301, 300]);

    // After the overlap the old key is gone, from memory and from disk.
    assert!(!keys.advance(301 * EPOCH_DAYS + OVERLAP_DAYS - 1).unwrap());
    assert!(keys.advance(301 * EPOCH_DAYS + OVERLAP_DAYS).unwrap());
    relay.set_keys(keys.secrets());
    assert!(relay.open(&old_token).is_err());
    let reloaded = RelayKeys::load(&dir.join("k")).unwrap();
    assert_eq!(Relay::new(reloaded.secrets()).epochs(), [301]);
    let _ = std::fs::remove_dir_all(&dir);
}
