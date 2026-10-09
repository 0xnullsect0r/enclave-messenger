//! Notification previews (`docs/10-push.md` §4): with previews on, a
//! contact fills the capsule of what they send with their name and a
//! preview that only our notification key table opens; off, capsules are
//! random again.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_push_relay::{Platform, Relay, RelaySecret};
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];
const S2: [u8; 16] = [2; 16];

fn network() -> LocalTransport {
    let t = LocalTransport::new();
    for id in [S1, S2] {
        t.add_server(enclave_server::Config {
            id,
            effort_request: 4,
            effort_claim: 1,
            blob_tokens_per_day: 64,
            effort_username: 1,
            effort_inbox: 1,
            ..Default::default()
        })
        .unwrap();
    }
    t
}

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn previews_in_capsules() {
    let net = network();
    let (mut alice, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Alice")
        .await
        .unwrap();
    let (mut bob, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Bob")
        .await
        .unwrap();
    alice.add_contact(&bob.card(), "hi").await.unwrap();
    bob.sync().await.unwrap();
    bob.accept(&alice.root()).await.unwrap();
    alice.sync().await.unwrap();
    let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
    let key = RelaySecret::generate(1, &mut rng).unwrap();
    let public = key.public().clone();
    let mut relay = Relay::new(vec![key]);
    bob.register_push(&public, Platform::Apns, b"apns-device-token")
        .await
        .unwrap();
    let mut wake = |net: &LocalTransport| {
        net.advance(enclave_server::PUSH_WINDOW_SECS + enclave_server::PUSH_JITTER_SECS + 1);
        let now = net.now();
        let wakes = net.with_server(&S2, |s| s.due_wakes(now)).unwrap();
        assert_eq!(wakes.len(), 1);
        let d = relay.wake(&wakes[0], now).unwrap();
        assert_eq!(d.token, b"apns-device-token");
        assert_eq!(d.capsule.len(), enclave_push_relay::CAPSULE_LEN);
        d.capsule
    };

    // Off by default: the capsule is random.
    assert!(!bob.previews());
    alice.send_text(&bob.root(), "first").await.unwrap();
    let capsule = wake(&net);
    assert_eq!(bob.notify_table(net.now()).open(&capsule), None);

    // On: Alice gets Bob's key, and her next message's capsule opens.
    bob.set_previews(true).await.unwrap();
    alice.sync().await.unwrap();
    alice
        .send_text(&bob.root(), "see you at six")
        .await
        .unwrap();
    let capsule = wake(&net);
    let table = bob.notify_table(net.now());
    let table = enclave_proto::notify::KeyTable::decode(&table.encode()).unwrap();
    assert_eq!(
        table.open(&capsule),
        Some(("Alice".into(), "see you at six".into()))
    );
    // A day later the chain has moved on; yesterday's key still opens.
    net.advance(86_400);
    bob.sync().await.unwrap();
    alice.send_text(&bob.root(), "tomorrow").await.unwrap();
    let capsule = wake(&net);
    assert_eq!(
        bob.notify_table(net.now()).open(&capsule),
        Some(("Alice".into(), "tomorrow".into()))
    );

    // Off again: Alice is told, and capsules are random.
    bob.set_previews(false).await.unwrap();
    alice.sync().await.unwrap();
    alice.send_text(&bob.root(), "quiet").await.unwrap();
    let capsule = wake(&net);
    assert_eq!(table.open(&capsule), None);
    assert!(bob.notify_table(net.now()).entries.is_empty());
}

/// A group's mailbox wakes every member device registered there, and the
/// capsule opens with the group's key for the day; an account that asked
/// for dummy wakes gets about one an hour with nothing behind them.
#[tokio::test(flavor = "multi_thread")]
async fn group_wakes_and_dummies() {
    let net = network();
    let new = |s, n| Client::create(memory(), Arc::new(net.clone()), s, n);
    let (mut alice, _) = new(S1, "Alice").await.unwrap();
    let (mut bob, _) = new(S2, "Bob").await.unwrap();
    let (mut cy, _) = new(S2, "Cy").await.unwrap();
    for other in [&mut bob, &mut cy] {
        alice.add_contact(&other.card(), "hi").await.unwrap();
        other.sync().await.unwrap();
        other.accept(&alice.root()).await.unwrap();
        alice.sync().await.unwrap();
    }
    let gid = alice
        .create_group("Trip", &[bob.root(), cy.root()])
        .await
        .unwrap();
    for _ in 0..2 {
        for c in [&mut alice, &mut bob, &mut cy] {
            c.sync().await.unwrap();
        }
    }
    let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
    let key = RelaySecret::generate(1, &mut rng).unwrap();
    let public = key.public().clone();
    let mut relay = Relay::new(vec![key]);
    bob.set_previews(true).await.unwrap();
    bob.register_push(&public, Platform::Apns, b"bob-phone")
        .await
        .unwrap();
    bob.sync().await.unwrap(); // registers on today's group mailbox
    cy.register_push_with(&public, Platform::Fcm, b"cy-phone", true)
        .await
        .unwrap();

    alice.send_group_text(&gid, "group hello").await.unwrap();
    net.advance(enclave_server::PUSH_WINDOW_SECS + enclave_server::PUSH_JITTER_SECS + 1);
    let now = net.now();
    // The group is hosted on Alice's server.
    let wakes = net.with_server(&S1, |s| s.due_wakes(now)).unwrap();
    let to_bob: Vec<_> = wakes
        .iter()
        .filter_map(|w| relay.wake(w, now))
        .filter(|d| d.token == b"bob-phone")
        .collect();
    assert_eq!(to_bob.len(), 1, "one wake for Bob's device");
    assert_eq!(
        bob.notify_table(now).open(&to_bob[0].capsule),
        Some(("Alice".into(), "group hello".into()))
    );

    // Cy asked for dummy wakes: over twelve quiet hours, some come (about
    // twelve; none at all has odds of e^-12).
    let mut dummies = 0;
    for _ in 0..72 {
        net.advance(600);
        let now = net.now();
        for w in net.with_server(&S2, |s| s.due_wakes(now)).unwrap() {
            if relay.wake(&w, now).is_some_and(|d| d.token == b"cy-phone") {
                dummies += 1;
            }
        }
    }
    assert!((1..=40).contains(&dummies), "{dummies} dummy wakes");
    // Unregistering stops them.
    cy.unregister_push().await.unwrap();
    net.advance(6 * 3600);
    let now = net.now();
    assert!(
        net.with_server(&S2, |s| s.due_wakes(now))
            .unwrap()
            .is_empty()
    );
}

/// RT-16: however many messages arrive in a window, a device gets one wake
/// for it, and every wake has the same size with a 1,024-byte capsule,
/// previews off (random) or on (sealed).
#[tokio::test(flavor = "multi_thread")]
async fn rt16_one_wake_per_window() {
    let net = network();
    let (mut alice, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Alice")
        .await
        .unwrap();
    let (mut bob, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Bob")
        .await
        .unwrap();
    alice.add_contact(&bob.card(), "hi").await.unwrap();
    bob.sync().await.unwrap();
    bob.accept(&alice.root()).await.unwrap();
    alice.sync().await.unwrap();
    let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
    let key = RelaySecret::generate(1, &mut rng).unwrap();
    let public = key.public().clone();
    let mut relay = Relay::new(vec![key]);
    bob.register_push(&public, Platform::Apns, b"bob-phone")
        .await
        .unwrap();
    let window = enclave_server::PUSH_WINDOW_SECS;
    let due = |net: &LocalTransport| {
        let now = net.now();
        net.with_server(&S2, |s| s.due_wakes(now)).unwrap()
    };
    for previews in [false, true] {
        if previews {
            bob.set_previews(true).await.unwrap();
            bob.sync().await.unwrap();
            alice.sync().await.unwrap();
        }
        // Start from a quiet window.
        net.advance(3 * window);
        due(&net);
        for i in 0..5 {
            alice
                .send_text(&bob.root(), &format!("m{i}"))
                .await
                .unwrap();
        }
        net.advance(window + enclave_server::PUSH_JITTER_SECS + 1);
        let wakes = due(&net);
        assert_eq!(wakes.len(), 1, "one wake for five messages");
        assert_eq!(wakes[0].len(), enclave_push_relay::WAKE_LEN);
        let d = relay.wake(&wakes[0], net.now()).unwrap();
        assert_eq!(d.capsule.len(), enclave_push_relay::CAPSULE_LEN);
        let opened = bob.notify_table(net.now()).open(&d.capsule);
        if previews {
            assert_eq!(opened, Some(("Alice".into(), "m4".into())), "the newest");
        } else {
            assert_eq!(opened, None, "random");
        }
        net.advance(window);
        assert!(due(&net).is_empty(), "nothing new, no wake");
    }
}

/// RT-20: the server holds only sealed tokens, each registration's
/// different, never the platform token itself.
#[tokio::test(flavor = "multi_thread")]
async fn rt20_server_never_sees_plain_token() {
    let net = network();
    let (mut bob, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Bob")
        .await
        .unwrap();
    let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
    let key = RelaySecret::generate(1, &mut rng).unwrap();
    let public = key.public().clone();
    let token = b"fcm:plain-device-token-RT20";
    let dir = std::env::temp_dir().join(format!("enclave-rt20-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut seen = Vec::new();
    for i in 0..2 {
        bob.register_push(&public, Platform::Fcm, token)
            .await
            .unwrap();
        let path = dir.join(format!("snap-{i}.redb"));
        net.with_server(&S2, |s| s.db().snapshot(&path).unwrap())
            .unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(token.len()).any(|w| w == token),
            "the token isn't in the server's state"
        );
        let push = net
            .with_server(&S2, |s| {
                s.db().read(|r| r.scan(enclave_server::db::PUSH, b""))
            })
            .unwrap()
            .unwrap();
        // One per live inbox (this week's and next), replaced each time.
        assert!(!push.is_empty());
        seen.push(push.into_iter().map(|(_, v)| v).collect::<Vec<_>>());
    }
    assert_eq!(seen[0].len(), seen[1].len(), "replaced, not added");
    // Each registration is an unrelated sealing of the same token.
    for a in &seen[0] {
        for b in &seen[1] {
            for (x, y) in a.windows(32).zip(b.windows(32)).step_by(32) {
                assert_ne!(x, y, "no 32-byte block in common");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
