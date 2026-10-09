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
