//! Account records in key transparency (`docs/03-identity.md` §8.1): a
//! contact takes a manifest change only once the server's log holds the
//! manifest and its co-signatures as served.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Event, Options};
use enclave_crypto::pwhash::PwParams;
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

fn texts(ev: &[Event]) -> Vec<String> {
    ev.iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(message.text.clone()),
            _ => None,
        })
        .collect()
}

/// Ada restores onto a new phone and approves it from her old one, but her
/// server keeps the change out of its log: Ben holds the new phone's
/// greeting. Once the log has it, Ben takes it.
#[tokio::test(flavor = "multi_thread")]
async fn manifest_changes_wait_for_the_log() {
    let net = network();
    let mut policy = net.enable_usernames(&S1, "one.test").unwrap();
    policy.merge(net.enable_usernames(&S2, "two.test").unwrap());
    let (mut a, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    a.set_kt_policy(policy.clone());
    b.set_kt_policy(policy.clone());
    a.add_contact(&b.card(), "hi").await.unwrap();
    b.sync().await.unwrap();
    b.accept(&a.root()).await.unwrap();
    a.sync().await.unwrap();
    let old_version = b.contact(&a.root()).unwrap().manifest_version();

    net.with_server(&S1, |s| s.kt_withhold(true)).unwrap();
    let archive = a.export_backup().unwrap();
    let mut a_new = Client::restore(&words.join(" "), &archive, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    a_new.set_kt_policy(policy.clone());
    net.advance(601);
    let ev = a.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::RecoveryPending { .. })),
        "{ev:?}"
    );
    a.approve_recovery().await.unwrap();
    let ev = a_new.sync().await.unwrap();
    assert!(ev.contains(&Event::RecoveryDone), "{ev:?}");

    // Co-signed, but not in the log: held.
    net.advance(601);
    let ev = b.sync().await.unwrap();
    assert!(texts(&ev).is_empty(), "{ev:?}");
    assert_eq!(
        b.contact(&a.root()).unwrap().manifest_version(),
        old_version,
        "the change waits for the log"
    );

    // The server logs it after all: Ben takes it at his next look.
    net.with_server(&S1, |s| s.kt_withhold(false)).unwrap();
    net.advance(601);
    b.sync().await.unwrap();
    assert!(b.contact(&a.root()).unwrap().manifest_version() > old_version);
    a_new.sync().await.unwrap();
    a_new
        .send_text(&b.root(), "new phone, same me")
        .await
        .unwrap();
    let ev = b.sync().await.unwrap();
    assert_eq!(texts(&ev), ["new phone, same me"]);
}

/// Ada changes her recovery words, but her server keeps the migration out
/// of its log: Ben keeps it until the log shows it, then follows it.
#[tokio::test(flavor = "multi_thread")]
async fn migrations_wait_for_the_log() {
    let net = network();
    let mut policy = net.enable_usernames(&S1, "one.test").unwrap();
    policy.merge(net.enable_usernames(&S2, "two.test").unwrap());
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    a.set_kt_policy(policy.clone());
    b.set_kt_policy(policy.clone());
    a.add_contact(&b.card(), "hi").await.unwrap();
    b.sync().await.unwrap();
    b.accept(&a.root()).await.unwrap();
    a.sync().await.unwrap();
    let old = a.root();

    net.with_server(&S1, |s| s.kt_withhold(true)).unwrap();
    a.change_recovery_words().await.unwrap();
    let new = a.root();
    let moved = |ev: &[Event]| {
        ev.iter().any(
            |e| matches!(e, Event::ContactMoved { old: o, root: r, .. } if *o == old && *r == new),
        )
    };
    for _ in 0..2 {
        let ev = b.sync().await.unwrap();
        assert!(!moved(&ev), "{ev:?}");
    }
    assert!(b.contact(&old).is_some(), "not followed while unlogged");

    net.with_server(&S1, |s| s.kt_withhold(false)).unwrap();
    let ev = b.sync().await.unwrap();
    assert!(moved(&ev), "{ev:?}");
    assert!(b.contact(&new).is_some() && b.contact(&old).is_none());
}
