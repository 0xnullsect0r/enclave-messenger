//! Maximum privacy in the engine (`docs/09-transport.md` §6.6): no push,
//! and nothing sent to a contact until all three KEMs protect the session.
#![allow(clippy::unwrap_used)]

use super::{Client, Options};
use crate::CoreError;
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

/// A contact whose client started the session on two KEMs: in Maximum,
/// replies wait until the braid brings in the third.
#[tokio::test(flavor = "multi_thread")]
async fn maximum_waits_for_three_kems() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    ada.two_kem_for_tests = true;
    ben.set_maximum(true);
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    let (a, b) = (ada.root(), ben.root());
    assert!(ben.protection_finishing(&a), "the request came on two KEMs");

    // Ben accepts (a protocol message goes), and writes: held.
    ben.accept(&a).await.unwrap();
    let m = ben.send_text(&a, "wait for it").await.unwrap();
    assert!(!m.sent, "held until all three KEMs protect the session");
    ada.sync().await.unwrap();
    assert!(
        ada.messages(&b)
            .unwrap()
            .iter()
            .all(|m| m.text != "wait for it"),
        "nothing reached Ada"
    );

    // Ada's next message carries the braid; then Ben's goes.
    ada.send_text(&b, "hello again").await.unwrap();
    ben.sync().await.unwrap();
    assert!(
        !ben.protection_finishing(&a),
        "the braid brought the third KEM"
    );
    ben.sync().await.unwrap();
    let mine = ben.messages(&a).unwrap();
    assert!(mine.iter().find(|m| m.text == "wait for it").unwrap().sent);
    ada.sync().await.unwrap();
    assert!(
        ada.messages(&b)
            .unwrap()
            .iter()
            .any(|m| m.text == "wait for it"),
        "and it arrived"
    );

    // Standard privacy sends at once, whatever the session.
    ben.set_maximum(false);
    assert!(ben.send_text(&a, "now").await.unwrap().sent);
}

/// No push in Maximum privacy.
#[tokio::test(flavor = "multi_thread")]
async fn maximum_has_no_push() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net), S1, "Ada")
        .await
        .unwrap();
    ada.set_maximum(true);
    let relay = enclave_push_relay::RelaySecret::generate(
        1,
        &mut enclave_crypto::rng::HedgedRng::new().unwrap(),
    )
    .unwrap();
    let r = ada
        .register_push(
            relay.public(),
            enclave_push_relay::Platform::UnifiedPush,
            b"https://up.example/x",
        )
        .await;
    assert!(matches!(r, Err(CoreError::MaximumPrivacy)), "{r:?}");
}
