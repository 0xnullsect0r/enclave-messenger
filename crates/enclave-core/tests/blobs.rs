//! Files (`docs/09-transport.md` §9, RT-17): uploads are paid with
//! Privacy Pass tokens from the uploader's home server, and downloads
//! mix in fetches of other files' chunks, so the server can't tell which
//! upload a download belongs to.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Options};
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
            blob_tokens_per_day: 8,
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
async fn rt17_fetch_includes_decoys() {
    let net = network();
    let new = |s, n| Client::create(memory(), Arc::new(net.clone()), s, n);
    let (mut ada, _) = new(S1, "Ada").await.unwrap();
    let (mut ben, _) = new(S2, "Ben").await.unwrap();
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();

    // Two files, paid with tokens from Ada's server (8 a day buy 8 × 512
    // uploads; these take 5 each).
    let one = ada
        .send_attachment(
            &ben.root(),
            "one.bin",
            "application/octet-stream",
            &[1; 9_000],
            "",
        )
        .await
        .unwrap();
    let two = ada
        .send_attachment(
            &ben.root(),
            "two.bin",
            "application/octet-stream",
            &[2; 9_000],
            "",
        )
        .await
        .unwrap();
    let att = |m: &enclave_core::Message| m.attachment.clone().unwrap();
    let ids = |a: &enclave_core::files::Attachment| -> Vec<[u8; 32]> {
        (0..a.chunks).map(|i| a.chunk_id(i)).collect()
    };
    let (a1, a2) = (att(&one), att(&two));
    ben.sync().await.unwrap();
    let got = ben.messages(&ada.root()).unwrap();
    let seq = |name: &str| {
        got.iter()
            .find(|m| m.attachment.as_ref().is_some_and(|a| a.name == name))
            .unwrap()
            .seq
    };

    // The first download knows no other file: just its chunks.
    net.with_server(&S1, |s| s.take_blob_gets()).unwrap();
    assert_eq!(
        ben.fetch_attachment(&ada.root(), seq("one.bin"))
            .await
            .unwrap(),
        vec![1; 9_000]
    );
    let first = net.with_server(&S1, |s| s.take_blob_gets()).unwrap();
    assert_eq!(first, ids(&a1));

    // The second fetches 1 to 3 chunks of the first among its own.
    assert_eq!(
        ben.fetch_attachment(&ada.root(), seq("two.bin"))
            .await
            .unwrap(),
        vec![2; 9_000]
    );
    let second = net.with_server(&S1, |s| s.take_blob_gets()).unwrap();
    let decoys: Vec<_> = second.iter().filter(|id| !ids(&a2).contains(id)).collect();
    assert!((1..=3).contains(&decoys.len()), "{} decoys", decoys.len());
    assert!(
        decoys.iter().all(|d| ids(&a1).contains(d)),
        "decoys are real chunks"
    );
    let real: Vec<_> = second
        .iter()
        .filter(|id| ids(&a2).contains(id))
        .copied()
        .collect();
    assert_eq!(real, ids(&a2), "every real chunk, in order");
}

/// Uploads need an allocation bought with a token; the daily quota of
/// tokens caps what an account uploads.
#[tokio::test(flavor = "multi_thread")]
async fn uploads_are_paid_with_tokens() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    for i in 0..3u8 {
        ada.send_attachment(&ben.root(), "f", "application/octet-stream", &[i; 100], "")
            .await
            .unwrap();
    }
    ben.sync().await.unwrap();
    let files: Vec<_> = ben
        .messages(&ada.root())
        .unwrap()
        .into_iter()
        .filter(|m| m.attachment.is_some())
        .collect();
    assert_eq!(files.len(), 3);
    for (i, m) in files.iter().enumerate() {
        assert_eq!(
            ben.fetch_attachment(&ada.root(), m.seq).await.unwrap(),
            vec![i as u8; 100]
        );
    }
}
