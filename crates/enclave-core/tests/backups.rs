//! Backups (`docs/14-storage.md` §4): archives with a header, notes and
//! (when chosen) files in them, "Check my backup", and the copy kept on the
//! home server that the words alone bring back.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];

fn network() -> LocalTransport {
    let t = LocalTransport::new();
    t.add_server(enclave_server::Config {
        id: S1,
        effort_request: 4,
        effort_claim: 1,
        blob_tokens_per_day: 64,
        effort_username: 1,
        effort_inbox: 1,
        ..Default::default()
    })
    .unwrap();
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
async fn backups_local_and_on_the_server() {
    let net = network();
    let (mut ada, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, ben_words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ben")
        .await
        .unwrap();
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    ada.send_text(&ben.root(), "see you at the harbour")
        .await
        .unwrap();
    ada.send_attachment(&ben.root(), "map.png", "image/png", &[7; 5000], "")
        .await
        .unwrap();
    ada.send_note("buy oat milk").await.unwrap();
    let words = words.join(" ");

    // Two archives: the second counts on, and holds the files.
    let plain = ada.export_backup().unwrap();
    let media = ada.export_backup_with(true).unwrap();
    let h1 = enclave_store::backup::header(&plain).unwrap();
    let h2 = enclave_store::backup::header(&media).unwrap();
    assert_eq!((h1.sequence, h1.media), (1, false));
    assert_eq!((h2.sequence, h2.media), (2, true));
    assert!(media.len() > plain.len());

    // Check my backup: the words open it and are this account's.
    let c = ada.check_backup(&words, &plain).unwrap();
    assert!(c.ours && c.contacts == 1 && c.messages >= 3, "{c:?}");
    assert!(
        ada.check_backup(&ben_words.join(" "), &plain).is_err(),
        "other words"
    );
    let theirs = ben.export_backup().unwrap();
    assert!(
        !ben.check_backup(&ben_words.join(" "), &theirs)
            .is_ok_and(|c| !c.ours)
    );
    assert!(
        !ada.check_backup(&ben_words.join(" "), &theirs)
            .unwrap()
            .ours,
        "Ben's backup opens with Ben's words, but it isn't Ada's"
    );

    // On the server: up now, again after a week, and found with the words.
    assert_eq!(ada.server_backup(), (false, 0));
    ada.set_server_backup(true).await.unwrap();
    let (on, first) = ada.server_backup();
    assert!(on && first > 0);
    let fetched = Client::fetch_server_backup(&words, S1, Arc::new(net.clone()))
        .await
        .unwrap();
    assert!(enclave_core::check_archive(&words, &fetched).unwrap().ours);
    net.advance(enclave_core::SERVER_BACKUP_EVERY + 60);
    ada.sync().await.unwrap();
    assert!(ada.server_backup().1 > first, "uploaded again");
    assert!(
        Client::fetch_server_backup(&ben_words.join(" "), S1, Arc::new(net.clone()))
            .await
            .is_err(),
        "nothing there for Ben's words"
    );

    // Restoring (each makes a new primary device, so last): from the
    // file, and from the server with the words alone. Notes come back,
    // and the search index is built afresh.
    let back = Client::restore(&words, &media, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    assert!(
        back.notes()
            .unwrap()
            .iter()
            .any(|n| n.text == "buy oat milk")
    );
    assert_eq!(back.search("harbour", 5).unwrap().len(), 1, "searchable");
    drop(back);

    let mut back = Client::restore_from_server(&words, S1, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    assert!(
        back.notes()
            .unwrap()
            .iter()
            .any(|n| n.text == "buy oat milk")
    );

    // Off: the server's copy is deleted (by the device that holds the
    // words, the restored one now).
    back.set_server_backup(false).await.unwrap();
    assert!(
        Client::fetch_server_backup(&words, S1, Arc::new(net.clone()))
            .await
            .is_err()
    );
}
