//! Deleting an account (`docs/03-identity.md` §8.5): contacts and groups are
//! told, the server forgets the account and its inboxes, and the account's
//! other devices erase themselves.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Event, LinkProgress, LinkingDevice, Options};
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

async fn connect(a: &mut Client, b: &mut Client) {
    a.add_contact(&b.card(), "hi").await.unwrap();
    b.sync().await.unwrap();
    b.accept(&a.root()).await.unwrap();
    a.sync().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_an_account() {
    let net = network();
    let new = |s, n| Client::create(memory(), Arc::new(net.clone()), s, n);
    let (mut ada, _) = new(S1, "Ada").await.unwrap();
    let (mut ben, _) = new(S2, "Ben").await.unwrap();
    let (mut cy, _) = new(S2, "Cy").await.unwrap();
    connect(&mut ada, &mut ben).await;
    connect(&mut ben, &mut cy).await;
    let mut n = LinkingDevice::start(memory(), Arc::new(net.clone()), S1)
        .await
        .unwrap();
    let offer = ada.link_prepare(&n.code()).await.unwrap();
    let LinkProgress::Words(words) = n.poll().await.unwrap() else {
        unreachable!("words come before the package")
    };
    let right = offer.choices.iter().position(|c| *c == words).unwrap();
    ada.link_confirm(offer, right).await.unwrap();
    assert_eq!(n.poll().await.unwrap(), LinkProgress::Ready);
    let mut tab = n.finish().await.unwrap();
    let gid = ben
        .create_group("Trip", &[ada.root(), cy.root()])
        .await
        .unwrap();
    for _ in 0..3 {
        for c in [&mut ben, &mut ada, &mut tab, &mut cy] {
            c.sync().await.unwrap();
        }
    }
    let root = ada.root();
    let (inboxes, vaults) = net.with_server(&S1, |s| s.inboxes_held()).unwrap();
    assert!(inboxes >= 2 && vaults >= 1);

    // Only a device holding the words can delete the account.
    assert!(tab.delete_account().await.is_err());
    ada.delete_account().await.unwrap();
    // Each step is safe to repeat.
    ada.delete_account().await.unwrap();
    ada.erase().unwrap();
    let (after, vaults_after) = net.with_server(&S1, |s| s.inboxes_held()).unwrap();
    assert!(after < inboxes, "her inboxes are gone");
    assert_eq!(vaults_after, vaults - 1, "and her vault-key blob");

    // Ben sees she closed her account, and she left the group.
    let ev = ben.sync().await.unwrap();
    assert!(ev.contains(&Event::ContactClosed { root }), "{ev:?}");
    assert!(ben.is_closed(&root));
    for c in [&mut ben, &mut cy] {
        c.sync().await.unwrap();
        let g = c.groups().into_iter().find(|g| g.id == gid).unwrap();
        assert!(!g.members.iter().any(|(r, _)| *r == root));
    }
    // A new contact request to her account goes nowhere: the server holds
    // its tombstone and no manifest.
    assert!(cy.find_username("ada@one.test").await.is_err());

    // Her tablet finds the tombstone at its next check and is told once.
    net.advance(601);
    let ev = tab.sync().await.unwrap();
    assert!(ev.contains(&Event::AccountDeleted), "{ev:?}");
    assert!(tab.account_deleted());
    net.advance(601);
    let ev = tab.sync().await.unwrap();
    assert!(!ev.contains(&Event::AccountDeleted));
}
