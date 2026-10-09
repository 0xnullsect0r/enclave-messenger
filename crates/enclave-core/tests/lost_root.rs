//! "Root lost, devices kept" (`docs/03-identity.md` §8.2): the recovery
//! words and the device that held them are gone, but a linked device makes
//! new words and moves the account to them. Contacts are told it can't be
//! confirmed by the old key; a group member who never hears it from them
//! sees the change on hold.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::client::HELD_MOVE_NOTICE_SECS;
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

async fn link(net: &LocalTransport, a: &mut Client) -> Client {
    let mut n = LinkingDevice::start(memory(), Arc::new(net.clone()), S1)
        .await
        .unwrap();
    let offer = a.link_prepare(&n.code()).await.unwrap();
    let LinkProgress::Words(words) = n.poll().await.unwrap() else {
        unreachable!("words come before the package")
    };
    let right = offer.choices.iter().position(|c| *c == words).unwrap();
    a.link_confirm(offer, right).await.unwrap();
    assert_eq!(n.poll().await.unwrap(), LinkProgress::Ready);
    n.finish().await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_linked_device_replaces_lost_words() {
    let net = network();
    let new = |s, n| Client::create(memory(), Arc::new(net.clone()), s, n);
    let (mut ada, _) = new(S1, "Ada").await.unwrap();
    let (mut ben, _) = new(S2, "Ben").await.unwrap();
    let (mut cy, _) = new(S2, "Cy").await.unwrap();
    connect(&mut ada, &mut ben).await;
    connect(&mut ben, &mut cy).await;
    let mut tab = link(&net, &mut ada).await;
    let gid = ben
        .create_group("Trip", &[ada.root(), cy.root()])
        .await
        .unwrap();
    for _ in 0..3 {
        for c in [&mut ben, &mut ada, &mut tab, &mut cy] {
            c.sync().await.unwrap();
        }
    }
    let old = ada.root();
    assert!(!tab.holds_recovery_words());
    // A device holding the words changes them the usual way instead.
    assert!(ada.replace_lost_root().await.is_err());
    drop(ada); // lost, and the words with it

    let words = tab.replace_lost_root().await.unwrap();
    assert_eq!(words.len(), 24);
    assert!(tab.holds_recovery_words(), "this device holds them now");
    let root = tab.root();
    assert_ne!(root, old);
    assert!(tab.replace_lost_root().await.is_err(), "it holds the words");

    // Ben gets it in their session: moved, but not confirmed by the old key.
    let ev = ben.sync().await.unwrap();
    assert!(
        ev.iter().any(|e| matches!(
            e,
            Event::ContactMoved { old: o, root: r, cross_signed: false } if *o == old && *r == root
        )),
        "{ev:?}"
    );
    assert!(!ben.moved(&root).unwrap().cross_signed);
    assert!(ben.contact(&root).is_some() && ben.contact(&old).is_none());

    // Cy can't fetch it (the file is withheld), so the group's update of
    // Ada's member entry stays on hold, and after an hour Cy is told.
    net.with_server(&S1, |s| s.blob_withhold(true)).unwrap();
    for _ in 0..3 {
        tab.sync().await.unwrap();
        cy.sync().await.unwrap();
        ben.sync().await.unwrap();
    }
    let info = |c: &Client| c.groups().into_iter().find(|g| g.id == gid).unwrap();
    assert!(info(&cy).held_moves.is_empty(), "not before the hour");
    net.advance(HELD_MOVE_NOTICE_SECS + 1);
    let ev = cy.sync().await.unwrap();
    assert!(
        ev.contains(&Event::GroupMoveHeld {
            group_id: gid,
            root: old
        }),
        "{ev:?}"
    );
    assert_eq!(info(&cy).held_moves, vec![old]);
    let ev = cy.sync().await.unwrap();
    assert!(
        !ev.iter().any(|e| matches!(e, Event::GroupMoveHeld { .. })),
        "told once"
    );
    // Ben, who had the migration, took the update.
    assert!(info(&ben).members.iter().any(|(r, _)| *r == root));
    assert!(info(&ben).held_moves.is_empty());

    // The conversation goes on under the new root.
    net.with_server(&S1, |s| s.blob_withhold(false)).unwrap();
    tab.send_text(&ben.root(), "new words, same me")
        .await
        .unwrap();
    let ev = ben.sync().await.unwrap();
    assert!(
        ev.iter().any(|e| matches!(
            e,
            Event::Message { root: r, message } if *r == root && message.text == "new words, same me"
        )),
        "{ev:?}"
    );
}
