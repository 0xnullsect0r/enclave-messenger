//! "Secure my account" (`docs/03-identity.md` §5.2): after removing a
//! device, the account's identity and vault keys, inboxes, request inbox
//! and prekeys are replaced, every contact takes a PQ step and every group
//! is rekeyed, and nothing stops working.
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

fn texts(ev: &[Event]) -> Vec<String> {
    ev.iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(message.text.clone()),
            Event::GroupMessage { message, .. } => Some(message.text.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn securing_an_account() {
    let net = network();
    let new = |s, n| Client::create(memory(), Arc::new(net.clone()), s, n);
    let (mut ada, _) = new(S1, "Ada").await.unwrap();
    let (mut ben, _) = new(S2, "Ben").await.unwrap();
    let (mut cy, _) = new(S2, "Cy").await.unwrap();
    connect(&mut ada, &mut ben).await;
    let mut tab = link(&net, &mut ada).await;
    let lost = link(&net, &mut ada).await;
    let trip = ada.create_group("Trip", &[ben.root()]).await.unwrap();
    for _ in 0..3 {
        for c in [&mut ada, &mut tab, &mut ben] {
            c.sync().await.unwrap();
        }
    }
    let old_card = ada.card();
    let old_identity = ada.identity_public();
    let code = ben.security_code(&ada.root());

    // A device was lost: remove it, then secure the account.
    let lost_id = ada
        .devices()
        .into_iter()
        .find(|d| {
            !d.this_device && d.id != tab.devices().iter().find(|t| t.this_device).unwrap().id
        })
        .unwrap()
        .id;
    ada.remove_device(&lost_id).await.unwrap();
    drop(lost);
    assert!(tab.secure_account().await.is_err(), "only with the words");
    ada.secure_account().await.unwrap();
    assert!(ada.securing());
    for _ in 0..4 {
        for c in [&mut ada, &mut tab, &mut ben] {
            c.sync().await.unwrap();
        }
    }
    assert!(!ada.securing() && !ada.move_pending());
    assert_ne!(ada.identity_public(), old_identity);
    assert_eq!(
        tab.identity_public(),
        ada.identity_public(),
        "the tablet has them"
    );
    let card = ada.card();
    assert_eq!(card.server, old_card.server);
    assert_ne!(card.request_inbox, old_card.request_inbox);
    assert_ne!(card.vault_locator, old_card.vault_locator);
    assert_eq!(ben.security_code(&ada.root()), code, "the code stays");

    // Nothing stopped working, for either of Ada's devices.
    ben.send_text(&ada.root(), "still there?").await.unwrap();
    assert_eq!(texts(&ada.sync().await.unwrap()), ["still there?"]);
    for _ in 0..3 {
        tab.sync().await.unwrap();
        ben.sync().await.unwrap();
    }
    assert!(
        tab.messages(&ben.root())
            .unwrap()
            .iter()
            .any(|m| m.text == "still there?")
    );
    ada.send_text(&ben.root(), "yes").await.unwrap();
    assert!(texts(&ben.sync().await.unwrap()).contains(&"yes".to_string()));
    ben.send_group_text(&trip, "group still works")
        .await
        .unwrap();
    for _ in 0..2 {
        ada.sync().await.unwrap();
        tab.sync().await.unwrap();
    }
    assert!(
        ada.group_messages(&trip)
            .unwrap()
            .iter()
            .any(|m| m.text == "group still works")
    );

    // Someone new reaches her with her new card and keys.
    cy.add_contact(&card, "hello").await.unwrap();
    let ev = ada.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { root, .. } if *root == cy.root())),
        "{ev:?}"
    );
    ada.accept(&cy.root()).await.unwrap();
    cy.sync().await.unwrap();
    cy.send_text(&ada.root(), "hi Ada").await.unwrap();
    assert_eq!(texts(&ada.sync().await.unwrap()), ["hi Ada"]);
}
