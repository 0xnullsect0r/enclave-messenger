//! An account's devices kept in step (`docs/06-multidevice.md` §4–§6):
//! the self-copy written even with one device, contacts, read state and
//! conversation settings carried to the other devices, the inbox
//! acknowledged once every device has read it, and a device that went
//! quiet taken off the account.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::client::INACTIVE_SECS;
use enclave_core::{Client, ConvPrefs, Event, LinkProgress, LinkingDevice, Options, Place};
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
            effort_blob: 1,
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

fn stored(net: &LocalTransport, s: [u8; 16]) -> u64 {
    net.with_server(&s, |s| s.stats().stored).unwrap()
}

fn held(net: &LocalTransport, s: [u8; 16]) -> usize {
    net.with_server(&s, |s| s.envelopes_held()).unwrap()
}

/// A single-device account still writes a self-copy for each message (a
/// cover envelope), and acknowledges its inbox as soon as it has read it.
#[tokio::test(flavor = "multi_thread")]
async fn one_device_self_copy_and_watermark() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut ada, &mut ben).await;
    ada.sync().await.unwrap();
    let a = ada.root();
    // Each of Ben's messages: one write to Ada's inbox (S1) and one cover
    // self-copy to his own (S2).
    let (s1, s2) = (stored(&net, S1), stored(&net, S2));
    ben.send_text(&a, "one").await.unwrap();
    ben.send_text(&a, "two").await.unwrap();
    assert_eq!(stored(&net, S1) - s1, 2);
    assert_eq!(stored(&net, S2) - s2, 2, "the self-copies");
    // Ada reads them, and the server drops them: she has no other device.
    assert!(held(&net, S1) >= 2);
    ada.sync().await.unwrap();
    assert_eq!(held(&net, S1), 0, "acknowledged once read");
}

#[tokio::test(flavor = "multi_thread")]
async fn own_devices_stay_in_step() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    let (mut cy, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Cy")
        .await
        .unwrap();
    connect(&mut ada, &mut ben).await;
    let mut ada2 = link(&net, &mut ada).await;
    ben.sync().await.unwrap();
    ada.sync().await.unwrap();
    ada2.sync().await.unwrap();
    assert!(
        ada.own_devices().iter().all(|d| d.new && !d.inactive),
        "a new device, pointed out for a week"
    );

    // A contact made on one device appears on the other, which greets it
    // from its own device and can write to it.
    connect(&mut ada, &mut cy).await;
    let ev = ada2.sync().await.unwrap();
    assert!(ev.contains(&Event::Synced), "{ev:?}");
    assert!(ada2.contacts().iter().any(|c| c.root == cy.root()));
    cy.sync().await.unwrap();
    ada2.send_text(&cy.root(), "from the other device")
        .await
        .unwrap();
    let got = cy.sync().await.unwrap();
    assert!(
        got.iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "from the other device")
        ),
        "{got:?}"
    );

    // Read on one device: read on the other. Archived on one: on the other.
    let b = ben.root();
    ben.send_text(&ada.root(), "hello both").await.unwrap();
    ada.sync().await.unwrap();
    ada2.sync().await.unwrap();
    assert!(ada2.contacts().iter().any(|c| c.root == b && c.unread == 1));
    ada.mark_read(&b).await.unwrap();
    ada.set_conv_prefs(
        &Place::Contact(b),
        ConvPrefs {
            archived: true,
            ..Default::default()
        },
    )
    .unwrap();
    ada.sync().await.unwrap();
    ada2.sync().await.unwrap();
    assert!(ada2.contacts().iter().any(|c| c.root == b && c.unread == 0));
    assert!(ada2.conv_prefs(&Place::Contact(b)).archived);

    // The inbox is acknowledged only as far as both devices have read.
    ben.send_text(&ada.root(), "kept for the other")
        .await
        .unwrap();
    ada.sync().await.unwrap();
    ada.sync().await.unwrap();
    let before = held(&net, S1);
    assert!(before >= 1, "the other device hasn't read it");
    ada2.sync().await.unwrap();
    ada.sync().await.unwrap();
    assert!(held(&net, S1) < before, "read by both: dropped");

    // The second device goes quiet for a month: nothing is encrypted to it
    // and the first device takes it off the account.
    let ada2_id = ada2.devices().iter().find(|d| d.this_device).unwrap().id;
    net.advance(INACTIVE_SECS + 86_400);
    ben.sync().await.unwrap();
    let ev = ada.sync().await.unwrap();
    assert!(ev.contains(&Event::DevicesChanged), "{ev:?}");
    assert!(ada.devices().iter().all(|d| d.id != ada2_id));
}

/// A group made on one device reaches the other: it reads what members
/// send, and what it sends shows on the first device as our own.
#[tokio::test(flavor = "multi_thread")]
async fn groups_on_every_device() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut ada, &mut ben).await;
    let mut ada2 = link(&net, &mut ada).await;
    ben.sync().await.unwrap();
    ada.sync().await.unwrap();
    ada2.sync().await.unwrap();

    let gid = ada.create_group("Club", &[ben.root()]).await.unwrap();
    ben.sync().await.unwrap();
    ada.sync().await.unwrap();
    let ev = ada2.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::GroupJoined { group_id, .. } if *group_id == gid)),
        "{ev:?}"
    );

    // A member writes: both of Ada's devices read it.
    ben.send_group_text(&gid, "hi all").await.unwrap();
    ada.sync().await.unwrap();
    ada2.sync().await.unwrap();
    for c in [&ada, &ada2] {
        assert!(
            c.group_messages(&gid)
                .unwrap()
                .iter()
                .any(|m| m.text == "hi all" && m.from == Some(ben.root())),
            "every device of ours reads members"
        );
    }

    // The second device writes: the member reads it. The first device holds
    // it (no MAC vouches for our own account) until the second one, at its
    // next sync, confirms it sent it; then it shows as ours.
    ada2.send_group_text(&gid, "from my phone").await.unwrap();
    ben.sync().await.unwrap();
    ada.sync().await.unwrap();
    assert!(
        !ada.group_messages(&gid)
            .unwrap()
            .iter()
            .any(|m| m.text == "from my phone"),
        "not shown on the mailbox's word alone"
    );
    ada2.sync().await.unwrap();
    ada.sync().await.unwrap();
    assert!(
        ben.group_messages(&gid)
            .unwrap()
            .iter()
            .any(|m| m.text == "from my phone" && m.from == Some(ada.root()))
    );
    assert!(
        ada.group_messages(&gid)
            .unwrap()
            .iter()
            .any(|m| m.text == "from my phone" && m.from.is_none()),
        "our own, from another device"
    );
}

/// A text too long for one envelope goes in continuation units, to the
/// contact and as the self-copy to our other device, and arrives whole.
#[tokio::test(flavor = "multi_thread")]
async fn long_text_in_parts() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut ada, &mut ben).await;
    let mut ada2 = link(&net, &mut ada).await;
    ben.sync().await.unwrap();
    ada.sync().await.unwrap();
    ada2.sync().await.unwrap();
    let long: String = "Lorem ipsum dolor sit amet. ".repeat(1_000);
    assert!(long.len() > 20_000);
    let before = stored(&net, S2);
    ada.send_text(&ben.root(), &long).await.unwrap();
    assert!(stored(&net, S2) - before >= 3, "several units");
    let got = ben.sync().await.unwrap();
    assert!(
        got.iter()
            .any(|e| matches!(e, Event::Message { message, .. } if message.text == long)),
        "arrives whole"
    );
    ada2.sync().await.unwrap();
    assert!(
        ada2.messages(&ben.root())
            .unwrap()
            .iter()
            .any(|m| m.outgoing && m.text == long),
        "the self-copy too"
    );
}
