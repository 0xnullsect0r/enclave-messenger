//! A group's admins, and moving its mailboxes to another server by a
//! vote of its admins (`docs/07-groups.md` §4, §7.3).
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

async fn connect(a: &mut Client, b: &mut Client) {
    a.add_contact(&b.card(), "hi").await.unwrap();
    b.sync().await.unwrap();
    b.accept(&a.root()).await.unwrap();
    a.sync().await.unwrap();
}

async fn settle(clients: &mut [&mut Client], rounds: usize) -> Vec<Vec<Event>> {
    let mut all = vec![Vec::new(); clients.len()];
    for _ in 0..rounds {
        for (i, c) in clients.iter_mut().enumerate() {
            all[i].extend(c.sync().await.unwrap());
        }
    }
    all
}

fn texts(c: &Client, gid: &[u8; 32]) -> Vec<String> {
    c.group_messages(gid)
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn group_moves_by_admin_vote() {
    let net = network();
    let new = |s, n| Client::create(memory(), Arc::new(net.clone()), s, n);
    let (mut ada, _) = new(S1, "Ada").await.unwrap();
    let (mut mo, _) = new(S2, "Mo").await.unwrap();
    let (mut jo, _) = new(S1, "Jo").await.unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let gid = ada
        .create_group("Trip", &[mo.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;
    let info = |c: &Client| c.groups().into_iter().find(|g| g.id == gid).unwrap();
    assert_eq!(info(&mo).host, S1, "on the creator's server");

    // Only an admin makes admins; Ada makes Mo one.
    assert!(jo.set_group_admin(&gid, &mo.root(), true).await.is_err());
    ada.set_group_admin(&gid, &mo.root(), true).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 1).await;
    for c in [&ada, &mo, &jo] {
        assert_eq!(info(c).admins.len(), 2);
    }

    // One of two admins is no majority; a non-admin's vote is refused.
    assert!(jo.vote_group_host(&gid, S2).await.is_err());
    ada.vote_group_host(&gid, S2).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 1).await;
    assert_eq!(info(&jo).host, S1);

    // Mo's vote makes the majority: the group moves from tomorrow.
    mo.vote_group_host(&gid, S2).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 1).await;
    for c in [&ada, &mo, &jo] {
        assert_eq!(info(c).host, S1, "today's mailboxes stay");
    }
    jo.send_group_text(&gid, "still today").await.unwrap();
    settle(&mut [&mut ada, &mut mo], 1).await;
    assert!(texts(&mo, &gid).contains(&"still today".to_string()));

    // Tomorrow everyone writes and reads on the new server.
    net.advance(86_400);
    for c in [&ada, &mo, &jo] {
        assert_eq!(info(c).host, S2);
    }
    let before = net.with_server(&S2, |s| s.stats().stored).unwrap();
    ada.send_group_text(&gid, "on the new server")
        .await
        .unwrap();
    assert!(net.with_server(&S2, |s| s.stats().stored).unwrap() > before);
    settle(&mut [&mut mo, &mut jo], 2).await;
    for c in [&mo, &jo] {
        assert!(texts(c, &gid).contains(&"on the new server".to_string()));
    }
}

/// Two people who meet through a group start on two KEMs (no 1.36 MB
/// vault key per member); the vault key comes later and the braid adds the
/// third, at the latest 7 days in on a metered network
/// (`docs/04-eqxdh.md` §7).
#[tokio::test(flavor = "multi_thread")]
async fn group_only_peers_braid_within_seven_days() {
    let net = network();
    let new = |s, n| Client::create(memory(), Arc::new(net.clone()), s, n);
    let (mut ada, _) = new(S1, "Ada").await.unwrap();
    let (mut mo, _) = new(S2, "Mo").await.unwrap();
    let (mut jo, _) = new(S1, "Jo").await.unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    mo.set_metered(true);
    jo.set_metered(true);
    ada.create_group("Trip", &[mo.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 4).await;
    // Whoever introduced themselves first holds two-KEM sessions and waits.
    let (mo_r, jo_r) = (mo.root(), jo.root());
    assert!(mo.contact(&jo_r).is_some() && jo.contact(&mo_r).is_some());
    assert!(mo.braid_pending(&jo_r) || jo.braid_pending(&mo_r));
    assert!(!mo.fully_protected(&jo_r) && !jo.fully_protected(&mo_r));

    // Metered: still waiting after six days…
    net.advance(6 * 86_400);
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    assert!(mo.braid_pending(&jo_r) || jo.braid_pending(&mo_r));

    // …and done past the deadline: both hold all three KEMs.
    net.advance(86_400 + 60);
    settle(&mut [&mut mo, &mut jo], 4).await;
    assert!(!mo.braid_pending(&jo_r) && !jo.braid_pending(&mo_r));
    assert!(mo.fully_protected(&jo_r), "Mo");
    assert!(jo.fully_protected(&mo_r), "Jo");
}
