//! On the record (`docs/05-ratchet.md` §9, RT-07): a mode change is an
//! authenticated event of the conversation itself, shown on both sides;
//! messages on the record carry their sender's device signature, which an
//! operator can check in a report (`docs/13-operators.md` §2).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Event, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_rpc::api::ReportReason;
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

fn mode_changes(events: &[Event]) -> Vec<([u8; 64], bool, bool)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::ModeChanged {
                root,
                on_record,
                by_us,
            } => Some((*root, *on_record, *by_us)),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn rt07_mode_switch_requires_authenticated_event() {
    let net = network();
    let new = |s, n| Client::create(memory(), Arc::new(net.clone()), s, n);
    let (mut ada, _) = new(S1, "Ada").await.unwrap();
    let (mut mo, _) = new(S2, "Mo").await.unwrap();
    let (mut kit, _) = new(S1, "Kit").await.unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut kit, &mut mo).await;

    // Kit's change reaches Mo through Kit's own session: it switches only
    // that conversation.
    kit.set_on_the_record(&mo.root(), true).await.unwrap();
    let ev = mo.sync().await.unwrap();
    assert_eq!(mode_changes(&ev), vec![(kit.root(), true, false)]);
    assert!(mo.on_the_record(&kit.root()));
    assert!(!mo.on_the_record(&ada.root()), "not Ada's conversation");

    // Ada puts theirs on the record. Mo writes before hearing of it: the
    // message arrives unsigned in a conversation on the record, and is
    // marked so.
    ada.set_on_the_record(&mo.root(), true).await.unwrap();
    assert!(ada.on_the_record(&mo.root()));
    mo.send_text(&ada.root(), "written before I knew")
        .await
        .unwrap();
    ada.sync().await.unwrap();
    let m = ada.messages(&mo.root()).unwrap().pop().unwrap();
    assert_eq!(m.text, "written before I knew");
    assert_eq!(m.signed, Some(false), "not signed");
    assert!(m.evidence.is_none());

    // Mo hears of it, shown as a change Ada made.
    let ev = mo.sync().await.unwrap();
    assert_eq!(mode_changes(&ev), vec![(ada.root(), true, false)]);
    assert!(mo.on_the_record(&ada.root()));

    // From now on what Mo writes is signed, and Ada checks it against Mo's
    // manifest.
    for t in ["one", "two", "three"] {
        let sent = mo.send_text(&ada.root(), t).await.unwrap();
        assert_eq!(sent.signed, Some(true));
    }
    ada.sync().await.unwrap();
    let got = ada.messages(&mo.root()).unwrap();
    let three = &got[got.len() - 3..];
    assert!(three.iter().all(|m| m.signed == Some(true)));
    assert!(three.iter().all(|m| m.evidence.is_some()));
    assert_eq!(three[2].text, "three");

    // A report carries the latest signatures; Mo's operator checks them.
    ada.report(&mo.root(), ReportReason::Abuse, 3)
        .await
        .unwrap();
    let verified = net
        .with_server(&S2, |s| {
            let r = s.take_reports().pop().expect("a report");
            assert!(r.body.on_record);
            assert_eq!(r.body.reported, Some(mo.root()));
            let mut tampered = r.clone();
            tampered.body.signed[0].counter += 1;
            assert!(
                s.verify_quotes(&tampered)[0].is_err(),
                "a changed quote doesn't verify"
            );
            s.verify_quotes(&r)
        })
        .unwrap();
    assert_eq!(
        verified,
        vec![Ok("two".to_string()), Ok("three".to_string())],
        "the latest two"
    );

    // Off again: Mo takes it off; Ada sees Mo did, and nothing is signed.
    mo.set_on_the_record(&ada.root(), false).await.unwrap();
    let ev = ada.sync().await.unwrap();
    assert_eq!(mode_changes(&ev), vec![(mo.root(), false, false)]);
    let sent = mo.send_text(&ada.root(), "off again").await.unwrap();
    assert_eq!(sent.signed, None);
    ada.sync().await.unwrap();
    let m = ada.messages(&mo.root()).unwrap().pop().unwrap();
    assert_eq!((m.text.as_str(), m.signed), ("off again", None));

    // An old change that arrives late (a re-send) changes nothing: the
    // later number wins.
    assert!(!ada.on_the_record(&mo.root()));
    assert!(!mo.on_the_record(&ada.root()));
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

/// An admin puts a group on the record: everyone sees who did; messages,
/// poll closes and later state updates carry signatures that every member
/// checks; only an admin can change it.
#[tokio::test(flavor = "multi_thread")]
async fn groups_on_the_record() {
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
    assert!(!mo.group_on_the_record(&gid));

    // Only an admin changes it.
    assert!(mo.set_group_on_the_record(&gid, true).await.is_err());
    ada.set_group_on_the_record(&gid, true).await.unwrap();
    assert!(ada.group_on_the_record(&gid));
    let ev = settle(&mut [&mut mo, &mut jo], 1).await;
    for e in &ev {
        assert!(
            e.iter().any(|e| matches!(
                e,
                Event::GroupModeChanged { group_id, on_record: true, by }
                    if *group_id == gid && *by == ada.root()
            )),
            "{e:?}"
        );
    }
    assert!(mo.group_on_the_record(&gid) && jo.group_on_the_record(&gid));

    // Messages are signed, and checked by every member.
    let sent = mo.send_group_text(&gid, "signed by Mo").await.unwrap();
    assert_eq!(sent.signed, Some(true));
    settle(&mut [&mut ada, &mut jo], 1).await;
    for c in [&ada, &jo] {
        let m = c.group_messages(&gid).unwrap().pop().unwrap();
        assert_eq!((m.text.as_str(), m.signed), ("signed by Mo", Some(true)));
    }

    // A poll close carries its creator's tally signature.
    let opts = ["Friday".to_string(), "Saturday".into()];
    let id = ada.create_poll(&gid, "When?", &opts).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    mo.vote(&gid, &id, 1).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    ada.close_poll(&gid, &id).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    for c in [&mo, &jo] {
        let p = c.poll(&gid, &id).unwrap();
        assert!(p.closed, "the signed close was accepted");
        assert_eq!(p.tally_agrees, Some(true));
    }

    // Taking it off is a state update signed by the admin.
    ada.set_group_on_the_record(&gid, false).await.unwrap();
    let ev = settle(&mut [&mut mo, &mut jo], 1).await;
    for e in &ev {
        assert!(
            e.iter().any(|e| matches!(
                e,
                Event::GroupModeChanged {
                    on_record: false,
                    ..
                }
            )),
            "{e:?}"
        );
    }
    let sent = jo.send_group_text(&gid, "deniable again").await.unwrap();
    assert_eq!(sent.signed, None);
    settle(&mut [&mut ada, &mut mo], 1).await;
    let m = mo.group_messages(&gid).unwrap().pop().unwrap();
    assert_eq!((m.text.as_str(), m.signed), ("deniable again", None));
}
