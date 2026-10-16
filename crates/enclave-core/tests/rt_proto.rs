//! Red-team scenarios against the client engine (`docs/redteam-matrix.md`
//! RT-05, RT-06, RT-23, RT-26): a prekey directory replaying or drained, a
//! device clock set back, look-alike usernames.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, CoreError, Event, Options, UsernameError};
use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_net::transport::{ServerId, Transport};
use enclave_proto::envelope::request_initial;
use enclave_proto::eqxdh::PqPrekeyRef;
use enclave_rpc::api::{self, DirAction, DirKind, DirRequest, Status};
use enclave_server::db;
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use enclave_wire::{Op, RequestHeader};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
            Event::Request { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// Claim one bundle of `device` at `server`, with a fresh proof of work,
/// as anyone may: true if the server served one.
fn claim(net: &LocalTransport, server: &ServerId, device: &[u8; 16], rng: &mut HedgedRng) -> bool {
    let key = api::device_key(device);
    let now = net.now();
    let proof = enclave_tokens::solve(&api::pow_context_claim(&key, now / 86_400), 1, rng).unwrap();
    let req = DirRequest {
        kind: DirKind::Bundle,
        action: DirAction::Claim,
        key,
        index: 0,
        total: 0,
        proof: proof.0,
        data: vec![],
    };
    let env = api::frame(&req.encode(), rng).unwrap();
    let h = RequestHeader {
        op: Op::Directory,
        flags: 0,
        mailbox: [0; 32],
        token: [0; 32],
    };
    net.with_server(server, |s| {
        let (bytes, ex) =
            enclave_rpc::seal_request(&s.public_key().unwrap(), &h, &env, rng).unwrap();
        let (rh, _) = ex.open_reply(&s.handle(&bytes, now)).unwrap();
        Status::from_u8(rh.flags) == Status::Ok
    })
    .unwrap()
}

/// The devices whose prekeys `server` holds.
fn devices_at(net: &LocalTransport, server: &ServerId) -> Vec<[u8; 16]> {
    net.with_server(server, |s| {
        s.db()
            .read(|r| r.scan(db::BUNDLES, b""))
            .unwrap()
            .into_iter()
            .map(|(k, _)| k.try_into().unwrap())
            .collect()
    })
    .unwrap()
}

/// Someone claims every one-time prekey of every device at `server`.
fn drain(net: &LocalTransport, server: &ServerId, rng: &mut HedgedRng) {
    for dev in devices_at(net, server) {
        for _ in 0..enclave_proto::bundle::OPK_BATCH {
            assert!(claim(net, server, &dev, rng));
        }
    }
}

/// The request envelopes `server` holds: (storage key, stored value).
fn stored_requests(net: &LocalTransport, server: &ServerId) -> Vec<(Vec<u8>, Vec<u8>)> {
    net.with_server(server, |s| {
        s.db()
            .read(|r| r.scan(db::ENVELOPES, b""))
            .unwrap()
            .into_iter()
            .filter(|(_, v)| v.get(8..).is_some_and(|e| request_initial(e).is_ok()))
            .collect()
    })
    .unwrap()
}

/// Ada (on S1) greets Ben (on S2) after someone drained Ben's one-time
/// prekeys; returns the greeting as Ben's server stored it.
async fn greet_drained(net: &LocalTransport, ada: &mut Client, ben: &Client) -> (Vec<u8>, Vec<u8>) {
    let mut rng = HedgedRng::new().unwrap();
    drain(net, &S2, &mut rng);
    ada.add_contact(&ben.card(), "hi ben").await.unwrap();
    let mut stored = stored_requests(net, &S2);
    assert_eq!(stored.len(), 1);
    stored.pop().unwrap()
}

/// With every one-time prekey claimed, a greeting encapsulates to the
/// last-resort PQ prekey (rotated every 7 days) rather than the signed
/// prekey (14 days), and the conversation starts as usual (RT-06).
#[tokio::test(flavor = "multi_thread")]
async fn rt06_last_resort_used_when_drained() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    let (_, greeting) = greet_drained(&net, &mut ada, &ben).await;
    let msg = request_initial(&greeting[8..]).unwrap();
    assert!(
        matches!(msg.pq_prekey, PqPrekeyRef::LastResort(_)),
        "{:?}",
        msg.pq_prekey
    );

    let ev = ben.sync().await.unwrap();
    assert_eq!(texts(&ev), ["hi ben"]);
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    ben.send_text(&ada.root(), "hello ada").await.unwrap();
    let ev = ada.sync().await.unwrap();
    assert_eq!(texts(&ev), ["hello ada"]);
}

/// A prekey server that delivers the same greeting again, after the
/// conversation has moved on, changes nothing (RT-05): the greeting used
/// the last-resort prekey (one-time prekeys drained), which is still there,
/// so only the responder's replay cache stops it from starting the
/// session over.
#[tokio::test(flavor = "multi_thread")]
async fn rt05_replayed_initial_message_rejected() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    let (key, greeting) = greet_drained(&net, &mut ada, &ben).await;
    let ev = ben.sync().await.unwrap();
    assert_eq!(texts(&ev), ["hi ben"]);
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    ada.send_text(&ben.root(), "one").await.unwrap();
    assert_eq!(texts(&ben.sync().await.unwrap()), ["one"]);

    // The server puts the greeting back in Ben's request inbox, later in
    // the queue so Ben reads it again.
    let seq = u64::from_be_bytes(key[32..40].try_into().unwrap());
    let mut replayed = key[..32].to_vec();
    replayed.extend_from_slice(&(seq + 1_000).to_be_bytes());
    net.with_server(&S2, |s| {
        s.db()
            .write(|t| t.put(db::ENVELOPES, &replayed, &greeting))
            .unwrap();
    })
    .unwrap();
    let ev = ben.sync().await.unwrap();
    assert!(texts(&ev).is_empty(), "{ev:?}");
    let a = ada.root();
    let hellos = ben
        .messages(&a)
        .unwrap()
        .iter()
        .filter(|m| m.text == "hi ben")
        .count();
    assert_eq!(hellos, 1, "the greeting is not taken twice");

    // The session was not started over: both directions still work.
    ada.send_text(&ben.root(), "two").await.unwrap();
    assert_eq!(texts(&ben.sync().await.unwrap()), ["two"]);
    ben.send_text(&a, "three").await.unwrap();
    assert_eq!(texts(&ada.sync().await.unwrap()), ["three"]);
}

/// The local network with a device clock that can be set back.
struct Skewed {
    net: LocalTransport,
    back: AtomicU64,
}

#[async_trait::async_trait]
impl Transport for Skewed {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        self.net.exchange(server, request).await
    }
    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.net.server_key(server).await
    }
    fn now(&self) -> u64 {
        self.net.now() - self.back.load(Ordering::SeqCst)
    }
}

/// A disappearing message's timer, once started, runs on local monotonic
/// time (RT-23): setting the device clock back two hours right after
/// reading it doesn't keep the message around for two more hours.
#[tokio::test(flavor = "multi_thread")]
async fn rt23_disappearing_timer_uses_monotonic() {
    const TIMER: u32 = 4;
    let net = network();
    let clock = Arc::new(Skewed {
        net: net.clone(),
        back: AtomicU64::new(0),
    });
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), clock.clone(), S2, "Ben")
        .await
        .unwrap();
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    let a = ada.root();
    ada.set_timer(&ben.root(), TIMER).await.unwrap();
    ada.send_text(&ben.root(), "gone soon").await.unwrap();
    ben.sync().await.unwrap();
    let unread = |ben: &Client| {
        ben.messages(&a)
            .unwrap()
            .into_iter()
            .filter(|m| m.text == "gone soon")
            .collect::<Vec<_>>()
    };
    let m = unread(&ben);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].expires_secs, TIMER);
    assert_eq!(m[0].expires_at, None, "unread: the timer hasn't started");

    // Ben reads it, which starts the timer, and the clock goes back.
    let read_at = ben.now();
    ben.mark_read(&a).await.unwrap();
    clock.back.store(2 * 3600, Ordering::SeqCst);
    assert!(ben.now() + 3600 < read_at, "the device clock went back");
    tokio::time::sleep(std::time::Duration::from_secs(u64::from(TIMER) + 2)).await;
    let expires_at = read_at + u64::from(TIMER);
    assert!(
        ben.now() < expires_at,
        "by the device clock it hasn't expired"
    );
    assert!(unread(&ben).is_empty(), "but it has gone");
    ben.sync().await.unwrap();
    assert!(unread(&ben).is_empty(), "and stays gone");
    assert!(ben.messages(&a).unwrap().iter().any(|m| m.text == "hi"));
}

/// A name that looks like one already taken can't be registered, whether
/// by look-alike letters, case, width or another script; a name that
/// doesn't look like it can (RT-26).
#[tokio::test(flavor = "multi_thread")]
async fn rt26_confusable_username_rejected() {
    let net = network();
    let policy = net.enable_usernames(&S1, "one.test").unwrap();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ben")
        .await
        .unwrap();
    ada.set_kt_policy(policy.clone());
    ben.set_kt_policy(policy);
    assert_eq!(ada.claim_username("poe").await.unwrap(), "poe@one.test");

    let refused = |r: Result<String, CoreError>| match r {
        Err(CoreError::Username(e)) => e,
        other => panic!("{other:?}"),
    };
    for lookalike in [
        "p0e",    // a digit for a letter
        "POE",    // case
        "ｐｏｅ", // fullwidth
        "рое",    // all Cyrillic
        "poe_",   // a separator
    ] {
        assert_eq!(
            refused(ben.claim_username(lookalike).await),
            UsernameError::Taken,
            "{lookalike}"
        );
    }
    // Mixing scripts in one name is refused outright.
    assert_eq!(
        refused(ben.claim_username("pое").await),
        UsernameError::NotAllowed
    );
    assert_eq!(ben.username(), None);
    assert_eq!(ben.claim_username("ben").await.unwrap(), "ben@one.test");
    // Ada's own name is still hers to update.
    assert_eq!(ada.claim_username("poe").await.unwrap(), "poe@one.test");
}
