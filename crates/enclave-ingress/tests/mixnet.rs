//! A client reaches a real server through the in-process mixnet and the
//! ingress (`docs/09-transport.md` §1): key bundle, inbox, write and poll,
//! replies matched to requests under delay and reordering, a lost request
//! failing in time, garbage dropped, a dead server reported.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::KeyBundle;
use enclave_ingress::{Stats, serve};
use enclave_net::NetError;
use enclave_net::transport::{NymTransport, Transport};
use enclave_nym::MixnetDriver;
use enclave_nym::fake::{FakeMixnet, Faults};
use enclave_rpc::api::{self, FLAG_CREATE, FLAG_FOUND, Status};
use enclave_rpc::{seal_poll, seal_request};
use enclave_server::{Config, Server};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A server with a real identity behind the stack's TCP framing.
async fn spawn_server() -> (std::net::SocketAddr, [u8; 16]) {
    let mut rng = HedgedRng::new().unwrap();
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let id = enclave_federation::server_id(identity.public());
    let mut server = Server::new(
        Config {
            id,
            effort_inbox: 0,
            ..Config::default()
        },
        (now() / 86_400) as u32,
    )
    .unwrap();
    let key = server.public_key().unwrap();
    server.set_key_bundle(
        KeyBundle::sign(&identity, &[key], &mut rng)
            .unwrap()
            .encode(),
    );
    let server = Arc::new(Mutex::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
                sock.read_exact(&mut buf).await.unwrap();
                let reply = {
                    let mut s = server.lock().await;
                    if buf.is_empty() {
                        s.key_bundle().to_vec()
                    } else {
                        s.handle(&buf, now())
                    }
                };
                sock.write_all(&(reply.len() as u32).to_be_bytes())
                    .await
                    .unwrap();
                sock.write_all(&reply).await.unwrap();
            });
        }
    });
    (addr, id)
}

#[tokio::test(flavor = "multi_thread")]
async fn through_the_mixnet_to_a_server() {
    let (addr, id) = spawn_server().await;
    let net = FakeMixnet::new(
        Faults {
            loss: 0.0,
            max_delay: Duration::from_millis(30),
        },
        42,
    );
    let ingress: Arc<dyn MixnetDriver> = Arc::new(net.client("ingress-a"));
    let stats = Arc::new(Stats::default());
    tokio::spawn(serve(Arc::clone(&ingress), addr, Arc::clone(&stats)));
    let t = Arc::new(NymTransport::new(
        Arc::new(net.client("phone")),
        HashMap::from([(id, "ingress-a".to_string())]),
        Duration::from_secs(10),
    ));

    // The key bundle, checked against the server's id.
    let key = t.server_key(&id).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();

    // Create an inbox, write to it, read it back.
    let owner = [3u8; 32];
    let mailbox = [4u8; 32];
    let call = |h: RequestHeader, env: Vec<u8>, rng: &mut HedgedRng| {
        let (bytes, ex) = if matches!(h.op, Op::Poll) {
            seal_poll(&key, &h, rng).unwrap()
        } else {
            seal_request(&key, &h, &env, rng).unwrap()
        };
        let t = Arc::clone(&t);
        async move {
            let reply = t.exchange(&id, bytes).await.unwrap();
            ex.open_reply(&reply).unwrap()
        }
    };
    let create = RequestHeader {
        op: Op::RegisterTokens,
        flags: FLAG_CREATE,
        mailbox,
        token: owner,
    };
    let (rh, _) = call(create, api::frame(&[], &mut rng).unwrap(), &mut rng).await;
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);
    let token = [5u8; 32];
    let reg = RequestHeader {
        op: Op::RegisterTokens,
        flags: 0,
        mailbox,
        token: owner,
    };
    let hashes = enclave_tokens::token_hash(&token, &mailbox).to_vec();
    let (rh, _) = call(reg, api::frame(&hashes, &mut rng).unwrap(), &mut rng).await;
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);
    let envelope = vec![0x42; ENVELOPE_LEN];
    let write = RequestHeader {
        op: Op::Write,
        flags: 0,
        mailbox,
        token,
    };
    let (rh, _) = call(write, envelope.clone(), &mut rng).await;
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);

    // Twenty polls at once over a network that reorders: each reply
    // reaches the request it answers.
    let mut cred = [0u8; 32];
    cred[..24].copy_from_slice(&api::read_credential(&owner));
    let poll = RequestHeader {
        op: Op::Poll,
        flags: 0,
        mailbox,
        token: cred,
    };
    let mut polls = Vec::new();
    for _ in 0..20 {
        polls.push(call(poll, Vec::new(), &mut rng));
    }
    for (rh, env) in futures_join_all(polls).await {
        assert_eq!(Status::from_u8(rh.flags), Status::Ok);
        assert!(rh.flags & FLAG_FOUND != 0);
        assert_eq!(env, envelope);
    }
    assert_eq!(t.in_flight(), 0);
    assert_eq!(stats.answered.load(Ordering::Relaxed), 24);

    // Garbage, or a frame without reply blocks, is dropped.
    let other = net.client("prober");
    other.send("ingress-a", vec![1, 2, 3], 1000).await.unwrap();
    other.send("ingress-a", vec![0; 2066], 0).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stats.dropped.load(Ordering::Relaxed), 2);

    // A network that loses everything: the request fails in time, and
    // nothing is left waiting.
    net.set_faults(Faults {
        loss: 1.0,
        ..Faults::default()
    });
    let lossy = NymTransport::new(
        Arc::new(net.client("phone-2")),
        HashMap::from([(id, "ingress-a".to_string())]),
        Duration::from_millis(300),
    );
    assert!(matches!(
        lossy.server_key(&id).await,
        Err(NetError::Unreachable(_))
    ));
    assert_eq!(lossy.in_flight(), 0);
    net.set_faults(Faults::default());

    // No route, no request.
    assert!(matches!(
        t.server_key(&[9; 16]).await,
        Err(NetError::Unreachable(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dead_server_is_reported() {
    let net = FakeMixnet::default();
    let ingress: Arc<dyn MixnetDriver> = Arc::new(net.client("ingress-b"));
    // Nothing listens there.
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let stats = Arc::new(Stats::default());
    tokio::spawn(serve(ingress, dead, Arc::clone(&stats)));
    let t = NymTransport::new(
        Arc::new(net.client("phone")),
        HashMap::from([([1; 16], "ingress-b".to_string())]),
        Duration::from_secs(5),
    );
    let err = t.exchange(&[1; 16], vec![0; enclave_wire::POLL_LEN]).await;
    assert!(matches!(err, Err(NetError::Unreachable(m)) if m.contains("couldn't reach")));
    assert_eq!(stats.failed.load(Ordering::Relaxed), 1);
}

/// Await futures concurrently (no extra dependency).
async fn futures_join_all<F>(fs: Vec<F>) -> Vec<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let handles: Vec<_> = fs.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

/// Wakes go from a server's push egress to a push relay's ingress one way
/// through the mixnet, each intact and with no reply blocks; anything else
/// reaching the relay's ingress is dropped (`docs/10-push.md`).
#[tokio::test(flavor = "multi_thread")]
async fn wakes_cross_the_mixnet_one_way() {
    use enclave_ingress::{forward, oneway};
    // The push relay: collects what it's handed.
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = relay.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut len = [0u8; 4];
                while sock.read_exact(&mut len).await.is_ok() {
                    let mut b = vec![0u8; u32::from_be_bytes(len) as usize];
                    sock.read_exact(&mut b).await.unwrap();
                    tx.send(b).unwrap();
                }
            });
        }
    });
    let net = FakeMixnet::default();
    let ingress_stats = Arc::new(Stats::default());
    tokio::spawn(oneway(
        Arc::new(net.client("push-ingress")),
        relay_addr,
        Arc::clone(&ingress_stats),
    ));
    let egress = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let egress_addr = egress.local_addr().unwrap();
    let egress_stats = Arc::new(Stats::default());
    tokio::spawn(forward(
        Arc::new(net.client("egress")),
        egress,
        Arc::new(vec!["push-ingress".into()]),
        Arc::clone(&egress_stats),
    ));

    // The server's forwarder: two wakes on one connection.
    let wakes = [vec![1u8; 1_952], vec![2u8; 1_952]];
    let mut s = tokio::net::TcpStream::connect(egress_addr).await.unwrap();
    for w in &wakes {
        s.write_all(&(w.len() as u32).to_be_bytes()).await.unwrap();
        s.write_all(w).await.unwrap();
    }
    let mut got = Vec::new();
    for _ in 0..2 {
        got.push(
            tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    got.sort();
    assert_eq!(got, wakes.to_vec());
    assert_eq!(egress_stats.answered.load(Ordering::Relaxed), 2);

    // A request (or anything else) sent to the relay's ingress goes nowhere.
    let stranger = net.client("stranger");
    stranger
        .send("push-ingress", vec![0u8; 3_074], 0)
        .await
        .unwrap();
    let poll = enclave_nym::frame::Request::for_sealed([1; 16], vec![0; 2_048])
        .unwrap()
        .encode();
    stranger.send("push-ingress", poll, 100).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(rx.try_recv().is_err());
    assert_eq!(ingress_stats.dropped.load(Ordering::Relaxed), 2);
    assert_eq!(ingress_stats.answered.load(Ordering::Relaxed), 2);
}

/// A write sent one way carries no reply blocks: the ingress hands it to
/// the server and drops the answer, nothing comes back over the mixnet, and
/// the envelope is there for the owner's next poll (`docs/09-transport.md`
/// §6.1).
#[tokio::test(flavor = "multi_thread")]
async fn writes_go_one_way() {
    let (addr, id) = spawn_server().await;
    let net = FakeMixnet::default();
    let stats = Arc::new(Stats::default());
    tokio::spawn(serve(
        Arc::new(net.client("ingress-a")),
        addr,
        Arc::clone(&stats),
    ));
    let t = Arc::new(NymTransport::new(
        Arc::new(net.client("phone")),
        HashMap::from([(id, "ingress-a".to_string())]),
        Duration::from_secs(10),
    ));
    let key = t.server_key(&id).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let (owner, mailbox, token) = ([3u8; 32], [4u8; 32], [5u8; 32]);
    let ok = |reply: Vec<u8>, ex: enclave_rpc::Exchange| {
        let (rh, body) = ex.open_reply(&reply).unwrap();
        assert_eq!(Status::from_u8(rh.flags), Status::Ok);
        (rh, body)
    };
    for (flags, body) in [
        (FLAG_CREATE, Vec::new()),
        (0, enclave_tokens::token_hash(&token, &mailbox).to_vec()),
    ] {
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags,
            mailbox,
            token: owner,
        };
        let (bytes, ex) =
            seal_request(&key, &h, &api::frame(&body, &mut rng).unwrap(), &mut rng).unwrap();
        ok(t.exchange(&id, bytes).await.unwrap(), ex);
    }
    let replies_before = net.stats().replies;

    let envelope = vec![0x24; ENVELOPE_LEN];
    let write = RequestHeader {
        op: Op::Write,
        flags: 0,
        mailbox,
        token,
    };
    let (bytes, _) = seal_request(&key, &write, &envelope, &mut rng).unwrap();
    assert_eq!(t.exchange_oneway(&id, bytes).await.unwrap(), None);
    for _ in 0..100 {
        if stats.oneway.load(Ordering::Relaxed) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(stats.oneway.load(Ordering::Relaxed), 1);
    assert_eq!(net.stats().replies, replies_before, "nothing came back");

    let mut cred = [0u8; 32];
    cred[..24].copy_from_slice(&api::read_credential(&owner));
    let poll = RequestHeader {
        op: Op::Poll,
        flags: 0,
        mailbox,
        token: cred,
    };
    let (bytes, ex) = seal_poll(&key, &poll, &mut rng).unwrap();
    let (rh, env) = ok(t.exchange(&id, bytes).await.unwrap(), ex);
    assert!(rh.flags & FLAG_FOUND != 0);
    assert_eq!(env, envelope);
}

/// A request whose answer is needed goes one way too, marked
/// `FLAG_DEFER`: its answer comes back through a poll-sized status poll
/// (`Op::Status`, keyed by the request's own status id), once, so every
/// unit on the wire looks alike (`docs/09-transport.md` §6.1).
#[tokio::test(flavor = "multi_thread")]
async fn deferred_answers_come_back_through_status_polls() {
    let (addr, id) = spawn_server().await;
    let net = FakeMixnet::default();
    let stats = Arc::new(Stats::default());
    tokio::spawn(serve(
        Arc::new(net.client("ingress-a")),
        addr,
        Arc::clone(&stats),
    ));
    let t = Arc::new(NymTransport::new(
        Arc::new(net.client("phone")),
        HashMap::from([(id, "ingress-a".to_string())]),
        Duration::from_secs(10),
    ));
    let key = t.server_key(&id).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let status = |status_id: [u8; 32], rng: &mut HedgedRng| {
        let h = RequestHeader {
            op: Op::Status,
            flags: 0,
            mailbox: status_id,
            token: [9; 32],
        };
        let (bytes, ex) = seal_poll(&key, &h, rng).unwrap();
        let t = Arc::clone(&t);
        async move {
            let reply = t.exchange(&id, bytes).await.unwrap();
            ex.open_reply(&reply).unwrap()
        }
    };

    // Create an inbox, one way.
    let create = RequestHeader {
        op: Op::RegisterTokens,
        flags: FLAG_CREATE | api::FLAG_DEFER,
        mailbox: [4; 32],
        token: [3; 32],
    };
    let (bytes, ex) =
        seal_request(&key, &create, &api::frame(&[], &mut rng).unwrap(), &mut rng).unwrap();
    assert_eq!(t.exchange_oneway(&id, bytes).await.unwrap(), None);
    let mut answer = None;
    for _ in 0..100 {
        let (rh, _) = status(ex.status_id(), &mut rng).await;
        if !(rh.op == Op::Status && Status::from_u8(rh.flags) == Status::NotFound) {
            answer = Some(rh);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let rh = answer.expect("the answer arrives");
    assert_eq!(rh.op, Op::RegisterTokens);
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);

    // Fetched once; an id nobody made finds nothing.
    let (rh, _) = status(ex.status_id(), &mut rng).await;
    assert_eq!(
        (rh.op, Status::from_u8(rh.flags)),
        (Op::Status, Status::NotFound)
    );
    let (rh, _) = status([0x55; 32], &mut rng).await;
    assert_eq!(Status::from_u8(rh.flags), Status::NotFound);
}

/// Two people on one server reached only through its ingress over the
/// mixnet: account creation, a first-contact request, accepting, talking
/// and delivery receipts, with every unit sent one way and every answer
/// fetched by a status poll.
#[tokio::test(flavor = "multi_thread")]
async fn clients_over_the_mixnet() {
    use enclave_core::{Client, Event, Options};
    let (addr, id) = spawn_server().await;
    let net = FakeMixnet::new(
        Faults {
            loss: 0.0,
            max_delay: Duration::from_millis(20),
        },
        7,
    );
    tokio::spawn(serve(
        Arc::new(net.client("ingress-a")),
        addr,
        Arc::new(Stats::default()),
    ));
    let transport = |name: &str| -> Arc<dyn Transport> {
        Arc::new(NymTransport::new(
            Arc::new(net.client(name)),
            HashMap::from([(id, "ingress-a".to_string())]),
            Duration::from_secs(10),
        ))
    };
    let opts = || Options {
        path: None,
        keystore: Arc::new(enclave_store::MemoryKeystore::default()),
        passphrase: None,
        pw_params: enclave_crypto::pwhash::PwParams::FLOOR,
    };
    let replies_at_start = net.stats().replies;
    let (mut ada, _) = Client::create(opts(), transport("ada"), id, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(opts(), transport("ben"), id, "Ben")
        .await
        .unwrap();
    ada.add_contact(&ben.card(), "hi Ben").await.unwrap();
    let ev = ben.sync().await.unwrap();
    assert!(
        ev.iter().any(|e| matches!(e, Event::Request { .. })),
        "{ev:?}"
    );
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    // Writes go one way: what was sent may still be crossing the (fake)
    // mixnet when the other side polls, so poll a few times.
    ada.send_text(&ben.root(), "over the mixnet").await.unwrap();
    let mut got = Vec::new();
    for _ in 0..50 {
        got.extend(ben.sync().await.unwrap());
        if got.iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "over the mixnet"),
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got.iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "over the mixnet")
        ),
        "{got:?}"
    );
    ben.send_text(&ada.root(), "and back").await.unwrap();
    let delivered = |ada: &Client| {
        ada.messages(&ben.root())
            .unwrap()
            .into_iter()
            .find(|m| m.text == "over the mixnet")
            .is_some_and(|m| m.delivered)
    };
    for _ in 0..50 {
        ada.sync().await.unwrap();
        if delivered(&ada) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mine = ada.messages(&ben.root()).unwrap();
    let m = mine.iter().find(|m| m.text == "over the mixnet").unwrap();
    assert!(m.delivered, "Ben's receipt rode on his answer: {m:?}");
    assert!(
        net.stats().replies > replies_at_start,
        "polls were answered"
    );
}
