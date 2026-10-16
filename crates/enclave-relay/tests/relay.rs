//! A call through two relays: neither relay sees both callers; clients
//! reach their relay over WireGuard with a ticket paid by proof of work.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_calls::sframe::{Receiver, Sender};
use enclave_calls::shape::{self, Inner, Shaper, Stream};
use enclave_calls::signal::{self, Answer, CALLEE, CALLER, Media, Offer, Route};
use enclave_calls::ticket;
use enclave_calls::wg::ClientLink;
use enclave_crypto::rng::HedgedRng;
use enclave_relay::{P_MEDIA, Relay, join_payload, serve, ticket_datagrams, ticket_reply};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

const NOW: u64 = 1_790_000_000;
/// Proof-of-work effort in tests (the default costs a moment each).
const EFFORT: u32 = 1;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn wg_key(rng: &mut HedgedRng) -> ([u8; 32], [u8; 32]) {
    let secret: [u8; 32] = rng.array("t").unwrap();
    (secret, enclave_calls::wg::public_key(secret))
}

/// A ticket from `relay` (asked over its datagrams) and the client end of
/// the link it opens.
fn connect(relay: &mut Relay, from: SocketAddr, now: u64, rng: &mut HedgedRng) -> ClientLink {
    relay.set_ticket_effort(EFFORT);
    let (secret, public) = wg_key(rng);
    let (req, client) = ticket::request(relay.ticket_key(), public, 3600, EFFORT, rng).unwrap();
    let parts = ticket_datagrams([7; 8], &req);
    assert_eq!(parts.len(), 2, "a request needs two datagrams");
    assert!(relay.handle(from, &parts[0], now).is_empty());
    let out = relay.handle(from, &parts[1], now);
    assert_eq!(out.len(), 1);
    let (id, reply) = ticket_reply(&out[0].1).unwrap();
    assert_eq!(id, [7; 8]);
    let issued = client.finish(reply, now).unwrap();
    assert_eq!(issued.relay_wg, relay.wg_public());
    // The same request again (its proof of work spent) is refused.
    assert!(relay.handle(from, &parts[0], now).is_empty());
    assert!(relay.handle(from, &parts[1], now).is_empty());
    ClientLink::new(secret, issued.relay_wg, issued.ticket, issued.offset)
}

/// Send `payload` from a client to its relay, carrying the handshake and
/// any queued packets back and forth: what the relay sends elsewhere.
fn up(
    link: &mut ClientLink,
    relay: &mut Relay,
    from: SocketAddr,
    now: u64,
    payload: &[u8],
) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut to_relay = link.send(now, payload).unwrap();
    let mut elsewhere = Vec::new();
    for _ in 0..8 {
        let mut back = Vec::new();
        for dg in to_relay.drain(..) {
            for (to, out) in relay.handle(from, &dg, now) {
                if to == from {
                    back.push(out);
                } else {
                    elsewhere.push((to, out));
                }
            }
        }
        for dg in back {
            if let Ok(r) = link.receive(now, &dg) {
                to_relay.extend(r.send);
            }
        }
        if to_relay.is_empty() {
            break;
        }
    }
    elsewhere
}

/// The media packet in a datagram from the relay.
fn down(link: &mut ClientLink, now: u64, dg: &[u8]) -> Vec<u8> {
    let r = link.receive(now, dg).unwrap();
    let p = r.payload.unwrap();
    assert_eq!(p[0], P_MEDIA);
    p[1..].to_vec()
}

#[test]
fn two_relays_carry_a_call_without_seeing_both_ends() {
    let mut rng = HedgedRng::new().unwrap();
    let (ra_addr, rb_addr) = (addr("203.0.113.10:4000"), addr("198.51.100.20:4000"));
    let (a_addr, b_addr) = (addr("192.0.2.1:50000"), addr("192.0.2.200:60000"));
    let day = (NOW / 86_400) as u32;
    let mut ra = Relay::new([0xA; 16], "family-a", ra_addr, day).unwrap();
    let mut rb = Relay::new([0xB; 16], "family-b", rb_addr, day).unwrap();
    ra.add_peer(rb.descriptor()).unwrap();
    rb.add_peer(ra.descriptor()).unwrap();

    // Signalling (normally ratchet messages over the mixnet).
    let pending = signal::offer(
        Media::Audio,
        Route::Relay,
        rb_addr.to_string().into_bytes(),
        NOW,
        &mut rng,
    )
    .unwrap();
    let offer = Offer::decode(&pending.offer().encode()).unwrap();
    let (ans, kb) = signal::answer(
        &offer,
        ra_addr.to_string().into_bytes(),
        b"conv",
        NOW,
        &mut rng,
    )
    .unwrap();
    let ka = pending
        .finish(&Answer::decode(&ans.encode()).unwrap(), b"conv", NOW)
        .unwrap();
    assert_eq!(ka.check_words(), kb.check_words());

    let mut la = connect(&mut ra, a_addr, NOW, &mut rng);
    let mut lb = connect(&mut rb, b_addr, NOW, &mut rng);
    // Each side joins its own relay, naming the other relay.
    assert!(
        up(
            &mut la,
            &mut ra,
            a_addr,
            NOW,
            &join_payload(&ka.rendezvous(), rb_addr)
        )
        .is_empty()
    );
    assert!(
        up(
            &mut lb,
            &mut rb,
            b_addr,
            NOW,
            &join_payload(&kb.rendezvous(), ra_addr)
        )
        .is_empty()
    );

    let mut a_tx = Sender::new(CALLER, &ka.sframe_base(CALLER, 0));
    let mut b_rx = Receiver::new(CALLER, &kb.sframe_base(CALLER, 0));
    let mut b_tx = Sender::new(CALLEE, &kb.sframe_base(CALLEE, 0));
    let mut a_rx = Receiver::new(CALLEE, &ka.sframe_base(CALLEE, 0));
    let mut a_shape = Shaper::new(Stream::Audio);
    let mut b_shape = Shaper::new(Stream::Audio);
    let mut wire_sizes = std::collections::HashSet::new();
    let (mut a_heard, mut b_heard) = (0, 0);

    for i in 0..300u64 {
        let t = NOW + i / 50;
        if i % 2 == 0 {
            a_shape.push_frame(&[1; 80]).unwrap();
        }
        if i % 5 == 0 {
            b_shape.push_frame(&[2; 80]).unwrap();
        }
        // A → RA → RB → B
        let pkt = a_tx
            .protect(i * 20, b"", &a_shape.next_plaintext())
            .unwrap();
        let dgs = la.send(t, &[&[P_MEDIA][..], &pkt].concat()).unwrap();
        assert_eq!(dgs.len(), 1);
        wire_sizes.insert(dgs[0].len());
        let hop = ra.handle(a_addr, &dgs[0], t);
        assert_eq!(hop.len(), 1);
        assert_eq!(hop[0].0, rb_addr, "RA only ever sends to the peer relay");
        wire_sizes.insert(hop[0].1.len());
        let out = rb.handle(ra_addr, &hop[0].1, t);
        assert_eq!(out[0].0, b_addr);
        wire_sizes.insert(out[0].1.len());
        let got = down(&mut lb, t, &out[0].1);
        if let Inner::Media(m) =
            shape::decode_plaintext(&b_rx.unprotect(&got, b"").unwrap()).unwrap()
        {
            assert_eq!(m, vec![1; 80]);
            b_heard += 1;
        }
        // B → RB → RA → A
        let pkt = b_tx
            .protect(i * 20, b"", &b_shape.next_plaintext())
            .unwrap();
        let dgs = lb.send(t, &[&[P_MEDIA][..], &pkt].concat()).unwrap();
        let hop = rb.handle(b_addr, &dgs[0], t);
        let out = ra.handle(rb_addr, &hop[0].1, t);
        assert_eq!(out[0].0, a_addr);
        if let Inner::Media(_) =
            shape::decode_plaintext(&a_rx.unprotect(&down(&mut la, t, &out[0].1), b"").unwrap())
                .unwrap()
        {
            a_heard += 1;
        }
    }
    assert_eq!((b_heard, a_heard), (150, 60));
    // Client↔relay datagrams have one size both ways (WireGuard data with
    // the same payload length), relay↔relay datagrams another.
    assert_eq!(wire_sizes.len(), 2, "{wire_sizes:?}");
    assert_eq!(
        ra.client_addrs(),
        vec![a_addr],
        "RA never learns B's address"
    );
    assert_eq!(
        rb.client_addrs(),
        vec![b_addr],
        "RB never learns A's address"
    );

    // A relay-link datagram replayed or from a stranger is dropped; so is
    // a client datagram replayed.
    let pkt = a_tx.protect(6_000, b"", &a_shape.next_plaintext()).unwrap();
    let dg = la
        .send(NOW + 6, &[&[P_MEDIA][..], &pkt].concat())
        .unwrap()
        .remove(0);
    let hop = ra.handle(a_addr, &dg, NOW + 6);
    assert_eq!(rb.handle(ra_addr, &hop[0].1, NOW + 6).len(), 1);
    assert!(rb.handle(ra_addr, &hop[0].1, NOW + 6).is_empty(), "replay");
    assert!(
        rb.handle(addr("192.0.2.66:1"), &hop[0].1, NOW + 6)
            .is_empty(),
        "not a peer"
    );
    assert!(ra.handle(a_addr, &dg, NOW + 6).is_empty(), "client replay");
    assert!(rb.stats().dropped >= 2);
}

#[test]
fn tickets_cost_their_proof_of_work() {
    let mut rng = HedgedRng::new().unwrap();
    let day = (NOW / 86_400) as u32;
    let mut relay = Relay::new([0xC; 16], "c", addr("203.0.113.5:4000"), day).unwrap();
    relay.set_ticket_effort(4);
    let (_, public) = wg_key(&mut rng);
    // Work done at a lower effort than the relay asks is refused.
    let (cheap, _) = ticket::request(relay.ticket_key(), public, 600, 1, &mut rng).unwrap();
    assert!(relay.issue_ticket(&cheap, NOW).is_err());
    let (paid, client) = ticket::request(relay.ticket_key(), public, 600, 4, &mut rng).unwrap();
    let reply = relay.issue_ticket(&paid, NOW).unwrap();
    let issued = client.finish(&reply, NOW - 30).unwrap();
    assert_eq!(issued.offset, 30, "the relay's clock is kept");
    assert!(relay.issue_ticket(&paid, NOW).is_err(), "spent once");
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_loopback_call() {
    let mut rng = HedgedRng::new().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let day = (now / 86_400) as u32;
    let sa = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sb = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (ra_addr, rb_addr) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
    let ra = Arc::new(Mutex::new(
        Relay::new([0xA; 16], "a", ra_addr, day).unwrap(),
    ));
    let rb = Arc::new(Mutex::new(
        Relay::new([0xB; 16], "b", rb_addr, day).unwrap(),
    ));
    {
        let d = rb.lock().await.descriptor().clone();
        ra.lock().await.add_peer(&d).unwrap();
        let d = ra.lock().await.descriptor().clone();
        rb.lock().await.add_peer(&d).unwrap();
        ra.lock().await.set_ticket_effort(EFFORT);
        rb.lock().await.set_ticket_effort(EFFORT);
    }
    let (ka_key, kb_key) = (
        ra.lock().await.ticket_key().clone(),
        rb.lock().await.ticket_key().clone(),
    );
    tokio::spawn(serve(Arc::clone(&ra), sa));
    tokio::spawn(serve(Arc::clone(&rb), sb));

    let pending = signal::offer(Media::Audio, Route::Relay, vec![], now, &mut rng).unwrap();
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"c", now, &mut rng).unwrap();
    let ka = pending.finish(&ans, b"c", now).unwrap();
    let ca = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cb = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    ca.connect(ra_addr).await.unwrap();
    cb.connect(rb_addr).await.unwrap();
    let mut buf = vec![0u8; 2048];

    // Tickets over UDP, then a WireGuard link to each relay.
    let mut links = Vec::new();
    for (sock, key) in [(&ca, &ka_key), (&cb, &kb_key)] {
        let (secret, public) = wg_key(&mut rng);
        let (req, client) = ticket::request(key, public, 600, EFFORT, &mut rng).unwrap();
        for dg in ticket_datagrams([1; 8], &req) {
            sock.send(&dg).await.unwrap();
        }
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (_, reply) = ticket_reply(&buf[..n]).unwrap();
        let issued = client.finish(reply, now).unwrap();
        links.push(ClientLink::new(
            secret,
            issued.relay_wg,
            issued.ticket,
            issued.offset,
        ));
    }
    let (mut la, mut lb) = (links.remove(0), links.remove(0));
    for (link, sock, rv, peer) in [
        (&mut la, &ca, ka.rendezvous(), rb_addr),
        (&mut lb, &cb, kb.rendezvous(), ra_addr),
    ] {
        for dg in link.send(now, &join_payload(&rv, peer)).unwrap() {
            sock.send(&dg).await.unwrap();
        }
        // The handshake answer; then the queued join goes.
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        for dg in link.receive(now, &buf[..n]).unwrap().send {
            sock.send(&dg).await.unwrap();
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut tx = Sender::new(CALLER, &ka.sframe_base(CALLER, 0));
    let mut rx = Receiver::new(CALLER, &kb.sframe_base(CALLER, 0));
    for i in 0..20u64 {
        let pkt = tx.protect(i * 20, b"", &[i as u8; 111]).unwrap();
        for dg in la.send(now, &[&[P_MEDIA][..], &pkt].concat()).unwrap() {
            ca.send(&dg).await.unwrap();
        }
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), cb.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let got = rx.unprotect(&down(&mut lb, now, &buf[..n]), b"").unwrap();
        assert_eq!(got, vec![i as u8; 111]);
    }
}

/// Keys and spent requests survive a restart; ticket keys roll daily and a
/// request sealed to yesterday's key is still served for a day.
#[test]
fn keys_and_spent_tokens_survive_a_restart() {
    use enclave_relay::keys::RelayKeys;
    use enclave_relay::ledger::RedbSpent;
    let dir = std::env::temp_dir().join(format!("enclave-relay-keys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    let day = 20_000;
    let now = u64::from(day) * 86_400 + 100;
    let mut rng = HedgedRng::new().unwrap();
    let open = |keys: &RelayKeys| {
        let mut r = Relay::with_keys(
            keys.id,
            "a",
            addr,
            keys.link_secret(),
            keys.tickets(),
            Box::new(RedbSpent::open(&dir.join("relay.redb")).unwrap()),
        )
        .unwrap();
        r.set_ticket_effort(EFFORT);
        r
    };

    let keys = RelayKeys::init(&dir.join("k"), day).unwrap();
    assert!(
        RelayKeys::init(&dir.join("k"), day).is_err(),
        "never overwrites"
    );
    let tomorrow = keys.next_ticket().public().clone();
    let (desc, ticket_key, wg, spent) = {
        let mut relay = open(&keys);
        let (req, _) = ticket::request(relay.ticket_key(), [1; 32], 600, EFFORT, &mut rng).unwrap();
        relay.issue_ticket(&req, now).unwrap();
        (
            relay.descriptor().clone(),
            relay.ticket_key().clone(),
            relay.wg_public(),
            req,
        )
    };

    let mut keys = RelayKeys::load(&dir.join("k")).unwrap();
    let mut relay = open(&keys);
    assert_eq!(relay.descriptor(), &desc, "same id and link key");
    assert_eq!(relay.wg_public(), wg, "same WireGuard key");
    assert!(relay.ticket_key() == &ticket_key, "same ticket key");
    // The request served before the restart stays spent.
    assert!(relay.issue_ticket(&spent, now).is_err());

    // Next day: tomorrow's published key is current; yesterday's still works.
    let (late, _) = ticket::request(relay.ticket_key(), [2; 32], 600, EFFORT, &mut rng).unwrap();
    assert!(keys.advance(day + 1).unwrap());
    relay.set_ticket_keys(keys.tickets());
    assert!(relay.ticket_key() == &tomorrow);
    relay.issue_ticket(&late, now + 86_400).unwrap();
    // Two days on, the old key is gone.
    let (stale, _) = ticket::request(&ticket_key, [3; 32], 600, EFFORT, &mut rng).unwrap();
    keys.advance(day + 2).unwrap();
    relay.set_ticket_keys(keys.tickets());
    assert!(relay.issue_ticket(&stale, now + 2 * 86_400).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Carry datagrams between two relays until neither has more, with their
/// once-a-second upkeep in between.
fn pump(ra: &mut Relay, rb: &mut Relay, (ra_addr, rb_addr): (SocketAddr, SocketAddr), now: u64) {
    for _ in 0..8 {
        let mut to_b: Vec<Vec<u8>> = ra.peer_upkeep(now).into_iter().map(|(_, d)| d).collect();
        let mut to_a: Vec<Vec<u8>> = rb.peer_upkeep(now).into_iter().map(|(_, d)| d).collect();
        for _ in 0..8 {
            let back: Vec<Vec<u8>> = to_b
                .drain(..)
                .flat_map(|d| rb.handle(ra_addr, &d, now))
                .map(|(_, d)| d)
                .collect();
            to_a.extend(back);
            let back: Vec<Vec<u8>> = to_a
                .drain(..)
                .flat_map(|d| ra.handle(rb_addr, &d, now))
                .map(|(_, d)| d)
                .collect();
            to_b.extend(back);
            if to_a.is_empty() && to_b.is_empty() {
                break;
            }
        }
    }
}

/// Relay links (ADR 0007): each 120 s epoch the relay with the lower id
/// starts an ML-KEM-1024 exchange, and both switch to the epoch's keys
/// once they have heard under them. A first message anyone could forge
/// (the static ML-KEM keys are public) never switches the other relay.
#[test]
fn relay_links_turn_post_quantum_each_epoch() {
    use enclave_relay::{LINK_EPOCH_SECS, T_KX};
    let (ra_addr, rb_addr) = (addr("203.0.113.10:4000"), addr("198.51.100.20:4000"));
    let day = (NOW / 86_400) as u32;
    let mut ra = Relay::new([0xA; 16], "family-a", ra_addr, day).unwrap();
    let mut rb = Relay::new([0xB; 16], "family-b", rb_addr, day).unwrap();
    ra.add_peer(rb.descriptor()).unwrap();
    rb.add_peer(ra.descriptor()).unwrap();
    assert_eq!(ra.link_epoch(&rb_addr), Some(0), "classical to start with");

    let epoch = (NOW / LINK_EPOCH_SECS) as u32 + 1;
    pump(&mut ra, &mut rb, (ra_addr, rb_addr), NOW);
    assert_eq!(ra.link_epoch(&rb_addr), Some(epoch));
    assert_eq!(rb.link_epoch(&ra_addr), Some(epoch));
    // The next epoch: fresh keys again.
    let later = NOW + LINK_EPOCH_SECS;
    pump(&mut ra, &mut rb, (ra_addr, rb_addr), later);
    assert_eq!(ra.link_epoch(&rb_addr), Some(epoch + 1));
    assert_eq!(rb.link_epoch(&ra_addr), Some(epoch + 1));

    // A forged first message for a later epoch, "from" relay A.
    let mut rng = HedgedRng::new().unwrap();
    let b_kem =
        enclave_crypto::kem::MlKemPublic::from_slice(rb.descriptor().kem.as_deref().unwrap())
            .unwrap();
    let (_eph, eph_pk) = enclave_crypto::kem::MlKemSecret::generate(&mut rng).unwrap();
    let (ct1, _) = b_kem.encapsulate(&mut rng).unwrap();
    let msg = [&eph_pk.0[..], &ct1.0[..]].concat();
    let forged_epoch = epoch + 5;
    let parts: Vec<&[u8]> = msg.chunks(1100).collect();
    let mut answers = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        let dg = [
            &[T_KX, 1][..],
            &forged_epoch.to_be_bytes(),
            &[i as u8, parts.len() as u8],
            p,
        ]
        .concat();
        answers.extend(rb.handle(ra_addr, &dg, later));
    }
    assert!(!answers.is_empty(), "B answers what it can't tell from A's");
    // Whatever B sends under those keys, A can't open: B never switches.
    for (_, d) in answers.into_iter().chain(rb.peer_upkeep(later)) {
        assert!(ra.handle(rb_addr, &d, later).is_empty());
    }
    pump(&mut ra, &mut rb, (ra_addr, rb_addr), later + 1);
    assert_eq!(rb.link_epoch(&ra_addr), Some(epoch + 1));
}
