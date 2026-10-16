//! A call end to end: two relays on this machine in different operator
//! families, each side's leg (descriptor, ticket paid with proof of work,
//! WireGuard link), and audio both ways through the two relays.
#![allow(clippy::unwrap_used)]

use enclave_calls::signal::{self, Media, Route};
use enclave_crypto::rng::HedgedRng;
use enclave_federation::ListedRelay;
use enclave_ipc::Out;
use enclave_relay::keys::RelayKeys;
use enclave_relay::{MemorySpent, Relay, serve};
use enclave_vault::calls::{self, CallEvent, FromCall, Plan, ToCall};
use enclave_vault::media::Media as Helpers;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

const EFFORT: u32 = 4;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A relay serving on a loopback port, and what the server list says of it.
async fn relay(
    dir: &std::path::Path,
    family: &str,
) -> (ListedRelay, Arc<Mutex<Relay>>, SocketAddr) {
    let day = (now() / 86_400) as u32;
    let keys = RelayKeys::init(dir, day).unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let signed = keys
        .descriptor("Op", family, &addr.to_string(), EFFORT, now())
        .unwrap();
    let mut r = Relay::with_keys(
        signed.id(),
        family,
        addr,
        keys.link_secret(),
        keys.tickets(),
        Box::new(MemorySpent::default()),
    )
    .unwrap();
    r.set_ticket_effort(EFFORT);
    r.set_published(signed.encode());
    let listed = ListedRelay {
        identity: signed.identity.clone(),
        operator: "Op".into(),
        family: family.into(),
        addr: addr.to_string(),
        link_key: signed.link_key,
    };
    let r = Arc::new(Mutex::new(r));
    tokio::spawn(serve(Arc::clone(&r), socket));
    (listed, r, addr)
}

fn tone(frame: usize) -> Vec<i16> {
    (0..960)
        .map(|i| {
            let t = (frame * 960 + i) as f32 / 48_000.0;
            (8_000.0 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()) as i16
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audio_goes_both_ways_through_two_relays() {
    let dir = std::env::temp_dir().join(format!("enclave-call-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (la, ra, aa) = relay(&dir.join("a"), "alpha").await;
    let (lb, rb, ab) = relay(&dir.join("b"), "beta").await;
    {
        let d = rb.lock().await.descriptor().clone();
        ra.lock().await.add_peer(&d).unwrap();
        let d = ra.lock().await.descriptor().clone();
        rb.lock().await.add_peer(&d).unwrap();
    }
    let t = enclave_net::transport::TcpTransport::new(Default::default());
    // A relay that isn't who the list says is refused.
    let mut wrong = la.clone();
    wrong.identity = lb.identity.clone();
    assert!(calls::open_leg(&t, &wrong).await.is_err());

    let leg_a = calls::open_leg(&t, &la).await.unwrap();
    let leg_b = calls::open_leg(&t, &lb).await.unwrap();

    let mut rng = HedgedRng::new().unwrap();
    let pending = signal::offer(Media::Audio, Route::Relay, vec![], now(), &mut rng).unwrap();
    let id = pending.offer().call_id;
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"conv", now(), &mut rng).unwrap();
    let ka = pending.finish(&ans, b"conv", now()).unwrap();
    assert_eq!(ka.check_words(), kb.check_words());

    let helpers = Helpers::in_process();
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let mut sides = Vec::new();
    for (leg, keys, caller, peer) in [(leg_a, ka, true, ab), (leg_b, kb, false, aa)] {
        let (tx, rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let plan = Plan {
            id,
            keys,
            caller,
            peer_relay: peer,
            codec: helpers.open_call().await.unwrap(),
            video: None,
        };
        tokio::spawn(calls::run(leg, plan, rx, out_tx, ev_tx.clone()));
        sides.push((tx, out_rx));
    }
    let (b_tx, mut b_out) = sides.pop().unwrap();
    let (a_tx, mut a_out) = sides.pop().unwrap();
    // Ada talks for 3 s; Ben says nothing but is muted half the time.
    let talk = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        for f in 0..150 {
            tick.tick().await;
            a_tx.send(ToCall::Mic(tone(f))).unwrap();
            b_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
            if f == 75 {
                b_tx.send(ToCall::Mute(true)).unwrap();
            }
        }
        (a_tx, b_tx)
    });
    let (a_tx, b_tx) = talk.await.unwrap();
    let mut connected = 0;
    while let Ok(ev) = ev_rx.try_recv() {
        if let CallEvent::Media(i, FromCall::Connected) = ev {
            assert_eq!(i, id);
            connected += 1;
        }
    }
    assert_eq!(connected, 2, "both sides heard the other");
    let mut loud = 0;
    let mut frames = 0;
    while let Ok(Out::CallAudio(pcm)) = b_out.try_recv() {
        frames += 1;
        let e: f64 = pcm.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / pcm.len() as f64;
        if e > 1e5 {
            loud += 1;
        }
    }
    assert!(frames > 100, "Ben played {frames} frames");
    assert!(loud > 80, "and heard Ada in {loud} of them");
    let mut a_frames = 0;
    while let Ok(Out::CallAudio(_)) = a_out.try_recv() {
        a_frames += 1;
    }
    // Ben's silence until he muted; padding after that, which plays
    // nothing.
    assert!(
        (50..=100).contains(&a_frames),
        "Ada played {a_frames} frames"
    );
    // Neither relay saw a client it can't account for, and both carried
    // traffic to the other.
    assert!(ra.lock().await.stats().to_peer > 100);
    assert!(rb.lock().await.stats().to_peer > 100);
    // And their link went post-quantum (ADR 0007) within the first second.
    assert!(ra.lock().await.link_epoch(&ab).unwrap() > 0);
    assert!(rb.lock().await.link_epoch(&aa).unwrap() > 0);
    // Hanging up ends the media.
    drop(a_tx);
    drop(b_tx);
    let ended = tokio::time::timeout(Duration::from_secs(2), async {
        let mut n = 0;
        while let Some(ev) = ev_rx.recv().await {
            if let CallEvent::Media(_, FromCall::Dropped(why)) = ev {
                assert!(why.is_empty());
                n += 1;
                if n == 2 {
                    break;
                }
            }
        }
    })
    .await;
    assert!(ended.is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn video_goes_through_two_relays() {
    let dir = std::env::temp_dir().join(format!("enclave-video-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (la, ra, aa) = relay(&dir.join("a"), "alpha").await;
    let (lb, rb, ab) = relay(&dir.join("b"), "beta").await;
    {
        let d = rb.lock().await.descriptor().clone();
        ra.lock().await.add_peer(&d).unwrap();
        let d = ra.lock().await.descriptor().clone();
        rb.lock().await.add_peer(&d).unwrap();
    }
    let t = enclave_net::transport::TcpTransport::new(Default::default());
    let leg_a = calls::open_leg(&t, &la).await.unwrap();
    let leg_b = calls::open_leg(&t, &lb).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let pending = signal::offer(Media::Video(0), Route::Relay, vec![], now(), &mut rng).unwrap();
    let id = pending.offer().call_id;
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"conv", now(), &mut rng).unwrap();
    let ka = pending.finish(&ans, b"conv", now()).unwrap();
    let helpers = Helpers::in_process();
    let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
    let mut sides = Vec::new();
    for (leg, keys, caller, peer) in [(leg_a, ka, true, ab), (leg_b, kb, false, aa)] {
        let (tx, rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let plan = Plan {
            id,
            keys,
            caller,
            peer_relay: peer,
            codec: helpers.open_call().await.unwrap(),
            video: Some((helpers.open_video(0).await.unwrap(), 0)),
        };
        tokio::spawn(calls::run(leg, plan, rx, out_tx, ev_tx.clone()));
        sides.push((tx, out_rx));
    }
    let (_b_tx, mut b_out) = sides.pop().unwrap();
    let (a_tx, _a_out) = sides.pop().unwrap();
    let tier = enclave_media::callvideo::tier(0);
    // Ada's camera for 4 s at the tier's frame rate (a moving gradient).
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / u64::from(tier.fps)));
    for n in 0..(4 * tier.fps) {
        tick.tick().await;
        let mut px = Vec::with_capacity((tier.width * tier.height * 4) as usize);
        for y in 0..tier.height {
            for x in 0..tier.width {
                px.extend_from_slice(&[((x + n * 8) % 256) as u8, (y % 256) as u8, 90, 255]);
            }
        }
        a_tx.send(ToCall::Frame(px)).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut pictures = 0;
    while let Ok(o) = b_out.try_recv() {
        if let Out::CallVideo(w, h, px) = o {
            assert_eq!((w, h), (tier.width, tier.height));
            assert_eq!(px.len(), (w * h * 4) as usize);
            pictures += 1;
        }
    }
    // Encoding is slow in a debug build: some frames are dropped, never
    // queued.
    assert!(pictures >= 3, "Ben saw {pictures} pictures");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Direct mode (`docs/11-calls.md` §4): each side learns its address from
/// its relay, the two exchange candidates, and once WireGuard's handshake
/// (the caller's probes) gets through, the media goes directly, with the
/// relays kept as the fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audio_goes_directly_once_both_agree() {
    let dir = std::env::temp_dir().join(format!("enclave-direct-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (la, ra, aa) = relay(&dir.join("a"), "alpha").await;
    let (lb, rb, ab) = relay(&dir.join("b"), "beta").await;
    {
        let d = rb.lock().await.descriptor().clone();
        ra.lock().await.add_peer(&d).unwrap();
        let d = ra.lock().await.descriptor().clone();
        rb.lock().await.add_peer(&d).unwrap();
    }
    let t = enclave_net::transport::TcpTransport::new(Default::default());
    let leg_a = calls::open_leg(&t, &la).await.unwrap();
    let leg_b = calls::open_leg(&t, &lb).await.unwrap();
    // Each side's address as its own relay sees it, and its key.
    let side_a = calls::open_direct(&t, &la).await.unwrap();
    let side_b = calls::open_direct(&t, &lb).await.unwrap();
    assert!(
        side_a.ours.addrs.iter().any(|a| a.ip().is_loopback()),
        "the relay reflected {:?}",
        side_a.ours.addrs
    );
    let (cand_a, cand_b) = (side_a.ours.clone(), side_b.ours.clone());

    let mut rng = HedgedRng::new().unwrap();
    let pending = signal::offer(Media::Audio, Route::Direct, vec![], now(), &mut rng).unwrap();
    let id = pending.offer().call_id;
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"conv", now(), &mut rng).unwrap();
    let ka = pending.finish(&ans, b"conv", now()).unwrap();
    assert_eq!(*ka.direct_psk(), *kb.direct_psk());
    let paths = [
        calls::DirectPath::new(side_a, &cand_b, *ka.direct_psk(), true),
        calls::DirectPath::new(side_b, &cand_a, *kb.direct_psk(), false),
    ];

    let helpers = Helpers::in_process();
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let mut sides = Vec::new();
    for ((leg, keys, caller, peer), path) in [(leg_a, ka, true, ab), (leg_b, kb, false, aa)]
        .into_iter()
        .zip(paths)
    {
        let (tx, rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let plan = Plan {
            id,
            keys,
            caller,
            peer_relay: peer,
            codec: helpers.open_call().await.unwrap(),
            video: None,
        };
        tokio::spawn(calls::run(leg, plan, rx, out_tx, ev_tx.clone()));
        tx.send(ToCall::Direct(Box::new(path))).unwrap();
        sides.push((tx, out_rx));
    }
    let (b_tx, mut b_out) = sides.pop().unwrap();
    let (a_tx, _a_out) = sides.pop().unwrap();
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    for f in 0..200 {
        tick.tick().await;
        a_tx.send(ToCall::Mic(tone(f))).unwrap();
        b_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
    }
    let mut direct = 0;
    while let Ok(ev) = ev_rx.try_recv() {
        if let CallEvent::Media(_, FromCall::Direct(true)) = ev {
            direct += 1;
        }
    }
    assert_eq!(direct, 2, "both sides went direct");
    let mut loud = 0;
    while let Ok(Out::CallAudio(pcm)) = b_out.try_recv() {
        let e: f64 = pcm.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / pcm.len() as f64;
        if e > 1e5 {
            loud += 1;
        }
    }
    assert!(loud > 120, "Ben heard Ada in {loud} frames");
    // Most of the 4 s went directly: the relays carried the first moments.
    let relayed = ra.lock().await.stats().to_peer;
    assert!(relayed < 100, "relay A forwarded {relayed} packets");
    drop(a_tx);
    drop(b_tx);
    let _ = rb;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Maximum privacy's standby tunnel (`docs/11-calls.md` §7): padding at
/// the audio rate until a call takes the leg over, which then carries it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_standby_tunnel_carries_the_call_that_takes_it() {
    let dir = std::env::temp_dir().join(format!("enclave-standby-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (la, ra, aa) = relay(&dir.join("a"), "alpha").await;
    let (lb, rb, ab) = relay(&dir.join("b"), "beta").await;
    {
        let d = rb.lock().await.descriptor().clone();
        ra.lock().await.add_peer(&d).unwrap();
        let d = ra.lock().await.descriptor().clone();
        rb.lock().await.add_peer(&d).unwrap();
    }
    let t = enclave_net::transport::TcpTransport::new(Default::default());
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let standby = calls::Standby::start(calls::open_leg(&t, &la).await.unwrap(), ev_tx.clone());
    assert_eq!(standby.relay.identity, la.identity);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let leg_a = standby.take().await.expect("the standby's leg");
    assert!(ev_rx.try_recv().is_err(), "it didn't stop by itself");
    let leg_b = calls::open_leg(&t, &lb).await.unwrap();

    let mut rng = HedgedRng::new().unwrap();
    let pending = signal::offer(Media::Audio, Route::Relay, vec![], now(), &mut rng).unwrap();
    let id = pending.offer().call_id;
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"conv", now(), &mut rng).unwrap();
    let ka = pending.finish(&ans, b"conv", now()).unwrap();
    let helpers = Helpers::in_process();
    let mut sides = Vec::new();
    for (leg, keys, caller, peer) in [(leg_a, ka, true, ab), (leg_b, kb, false, aa)] {
        let (tx, rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let plan = Plan {
            id,
            keys,
            caller,
            peer_relay: peer,
            codec: helpers.open_call().await.unwrap(),
            video: None,
        };
        tokio::spawn(calls::run(leg, plan, rx, out_tx, ev_tx.clone()));
        sides.push((tx, out_rx));
    }
    let (b_tx, mut b_out) = sides.pop().unwrap();
    let (a_tx, _a_out) = sides.pop().unwrap();
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    for f in 0..100 {
        tick.tick().await;
        a_tx.send(ToCall::Mic(tone(f))).unwrap();
        b_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
    }
    let mut loud = 0;
    while let Ok(Out::CallAudio(pcm)) = b_out.try_recv() {
        let e: f64 = pcm.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / pcm.len() as f64;
        if e > 1e5 {
            loud += 1;
        }
    }
    assert!(
        loud > 50,
        "Ben heard Ada through the taken-over tunnel in {loud} frames"
    );
    drop((a_tx, b_tx, rb));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A group call (`docs/11-calls.md` §8): three relays in different
/// families, the first the call's SFU; four people, two of them on the same
/// relay; one joins late (epochs count from the start). Everyone hears the
/// others mixed, sees the one picture sent, and the raised hand and the
/// reaction reach the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_group_call_through_an_sfu_relay() {
    use enclave_calls::signal::CallKeys;
    let dir = std::env::temp_dir().join(format!("enclave-group-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (la, ra, aa) = relay(&dir.join("a"), "alpha").await;
    let (lb, rb, _) = relay(&dir.join("b"), "beta").await;
    let (lc, rc, _) = relay(&dir.join("c"), "gamma").await;
    for (x, y) in [(&ra, &rb), (&ra, &rc), (&rb, &rc)] {
        let d = y.lock().await.descriptor().clone();
        x.lock().await.add_peer(&d).unwrap();
        let d = x.lock().await.descriptor().clone();
        y.lock().await.add_peer(&d).unwrap();
    }
    let t = enclave_net::transport::TcpTransport::new(Default::default());
    let id = [7u8; 16];
    let secret = [9u8; 64];
    // Started half a minute ago: six SFrame epochs in.
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        - 30_000;
    let keys = CallKeys::group(id, &secret);
    let names = ["ada", "ben", "cyrus", "dana"];
    let pid: Vec<u32> = names
        .iter()
        .map(|n| keys.participant(n.as_bytes()))
        .collect();
    let helpers = Helpers::in_process();
    let mut sides = Vec::new();
    for (i, relay) in [&la, &lb, &lc, &lb].into_iter().enumerate() {
        if i == 3 {
            // Dana joins late.
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
        let leg = calls::open_leg(&t, relay).await.unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let video = if i < 2 {
            Some((helpers.open_video(0).await.unwrap(), 0))
        } else {
            None
        };
        let plan = calls::GroupPlan {
            id,
            keys: CallKeys::group(id, &secret),
            me: pid[i],
            sfu: aa,
            started_ms,
            codec: helpers.open_call().await.unwrap(),
            video,
            name: names[i].into(),
        };
        tokio::spawn(calls::run_group(leg, plan, rx, out_tx, ev_tx));
        sides.push((tx, out_rx, ev_rx));
    }
    let txs: Vec<_> = sides.iter().map(|s| s.0.clone()).collect();
    let tier = enclave_media::callvideo::tier(0);
    // Ada talks and films for 4 s; the others send silence. Ben raises his
    // hand; Dana reacts.
    let talk = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        for f in 0..200 {
            tick.tick().await;
            txs[0].send(ToCall::Mic(tone(f))).unwrap();
            for tx in &txs[1..] {
                tx.send(ToCall::Mic(vec![0; 960])).unwrap();
            }
            if f % 3 == 0 {
                let n = f as u32;
                let mut px = Vec::with_capacity((tier.width * tier.height * 4) as usize);
                for y in 0..tier.height {
                    for x in 0..tier.width {
                        px.extend_from_slice(&[
                            ((x + n * 8) % 256) as u8,
                            (y % 256) as u8,
                            90,
                            255,
                        ]);
                    }
                }
                txs[0].send(ToCall::Frame(px)).unwrap();
            }
            if f == 100 {
                txs[1].send(ToCall::Hand(true)).unwrap();
                txs[3].send(ToCall::React("👏".into())).unwrap();
            }
        }
        txs
    });
    let txs = talk.await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    for (i, (_, out, ev)) in sides.iter_mut().enumerate() {
        let mut heard = std::collections::BTreeSet::new();
        let (mut connected, mut hand, mut react) = (false, false, false);
        while let Ok(e) = ev.try_recv() {
            match e {
                CallEvent::Media(_, FromCall::Connected) => connected = true,
                CallEvent::Media(_, FromCall::Heard(p)) => {
                    heard.insert(p);
                }
                CallEvent::Media(_, FromCall::Hand(p, true)) => hand |= p == pid[1],
                CallEvent::Media(_, FromCall::React(p, r)) => react |= p == pid[3] && r == "👏",
                CallEvent::Media(_, FromCall::Dropped(why)) => {
                    panic!("{}: dropped: {why}", names[i])
                }
                _ => {}
            }
        }
        assert!(connected, "{} connected", names[i]);
        let others: std::collections::BTreeSet<u32> = pid
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, p)| *p)
            .collect();
        assert_eq!(heard, others, "{} heard everyone else", names[i]);
        if i != 1 {
            assert!(hand, "{} saw Ben's hand", names[i]);
        }
        if i != 3 {
            assert!(react, "{} saw Dana's reaction", names[i]);
        }
        let (mut loud, mut tiles) = (0, 0);
        while let Ok(o) = out.try_recv() {
            match o {
                Out::CallAudio(pcm) => {
                    let e: f64 =
                        pcm.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / pcm.len() as f64;
                    if e > 1e5 {
                        loud += 1;
                    }
                }
                Out::CallTile(who, w, h, px) => {
                    assert_eq!(who, pid[0], "only Ada films");
                    assert_eq!((w, h), (tier.width, tier.height));
                    assert_eq!(px.len(), (w * h * 4) as usize);
                    tiles += 1;
                }
                _ => {}
            }
        }
        if i != 0 {
            assert!(loud > 60, "{} heard Ada in {loud} frames", names[i]);
        }
        // Only Ben has a video decoder besides Ada (a video participant).
        if i == 1 {
            assert!(tiles >= 3, "Ben saw {tiles} of Ada's pictures");
        }
    }
    // The SFU sent the call on to both other relays; Ben and Dana's relay
    // sent each of them the other's media itself too.
    assert!(ra.lock().await.stats().to_peer > 100);
    assert!(rb.lock().await.stats().to_peer > 100);
    assert!(rc.lock().await.stats().to_peer > 100);
    drop(txs);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A call link with a lobby (`docs/11-calls.md` §8.2): a guest on another
/// relay knocks in the lobby at the call's SFU; the host lets them in with
/// the call's secret sealed to their one-time keys; the guest then joins
/// the call itself, and the host hears them and learns the name they gave.
/// Someone else in the lobby, with the same link, can't open the admission.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_guest_is_let_in_from_a_call_links_lobby() {
    use enclave_calls::link::{self, CallLink, CallSecret, Knocker, LobbyMessage};
    use enclave_calls::signal::CallKeys;
    let dir = std::env::temp_dir().join(format!("enclave-lobby-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (la, ra, aa) = relay(&dir.join("a"), "alpha").await;
    let (lb, rb, _) = relay(&dir.join("b"), "beta").await;
    {
        let d = rb.lock().await.descriptor().clone();
        ra.lock().await.add_peer(&d).unwrap();
        let d = ra.lock().await.descriptor().clone();
        rb.lock().await.add_peer(&d).unwrap();
    }
    let t = enclave_net::transport::TcpTransport::new(Default::default());
    let mut rng = HedgedRng::new().unwrap();
    let ms = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    };
    let call = CallSecret {
        call_id: [8; 16],
        secret: zeroize::Zeroizing::new([2; 64]),
        started_ms: ms(),
    };
    let sfu_id = enclave_federation::relay_id(&la.identity);
    let link = CallLink::new(&call, sfu_id, false, true, ms(), &mut rng).unwrap();
    let link = CallLink::decode(&link.encode()).unwrap();
    assert!(link.open.is_none(), "a lobby link carries no call secret");
    let lobby = link.lobby_keys();
    let lobby_id = [9u8; 16];
    let helpers = Helpers::in_process();

    // The host: in the call (on the SFU) and in the lobby.
    let keys = CallKeys::group(call.call_id, &call.secret);
    let host_pid = keys.participant(b"host");
    let (host_tx, host_rx) = mpsc::unbounded_channel();
    let (host_out, _host_out_rx) = mpsc::unbounded_channel();
    let (host_ev, mut host_events) = mpsc::unbounded_channel();
    tokio::spawn(calls::run_group(
        calls::open_leg(&t, &la).await.unwrap(),
        calls::GroupPlan {
            id: call.call_id,
            keys: CallKeys::group(call.call_id, &call.secret),
            me: host_pid,
            sfu: aa,
            started_ms: call.started_ms,
            codec: helpers.open_call().await.unwrap(),
            video: None,
            name: "Ada".into(),
        },
        host_rx,
        host_out,
        host_ev.clone(),
    ));
    let (host_lobby_tx, host_lobby_rx) = mpsc::unbounded_channel();
    tokio::spawn(calls::run_lobby(
        calls::open_leg(&t, &la).await.unwrap(),
        calls::LobbyPlan {
            id: lobby_id,
            keys: link.lobby_keys(),
            me: lobby.participant(b"host"),
            sfu: aa,
            started_ms: link.created_ms,
        },
        host_lobby_rx,
        host_ev,
    ));

    // The guest, and an eavesdropper with the link, both in the lobby from
    // the other relay.
    let ana = Knocker::new(&mut rng).unwrap();
    let eve = Knocker::new(&mut rng).unwrap();
    let mut lobbies = Vec::new();
    for k in [&ana, &eve] {
        let (tx, rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        tokio::spawn(calls::run_lobby(
            calls::open_leg(&t, &lb).await.unwrap(),
            calls::LobbyPlan {
                id: lobby_id,
                keys: link.lobby_keys(),
                me: k.id(&link),
                sfu: aa,
                started_ms: link.created_ms,
            },
            rx,
            ev_tx,
        ));
        lobbies.push((tx, ev_rx));
    }
    let (eve_tx, mut eve_events) = lobbies.pop().unwrap();
    let (ana_tx, mut ana_events) = lobbies.pop().unwrap();
    let _eve_tx = eve_tx;

    // Ana knocks until the host's admission reaches her.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut admitted = None;
    let mut knocked_at = tokio::time::Instant::now() - Duration::from_secs(10);
    let mut eve_saw_admission = None;
    while admitted.is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Ana was never let in"
        );
        if knocked_at.elapsed() > Duration::from_secs(2) {
            ana_tx.send(ana.knock("Ana").encode()).unwrap();
            knocked_at = tokio::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        while let Ok(e) = host_events.try_recv() {
            if let CallEvent::Media(id, FromCall::Lobby(from, m)) = e {
                assert_eq!(id, lobby_id);
                let m = LobbyMessage::decode(&m).unwrap();
                assert_eq!(link::knocker_id(&link, &m), Some(from));
                let (to, admit) = link::admit(&link, &m, &call, &mut rng).unwrap();
                assert_eq!(to, ana.id(&link));
                host_lobby_tx.send(admit.encode()).unwrap();
            }
        }
        while let Ok(e) = eve_events.try_recv() {
            if let CallEvent::Media(_, FromCall::Lobby(_, m)) = e {
                let m = LobbyMessage::decode(&m).unwrap();
                if matches!(m, LobbyMessage::Admit { .. }) {
                    eve_saw_admission = Some(m);
                }
            }
        }
        while let Ok(e) = ana_events.try_recv() {
            if let CallEvent::Media(_, FromCall::Lobby(_, m)) = e {
                let m = LobbyMessage::decode(&m).unwrap();
                if let Ok(c) = ana.open(&link, &m) {
                    admitted = Some(c);
                }
            }
        }
    }
    let got = admitted.unwrap();
    assert!(got == call);
    // Eve heard the admission go by and can't open it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    while let Ok(e) = eve_events.try_recv() {
        if let CallEvent::Media(_, FromCall::Lobby(_, m)) = e
            && let Ok(m) = LobbyMessage::decode(&m)
            && matches!(m, LobbyMessage::Admit { .. })
        {
            eve_saw_admission = Some(m);
        }
    }
    let seen = eve_saw_admission.expect("the lobby carried the admission to everyone in it");
    assert!(eve.open(&link, &seen).is_err());

    // Ana joins the call from the other relay, as a guest.
    let ana_pid = keys.participant(b"ana");
    let (ana_call_tx, ana_call_rx) = mpsc::unbounded_channel();
    let (ana_out, _ana_out_rx) = mpsc::unbounded_channel();
    let (ana_ev, mut ana_call_events) = mpsc::unbounded_channel();
    tokio::spawn(calls::run_group(
        calls::open_leg(&t, &lb).await.unwrap(),
        calls::GroupPlan {
            id: got.call_id,
            keys: CallKeys::group(got.call_id, &got.secret),
            me: ana_pid,
            sfu: aa,
            started_ms: got.started_ms,
            codec: helpers.open_call().await.unwrap(),
            video: None,
            name: "Ana".into(),
        },
        ana_call_rx,
        ana_out,
        ana_ev,
    ));
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    for f in 0..600 {
        tick.tick().await;
        ana_call_tx.send(ToCall::Mic(tone(f))).unwrap();
        host_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
    }
    let (mut heard_ana, mut named) = (false, false);
    while let Ok(e) = host_events.try_recv() {
        match e {
            CallEvent::Media(_, FromCall::Heard(p)) if p == ana_pid => heard_ana = true,
            CallEvent::Media(_, FromCall::Name(p, n)) if p == ana_pid => named = n == "Ana",
            _ => {}
        }
    }
    assert!(heard_ana, "the host heard Ana");
    assert!(named, "and her name");
    let mut heard_host = false;
    while let Ok(e) = ana_call_events.try_recv() {
        if let CallEvent::Media(_, FromCall::Heard(p)) = e {
            heard_host |= p == host_pid;
        }
    }
    assert!(heard_host, "Ana heard the host");
    drop((host_tx, ana_call_tx, host_lobby_tx, ana_tx));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Screen share (`docs/11-calls.md` §8.3): in a video call, Ada switches
/// from her camera to her screen. Ben's pictures change size (960 × 540,
/// the screen's) while the stream on the wire stays the same: the relays
/// carry as many packets a second before and after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_screen_goes_in_place_of_the_camera() {
    let dir = std::env::temp_dir().join(format!("enclave-screen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (la, ra, aa) = relay(&dir.join("a"), "alpha").await;
    let (lb, rb, ab) = relay(&dir.join("b"), "beta").await;
    {
        let d = rb.lock().await.descriptor().clone();
        ra.lock().await.add_peer(&d).unwrap();
        let d = ra.lock().await.descriptor().clone();
        rb.lock().await.add_peer(&d).unwrap();
    }
    let t = enclave_net::transport::TcpTransport::new(Default::default());
    let leg_a = calls::open_leg(&t, &la).await.unwrap();
    let leg_b = calls::open_leg(&t, &lb).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let pending = signal::offer(Media::Video(0), Route::Relay, vec![], now(), &mut rng).unwrap();
    let id = pending.offer().call_id;
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"conv", now(), &mut rng).unwrap();
    let ka = pending.finish(&ans, b"conv", now()).unwrap();
    let helpers = Helpers::in_process();
    let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
    let mut sides = Vec::new();
    for (leg, keys, caller, peer) in [(leg_a, ka, true, ab), (leg_b, kb, false, aa)] {
        let (tx, rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let plan = Plan {
            id,
            keys,
            caller,
            peer_relay: peer,
            codec: helpers.open_call().await.unwrap(),
            video: Some((helpers.open_video(0).await.unwrap(), 0)),
        };
        tokio::spawn(calls::run(leg, plan, rx, out_tx, ev_tx.clone()));
        sides.push((tx, out_rx));
    }
    let (_b_tx, mut b_out) = sides.pop().unwrap();
    let (a_tx, _a_out) = sides.pop().unwrap();
    let tier = enclave_media::callvideo::tier(0);
    let screen = enclave_media::callvideo::screen(0);
    assert_eq!(
        (screen.width, screen.height),
        (enclave_ipc::SCREEN_WIDTH, enclave_ipc::SCREEN_HEIGHT)
    );
    let picture = |w: u32, h: u32, n: u32| {
        let mut px = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                px.extend_from_slice(&[((x + n * 8) % 256) as u8, (y % 256) as u8, 90, 255]);
            }
        }
        px
    };
    // Let the call settle, then count a phase's packets on the relays.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let carried = || async { ra.lock().await.stats().to_peer + rb.lock().await.stats().to_peer };
    let before = carried().await;
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / u64::from(tier.fps)));
    for n in 0..(3 * tier.fps) {
        tick.tick().await;
        a_tx.send(ToCall::Frame(picture(tier.width, tier.height, n)))
            .unwrap();
    }
    let camera_phase = carried().await - before;
    a_tx.send(ToCall::Screen(true)).unwrap();
    let before = carried().await;
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / u64::from(screen.fps)));
    for n in 0..(3 * screen.fps) {
        tick.tick().await;
        a_tx.send(ToCall::Frame(picture(screen.width, screen.height, n)))
            .unwrap();
    }
    let screen_phase = carried().await - before;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (mut cameras, mut screens) = (0, 0);
    while let Ok(o) = b_out.try_recv() {
        if let Out::CallVideo(w, h, px) = o {
            assert_eq!(px.len(), (w * h * 4) as usize);
            match (w, h) {
                (w, h) if (w, h) == (tier.width, tier.height) => cameras += 1,
                (w, h) if (w, h) == (screen.width, screen.height) => screens += 1,
                other => panic!("a picture of {other:?}"),
            }
        }
    }
    assert!(cameras >= 3, "Ben saw {cameras} camera pictures");
    assert!(screens >= 2, "and {screens} of the screen");
    // The same stream on the wire (within the jitter of three seconds).
    let (c, s) = (camera_phase as f64, screen_phase as f64);
    assert!((s - c).abs() / c < 0.05, "packets: camera {c}, screen {s}");
    let _ = std::fs::remove_dir_all(&dir);
}
