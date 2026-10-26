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

/// These tests run calls in real time (20 ms frames, jitter buffers,
/// relays): run at once, they starve each other on a small CI runner, so
/// they take turns.
static REALTIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
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
    let _turn = REALTIME.lock().await;
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
    let _turn = REALTIME.lock().await;
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
    let _turn = REALTIME.lock().await;
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
    let _turn = REALTIME.lock().await;
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
    let _turn = REALTIME.lock().await;
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
    // hand; Dana reacts. Then everyone keeps sending silence until the
    // checks below are done: on a loaded machine a side may connect late,
    // and it can only hear the others while they still send.
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let keep_on = {
        let (txs, done) = (txs.clone(), Arc::clone(&done));
        move || async move {
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                tick.tick().await;
                for tx in &txs {
                    let _ = tx.send(ToCall::Mic(vec![0; 960]));
                }
            }
        }
    };
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
    let silence = tokio::spawn(keep_on());
    // What each side's window and call got. A slow machine decodes behind
    // the call: wait (up to 20 s) until Ben has pictures and everyone has
    // heard everyone else, rather than a fixed time.
    let mut outs: Vec<Vec<Out>> = vec![Vec::new(); sides.len()];
    let mut evs: Vec<Vec<CallEvent>> = (0..sides.len()).map(|_| Vec::new()).collect();
    let start = std::time::Instant::now();
    let deadline = start + Duration::from_secs(20);
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        for (i, (_, out, ev)) in sides.iter_mut().enumerate() {
            while let Ok(o) = out.try_recv() {
                outs[i].push(o);
            }
            while let Ok(e) = ev.try_recv() {
                evs[i].push(e);
            }
        }
        let ben = outs[1]
            .iter()
            .filter(|o| matches!(o, Out::CallTile(..)))
            .count();
        let all_heard = evs.iter().all(|e| {
            e.iter()
                .filter_map(|e| match e {
                    CallEvent::Media(_, FromCall::Heard(p)) => Some(*p),
                    _ => None,
                })
                .collect::<std::collections::BTreeSet<u32>>()
                .len()
                == pid.len() - 1
        });
        let settled = start.elapsed() >= Duration::from_secs(1);
        if (ben >= 3 && all_heard && settled) || std::time::Instant::now() > deadline {
            break;
        }
    }
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = silence.await;
    for (i, ev) in evs.into_iter().enumerate() {
        let mut heard = std::collections::BTreeSet::new();
        let (mut connected, mut hand, mut react) = (false, false, false);
        for e in ev {
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
        for o in std::mem::take(&mut outs[i]) {
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
    let _turn = REALTIME.lock().await;
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
    let _turn = REALTIME.lock().await;
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
    // Packets a second over each phase, by the clock: the phases' lengths
    // vary with the machine's timers (Windows ticks in 15.6 ms steps).
    let (before, t0) = (carried().await, std::time::Instant::now());
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / u64::from(tier.fps)));
    for n in 0..(3 * tier.fps) {
        tick.tick().await;
        a_tx.send(ToCall::Frame(picture(tier.width, tier.height, n)))
            .unwrap();
    }
    let camera_phase = (carried().await - before) as f64 / t0.elapsed().as_secs_f64();
    a_tx.send(ToCall::Screen(true)).unwrap();
    let (before, t0) = (carried().await, std::time::Instant::now());
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / u64::from(screen.fps)));
    for n in 0..(3 * screen.fps) {
        tick.tick().await;
        a_tx.send(ToCall::Frame(picture(screen.width, screen.height, n)))
            .unwrap();
    }
    let screen_phase = (carried().await - before) as f64 / t0.elapsed().as_secs_f64();
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
    // The same stream on the wire: the same packets a second.
    let (c, s) = (camera_phase, screen_phase);
    assert!(
        (s - c).abs() / c < 0.05,
        "packets a second: camera {c:.1}, screen {s:.1}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// What an observer on the client's link sees: every datagram the
/// client's leg sends (what goes out of its socket), when and how big.
type Seen = Arc<std::sync::Mutex<Vec<(std::time::Instant, usize)>>>;

fn watch(leg: &mut calls::Leg) -> Seen {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let out = std::mem::replace(&mut leg.dg.send, tx);
    let seen: Seen = Arc::default();
    let s = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Some(d) = rx.recv().await {
            s.lock().unwrap().push((std::time::Instant::now(), d.len()));
            if out.send(d).is_err() {
                return;
            }
        }
    });
    seen
}

/// Per size, how many datagrams a second went in `[from, to)`.
fn per_second(
    seen: &Seen,
    from: std::time::Instant,
    to: std::time::Instant,
) -> std::collections::BTreeMap<usize, f64> {
    let secs = (to - from).as_secs_f64();
    let mut m = std::collections::BTreeMap::new();
    for (at, n) in seen.lock().unwrap().iter() {
        if *at >= from && *at < to {
            *m.entry(*n).or_insert(0.0) += 1.0 / secs;
        }
    }
    m
}

/// The same sizes at the same rates, within `tol` (a fraction), for every
/// size seen more than once a second.
fn same_shape(
    a: &std::collections::BTreeMap<usize, f64>,
    b: &std::collections::BTreeMap<usize, f64>,
    tol: f64,
) {
    let sizes: std::collections::BTreeSet<usize> = a
        .iter()
        .chain(b.iter())
        .filter(|(_, r)| **r > 1.5)
        .map(|(n, _)| *n)
        .collect();
    assert!(!sizes.is_empty(), "nothing went");
    for n in sizes {
        let (x, y) = (
            a.get(&n).copied().unwrap_or(0.0),
            b.get(&n).copied().unwrap_or(0.0),
        );
        assert!(
            (x - y).abs() <= tol * x.max(y),
            "{n}-byte datagrams: {x:.1}/s against {y:.1}/s\n{a:?}\n{b:?}"
        );
    }
}

/// A call whose caller's link is watched, through four 2-second phases:
/// talking, silence, muted, talking again. Returns what was seen and when
/// each phase began (and the end).
async fn watched_call(name: &str) -> (Seen, Vec<std::time::Instant>) {
    let dir = std::env::temp_dir().join(format!("enclave-{name}-{}", std::process::id()));
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
    let mut leg_a = calls::open_leg(&t, &la).await.unwrap();
    let seen = watch(&mut leg_a);
    let leg_b = calls::open_leg(&t, &lb).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let pending = signal::offer(Media::Audio, Route::Relay, vec![], now(), &mut rng).unwrap();
    let id = pending.offer().call_id;
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"conv", now(), &mut rng).unwrap();
    let ka = pending.finish(&ans, b"conv", now()).unwrap();
    let helpers = Helpers::in_process();
    let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
    let mut txs = Vec::new();
    for (leg, keys, caller, peer) in [(leg_a, ka, true, ab), (leg_b, kb, false, aa)] {
        let (tx, rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        std::mem::forget(out_rx);
        let plan = Plan {
            id,
            keys,
            caller,
            peer_relay: peer,
            codec: helpers.open_call().await.unwrap(),
            video: None,
        };
        tokio::spawn(calls::run(leg, plan, rx, out_tx, ev_tx.clone()));
        txs.push(tx);
    }
    let b_tx = txs.pop().unwrap();
    let a_tx = txs.pop().unwrap();
    // Settle (the link's handshake, the join), then the phases.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut marks = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    for phase in 0..4 {
        marks.push(std::time::Instant::now());
        if phase == 2 {
            a_tx.send(ToCall::Mute(true)).unwrap();
        }
        if phase == 3 {
            a_tx.send(ToCall::Mute(false)).unwrap();
        }
        for f in 0..100 {
            tick.tick().await;
            let pcm = if phase == 1 { vec![0; 960] } else { tone(f) };
            a_tx.send(ToCall::Mic(pcm)).unwrap();
            b_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
        }
    }
    marks.push(std::time::Instant::now());
    drop((a_tx, b_tx));
    let _ = std::fs::remove_dir_all(&dir);
    (seen, marks)
}

/// RT-19: what the caller sends doesn't depend on what is said — talking,
/// silence and talking again look the same on the wire: the same datagram
/// sizes, each at the same rate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt19_call_packets_constant_size_and_rate() {
    let _turn = REALTIME.lock().await;
    let (seen, m) = watched_call("rt19-shape").await;
    let talking = per_second(&seen, m[0], m[1]);
    let silent = per_second(&seen, m[1], m[2]);
    let again = per_second(&seen, m[3], m[4]);
    same_shape(&talking, &silent, 0.05);
    same_shape(&talking, &again, 0.05);
    // One media size, 50 a second (one Opus frame each 20 ms).
    let media: Vec<_> = talking.iter().filter(|(_, r)| **r > 40.0).collect();
    assert_eq!(media.len(), 1, "{talking:?}");
    assert!((45.0..=55.0).contains(media[0].1), "{talking:?}");
}

/// RT-19: muting keeps the rate: the muted phase looks like talking.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt19_mute_keeps_rate() {
    let _turn = REALTIME.lock().await;
    let (seen, m) = watched_call("rt19-mute").await;
    same_shape(
        &per_second(&seen, m[0], m[1]),
        &per_second(&seen, m[2], m[3]),
        0.05,
    );
}

/// RT-18: Maximum privacy's standby tunnel looks like a call, so a call
/// starting on it (and its end) shows nothing on the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt18_max_mode_tunnel_constant() {
    let _turn = REALTIME.lock().await;
    let dir = std::env::temp_dir().join(format!("enclave-rt18-{}", std::process::id()));
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
    let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
    let mut leg = calls::open_leg(&t, &la).await.unwrap();
    let seen = watch(&mut leg);
    let standby = calls::Standby::start(leg, ev_tx.clone());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let s0 = std::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let s1 = std::time::Instant::now();
    let leg_a = standby.take().await.expect("the standby's leg");
    let leg_b = calls::open_leg(&t, &lb).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let pending = signal::offer(Media::Audio, Route::Relay, vec![], now(), &mut rng).unwrap();
    let id = pending.offer().call_id;
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"conv", now(), &mut rng).unwrap();
    let ka = pending.finish(&ans, b"conv", now()).unwrap();
    let helpers = Helpers::in_process();
    let mut txs = Vec::new();
    for (leg, keys, caller, peer) in [(leg_a, ka, true, ab), (leg_b, kb, false, aa)] {
        let (tx, rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        std::mem::forget(out_rx);
        let plan = Plan {
            id,
            keys,
            caller,
            peer_relay: peer,
            codec: helpers.open_call().await.unwrap(),
            video: None,
        };
        tokio::spawn(calls::run(leg, plan, rx, out_tx, ev_tx.clone()));
        txs.push(tx);
    }
    let b_tx = txs.pop().unwrap();
    let a_tx = txs.pop().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let c0 = std::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    for f in 0..150 {
        tick.tick().await;
        a_tx.send(ToCall::Mic(tone(f))).unwrap();
        b_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
    }
    let c1 = std::time::Instant::now();
    same_shape(&per_second(&seen, s0, s1), &per_second(&seen, c0, c1), 0.05);
    drop((a_tx, b_tx));
    let _ = std::fs::remove_dir_all(&dir);
}

/// From when `on` is set, drop each datagram the leg sends with chance
/// `rate` (a seeded generator, so a run repeats): loss on the client's own
/// link, after the link is up.
fn lossy(leg: &mut calls::Leg, rate: f64, seed: u64, on: Arc<std::sync::atomic::AtomicBool>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let out = std::mem::replace(&mut leg.dg.send, tx);
    tokio::spawn(async move {
        // The generator moves only while losing, so the same packets of the
        // talk are lost on every run (how many went before depends on
        // timing: the handshake, keepalives).
        let mut x = seed | 1;
        while let Some(d) = rx.recv().await {
            let drop = on.load(std::sync::atomic::Ordering::Relaxed) && {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x % 1_000_000) as f64 / 1_000_000.0 < rate
            };
            if !drop && out.send(d).is_err() {
                return;
            }
        }
    });
}

/// Speech for the loss matrix, at 48 kHz: a recording when one is given
/// (`ENCLAVE_CALL_SPEECH`, a 16 kHz mono 16-bit WAV, as the nightly job
/// does), else a voice-like signal (a 140 Hz voice with its harmonics, in
/// syllables of about 4 a second).
fn speech(frames: usize) -> Vec<i16> {
    if let Ok(path) = std::env::var("ENCLAVE_CALL_SPEECH") {
        let wav = std::fs::read(path).unwrap();
        let mut at = 12;
        let data = loop {
            let len = u32::from_le_bytes(wav[at + 4..at + 8].try_into().unwrap()) as usize;
            if &wav[at..at + 4] == b"data" {
                break &wav[at + 8..(at + 8 + len).min(wav.len())];
            }
            at += 8 + len + (len & 1);
        };
        let s16: Vec<f32> = data
            .chunks_exact(2)
            .map(|c| f32::from(i16::from_le_bytes([c[0], c[1]])))
            .collect();
        // 16 → 48 kHz, linearly.
        let mut out: Vec<i16> = (0..s16.len().saturating_sub(1) * 3)
            .map(|i| {
                let (j, f) = (i / 3, (i % 3) as f32 / 3.0);
                (s16[j] * (1.0 - f) + s16[j + 1] * f) as i16
            })
            .collect();
        out.resize(frames * 960, 0);
        return out;
    }
    (0..frames * 960)
        .map(|i| {
            let t = i as f32 / 48_000.0;
            let syllable = (2.0 * std::f32::consts::PI * 4.0 * t).sin().max(0.0);
            let voice: f32 = (1..=8)
                .map(|h| (2.0 * std::f32::consts::PI * 140.0 * h as f32 * t).sin() / h as f32)
                .sum();
            (5_000.0 * syllable * voice) as i16
        })
        .collect()
}

/// Each 20 ms frame's energy, in dB.
fn envelope(pcm: &[i16]) -> Vec<f64> {
    pcm.chunks(960)
        .map(|c| {
            let e = c.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / c.len().max(1) as f64;
            // Below 40 dB (an amplitude of about 100 of 32,768) counts as
            // silence: the codec's and the canceller's quiet floors differ.
            (10.0 * (e + 1.0).log10()).max(40.0)
        })
        .collect()
}

/// The best correlation of `b`'s envelope with `a`'s over lags up to 1 s.
fn best_correlation(a: &[f64], b: &[f64]) -> f64 {
    let corr = |x: &[f64], y: &[f64]| {
        let n = x.len().min(y.len());
        if n < 25 {
            return 0.0;
        }
        let (x, y) = (&x[..n], &y[..n]);
        let (mx, my) = (
            x.iter().sum::<f64>() / n as f64,
            y.iter().sum::<f64>() / n as f64,
        );
        let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
        for (p, q) in x.iter().zip(y) {
            sxy += (p - mx) * (q - my);
            sxx += (p - mx).powi(2);
            syy += (q - my).powi(2);
        }
        sxy / (sxx * syy).sqrt().max(1e-9)
    };
    (0..50.min(b.len()))
        .map(|lag| corr(a, &b[lag..]))
        .fold(f64::MIN, f64::max)
}

fn write_wav(path: &std::path::Path, pcm: &[i16]) {
    let mut w = Vec::with_capacity(44 + pcm.len() * 2);
    let data = (pcm.len() * 2) as u32;
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + data).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&48_000u32.to_le_bytes());
    w.extend_from_slice(&96_000u32.to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&data.to_le_bytes());
    for s in pcm {
        w.extend_from_slice(&s.to_le_bytes());
    }
    std::fs::write(path, w).unwrap();
}

/// The call matrix (`docs/11-calls.md` §10): a relayed call with 1 %, 5 %
/// and 10 % of the caller's packets lost. What the callee plays keeps the
/// speech's shape (its loudness, frame by frame, follows what was said:
/// Opus's in-band FEC and loss concealment fill the gaps). With
/// `ENCLAVE_CALL_QUALITY_DIR` set, each run's reference and what was heard
/// are written there as WAVs, for the nightly job's PESQ score.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_quality_under_loss() {
    let _turn = REALTIME.lock().await;
    const FRAMES: usize = 400; // 8 s
    /// Runs of each rate at most.
    const TRIES: usize = 3;
    let talk = speech(FRAMES);
    let reference = envelope(&talk);
    let out_dir = std::env::var_os("ENCLAVE_CALL_QUALITY_DIR").map(std::path::PathBuf::from);
    if let Some(d) = &out_dir {
        std::fs::create_dir_all(d).unwrap();
        write_wav(&d.join("reference.wav"), &talk);
    }
    // What the same call plays with no loss is the yardstick: the sender's
    // echo canceller, noise suppression and gain control shape the sound
    // either way, so only what loss changes is measured.
    let mut baseline: Option<f64> = None;
    // How far below the no-loss run each loss rate may fall. A loaded
    // machine only ever lowers a run's score (frames that come late are
    // concealed like lost ones), so each rate gets a few runs and the best
    // counts: what loss itself costs is the same in every one of them.
    for (rate, margin) in [(0.0, 0.0), (0.01, 0.05), (0.05, 0.08), (0.10, 0.12)] {
        // That the call carries speech at all: 0.85 or more on an idle
        // machine and 0.79 to 0.80 on a loaded one; a broken pipeline is
        // far below. What loss costs is measured against this run.
        let floor = baseline.map_or(0.75, |b| b - margin);
        let mut best: Option<(f64, usize)> = None;
        for _ in 0..TRIES {
            let heard = lossy_call(rate, &talk).await;
            if let Some(d) = &out_dir {
                write_wav(
                    &d.join(format!("loss-{:02}.wav", (rate * 100.0) as u32)),
                    &heard,
                );
            }
            let played = heard.len() / 960;
            let c = best_correlation(&reference, &envelope(&heard));
            eprintln!(
                "loss {:.0}%: {played} frames, envelope correlation {c:.3}",
                rate * 100.0
            );
            if best.is_none_or(|(b, _)| c > b) {
                best = Some((c, played));
            }
            if played >= FRAMES * 9 / 10 && c >= floor {
                break;
            }
        }
        let (c, played) = best.unwrap();
        assert!(
            played >= FRAMES * 9 / 10,
            "{rate}: played {played} of {FRAMES} frames"
        );
        match baseline {
            None => {
                assert!(c >= floor, "the speech's shape comes through: {c:.3}");
                baseline = Some(c);
            }
            Some(b) => assert!(c >= floor, "{rate}: {c:.3}, against {b:.3} with no loss"),
        }
    }
}

/// One relayed call in which the caller's packets are lost at `rate` while
/// it says `talk`: what the callee played.
async fn lossy_call(rate: f64, talk: &[i16]) -> Vec<i16> {
    let dir = std::env::temp_dir().join(format!("enclave-loss-{rate}-{}", std::process::id()));
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
    let mut leg_a = calls::open_leg(&t, &la).await.unwrap();
    let losing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    lossy(
        &mut leg_a,
        rate,
        0x5eed_0000 + (rate * 100.0) as u64,
        Arc::clone(&losing),
    );
    let leg_b = calls::open_leg(&t, &lb).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let pending = signal::offer(Media::Audio, Route::Relay, vec![], now(), &mut rng).unwrap();
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
            video: None,
        };
        tokio::spawn(calls::run(leg, plan, rx, out_tx, ev_tx.clone()));
        sides.push((tx, out_rx));
    }
    let (b_tx, mut b_out) = sides.pop().unwrap();
    let (a_tx, _a_out) = sides.pop().unwrap();
    // The link up and the call joined, in silence; then the loss
    // starts and Ada talks.
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    for _ in 0..75 {
        tick.tick().await;
        a_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
        b_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
    }
    while b_out.try_recv().is_ok() {}
    losing.store(true, std::sync::atomic::Ordering::Relaxed);
    for f in 0..talk.len() / 960 {
        tick.tick().await;
        a_tx.send(ToCall::Mic(talk[f * 960..(f + 1) * 960].to_vec()))
            .unwrap();
        b_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
    }
    // The jitter buffer's tail.
    for _ in 0..25 {
        tick.tick().await;
        a_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
        b_tx.send(ToCall::Mic(vec![0; 960])).unwrap();
    }
    let mut heard = Vec::new();
    while let Ok(o) = b_out.try_recv() {
        if let Out::CallAudio(pcm) = o {
            heard.extend(pcm);
        }
    }
    drop((a_tx, b_tx));
    let _ = std::fs::remove_dir_all(&dir);
    heard
}
