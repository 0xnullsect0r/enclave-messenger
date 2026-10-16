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
