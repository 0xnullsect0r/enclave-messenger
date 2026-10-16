//! Call key agreement, SFrame, shaping and tickets.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_calls::CallError;
use enclave_calls::sframe::{self, Receiver, Sender};
use enclave_calls::shape::{self, Inner, Reassembler, Shaper, Stream};
use enclave_calls::signal::{self, Answer, CALLEE, CALLER, Media, Offer, Route};
use enclave_calls::ticket::{self, PERIOD_SECS, TicketSecretKey};
use enclave_crypto::rng::HedgedRng;

const NOW: u64 = 1_790_000_000;

fn keys(rng: &mut HedgedRng) -> (signal::CallKeys, signal::CallKeys) {
    let pending = signal::offer(Media::Audio, Route::Relay, b"relay-A".to_vec(), NOW, rng).unwrap();
    let offer = Offer::decode(&pending.offer().encode()).unwrap();
    let (ans, callee) = signal::answer(&offer, b"relay-B".to_vec(), b"conv", NOW + 5, rng).unwrap();
    let ans = Answer::decode(&ans.encode()).unwrap();
    let caller = pending.finish(&ans, b"conv", NOW + 6).unwrap();
    (caller, callee)
}

#[test]
fn offer_answer_agree_and_bind_the_conversation() {
    let mut rng = HedgedRng::new().unwrap();
    let (a, b) = keys(&mut rng);
    assert_eq!(a.sframe_base(CALLER, 0)[..], b.sframe_base(CALLER, 0)[..]);
    assert_ne!(a.sframe_base(CALLER, 0)[..], a.sframe_base(CALLEE, 0)[..]);
    assert_eq!(a.check_words(), b.check_words());
    assert_eq!(a.rendezvous(), b.rendezvous());

    // Wrong conversation id: different keys (the answer is bound to it).
    let pending = signal::offer(Media::Audio, Route::Relay, vec![], NOW, &mut rng).unwrap();
    let (ans, callee) = signal::answer(pending.offer(), vec![], b"conv-1", NOW, &mut rng).unwrap();
    let caller = pending.finish(&ans, b"conv-2", NOW).unwrap();
    assert_ne!(
        caller.sframe_base(CALLER, 0)[..],
        callee.sframe_base(CALLER, 0)[..]
    );

    // Stale offers.
    let pending = signal::offer(Media::Video(1), Route::Direct, vec![], NOW, &mut rng).unwrap();
    assert!(matches!(
        signal::answer(pending.offer(), vec![], b"c", NOW + 61, &mut rng),
        Err(CallError::Stale)
    ));
    let o = Offer::decode(&pending.offer().encode()).unwrap();
    assert_eq!((o.media, o.route), (Media::Video(1), Route::Direct));
}

#[test]
fn sframe_epochs_reordering_replay_and_tamper() {
    let mut rng = HedgedRng::new().unwrap();
    let (a, b) = keys(&mut rng);
    let mut tx = Sender::new(CALLER, &a.sframe_base(CALLER, 0));
    let mut rx = Receiver::new(CALLER, &b.sframe_base(CALLER, 0));
    let mut stream = Shaper::new(Stream::Audio);

    // 12 s of audio at 50 packets/s: epochs 0, 1 and 2.
    let mut packets = Vec::new();
    for i in 0..600u64 {
        if i % 3 == 0 {
            stream.push_frame(&[i as u8; 80]).unwrap(); // speaking a third of the time
        }
        let pt = stream.next_plaintext();
        packets.push(tx.protect(i * 20, b"", &pt).unwrap());
    }
    assert_eq!(tx.epoch(), 2);
    assert!(
        packets.iter().all(|p| p.len() == shape::AUDIO_PACKET),
        "constant size, speaking or not"
    );

    // Swap two packets across the 5 s boundary and drop one.
    packets.swap(249, 251);
    packets.remove(300);
    let mut media = 0;
    for p in &packets {
        match shape::decode_plaintext(&rx.unprotect(p, b"").unwrap()).unwrap() {
            Inner::Media(m) => {
                assert_eq!(m.len(), 80);
                media += 1;
            }
            Inner::Padding => {}
            Inner::Control(_) => panic!(),
        }
    }
    assert_eq!(media, 199, "one media packet was dropped");
    assert_eq!(rx.unprotect(&packets[500], b""), Err(CallError::Replay));
    // Two epochs back is gone.
    assert_eq!(rx.unprotect(&packets[10], b""), Err(CallError::UnknownKey));
    // Tamper: header (AD), body, metadata.
    let fresh = tx.protect(12_000, b"m", &stream.next_plaintext()).unwrap();
    let mut bad = fresh.clone();
    bad[5] ^= 1;
    assert!(rx.unprotect(&bad, b"m").is_err());
    let mut bad = fresh.clone();
    let n = bad.len() - 1;
    bad[n] ^= 1;
    assert_eq!(rx.unprotect(&bad, b"m"), Err(CallError::Crypto));
    assert_eq!(rx.unprotect(&fresh, b"x"), Err(CallError::Crypto));
    rx.unprotect(&fresh, b"m").unwrap();
    // A frame far in the future is refused without disturbing state.
    let far = Sender::new(CALLER, &a.sframe_base(CALLER, 0))
        .protect(200_000, b"", &[0; 111])
        .unwrap();
    assert_eq!(rx.unprotect(&far, b""), Err(CallError::UnknownKey));
    // Another participant's KID is refused.
    let other = Sender::new(CALLEE, &a.sframe_base(CALLEE, 0))
        .protect(12_000, b"", &[0; 111])
        .unwrap();
    assert_eq!(rx.unprotect(&other, b""), Err(CallError::UnknownKey));
    assert_eq!(sframe::parse_header(&fresh).unwrap().2, sframe::HEADER_LEN);
}

#[test]
fn shaping_is_constant_and_only_steps_down() {
    assert_eq!(Stream::Audio.interval_us(), 20_000);
    assert_eq!(Stream::Video(0).interval_us(), 32_000);
    assert_eq!(Stream::Video(2).interval_us(), 6_400);
    let mut s = Shaper::new(Stream::Video(2));
    let frame: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
    s.push_video_frame(&frame).unwrap();
    s.push_control(b"step-down").unwrap();
    let mut r = Reassembler::default();
    let mut control = None;
    let mut got = None;
    for _ in 0..10 {
        let pt = s.next_plaintext();
        assert_eq!(pt.len(), shape::VIDEO_PACKET - sframe::OVERHEAD);
        match shape::decode_plaintext(&pt).unwrap() {
            Inner::Media(m) => got = r.push(&m).or(got),
            Inner::Control(c) => control = Some(c),
            Inner::Padding => {}
        }
    }
    assert_eq!(control.as_deref(), Some(&b"step-down"[..]), "control first");
    assert_eq!(got.unwrap(), frame);
    assert!(s.step_down(1_000));
    assert!(!s.step_down(20_000), "not twice within 30 s");
    assert!(s.step_down(31_000));
    assert!(!s.step_down(100_000), "never below the lowest tier");
    assert_eq!(s.stream(), Stream::Video(0));
    assert!(Shaper::new(Stream::Audio).push_frame(&[0; 200]).is_err());
}

#[test]
fn tickets() {
    let mut rng = HedgedRng::new().unwrap();
    let relay_key = TicketSecretKey::generate([7; 16], 20_000, &mut rng).unwrap();
    let (req, client) = ticket::request(relay_key.public(), [9; 32], 3600, 1, &mut rng).unwrap();
    let accepted = relay_key.accept(&req, 1).unwrap();
    assert_eq!((accepted.wg_public, accepted.duration), ([9; 32], 3600));
    let spend = accepted.spend;
    let (reply, relay_ticket) = accepted
        .issue([1; 16], NOW, NOW + 3600, [4; 32], &mut rng)
        .unwrap();
    let issued = client.finish(&reply, NOW - 2).unwrap();
    assert_eq!((issued.relay_wg, issued.offset), ([4; 32], 2));
    let client_ticket = issued.ticket;
    assert_eq!(client_ticket.psk(3)[..], relay_ticket.psk(3)[..]);
    assert_ne!(client_ticket.psk(3)[..], client_ticket.psk(4)[..]);
    assert_eq!(client_ticket.period(NOW + PERIOD_SECS + 1), 1);
    // The same request burns the same id; another request another.
    assert_eq!(relay_key.accept(&req, 1).unwrap().spend, spend);
    let (other, _) = ticket::request(relay_key.public(), [9; 32], 3600, 1, &mut rng).unwrap();
    assert_ne!(relay_key.accept(&other, 1).unwrap().spend, spend);
    // Tampering anywhere (the proof of work last) is refused.
    for i in [4, 100, req.len() - 40, req.len() - 1] {
        let mut bad = req.clone();
        bad[i] ^= 1;
        assert!(relay_key.accept(&bad, 1).is_err(), "byte {i}");
    }
    assert_eq!(
        relay_key.accept(&req[..req.len() - 1], 1).err(),
        Some(CallError::Malformed)
    );
}
