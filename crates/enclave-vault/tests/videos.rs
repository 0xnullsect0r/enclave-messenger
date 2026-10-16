//! A video through the engine (demo mode): frames and sound streamed from
//! the window become a clip attachment with a poster and a length, and it
//! plays back in pieces with its sound.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::{Cmd, Out, Snapshot};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

async fn next<T>(rx: &mut UnboundedReceiver<Out>, mut want: impl FnMut(Out) -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if let Some(t) = want(rx.recv().await.expect("engine running")) {
                return t;
            }
        }
    })
    .await
    .expect("in time")
}

fn snapshot(want: impl Fn(&Snapshot) -> bool) -> impl FnMut(Out) -> Option<Snapshot> {
    move |o| match o {
        Out::Snapshot(s) if want(&s) => Some(*s),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_recorded_video_goes_out_and_plays() {
    let (tx, mut rx) = enclave_vault::spawn(enclave_vault::Mode::Demo);
    tx.send(Cmd::Create("Robin".into(), String::new())).unwrap();
    let s = next(&mut rx, snapshot(|s| !s.requests.is_empty())).await;
    let sam = s.requests[0].id.clone();
    tx.send(Cmd::Accept(sam.clone())).unwrap();
    next(
        &mut rx,
        snapshot(|s| s.contacts.iter().any(|c| c.id == sam && c.state == 2)),
    )
    .await;
    tx.send(Cmd::Select(sam.clone())).unwrap();

    // A size that isn't one a video takes is refused.
    tx.send(Cmd::RecordStart(sam.clone(), "walk".into(), 65, 48))
        .unwrap();
    next(&mut rx, snapshot(|s| s.status.contains("Couldn't start"))).await;

    let (w, h) = enclave_media::movie::video_size(64, 48);
    tx.send(Cmd::RecordStart(sam.clone(), "walk".into(), w, h))
        .unwrap();
    for i in 0..36u32 {
        let rgba: Vec<u8> = (0..w * h)
            .flat_map(|p| {
                if (p % w / 8 + i) % 2 == 0 {
                    [200, 30, 30, 255]
                } else {
                    [20, 60, 180, 255]
                }
            })
            .collect();
        tx.send(Cmd::RecordFrame(rgba)).unwrap();
        let pcm: Vec<u8> = (0..1600i16)
            .flat_map(|k| ((k % 40) * 400).to_le_bytes())
            .collect();
        tx.send(Cmd::RecordSound(pcm)).unwrap();
    }
    tx.send(Cmd::RecordEnd("A walk".into())).unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.messages.iter().any(|m| m.outgoing && m.clip_ms > 0)),
    )
    .await;
    let m = s
        .messages
        .iter()
        .find(|m| m.outgoing && m.clip_ms > 0)
        .unwrap();
    assert_eq!(m.clip_ms, 1_200);
    assert_eq!(m.file, "walk.clip");
    assert_eq!(m.text, "A walk");
    let seq = m.seq;

    // Played back: pieces until the last, with sound.
    tx.send(Cmd::PlayClip(sam.clone(), seq)).unwrap();
    let mut frames = 0;
    let mut sound = 0;
    loop {
        let p = next(&mut rx, |o| match o {
            Out::VideoPiece(p) => Some(p),
            _ => None,
        })
        .await;
        assert_eq!((p.fps, p.duration_ms), (30, 1_200));
        assert_eq!(p.key, format!("{sam}:{seq}"));
        assert_eq!(p.first, frames == 0);
        frames += p.frames.len();
        sound += p.pcm.len();
        if p.done {
            break;
        }
        tx.send(Cmd::VideoMore(p.key)).unwrap();
    }
    assert_eq!(frames, 36);
    assert_eq!(sound, 48_000 * 12 / 10);
}
