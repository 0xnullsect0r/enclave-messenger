//! Pictures through the engine (demo mode, decoding in-process): what is
//! sent is re-encoded without its metadata, and the UI gets a preview.
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

/// A phone photo: EXIF with GPS and orientation 6 (turn right).
fn photo() -> Vec<u8> {
    let (w, h) = (60u16, 40u16);
    let px: Vec<u8> = (0..u32::from(w) * u32::from(h))
        .flat_map(|i| [(i % 251) as u8, 120, 200])
        .collect();
    let mut exif =
        b"Exif\0\0MM\0\x2a\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01\0\x06\0\0\0\0\0\0".to_vec();
    exif.extend_from_slice(b"GPS 48.8584N 2.2945E");
    let mut out = Vec::new();
    let mut e = jpeg_encoder::Encoder::new(&mut out, 90);
    e.add_app_segment(1, exif).unwrap();
    e.encode(&px, w, h, jpeg_encoder::ColorType::Rgb).unwrap();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn sent_pictures_lose_metadata_and_get_previews() {
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

    let original = photo();
    assert!(original.windows(3).any(|w| w == b"GPS"));
    tx.send(Cmd::SendFile(
        sam.clone(),
        "IMG_2041.JPG".into(),
        original,
        "Look".into(),
    ))
    .unwrap();
    let s = next(&mut rx, snapshot(|s| s.messages.iter().any(|m| m.image))).await;
    let m = s.messages.iter().find(|m| m.image).unwrap().clone();
    assert_eq!(m.file, "IMG_2041.jpg");
    assert_eq!(
        m.text, "Look",
        "pictures show their caption, not a file line"
    );

    // The preview: turned upright (40 × 60), for this conversation.
    let p = next(&mut rx, |o| match o {
        Out::Preview(p) => Some(p),
        _ => None,
    })
    .await;
    assert_eq!((p.conversation.as_str(), p.seq), (sam.as_str(), m.seq));
    assert_eq!((p.width, p.height), (40, 60));

    // What was sent (and is saved) carries no metadata.
    tx.send(Cmd::SaveFile(sam.clone(), m.seq)).unwrap();
    let (name, bytes) = next(&mut rx, |o| match o {
        Out::File(n, b) => Some((n, b)),
        _ => None,
    })
    .await;
    assert_eq!(name, "IMG_2041.jpg");
    assert!(bytes.starts_with(&[0xFF, 0xD8, 0xFF]));
    assert!(
        !bytes.windows(3).any(|w| w == b"GPS"),
        "GPS left the device"
    );
    assert!(!bytes.windows(4).any(|w| w == b"Exif"));

    // A file that only claims to be a picture is sent as a plain file.
    tx.send(Cmd::SendFile(
        sam.clone(),
        "notes.png".into(),
        b"just text".to_vec(),
        String::new(),
    ))
    .unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.messages.iter().any(|m| m.file == "notes.png")),
    )
    .await;
    assert!(
        !s.messages
            .iter()
            .find(|m| m.file == "notes.png")
            .unwrap()
            .image
    );

    // A damaged picture is not sent at all.
    let mut broken = photo();
    broken.truncate(40);
    tx.send(Cmd::SendFile(
        sam.clone(),
        "broken.jpg".into(),
        broken,
        String::new(),
    ))
    .unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.status.contains("couldn't read that picture")),
    )
    .await;
    assert!(!s.messages.iter().any(|m| m.file.starts_with("broken")));
}

/// A mediad that dies is replaced by a spare that is already running (the
/// confined vault can't start a new one). Needs the mediad binary, which
/// `cargo test --workspace` builds; skipped otherwise.
#[tokio::test]
async fn a_dead_mediad_is_replaced_by_a_spare() {
    let mediad = std::path::Path::new(env!("CARGO_BIN_EXE_enclave-vault"))
        .with_file_name(format!("enclave-mediad{}", std::env::consts::EXE_SUFFIX));
    let dies = std::path::PathBuf::from("/bin/false");
    if !mediad.exists() || !dies.exists() {
        return;
    }
    let media = enclave_vault::media::Media::spawn_each(&[dies, mediad]).unwrap();
    assert!(media.separate());
    let mut last = Err(String::new());
    for _ in 0..3 {
        last = media.thumbnail(photo(), 32).await;
        if last.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let t = last.expect("the spare decoded it");
    assert!(t.width <= 32 && t.height <= 32);
    assert_eq!(media.alive(), 1, "the first is gone, the spare runs");
}

/// Stickers through the engine: a pack made from a phone photo (redrawn
/// small, without its metadata), shown in the picker, sent, and previewed
/// in the conversation.
#[tokio::test(flavor = "multi_thread")]
async fn sticker_pack_through_the_engine() {
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

    tx.send(Cmd::CreatePack("Robin's".into(), vec![photo(), photo()]))
        .unwrap();
    let s = next(&mut rx, snapshot(|s| !s.sticker_packs.is_empty())).await;
    let pack = s.sticker_packs[0].clone();
    assert_eq!((pack.title.as_str(), pack.count), ("Robin's", 2));

    tx.send(Cmd::LoadStickers).unwrap();
    let p = next(&mut rx, |o| match o {
        Out::Preview(p) if p.conversation.starts_with("stickers/") => Some(p),
        _ => None,
    })
    .await;
    assert_eq!(p.conversation, format!("stickers/{}", pack.id));

    tx.send(Cmd::SendSticker(sam.clone(), pack.id.clone(), 1))
        .unwrap();
    let s = next(&mut rx, snapshot(|s| s.messages.iter().any(|m| m.sticker))).await;
    let m = s.messages.iter().find(|m| m.sticker).unwrap().clone();
    assert!(
        m.text.is_empty() && m.file.is_empty(),
        "no file line for a sticker"
    );
    let p = next(&mut rx, |o| match o {
        Out::Preview(p) if p.conversation == sam => Some(p),
        _ => None,
    })
    .await;
    assert_eq!(p.seq, m.seq);
    assert_eq!((p.width, p.height), (40, 60), "upright, small");
}

/// A 16-bit WAV, 1.2 s of a 330 Hz tone at 22.05 kHz, stereo, with a
/// metadata chunk.
fn recording() -> Vec<u8> {
    let rate = 22_050u32;
    let n = (rate as f32 * 1.2) as usize;
    let mut pcm = Vec::new();
    for i in 0..n {
        let s =
            ((i as f32 * 330.0 * 2.0 * std::f32::consts::PI / rate as f32).sin() * 9000.0) as i16;
        pcm.extend_from_slice(&s.to_le_bytes());
        pcm.extend_from_slice(&s.to_le_bytes());
    }
    let mut w = b"RIFF".to_vec();
    w.extend_from_slice(&((36 + 20 + pcm.len()) as u32).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&rate.to_le_bytes());
    w.extend_from_slice(&(rate * 4).to_le_bytes());
    w.extend_from_slice(&4u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"LIST");
    w.extend_from_slice(&12u32.to_le_bytes());
    w.extend_from_slice(b"INFOIART\0\0\0\0");
    w.extend_from_slice(b"data");
    w.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
    w.extend_from_slice(&pcm);
    w
}

/// Voice notes through the engine: a WAV recording is re-encoded as a
/// voice note (Opus, our container) in mediad's code; the conversation
/// shows its length and waveform, and saving it gives back a WAV.
#[tokio::test(flavor = "multi_thread")]
async fn voice_note_through_the_engine() {
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
    tx.send(Cmd::SendFile(
        sam.clone(),
        "Memo 14.wav".into(),
        recording(),
        String::new(),
    ))
    .unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.messages.iter().any(|m| m.voice && m.voice_ms > 0)),
    )
    .await;
    let m = s.messages.iter().find(|m| m.voice).unwrap().clone();
    assert_eq!(m.voice_ms, 1200);
    assert_eq!(m.waveform.len(), 64);
    assert_eq!(m.file, "voice-note.evn", "not the original name");
    assert!(m.text.is_empty());

    tx.send(Cmd::SaveFile(sam.clone(), m.seq)).unwrap();
    let (name, bytes) = next(&mut rx, |o| match o {
        Out::File(n, b) => Some((n, b)),
        _ => None,
    })
    .await;
    // Saved as Ogg Opus (the note's own packets, playable anywhere).
    assert_eq!(name, "voice-note.opus");
    assert!(bytes.starts_with(b"OggS"));
    assert!(bytes.windows(8).any(|w| w == b"OpusHead"));
    assert!(
        !bytes.windows(4).any(|w| w == b"IART"),
        "no metadata from the original"
    );

    // Played in the app: the sound comes back, 48 kHz mono, all of it.
    tx.send(Cmd::PlayVoice(sam.clone(), m.seq)).unwrap();
    let (key, first, pcm) = next(&mut rx, |o| match o {
        Out::VoiceAudio(k, f, p) => Some((k, f, p)),
        _ => None,
    })
    .await;
    assert_eq!(key, format!("{sam}:{}", m.seq));
    assert!(first);
    assert_eq!(pcm.len(), 48 * 1200);

    // With the speech model at hand (`ENCLAVE_WHISPER_DIR`: the nightly
    // job downloads it), the note is transcribed here and the text kept
    // with it; a tone has no words, which is said so.
    if std::env::var_os("ENCLAVE_WHISPER_DIR").is_some() {
        let s = next(&mut rx, snapshot(|s| s.transcription == 2)).await;
        assert!(s.transcription_error.is_empty());
        tx.send(Cmd::Transcribe(sam.clone(), m.seq)).unwrap();
        let s = next(
            &mut rx,
            snapshot(|s| {
                s.messages
                    .iter()
                    .any(|x| x.voice && !x.transcript.is_empty())
            }),
        )
        .await;
        let t = &s.messages.iter().find(|x| x.voice).unwrap().transcript;
        eprintln!("transcript of the tone: {t:?}");
    }
}

/// A small animated GIF: `n` frames of a block moving right, 100 ms each.
fn animation(n: usize) -> Vec<u8> {
    let (w, h) = (48u16, 32u16);
    let mut out = Vec::new();
    {
        let mut e = gif::Encoder::new(&mut out, w, h, &[]).unwrap();
        for i in 0..n {
            let mut px = vec![0u8; w as usize * h as usize * 4];
            for (j, p) in px.chunks_exact_mut(4).enumerate() {
                let on = ((j % w as usize) / 8 + i).is_multiple_of(3);
                p.copy_from_slice(if on {
                    &[220, 60, 40, 255]
                } else {
                    &[20, 80, 60, 255]
                });
            }
            let mut f = gif::Frame::from_rgba_speed(w, h, &mut px, 10);
            f.delay = 10;
            e.write_frame(&f).unwrap();
        }
    }
    out
}

/// Animated pictures through the engine: a GIF goes out as a short AV1
/// clip (never as a GIF), its poster shows in the conversation with its
/// length, and without mediad the vault refuses to decode the AV1 itself.
#[tokio::test(flavor = "multi_thread")]
async fn clips_through_the_engine() {
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
    tx.send(Cmd::SendFile(
        sam.clone(),
        "party.gif".into(),
        animation(6),
        String::new(),
    ))
    .unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.messages.iter().any(|m| m.clip_ms > 0)),
    )
    .await;
    let m = s.messages.iter().find(|m| m.clip_ms > 0).unwrap().clone();
    assert_eq!(m.clip_ms, 600);
    assert_eq!(m.file, "party.clip");
    assert!(m.image, "shown by its poster");

    tx.send(Cmd::PlayClip(sam.clone(), m.seq)).unwrap();
    let c = next(&mut rx, |o| match o {
        Out::Clip(c) => Some(c),
        _ => None,
    })
    .await;
    assert!(
        c.frames.is_empty(),
        "other people's AV1 is decoded in mediad only, never in the vault"
    );
}

/// The confined mediad encodes a GIF to a clip and plays it back: rav1e and
/// rav1d run under its sandbox (no files, no network, 2 GiB cap). Needs the
/// mediad binary; skipped otherwise.
#[tokio::test]
async fn mediad_plays_clips() {
    let mediad = std::path::Path::new(env!("CARGO_BIN_EXE_enclave-vault"))
        .with_file_name(format!("enclave-mediad{}", std::env::consts::EXE_SUFFIX));
    if !mediad.exists() {
        return;
    }
    let media = enclave_vault::media::Media::spawn_each(&[mediad]).unwrap();
    assert!(media.separate());
    let (clip, w, h, ms) = media.clip(animation(6)).await.unwrap();
    assert_eq!((w, h, ms), (48, 32, 600));
    let (poster, _) = media.clip_poster(clip.clone(), 64).await.unwrap();
    assert_eq!((poster.width, poster.height), (48, 32));
    let (frames, ms) = media.clip_frames(clip.clone(), 360).await.unwrap();
    assert_eq!(ms, 600);
    assert_eq!(frames.len(), 9, "600 ms at 15 frames a second");
    let px = &frames[0].pixels[(16 * 48 + 2) * 4..][..3];
    assert!(px[0] > 150 && px[1] < 110, "the red block, decoded: {px:?}");
    // A damaged clip is refused, and mediad keeps going.
    let mut bad = clip;
    bad[70_000] ^= 0xff;
    let _ = media.clip_frames(bad, 360).await;
    assert!(media.thumbnail(photo(), 16).await.is_ok());
}
