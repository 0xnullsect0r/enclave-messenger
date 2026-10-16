//! Link previews and GIF search through the engine, with a stand-in for
//! the web (demo mode, decoding in-process): nothing is fetched while they
//! are off; when on, a link gets a preview the receiver needs nothing to
//! show, and a GIF from a search goes out as a clip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::{Cmd, GIF_RESULTS, Out, Snapshot};
use enclave_net::transport::{ServerId, Transport, WEB};
use enclave_net::{NetError, Result};
use enclave_rpc::ServerKey;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

/// A few web pages and files, and what was asked for.
#[derive(Default)]
struct Web {
    asked: Mutex<Vec<String>>,
}

fn jpeg() -> Vec<u8> {
    let px: Vec<u8> = (0..64u32 * 48)
        .flat_map(|i| [(i % 251) as u8, 90, 160])
        .collect();
    let mut out = Vec::new();
    jpeg_encoder::Encoder::new(&mut out, 85)
        .encode(&px, 64, 48, jpeg_encoder::ColorType::Rgb)
        .unwrap();
    out
}

fn gif(shade: u8) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut e = gif::Encoder::new(&mut out, 32, 24, &[]).unwrap();
        e.set_repeat(gif::Repeat::Infinite).unwrap();
        for k in 0..3u8 {
            let mut px = [shade, k * 60, 255 - shade, 255].repeat(32 * 24);
            let mut f = gif::Frame::from_rgba_speed(32, 24, &mut px, 10);
            f.delay = 10;
            e.write_frame(&f).unwrap();
        }
    }
    out
}

#[async_trait::async_trait]
impl Transport for Web {
    async fn exchange(&self, _: &ServerId, _: Vec<u8>) -> Result<Vec<u8>> {
        Err(NetError::Unavailable("the web only"))
    }
    async fn server_key(&self, _: &ServerId) -> Result<ServerKey> {
        Err(NetError::Unavailable("the web only"))
    }
    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        assert_eq!(method, "GET");
        assert!(body.is_empty());
        self.asked.lock().unwrap().push(url.to_string());
        let url = url.strip_prefix(WEB).expect("an ordinary web site");
        let page = r#"<html><head><title>fallback</title>
            <meta property="og:title" content="A story">
            <meta property="og:description" content="What happened today">
            <meta property="og:image" content="/card.jpg"></head><body></body></html>"#;
        let commons = r#"{"query":{"pages":[
            {"title":"File:A cat.gif","index":1,"imageinfo":[{"mime":"image/gif","url":"https://upload.example/a.gif","thumburl":"https://upload.example/320px-a.gif","thumbwidth":32,"thumbheight":24}]},
            {"title":"File:B cat.gif","index":2,"imageinfo":[{"mime":"image/gif","url":"https://upload.example/b.gif","width":32,"height":24}]}
        ]}}"#;
        Ok(match url {
            "https://example.org/story" => (200, page.as_bytes().to_vec()),
            "https://example.org/card.jpg" => (200, jpeg()),
            u if u.starts_with(enclave_core::client::web::GIF_SEARCH_API) => {
                assert!(u.contains("cats"), "{u}");
                (200, commons.as_bytes().to_vec())
            }
            "https://upload.example/320px-a.gif" => (200, gif(30)),
            "https://upload.example/b.gif" => (200, gif(200)),
            _ => (404, Vec::new()),
        })
    }
}

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
async fn link_previews_and_gif_search_through_tor() {
    let web = Arc::new(Web::default());
    let (tx, mut rx) =
        enclave_vault::spawn_with_web(enclave_vault::Mode::Demo, Arc::clone(&web) as _);
    tx.send(Cmd::Create("Robin".into(), String::new())).unwrap();
    let s = next(&mut rx, snapshot(|s| !s.requests.is_empty())).await;
    assert!(!s.link_previews && !s.gif_search, "both off at first");
    let sam = s.requests[0].id.clone();
    tx.send(Cmd::Accept(sam.clone())).unwrap();
    next(
        &mut rx,
        snapshot(|s| s.contacts.iter().any(|c| c.id == sam && c.state == 2)),
    )
    .await;
    tx.send(Cmd::Select(sam.clone())).unwrap();

    // Off: a link goes as plain text, and nothing is fetched.
    let text = "look: https://example.org/story";
    tx.send(Cmd::Send(sam.clone(), format!("{text} (off)")))
        .unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.messages.iter().any(|m| m.text.ends_with("(off)"))),
    )
    .await;
    assert!(s.messages.iter().all(|m| m.link_title.is_empty()));
    tx.send(Cmd::GifSearch("cats".into())).unwrap();
    tx.send(Cmd::Select(sam.clone())).unwrap();
    next(&mut rx, snapshot(|_| true)).await;
    assert!(
        web.asked.lock().unwrap().is_empty(),
        "nothing fetched while off"
    );

    // On: the preview is made before sending, and its picture shown.
    tx.send(Cmd::LinkPreviewsSetting(true)).unwrap();
    next(&mut rx, snapshot(|s| s.link_previews)).await;
    tx.send(Cmd::Send(sam.clone(), text.into())).unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| {
            s.messages
                .iter()
                .any(|m| m.text == text && !m.link_title.is_empty())
        }),
    )
    .await;
    let m = s.messages.iter().find(|m| m.text == text).unwrap();
    assert_eq!(m.link_title, "A story");
    assert_eq!(m.link_description, "What happened today");
    assert_eq!(m.link_site, "example.org");
    assert!(m.link_image);
    let seq = m.seq;
    let p = next(&mut rx, |o| match o {
        Out::Preview(p) if p.conversation == sam && p.seq == seq => Some(p),
        _ => None,
    })
    .await;
    assert!(p.width > 0 && p.width <= 240);
    assert_eq!(
        web.asked.lock().unwrap().as_slice(),
        [
            format!("{WEB}https://example.org/story"),
            format!("{WEB}https://example.org/card.jpg")
        ]
    );

    // GIF search: the names, each one's first frame, then one sent as a
    // clip.
    tx.send(Cmd::GifSearchSetting(true)).unwrap();
    next(&mut rx, snapshot(|s| s.gif_search)).await;
    tx.send(Cmd::GifSearch("cats".into())).unwrap();
    let names = next(&mut rx, |o| match o {
        Out::Gifs(n) => Some(n),
        _ => None,
    })
    .await;
    assert_eq!(names, ["A cat", "B cat"]);
    let mut seen = Vec::new();
    while seen.len() < 2 {
        let p = next(&mut rx, |o| match o {
            Out::Preview(p) if p.conversation == GIF_RESULTS => Some(p),
            _ => None,
        })
        .await;
        assert!(p.width <= 160 && p.height <= 160);
        seen.push(p.seq);
    }
    seen.sort_unstable();
    assert_eq!(seen, [0, 1]);
    tx.send(Cmd::SendGif(sam.clone(), 1)).unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.messages.iter().any(|m| m.outgoing && m.clip_ms > 0)),
    )
    .await;
    let clip = s
        .messages
        .iter()
        .find(|m| m.outgoing && m.clip_ms > 0)
        .unwrap();
    assert!(clip.file.starts_with("B cat"), "{}", clip.file);
}
