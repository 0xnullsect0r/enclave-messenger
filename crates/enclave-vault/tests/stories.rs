//! Stories through the engine (demo mode): posting words and a picture,
//! who they go to, opening one, deleting one.
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

fn photo() -> Vec<u8> {
    let px: Vec<u8> = (0..48u32 * 32).flat_map(|i| [(i % 251) as u8, 120, 200]).collect();
    let mut out = Vec::new();
    jpeg_encoder::Encoder::new(&mut out, 90)
        .encode(&px, 48, 32, jpeg_encoder::ColorType::Rgb)
        .unwrap();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn stories_through_the_engine() {
    let (tx, mut rx) = enclave_vault::spawn(enclave_vault::Mode::Demo);
    tx.send(Cmd::Create("Robin".into(), String::new())).unwrap();
    let s = next(&mut rx, snapshot(|s| !s.requests.is_empty())).await;
    let sam = s.requests[0].id.clone();
    tx.send(Cmd::Accept(sam.clone())).unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.story_audience.iter().any(|p| p.id == sam)),
    )
    .await;
    assert!(s.stories.is_empty());
    assert!(s.story_audience.iter().find(|p| p.id == sam).unwrap().selected);

    // Words: ours, going to Sam.
    tx.send(Cmd::PostStory("At the lake".into(), String::new(), Vec::new()))
        .unwrap();
    let s = next(&mut rx, snapshot(|s| !s.stories.is_empty())).await;
    let ours = &s.stories[0];
    assert_eq!((ours.who.as_str(), ours.text.as_str()), ("", "At the lake"));
    assert_eq!(ours.name, "Robin");
    assert_eq!(ours.reached + ours.waiting, 1);

    // Hidden from Sam: the next one goes to nobody.
    tx.send(Cmd::StoryHidden(sam.clone(), true)).unwrap();
    next(
        &mut rx,
        snapshot(|s| s.story_audience.iter().any(|p| p.id == sam && !p.selected)),
    )
    .await;
    tx.send(Cmd::PostStory(String::new(), "lake.jpg".into(), photo()))
        .unwrap();
    let s = next(&mut rx, snapshot(|s| s.stories.len() == 2)).await;
    let pic = s.stories.iter().find(|r| r.picture).unwrap().clone();
    assert_eq!(pic.reached + pic.waiting, 0);
    assert!(pic.key.starts_with("me/"));

    // Opening it decodes its picture.
    tx.send(Cmd::OpenStory(pic.key.clone())).unwrap();
    let p = next(&mut rx, |o| match o {
        Out::Preview(p) if p.conversation == format!("story/{}", pic.key) => Some(p),
        _ => None,
    })
    .await;
    assert!(p.width > 0 && p.height > 0);

    // Deleted.
    tx.send(Cmd::DeleteStory(pic.key.clone())).unwrap();
    let s = next(&mut rx, snapshot(|s| s.stories.len() == 1)).await;
    assert_eq!(s.stories[0].text, "At the lake");
}
