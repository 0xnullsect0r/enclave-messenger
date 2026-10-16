//! Red-team rows that need a client misbehaving on purpose
//! (`docs/redteam-matrix.md`), with crate access to send what the public
//! API never would.
#![allow(clippy::unwrap_used)]

use super::{Client, Event, Options};
use crate::content::Content;
use crate::files::Attachment;
use enclave_crypto::pwhash::PwParams;
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];
const S2: [u8; 16] = [2; 16];

fn network() -> LocalTransport {
    let t = LocalTransport::new();
    for id in [S1, S2] {
        t.add_server(enclave_server::Config {
            id,
            effort_request: 4,
            effort_claim: 1,
            blob_tokens_per_day: 64,
            effort_username: 1,
            ..Default::default()
        })
        .unwrap();
    }
    t
}

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

/// RT-25: message requests are text only (`09-transport.md` §4). A
/// stranger's client that puts a file, a sticker or a place in its first
/// message instead of a greeting gets nothing in: the request is dropped
/// whole, no contact or request appears, and nothing it names is fetched.
/// The same stranger's plain greeting still arrives, as text.
#[tokio::test(flavor = "multi_thread")]
async fn rt25_request_media_stripped() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut mal, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Mal")
        .await
        .unwrap();
    let card = ada.card();
    let now = mal.now();
    let (manifest, vault) = mal.fetch_peer(&card, now).await.unwrap();
    let file = Attachment {
        host: S2,
        secret: [7; 32],
        size: 4096,
        chunks: 1,
        hash: [8; 64],
        name: "photo.jpg".into(),
        mime: "image/jpeg".into(),
    }
    .encode();
    let media = [
        Content::Attachment {
            id: [1; 16],
            attachment: file.clone(),
            caption: "look at this".into(),
            expires: 0,
        },
        Content::Sticker {
            id: [2; 16],
            pack: file,
            index: 0,
            expires: 0,
        },
        Content::Location {
            id: [3; 16],
            location: b"48.8584,2.2945".to_vec(),
            expires: 0,
        },
    ];
    let gets_before = net.with_server(&S2, |s| s.take_blob_gets().len()).unwrap();
    for content in &media {
        // A fresh session each time, as a first message.
        mal.sessions.retain(|(r, _), _| *r != card.root);
        mal.initiate_to(
            &card,
            &manifest,
            Some(&vault),
            &content.encode().unwrap(),
            None,
            now,
            None,
        )
        .await
        .unwrap();
        let ev = ada.sync().await.unwrap();
        assert!(ev.is_empty(), "{ev:?}");
        assert!(ada.contact(&mal.root()).is_none(), "no request kept");
    }
    assert_eq!(
        net.with_server(&S2, |s| s.take_blob_gets().len()).unwrap(),
        gets_before,
        "nothing a request names is fetched"
    );

    // An ordinary greeting from the same stranger: a text request.
    mal.sessions.retain(|(r, _), _| *r != card.root);
    mal.add_contact(&card, "hello, it's Mal").await.unwrap();
    let ev = ada.sync().await.unwrap();
    assert_eq!(
        ev,
        vec![Event::Request {
            root: mal.root(),
            name: "Mal".into(),
            text: "hello, it's Mal".into(),
        }]
    );
    assert!(
        ada.messages(&mal.root())
            .unwrap()
            .iter()
            .all(|m| m.attachment.is_none())
    );
}
