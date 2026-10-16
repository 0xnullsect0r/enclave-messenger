//! Call signalling between contacts (`docs/11-calls.md` §2): an offer and
//! its answer travel as ratchet messages, both sides end with the same
//! call keys, and each conversation gets its line.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_calls::message::CallMessage;
use enclave_calls::signal::{self, Media, Route};
use enclave_core::{Client, CoreError, Event, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

fn calls(events: Vec<Event>) -> Vec<([u8; 64], CallMessage)> {
    events
        .into_iter()
        .filter_map(|e| match e {
            Event::Call { from, message } => Some((from, CallMessage::decode(&message).unwrap())),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_offer_and_its_answer_give_both_sides_the_same_keys() {
    let net = LocalTransport::new();
    net.add_server(enclave_server::Config {
        id: S1,
        effort_request: 4,
        effort_claim: 1,
        blob_tokens_per_day: 64,
        effort_username: 1,
        ..Default::default()
    })
    .unwrap();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ben")
        .await
        .unwrap();
    let (a, b) = (ada.root(), ben.root());
    let mut rng = HedgedRng::new().unwrap();
    let now = enclave_net::transport::Transport::now(&net);

    // Not before they are contacts.
    let pending = signal::offer(
        Media::Audio,
        Route::Relay,
        b"relay-a".to_vec(),
        now,
        &mut rng,
    )
    .unwrap();
    let offer = CallMessage::Offer(pending.offer().clone());
    assert!(matches!(
        ada.send_call(&b, &offer.encode()).await,
        Err(CoreError::NotFound)
    ));
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&a).await.unwrap();
    ada.sync().await.unwrap();
    let conv = ada.call_conversation(&b);
    assert_eq!(conv, ben.call_conversation(&a));

    // The offer rings Ben's device.
    ada.send_call(&b, &offer.encode()).await.unwrap();
    let got = calls(ben.sync().await.unwrap());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, a);
    let CallMessage::Offer(received) = &got[0].1 else {
        panic!("{:?}", got[0].1)
    };
    let id = received.call_id;
    ben.send_call(&a, &CallMessage::Ringing(id).encode())
        .await
        .unwrap();
    let (answer, ben_keys) =
        signal::answer(received, b"relay-b".to_vec(), &conv, now, &mut rng).unwrap();
    ben.send_call(&a, &CallMessage::Answer(answer).encode())
        .await
        .unwrap();

    // Ada hears it ring, then gets the answer: the same keys on both sides.
    let got = calls(ada.sync().await.unwrap());
    assert!(matches!(got[0].1, CallMessage::Ringing(i) if i == id));
    let CallMessage::Answer(answer) = &got[1].1 else {
        panic!("{:?}", got[1].1)
    };
    let ada_keys = pending.finish(answer, &conv, now).unwrap();
    assert_eq!(ada_keys.check_words(), ben_keys.check_words());
    assert_eq!(ada_keys.rendezvous(), ben_keys.rendezvous());

    // Hanging up, and each side's line in the conversation.
    ada.send_call(&b, &CallMessage::End(id).encode())
        .await
        .unwrap();
    assert!(matches!(
        calls(ben.sync().await.unwrap())[0].1,
        CallMessage::End(i) if i == id
    ));
    ada.add_call_line(&b, true, "Call, 0:42").unwrap();
    let line = ben.add_call_line(&a, false, "Call, 0:42").unwrap();
    assert!(line.notice && line.read);
    let last = ben.messages(&a).unwrap().pop().unwrap();
    assert_eq!(last.text, "Call, 0:42");
    assert!(last.notice);
    // Call signalling never shows as a message.
    assert!(
        ben.messages(&a)
            .unwrap()
            .iter()
            .all(|m| m.text == "hi" || m.notice)
    );
}
