//! A server that holds a message back (RT-24, `docs/05-ratchet.md` §11):
//! after a minute the conversation says one may not have arrived, and when
//! it does arrive it is marked late.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Event, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_net::transport::{ServerId, Transport};
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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
            effort_inbox: 1,
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

/// One-way writes that, while `hold` is set, wait (as a server holding
/// them back would) until released.
struct Holding {
    net: LocalTransport,
    hold: AtomicBool,
    held: Mutex<Vec<(ServerId, Vec<u8>)>>,
}

impl Holding {
    async fn release(&self) {
        let held = std::mem::take(&mut *self.held.lock().unwrap());
        for (s, r) in held {
            self.net.exchange(&s, r).await.unwrap();
        }
    }
}

#[async_trait::async_trait]
impl Transport for Holding {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        self.net.exchange(server, request).await
    }
    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.net.server_key(server).await
    }
    fn now(&self) -> u64 {
        self.net.now()
    }
    async fn exchange_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> enclave_net::Result<Option<Vec<u8>>> {
        if self.hold.load(Ordering::SeqCst) {
            self.held.lock().unwrap().push((*server, request));
        } else {
            self.net.exchange(server, request).await?;
        }
        Ok(None)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rt24_gap_notice_after_60s() {
    let net = network();
    let wire = Arc::new(Holding {
        net: net.clone(),
        hold: AtomicBool::new(false),
        held: Mutex::new(Vec::new()),
    });
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), wire.clone(), S2, "Ben")
        .await
        .unwrap();
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    let b = ben.root();

    // The first is held back; the second arrives.
    wire.hold.store(true, Ordering::SeqCst);
    ben.send_text(&ada.root(), "first").await.unwrap();
    wire.hold.store(false, Ordering::SeqCst);
    ben.send_text(&ada.root(), "second").await.unwrap();
    ada.sync().await.unwrap();
    assert!(!ada.gap(&b), "not within the first minute");

    // A minute on: pointed out, once.
    net.advance(61);
    let ev = ada.sync().await.unwrap();
    assert!(ev.contains(&Event::Gap { root: b }), "{ev:?}");
    assert!(ada.gap(&b));
    assert!(!ada.sync().await.unwrap().contains(&Event::Gap { root: b }));

    // It arrives after all: marked late, and the gap is gone.
    wire.release().await;
    let ev = ada.sync().await.unwrap();
    let late = ev.iter().find_map(|e| match e {
        Event::Message { message, .. } if message.text == "first" => Some(message.late),
        _ => None,
    });
    assert_eq!(late, Some(true), "{ev:?}");
    assert!(!ada.gap(&b));
    let second = ada
        .messages(&b)
        .unwrap()
        .into_iter()
        .find(|m| m.text == "second")
        .unwrap();
    assert!(!second.late, "the one that came in order isn't");
}
