//! Delivery over a mixnet that doesn't answer writes
//! (`docs/09-transport.md` §6.1): receipts mark messages delivered, a lost
//! write is sent again, the recipient keeps one copy, and a message nobody
//! acknowledges is shown as not delivered yet.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Message, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_net::transport::{ServerId, Transport};
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// The network as a one-way sender sees it: writes go one way (no answer),
/// and while `lose` is set they vanish after leaving. Questions go one way
/// too and their answers are fetched by status polls; they always arrive.
struct OneWay {
    net: LocalTransport,
    lose: AtomicBool,
}

#[async_trait::async_trait]
impl Transport for OneWay {
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
        if !self.lose.load(Ordering::SeqCst) {
            self.net.exchange(server, request).await?;
        }
        Ok(None)
    }
    async fn exchange_deferred(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> enclave_net::Result<Option<Vec<u8>>> {
        self.net.exchange(server, request).await?;
        Ok(None)
    }
}

fn find(c: &Client, root: &[u8; 64], text: &str) -> Vec<Message> {
    c.messages(root)
        .unwrap()
        .into_iter()
        .filter(|m| m.text == text)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn receipts_resends_and_not_delivered_yet() {
    use enclave_core::client::outbox::{RECEIPT_DELAY, RESEND_AFTER};
    let net = network();
    let wire = Arc::new(OneWay {
        net: net.clone(),
        lose: AtomicBool::new(false),
    });
    let (mut ada, _) = Client::create(memory(), wire.clone(), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    let (a, b) = (ada.root(), ben.root());

    // Sent one way: on its way until Ben's receipt comes. Ben has nothing
    // to say, so after a moment the receipt goes on its own.
    let m = ada.send_text(&b, "first").await.unwrap();
    assert!(m.sent && !m.delivered);
    ben.sync().await.unwrap();
    assert_eq!(ben.receipts_owed(&a), 1, "waits for something to ride on");
    net.advance(RECEIPT_DELAY);
    ben.sync().await.unwrap();
    assert_eq!(ben.receipts_owed(&a), 0);
    ada.sync().await.unwrap();
    let m = &find(&ada, &b, "first")[0];
    assert!(m.delivered && !m.read && !m.stalled, "{m:?}");
    assert_eq!(ada.outbox_len().unwrap(), 0);

    // Ben answers: the receipt rides on his message, at no extra cost.
    ada.send_text(&b, "second").await.unwrap();
    ben.sync().await.unwrap();
    ben.send_text(&a, "answer").await.unwrap();
    assert_eq!(ben.receipts_owed(&a), 0);
    ada.sync().await.unwrap();
    assert!(find(&ada, &b, "second")[0].delivered);

    // Lost on the way: nothing arrives, then the re-send does, once.
    wire.lose.store(true, Ordering::SeqCst);
    ada.send_text(&b, "lost").await.unwrap();
    wire.lose.store(false, Ordering::SeqCst);
    ben.sync().await.unwrap();
    assert!(find(&ben, &a, "lost").is_empty());
    net.advance(RESEND_AFTER[0] + 1);
    ada.sync().await.unwrap();
    ben.sync().await.unwrap();
    net.advance(RECEIPT_DELAY);
    ben.sync().await.unwrap();
    ada.sync().await.unwrap();
    assert_eq!(find(&ben, &a, "lost").len(), 1);
    assert!(find(&ada, &b, "lost")[0].delivered);

    // Both the first copy and a re-send arrive: Ben keeps one.
    ada.send_text(&b, "twice").await.unwrap();
    net.advance(RESEND_AFTER[0] + 1);
    ada.sync().await.unwrap();
    ben.sync().await.unwrap();
    assert_eq!(find(&ben, &a, "twice").len(), 1);

    // Never arrives: re-sent three times, then not delivered yet.
    wire.lose.store(true, Ordering::SeqCst);
    ada.send_text(&b, "never").await.unwrap();
    for wait in RESEND_AFTER {
        net.advance(wait + 1);
        ada.sync().await.unwrap();
    }
    let m = &find(&ada, &b, "never")[0];
    assert!(m.stalled && !m.delivered, "{m:?}");
    assert_eq!(ada.outbox_len().unwrap(), 0);
}
