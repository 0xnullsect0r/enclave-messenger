//! The account inbox's weekly addresses and the request inbox's adaptive
//! effort, end to end (`docs/09-transport.md` §3–§4).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, Event, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_net::transport::{ServerId, Transport};
use enclave_rpc::api::{self, Status};
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];
const S2: [u8; 16] = [2; 16];
const WEEK: u64 = api::WEEK_SECS;

fn network() -> LocalTransport {
    let t = LocalTransport::new();
    for id in [S1, S2] {
        t.add_server(enclave_server::Config {
            id,
            effort_request: 1,
            effort_claim: 1,
            effort_blob: 1,
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

/// Writes go one way, as over the mixnet: the writer never learns that an
/// address wasn't there.
struct OneWay(LocalTransport);

#[async_trait::async_trait]
impl Transport for OneWay {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        self.0.exchange(server, request).await
    }
    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.0.server_key(server).await
    }
    fn now(&self) -> u64 {
        self.0.now()
    }
    async fn exchange_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> enclave_net::Result<Option<Vec<u8>>> {
        self.0.exchange(server, request).await?;
        Ok(None)
    }
}

fn texts(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(message.text.clone()),
            _ => None,
        })
        .collect()
}

async fn pair(net: &LocalTransport) -> (Client, Client) {
    let (mut ada, _) = Client::create(memory(), Arc::new(OneWay(net.clone())), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(OneWay(net.clone())), S2, "Ben")
        .await
        .unwrap();
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    (ada, ben)
}

/// Writers follow the owner's address from week to week. An owner who was
/// away when a week began has no address for it yet: the writer's first
/// re-send falls back to the week before's, which the owner still reads,
/// and the owner makes the missing addresses when it comes back.
#[tokio::test(flavor = "multi_thread")]
async fn inbox_rotates_weekly() {
    use enclave_core::client::outbox::RESEND_AFTER;
    let net = network();
    let (mut ada, mut ben) = pair(&net).await;
    let a = ada.root();

    // Next week: Ada made its address ahead of time.
    net.advance(WEEK);
    ben.send_text(&a, "next week").await.unwrap();
    assert_eq!(texts(&ada.sync().await.unwrap()), ["next week"]);

    // Two weeks on, Ada away all along: this week's address doesn't
    // exist, so the write goes nowhere...
    net.advance(2 * WEEK);
    ben.send_text(&a, "while away").await.unwrap();
    // ...nor does the first re-send (for a write lost on the way)...
    net.advance(RESEND_AFTER[0] + 1);
    ben.sync().await.unwrap();
    // ...until the second, to last week's address (which Ada made the week
    // she was last online).
    net.advance(RESEND_AFTER[1] + 1);
    ben.sync().await.unwrap();
    let got = texts(&ada.sync().await.unwrap());
    assert_eq!(got, ["while away"], "read from the week before's address");

    // Ada made this week's and next week's addresses on coming back:
    // Ben's next write lands at once.
    ben.send_text(&a, "back").await.unwrap();
    assert_eq!(texts(&ada.sync().await.unwrap()), ["back"]);
}

/// A write's session hint tells the owner which of a contact's tokens was
/// used, so it isn't registered at the next week's address.
#[tokio::test(flavor = "multi_thread")]
async fn burned_tokens_are_forgotten() {
    let net = network();
    let (mut ada, mut ben) = pair(&net).await;
    let (a, b) = (ada.root(), ben.root());
    let before = ada.tokens_outstanding(&b);
    assert!(before > 2);
    ben.send_text(&a, "one").await.unwrap();
    ben.send_text(&a, "two").await.unwrap();
    assert_eq!(texts(&ada.sync().await.unwrap()), ["one", "two"]);
    assert_eq!(ada.tokens_outstanding(&b), before - 2);
}

async fn spam_request(net: &LocalTransport, inbox: [u8; 32], n: usize) {
    let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
    let key = net.server_key(&S1).await.unwrap();
    for i in 0..n {
        let env = vec![i as u8; ENVELOPE_LEN];
        let ctx = api::pow_context_request(
            &inbox,
            net.now() / 86_400,
            &enclave_crypto::hash::sha3_512(&env),
        );
        let effort = 1u32 << 12;
        let mut ok = false;
        // The server's effort, or the one the owner raised it to.
        for e in [1, 256, 1024, effort] {
            let proof = enclave_tokens::solve(&ctx, e, &mut rng).unwrap();
            let h = RequestHeader {
                op: Op::WriteRequest,
                flags: 0,
                mailbox: inbox,
                token: proof.0,
            };
            let (bytes, ex) = enclave_rpc::seal_request(&key, &h, &env, &mut rng).unwrap();
            let reply = net.exchange(&S1, bytes).await.unwrap();
            let (rh, _) = ex.open_reply(&reply).unwrap();
            match Status::from_u8(rh.flags) {
                Status::Ok => {
                    ok = true;
                    break;
                }
                s => assert_eq!(s, Status::Pow, "only more work is asked for"),
            }
        }
        assert!(ok);
    }
}

/// A flood of message requests makes new ones cost more, and a calm day
/// brings the cost back down.
#[tokio::test(flavor = "multi_thread")]
async fn request_effort_adapts() {
    use enclave_core::client::{CALM_PER_DAY, FLOOD_PER_DAY};
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let inbox = ada.card().request_inbox;
    spam_request(&net, inbox, FLOOD_PER_DAY as usize - 1).await;
    ada.sync().await.unwrap();
    assert_eq!(ada.request_effort().unwrap().0, 0, "not a flood yet");
    spam_request(&net, inbox, 1).await;
    ada.sync().await.unwrap();
    assert_eq!(ada.request_effort().unwrap().0, 256, "a flood");
    // A calm day after (fewer than CALM_PER_DAY), then the next day.
    net.advance(86_400);
    spam_request(&net, inbox, CALM_PER_DAY as usize - 1).await;
    ada.sync().await.unwrap();
    net.advance(86_400);
    ada.sync().await.unwrap();
    assert_eq!(ada.request_effort().unwrap().0, 0, "calm again");
}
