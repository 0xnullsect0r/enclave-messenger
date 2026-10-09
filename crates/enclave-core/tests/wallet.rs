//! zk-nym tickets (`docs/09-transport.md` §7): a device buys ticketbooks
//! from the credential gate its server list names, with tokens blinded to
//! the listed issuer key; connects the mixnet client with them; follows
//! what the client spends; buys the next book from a token left over
//! (no new work) before the last runs out; and refuses a gate whose key
//! isn't the listed one.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, CoreError, Options};
use enclave_credgate::{Config, DevTickets, Gate};
use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_federation::{CredGateEntry, FoundationKey, ServerList};
use enclave_net::transport::{ServerId, Transport};
use enclave_nym::Held;
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use enclave_tokens::privpass::IssuerKey;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};
use zeroize::Zeroizing;

const SEED: [u8; 32] = [9; 32];

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

/// The server network, plus a credential gate and a mixnet client's
/// ticket side as netd would give them.
struct Gated {
    inner: LocalTransport,
    gate: Arc<Gate>,
    challenges: AtomicUsize,
    spent: AtomicU64,
    connected: std::sync::Mutex<Option<Vec<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl Transport for Gated {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        self.inner.exchange(server, request).await
    }
    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.inner.server_key(server).await
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
    async fn fetch(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
    ) -> enclave_net::Result<(u16, Vec<u8>)> {
        assert_eq!(method, "POST");
        let mut rng = HedgedRng::new().unwrap();
        let answer = match url {
            "https://gate.test/credgate/v1/challenge" => {
                self.challenges.fetch_add(1, SeqCst);
                Ok(self.gate.challenge(&mut rng).unwrap())
            }
            "https://gate.test/credgate/v1/tokens" => self.gate.tokens(&body, &mut rng),
            _ => panic!("{url}"),
        };
        Ok(match answer {
            Ok(b) => (200, b),
            Err(s) => (s.as_u16(), Vec::new()),
        })
    }
    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> enclave_net::Result<Vec<u8>> {
        assert_eq!(gate, "https://gate.test");
        let book = self
            .gate
            .ticketbook(&[token, b"withdrawal request"].concat())
            .await
            .map_err(|s| enclave_net::NetError::Unreachable(s.to_string()))?;
        Ok(Held {
            total: 50,
            spent: 0,
            book,
        }
        .encode())
    }
    async fn connect_mixnet(&self, tickets: Vec<Vec<u8>>) -> enclave_net::Result<()> {
        *self.connected.lock().unwrap() = Some(tickets);
        Ok(())
    }
    async fn tickets_spent(&self) -> enclave_net::Result<u64> {
        Ok(self.spent.load(SeqCst))
    }
}

fn list(seq: u64, now: u64, key: [u8; 49], gates: bool) -> ServerList {
    let epoch = enclave_tokens::gate::epoch_of(now);
    ServerList {
        seq,
        issued: now,
        expires: now + 30 * 86_400,
        witness_threshold: 0,
        servers: Vec::new(),
        witnesses: Vec::new(),
        relays: Vec::new(),
        push: Vec::new(),
        credgates: if gates {
            vec![CredGateEntry {
                url: "https://gate.test".into(),
                issuer_name: "gate.test".into(),
                keys: vec![(epoch, key)],
            }]
        } else {
            Vec::new()
        },
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tickets_from_the_listed_gate() {
    let net = LocalTransport::new();
    let (server, _) = net.add_federated_server("a.test", 1).unwrap();
    let clock = net.clone();
    let gate = Gate::open(
        Zeroizing::new(SEED),
        Config {
            effort: 1,
            tokens_per_proof: 8,
            issuer_name: "gate.test".into(),
            ..Config::default()
        },
        Arc::new(DevTickets),
        None,
    )
    .unwrap()
    .with_clock(move || clock.now());
    let gated = Arc::new(Gated {
        inner: net.clone(),
        gate: Arc::new(gate),
        challenges: AtomicUsize::new(0),
        spent: AtomicU64::new(0),
        connected: std::sync::Mutex::new(None),
    });
    let now = net.now();
    let epoch = enclave_tokens::gate::epoch_of(now);
    let key = IssuerKey::derive(&SEED, epoch).unwrap().public().0;
    let mut rng = HedgedRng::new().unwrap();
    let foundation = FoundationKey::generate(&mut rng).unwrap();

    let (mut ada, _) = Client::create(
        memory(),
        Arc::clone(&gated) as Arc<dyn Transport>,
        server.id(),
        "Ada",
    )
    .await
    .unwrap();
    ada.set_foundation(foundation.public()).unwrap();

    // No gate listed: the mixnet client connects without tickets.
    let signed = list(1, now, key, false)
        .sign(&foundation, &mut rng)
        .unwrap();
    ada.offer_server_list(&signed).unwrap();
    ada.start_mixnet().await.unwrap();
    assert_eq!(gated.connected.lock().unwrap().take(), Some(Vec::new()));

    // With the gate listed: one proof of work, one book bought, and the
    // client connects with it.
    let signed = list(2, now, key, true).sign(&foundation, &mut rng).unwrap();
    ada.offer_server_list(&signed).unwrap();
    ada.start_mixnet().await.unwrap();
    let books = gated.connected.lock().unwrap().take().unwrap();
    assert_eq!(books.len(), 1);
    assert_eq!(Held::decode(&books[0]).unwrap().left(), 50);
    assert_eq!(ada.tickets_left().unwrap(), 50);
    assert_eq!(gated.gate.spent_count(), 1);
    assert_eq!(gated.challenges.load(SeqCst), 1);

    // Spending is followed; nothing bought while plenty is left.
    gated.spent.store(30, SeqCst);
    assert!(!ada.upkeep_tickets().await.unwrap());
    assert_eq!(ada.tickets_left().unwrap(), 20);
    // Low: the next book, from a token kept from the first proof.
    gated.spent.store(45, SeqCst);
    assert!(ada.upkeep_tickets().await.unwrap());
    assert_eq!(ada.tickets_left().unwrap(), 55);
    assert_eq!(gated.gate.spent_count(), 2);
    assert_eq!(gated.challenges.load(SeqCst), 1);
    // Spending runs on into the second book.
    gated.spent.store(60, SeqCst);
    assert!(!ada.upkeep_tickets().await.unwrap());
    assert_eq!(ada.tickets_left().unwrap(), 40);

    // A restart: the new mixnet client gets what is left, in order, and
    // counts from zero.
    ada.start_mixnet().await.unwrap();
    let books: Vec<Held> = gated
        .connected
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .iter()
        .map(|b| Held::decode(b).unwrap())
        .collect();
    assert_eq!(books.iter().map(Held::left).collect::<Vec<_>>(), [40]);
    gated.spent.store(5, SeqCst);
    ada.upkeep_tickets().await.unwrap();
    assert_eq!(ada.tickets_left().unwrap(), 35);

    // A list naming a key that isn't the gate's: its tokens don't verify
    // against the listed key, so nothing is bought.
    let (mut ben, _) = Client::create(
        memory(),
        Arc::clone(&gated) as Arc<dyn Transport>,
        server.id(),
        "Ben",
    )
    .await
    .unwrap();
    ben.set_foundation(foundation.public()).unwrap();
    let other = IssuerKey::derive(&[1; 32], epoch).unwrap().public().0;
    let signed = list(3, now, other, true)
        .sign(&foundation, &mut rng)
        .unwrap();
    ben.offer_server_list(&signed).unwrap();
    assert!(matches!(
        ben.start_mixnet().await,
        Err(CoreError::Tickets(_))
    ));
    assert_eq!(ben.tickets_left().unwrap(), 0);
    assert_eq!(gated.gate.spent_count(), 2);
}
