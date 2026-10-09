//! Three servers held together by the foundation's list (`docs/12-servers.md`
//! §4): people on different servers find each other by username through
//! pins that come only from the list, add each other and talk; cards carry
//! the home server's domain; each server's descriptor is taken only if
//! its own log commits to it and it is the server's; the list moves
//! forward from the home server and never back; a list from any other key
//! is refused.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, CoreError, Event, ListUpdate, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_federation::{FedError, FoundationKey, ServerList};
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use std::sync::Arc;

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

fn list(
    seq: u64,
    servers: &[enclave_federation::ListedServer],
    witnesses: &[enclave_federation::ListedWitness],
    now: u64,
) -> ServerList {
    ServerList {
        seq,
        issued: now,
        expires: now + 30 * 86_400,
        witness_threshold: 3,
        servers: servers.to_vec(),
        witnesses: witnesses.to_vec(),
        relays: Vec::new(),
        push: Vec::new(),
        credgates: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_servers_one_list() {
    let net = LocalTransport::new();
    let mut servers = Vec::new();
    let mut witnesses = Vec::new();
    for (i, d) in ["a.test", "b.test", "c.test"].iter().enumerate() {
        let (s, w) = net.add_federated_server(d, i as u32 + 1).unwrap();
        servers.push(s);
        witnesses.extend(w);
    }
    let ids: Vec<[u8; 16]> = servers.iter().map(|s| s.id()).collect();
    let now = net.now();
    let mut rng = HedgedRng::new().unwrap();
    let foundation = FoundationKey::generate(&mut rng).unwrap();
    let signed = list(1, &servers, &witnesses, now)
        .sign(&foundation, &mut rng)
        .unwrap();

    let mut people = Vec::new();
    for (i, name) in ["Ada", "Ben", "Cy"].iter().enumerate() {
        let (mut c, _) = Client::create(memory(), Arc::new(net.clone()), ids[i], name)
            .await
            .unwrap();
        c.set_foundation(foundation.public()).unwrap();
        assert_eq!(
            c.offer_server_list(&signed).unwrap(),
            ListUpdate::Updated(1)
        );
        assert_eq!(c.offer_server_list(&signed).unwrap(), ListUpdate::Unchanged);
        people.push(c);
    }
    let [ada, ben, cy] = people.as_mut_slice() else {
        unreachable!()
    };
    // Cards carry the home server's domain, from the list.
    assert_eq!(ada.card().server_domain, "a.test");
    assert_eq!(cy.card().server_domain, "c.test");

    // Usernames on each server, pinned only through the list.
    assert_eq!(ada.claim_username("ada").await.unwrap(), "ada@a.test");
    assert_eq!(ben.claim_username("ben").await.unwrap(), "ben@b.test");
    assert_eq!(cy.claim_username("cyrus").await.unwrap(), "cyrus@c.test");

    // Cy (on C) finds Ada (on A) and Ben (on B) by name, adds both, and
    // each conversation crosses servers.
    let card = cy.find_username("@ada@a.test").await.unwrap();
    assert_eq!(
        (card.root, card.server_domain.as_str()),
        (ada.root(), "a.test")
    );
    cy.add_contact(&card, "Hi Ada, from c.test").await.unwrap();
    let card = cy.find_username("ben@b.test").await.unwrap();
    assert_eq!(card.root, ben.root());
    cy.add_contact(&card, "Hi Ben, from c.test").await.unwrap();
    for (p, text) in [
        (&mut *ada, "Hi Ada, from c.test"),
        (&mut *ben, "Hi Ben, from c.test"),
    ] {
        let ev = p.sync().await.unwrap();
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Request { root, text: t, .. }
                if *root == cy.root() && t == text)),
            "{ev:?}"
        );
    }

    // Each server's descriptor, checked against the digest its own log
    // commits to under the witness quorum.
    for (i, d) in ["a.test", "b.test", "c.test"].iter().enumerate() {
        let desc = cy.fetch_descriptor(&ids[i]).await.unwrap();
        assert_eq!((desc.domain.as_str(), desc.id()), (*d, ids[i]));
    }
    assert_eq!(
        cy.server_descriptor(&ids[1]).unwrap().unwrap().domain,
        "b.test"
    );
    // B shows a descriptor its log doesn't carry: refused, and the one
    // held is kept. Once committed, it's taken.
    net.publish_descriptor(&ids[1], "nym-shown-to-one", false)
        .unwrap();
    assert!(matches!(
        cy.fetch_descriptor(&ids[1]).await,
        Err(CoreError::Federation(FedError::NotLogged))
    ));
    assert_eq!(
        cy.server_descriptor(&ids[1]).unwrap().unwrap().nym_address,
        ""
    );
    net.publish_descriptor(&ids[1], "nym-for-everyone", true)
        .unwrap();
    assert_eq!(
        cy.fetch_descriptor(&ids[1]).await.unwrap().nym_address,
        "nym-for-everyone"
    );
    // B serves A's (genuine) descriptor as its own: not B's identity.
    let a_desc = cy.server_descriptor(&ids[0]).unwrap().unwrap().encode();
    net.with_server(&ids[1], |s| s.set_descriptor(a_desc))
        .unwrap();
    assert!(matches!(
        cy.fetch_descriptor(&ids[1]).await,
        Err(CoreError::Federation(FedError::WrongId))
    ));

    // A newer list, mirrored by A: Ada fetches it from her home server. An
    // older one offered afterwards changes nothing.
    let mut l2 = list(2, &servers, &witnesses, now);
    l2.servers[1].weight = 9;
    let signed2 = l2.sign(&foundation, &mut rng).unwrap();
    net.with_server(&ids[0], |s| s.set_server_list(signed2.clone()))
        .unwrap();
    assert_eq!(
        ada.refresh_server_list().await.unwrap(),
        ListUpdate::Updated(2)
    );
    assert_eq!(ada.server_list().unwrap().servers[1].weight, 9);
    assert_eq!(
        ada.offer_server_list(&signed).unwrap(),
        ListUpdate::Unchanged
    );
    assert_eq!(ada.server_list().unwrap().seq, 2);

    // A list signed by anyone else is refused, however new it claims to be.
    let mallory = FoundationKey::generate(&mut rng).unwrap();
    let forged = list(99, &servers, &witnesses, now)
        .sign(&mallory, &mut rng)
        .unwrap();
    assert!(matches!(
        ben.offer_server_list(&forged),
        Err(CoreError::Federation(FedError::Signature))
    ));
    assert_eq!(ben.server_list().unwrap().seq, 1);

    // The list held is kept: given the key again (as at every start), the
    // client still has it.
    ada.set_foundation(foundation.public()).unwrap();
    assert_eq!(ada.server_list().unwrap().seq, 2);
}

/// The real network, seen by a device whose clock is `skew` seconds off.
struct SkewedClock {
    net: LocalTransport,
    skew: std::sync::Mutex<i64>,
}

#[async_trait::async_trait]
impl enclave_net::transport::Transport for SkewedClock {
    async fn exchange(&self, server: &[u8; 16], request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        self.net.exchange(server, request).await
    }
    fn now(&self) -> u64 {
        let skew = *self.skew.lock().unwrap();
        self.net.now().saturating_add_signed(skew)
    }
    async fn server_key(&self, server: &[u8; 16]) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.net.server_key(server).await
    }
}

/// A device clock that trusted time (the witnesses' median timestamp) shows
/// to be wrong raises a warning once, and another when it's right again
/// (RT-23).
#[tokio::test(flavor = "multi_thread")]
async fn rt23_clock_skew_warning_shown() {
    use enclave_core::client::clock::{AHEAD_SECS, CHECK_EVERY_SECS};
    use enclave_net::transport::Transport as _;
    let net = LocalTransport::new();
    let (server, witnesses) = net.add_federated_server("a.test", 1).unwrap();
    let id = server.id();
    let mut rng = HedgedRng::new().unwrap();
    let foundation = FoundationKey::generate(&mut rng).unwrap();
    let signed = list(1, &[server], &witnesses, net.now())
        .sign(&foundation, &mut rng)
        .unwrap();
    let t = Arc::new(SkewedClock {
        net: net.clone(),
        skew: std::sync::Mutex::new(0),
    });
    let (mut ada, _) = Client::create(memory(), t.clone(), id, "Ada")
        .await
        .unwrap();
    ada.set_foundation(foundation.public()).unwrap();
    ada.offer_server_list(&signed).unwrap();
    let clock_events = |ev: &[Event]| -> Vec<Option<i64>> {
        ev.iter()
            .filter_map(|e| match e {
                Event::ClockSkew { skew } => Some(*skew),
                _ => None,
            })
            .collect()
    };

    // A right clock: nothing.
    let ev = ada.sync().await.unwrap();
    assert!(clock_events(&ev).is_empty(), "{ev:?}");
    assert_eq!(ada.clock_skew().unwrap(), None);

    // Two hours behind: warned once, at the next check (due by the
    // device's clock, which moved two hours less).
    *t.skew.lock().unwrap() = -2 * 3600;
    net.advance(CHECK_EVERY_SECS + 2 * 3600);
    let ev = ada.sync().await.unwrap();
    let got = clock_events(&ev);
    assert_eq!(got.len(), 1, "{ev:?}");
    assert!(got[0].is_some_and(|s| (-2 * 3600 - 60..=-2 * 3600 + 60).contains(&s)));
    assert!(ada.clock_skew().unwrap().is_some());
    let ev = ada.sync().await.unwrap();
    assert!(clock_events(&ev).is_empty(), "once: {ev:?}");

    // Set right: the warning goes.
    *t.skew.lock().unwrap() = 0;
    net.advance(CHECK_EVERY_SECS);
    let ev = ada.sync().await.unwrap();
    assert_eq!(clock_events(&ev), vec![None], "{ev:?}");
    assert_eq!(ada.clock_skew().unwrap(), None);

    // Days ahead: past where any head is still fresh.
    *t.skew.lock().unwrap() = i64::try_from(AHEAD_SECS).unwrap() + 86_400;
    let ev = ada.sync().await.unwrap();
    let got = clock_events(&ev);
    assert!(matches!(got.as_slice(), [Some(s)] if *s > 0), "{ev:?}");
    assert!(t.now() > net.now());
}

/// The network, noting the routes the client gives it.
struct Routes {
    net: LocalTransport,
    seen: std::sync::Mutex<Vec<([u8; 16], enclave_net::transport::Route)>>,
}

#[async_trait::async_trait]
impl enclave_net::transport::Transport for Routes {
    async fn exchange(&self, server: &[u8; 16], request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        self.net.exchange(server, request).await
    }
    fn now(&self) -> u64 {
        self.net.now()
    }
    async fn server_key(&self, server: &[u8; 16]) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.net.server_key(server).await
    }
    fn set_route(&self, server: [u8; 16], route: enclave_net::transport::Route) {
        self.seen.lock().unwrap().push((server, route));
    }
}

/// Listed servers are reached at their ingress's Nym address, and a
/// descriptor's (newer) address replaces it.
#[tokio::test(flavor = "multi_thread")]
async fn nym_routes_from_the_list_and_descriptors() {
    use enclave_net::transport::Route;
    let net = LocalTransport::new();
    let (mut a, wa) = net.add_federated_server("a.test", 1).unwrap();
    let (b, wb) = net.add_federated_server("b.test", 2).unwrap();
    a.nym_address = "ingress-a".into();
    let (ida, idb) = (a.id(), b.id());
    let mut rng = HedgedRng::new().unwrap();
    let foundation = FoundationKey::generate(&mut rng).unwrap();
    let witnesses: Vec<_> = wa.into_iter().chain(wb).collect();
    let signed = list(1, &[a, b], &witnesses, net.now())
        .sign(&foundation, &mut rng)
        .unwrap();
    let t = Arc::new(Routes {
        net: net.clone(),
        seen: std::sync::Mutex::default(),
    });
    let (mut ada, _) = Client::create(memory(), t.clone(), ida, "Ada")
        .await
        .unwrap();
    ada.set_foundation(foundation.public()).unwrap();
    ada.offer_server_list(&signed).unwrap();
    // B has no ingress in the list: no route for it.
    assert_eq!(
        t.seen.lock().unwrap().as_slice(),
        &[(ida, Route::Nym("ingress-a".into()))]
    );
    net.publish_descriptor(&idb, "ingress-b", true).unwrap();
    ada.fetch_descriptor(&idb).await.unwrap();
    assert_eq!(
        t.seen.lock().unwrap().last(),
        Some(&(idb, Route::Nym("ingress-b".into())))
    );
}
