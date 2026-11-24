//! The join story, in process (RFC 0012): an application parses and
//! survives its checks only when everything about the stack is true; the
//! rebuild takes listed servers that still are who they were, refuses a
//! changed identity, and the resulting list verifies under the
//! foundation's public key.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::{FoundationKey, ListedServer, ServerList};
use enclave_registrar::Application;
use enclave_rpc::ServerSecret;

/// Everything `NOW`-anchored, as `enclave-admin`'s tests do.
const NOW: u64 = 1_900_000_000;
const DAY: u64 = 86_400;

fn descriptor(
    domain: &str,
    identity: &CompositeSigningKey,
    rng: &mut HedgedRng,
) -> enclave_federation::ServerDescriptor {
    let head = CompositeSigningKey::generate(rng).unwrap();
    let day = (NOW / DAY) as u32;
    let keys = [
        ServerSecret::from_seed(day, &[1; 32]).public().clone(),
        ServerSecret::from_seed(day + 1, &[2; 32]).public().clone(),
    ];
    enclave_federation::ServerDescriptor::sign(
        identity,
        domain,
        &format!("op-{domain}"),
        &format!("fam-{domain}"),
        "",
        "",
        enclave_federation::Policy::default(),
        Some(enclave_federation::KtKeys {
            head_key: head.public().clone(),
            vrf_public: vec![9; 32],
        }),
        &keys,
        &[],
        NOW - 10,
        NOW + DAY,
        rng,
    )
    .unwrap()
}

/// The application body, as `enclave-server apply` makes it.
fn body(descriptor: &enclave_federation::ServerDescriptor, id: &[u8; 16], effort: u32) -> Vec<u8> {
    let mut rng = HedgedRng::new().unwrap();
    let d = descriptor.encode();
    let proof = enclave_tokens::solve(
        &enclave_rpc::api::pow_context_join(id, NOW / DAY),
        effort,
        &mut rng,
    )
    .unwrap();
    [
        &(d.len() as u32).to_be_bytes()[..],
        &d,
        &0u32.to_be_bytes(),
        &proof.0,
    ]
    .concat()
}

fn list_of(seq: u64, server: ListedServer) -> ServerList {
    ServerList {
        seq,
        issued: NOW,
        expires: NOW + DAY,
        witness_threshold: 1,
        servers: vec![server],
        witnesses: Vec::new(),
        relays: Vec::new(),
        push: Vec::new(),
        credgates: Vec::new(),
    }
}

/// An application parses, and survives its checks only when the stack is
/// what it says: a bad proof of work, or a front serving anything but the
/// applied descriptor, is refused.
#[test]
fn an_application_is_checked_completely() {
    let mut rng = HedgedRng::new().unwrap();
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let d = descriptor("new.test", &identity, &mut rng);
    let id = enclave_federation::server_id(identity.public());
    let served = d.encode();

    // Good: parse and check.
    let (a, proof) = Application::parse(&body(&d, &id, 1)).unwrap();
    assert_eq!(a.check(&proof, 1, NOW, &served).unwrap(), id);

    // The proof at an effort the registrar didn't ask for: a proof that
    // passes a lower bar doesn't clear a higher one (the scheme is
    // probabilistic, so find one that genuinely fails).
    let too_weak = loop {
        let p = enclave_tokens::solve(
            &enclave_rpc::api::pow_context_join(&id, NOW / DAY),
            1,
            &mut HedgedRng::new().unwrap(),
        )
        .unwrap();
        if !enclave_tokens::verify(&enclave_rpc::api::pow_context_join(&id, NOW / DAY), 8, &p) {
            break p;
        }
    };
    assert!(a.check(&too_weak.0, 8, NOW, &served).is_err());

    // A front serving something else: no.
    assert!(a.check(&proof, 1, NOW, b"an imposter").is_err());

    // Truncated garbage: no.
    assert!(Application::parse(&body(&d, &id, 1)[..20]).is_err());
}

/// The rebuild: a listed server that still is who it was stays, one that
/// changed identity or went quiet keeps its last entry, an application joins, and the
/// result verifies under the foundation's public key with the next
/// sequence number.
#[test]
fn the_rebuild_keeps_who_stays_holds_who_changed_and_takes_the_new() {
    use std::collections::HashMap;
    let mut rng = HedgedRng::new().unwrap();
    let key = FoundationKey::generate(&mut rng).unwrap();

    // The one listed server, still itself.
    let old_identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let old = descriptor("old.test", &old_identity, &mut rng);
    let old_entry = Application {
        descriptor: old.clone(),
        witness: None,
    }
    .entries()
    .0;
    let previous = list_of(4, old_entry);

    // The applicant, with its witness (a stack runs one).
    let new_identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let new = descriptor("new.test", &new_identity, &mut rng);
    let new_id = enclave_federation::server_id(new_identity.public());
    let witness_key = CompositeSigningKey::generate(&mut rng).unwrap();
    let witness = enclave_federation::WitnessDescriptor::sign(
        &witness_key,
        "op-new.test",
        "fam-new.test",
        "https://new.test/witness/v1",
        NOW - 10,
        NOW + DAY,
        &mut rng,
    )
    .unwrap();
    let application_body = {
        let d = new.encode();
        let w = witness.encode();
        let proof = enclave_tokens::solve(
            &enclave_rpc::api::pow_context_join(&new_id, NOW / DAY),
            1,
            &mut rng,
        )
        .unwrap();
        [
            &(d.len() as u32).to_be_bytes()[..],
            &d,
            &(w.len() as u32).to_be_bytes()[..],
            &w,
            &proof.0,
        ]
        .concat()
    };
    let (application, proof) = Application::parse(&application_body).unwrap();
    application.check(&proof, 1, NOW, &new.encode()).unwrap();

    let statik = enclave_registrar::Static {
        witness_threshold: 1,
        valid_days: 3,
        ..Default::default()
    };

    // Both fronts answer: the list takes both, seq 5.
    let mut served = HashMap::new();
    served.insert("old.test".to_string(), old.encode());
    let bytes = enclave_registrar::rebuild(
        &previous,
        &served,
        &[application],
        &statik,
        NOW,
        &key,
        &mut rng,
    )
    .unwrap();
    let list = ServerList::verify(&bytes, &key.public(), NOW, 4).unwrap();
    assert_eq!(list.seq, 5);
    assert_eq!(list.servers.len(), 2);
    assert_eq!(list.witnesses.len(), 1, "the applicant's witness is listed");
    assert!(list.servers.iter().any(|s| s.domain == "old.test"));
    assert!(list.servers.iter().any(|s| s.domain == "new.test"));
    // The same bytes verify for a client that held seq 4.
    assert!(ServerList::verify(&bytes, &key.public(), NOW, 5).is_err());

    // Replaced by a different identity, or not answering at all: it keeps
    // the entry it last proved, and the list still renews.
    let impostor = descriptor(
        "old.test",
        &CompositeSigningKey::generate(&mut rng).unwrap(),
        &mut rng,
    );
    let mut hijacked = HashMap::new();
    hijacked.insert("old.test".to_string(), impostor.encode());
    let mut previous = previous;
    previous.witnesses.push(enclave_federation::ListedWitness {
        key: witness.key.clone(),
        operator: witness.operator.clone(),
        family: witness.family.clone(),
        url: witness.url.clone(),
    });
    for served in [hijacked, HashMap::new()] {
        let bytes =
            enclave_registrar::rebuild(&previous, &served, &[], &statik, NOW, &key, &mut rng)
                .unwrap();
        let list = ServerList::verify(&bytes, &key.public(), NOW, 4).unwrap();
        assert_eq!(list.seq, 5);
        assert_eq!(list.servers.len(), 1);
        assert_eq!(list.servers[0].id(), previous.servers[0].id());
    }
}

/// The proof is checked again at the rebuild, which can land after
/// midnight: yesterday's still counts, the day before doesn't.
#[test]
fn a_proof_of_work_survives_midnight_but_not_two() {
    let mut rng = HedgedRng::new().unwrap();
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let d = descriptor("new.test", &identity, &mut rng);
    let id = enclave_federation::server_id(identity.public());
    let proof = enclave_tokens::solve(
        &enclave_rpc::api::pow_context_join(&id, NOW / DAY - 2),
        12,
        &mut rng,
    )
    .unwrap();
    let served = d.encode();
    let a = Application {
        descriptor: d,
        witness: None,
    };
    let fresh = enclave_tokens::solve(
        &enclave_rpc::api::pow_context_join(&id, NOW / DAY - 1),
        12,
        &mut rng,
    )
    .unwrap();
    a.check(&fresh.0, 12, NOW, &served).unwrap();
    assert!(a.check(&proof.0, 12, NOW, &served).is_err());
}

/// The foundation's push relays come from the spec, in the same key file
/// `enclave-admin server-list build` reads, and survive every rebuild.
#[test]
fn the_rebuild_keeps_the_push_relay_keys() {
    use std::collections::HashMap;
    let mut rng = HedgedRng::new().unwrap();
    let key = FoundationKey::generate(&mut rng).unwrap();
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let d = descriptor("old.test", &identity, &mut rng);
    let entry = Application {
        descriptor: d.clone(),
        witness: None,
    }
    .entries()
    .0;
    let witness_key = CompositeSigningKey::generate(&mut rng).unwrap();
    let witness = enclave_federation::WitnessDescriptor::sign(
        &witness_key,
        "op-w.test",
        "fam-w.test",
        "https://old.test/witness/v1",
        NOW - 10,
        NOW + DAY,
        &mut rng,
    )
    .unwrap();
    let mut previous = list_of(4, entry);
    previous.witnesses.push(enclave_federation::ListedWitness {
        key: witness.key.clone(),
        operator: witness.operator.clone(),
        family: witness.family.clone(),
        url: witness.url.clone(),
    });

    let dir = std::env::temp_dir().join(format!("enclave-registrar-push-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let keys = dir.join("push.keys");
    std::fs::write(&keys, vec![7u8; 2 * enclave_federation::PUSH_KEY_LEN]).unwrap();
    let witness_file = dir.join("witness.bin");
    std::fs::write(&witness_file, witness.encode()).unwrap();
    let statik = enclave_registrar::Static {
        witness_threshold: 1,
        valid_days: 3,
        // Already on the list: it must not be listed twice.
        witness: vec![witness_file.display().to_string()],
        push: vec![enclave_registrar::PushSpec {
            nym_address: String::new(),
            onion: "example.onion".into(),
            keys: keys.display().to_string(),
        }],
        ..Default::default()
    };
    let mut served = HashMap::new();
    served.insert("old.test".to_string(), d.encode());
    let bytes =
        enclave_registrar::rebuild(&previous, &served, &[], &statik, NOW, &key, &mut rng).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let list = ServerList::verify(&bytes, &key.public(), NOW, 4).unwrap();
    assert_eq!(list.push.len(), 1);
    assert_eq!(list.push[0].keys.len(), 2);
    assert_eq!(list.witnesses.len(), 1);
}

/// A relay's descriptor lasts two days. One that has lapsed keeps the
/// entry the list already holds for that relay; a lapsed one the list
/// never held is still refused.
#[test]
fn an_expired_relay_descriptor_keeps_its_listed_entry() {
    use std::collections::HashMap;
    let mut rng = HedgedRng::new().unwrap();
    let key = FoundationKey::generate(&mut rng).unwrap();
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let d = descriptor("old.test", &identity, &mut rng);
    let entry = Application {
        descriptor: d.clone(),
        witness: None,
    }
    .entries()
    .0;
    let witness_key = CompositeSigningKey::generate(&mut rng).unwrap();
    let witness = enclave_federation::WitnessDescriptor::sign(
        &witness_key,
        "op-w.test",
        "fam-w.test",
        "https://old.test/witness/v1",
        NOW - 10,
        NOW + DAY,
        &mut rng,
    )
    .unwrap();
    let relay_key = CompositeSigningKey::generate(&mut rng).unwrap();
    let lapsed = enclave_federation::RelayDescriptor::sign(
        &relay_key,
        "op-r.test",
        "fam-r.test",
        "198.51.100.7:51820",
        [5; 56],
        vec![7; 1568],
        [6; 32],
        vec![vec![1; enclave_federation::relay::TICKET_KEY_LEN]],
        16,
        NOW - 3 * DAY,
        NOW - DAY,
        &mut rng,
    )
    .unwrap();
    let listed = enclave_federation::ListedRelay {
        identity: lapsed.identity.clone(),
        operator: lapsed.operator.clone(),
        family: lapsed.family.clone(),
        addr: lapsed.addr.clone(),
        link_key: lapsed.link_key,
    };

    let dir = std::env::temp_dir().join(format!("enclave-registrar-relay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let relay_file = dir.join("relay.bin");
    std::fs::write(&relay_file, lapsed.encode()).unwrap();
    let statik = enclave_registrar::Static {
        witness_threshold: 1,
        valid_days: 3,
        relay: vec![relay_file.display().to_string()],
        ..Default::default()
    };
    let mut served = HashMap::new();
    served.insert("old.test".to_string(), d.encode());

    let mut previous = list_of(4, entry);
    previous.witnesses.push(enclave_federation::ListedWitness {
        key: witness.key.clone(),
        operator: witness.operator.clone(),
        family: witness.family.clone(),
        url: witness.url.clone(),
    });
    let without_relay = previous.clone();
    previous.relays.push(listed.clone());

    let bytes =
        enclave_registrar::rebuild(&previous, &served, &[], &statik, NOW, &key, &mut rng).unwrap();
    let list = ServerList::verify(&bytes, &key.public(), NOW, 4).unwrap();
    assert_eq!(list.relays, vec![listed]);

    let refused =
        enclave_registrar::rebuild(&without_relay, &served, &[], &statik, NOW, &key, &mut rng);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(refused.is_err());
}
