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
/// changed identity is refused outright, an application joins, and the
/// result verifies under the foundation's public key with the next
/// sequence number.
#[test]
fn the_rebuild_keeps_who_stays_refuses_who_changed_and_takes_the_new() {
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

    // The old server replaced by a different identity: refused — a server
    // may change anything but who it is.
    let impostor = descriptor(
        "old.test",
        &CompositeSigningKey::generate(&mut rng).unwrap(),
        &mut rng,
    );
    let mut served = HashMap::new();
    served.insert("old.test".to_string(), impostor.encode());
    assert!(
        enclave_registrar::rebuild(&previous, &served, &[], &statik, NOW, &key, &mut rng,).is_err()
    );

    // A front that doesn't answer: the rebuild holds back rather than
    // dropping a server silently.
    assert!(
        enclave_registrar::rebuild(
            &previous,
            &HashMap::new(),
            &[],
            &statik,
            NOW,
            &key,
            &mut rng,
        )
        .is_err()
    );
}
