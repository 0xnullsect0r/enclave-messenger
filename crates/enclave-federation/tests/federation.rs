//! Key certificates, descriptors and the server list: each verifies only
//! under the right key, for the right id, inside its window; any changed
//! byte is refused.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::*;
use enclave_rpc::{ServerKey, ServerSecret};

const DAY: u32 = 20_700;
const NOW: u64 = DAY as u64 * 86_400 + 600;

fn key(day: u32) -> ServerKey {
    ServerSecret::from_seed(day, &[day as u8; 32])
        .public()
        .clone()
}

/// Flip one byte at each of a spread of offsets; every result must fail.
fn every_flip_fails(b: &[u8], check: impl Fn(&[u8]) -> bool) {
    let step = (b.len() / 97).max(1);
    for i in (0..b.len()).step_by(step) {
        let mut t = b.to_vec();
        t[i] ^= 0x40;
        assert!(
            !check(&t),
            "byte {i} of {} changed and still accepted",
            b.len()
        );
    }
}

#[test]
fn key_bundles_bind_keys_to_the_server_id() {
    let mut rng = HedgedRng::new().unwrap();
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let id = server_id(identity.public());
    let bundle = KeyBundle {
        identity: identity.public().clone(),
        certs: vec![
            KeyCert::sign(&identity, &key(DAY), &mut rng).unwrap(),
            KeyCert::sign(&identity, &key(DAY + 1), &mut rng).unwrap(),
        ],
    };
    let b = bundle.encode();
    let decoded = KeyBundle::decode(&b).unwrap();
    assert_eq!(decoded, bundle);
    assert_eq!(
        decoded.verify(&id, NOW).unwrap(),
        key(DAY),
        "today's key today"
    );
    assert_eq!(
        decoded.verify(&id, NOW + 86_400).unwrap(),
        key(DAY + 1),
        "tomorrow's key tomorrow"
    );
    assert_eq!(
        decoded.verify(&id, NOW + 3 * 86_400),
        Err(FedError::Expired)
    );
    assert_eq!(decoded.verify(&[0; 16], NOW), Err(FedError::WrongId));

    // Another server's identity can't certify keys for this id, even with
    // genuine signatures of its own.
    let other = CompositeSigningKey::generate(&mut rng).unwrap();
    let forged = KeyBundle {
        identity: other.public().clone(),
        certs: vec![KeyCert::sign(&other, &key(DAY), &mut rng).unwrap()],
    };
    assert_eq!(forged.verify(&id, NOW), Err(FedError::WrongId));
    // A certificate lifted into a bundle with a different identity fails.
    let mixed = KeyBundle {
        identity: identity.public().clone(),
        certs: vec![KeyCert::sign(&other, &key(DAY), &mut rng).unwrap()],
    };
    assert!(mixed.verify(&id, NOW).is_err());
    every_flip_fails(&b, |t| {
        KeyBundle::decode(t).is_ok_and(|k| k.verify(&id, NOW).is_ok_and(|k| k == key(DAY)))
    });
    assert!(KeyBundle::decode(&b[..b.len() - 1]).is_err());
    assert!(KeyBundle::decode(&[&b[..], &[0]].concat()).is_err());
}

#[test]
fn descriptors_witnesses_and_relays() {
    let mut rng = HedgedRng::new().unwrap();
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let head = CompositeSigningKey::generate(&mut rng).unwrap();
    let policy = Policy {
        effort_request: 64,
        effort_claim: 8,
        effort_blob: 1,
        effort_username: 64,
        effort_inbox: 16,
        inbox_quota: 5_000,
        request_quota: 100,
        token_quota: 4_096,
        ttl_days: 30,
    };
    let d = ServerDescriptor::sign(
        &identity,
        "a.example",
        "Ada's Servers",
        "ada",
        "",
        "",
        policy,
        Some(KtKeys {
            head_key: head.public().clone(),
            vrf_public: vec![7; 32],
        }),
        &[key(DAY), key(DAY + 1)],
        NOW - 60,
        NOW + 86_400,
        &mut rng,
    )
    .unwrap();
    let b = d.encode();
    let back = ServerDescriptor::decode(&b).unwrap();
    assert_eq!(back, d);
    back.verify(NOW).unwrap();
    assert_eq!(back.id(), server_id(identity.public()));
    assert_eq!(back.key_at(NOW), Some(&key(DAY)));
    assert_eq!(back.verify(NOW + 86_400), Err(FedError::Expired));
    every_flip_fails(&b, |t| {
        ServerDescriptor::decode(t).is_ok_and(|d| d.verify(NOW).is_ok())
    });
    // Too long a validity, no keys: refused at signing.
    assert!(
        ServerDescriptor::sign(
            &identity,
            "a.example",
            "",
            "",
            "",
            "",
            policy,
            None,
            &[key(DAY)],
            NOW,
            NOW + 4 * 86_400,
            &mut rng
        )
        .is_err()
    );

    let wk = CompositeSigningKey::generate(&mut rng).unwrap();
    let w = WitnessDescriptor::sign(
        &wk,
        "Wit",
        "wit",
        "https://w.example",
        NOW,
        NOW + 3600,
        &mut rng,
    )
    .unwrap();
    let wb = w.encode();
    let w2 = WitnessDescriptor::decode(&wb).unwrap();
    w2.verify(NOW).unwrap();
    assert_eq!(w2.id(), witness_id(wk.public()));
    every_flip_fails(&wb, |t| {
        WitnessDescriptor::decode(t).is_ok_and(|d| d.verify(NOW).is_ok())
    });

    let rk = CompositeSigningKey::generate(&mut rng).unwrap();
    let r = RelayDescriptor::sign(
        &rk,
        "Rel",
        "rel",
        "198.51.100.7:51820",
        [5; 56],
        vec![vec![1; enclave_federation::relay::TICKET_KEY_LEN]],
        NOW,
        NOW + 3600,
        &mut rng,
    )
    .unwrap();
    let rb = r.encode();
    let r2 = RelayDescriptor::decode(&rb).unwrap();
    r2.verify(NOW).unwrap();
    assert_eq!(r2.id(), relay_id(rk.public()));
    every_flip_fails(&rb, |t| {
        RelayDescriptor::decode(t).is_ok_and(|d| d.verify(NOW).is_ok())
    });
}

#[test]
fn server_lists_need_both_signatures_and_only_move_forward() {
    let mut rng = HedgedRng::new().unwrap();
    let foundation = FoundationKey::generate(&mut rng).unwrap();
    let public = foundation.public();
    let restored = FoundationKey::from_bytes(&foundation.to_bytes()).unwrap();
    assert_eq!(
        restored.public(),
        public,
        "the secret file restores the key"
    );
    assert_eq!(FoundationPublic::decode(&public.encode()).unwrap(), public);

    let a = CompositeSigningKey::generate(&mut rng).unwrap();
    let b = CompositeSigningKey::generate(&mut rng).unwrap();
    let list = ServerList {
        seq: 7,
        issued: NOW,
        expires: NOW + 30 * 86_400,
        witness_threshold: 2,
        servers: vec![
            ListedServer {
                identity: a.public().clone(),
                domain: "a.example".into(),
                operator: "A".into(),
                family: "a".into(),
                nym_address: "a-nym".into(),
                weight: 1,
                kt: None,
            },
            ListedServer {
                identity: b.public().clone(),
                domain: "b.example".into(),
                operator: "B".into(),
                family: "b".into(),
                nym_address: String::new(),
                weight: 3,
                kt: None,
            },
        ],
        witnesses: Vec::new(),
        relays: Vec::new(),
        push: vec![PushRelayEntry {
            nym_address: "nym-address".into(),
            keys: vec![vec![0; 4 + 56 + 1568]],
        }],
        credgates: vec![CredGateEntry {
            url: "https://a.example".into(),
            issuer_name: "a.example".into(),
            keys: vec![(700, [2; 49]), (701, [3; 49])],
        }],
    };
    // A gate must be HTTPS and list its epochs in order.
    for bad in [
        CredGateEntry {
            url: "http://a.example".into(),
            ..list.credgates[0].clone()
        },
        CredGateEntry {
            keys: vec![(701, [3; 49]), (700, [2; 49])],
            ..list.credgates[0].clone()
        },
        CredGateEntry {
            keys: Vec::new(),
            ..list.credgates[0].clone()
        },
    ] {
        let l = ServerList {
            credgates: vec![bad],
            ..list.clone()
        };
        assert_eq!(l.encode_unsigned(), Err(FedError::Malformed));
    }
    let signed = list.sign(&foundation, &mut rng).unwrap();
    let got = ServerList::verify(&signed, &public, NOW, 6).unwrap();
    assert_eq!(got, list);
    assert_eq!(
        ServerList::verify(&signed, &public, NOW, 7),
        Err(FedError::Stale)
    );
    assert_eq!(
        ServerList::verify(&signed, &public, NOW + 31 * 86_400, 0),
        Err(FedError::Expired)
    );
    assert_eq!(
        got.server(&server_id(b.public())).unwrap().domain,
        "b.example"
    );
    assert_eq!(got.by_domain("A.EXAMPLE").unwrap().operator, "A");
    assert_eq!(got.credgates[0].key(701), Some(&[3; 49]));
    assert_eq!(got.credgates[0].key(702), None);
    // Weighted pick: draws 0 → a, 1..3 → b.
    assert_eq!(got.pick(0).unwrap().domain, "a.example");
    assert_eq!(got.pick(1).unwrap().domain, "b.example");
    assert_eq!(got.pick(3).unwrap().domain, "b.example");

    // Each signature is required on its own: a list carrying one valid
    // signature and one from another foundation key is refused.
    let other = FoundationKey::generate(&mut rng).unwrap();
    let theirs = list.sign(&other, &mut rng).unwrap();
    let body_len =
        signed.len() - enclave_crypto::sig::ROOT_SIG_LEN - enclave_crypto::sig::COMPOSITE_SIG_LEN;
    let slh_end = body_len + enclave_crypto::sig::ROOT_SIG_LEN;
    let ours_slh_theirs_comp = [&signed[..slh_end], &theirs[slh_end..]].concat();
    let theirs_slh_ours_comp = [
        &signed[..body_len],
        &theirs[body_len..slh_end],
        &signed[slh_end..],
    ]
    .concat();
    for t in [&ours_slh_theirs_comp, &theirs_slh_ours_comp, &theirs] {
        assert_eq!(
            ServerList::verify(t, &public, NOW, 0),
            Err(FedError::Signature)
        );
    }
    // Changing the body breaks both.
    let mut t = signed.clone();
    t[3] ^= 1;
    assert!(ServerList::verify(&t, &public, NOW, 0).is_err());
}
