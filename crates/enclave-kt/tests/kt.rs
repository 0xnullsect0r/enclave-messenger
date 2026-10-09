//! Key-transparency tests: lookups, witness quorum, split-view detection.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_kt::{KtError, KtLog, Witness, WitnessPolicy, verify_lookup};

const NOW: u64 = 1_790_000_000;

async fn cosign_all(
    log: &mut KtLog,
    witnesses: &mut [Witness],
    from_epoch: u64,
    rng: &mut HedgedRng,
) {
    let latest = log.latest().unwrap().head.epoch;
    let heads = log.heads_after(from_epoch, latest);
    let proof = if from_epoch == 0 {
        None
    } else {
        Some(log.audit(from_epoch, latest).await.unwrap())
    };
    for w in witnesses.iter_mut() {
        let c = w
            .cosign(log.public_key(), &heads, proof.clone(), NOW + 5, rng)
            .await
            .unwrap();
        log.add_cosignature(latest, c).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_with_witness_quorum_and_split_view() {
    let mut rng = HedgedRng::new().unwrap();
    let server_key = CompositeSigningKey::generate(&mut rng).unwrap();
    let server_seed = *server_key.seed();
    let mut log = KtLog::new([1; 16], server_key, [9; 32]).await.unwrap();

    let mut witnesses = vec![
        Witness::new(
            [10; 16],
            "operator-a",
            CompositeSigningKey::generate(&mut rng).unwrap(),
        ),
        Witness::new(
            [11; 16],
            "operator-b",
            CompositeSigningKey::generate(&mut rng).unwrap(),
        ),
        Witness::new(
            [12; 16],
            "server-operator",
            CompositeSigningKey::generate(&mut rng).unwrap(),
        ),
    ];
    let policy = WitnessPolicy {
        witnesses: witnesses
            .iter()
            .map(|w| (w.id, w.public_key().clone(), w.operator.clone()))
            .collect(),
        threshold: 2,
    };

    log.publish("alice", b"alice-root-hash".to_vec(), NOW, &mut rng)
        .await
        .unwrap();
    cosign_all(&mut log, &mut witnesses, 0, &mut rng).await;
    log.publish("bob", b"bob-root-hash".to_vec(), NOW + 1, &mut rng)
        .await
        .unwrap();
    cosign_all(&mut log, &mut witnesses, 1, &mut rng).await;

    let (proof, head) = log.lookup("Alice").await.unwrap();
    let (value, version, trusted) = verify_lookup(
        &policy,
        log.public_key(),
        "server-operator",
        log.vrf_public(),
        &head,
        "alice",
        proof,
        NOW + 10,
    )
    .unwrap();
    assert_eq!(value, b"alice-root-hash");
    assert_eq!(version, 1);
    assert_eq!(trusted, NOW + 5);

    // Cosignatures from the server's own operator do not count.
    let strict = WitnessPolicy {
        witnesses: policy.witnesses.clone(),
        threshold: 3,
    };
    let (proof, head) = log.lookup("alice").await.unwrap();
    let e = verify_lookup(
        &strict,
        log.public_key(),
        "server-operator",
        log.vrf_public(),
        &head,
        "alice",
        proof,
        NOW + 10,
    );
    assert_eq!(e.unwrap_err(), KtError::Quorum);

    // A lookup proof for one name does not verify for another.
    let (proof, head) = log.lookup("alice").await.unwrap();
    assert!(
        verify_lookup(
            &policy,
            log.public_key(),
            "server-operator",
            log.vrf_public(),
            &head,
            "bob",
            proof,
            NOW + 10
        )
        .is_err()
    );

    // Split view: the server forks history (same key, different alice value).
    let forked_key = CompositeSigningKey::from_seed(&server_seed).unwrap();
    let mut fork = KtLog::new([1; 16], forked_key, [9; 32]).await.unwrap();
    fork.publish("alice", b"attacker-root".to_vec(), NOW, &mut rng)
        .await
        .unwrap();
    fork.publish("bob", b"bob-root-hash".to_vec(), NOW + 1, &mut rng)
        .await
        .unwrap();
    fork.publish("carol", b"carol".to_vec(), NOW + 2, &mut rng)
        .await
        .unwrap();
    // Witnesses already cosigned epoch 2 of the real log; the fork's epoch 3
    // does not extend it, so they refuse.
    let heads = fork.heads_after(2, 3);
    let proof = fork.audit(2, 3).await.unwrap();
    for w in witnesses.iter_mut() {
        let r = w
            .cosign(
                fork.public_key(),
                &heads,
                Some(proof.clone()),
                NOW + 20,
                &mut rng,
            )
            .await;
        assert_eq!(r.unwrap_err(), KtError::NotAppendOnly);
    }
    // Gossip also catches it: the two heads for epoch 2 differ.
    let real2 = log.heads_after(1, 2)[0].head;
    let fork2 = fork.heads_after(1, 2)[0].head;
    assert_ne!(real2.gossip_digest(), fork2.gossip_digest());
}

#[tokio::test(flavor = "multi_thread")]
async fn confusable_names_are_refused() {
    let mut rng = HedgedRng::new().unwrap();
    let mut log = KtLog::new(
        [2; 16],
        CompositeSigningKey::generate(&mut rng).unwrap(),
        [3; 32],
    )
    .await
    .unwrap();
    log.publish("paul", b"p".to_vec(), NOW, &mut rng)
        .await
        .unwrap();
    assert_eq!(
        log.publish("pau1", b"x".to_vec(), NOW, &mut rng)
            .await
            .unwrap_err(),
        KtError::Username
    );
    // The owner can update their own name.
    log.publish("paul", b"p2".to_vec(), NOW + 1, &mut rng)
        .await
        .unwrap();
    assert_eq!(
        log.publish("adm1n", b"x".to_vec(), NOW, &mut rng)
            .await
            .unwrap_err(),
        KtError::Username
    );
}

/// The service: publish, cosign, a lookup reply that survives encoding, the
/// heartbeat for a stale head, and wire round trips.
#[test]
fn service_round_trip_from_sync_code() {
    use enclave_kt::{KtInfo, KtService, LookupReply, SignedHead, UsernameClaim};
    let mut rng = HedgedRng::new().unwrap();
    let witnesses: Vec<Witness> = (0..3u8)
        .map(|i| {
            Witness::new(
                [20 + i; 16],
                &format!("witness-op-{i}"),
                CompositeSigningKey::generate(&mut rng).unwrap(),
            )
        })
        .collect();
    let policy = WitnessPolicy {
        witnesses: witnesses
            .iter()
            .map(|w| (w.id, w.public_key().clone(), w.operator.clone()))
            .collect(),
        threshold: 3,
    };
    let svc = KtService::start(
        [3; 16],
        "enclave.test",
        "server-op",
        CompositeSigningKey::generate(&mut rng).unwrap(),
        [4; 32],
        witnesses,
    )
    .unwrap();
    let info = KtInfo::decode(&svc.info().encode()).unwrap();
    assert_eq!(&info, svc.info());

    assert_eq!(svc.publish("sam", vec![1; 80], NOW).unwrap(), 1);
    assert_eq!(svc.publish("alex", vec![2; 80], NOW).unwrap(), 2);
    assert_eq!(svc.publish("sam", vec![3; 80], NOW).unwrap(), 3);
    assert_eq!(svc.publish("5am", vec![9; 80], NOW), Err(KtError::Username));

    let check = |bytes: Vec<u8>, name: &str, now: u64| {
        let r = LookupReply::decode(&bytes).unwrap();
        let sh = SignedHead::decode(&r.head.encode()).unwrap();
        assert_eq!(sh, r.head);
        verify_lookup(
            &policy,
            &info.head_key,
            &info.operator,
            &info.vrf_public,
            &r.head,
            name,
            r.proof,
            now,
        )
    };
    let (value, version, _) = check(svc.lookup("sam", NOW + 10).unwrap(), "sam", NOW + 10).unwrap();
    assert_eq!((value, version), (vec![3; 80], 2));
    // A proof for one name does not verify for another.
    assert_eq!(
        check(svc.lookup("sam", NOW + 10).unwrap(), "alex", NOW + 10).unwrap_err(),
        KtError::Lookup
    );
    assert!(svc.lookup("nobody", NOW + 10).is_err());

    // "Nobody has it", proved: the label the name's first version would
    // have isn't in the tree. The proof is for that name only, and a
    // registered name gets its entry, never an absence proof.
    let absent = |bytes: Vec<u8>, name: &str| match enclave_kt::NameAnswer::decode(&bytes).unwrap()
    {
        enclave_kt::NameAnswer::Absent { head, proof } => enclave_kt::verify_absence(
            &policy,
            &info.head_key,
            &info.operator,
            &info.vrf_public,
            &head,
            name,
            &proof,
            NOW + 10,
        ),
        enclave_kt::NameAnswer::Found(_) => Err(KtError::Malformed),
    };
    let nobody = svc.lookup_name("nobody", NOW + 10).unwrap();
    absent(nobody.clone(), "nobody").unwrap();
    assert_eq!(
        absent(nobody.clone(), "sam"),
        Err(KtError::Lookup),
        "not sam's"
    );
    assert_eq!(absent(nobody, "nobody2"), Err(KtError::Lookup));
    match enclave_kt::NameAnswer::decode(&svc.lookup_name("sam", NOW + 10).unwrap()).unwrap() {
        enclave_kt::NameAnswer::Found(r) => {
            let (value, _, _) = verify_lookup(
                &policy,
                &info.head_key,
                &info.operator,
                &info.vrf_public,
                &r.head,
                "sam",
                r.proof,
                NOW + 10,
            )
            .unwrap();
            assert_eq!(value, vec![3; 80]);
        }
        other => panic!("{other:?}"),
    }
    // A damaged VRF proof, or one under another log's VRF key, fails.
    let mut bytes = svc.lookup_name("nobody", NOW + 10).unwrap();
    if let enclave_kt::NameAnswer::Absent { head, mut proof } =
        enclave_kt::NameAnswer::decode(&bytes).unwrap()
    {
        proof.vrf_proof[40] ^= 1;
        bytes = enclave_kt::NameAnswer::Absent { head, proof }
            .encode()
            .unwrap();
    }
    assert_eq!(absent(bytes, "nobody"), Err(KtError::Lookup));
    // Two days later the service starts a heartbeat epoch, cosigned afresh.
    let later = NOW + 2 * 86_400;
    let (value, _, trusted) = check(svc.lookup("alex", later).unwrap(), "alex", later).unwrap();
    assert_eq!((value, trusted), (vec![2; 80], later));

    let claim = UsernameClaim {
        name: "sam".into(),
        value: vec![7; 100],
        device: [8; 16],
        time: NOW,
        signature: vec![9; 50],
    };
    assert_eq!(UsernameClaim::decode(&claim.encode()).unwrap(), claim);
    assert_eq!(claim.root(), Some([7; 64]));
}

/// A descriptor digest committed to the log is provable against the head,
/// and no username lookup can reach its label.
#[tokio::test(flavor = "multi_thread")]
async fn descriptor_digests_are_committed() {
    let mut rng = HedgedRng::new().unwrap();
    let key = CompositeSigningKey::generate(&mut rng).unwrap();
    let mut log = KtLog::new([1; 16], key, [9; 32]).await.unwrap();
    let digest = [0x42u8; 64];
    let sh = log.commit_descriptor(digest, NOW, &mut rng).await.unwrap();
    assert_eq!(sh.head.epoch, 1);
    let (proof, head) = log.lookup_descriptor().await.unwrap();
    let r = akd::verify::lookup_verify::<enclave_kt::EnclaveKtConfig>(
        log.vrf_public(),
        head.head.root,
        head.head.epoch,
        akd::AkdLabel(enclave_kt::log::DESCRIPTOR_LABEL.to_vec()),
        proof,
    )
    .unwrap();
    assert_eq!(r.value.0, digest);
    // The label isn't a name.
    assert!(log.lookup("\0descriptor").await.is_err());
}

/// Account records (`03-identity.md` §8.1) are committed under labels no
/// username can equal, verify with `verify_label_lookup`'s proof check, and
/// a later commit replaces the value. Name labels can't be committed raw.
#[tokio::test(flavor = "multi_thread")]
async fn account_records_are_committed() {
    let mut rng = HedgedRng::new().unwrap();
    let key = CompositeSigningKey::generate(&mut rng).unwrap();
    let mut log = KtLog::new([1; 16], key, [9; 32]).await.unwrap();
    let label = enclave_kt::account_label(&[7; 31]);
    assert_eq!(label[0], enclave_kt::ACCOUNT_TAG);
    let first = enclave_kt::account_record(b"manifest v1", b"");
    let second = enclave_kt::account_record(b"manifest v2", b"cosign");
    assert_ne!(first, second);
    log.commit_labels(vec![(label.clone(), first.to_vec())], NOW, &mut rng)
        .await
        .unwrap();
    log.commit_labels(vec![(label.clone(), second.to_vec())], NOW, &mut rng)
        .await
        .unwrap();
    let (proof, head) = log.lookup_raw(&label).await.unwrap();
    let r = akd::verify::lookup_verify::<enclave_kt::EnclaveKtConfig>(
        log.vrf_public(),
        head.head.root,
        head.head.epoch,
        akd::AkdLabel(label.clone()),
        proof,
    )
    .unwrap();
    assert_eq!(r.value.0, second);
    // Not a name, and a name can't be committed this way.
    assert!(log.lookup("\u{1}").await.is_err());
    assert!(
        log.commit_labels(vec![(b"alice".to_vec(), vec![1])], NOW, &mut rng)
            .await
            .is_err()
    );
}
