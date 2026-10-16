//! Red-team matrix rows for key transparency (`docs/redteam-matrix.md`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_kt::{Cosignature, KtError, KtLog, SignedHead, Witness, WitnessPolicy, verify_lookup};

const NOW: u64 = 1_790_000_000;

/// RT-04: a tree head counts only with a quorum of valid cosignatures from
/// pinned witnesses run by someone other than the log's operator (three in
/// production). Fewer, the same witness twice, an unpinned witness, a
/// witness of the log's own operator, a forged signature, or a
/// cosignature over another head all leave it below the quorum, and a
/// lookup against such a head is refused.
#[tokio::test(flavor = "multi_thread")]
async fn rt04_head_rejected_below_witness_quorum() {
    let mut rng = HedgedRng::new().unwrap();
    let mut log = KtLog::new(
        [1; 16],
        CompositeSigningKey::generate(&mut rng).unwrap(),
        [9; 32],
    )
    .await
    .unwrap();
    let witness = |id: u8, operator: &str, rng: &mut HedgedRng| {
        Witness::new(
            [id; 16],
            operator,
            CompositeSigningKey::generate(rng).unwrap(),
        )
    };
    let mut ws = [
        witness(10, "operator-a", &mut rng),
        witness(11, "operator-b", &mut rng),
        witness(12, "operator-c", &mut rng),
        witness(13, "log-operator", &mut rng),
    ];
    let stranger = witness(14, "operator-d", &mut rng);
    let policy = WitnessPolicy {
        witnesses: ws
            .iter()
            .map(|w| (w.id, w.public_key().clone(), w.operator.clone()))
            .collect(),
        threshold: 3,
    };
    log.publish("alice", b"alice-root".to_vec(), NOW, &mut rng)
        .await
        .unwrap();
    let head = log.latest().unwrap().clone();
    let mut cos = Vec::new();
    for w in ws.iter_mut() {
        cos.push(
            w.cosign(
                log.public_key(),
                std::slice::from_ref(&head),
                None,
                NOW + 5,
                &mut rng,
            )
            .await
            .unwrap(),
        );
    }
    let with = |c: &[Cosignature]| SignedHead {
        cosignatures: c.to_vec(),
        ..head.clone()
    };
    let check = |sh: &SignedHead| policy.check(sh, log.public_key(), "log-operator", NOW + 10);

    // Three independent witnesses: the head is good.
    assert_eq!(check(&with(&cos[..3])), Ok(NOW + 5));

    // Below the quorum.
    let mut forged = cos[2].clone();
    let last = forged.signature.len() - 1;
    forged.signature[last] ^= 1;
    let mut other_head = cos[2].clone();
    other_head.time += 1; // signed over another (head, time)
    let unpinned = {
        let mut s = stranger;
        s.cosign(
            log.public_key(),
            std::slice::from_ref(&head),
            None,
            NOW + 5,
            &mut rng,
        )
        .await
        .unwrap()
    };
    let cases: [(&str, Vec<Cosignature>); 7] = [
        ("none", vec![]),
        ("two", cos[..2].to_vec()),
        (
            "one witness twice",
            vec![cos[0].clone(), cos[1].clone(), cos[1].clone()],
        ),
        (
            "the log's own operator",
            vec![cos[0].clone(), cos[1].clone(), cos[3].clone()],
        ),
        (
            "an unpinned witness",
            vec![cos[0].clone(), cos[1].clone(), unpinned],
        ),
        (
            "a forged signature",
            vec![cos[0].clone(), cos[1].clone(), forged],
        ),
        (
            "another head",
            vec![cos[0].clone(), cos[1].clone(), other_head],
        ),
    ];
    for (what, c) in &cases {
        assert_eq!(check(&with(c)), Err(KtError::Quorum), "{what}");
    }

    // A lookup proof against a head below the quorum is refused.
    let (proof, served) = log.lookup("alice").await.unwrap();
    let thin = SignedHead {
        cosignatures: cos[..2].to_vec(),
        ..served
    };
    assert_eq!(
        verify_lookup(
            &policy,
            log.public_key(),
            "log-operator",
            log.vrf_public(),
            &thin,
            "alice",
            proof,
            NOW + 10,
        )
        .unwrap_err(),
        KtError::Quorum
    );
}
