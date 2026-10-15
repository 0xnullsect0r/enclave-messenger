//! The release metadata chain (`docs/19-ops.md` §1.5), and RT-13: an
//! update needs 2 of the 3 maintainers and a Sigsum inclusion proof.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_update::sigsum::Policy;
use enclave_update::*;
use std::sync::OnceLock;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

/// Three maintainers and an online key (index 3) for snapshot and
/// timestamp; made once, as SLH-DSA key generation is slow.
fn keys() -> &'static [MaintainerKey] {
    static K: OnceLock<Vec<MaintainerKey>> = OnceLock::new();
    K.get_or_init(|| {
        let mut rng = HedgedRng::new().unwrap();
        (0..5)
            .map(|_| MaintainerKey::generate(&mut rng).unwrap())
            .collect()
    })
}

fn root(version: u32, roles: [RoleKeys; 4], keys: &[MaintainerKey], sigsum: Policy) -> Root {
    Root {
        version,
        expires: NOW + 365 * DAY,
        keys: keys.iter().map(MaintainerKey::public).collect(),
        roles,
        sigsum,
    }
}

fn roles() -> [RoleKeys; 4] {
    [
        RoleKeys {
            keys: vec![0, 1, 2],
            threshold: 2,
        },
        RoleKeys {
            keys: vec![0, 1, 2],
            threshold: 2,
        },
        RoleKeys {
            keys: vec![3],
            threshold: 1,
        },
        RoleKeys {
            keys: vec![3],
            threshold: 1,
        },
    ]
}

fn policy() -> Policy {
    Policy {
        log: [1; 32],
        submitters: vec![[2; 32]],
        witnesses: vec![[5; 32], [6; 32]],
        quorum: 2,
    }
}

fn signed_root(r: &Root, by: &[u8]) -> Vec<u8> {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = Signed::root(r);
    for &i in by {
        s.sign(i, &keys()[usize::from(i)], &mut rng).unwrap();
    }
    s.encode()
}

/// timestamp, snapshot, targets for `files`, targets signed by `by`.
fn chain(
    version: u32,
    files: &[(&str, &[u8])],
    by: &[u8],
    expires: u64,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use sha2::Digest as _;
    let mut rng = HedgedRng::new().unwrap();
    let t = Targets {
        version,
        expires,
        release: "v1.0.0".into(),
        targets: files.iter().map(|(n, f)| Target::of(n, f)).collect(),
    };
    let mut ts = Signed::targets(&t);
    for &i in by {
        ts.sign(i, &keys()[usize::from(i)], &mut rng).unwrap();
    }
    let targets = ts.encode();
    let s = Snapshot {
        version,
        expires,
        targets_version: version,
        targets_hash: sha2::Sha256::digest(&targets).into(),
    };
    let mut ss = Signed::snapshot(&s);
    ss.sign(3, &keys()[3], &mut rng).unwrap();
    let snapshot = ss.encode();
    let tm = Timestamp {
        version,
        expires: expires.min(NOW + 7 * DAY),
        snapshot_version: version,
        snapshot_hash: sha2::Sha256::digest(&snapshot).into(),
    };
    let mut tms = Signed::timestamp(&tm);
    tms.sign(3, &keys()[3], &mut rng).unwrap();
    (tms.encode(), snapshot, targets)
}

#[test]
fn a_release_with_two_maintainers_is_accepted() {
    let r = signed_root(&root(1, roles(), &keys()[..4], policy()), &[0, 1]);
    let mut c = Client::new(&r, [0; 3]).unwrap();
    let (t, s, g) = chain(
        1,
        &[("Enclave-1.0.0.dmg", b"the app")],
        &[0, 2],
        NOW + 30 * DAY,
    );
    let rel = c.refresh(&t, &s, &g, NOW).unwrap();
    assert_eq!(rel.release, "v1.0.0");
    assert_eq!(c.seen(), [1, 1, 1]);
}

#[test]
fn rt13_update_rejected_without_2_of_3() {
    let r = signed_root(&root(1, roles(), &keys()[..4], policy()), &[0, 1]);
    // One maintainer.
    let mut c = Client::new(&r, [0; 3]).unwrap();
    let (t, s, g) = chain(1, &[("f", b"x")], &[1], NOW + DAY);
    assert_eq!(
        c.refresh(&t, &s, &g, NOW),
        Err(UpdateError::Threshold(Role::Targets, 1, 2))
    );
    // The same maintainer twice.
    let (t, s, g) = chain(1, &[("f", b"x")], &[1, 1], NOW + DAY);
    assert!(matches!(
        c.refresh(&t, &s, &g, NOW),
        Err(UpdateError::Threshold(..))
    ));
    // The online key isn't a maintainer for targets.
    let (t, s, g) = chain(1, &[("f", b"x")], &[1, 3], NOW + DAY);
    assert!(matches!(
        c.refresh(&t, &s, &g, NOW),
        Err(UpdateError::Threshold(..))
    ));
    // A key that isn't in the root.
    let (t, s, g) = chain(1, &[("f", b"x")], &[1, 4], NOW + DAY);
    assert!(matches!(
        c.refresh(&t, &s, &g, NOW),
        Err(UpdateError::Threshold(..))
    ));
    // A root may not lower the threshold below 2.
    let mut weak = roles();
    weak[1].threshold = 1;
    let r1 = signed_root(&root(1, weak, &keys()[..4], policy()), &[0, 1]);
    assert_eq!(Client::new(&r1, [0; 3]).err(), Some(UpdateError::Malformed));
    // Nor list one maintainer twice so one signs as two.
    let mut ks: Vec<&MaintainerKey> = keys()[..4].iter().collect();
    ks[2] = &keys()[1];
    let dup = Root {
        version: 1,
        expires: NOW + DAY,
        keys: ks.iter().map(|k| k.public()).collect(),
        roles: roles(),
        sigsum: policy(),
    };
    let mut rng = HedgedRng::new().unwrap();
    let mut s = Signed::root(&dup);
    s.sign(0, &keys()[0], &mut rng).unwrap();
    s.sign(1, &keys()[1], &mut rng).unwrap();
    let c2 = Client::new(&s.encode(), [0; 3]);
    assert!(c2.is_ok(), "two distinct maintainers signed this root");
    let mut c2 = c2.unwrap();
    let (t, s, g) = chain(1, &[("f", b"x")], &[1, 2], NOW + DAY);
    // Indices 1 and 2 are the same maintainer.
    let _ = (t, s, g);
    let mut rng = HedgedRng::new().unwrap();
    let tgt = Targets {
        version: 1,
        expires: NOW + DAY,
        release: "v1".into(),
        targets: vec![Target::of("f", b"x")],
    };
    let mut tsg = Signed::targets(&tgt);
    tsg.sign(1, &keys()[1], &mut rng).unwrap();
    tsg.sign(2, &keys()[1], &mut rng).unwrap();
    let targets = tsg.encode();
    use sha2::Digest as _;
    let snap = Snapshot {
        version: 1,
        expires: NOW + DAY,
        targets_version: 1,
        targets_hash: sha2::Sha256::digest(&targets).into(),
    };
    let mut ss = Signed::snapshot(&snap);
    ss.sign(3, &keys()[3], &mut rng).unwrap();
    let snapshot = ss.encode();
    let tm = Timestamp {
        version: 1,
        expires: NOW + DAY,
        snapshot_version: 1,
        snapshot_hash: sha2::Sha256::digest(&snapshot).into(),
    };
    let mut tms = Signed::timestamp(&tm);
    tms.sign(3, &keys()[3], &mut rng).unwrap();
    assert_eq!(
        c2.refresh(&tms.encode(), &snapshot, &targets, NOW),
        Err(UpdateError::Threshold(Role::Targets, 1, 2))
    );
}

#[test]
fn rollback_freeze_and_mismatch_are_refused() {
    let r = signed_root(&root(1, roles(), &keys()[..4], policy()), &[0, 1]);
    let mut c = Client::new(&r, [0; 3]).unwrap();
    let (t2, s2, g2) = chain(2, &[("f", b"x")], &[0, 1], NOW + 30 * DAY);
    c.refresh(&t2, &s2, &g2, NOW).unwrap();
    // An older release.
    let (t1, s1, g1) = chain(1, &[("f", b"old")], &[0, 1], NOW + 30 * DAY);
    assert!(matches!(
        c.refresh(&t1, &s1, &g1, NOW),
        Err(UpdateError::Rollback(..))
    ));
    // A timestamp that ran out: the client is being kept from news.
    assert_eq!(
        c.refresh(&t2, &s2, &g2, NOW + 8 * DAY),
        Err(UpdateError::Expired(Role::Timestamp))
    );
    // A snapshot or targets that don't match the hashes above them.
    let (t3, s3, _g3) = chain(3, &[("f", b"y")], &[0, 1], NOW + 30 * DAY);
    assert_eq!(
        c.refresh(&t3, &s2, &g2, NOW),
        Err(UpdateError::Mismatch(Role::Snapshot))
    );
    assert_eq!(
        c.refresh(&t3, &s3, &g2, NOW),
        Err(UpdateError::Mismatch(Role::Targets))
    );
}

#[test]
fn roots_rotate_one_version_at_a_time_signed_by_old_and_new() {
    let r1 = root(1, roles(), &keys()[..4], policy());
    let mut c = Client::new(&signed_root(&r1, &[0, 1]), [0; 3]).unwrap();
    // Version 2 replaces maintainer 2 with key 4.
    let mut ks: Vec<&MaintainerKey> = keys()[..4].iter().collect();
    ks[2] = &keys()[4];
    let r2 = Root {
        version: 2,
        expires: NOW + 365 * DAY,
        keys: ks.iter().map(|k| k.public()).collect(),
        roles: roles(),
        sigsum: policy(),
    };
    let mut rng = HedgedRng::new().unwrap();
    // Signed only by the new root's keys 2 (key 4) and 0: the old root
    // has just one of those (0), so it isn't enough.
    let mut s = Signed::root(&r2);
    s.sign(0, &keys()[0], &mut rng).unwrap();
    s.sign(2, &keys()[4], &mut rng).unwrap();
    assert!(matches!(
        c.update_root(&s.encode()),
        Err(UpdateError::Threshold(Role::Root, 1, 2))
    ));
    // Adding maintainer 1 satisfies both.
    s.sign(1, &keys()[1], &mut rng).unwrap();
    c.update_root(&s.encode()).unwrap();
    assert_eq!(c.root().version, 2);
    // Skipping or going back is refused.
    let mut r4 = r2.clone();
    r4.version = 4;
    assert_eq!(
        c.update_root(&signed_root(&r4, &[0, 1])),
        Err(UpdateError::RootSkip)
    );
    assert!(matches!(
        c.update_root(&signed_root(&r1, &[0, 1])),
        Err(UpdateError::Rollback(..))
    ));
}

/// A one-leaf Sigsum log holding `file`'s SHA-256, in sigsum-go's format
/// (checked against it in `tests/sigsum.rs`), with the vectors' keys:
/// log seed 1, submitter 2, witnesses 5 and 6.
fn sigsum_proof(file: &[u8], witnesses: &[u8]) -> (String, Policy) {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};
    let h = |parts: &[&[u8]]| -> [u8; 32] {
        let mut d = Sha256::new();
        for p in parts {
            d.update(p);
        }
        d.finalize().into()
    };
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let key = |s: u8| SigningKey::from_bytes(&[s; 32]);
    let (log, sub) = (key(1), key(2));
    let msg = h(&[file]);
    let checksum = h(&[&msg]);
    let leaf_sig = sub.sign(&[b"sigsum.org/v1/tree-leaf".as_slice(), &[0], &checksum].concat());
    let sub_hash = h(&[sub.verifying_key().as_bytes()]);
    let root = h(&[&[0], &checksum, &leaf_sig.to_bytes(), &sub_hash]);
    let log_hash = h(&[log.verifying_key().as_bytes()]);
    use base64::Engine as _;
    let cp = format!(
        "sigsum.org/v1/tree/{}\n1\n{}\n",
        hex(&log_hash),
        base64::engine::general_purpose::STANDARD.encode(root)
    );
    let mut text = format!(
        "version=2\nlog={}\nleaf={} {}\n\nsize=1\nroot_hash={}\nsignature={}\n",
        hex(&log_hash),
        hex(&sub_hash),
        hex(&leaf_sig.to_bytes()),
        hex(&root),
        hex(&log.sign(cp.as_bytes()).to_bytes())
    );
    for &w in witnesses {
        let k = key(w);
        let sig = k.sign(format!("cosignature/v1\ntime 1800000000\n{cp}").as_bytes());
        text.push_str(&format!(
            "cosignature={} 1800000000 {}\n",
            hex(&h(&[k.verifying_key().as_bytes()])),
            hex(&sig.to_bytes())
        ));
    }
    let policy = Policy {
        log: log.verifying_key().to_bytes(),
        submitters: vec![sub.verifying_key().to_bytes()],
        witnesses: [5u8, 6, 7]
            .iter()
            .map(|&s| key(s).verifying_key().to_bytes())
            .collect(),
        quorum: 2,
    };
    (text, policy)
}

#[test]
fn rt13_update_rejected_without_sigsum_inclusion() {
    let file: &[u8] = b"Enclave 1.0.0 for macOS";
    let (proof, sigsum) = sigsum_proof(file, &[5, 6]);
    let r = signed_root(&root(1, roles(), &keys()[..4], sigsum.clone()), &[0, 1]);
    let mut c = Client::new(&r, [0; 3]).unwrap();
    let (t, s, g) = chain(1, &[("Enclave-1.0.0.dmg", file)], &[0, 1], NOW + 30 * DAY);
    let rel = c.refresh(&t, &s, &g, NOW).unwrap();
    // Logged, with two witnesses: installed.
    c.check(&rel, "Enclave-1.0.0.dmg", file, &proof).unwrap();
    // No proof.
    assert!(matches!(
        c.check(&rel, "Enclave-1.0.0.dmg", file, ""),
        Err(UpdateError::Sigsum(_))
    ));
    // One witness of the two needed.
    let (thin, _) = sigsum_proof(file, &[5]);
    assert!(matches!(
        c.check(&rel, "Enclave-1.0.0.dmg", file, &thin),
        Err(UpdateError::Sigsum(
            enclave_update::sigsum::SigsumError::Quorum(1, 2)
        ))
    ));
    // A proof for another file (signed and listed, but not this one).
    let other: &[u8] = b"Enclave 1.0.0 for Windows";
    let (wrong, _) = sigsum_proof(other, &[5, 6]);
    assert!(matches!(
        c.check(&rel, "Enclave-1.0.0.dmg", file, &wrong),
        Err(UpdateError::Sigsum(_))
    ));
    // A changed file never reaches the proof; nor an unlisted name.
    assert_eq!(
        c.check(
            &rel,
            "Enclave-1.0.0.dmg",
            b"Enclave 1.0.0 for macOS!",
            &proof
        ),
        Err(UpdateError::Target)
    );
    assert_eq!(
        c.check(&rel, "Other.dmg", file, &proof),
        Err(UpdateError::Target)
    );
}
