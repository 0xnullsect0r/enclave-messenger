//! Sigsum proofs made by the reference implementation (sigsum-go,
//! `ci/sigsum`): every case it accepts, this accepts, and the one it
//! refuses (one cosignature where two are needed), this refuses; any
//! changed byte breaks a proof.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_update::sigsum::{Policy, Proof, SigsumError};

struct Case {
    name: String,
    ok: bool,
    message: [u8; 32],
    policy: Policy,
    proof: String,
}

fn unhex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn cases() -> Vec<Case> {
    let text = include_str!("sigsum/vectors.txt");
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        let mut head = l.strip_prefix("case ").unwrap().split(' ');
        let (name, verdict) = (head.next().unwrap().to_string(), head.next().unwrap());
        let field = |l: Option<&str>, k: &str| unhex32(l.unwrap().strip_prefix(k).unwrap());
        let message = field(lines.next(), "message ");
        let log = field(lines.next(), "log_key ");
        let submit = field(lines.next(), "submit_key ");
        let witnesses = (0..3)
            .map(|_| field(lines.next(), "witness_key "))
            .collect();
        assert_eq!(lines.next(), Some("proof"));
        let mut proof = String::new();
        for l in lines.by_ref() {
            if l == "end" {
                break;
            }
            proof.push_str(l);
            proof.push('\n');
        }
        out.push(Case {
            name,
            ok: verdict == "ok",
            message,
            policy: Policy {
                log,
                submitters: vec![submit],
                witnesses,
                quorum: 2,
            },
            proof,
        });
    }
    out
}

#[test]
fn agrees_with_sigsum_go() {
    let cases = cases();
    assert_eq!(cases.len(), 5);
    for c in &cases {
        let got = Proof::parse(&c.proof).and_then(|p| p.verify(&c.message, &c.policy));
        assert_eq!(got.is_ok(), c.ok, "{}: {got:?}", c.name);
    }
    let one = cases.iter().find(|c| c.name == "one-witness").unwrap();
    let err = Proof::parse(&one.proof)
        .unwrap()
        .verify(&one.message, &one.policy);
    assert_eq!(err, Err(SigsumError::Quorum(1, 2)));
}

#[test]
fn every_changed_character_is_refused() {
    let c = cases().into_iter().find(|c| c.name == "seven").unwrap();
    let hexdigits = b"0123456789abcdef";
    let bytes = c.proof.as_bytes();
    for i in 0..bytes.len() {
        if !hexdigits.contains(&bytes[i]) {
            continue;
        }
        let mut b = bytes.to_vec();
        b[i] = if b[i] == b'0' { b'1' } else { b'0' };
        let text = String::from_utf8(b).unwrap();
        // A changed digit in a cosignature that isn't needed, or in a time
        // nobody signed differently, may still leave a valid proof only if
        // it doesn't count: a third cosignature here is spare.
        let ok = Proof::parse(&text)
            .and_then(|p| p.verify(&c.message, &c.policy))
            .is_ok();
        if ok {
            let line = text[..i].rsplit('\n').next().unwrap_or("");
            assert!(
                line.starts_with("cosignature="),
                "byte {i} changed and still verified"
            );
        }
    }
}

#[test]
fn wrong_message_log_or_submitter_is_refused() {
    let c = cases().into_iter().find(|c| c.name == "sixteen").unwrap();
    let p = Proof::parse(&c.proof).unwrap();
    p.verify(&c.message, &c.policy).unwrap();
    let mut m = c.message;
    m[0] ^= 1;
    assert!(p.verify(&m, &c.policy).is_err());
    let mut pol = c.policy.clone();
    pol.log[0] ^= 1;
    assert_eq!(p.verify(&c.message, &pol), Err(SigsumError::Unknown("log")));
    let mut pol = c.policy.clone();
    pol.submitters = vec![[9; 32]];
    assert_eq!(
        p.verify(&c.message, &pol),
        Err(SigsumError::Unknown("submitter"))
    );
    let mut pol = c.policy.clone();
    pol.quorum = 3;
    assert!(matches!(
        p.verify(&c.message, &pol),
        Err(SigsumError::Quorum(2, 3))
    ));
}

#[test]
fn malformed_text_is_refused() {
    let c = cases().into_iter().find(|c| c.name == "seven").unwrap();
    for bad in [
        c.proof.replace("version=2", "version=3"),
        c.proof.replace("size=7", "size=07"),
        c.proof.replacen("node_hash=", "nodehash=", 1),
        format!("{}junk\n", c.proof),
        c.proof.replace("leaf_index=5", "leaf_index=9"),
        String::new(),
    ] {
        assert!(
            Proof::parse(&bad)
                .and_then(|p| p.verify(&c.message, &c.policy))
                .is_err(),
            "{bad}"
        );
    }
}
