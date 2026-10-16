//! Red-team checks on sealed requests (`docs/redteam-matrix.md` RT-03,
//! RT-27; `docs/09-transport.md` §2).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::kem::{MlKemSecret, X448Secret};
use enclave_crypto::rng::HedgedRng;
use enclave_rpc::{RpcError, ServerKey, ServerSecret, open_request, seal_poll, seal_request};
use enclave_wire::{ENVELOPE_LEN, Op, POLL_LEN, RequestHeader, UNIT_LEN};

const DAY: u32 = 20_700;

fn header(op: Op) -> RequestHeader {
    RequestHeader {
        op,
        flags: 0,
        mailbox: [0x5a; 32],
        token: [0xc3; 32],
    }
}

/// Whether `hay` holds `byte` eight times in a row.
fn contains_run(hay: &[u8], byte: u8) -> bool {
    hay.windows(8).any(|w| w.iter().all(|b| *b == byte))
}

/// A mix or gateway that tags a request by changing any bit of it, in
/// the prefix, the KEM part, the sealed region or the padding, gets a
/// request the server can't open, and the same error whatever it changed
/// (RT-03). Each byte has a different bit flipped, so every bit position
/// is covered.
#[test]
fn rt03_bitflip_in_any_unit_byte_rejected() {
    let mut rng = HedgedRng::new().unwrap();
    let today = ServerSecret::generate(DAY, &mut rng).unwrap();
    let yesterday = ServerSecret::generate(DAY - 1, &mut rng).unwrap();
    let keys = [&today, &yesterday];

    let env = vec![7u8; ENVELOPE_LEN];
    let (unit, _) = seal_request(today.public(), &header(Op::Write), &env, &mut rng).unwrap();
    let (poll, _) = seal_poll(yesterday.public(), &header(Op::Poll), &mut rng).unwrap();
    assert_eq!((unit.len(), poll.len()), (UNIT_LEN, POLL_LEN));
    assert!(open_request(&keys, &unit).is_ok());
    assert!(open_request(&keys, &poll).is_ok());

    for (name, sealed) in [("unit", &unit), ("poll", &poll)] {
        let mut tagged = sealed.clone();
        for i in 0..sealed.len() {
            let bit = 1u8 << (i % 8);
            tagged[i] ^= bit;
            assert!(
                matches!(open_request(&keys, &tagged), Err(RpcError::Crypto)),
                "{name}: byte {i} changed and still opened"
            );
            tagged[i] ^= bit;
        }
        assert_eq!(&tagged, sealed);
    }
}

/// A recorded request shows nothing of its mailbox or token, and the
/// cleartext of two requests for the same mailbox has nothing in common
/// but the version and suite. What hides them needs the ML-KEM-1024 part:
/// someone who can break X448 (a quantum computer, after the fact) still
/// can't open it (RT-27).
#[test]
fn rt27_request_fields_only_inside_pq_seal() {
    let mut rng = HedgedRng::new().unwrap();
    let server = ServerSecret::generate(DAY, &mut rng).unwrap();
    let env = vec![0u8; ENVELOPE_LEN];
    let h = header(Op::Write);
    let (a, _) = seal_request(server.public(), &h, &env, &mut rng).unwrap();
    let (b, _) = seal_request(server.public(), &h, &env, &mut rng).unwrap();
    let (p, _) = seal_poll(server.public(), &header(Op::Poll), &mut rng).unwrap();
    for bytes in [&a, &b, &p] {
        assert!(!contains_run(bytes, 0x5a), "mailbox in the clear");
        assert!(!contains_run(bytes, 0xc3), "token in the clear");
        assert!(
            !contains_run(bytes, 0x00),
            "plaintext envelope in the clear"
        );
    }
    assert_eq!(a[..4], b[..4], "version and suite");
    assert!(
        a[4..]
            .chunks(16)
            .zip(b[4..].chunks(16))
            .all(|(x, y)| x != y),
        "nothing else links two requests"
    );
    let opened = open_request(&[&server], &a).unwrap();
    assert_eq!(opened.header, h);

    // A key whose X448 half is the server's but whose ML-KEM half is
    // someone else's: holding the X448 secret (what breaking the classical
    // part gives) doesn't open what is sealed to it, and neither does the
    // ML-KEM secret alone.
    let (_x_sk, x_pk) = X448Secret::generate(&mut rng).unwrap();
    let (_m_sk, m_pk) = MlKemSecret::generate(&mut rng).unwrap();
    let classical_known = ServerKey {
        key_id: DAY,
        x448: server.public().x448,
        mlkem: m_pk,
    };
    let (u, _) = seal_request(&classical_known, &h, &env, &mut rng).unwrap();
    assert!(matches!(
        open_request(&[&server], &u),
        Err(RpcError::Crypto)
    ));
    let pq_known = ServerKey {
        key_id: DAY,
        x448: x_pk,
        mlkem: server.public().mlkem.clone(),
    };
    let (u, _) = seal_request(&pq_known, &h, &env, &mut rng).unwrap();
    assert!(matches!(
        open_request(&[&server], &u),
        Err(RpcError::Crypto)
    ));
}
