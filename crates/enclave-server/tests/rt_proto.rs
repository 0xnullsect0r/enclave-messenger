//! Red-team checks at the server (`docs/redteam-matrix.md` RT-24, RT-27;
//! `docs/09-transport.md` §2, §3.3).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{self, FLAG_CREATE, Status};
use enclave_rpc::{Exchange, ServerKey, open_request, seal_request};
use enclave_server::keys::ServerKeys;
use enclave_server::{Config, Server};
use enclave_tokens::token_hash;
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};

const DAY: u32 = 20_700;

fn at(day: u32) -> u64 {
    u64::from(day) * 86_400 + 600
}

fn server() -> Server {
    let cfg = Config {
        effort_inbox: 0,
        ..Config::default()
    };
    Server::new(cfg, DAY).unwrap()
}

fn sealed(
    key: &ServerKey,
    op: Op,
    flags: u8,
    mailbox: [u8; 32],
    token: [u8; 32],
    env: &[u8],
    rng: &mut HedgedRng,
) -> (Vec<u8>, Exchange) {
    let h = RequestHeader {
        op,
        flags,
        mailbox,
        token,
    };
    seal_request(key, &h, env, rng).unwrap()
}

/// The reply's status, or `None` when the server couldn't open the
/// request (its answer is random bytes).
fn answer(s: &mut Server, req: &(Vec<u8>, Exchange), now: u64) -> Option<Status> {
    let (rh, _) = req.1.open_reply(&s.handle(&req.0, now)).ok()?;
    Some(Status::from_u8(rh.flags))
}

/// A write token is good for one envelope (RT-24): written again, in a
/// freshly sealed request, it is refused and nothing more is stored; the
/// same request bytes sent again are not processed at all; another
/// registered token still works.
#[test]
fn rt24_token_reuse_rejected() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = server();
    let key = s.public_key().unwrap();
    let now = at(DAY);
    let seed = [4u8; 32];
    let addr = api::inbox_addr(&api::inbox_addr_seed(&seed), 3000);
    let owner = api::inbox_owner(&seed, &addr);
    let create = api::frame(&api::create_payload(&[0; 32], &[]), &mut rng).unwrap();
    let create = sealed(
        &key,
        Op::RegisterTokens,
        FLAG_CREATE,
        addr,
        owner,
        &create,
        &mut rng,
    );
    assert_eq!(answer(&mut s, &create, now), Some(Status::Ok));
    let (t1, t2) = ([1u8; 32], [2u8; 32]);
    let hashes = [token_hash(&t1, &addr), token_hash(&t2, &addr)].concat();
    let hashes = api::frame(&hashes, &mut rng).unwrap();
    let reg = sealed(&key, Op::RegisterTokens, 0, addr, owner, &hashes, &mut rng);
    assert_eq!(answer(&mut s, &reg, now), Some(Status::Ok));

    let env = vec![1u8; ENVELOPE_LEN];
    let first = sealed(&key, Op::Write, 0, addr, t1, &env, &mut rng);
    assert_eq!(answer(&mut s, &first, now), Some(Status::Ok));
    let held = s.envelopes_held();
    let again = sealed(
        &key,
        Op::Write,
        0,
        addr,
        t1,
        &vec![2u8; ENVELOPE_LEN],
        &mut rng,
    );
    assert_eq!(answer(&mut s, &again, now), Some(Status::Denied));
    assert_eq!(answer(&mut s, &first, now), None, "a replayed request");
    assert_eq!(s.envelopes_held(), held, "nothing more stored");
    let other = sealed(&key, Op::Write, 0, addr, t2, &env, &mut rng);
    assert_eq!(answer(&mut s, &other, now), Some(Status::Ok));
    assert_eq!(s.envelopes_held(), held + 1);
}

/// A request recorded on its way can't be opened once its day's key has
/// rotated out (RT-27): the server answers it the day after (late
/// requests), and two rotations later neither the running server nor the
/// key files on its disk can open it.
#[test]
fn rt27_server_request_key_deleted_after_rotation() {
    let mut rng = HedgedRng::new().unwrap();
    let env = api::frame(&[], &mut rng).unwrap();

    // In memory: today's key, kept one day more, then gone.
    let mut s = server();
    let key = s.public_key().unwrap();
    assert_eq!(key.key_id, DAY);
    let recorded: Vec<_> = (0..2)
        .map(|_| sealed(&key, Op::Cover, 0, [0; 32], [0; 32], &env, &mut rng))
        .collect();
    s.rotate(DAY + 1).unwrap();
    assert_eq!(s.public_key().unwrap().key_id, DAY + 1);
    assert!(answer(&mut s, &recorded[0], at(DAY + 1)).is_some());
    s.rotate(DAY + 2).unwrap();
    assert_eq!(answer(&mut s, &recorded[1], at(DAY + 2)), None);

    // On disk: the request-key chain steps forward and erases old seeds.
    let dir = std::env::temp_dir().join(format!("enclave-rt27-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut keys = ServerKeys::init(&dir, DAY).unwrap();
    let day_key = keys.chain.keys()[0].public().clone();
    let (a, _) = sealed(&day_key, Op::Cover, 0, [0; 32], [0; 32], &env, &mut rng);
    let (b, _) = sealed(&day_key, Op::Cover, 0, [0; 32], [0; 32], &env, &mut rng);
    let opens = |keys: &ServerKeys, req: &[u8]| {
        let held = keys.chain.keys();
        let refs: Vec<_> = held.iter().collect();
        open_request(&refs, req).is_ok()
    };
    keys.chain.advance_to(DAY + 1).unwrap();
    assert!(opens(&ServerKeys::load(&dir).unwrap(), &a), "a day late");
    keys.chain.advance_to(DAY + 2).unwrap();
    assert!(!opens(&keys, &b));
    let seized = ServerKeys::load(&dir).unwrap();
    assert!(!opens(&seized, &b), "nothing on disk opens it");
    assert!(
        seized
            .chain
            .keys()
            .iter()
            .all(|k| k.key_id > DAY && k.public() != &day_key)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
