//! A server that restarts keeps what it promised (`docs/12-servers.md` §1.3,
//! §1.4): its id and request keys, inboxes, unspent tokens and stored
//! envelopes; and a token spent before the restart stays spent.
//!
//! Each test runs on every storage backend (`common::stores`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use common::Store;

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{self, FLAG_CREATE, FLAG_FOUND, Status};
use enclave_rpc::{ServerKey, seal_poll, seal_request};
use enclave_server::keys::ServerKeys;
use enclave_server::{Config, Server};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::path::{Path, PathBuf};

const DAY: u32 = 20_500;
const NOW: u64 = DAY as u64 * 86_400 + 3_600;

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("enclave-restart-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn open(d: &Path, store: &Store) -> (Server, ServerKeys) {
    let keys = ServerKeys::load(&d.join("keys")).unwrap();
    // Inbox proofs of work are tested in tests/replay.rs.
    let cfg = Config {
        id: keys.id(),
        effort_inbox: 0,
        ..Config::default()
    };
    (
        Server::open(cfg, store.open(), keys.chain.keys()).unwrap(),
        keys,
    )
}

/// One request through the server; the reply status and envelope.
fn call(
    s: &mut Server,
    key: &ServerKey,
    h: RequestHeader,
    env: &[u8],
    rng: &mut HedgedRng,
) -> (Status, RequestHeader, Vec<u8>) {
    let (bytes, ex) = if matches!(h.op, Op::Poll | Op::Ack) {
        seal_poll(key, &h, rng).unwrap()
    } else {
        seal_request(key, &h, env, rng).unwrap()
    };
    let reply = s.handle(&bytes, NOW);
    let (rh, renv) = ex.open_reply(&reply).unwrap();
    (Status::from_u8(rh.flags), rh, renv)
}

#[test]
fn state_survives_a_restart() {
    let d = dir("state");
    for store in common::stores("state_survives_a_restart", &d) {
        state_survives_a_restart_on(&d, &store);
    }
    let _ = std::fs::remove_dir_all(&d);
}

fn state_survives_a_restart_on(d: &Path, store: &Store) {
    eprintln!("state_survives_a_restart on {}", store.name());
    let _ = std::fs::remove_dir_all(d.join("keys"));
    let keys = ServerKeys::init(&d.join("keys"), DAY).unwrap();
    let id = keys.id();
    drop(keys);
    let mut rng = HedgedRng::new().unwrap();
    let mailbox = [7u8; 32];
    let owner = [9u8; 32];
    let tokens: Vec<[u8; 32]> = (0..3u8).map(|i| [i + 1; 32]).collect();
    let envelope = vec![0x5a; ENVELOPE_LEN];

    let pinned_key = {
        let (mut s, _) = open(d, store);
        let key = s.public_key().unwrap();
        let create = RequestHeader {
            op: Op::RegisterTokens,
            flags: FLAG_CREATE,
            mailbox,
            token: owner,
        };
        let empty = api::frame(&[], &mut rng).unwrap();
        assert_eq!(call(&mut s, &key, create, &empty, &mut rng).0, Status::Ok);
        let hashes: Vec<u8> = tokens
            .iter()
            .flat_map(|t| enclave_tokens::token_hash(t, &mailbox))
            .collect();
        let reg = RequestHeader {
            op: Op::RegisterTokens,
            flags: 0,
            mailbox,
            token: owner,
        };
        let body = api::frame(&hashes, &mut rng).unwrap();
        assert_eq!(call(&mut s, &key, reg, &body, &mut rng).0, Status::Ok);
        let write = RequestHeader {
            op: Op::Write,
            flags: 0,
            mailbox,
            token: tokens[0],
        };
        assert_eq!(call(&mut s, &key, write, &envelope, &mut rng).0, Status::Ok);
        key
        // The server is dropped here: as good as a crash after the reply.
    };

    let (mut s, keys) = open(d, store);
    assert_eq!(keys.id(), id, "same id after a restart");
    let key = s.public_key().unwrap();
    assert_eq!(
        key, pinned_key,
        "same request key: clients' cached key works"
    );

    // The envelope is still there.
    let mut cred = [0u8; 32];
    cred[..24].copy_from_slice(&api::read_credential(&owner));
    let poll = RequestHeader {
        op: Op::Poll,
        flags: 0,
        mailbox,
        token: cred,
    };
    let (st, rh, env) = call(&mut s, &key, poll, &[], &mut rng);
    assert_eq!(st, Status::Ok);
    assert!(rh.flags & FLAG_FOUND != 0);
    assert_eq!(env, envelope);

    // The spent token stays spent; an unspent one still works.
    let replay = RequestHeader {
        op: Op::Write,
        flags: 0,
        mailbox,
        token: tokens[0],
    };
    assert_eq!(
        call(&mut s, &key, replay, &envelope, &mut rng).0,
        Status::Denied
    );
    let fresh = RequestHeader {
        op: Op::Write,
        flags: 0,
        mailbox,
        token: tokens[1],
    };
    assert_eq!(call(&mut s, &key, fresh, &envelope, &mut rng).0, Status::Ok);
}

#[test]
fn request_keys_roll_forward_and_old_seeds_are_gone() {
    let d = dir("chain");
    let mut keys = ServerKeys::init(&d.join("keys"), DAY).unwrap();
    let day0 = keys.chain.keys()[0].public().clone();
    let day1_published = keys.chain.next_key().public().clone();
    keys.chain.advance_to(DAY + 1).unwrap();
    assert_eq!(keys.chain.keys()[0].public(), &day1_published);
    keys.chain.advance_to(DAY + 3).unwrap();
    // Nothing on disk derives day 0's key any more.
    let file = std::fs::read(d.join("keys").join("request-chain.key")).unwrap();
    let reloaded = ServerKeys::load(&d.join("keys")).unwrap();
    assert!(reloaded.chain.keys().iter().all(|k| k.public() != &day0));
    assert!(file.len() <= 69, "today's and yesterday's seeds only");
    let _ = std::fs::remove_dir_all(&d);
}
