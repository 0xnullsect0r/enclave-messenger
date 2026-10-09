//! Rotating account inboxes at the server (`docs/09-transport.md` §3):
//! daily read credentials, token hashes bound to the address, the burned
//! token's hash returned as a session hint, and expiry after the last day.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{self, FLAG_CREATE, FLAG_FOUND, Status};
use enclave_rpc::{seal_poll, seal_request};
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

fn call(
    s: &mut Server,
    h: RequestHeader,
    env: &[u8],
    now: u64,
    rng: &mut HedgedRng,
) -> (Status, RequestHeader, Vec<u8>) {
    let key = s.public_key().unwrap();
    let (bytes, ex) = if matches!(h.op, Op::Poll | Op::Ack) {
        seal_poll(&key, &h, rng).unwrap()
    } else {
        seal_request(&key, &h, env, rng).unwrap()
    };
    let (rh, renv) = ex.open_reply(&s.handle(&bytes, now)).unwrap();
    (Status::from_u8(rh.flags), rh, renv)
}

struct Inbox {
    addr: [u8; 32],
    owner: [u8; 32],
    read_key: [u8; 32],
}

impl Inbox {
    fn new(seed: &[u8; 32], week: u32) -> Self {
        let addr = api::inbox_addr(&api::inbox_addr_seed(seed), week);
        Self {
            addr,
            owner: api::inbox_owner(seed, &addr),
            read_key: api::inbox_read_key(seed),
        }
    }

    fn create(&self, s: &mut Server, days: std::ops::RangeInclusive<u32>, rng: &mut HedgedRng) {
        let creds: Vec<(u32, [u8; 32])> = days
            .map(|d| {
                let c = api::daily_read_credential(&self.read_key, &self.addr, d);
                (d, api::credential_hash(&c))
            })
            .collect();
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags: FLAG_CREATE,
            mailbox: self.addr,
            token: self.owner,
        };
        let env = api::frame(&api::create_payload(&[0; 32], &creds), rng).unwrap();
        assert_eq!(call(s, h, &env, at(DAY), rng).0, Status::Ok);
    }

    fn register(&self, s: &mut Server, hashes: &[[u8; 32]], rng: &mut HedgedRng) -> Status {
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags: 0,
            mailbox: self.addr,
            token: self.owner,
        };
        call(
            s,
            h,
            &api::frame(&hashes.concat(), rng).unwrap(),
            at(DAY),
            rng,
        )
        .0
    }

    fn write(&self, s: &mut Server, token: [u8; 32], rng: &mut HedgedRng) -> Status {
        let h = RequestHeader {
            op: Op::Write,
            flags: 0,
            mailbox: self.addr,
            token,
        };
        call(s, h, &vec![1; ENVELOPE_LEN], at(DAY), rng).0
    }

    /// Poll on `day` with that day's credential (or `cred_day`'s).
    fn poll(
        &self,
        s: &mut Server,
        cred_day: u32,
        day: u32,
        rng: &mut HedgedRng,
    ) -> (Status, RequestHeader) {
        let mut token = [0u8; 32];
        token[..24].copy_from_slice(&api::daily_read_credential(
            &self.read_key,
            &self.addr,
            cred_day,
        ));
        let h = RequestHeader {
            op: Op::Poll,
            flags: 0,
            mailbox: self.addr,
            token,
        };
        let (st, rh, _) = call(s, h, &[], at(day), rng);
        (st, rh)
    }
}

/// Each day has its own credential; the server takes yesterday's, today's
/// and tomorrow's (clocks disagree), and nothing outside the registered
/// days or older.
#[test]
fn read_credential_is_daily() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = server();
    let ib = Inbox::new(&[1; 32], 3000);
    ib.create(&mut s, DAY..=DAY + 13, &mut rng);
    assert_eq!(ib.poll(&mut s, DAY, DAY, &mut rng).0, Status::Ok);
    assert_eq!(
        ib.poll(&mut s, DAY + 1, DAY, &mut rng).0,
        Status::Ok,
        "a clock ahead"
    );
    assert_eq!(
        ib.poll(&mut s, DAY + 5, DAY + 6, &mut rng).0,
        Status::Ok,
        "behind"
    );
    assert_eq!(
        ib.poll(&mut s, DAY + 2, DAY, &mut rng).0,
        Status::Denied,
        "two days off"
    );
    assert_eq!(
        ib.poll(&mut s, DAY + 14, DAY + 14, &mut rng).0,
        Status::Denied,
        "not registered"
    );
    // Another inbox's credential for the same day doesn't open this one.
    let other = Inbox::new(&[2; 32], 3000);
    let mut token = [0u8; 32];
    token[..24].copy_from_slice(&api::daily_read_credential(&other.read_key, &ib.addr, DAY));
    let h = RequestHeader {
        op: Op::Poll,
        flags: 0,
        mailbox: ib.addr,
        token,
    };
    assert_eq!(call(&mut s, h, &[], at(DAY), &mut rng).0, Status::Denied);
    // Days too far ahead or long past can't be registered.
    let far = Inbox::new(&[3; 32], 3000);
    let creds = vec![(DAY + 40, [0; 32])];
    let h = RequestHeader {
        op: Op::RegisterTokens,
        flags: FLAG_CREATE,
        mailbox: far.addr,
        token: far.owner,
    };
    let env = api::frame(&api::create_payload(&[0; 32], &creds), &mut rng).unwrap();
    assert_eq!(
        call(&mut s, h, &env, at(DAY), &mut rng).0,
        Status::Malformed
    );
}

/// A token registered at one address doesn't open another: what the
/// server stores is bound to the address, so the same token at two of an
/// owner's weeks gives two unrelated hashes.
#[test]
fn token_hash_bound_to_address() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = server();
    let a = Inbox::new(&[1; 32], 3000);
    let b = Inbox::new(&[1; 32], 3001);
    assert_ne!(a.addr, b.addr, "weeks have different addresses");
    assert_ne!(a.owner, b.owner, "and different owner secrets");
    a.create(&mut s, DAY..=DAY + 13, &mut rng);
    b.create(&mut s, DAY..=DAY + 13, &mut rng);
    let t = [9u8; 32];
    assert_ne!(token_hash(&t, &a.addr), token_hash(&t, &b.addr));
    assert_eq!(
        a.register(&mut s, &[token_hash(&t, &a.addr)], &mut rng),
        Status::Ok
    );
    assert_eq!(
        b.write(&mut s, t, &mut rng),
        Status::Denied,
        "not registered there"
    );
    // The unbound hash (no address) is not what the server checks either.
    let u = [8u8; 32];
    assert_eq!(
        a.register(&mut s, &[token_hash(&u, &[0; 32])], &mut rng),
        Status::Ok
    );
    assert_eq!(a.write(&mut s, u, &mut rng), Status::Denied);
    assert_eq!(a.write(&mut s, t, &mut rng), Status::Ok);
    assert_eq!(a.write(&mut s, t, &mut rng), Status::Denied, "burned");
    // Week b's owner secret can't register at week a's address.
    let h = RequestHeader {
        op: Op::RegisterTokens,
        flags: 0,
        mailbox: a.addr,
        token: b.owner,
    };
    let env = api::frame(&[7; 32], &mut rng).unwrap();
    assert_eq!(call(&mut s, h, &env, at(DAY), &mut rng).0, Status::Denied);
}

/// The poll that returns an envelope says which token its write burned
/// (the first 24 bytes of the hash), and nothing when there was none.
#[test]
fn session_hint_returns_burned_token() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = server();
    let ib = Inbox::new(&[4; 32], 3000);
    ib.create(&mut s, DAY..=DAY + 13, &mut rng);
    let t1 = [1u8; 32];
    let t2 = [2u8; 32];
    let hashes = [token_hash(&t1, &ib.addr), token_hash(&t2, &ib.addr)];
    assert_eq!(ib.register(&mut s, &hashes, &mut rng), Status::Ok);
    assert_eq!(ib.write(&mut s, t2, &mut rng), Status::Ok);
    assert_eq!(ib.write(&mut s, t1, &mut rng), Status::Ok);
    let (st, rh) = ib.poll(&mut s, DAY, DAY, &mut rng);
    assert_eq!(st, Status::Ok);
    assert_ne!(rh.flags & FLAG_FOUND, 0);
    assert_eq!(
        &rh.token[..24],
        &hashes[1][..24],
        "the first write burned t2"
    );
    assert_eq!(u64::from_be_bytes(rh.token[24..].try_into().unwrap()), 1);
}

/// A rotating inbox is deleted, with its tokens, envelopes and
/// credentials, once its last day and the envelope lifetime have passed;
/// a static one (no days) is kept.
#[test]
fn rotating_inbox_expires() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = server();
    let ib = Inbox::new(&[5; 32], 3000);
    ib.create(&mut s, DAY..=DAY + 13, &mut rng);
    let t = [3u8; 32];
    assert_eq!(
        ib.register(&mut s, &[token_hash(&t, &ib.addr)], &mut rng),
        Status::Ok
    );
    let ttl_days = Config::default().ttl_secs.div_ceil(86_400) as u32;
    s.expire(at(DAY + 13 + ttl_days));
    assert_eq!(ib.write(&mut s, t, &mut rng), Status::Ok, "still there");
    s.expire(at(DAY + 14 + ttl_days));
    assert_eq!(ib.write(&mut s, t, &mut rng), Status::NotFound, "gone");
}
