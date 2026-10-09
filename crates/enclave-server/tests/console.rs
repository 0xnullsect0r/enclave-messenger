//! The operator's console (`enclave_server::admin`, `docs/13-operators.md`
//! §2) and the request-inbox effort an owner can raise.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{
    self, FLAG_CREATE, FLAG_EFFORT, FLAG_REQUEST_INBOX, ReportBody, ReportReason, Status,
};
use enclave_rpc::{ServerKey, seal_request};
use enclave_server::admin::command;
use enclave_server::{Config, Server};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};

const NOW: u64 = 20_800 * 86_400 + 60;

fn call(
    s: &mut Server,
    key: &ServerKey,
    h: RequestHeader,
    env: &[u8],
    rng: &mut HedgedRng,
) -> Status {
    let (bytes, ex) = seal_request(key, &h, env, rng).unwrap();
    let (rh, _) = ex.open_reply(&s.handle(&bytes, NOW)).unwrap();
    Status::from_u8(rh.flags)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn reports_through_the_console() {
    let cfg = Config {
        id: [1; 16],
        effort_request: 1,
        effort_inbox: 0,
        ..Config::default()
    };
    let mut s = Server::new(cfg, (NOW / 86_400) as u32).unwrap();
    let key = s.public_key().unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let inbox = [7u8; 32];
    let owner = [8u8; 32];
    let create = RequestHeader {
        op: Op::RegisterTokens,
        flags: FLAG_CREATE | FLAG_REQUEST_INBOX,
        mailbox: inbox,
        token: owner,
    };
    let empty = api::frame(&[], &mut rng).unwrap();
    assert_eq!(call(&mut s, &key, create, &empty, &mut rng), Status::Ok);

    // A report about that account.
    let body = ReportBody {
        reason: ReportReason::Abuse,
        on_record: false,
        reported: None,
        signed: Vec::new(),
        quotes: vec!["first\nline".into(), "second".into()],
    };
    let env = api::frame(&body.encode(), &mut rng).unwrap();
    let ctx = api::pow_context_report(&inbox, NOW / 86_400, &enclave_crypto::hash::sha3_512(&env));
    let proof = enclave_tokens::solve(&ctx, 1, &mut rng).unwrap();
    let h = RequestHeader {
        op: Op::Report,
        flags: 0,
        mailbox: inbox,
        token: proof.0,
    };
    assert_eq!(call(&mut s, &key, h, &env, &mut rng), Status::Ok);

    let list = command(&mut s, "reports", NOW);
    assert!(list.starts_with("ok 1 waiting\n#0 "), "{list}");
    assert!(list.contains("harassment or threats"), "{list}");
    assert!(list.contains(&hex(&inbox)), "{list}");
    let one = command(&mut s, "report 0", NOW);
    assert!(one.contains("off the record: nobody can confirm"), "{one}");
    assert!(one.contains("quote 1: first \u{23ce} line\n"), "{one}");
    assert!(command(&mut s, "report 9", NOW).starts_with("error"));
    assert!(command(&mut s, "dismiss 0", NOW).starts_with("ok"));
    assert!(command(&mut s, "reports", NOW).starts_with("ok 0 waiting"));
    assert!(command(&mut s, "dismiss 0", NOW).starts_with("error"));

    let close = format!("close-request-inbox {}", hex(&inbox));
    assert!(command(&mut s, &close, NOW).starts_with("ok"));
    assert!(
        command(&mut s, &close, NOW).starts_with("error"),
        "already closed"
    );
    assert!(command(&mut s, "close-request-inbox 12", NOW).starts_with("error"));
    assert!(command(&mut s, "stats", NOW).contains("\nrequests "));
    assert!(
        command(&mut s, "withdraw-username ada", NOW).starts_with("error"),
        "no log here"
    );
    assert!(command(&mut s, "rm -rf /", NOW).starts_with("error: commands are"));
}

#[test]
fn an_owner_raises_what_requests_cost() {
    let cfg = Config {
        id: [1; 16],
        effort_request: 1,
        effort_inbox: 0,
        ..Config::default()
    };
    let mut s = Server::new(cfg, (NOW / 86_400) as u32).unwrap();
    let key = s.public_key().unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let inbox = [7u8; 32];
    let owner = [8u8; 32];
    let empty = api::frame(&[], &mut rng).unwrap();
    for (mb, flags) in [
        (inbox, FLAG_CREATE | FLAG_REQUEST_INBOX),
        ([9; 32], FLAG_CREATE),
    ] {
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags,
            mailbox: mb,
            token: owner,
        };
        assert_eq!(call(&mut s, &key, h, &empty, &mut rng), Status::Ok);
    }
    let set =
        |effort: u32, mailbox: [u8; 32], token: [u8; 32], s: &mut Server, rng: &mut HedgedRng| {
            let h = RequestHeader {
                op: Op::RegisterTokens,
                flags: FLAG_EFFORT,
                mailbox,
                token,
            };
            let env = api::frame(&effort.to_be_bytes(), rng).unwrap();
            call(s, &key, h, &env, rng)
        };
    assert_eq!(
        set(64, inbox, [0; 32], &mut s, &mut rng),
        Status::Denied,
        "not the owner"
    );
    assert_eq!(
        set(64, [9; 32], owner, &mut s, &mut rng),
        Status::Denied,
        "not a request inbox"
    );
    assert_eq!(
        set(api::MAX_INBOX_EFFORT + 1, inbox, owner, &mut s, &mut rng),
        Status::Malformed
    );
    assert_eq!(set(64, inbox, owner, &mut s, &mut rng), Status::Ok);

    let env = vec![3u8; ENVELOPE_LEN];
    let digest = enclave_crypto::hash::sha3_512(&env);
    let ctx = api::pow_context_request(&inbox, NOW / 86_400, &digest);
    let write = |effort: u32, s: &mut Server, rng: &mut HedgedRng| {
        // A proof of exactly this effort: one that happens to meet 64 too
        // would make the test flaky.
        let proof = loop {
            let p = enclave_tokens::solve(&ctx, effort, rng).unwrap();
            if effort >= 64 || !enclave_tokens::verify(&ctx, 64, &p) {
                break p;
            }
        };
        let h = RequestHeader {
            op: Op::WriteRequest,
            flags: 0,
            mailbox: inbox,
            token: proof.0,
        };
        call(s, &key, h, &env, rng)
    };
    assert_eq!(
        write(1, &mut s, &mut rng),
        Status::Pow,
        "the server's effort isn't enough"
    );
    assert_eq!(write(64, &mut s, &mut rng), Status::Ok);
    assert_eq!(
        set(0, inbox, owner, &mut s, &mut rng),
        Status::Ok,
        "back to the server's"
    );
    assert_eq!(write(1, &mut s, &mut rng), Status::Ok);
}
