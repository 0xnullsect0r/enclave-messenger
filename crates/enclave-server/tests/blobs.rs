//! Blob uploads paid with Privacy Pass tokens (`docs/09-transport.md` §9):
//! an inbox's owner is issued blind tokens up to the daily quota; a token,
//! spent once with nothing naming the account, buys an allocation of chunk
//! uploads; a `BlobPut` without one is refused.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{
    self, ALLOC_CHUNKS, BlobAlloc, BlobAllocReply, FLAG_CREATE, PP_TOKEN_LEN, Status,
};
use enclave_rpc::seal_request;
use enclave_server::{Config, Server};
use enclave_tokens::privpass::{IssuerPublic, Pending, blob_challenge};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};

const DAY: u32 = 20_700;
const NOW: u64 = DAY as u64 * 86_400 + 600;
const ID: [u8; 16] = [5; 16];

fn call(s: &mut Server, h: RequestHeader, env: &[u8], rng: &mut HedgedRng) -> (Status, Vec<u8>) {
    let key = s.public_key().unwrap();
    let (bytes, ex) = seal_request(&key, &h, env, rng).unwrap();
    let (rh, renv) = ex.open_reply(&s.handle(&bytes, NOW)).unwrap();
    (Status::from_u8(rh.flags), renv)
}

fn alloc_call(
    s: &mut Server,
    mailbox: [u8; 32],
    token: [u8; 32],
    req: &BlobAlloc,
    rng: &mut HedgedRng,
) -> (Status, Option<BlobAllocReply>) {
    let h = RequestHeader {
        op: Op::BlobAlloc,
        flags: 0,
        mailbox,
        token,
    };
    let env = api::frame(&req.encode(), rng).unwrap();
    let (st, renv) = call(s, h, &env, rng);
    let reply = api::unframe(&renv)
        .ok()
        .filter(|p| !p.is_empty())
        .and_then(|p| BlobAllocReply::decode(p).ok());
    (st, reply)
}

fn put(s: &mut Server, id: [u8; 32], alloc: [u8; 32], rng: &mut HedgedRng) -> Status {
    let h = RequestHeader {
        op: Op::BlobPut,
        flags: 0,
        mailbox: id,
        token: alloc,
    };
    call(s, h, &vec![7; ENVELOPE_LEN], rng).0
}

#[test]
fn tokens_buy_uploads() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = Server::new(
        Config {
            id: ID,
            effort_inbox: 0,
            blob_tokens_per_day: 10,
            ..Config::default()
        },
        DAY,
    )
    .unwrap();
    // An inbox to prove the account.
    let (inbox, owner) = ([1; 32], [2; 32]);
    let h = RequestHeader {
        op: Op::RegisterTokens,
        flags: FLAG_CREATE,
        mailbox: inbox,
        token: owner,
    };
    let env = api::frame(&api::create_payload(&[0; 32], &[]), &mut rng).unwrap();
    assert_eq!(call(&mut s, h, &env, &mut rng).0, Status::Ok);

    // The key, as the descriptor lists it.
    let (st, reply) = alloc_call(&mut s, [0; 32], [0; 32], &BlobAlloc::Key, &mut rng);
    assert_eq!(st, Status::Ok);
    let Some(BlobAllocReply::Issued { epoch, public, .. }) = reply else {
        panic!("no key");
    };
    assert_eq!(epoch, api::issuer_epoch(NOW));
    assert_eq!(s.blob_issuers(NOW)[0].public, public);

    let digest = blob_challenge(&ID).digest().unwrap();
    let issue = |s: &mut Server, owner: [u8; 32], n: usize, rng: &mut HedgedRng| {
        let (reqs, pending): (Vec<[u8; api::PP_REQUEST_LEN]>, Vec<_>) = (0..n)
            .map(|_| {
                let (r, p) = Pending::begin(IssuerPublic(public), digest, rng).unwrap();
                (<[u8; api::PP_REQUEST_LEN]>::try_from(r).unwrap(), p)
            })
            .unzip();
        let (st, reply) = alloc_call(s, inbox, owner, &BlobAlloc::Issue(reqs), rng);
        (st, reply, pending)
    };
    // Only the owner, and only the quota.
    assert_eq!(issue(&mut s, [9; 32], 1, &mut rng).0, Status::Denied);
    let (st, reply, pending) = issue(&mut s, owner, 8, &mut rng);
    assert_eq!(st, Status::Ok);
    let Some(BlobAllocReply::Issued { responses, .. }) = reply else {
        panic!("no tokens");
    };
    let tokens: Vec<[u8; PP_TOKEN_LEN]> = pending
        .into_iter()
        .zip(responses)
        .map(|(p, r)| p.finish(&r).unwrap().encode().try_into().unwrap())
        .collect();
    assert_eq!(
        issue(&mut s, owner, 3, &mut rng).0,
        Status::Quota,
        "8 + 3 is over 10 a day"
    );

    // A token buys an allocation; the same token again doesn't.
    let (st, reply) = alloc_call(
        &mut s,
        [3; 32],
        [4; 32],
        &BlobAlloc::Redeem(tokens[0]),
        &mut rng,
    );
    assert_eq!(st, Status::Ok);
    let Some(BlobAllocReply::Allocated { alloc, chunks }) = reply else {
        panic!("no allocation");
    };
    assert_eq!(chunks, ALLOC_CHUNKS);
    let again = alloc_call(
        &mut s,
        [3; 32],
        [4; 32],
        &BlobAlloc::Redeem(tokens[0]),
        &mut rng,
    );
    assert_eq!(again.0, Status::Denied, "spent");
    let mut forged = tokens[1];
    forged[PP_TOKEN_LEN - 1] ^= 1;
    let bad = alloc_call(
        &mut s,
        [3; 32],
        [4; 32],
        &BlobAlloc::Redeem(forged),
        &mut rng,
    );
    assert_eq!(bad.0, Status::Denied, "not one we issued");

    // Uploads under the allocation; none without one; an id only once.
    assert_eq!(put(&mut s, [8; 32], alloc, &mut rng), Status::Ok);
    assert_eq!(put(&mut s, [8; 32], alloc, &mut rng), Status::Denied);
    assert_eq!(put(&mut s, [9; 32], [0; 32], &mut rng), Status::Quota);
}
