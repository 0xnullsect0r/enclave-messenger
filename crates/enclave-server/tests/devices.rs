//! A device belongs to one account (`docs/12-servers.md` open question
//! 3): a manifest listing a device another account here still lists is
//! refused, so that account's bundle publications can't be taken over.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::Manifest;
use enclave_proto::recovery::RecoverySecret;
use enclave_rpc::api::{self, DirAction, DirKind, DirReply, DirRequest, Status, manifest_key};
use enclave_rpc::seal_request;
use enclave_server::{Config, Server};
use enclave_wire::{Op, RequestHeader};

const DAY: u32 = 20_700;
const NOW: u64 = DAY as u64 * 86_400 + 60;

fn dir(s: &mut Server, req: DirRequest, rng: &mut HedgedRng) -> (Status, Option<DirReply>) {
    let key = s.public_key().unwrap();
    let h = RequestHeader {
        op: Op::Directory,
        flags: 0,
        mailbox: [0; 32],
        token: [0; 32],
    };
    let env = api::frame(&req.encode(), rng).unwrap();
    let (bytes, ex) = seal_request(&key, &h, &env, rng).unwrap();
    let reply = s.handle(&bytes, NOW);
    let (rh, renv) = ex.open_reply(&reply).unwrap();
    let r = api::unframe(&renv)
        .ok()
        .filter(|p| !p.is_empty())
        .and_then(|p| DirReply::decode(p).ok());
    (Status::from_u8(rh.flags), r)
}

/// Upload `data` in chunks; the status of the last one.
fn put(s: &mut Server, kind: DirKind, key: [u8; 32], data: &[u8], rng: &mut HedgedRng) -> Status {
    let chunks = api::chunks(data);
    let total = chunks.len() as u32;
    let mut last = Status::Ok;
    for (i, c) in chunks.iter().enumerate() {
        let req = DirRequest {
            kind,
            action: DirAction::Put,
            key,
            index: i as u32,
            total,
            proof: [0; 32],
            data: c.to_vec(),
        };
        last = dir(s, req, rng).0;
    }
    last
}

#[test]
fn a_device_listed_by_another_account_is_refused() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = Server::new(Config::default(), DAY).unwrap();
    let device = DeviceKeys::generate(&mut rng).unwrap();
    let make = |rng: &mut HedgedRng| {
        let rs = RecoverySecret::generate(rng).unwrap();
        let account = AccountKeys::create(&rs, rng).unwrap();
        let m = Manifest::genesis(&account, &device, NOW, vec![1; 32]);
        let signed = m.sign(&account, rng).unwrap().to_bytes();
        (manifest_key(&account.root_public.0), signed)
    };
    let (ada, ada_m) = make(&mut rng);
    assert_eq!(
        put(&mut s, DirKind::Manifest, ada, &ada_m, &mut rng),
        Status::Ok
    );
    // Eve signs a manifest of her own with Ada's device ID and her own key
    // under it: refused.
    let rs = RecoverySecret::generate(&mut rng).unwrap();
    let eve = AccountKeys::create(&rs, &mut rng).unwrap();
    let mut forged = DeviceKeys::generate(&mut rng).unwrap();
    forged.id = device.id;
    let eve_m = Manifest::genesis(&eve, &forged, NOW, vec![1; 32])
        .sign(&eve, &mut rng)
        .unwrap();
    assert_eq!(
        put(
            &mut s,
            DirKind::Manifest,
            manifest_key(&eve.root_public.0),
            &eve_m.to_bytes(),
            &mut rng
        ),
        Status::Denied
    );
    // The same device, its own key, under a new root (a lost root
    // replaced, devices kept): allowed.
    let (moved, moved_m) = make(&mut rng);
    assert_eq!(
        put(&mut s, DirKind::Manifest, moved, &moved_m, &mut rng),
        Status::Ok
    );
    // A device of her own is fine.
    let rs = RecoverySecret::generate(&mut rng).unwrap();
    let account = AccountKeys::create(&rs, &mut rng).unwrap();
    let own = DeviceKeys::generate(&mut rng).unwrap();
    let m = Manifest::genesis(&account, &own, NOW, vec![1; 32])
        .sign(&account, &mut rng)
        .unwrap();
    assert_eq!(
        put(
            &mut s,
            DirKind::Manifest,
            manifest_key(&account.root_public.0),
            &m.to_bytes(),
            &mut rng
        ),
        Status::Ok
    );
}

/// Someone else's chunk with a different size of upload is refused, and the
/// upload already under way still completes (`12-servers.md` open question
/// 2).
#[test]
fn a_stray_chunk_doesnt_end_an_upload() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = Server::new(Config::default(), DAY).unwrap();
    let rs = RecoverySecret::generate(&mut rng).unwrap();
    let account = AccountKeys::create(&rs, &mut rng).unwrap();
    let device = DeviceKeys::generate(&mut rng).unwrap();
    let m = Manifest::genesis(&account, &device, NOW, vec![1; 32])
        .sign(&account, &mut rng)
        .unwrap()
        .to_bytes();
    let key = manifest_key(&account.root_public.0);
    let chunks = api::chunks(&m);
    assert!(chunks.len() > 1, "a manifest takes several chunks");
    let total = chunks.len() as u32;
    let req = |index: u32, total: u32, data: Vec<u8>| DirRequest {
        kind: DirKind::Manifest,
        action: DirAction::Put,
        key,
        index,
        total,
        proof: [0; 32],
        data,
    };
    assert_eq!(
        dir(&mut s, req(0, total, chunks[0].to_vec()), &mut rng).0,
        Status::Ok
    );
    assert_eq!(
        dir(&mut s, req(0, total + 1, vec![0; 10]), &mut rng).0,
        Status::Malformed
    );
    let mut last = Status::Ok;
    for (i, c) in chunks.iter().enumerate().skip(1) {
        last = dir(&mut s, req(i as u32, total, c.to_vec()), &mut rng).0;
    }
    assert_eq!(last, Status::Ok);
}
