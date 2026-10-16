//! End-to-end protocol tests: EQXDH, the Lockstep ratchet and envelopes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::kem::McEliecePublic;
use enclave_crypto::rng::HedgedRng;
use enclave_proto::bundle::{Bundle, PrekeyStore, Publication};
use enclave_proto::envelope::{
    self, open_direct, open_request, request_initial, seal_direct, seal_request,
};
use enclave_proto::eqxdh::{self, InitiatorIdentity, Local, ManifestResolver, Mode, Peer};
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::{DeviceEntry, Manifest, Role as DeviceRole};
use enclave_proto::ratchet::Session;
use enclave_proto::recovery::RecoverySecret;
use enclave_proto::{ProtoError, Result};

const NOW: u64 = 1_790_000_000;

struct Party {
    account: AccountKeys,
    devices: Vec<DeviceKeys>,
    prekeys: Vec<PrekeyStore>,
    publications: Vec<Publication>,
    manifest: Manifest,
}

impl Party {
    fn new(n_devices: usize, rng: &mut HedgedRng) -> Self {
        let rs = RecoverySecret::generate(rng).unwrap();
        let account = AccountKeys::create(&rs, rng).unwrap();
        let mut devices = Vec::new();
        let mut prekeys = Vec::new();
        let mut publications = Vec::new();
        for _ in 0..n_devices {
            let d = DeviceKeys::generate(rng).unwrap();
            let mut store = PrekeyStore::default();
            // Genesis manifests are at bundle epoch 1.
            publications.push(store.publish(&d, 1, NOW, rng).unwrap());
            prekeys.push(store);
            devices.push(d);
        }
        let mut manifest =
            Manifest::genesis(&account, &devices[0], NOW, b"server-1/inbox".to_vec());
        for d in &devices[1..] {
            manifest
                .devices
                .push(DeviceEntry::for_device(d, DeviceRole::Linked, NOW));
        }
        Self {
            account,
            devices,
            prekeys,
            publications,
            manifest,
        }
    }

    fn bundle(&self, dev: usize, opk_index: Option<usize>) -> Bundle {
        let p = &self.publications[dev];
        Bundle {
            spk: p.spk.clone(),
            opk: opk_index.map(|i| (p.batch.clone(), p.opks[i].clone())),
            last_resort: p.last_resort.clone(),
        }
    }

    fn local(&self, dev: usize) -> Local<'_> {
        Local {
            account: &self.account,
            device: &self.devices[dev],
            manifest: &self.manifest,
            locator: b"server-1/manifest",
        }
    }
}

struct Directory(Vec<Manifest>);

impl ManifestResolver for Directory {
    fn resolve(&mut self, id: &InitiatorIdentity) -> Result<Manifest> {
        self.0
            .iter()
            .find(|m| m.root.0 == id.root)
            .cloned()
            .ok_or(ProtoError::Missing)
    }
}

/// Alice device 0 → Bob device `bob_dev`; returns (alice session, bob session).
fn handshake(
    alice: &Party,
    bob: &mut Party,
    bob_dev: usize,
    vault: Option<&McEliecePublic>,
    mode: Mode,
    psk: Option<&[u8; 32]>,
    rng: &mut HedgedRng,
) -> (Session, Session) {
    let bundle = bob.bundle(bob_dev, Some(7));
    bundle
        .verify(
            bob.devices[bob_dev].signing.public(),
            bob.manifest.bundle_epoch,
            NOW,
        )
        .unwrap();
    let peer = Peer {
        manifest: &bob.manifest,
        device: &bob.manifest.devices[bob_dev],
        bundle: &bundle,
        vault,
    };
    let init = eqxdh::initiate(&alice.local(0), &peer, mode, psk, rng).unwrap();
    let mut a = init.session;
    let env = seal_request(&init.message, &mut a, b"hello bob", rng).unwrap();
    assert_eq!(env.len(), enclave_wire::ENVELOPE_LEN);

    let msg = request_initial(&env).unwrap();
    let mut dir = Directory(vec![alice.manifest.clone()]);
    let local = Local {
        account: &bob.account,
        device: &bob.devices[bob_dev],
        manifest: &bob.manifest,
        locator: b"server-2/manifest",
    };
    let resp = eqxdh::respond(&local, &mut bob.prekeys[bob_dev], &msg, psk, &mut dir, rng).unwrap();
    assert_eq!(resp.identity.root, alice.account.root_public.0);
    assert_eq!(resp.mode, mode);
    let mut b = resp.session;
    assert_eq!(open_request(&mut b, &env, rng).unwrap(), b"hello bob");
    (a, b)
}

fn send(from: &mut Session, text: &[u8], rng: &mut HedgedRng) -> Vec<u8> {
    let carry = from.wants_pq_slot().then_some(0);
    seal_direct(&mut [from], text, carry, rng).unwrap()
}

fn recv(
    to: &mut Session,
    env: &[u8],
    vault: Option<&enclave_crypto::kem::McElieceSecret>,
    rng: &mut HedgedRng,
) -> Result<Vec<u8>> {
    open_direct(&mut [to], env, vault, rng).map(|o| o.content)
}

#[test]
fn full_three_kem_conversation() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    let vault = bob.account.vault_public.clone();
    let (mut a, mut b) = handshake(
        &alice,
        &mut bob,
        0,
        Some(&vault),
        Mode::OffTheRecord,
        None,
        &mut rng,
    );
    assert!(a.three_kem() && b.three_kem());
    assert!(
        !b.pq_authenticated(),
        "Alice is not PQ-authenticated before a round trip"
    );

    // Bob replies; his first PQ step answers Alice's device auth key.
    let e = send(&mut b, b"hi alice", &mut rng);
    assert_eq!(recv(&mut a, &e, None, &mut rng).unwrap(), b"hi alice");
    assert!(a.pq_authenticated());
    assert_eq!(a.pq_epochs(), (0, 1));

    // Alice answers Bob's fresh key; Bob sees Alice use in-epoch 1.
    let e = send(&mut a, b"how are you", &mut rng);
    assert_eq!(recv(&mut b, &e, None, &mut rng).unwrap(), b"how are you");
    assert!(b.pq_authenticated());

    // Ping-pong: PQ epochs keep advancing in both directions.
    for i in 0..10u8 {
        let e = send(&mut a, &[i; 100], &mut rng);
        assert_eq!(recv(&mut b, &e, None, &mut rng).unwrap(), vec![i; 100]);
        let e = send(&mut b, &[i; 200], &mut rng);
        assert_eq!(recv(&mut a, &e, None, &mut rng).unwrap(), vec![i; 200]);
    }
    let (ao, ai) = a.pq_epochs();
    let (bo, bi) = b.pq_epochs();
    assert_eq!((ao, ai), (bi, bo));
    assert!(
        ao >= 10 && ai >= 10,
        "one PQ step per direction per round trip: {ao} {ai}"
    );
}

#[test]
fn out_of_order_loss_replay_and_tamper() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    let (mut a, mut b) = handshake(
        &alice,
        &mut bob,
        0,
        None,
        Mode::OffTheRecord,
        None,
        &mut rng,
    );
    let e = send(&mut b, b"reply", &mut rng);
    recv(&mut a, &e, None, &mut rng).unwrap();

    // Alice sends 6 messages; Bob gets them out of order, one is lost.
    let msgs: Vec<Vec<u8>> = (0..6u8).map(|i| send(&mut a, &[i], &mut rng)).collect();
    for i in [3usize, 0, 5, 1, 4] {
        assert_eq!(
            recv(&mut b, &msgs[i], None, &mut rng).unwrap(),
            vec![i as u8]
        );
    }
    // Replay is rejected.
    assert!(recv(&mut b, &msgs[3], None, &mut rng).is_err());
    // A tampered envelope is rejected and does not disturb state.
    let mut t = msgs[2].clone();
    let last = t.len() - 1;
    t[last] ^= 1;
    assert!(recv(&mut b, &t, None, &mut rng).is_err());
    assert_eq!(recv(&mut b, &msgs[2], None, &mut rng).unwrap(), vec![2]);

    // Conversation continues across a DH ratchet after all that.
    let e = send(&mut b, b"still here", &mut rng);
    assert_eq!(recv(&mut a, &e, None, &mut rng).unwrap(), b"still here");
    let e = send(&mut a, b"good", &mut rng);
    assert_eq!(recv(&mut b, &e, None, &mut rng).unwrap(), b"good");
}

#[test]
fn crossing_messages_and_lost_pq_slots() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    let (mut a, mut b) = handshake(
        &alice,
        &mut bob,
        0,
        None,
        Mode::OffTheRecord,
        None,
        &mut rng,
    );
    let e = send(&mut b, b"r", &mut rng);
    recv(&mut a, &e, None, &mut rng).unwrap();

    for round in 0..8u8 {
        // Both send at once (crossing); some messages are lost.
        let a1 = send(&mut a, &[round, 1], &mut rng);
        let a2 = send(&mut a, &[round, 2], &mut rng);
        let b1 = send(&mut b, &[round, 3], &mut rng);
        let b2 = send(&mut b, &[round, 4], &mut rng);
        if round % 3 != 0 {
            recv(&mut b, &a1, None, &mut rng).unwrap();
        }
        assert_eq!(recv(&mut b, &a2, None, &mut rng).unwrap(), vec![round, 2]);
        if round % 2 == 0 {
            recv(&mut a, &b1, None, &mut rng).unwrap();
        }
        assert_eq!(recv(&mut a, &b2, None, &mut rng).unwrap(), vec![round, 4]);
    }
    let (ao, ai) = a.pq_epochs();
    let (bo, bi) = b.pq_epochs();
    assert!(
        ao > 2 && bo > 2,
        "PQ ratchet advanced despite loss: {ao} {bo}"
    );
    assert!(ao >= bi.saturating_sub(1) && bo >= ai.saturating_sub(1));
}

#[test]
fn mceliece_braid_upgrades_two_kem_session() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    let (mut a, mut b) = handshake(
        &alice,
        &mut bob,
        0,
        None,
        Mode::OffTheRecord,
        None,
        &mut rng,
    );
    assert!(!a.three_kem());
    // Bob replies (announcing his fresh PQ key); the vault key then arrives.
    let e = send(&mut b, b"r", &mut rng);
    recv(&mut a, &e, None, &mut rng).unwrap();
    a.schedule_braid(bob.account.vault_public.clone());
    let e = send(&mut a, b"braided", &mut rng);
    // Without the vault secret Bob cannot process the braid.
    let mut b_copy = b.clone();
    assert!(recv(&mut b_copy, &e, None, &mut rng).is_err());
    assert_eq!(
        recv(&mut b, &e, Some(&bob.account.vault), &mut rng).unwrap(),
        b"braided"
    );
    assert!(b.three_kem());
    let e = send(&mut b, b"ack", &mut rng);
    recv(&mut a, &e, None, &mut rng).unwrap();
    assert!(a.three_kem());
}

#[test]
fn multi_device_wrap_table() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(3, &mut rng);
    let mut a_sessions = Vec::new();
    let mut b_sessions = Vec::new();
    for dev in 0..3 {
        let (a, b) = handshake(
            &alice,
            &mut bob,
            dev,
            None,
            Mode::OffTheRecord,
            None,
            &mut rng,
        );
        a_sessions.push(a);
        b_sessions.push(b);
    }
    // Each Bob device answers first so Alice's sessions are fully established.
    for (i, bs) in b_sessions.iter_mut().enumerate() {
        let e = send(bs, b"hi", &mut rng);
        recv(&mut a_sessions[i], &e, None, &mut rng).unwrap();
    }
    // One envelope reaches all three Bob devices; the PQ slot rotates.
    for round in 0..6usize {
        let carrier = Some(round % 3);
        let mut refs: Vec<&mut Session> = a_sessions.iter_mut().collect();
        let env = seal_direct(
            &mut refs,
            format!("round {round}").as_bytes(),
            carrier,
            &mut rng,
        )
        .unwrap();
        for bs in b_sessions.iter_mut() {
            let got = open_direct(&mut [bs], &env, None, &mut rng).unwrap();
            assert_eq!(got.content, format!("round {round}").as_bytes());
        }
    }
    // A device of another account cannot open it.
    let carol = Party::new(1, &mut rng);
    let (_, mut c) = handshake(
        &alice,
        &mut Party::new(1, &mut rng),
        0,
        None,
        Mode::OffTheRecord,
        None,
        &mut rng,
    );
    let mut refs: Vec<&mut Session> = a_sessions.iter_mut().collect();
    let env = seal_direct(&mut refs, b"private", None, &mut rng).unwrap();
    assert!(matches!(
        open_direct(&mut [&mut c], &env, None, &mut rng),
        Err(ProtoError::NoSession)
    ));
    // A cover envelope has a real one's form and length, and nobody opens
    // it.
    let cover = enclave_proto::envelope::cover_direct(&mut rng).unwrap();
    assert_eq!(cover.len(), env.len());
    assert_eq!(cover[..16], env[..16], "the same header");
    assert!(matches!(
        open_direct(&mut [&mut c], &cover, None, &mut rng),
        Err(ProtoError::NoSession)
    ));
    drop(carol);
}

#[test]
fn on_the_record_and_psk() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    let psk = eqxdh::bond_psk(&[1; 32], &[2; 32], b"qr-a", b"qr-b");
    let psk2 = eqxdh::bond_psk(&[2; 32], &[1; 32], b"qr-b", b"qr-a");
    assert_eq!(*psk, *psk2, "both phones derive the same PSK");
    assert_eq!(
        eqxdh::seal_words(&psk).unwrap(),
        eqxdh::seal_words(&psk2).unwrap()
    );
    let (mut a, mut b) = handshake(
        &alice,
        &mut bob,
        0,
        None,
        Mode::OnTheRecord,
        Some(&psk),
        &mut rng,
    );
    let e = send(&mut b, b"signed hello", &mut rng);
    assert_eq!(recv(&mut a, &e, None, &mut rng).unwrap(), b"signed hello");
}

#[test]
fn psk_mismatch_fails_closed() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    let bundle = bob.bundle(0, None);
    let peer = Peer {
        manifest: &bob.manifest,
        device: &bob.manifest.devices[0],
        bundle: &bundle,
        vault: None,
    };
    let init = eqxdh::initiate(
        &alice.local(0),
        &peer,
        Mode::OffTheRecord,
        Some(&[5; 32]),
        &mut rng,
    )
    .unwrap();
    let mut dir = Directory(vec![alice.manifest.clone()]);
    let local = Local {
        account: &bob.account,
        device: &bob.devices[0],
        manifest: &bob.manifest,
        locator: b"",
    };
    let r = eqxdh::respond(
        &local,
        &mut bob.prekeys[0],
        &init.message,
        Some(&[6; 32]),
        &mut dir,
        &mut rng,
    );
    assert!(r.is_err());
    let r = eqxdh::respond(
        &local,
        &mut bob.prekeys[0],
        &init.message,
        None,
        &mut dir,
        &mut rng,
    );
    assert!(r.is_err());
    let _ = envelope::DIRECT_CAPACITY;
}

#[test]
fn signed_manifest_roundtrip_and_rollback() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let v1 = alice.manifest.sign(&alice.account, &mut rng).unwrap();
    let m = v1.verify(&alice.account.root_public, NOW + 10).unwrap();
    assert_eq!(m, alice.manifest);
    let mut next = alice.manifest.clone();
    next.version = 2;
    next.prev_hash = v1.hash();
    let v2 = next.sign(&alice.account, &mut rng).unwrap();
    v2.verify_successor(&v1, &alice.account.root_public, NOW + 20)
        .unwrap();
    assert_eq!(
        v1.verify_successor(&v2, &alice.account.root_public, NOW + 20),
        Err(ProtoError::Rollback)
    );
    let mut forged = v2.clone();
    forged.body[10] ^= 1;
    assert!(forged.verify(&alice.account.root_public, NOW + 20).is_err());
    assert_eq!(
        v1.verify(&alice.account.root_public, NOW + 500 * 24 * 3600),
        Err(ProtoError::Expired)
    );
}

#[test]
fn persistence_roundtrips_mid_conversation() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    // Two-KEM start with a pending braid, so the export carries the McEliece key.
    let (mut a, mut b) = handshake(
        &alice,
        &mut bob,
        0,
        None,
        Mode::OffTheRecord,
        None,
        &mut rng,
    );
    a.schedule_braid(bob.account.vault_public.clone());
    let e1 = send(&mut a, b"one", &mut rng);
    let e2 = send(&mut a, b"two (arrives late)", &mut rng);
    assert_eq!(
        recv(&mut b, &e1, Some(&bob.account.vault), &mut rng).unwrap(),
        b"one"
    );

    // Save and reload both sides (and Bob's device and prekeys).
    let mut a = Session::import(&a.export()).unwrap();
    let mut b = Session::import(&b.export()).unwrap();
    let dev = DeviceKeys::import(&bob.devices[0].export()).unwrap();
    assert_eq!(dev.id, bob.devices[0].id);
    let pk = PrekeyStore::import(&bob.prekeys[0].export()).unwrap();
    assert_eq!(pk.one_time.len(), bob.prekeys[0].one_time.len());
    assert!(PrekeyStore::import(&[2]).is_err());

    // Skipped keys survived: the late message still opens after reload.
    for i in 0..4 {
        let r = send(&mut b, format!("reply {i}").as_bytes(), &mut rng);
        recv(&mut a, &r, Some(&alice.account.vault), &mut rng).unwrap();
        let m = send(&mut a, b"more", &mut rng);
        recv(&mut b, &m, Some(&bob.account.vault), &mut rng).unwrap();
    }
    assert_eq!(
        recv(&mut b, &e2, Some(&bob.account.vault), &mut rng).unwrap(),
        b"two (arrives late)"
    );
    assert!(
        a.three_kem() && b.three_kem(),
        "braid completed across the reload"
    );

    // Truncated or extended state is rejected.
    let s = a.export();
    assert!(Session::import(&s[..s.len() - 1]).is_err());
    let mut longer = s.to_vec();
    longer.push(0);
    assert!(Session::import(&longer).is_err());

    // Shared account keys: the recovery secret must match the root.
    let shared = alice.account.export_shared();
    let other = RecoverySecret::generate(&mut rng).unwrap();
    assert!(AccountKeys::import_shared(&shared, Some(&other)).is_err());
    let acct = AccountKeys::import_shared(&shared, None).unwrap();
    assert_eq!(acct.root_public, alice.account.root_public);
}

#[test]
fn skipped_keys_expire_after_seven_days() {
    use enclave_proto::ratchet::SKIPPED_MAX_AGE;
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    let vault = bob.account.vault_public.clone();
    let (mut a, mut b) = handshake(
        &alice,
        &mut bob,
        0,
        Some(&vault),
        Mode::OffTheRecord,
        None,
        &mut rng,
    );
    let late1 = send(&mut a, b"late 1", &mut rng);
    let late2 = send(&mut a, b"late 2", &mut rng);
    let now = send(&mut a, b"on time", &mut rng);
    assert_eq!(
        recv(&mut b, &now, Some(&bob.account.vault), &mut rng).unwrap(),
        b"on time"
    );
    assert_eq!(b.skipped_len(), 2);
    assert_eq!(
        b.expire_skipped(NOW, SKIPPED_MAX_AGE),
        0,
        "first call only stamps"
    );
    assert_eq!(
        recv(&mut b, &late1, Some(&bob.account.vault), &mut rng).unwrap(),
        b"late 1"
    );
    assert_eq!(
        b.expire_skipped(NOW + SKIPPED_MAX_AGE - 1, SKIPPED_MAX_AGE),
        0
    );
    // The stamp survives persistence.
    let mut b = Session::import(&b.export()).unwrap();
    assert_eq!(b.expire_skipped(NOW + SKIPPED_MAX_AGE, SKIPPED_MAX_AGE), 1);
    assert!(
        recv(&mut b, &late2, Some(&bob.account.vault), &mut rng).is_err(),
        "expired key is gone"
    );
}

/// A message delivered twice opens once (RT-24), whether it came in order
/// or after later ones; a skipped key says when it was first missed, and
/// is gone once used.
#[test]
fn rt24_replayed_message_rejected() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(1, &mut rng);
    let mut bob = Party::new(1, &mut rng);
    let (mut a, mut b) = handshake(
        &alice,
        &mut bob,
        0,
        None,
        Mode::OffTheRecord,
        None,
        &mut rng,
    );
    let e = send(&mut b, b"reply", &mut rng);
    recv(&mut a, &e, None, &mut rng).unwrap();
    let m0 = send(&mut a, b"zero", &mut rng);
    let m1 = send(&mut a, b"one", &mut rng);
    // In order: once only.
    recv(&mut b, &m0, None, &mut rng).unwrap();
    assert!(
        recv(&mut b, &m0, None, &mut rng).is_err(),
        "replay in order"
    );
    // Out of order: m2 first skips m1's key, stamped by the expiry pass.
    let m2 = send(&mut a, b"two", &mut rng);
    recv(&mut b, &m2, None, &mut rng).unwrap();
    assert_eq!(b.oldest_skipped(), None, "not stamped yet");
    b.expire_skipped(1_000, 7 * 86_400);
    assert_eq!(b.oldest_skipped(), Some(1_000));
    let opened = open_direct(&mut [&mut b], &m1, None, &mut rng).unwrap();
    assert_eq!(opened.content, b"one");
    assert_eq!(opened.skipped_at, Some(1_000), "arrived late");
    assert_eq!(b.oldest_skipped(), None, "nothing missing any more");
    assert!(
        recv(&mut b, &m1, None, &mut rng).is_err(),
        "replay out of order"
    );
}
