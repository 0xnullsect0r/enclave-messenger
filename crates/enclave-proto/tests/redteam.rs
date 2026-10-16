//! Red-team checks on session establishment (`docs/redteam-matrix.md`
//! RT-05, RT-07; `docs/04-eqxdh.md` §2, §7, §10; `docs/02-cryptography.md`
//! §5).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::kem::{self, MCELIECE_CT_LEN, McElieceCiphertext, Suite};
use enclave_crypto::rng::HedgedRng;
use enclave_proto::bundle::{
    Bundle, LAST_RESORT_LIFETIME_SECS, PrekeyStore, Publication, SPK_LIFETIME_SECS,
};
use enclave_proto::envelope::{open_request, request_initial, seal_request};
use enclave_proto::eqxdh::{
    self, InitialMessage, InitiatorIdentity, Local, ManifestResolver, Mode, Peer,
};
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::{Manifest, SignedManifest};
use enclave_proto::recovery::RecoverySecret;
use enclave_proto::{ProtoError, Result};

const NOW: u64 = 1_790_000_000;
const DAY: u64 = 86_400;

/// One account with one device and its first prekey publication.
struct Party {
    account: AccountKeys,
    device: DeviceKeys,
    prekeys: PrekeyStore,
    publication: Publication,
    manifest: Manifest,
}

impl Party {
    fn new(rng: &mut HedgedRng) -> Self {
        let account = AccountKeys::create(&RecoverySecret::generate(rng).unwrap(), rng).unwrap();
        let device = DeviceKeys::generate(rng).unwrap();
        let manifest = Manifest::genesis(&account, &device, NOW, b"server/inbox".to_vec());
        let mut prekeys = PrekeyStore::default();
        let publication = prekeys
            .publish(&device, manifest.bundle_epoch, NOW, rng)
            .unwrap();
        Self {
            account,
            device,
            prekeys,
            publication,
            manifest,
        }
    }

    /// The bundle a directory serves: with one-time prekey `opk`, if any.
    fn bundle(&self, opk: Option<usize>) -> Bundle {
        let p = &self.publication;
        Bundle {
            spk: p.spk.clone(),
            opk: opk.map(|i| (p.batch.clone(), p.opks[i].clone())),
            last_resort: p.last_resort.clone(),
        }
    }

    fn local(&self) -> Local<'_> {
        Local {
            account: &self.account,
            device: &self.device,
            manifest: &self.manifest,
            locator: b"server/manifest",
        }
    }

    fn signer(&self) -> &enclave_crypto::sig::CompositePublic {
        self.device.signing.public()
    }
}

struct Directory(Manifest);

impl ManifestResolver for Directory {
    fn resolve(&mut self, id: &InitiatorIdentity) -> Result<Manifest> {
        (self.0.root.0 == id.root)
            .then(|| self.0.clone())
            .ok_or(ProtoError::Missing)
    }
}

/// Alice's initial message to Bob (one-time prekey `opk`), with or without
/// Bob's vault key (3 or 2 KEMs) and a PSK.
fn initial(
    alice: &Party,
    bob: &Party,
    opk: Option<usize>,
    three_kem: bool,
    psk: Option<&[u8; 32]>,
    rng: &mut HedgedRng,
) -> InitialMessage {
    let bundle = bob.bundle(opk);
    bundle
        .verify(bob.signer(), bob.manifest.bundle_epoch, NOW)
        .unwrap();
    let peer = Peer {
        manifest: &bob.manifest,
        device: &bob.manifest.devices[0],
        bundle: &bundle,
        vault: three_kem.then_some(&bob.account.vault_public),
    };
    let init = eqxdh::initiate(&alice.local(), &peer, Mode::OffTheRecord, psk, rng).unwrap();
    assert_eq!(init.message.suite == Suite::ThreeKem, three_kem);
    init.message
}

/// Bob processes `msg`: `Ok(())` if a session results.
fn respond(
    alice: &Party,
    bob: &mut Party,
    msg: &InitialMessage,
    psk: Option<&[u8; 32]>,
    rng: &mut HedgedRng,
) -> Result<()> {
    let local = Local {
        account: &bob.account,
        device: &bob.device,
        manifest: &bob.manifest,
        locator: b"",
    };
    let mut dir = Directory(alice.manifest.clone());
    eqxdh::respond(&local, &mut bob.prekeys, msg, psk, &mut dir, rng).map(|_| ())
}

/// What crossed the network: the message as encoded, after changes.
fn reencoded(msg: &InitialMessage) -> InitialMessage {
    InitialMessage::decode(&msg.encode()).unwrap()
}

/// Prekeys are signed for the bundle epoch the device's manifest commits
/// to, and only verify for it (RT-05): once the account moves its epoch
/// on, a directory replaying a bundle from before is caught, part by
/// part, and the manifest's epoch can't be changed without its root
/// signature.
#[test]
fn rt05_bundle_epoch_mismatch_rejected() {
    let mut rng = HedgedRng::new().unwrap();
    let mut bob = Party::new(&mut rng);
    let epoch = bob.manifest.bundle_epoch;
    let old = bob.bundle(Some(3));
    old.verify(bob.signer(), epoch, NOW).unwrap();
    bob.publication.verify(bob.signer(), epoch, NOW).unwrap();

    // The account moves to the next epoch and republishes.
    let mut next = bob.manifest.clone();
    next.version += 1;
    next.bundle_epoch = epoch + 1;
    let fresh = bob
        .prekeys
        .publish(&bob.device, next.bundle_epoch, NOW + 60, &mut rng)
        .unwrap();
    let new = Bundle {
        spk: fresh.spk.clone(),
        opk: Some((fresh.batch.clone(), fresh.opks[0].clone())),
        last_resort: fresh.last_resort.clone(),
    };
    new.verify(bob.signer(), next.bundle_epoch, NOW + 60)
        .unwrap();

    // The old bundle and publication no longer verify, and the new ones
    // don't verify against the old manifest.
    for (b, e) in [(&old, next.bundle_epoch), (&new, epoch)] {
        assert_eq!(
            b.verify(bob.signer(), e, NOW + 60),
            Err(ProtoError::BadSignature)
        );
    }
    assert_eq!(
        bob.publication
            .verify(bob.signer(), next.bundle_epoch, NOW + 60),
        Err(ProtoError::BadSignature)
    );
    // Every part is bound: one stale part in a fresh bundle is caught.
    let stale_spk = Bundle {
        spk: old.spk.clone(),
        ..new.clone()
    };
    let stale_lr = Bundle {
        last_resort: old.last_resort.clone(),
        ..new.clone()
    };
    let stale_opk = Bundle {
        opk: old.opk.clone(),
        ..new.clone()
    };
    for b in [&stale_spk, &stale_lr, &stale_opk] {
        assert_eq!(
            b.verify(bob.signer(), next.bundle_epoch, NOW + 60),
            Err(ProtoError::BadSignature)
        );
    }

    // The epoch is part of what the root signs: a manifest signed at one
    // epoch, with its epoch changed, doesn't verify.
    let signed = next.sign(&bob.account, &mut rng).unwrap();
    assert_eq!(
        signed
            .verify(&bob.account.root_public, NOW + 60)
            .unwrap()
            .bundle_epoch,
        epoch + 1
    );
    let mut rolled = next.clone();
    rolled.bundle_epoch = epoch;
    let forged = SignedManifest {
        body: rolled.encode().unwrap(),
        signature: signed.signature.clone(),
    };
    assert!(forged.verify(&bob.account.root_public, NOW + 60).is_err());
}

/// A signed prekey is good for 14 days and no longer (RT-05): a bundle
/// whose signed prekey has expired is refused even when its other parts
/// are fresh, its expiry can't be pushed back without breaking the
/// signature, and the responder no longer answers to it once it is pruned.
#[test]
fn rt05_expired_spk_rejected() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(&mut rng);
    let mut bob = Party::new(&mut rng);
    let epoch = bob.manifest.bundle_epoch;
    let spk = bob.publication.spk.clone();
    assert_eq!(spk.expires_at, NOW + SPK_LIFETIME_SECS);

    // A later publication's last-resort key, so only the signed prekey is
    // stale.
    let later = bob
        .prekeys
        .publish(&bob.device, epoch, NOW + 10 * DAY, &mut rng)
        .unwrap();
    assert!(later.last_resort.expires_at > spk.expires_at);
    let bundle = Bundle {
        spk: spk.clone(),
        opk: None,
        last_resort: later.last_resort.clone(),
    };
    bundle.verify(bob.signer(), epoch, spk.expires_at).unwrap();
    assert_eq!(
        bundle.verify(bob.signer(), epoch, spk.expires_at + 1),
        Err(ProtoError::Expired)
    );
    let mut extended = bundle.clone();
    extended.spk.expires_at += 7 * DAY;
    assert_eq!(
        extended.verify(bob.signer(), epoch, spk.expires_at + 1),
        Err(ProtoError::BadSignature)
    );
    // The last-resort key expires the same way (after 7 days).
    let lr = &bob.publication.last_resort;
    assert_eq!(lr.expires_at, NOW + LAST_RESORT_LIFETIME_SECS);
    assert_eq!(
        lr.verify(bob.signer(), epoch, lr.expires_at + 1),
        Err(ProtoError::Expired)
    );

    // An initial message made while the signed prekey was valid, held back
    // past its expiry and the responder's grace period, is refused.
    let msg = initial(&alice, &bob, Some(0), false, None, &mut rng);
    assert_eq!(msg.spk_id, spk.id);
    let grace = 7 * DAY;
    bob.prekeys.prune(spk.expires_at + grace + 1, grace);
    assert!(!bob.prekeys.signed.contains_key(&spk.id));
    assert!(matches!(
        respond(&alice, &mut bob, &msg, None, &mut rng),
        Err(ProtoError::Missing)
    ));
}

/// Stripping the McEliece part from a 3-KEM initial message (relabeling it
/// 2-KEM, dropping or zeroing the ciphertext) gets nowhere (RT-07): the
/// combiner gives a different secret without it, so the responder can't
/// open the message and makes no session; the untouched message works.
#[test]
fn rt07_stripped_mceliece_rejected() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(&mut rng);
    let mut bob = Party::new(&mut rng);

    // The combiner: the same X448 and ML-KEM secrets with and without the
    // McEliece one never agree, in either suite.
    let (x, m, mce) = ([1u8; 56], [2u8; 32], [3u8; 32]);
    let full = kem::combine(Suite::ThreeKem, &[&x, &m, &mce], &[b"pk"], None);
    for suite in [Suite::TwoKem, Suite::ThreeKem] {
        let stripped = kem::combine(suite, &[&x, &m, b""], &[b"pk"], None);
        assert_ne!(full[..], stripped[..]);
    }

    let msg = initial(&alice, &bob, Some(0), true, None, &mut rng);
    let mut relabeled = msg.clone();
    relabeled.suite = Suite::TwoKem;
    relabeled.ct_mce = None;
    let mut zeroed = msg.clone();
    zeroed.ct_mce = Some(McElieceCiphertext([0; MCELIECE_CT_LEN]));
    for forged in [reencoded(&relabeled), reencoded(&zeroed)] {
        assert!(matches!(
            respond(&alice, &mut bob, &forged, None, &mut rng),
            Err(ProtoError::Crypto)
        ));
    }
    respond(&alice, &mut bob, &msg, None, &mut rng).unwrap();
}

/// The 2-KEM and 3-KEM suites have their own combiner labels and keys, so
/// the same inputs give unrelated secrets, and a message relabeled from
/// one suite to the other doesn't open (RT-07).
#[test]
fn rt07_kem2_kem3_label_confusion_rejected() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(&mut rng);
    let mut bob = Party::new(&mut rng);

    let secrets: [&[u8]; 3] = [&[1u8; 56], &[2u8; 32], b""];
    let public: [&[u8]; 2] = [b"ek", b"ct"];
    for psk in [None, Some(&[9u8; 32])] {
        let two = kem::combine(Suite::TwoKem, &secrets, &public, psk);
        let three = kem::combine(Suite::ThreeKem, &secrets, &public, psk);
        assert_ne!(two[..], three[..]);
        assert_ne!(two[..32], three[..32], "no shared half either");
    }

    // A 2-KEM message claimed as 3-KEM, with an all-zero McEliece
    // ciphertext (as the 2-KEM encoding carries) or a real one taken from
    // another 3-KEM message.
    let two = initial(&alice, &bob, Some(0), false, None, &mut rng);
    let three = initial(&alice, &bob, Some(1), true, None, &mut rng);
    let mut zero_ct = two.clone();
    zero_ct.suite = Suite::ThreeKem;
    zero_ct.ct_mce = Some(McElieceCiphertext([0; MCELIECE_CT_LEN]));
    let mut borrowed_ct = two.clone();
    borrowed_ct.suite = Suite::ThreeKem;
    borrowed_ct.ct_mce = three.ct_mce;
    for forged in [reencoded(&zero_ct), reencoded(&borrowed_ct)] {
        assert!(matches!(
            respond(&alice, &mut bob, &forged, None, &mut rng),
            Err(ProtoError::Crypto)
        ));
    }
    respond(&alice, &mut bob, &two, None, &mut rng).unwrap();
    respond(&alice, &mut bob, &three, None, &mut rng).unwrap();
}

/// The PSK flag can't be flipped to talk a responder out of the PSK (or
/// into one): it is bound into the combiner, where an all-zero PSK and no
/// PSK differ, and a flipped flag fails at the responder whether it tries
/// the PSK or not (RT-07).
#[test]
fn rt07_psk_flag_downgrade_rejected() {
    let mut rng = HedgedRng::new().unwrap();
    let alice = Party::new(&mut rng);
    let mut bob = Party::new(&mut rng);

    let secrets: [&[u8]; 2] = [&[1u8; 56], &[2u8; 32]];
    let none = kem::combine(Suite::TwoKem, &secrets, &[b"t"], None);
    let zero = kem::combine(Suite::TwoKem, &secrets, &[b"t"], Some(&[0; 32]));
    assert_ne!(none[..], zero[..], "no PSK is not an all-zero PSK");

    let psk = *eqxdh::bond_psk(&[1; 32], &[2; 32], b"qr-a", b"qr-b");
    let with = initial(&alice, &bob, Some(0), false, Some(&psk), &mut rng);
    assert!(with.psk);
    let mut cleared = with.clone();
    cleared.psk = false;
    let cleared = reencoded(&cleared);
    for try_psk in [None, Some(&psk)] {
        assert!(respond(&alice, &mut bob, &cleared, try_psk, &mut rng).is_err());
    }

    // The other way: a plain message claiming a PSK.
    let without = initial(&alice, &bob, Some(1), false, None, &mut rng);
    let mut set = without.clone();
    set.psk = true;
    let set = reencoded(&set);
    for try_psk in [None, Some(&psk), Some(&[0; 32])] {
        assert!(respond(&alice, &mut bob, &set, try_psk, &mut rng).is_err());
    }

    // Untouched, both open, and a session works.
    respond(&alice, &mut bob, &with, Some(&psk), &mut rng).unwrap();
    respond(&alice, &mut bob, &without, None, &mut rng).unwrap();
    let local = Local {
        account: &bob.account,
        device: &bob.device,
        manifest: &bob.manifest,
        locator: b"",
    };
    let bundle = bob.bundle(Some(2));
    let peer = Peer {
        manifest: &bob.manifest,
        device: &bob.manifest.devices[0],
        bundle: &bundle,
        vault: None,
    };
    let init = eqxdh::initiate(
        &alice.local(),
        &peer,
        Mode::OffTheRecord,
        Some(&psk),
        &mut rng,
    )
    .unwrap();
    let mut a = init.session;
    let env = seal_request(&init.message, &mut a, b"hi", &mut rng).unwrap();
    let msg = request_initial(&env).unwrap();
    let mut dir = Directory(alice.manifest.clone());
    let resp = eqxdh::respond(
        &local,
        &mut bob.prekeys,
        &msg,
        Some(&psk),
        &mut dir,
        &mut rng,
    )
    .unwrap();
    let mut b = resp.session;
    assert_eq!(open_request(&mut b, &env, &mut rng).unwrap(), b"hi");
}
