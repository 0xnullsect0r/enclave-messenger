//! Storage tests: sealing, passphrases, crypto-shredding, backups, erase.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_store::backup;
use enclave_store::shred::Shredder;
use enclave_store::{FileKeystore, Keystore, MemoryKeystore, Store, StoreError};
use std::sync::Arc;

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("enclave-store-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn records_are_sealed_and_blinded_on_disk() {
    let mut rng = HedgedRng::new().unwrap();
    let dir = tmpdir("sealed");
    let db = dir.join("profile.redb");
    let ks: Arc<dyn Keystore> = Arc::new(FileKeystore::new(dir.join("keys")).unwrap());
    {
        let s = Store::create(Some(&db), Arc::clone(&ks), None, &mut rng).unwrap();
        s.put(
            "contacts",
            b"alice@example",
            b"Alice Liddell, verified in person",
            &mut rng,
        )
        .unwrap();
        s.put("contacts", b"bob@example", b"Bob", &mut rng).unwrap();
        s.put("messages", b"m1", &vec![7u8; 200_000], &mut rng)
            .unwrap();
        assert_eq!(
            s.get("contacts", b"alice@example").unwrap().unwrap(),
            b"Alice Liddell, verified in person"
        );
        let mut scan = s.scan("contacts").unwrap();
        scan.sort();
        assert_eq!(scan.len(), 2);
        assert_eq!(scan[0].0, b"alice@example");
    }
    // Nothing readable on disk.
    let raw = std::fs::read(&db).unwrap();
    for needle in [&b"Alice Liddell"[..], b"alice@example", b"contacts"] {
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "plaintext leaked: {:?}",
            std::str::from_utf8(needle)
        );
    }
    // Reopen.
    let s = Store::open(&db, Arc::clone(&ks), None).unwrap();
    assert_eq!(
        s.get("messages", b"m1").unwrap().unwrap(),
        vec![7u8; 200_000]
    );
    s.delete("contacts", b"bob@example").unwrap();
    assert!(s.get("contacts", b"bob@example").unwrap().is_none());
}

#[test]
fn passphrase_required_and_checked() {
    let mut rng = HedgedRng::new().unwrap();
    let dir = tmpdir("pw");
    let db = dir.join("p.redb");
    let ks: Arc<dyn Keystore> = Arc::new(FileKeystore::new(dir.join("keys")).unwrap());
    {
        let s = Store::create(
            Some(&db),
            Arc::clone(&ks),
            Some((b"correct horse", PwParams::FLOOR)),
            &mut rng,
        )
        .unwrap();
        s.put("x", b"k", b"v", &mut rng).unwrap();
    }
    assert!(matches!(
        Store::open(&db, Arc::clone(&ks), Some(b"wrong")),
        Err(StoreError::Crypto)
    ));
    assert!(matches!(
        Store::open(&db, Arc::clone(&ks), None),
        Err(StoreError::Crypto)
    ));
    let s = Store::open(&db, Arc::clone(&ks), Some(b"correct horse")).unwrap();
    assert_eq!(s.get("x", b"k").unwrap().unwrap(), b"v");
    // Crypto-erase: the device secret is gone, the file is noise.
    s.crypto_erase().unwrap();
    assert!(Store::open(&db, ks, Some(b"correct horse")).is_err());
}

#[test]
fn shredding_makes_old_messages_unrecoverable() {
    let mut rng = HedgedRng::new().unwrap();
    let ks: Arc<dyn Keystore> = Arc::new(MemoryKeystore::default());
    let s = Store::create(None, Arc::clone(&ks), None, &mut rng).unwrap();
    let (c1, c2);
    {
        let mut sh = Shredder::open(&s, &mut rng).unwrap();
        c1 = sh.seal(b"conv-a", 100, b"day 100", &mut rng).unwrap();
        c2 = sh.seal(b"conv-a", 101, b"day 101", &mut rng).unwrap();
        assert_eq!(sh.open_msg(b"conv-a", 100, &c1).unwrap(), b"day 100");
        assert_eq!(sh.shred(b"conv-a", 101, &mut rng).unwrap(), 1);
        assert!(sh.open_msg(b"conv-a", 100, &c1).is_err());
        assert_eq!(sh.open_msg(b"conv-a", 101, &c2).unwrap(), b"day 101");
    }
    // After reopening, the shredded key is still gone and the other survives.
    let sh = Shredder::open(&s, &mut rng).unwrap();
    assert!(sh.open_msg(b"conv-a", 100, &c1).is_err());
    assert_eq!(sh.open_msg(b"conv-a", 101, &c2).unwrap(), b"day 101");
    // Old wrap generations were destroyed in the keystore.
    assert!(ks.load("enclave-shred-1").is_err());
}

#[test]
fn backups_exclude_sessions_and_need_the_recovery_secret() {
    let mut rng = HedgedRng::new().unwrap();
    let a = Store::create(None, Arc::new(MemoryKeystore::default()), None, &mut rng).unwrap();
    a.put("contacts", b"alice", b"A", &mut rng).unwrap();
    a.put("messages", b"1", b"hello", &mut rng).unwrap();
    a.put("sessions", b"alice/1", b"ratchet state", &mut rng)
        .unwrap();
    let recovery = [42u8; 32];
    let key = backup::backup_key(&recovery);
    let hdr = backup::Header {
        sequence: 7,
        created_at: 1_700_000_000,
        media: false,
    };
    let archive = backup::export(
        &a,
        &["contacts", "messages", "sessions"],
        &key,
        &hdr,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        backup::header(&archive),
        Some(hdr),
        "readable without the key"
    );

    let b = Store::create(None, Arc::new(MemoryKeystore::default()), None, &mut rng).unwrap();
    let wrong = backup::backup_key(&[41u8; 32]);
    assert!(backup::import(&b, &archive, &wrong, &mut rng).is_err());
    assert_eq!(
        backup::import(&b, &archive, &key, &mut rng).unwrap(),
        (Some(hdr), 2)
    );
    assert_eq!(b.get("messages", b"1").unwrap().unwrap(), b"hello");
    assert!(
        b.get("sessions", b"alice/1").unwrap().is_none(),
        "ratchet state never restored"
    );
    // The header is bound: changing it breaks the archive.
    let mut forged = archive.clone();
    forged[15] ^= 1;
    assert!(backup::read(&forged, &key).is_err());
    // Truncated archive is rejected.
    assert!(backup::import(&b, &archive[..archive.len() - 1], &key, &mut rng).is_err());
}

#[test]
fn passphrase_can_be_set_changed_and_removed() {
    let dir = tmpdir("change-passphrase");
    let path = dir.join("p.redb");
    let ks: Arc<dyn Keystore> = Arc::new(FileKeystore::new(dir.join("keys")).unwrap());
    let mut rng = HedgedRng::new().unwrap();
    {
        // Created without one, then given one.
        let mut s = Store::create(Some(&path), Arc::clone(&ks), None, &mut rng).unwrap();
        s.put("n", b"k", b"kept across changes", &mut rng).unwrap();
        s.change_passphrase(Some((b"first", PwParams::FLOOR)), &mut rng)
            .unwrap();
    }
    assert!(Store::open(&path, Arc::clone(&ks), None).is_err());
    assert!(Store::open(&path, Arc::clone(&ks), Some(b"wrong")).is_err());
    {
        let mut s = Store::open(&path, Arc::clone(&ks), Some(b"first")).unwrap();
        assert_eq!(s.get("n", b"k").unwrap().unwrap(), b"kept across changes");
        s.change_passphrase(Some((b"second", PwParams::FLOOR)), &mut rng)
            .unwrap();
    }
    assert!(Store::open(&path, Arc::clone(&ks), Some(b"first")).is_err());
    {
        let mut s = Store::open(&path, Arc::clone(&ks), Some(b"second")).unwrap();
        assert_eq!(s.get("n", b"k").unwrap().unwrap(), b"kept across changes");
        s.put("n", b"k2", b"written after", &mut rng).unwrap();
        s.change_passphrase(None, &mut rng).unwrap();
    }
    assert!(Store::open(&path, Arc::clone(&ks), Some(b"second")).is_err());
    let s = Store::open(&path, Arc::clone(&ks), None).unwrap();
    assert_eq!(s.get("n", b"k2").unwrap().unwrap(), b"written after");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The hedge secret (`02-cryptography.md` §6.1) lives in the keystore, is
/// refreshed each time it is taken, and goes with a crypto-erase.
#[test]
fn hedge_secret_is_kept_refreshed_and_erased() {
    use enclave_store::keystore::HEDGE_SECRET;
    let ks: Arc<dyn Keystore> = Arc::new(MemoryKeystore::default());
    assert!(ks.load(HEDGE_SECRET).is_err());
    let mut a = enclave_store::device_rng(ks.as_ref()).unwrap();
    let first = ks.load(HEDGE_SECRET).unwrap();
    let _b = enclave_store::device_rng(ks.as_ref()).unwrap();
    let second = ks.load(HEDGE_SECRET).unwrap();
    assert_ne!(*first, *second, "refreshed");
    let _: [u8; 32] = a.array("test").unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let store = Store::create(None, Arc::clone(&ks), None, &mut rng).unwrap();
    store.crypto_erase().unwrap();
    assert!(ks.load(HEDGE_SECRET).is_err(), "erased");
}
