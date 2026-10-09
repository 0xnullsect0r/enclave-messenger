//! The wrapped root (`docs/14-storage.md` §1.3) on a profile on disk: the
//! PIN survives a restart and a change of words, and a copy of the database
//! without the device's root secret can't unwrap the root even with the
//! PIN.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, CoreError, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_sim::LocalTransport;
use enclave_store::{FileKeystore, Keystore};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];

fn network() -> LocalTransport {
    let t = LocalTransport::new();
    t.add_server(enclave_server::Config {
        id: S1,
        effort_request: 4,
        effort_claim: 1,
        effort_username: 1,
        effort_inbox: 1,
        ..Default::default()
    })
    .unwrap();
    t
}

fn on_disk(dir: &Path, keys: Arc<dyn Keystore>) -> Options {
    Options {
        path: Some(dir.join("profile.redb")),
        keystore: keys,
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("enclave-root-wrap-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn the_root_stays_wrapped_on_disk() {
    let net = network();
    let dir = tmp("a");
    let keys: Arc<dyn Keystore> = Arc::new(FileKeystore::new(dir.join("keys")).unwrap());
    let (mut ada, words) = Client::create(
        on_disk(&dir, Arc::clone(&keys)),
        Arc::new(net.clone()),
        S1,
        "Ada",
    )
    .await
    .unwrap();
    ada.set_root_pin("314159", PwParams::FLOOR).unwrap();
    drop(ada);

    // Restarted: the root is behind the PIN.
    let mut ada = Client::open(on_disk(&dir, Arc::clone(&keys)), Arc::new(net.clone())).unwrap();
    assert!(ada.holds_recovery_words() && ada.has_root_pin());
    assert!(matches!(ada.recovery_words(), Err(CoreError::PinRequired)));
    assert!(matches!(
        ada.change_recovery_words().await,
        Err(CoreError::PinRequired)
    ));
    assert!(matches!(
        ada.unlock_root("000000"),
        Err(CoreError::PinWrong)
    ));
    ada.unlock_root("314159").unwrap();
    assert_eq!(ada.recovery_words().unwrap(), words);

    // New words are wrapped under the same PIN.
    let new_words = ada.change_recovery_words().await.unwrap();
    assert_ne!(new_words, words);
    drop(ada);
    let mut ada = Client::open(on_disk(&dir, Arc::clone(&keys)), Arc::new(net.clone())).unwrap();
    assert!(matches!(ada.recovery_words(), Err(CoreError::PinRequired)));
    ada.unlock_root("314159").unwrap();
    assert_eq!(ada.recovery_words().unwrap(), new_words);
    drop(ada);

    // The database and the device secret copied elsewhere, but not the
    // root secret (it stays in the device's keystore): the PIN alone
    // doesn't unwrap the root.
    let copy = tmp("b");
    std::fs::copy(dir.join("profile.redb"), copy.join("profile.redb")).unwrap();
    std::fs::create_dir_all(copy.join("keys")).unwrap();
    for f in std::fs::read_dir(dir.join("keys")).unwrap() {
        let f = f.unwrap();
        if !f.file_name().to_string_lossy().contains("root_secret") {
            std::fs::copy(f.path(), copy.join("keys").join(f.file_name())).unwrap();
        }
    }
    let keys2: Arc<dyn Keystore> = Arc::new(FileKeystore::new(copy.join("keys")).unwrap());
    let mut thief = Client::open(on_disk(&copy, keys2), Arc::new(net.clone())).unwrap();
    assert!(thief.holds_recovery_words());
    assert!(thief.unlock_root("314159").is_err());
    assert!(thief.recovery_words().is_err());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&copy);
}

/// A profile from before the wrap (schema 0, the recovery secret only
/// under the store's sealing) is migrated when it opens, a snapshot first;
/// a migration that fails puts the snapshot back.
#[tokio::test(flavor = "multi_thread")]
async fn old_profiles_migrate_with_a_snapshot_first() {
    use enclave_proto::recovery::RecoverySecret;
    use enclave_store::Store;
    let net = network();
    let dir = tmp("m");
    let keys: Arc<dyn Keystore> = Arc::new(FileKeystore::new(dir.join("keys")).unwrap());
    let (ada, words) = Client::create(
        on_disk(&dir, Arc::clone(&keys)),
        Arc::new(net.clone()),
        S1,
        "Ada",
    )
    .await
    .unwrap();
    drop(ada);
    let db = dir.join("profile.redb");
    let rs = RecoverySecret::from_words(&words.join(" ")).unwrap();
    let make_old = |recovery: &[u8]| {
        let store = Store::open(&db, Arc::clone(&keys), None).unwrap();
        let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
        store.delete("secrets", b"root-wrap").unwrap();
        store
            .put("secrets", b"recovery", recovery, &mut rng)
            .unwrap();
        store.set_schema(0).unwrap();
    };

    // A recovery record that can't be right: the migration fails, and
    // the profile is as it was, schema and all.
    make_old(&rs.as_bytes()[..31]);
    assert!(Client::open(on_disk(&dir, Arc::clone(&keys)), Arc::new(net.clone())).is_err());
    assert!(!dir.join("profile.redb.pre-migration").exists(), "put back");
    {
        let store = Store::open(&db, Arc::clone(&keys), None).unwrap();
        assert_eq!(store.schema().unwrap(), 0);
        assert_eq!(
            store.get("secrets", b"recovery").unwrap().unwrap().len(),
            31
        );
    }

    // The real one: wrapped, the old record gone, schema 2.
    make_old(rs.as_bytes());
    let ada = Client::open(on_disk(&dir, Arc::clone(&keys)), Arc::new(net.clone())).unwrap();
    assert!(
        !dir.join("profile.redb.pre-migration").exists(),
        "done with"
    );
    assert!(ada.holds_recovery_words());
    assert_eq!(ada.recovery_words().unwrap(), words);
    drop(ada);
    let store = Store::open(&db, Arc::clone(&keys), None).unwrap();
    assert_eq!(store.schema().unwrap(), 2);
    assert!(store.get("secrets", b"recovery").unwrap().is_none());
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
