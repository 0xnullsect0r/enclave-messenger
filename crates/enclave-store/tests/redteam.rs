//! Red-team check on backups (`docs/redteam-matrix.md` RT-08;
//! `docs/14-storage.md` §4).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_store::{MemoryKeystore, Store, backup};
use std::sync::Arc;

fn store(rng: &mut HedgedRng) -> Store {
    Store::create(None, Arc::new(MemoryKeystore::default()), None, rng).unwrap()
}

/// A backup carries no ratchet sessions, sender keys, shred keys or
/// prekeys, even when asked for them, so restoring an old one can never
/// bring back state that would reuse a key (RT-08). The archive of a
/// store holding 20 KB of such state in every excluded namespace is
/// exactly as long as that of a store without it: none of it went in.
#[test]
fn rt08_backup_contains_no_ratchet_state() {
    let mut rng = HedgedRng::new().unwrap();
    let with_state = store(&mut rng);
    let without = store(&mut rng);
    for s in [&with_state, &without] {
        s.put("contacts", b"ada", b"Ada", &mut rng).unwrap();
        s.put("messages", b"1", b"hello", &mut rng).unwrap();
    }
    let state = vec![0x5au8; 20_000];
    for ns in backup::EXCLUDED {
        with_state.put(ns, b"ada/1", &state, &mut rng).unwrap();
    }
    assert!(backup::EXCLUDED.contains(&"sessions"));
    assert!(backup::EXCLUDED.contains(&"sender-keys"));
    assert!(backup::EXCLUDED.contains(&"prekeys"));

    let key = backup::backup_key(&[42; 32]);
    let hdr = backup::Header {
        sequence: 1,
        created_at: 1_790_000_000,
        media: false,
    };
    let mut asked = vec!["contacts", "messages"];
    asked.extend_from_slice(backup::EXCLUDED);
    let archive = backup::export(&with_state, &asked, &key, &hdr, &mut rng).unwrap();
    let plain = backup::export(&without, &asked, &key, &hdr, &mut rng).unwrap();
    assert_eq!(archive.len(), plain.len(), "nothing excluded went in");
    assert!(archive.len() < state.len());

    // What it holds, and what a restore writes, is the rest only.
    let (_, records) = backup::read(&archive, &key).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|(ns, _, _)| !backup::EXCLUDED.contains(&ns.as_str()))
    );
    let restored = store(&mut rng);
    assert_eq!(
        backup::import(&restored, &archive, &key, &mut rng).unwrap(),
        (Some(hdr), 2)
    );
    for ns in backup::EXCLUDED {
        assert!(restored.scan(ns).unwrap().is_empty(), "{ns} restored");
    }

    // The length check would see it: the same state under a namespace
    // that is backed up makes the archive longer by at least its size.
    with_state.put("messages", b"2", &state, &mut rng).unwrap();
    let bigger = backup::export(&with_state, &asked, &key, &hdr, &mut rng).unwrap();
    assert!(bigger.len() >= archive.len() + state.len());
}
