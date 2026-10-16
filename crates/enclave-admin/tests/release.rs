//! The release ceremony through the command line (19-ops §1, ADR 0005):
//! three maintainers and the online key make and sign a root, two
//! maintainers sign a release, the online key adds snapshot and
//! timestamp, and `verify` accepts it as a client would; with one
//! maintainer's signature it refuses.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

fn admin(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_enclave-admin"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn ok(dir: &Path, args: &[&str]) {
    let o = admin(dir, args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn release_ceremony() {
    let tmp = std::env::temp_dir().join(format!("enclave-release-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("out")).unwrap();
    std::fs::create_dir_all(tmp.join("files")).unwrap();
    let d = tmp.as_path();
    for k in ["m1", "m2", "m3", "online"] {
        ok(
            d,
            &[
                "release",
                "keygen",
                &format!("{k}.key"),
                &format!("{k}.pub"),
            ],
        );
    }
    let w = "11".repeat(32);
    std::fs::write(
        d.join("root.toml"),
        format!(
            "version = 1\nvalid_days = 365\nkeys = [\"m1.pub\", \"m2.pub\", \"m3.pub\", \"online.pub\"]\n\
             root = [0, 1, 2]\nroot_threshold = 2\ntargets = [0, 1, 2]\ntargets_threshold = 2\nonline = [3]\n\
             [sigsum]\nlog = \"{w}\"\nsubmitters = [\"{w}\"]\nwitnesses = [\"{w}\", \"{w}\"]\nquorum = 2\n"
        ),
    )
    .unwrap();
    ok(
        d,
        &["release", "root", "root.toml", "--out", "root.unsigned"],
    );
    ok(
        d,
        &[
            "release",
            "sign",
            "root.unsigned",
            "--key",
            "m1.key",
            "--index",
            "0",
            "--out",
            "root.1",
        ],
    );
    ok(
        d,
        &[
            "release", "sign", "root.1", "--key", "m3.key", "--index", "2", "--out", "root.bin",
        ],
    );
    std::fs::write(d.join("files/Enclave-1.0.0.tar.gz"), b"the release").unwrap();
    std::fs::write(d.join("files/SHA256SUMS"), b"sums").unwrap();
    ok(
        d,
        &[
            "release",
            "targets",
            "files",
            "--tag",
            "v1.0.0",
            "--version",
            "1",
            "--out",
            "targets.unsigned",
        ],
    );
    // One maintainer: refused.
    ok(
        d,
        &[
            "release",
            "sign",
            "targets.unsigned",
            "--key",
            "m2.key",
            "--index",
            "1",
            "--out",
            "out/targets.bin",
        ],
    );
    ok(
        d,
        &[
            "release",
            "online",
            "out/targets.bin",
            "--key",
            "online.key",
            "--index",
            "3",
            "--out-dir",
            "out",
        ],
    );
    let o = admin(
        d,
        &["release", "verify", "--root", "root.bin", "--dir", "out"],
    );
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("needs 2"));
    // Two maintainers: accepted.
    ok(
        d,
        &[
            "release",
            "sign",
            "out/targets.bin",
            "--key",
            "m1.key",
            "--index",
            "0",
            "--out",
            "out/targets.bin",
        ],
    );
    std::fs::remove_file(d.join("out/snapshot.bin")).unwrap();
    std::fs::remove_file(d.join("out/timestamp.bin")).unwrap();
    ok(
        d,
        &[
            "release",
            "online",
            "out/targets.bin",
            "--key",
            "online.key",
            "--index",
            "3",
            "--out-dir",
            "out",
        ],
    );
    let o = admin(
        d,
        &["release", "verify", "--root", "root.bin", "--dir", "out"],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("release v1.0.0 (targets version 1): 2 files")
    );
    // The bundle servers relay: the documents and each file's proof.
    std::fs::write(d.join("out/Enclave-1.0.0.tar.gz.sigsum"), b"version=2\n").unwrap();
    ok(
        d,
        &["release", "bundle", "--dir", "out", "--out", "update.bin"],
    );
    let b = enclave_update::Bundle::decode(&std::fs::read(d.join("update.bin")).unwrap()).unwrap();
    assert!(b.roots.is_empty());
    assert_eq!(b.proof("Enclave-1.0.0.tar.gz"), Some("version=2\n"));
    let mut c =
        enclave_update::Client::new(&std::fs::read(d.join("root.bin")).unwrap(), [0; 3]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(b.apply(&mut c, now).unwrap().release, "v1.0.0");
    // A bundle missing a file's proof is refused by `verify --bundle`.
    let o = admin(
        d,
        &[
            "release",
            "verify",
            "--root",
            "root.bin",
            "--bundle",
            "update.bin",
        ],
    );
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("no Sigsum proof for SHA256SUMS"));
    // A root signed by one maintainer isn't one.
    let o = admin(
        d,
        &["release", "verify", "--root", "root.1", "--dir", "out"],
    );
    assert!(!o.status.success());
    let _ = std::fs::remove_dir_all(&tmp);
}
