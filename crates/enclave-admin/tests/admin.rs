//! The foundation's workflow end to end with the real binary: a key, a list
//! built from operators' signed descriptors, verification, pins.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::{
    FoundationPublic, KtKeys, Policy, ServerDescriptor, ServerList, WitnessDescriptor, server_id,
};
use enclave_rpc::ServerSecret;
use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_enclave-admin");
const NOW: u64 = 1_790_000_000;

fn admin(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(BIN)
        .args(args)
        .args(["--now", &NOW.to_string()])
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into(),
        String::from_utf8_lossy(&o.stderr).into(),
    )
}

fn server_descriptor(domain: &str, rng: &mut HedgedRng) -> (ServerDescriptor, [u8; 16]) {
    onion_server_descriptor(domain, "", rng)
}

fn onion_server_descriptor(
    domain: &str,
    onion: &str,
    rng: &mut HedgedRng,
) -> (ServerDescriptor, [u8; 16]) {
    let identity = CompositeSigningKey::generate(rng).unwrap();
    let head = CompositeSigningKey::generate(rng).unwrap();
    let day = (NOW / 86_400) as u32;
    let keys = [
        ServerSecret::from_seed(day, &[1; 32]).public().clone(),
        ServerSecret::from_seed(day + 1, &[2; 32]).public().clone(),
    ];
    let d = ServerDescriptor::sign(
        &identity,
        domain,
        &format!("op-{domain}"),
        &format!("fam-{domain}"),
        "",
        onion,
        Policy::default(),
        Some(KtKeys {
            head_key: head.public().clone(),
            vrf_public: vec![9; 32],
        }),
        &keys,
        &[],
        NOW - 10,
        NOW + 86_400,
        rng,
    )
    .unwrap();
    (d, server_id(identity.public()))
}

fn write(dir: &Path, name: &str, b: &[u8]) {
    std::fs::write(dir.join(name), b).unwrap();
}

/// RFC 0010: the list carries each server's onion address from its
/// descriptor, and a push relay may be listed by its onion address alone.
#[test]
fn build_copies_onion_and_push_onion() {
    let dir = std::env::temp_dir().join(format!("enclave-admin-onion-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).display().to_string();
    let mut rng = HedgedRng::new().unwrap();
    let (ok, _, err) = admin(&[
        "foundation-keygen",
        &p("foundation.key"),
        &p("foundation.pub"),
    ]);
    assert!(ok, "{err}");
    let onion = format!("{}.onion", "a".repeat(56));
    let (a, a_id) = onion_server_descriptor("a.example", &onion, &mut rng);
    write(&dir, "a.bin", &a.encode());
    write(&dir, "push.bin", &vec![0u8; 2 * (4 + 56 + 1568)]);
    let spec = |push: &str| {
        format!(
            "seq = 1\nvalid_days = 30\nwitness_threshold = 0\n\
             [[server]]\ndescriptor = \"a.bin\"\nweight = 1\n\
             [[push]]\n{push}keys = \"push.bin\"\n"
        )
    };
    let build = || {
        admin(&[
            "server-list",
            "build",
            &p("spec.toml"),
            "--key",
            &p("foundation.key"),
            "--out",
            &p("list.bin"),
        ])
    };
    // A push relay with neither address can't be reached.
    std::fs::write(dir.join("spec.toml"), spec("")).unwrap();
    let (ok, _, _) = build();
    assert!(!ok, "a push relay without an address");
    std::fs::write(dir.join("spec.toml"), spec("onion = \"push.onion\"\n")).unwrap();
    let (ok, _, err) = build();
    assert!(ok, "{err}");
    let (ok, out, err) = admin(&[
        "server-list",
        "verify",
        &p("list.bin"),
        "--foundation",
        &p("foundation.pub"),
    ]);
    assert!(ok, "{err}");
    assert!(out.contains(&format!("onion {onion}")), "{out}");
    assert!(out.contains("push    push.onion  2 keys"), "{out}");
    let public =
        FoundationPublic::decode(&std::fs::read(dir.join("foundation.pub")).unwrap()).unwrap();
    let list = ServerList::verify(
        &std::fs::read(dir.join("list.bin")).unwrap(),
        &public,
        NOW,
        0,
    )
    .unwrap();
    assert_eq!(list.server(&a_id).unwrap().onion, onion);
    assert_eq!(list.push[0].onion, "push.onion");
    assert!(list.push[0].nym_address.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn build_verify_and_pin_a_server_list() {
    let dir = std::env::temp_dir().join(format!("enclave-admin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).display().to_string();
    let mut rng = HedgedRng::new().unwrap();

    let (ok, _, err) = admin(&[
        "foundation-keygen",
        &p("foundation.key"),
        &p("foundation.pub"),
    ]);
    assert!(ok, "{err}");
    let (again, _, _) = admin(&["foundation-keygen", &p("foundation.key"), &p("x.pub")]);
    assert!(!again, "never overwrites the foundation key");

    let (a, a_id) = server_descriptor("a.example", &mut rng);
    let (b, _) = server_descriptor("b.example", &mut rng);
    write(&dir, "a.bin", &a.encode());
    write(&dir, "b.bin", &b.encode());
    for i in 0..2 {
        let wk = CompositeSigningKey::generate(&mut rng).unwrap();
        let w = WitnessDescriptor::sign(
            &wk,
            &format!("witness-op-{i}"),
            "wf",
            "https://w.example",
            NOW - 10,
            NOW + 86_400,
            &mut rng,
        )
        .unwrap();
        write(&dir, &format!("w{i}.bin"), &w.encode());
    }
    write(&dir, "push.bin", &vec![0u8; 2 * (4 + 56 + 1568)]);
    let spec = |seq: u64, threshold: u8, a_file: &str| {
        format!(
            "seq = {seq}\nvalid_days = 30\nwitness_threshold = {threshold}\n\
             [[server]]\ndescriptor = \"{a_file}\"\nweight = 1\n\
             [[server]]\ndescriptor = \"b.bin\"\nweight = 2\n\
             [[witness]]\ndescriptor = \"w0.bin\"\n[[witness]]\ndescriptor = \"w1.bin\"\n\
             [[push]]\nnym_address = \"push-nym\"\nkeys = \"push.bin\"\n"
        )
    };
    std::fs::write(dir.join("spec.toml"), spec(5, 2, "a.bin")).unwrap();
    let (ok, _, err) = admin(&[
        "server-list",
        "build",
        &p("spec.toml"),
        "--key",
        &p("foundation.key"),
        "--out",
        &p("list.bin"),
    ]);
    assert!(ok, "{err}");

    let (ok, out, err) = admin(&[
        "server-list",
        "verify",
        &p("list.bin"),
        "--foundation",
        &p("foundation.pub"),
    ]);
    assert!(ok, "{err}");
    assert!(
        out.contains("a.example") && out.contains("b.example"),
        "{out}"
    );
    assert!(out.contains("push-nym  2 keys"), "{out}");

    // Clients holding seq 5 refuse it again; another foundation's key
    // refuses it at all.
    let (stale, _, _) = admin(&[
        "server-list",
        "verify",
        &p("list.bin"),
        "--foundation",
        &p("foundation.pub"),
        "--held-seq",
        "5",
    ]);
    assert!(!stale);
    let (ok, _, _) = admin(&["foundation-keygen", &p("other.key"), &p("other.pub")]);
    assert!(ok);
    let (wrong, _, _) = admin(&[
        "server-list",
        "verify",
        &p("list.bin"),
        "--foundation",
        &p("other.pub"),
    ]);
    assert!(!wrong);

    // Pins: both servers' logs and both witnesses at threshold 2.
    let (ok, _, err) = admin(&[
        "kt-pins",
        &p("list.bin"),
        "--foundation",
        &p("foundation.pub"),
        "--out",
        &p("pins.bin"),
    ]);
    assert!(ok, "{err}");
    let pins = enclave_kt::KtPolicy::decode(&std::fs::read(dir.join("pins.bin")).unwrap()).unwrap();
    assert_eq!(pins.servers.len(), 2);
    assert_eq!(pins.witnesses.threshold, 2);
    assert_eq!(pins.by_domain("a.example").unwrap().server, a_id);

    // The list itself, read back with the library.
    let public =
        FoundationPublic::decode(&std::fs::read(dir.join("foundation.pub")).unwrap()).unwrap();
    let list = ServerList::verify(
        &std::fs::read(dir.join("list.bin")).unwrap(),
        &public,
        NOW,
        0,
    )
    .unwrap();
    assert_eq!(list.server(&a_id).unwrap().weight, 1);

    // A tampered descriptor, and a threshold above the witness count, stop
    // the build.
    let mut bad = a.encode();
    let n = bad.len();
    bad[n / 2] ^= 1;
    write(&dir, "bad.bin", &bad);
    std::fs::write(dir.join("spec.toml"), spec(6, 2, "bad.bin")).unwrap();
    let (ok, _, err) = admin(&[
        "server-list",
        "build",
        &p("spec.toml"),
        "--key",
        &p("foundation.key"),
        "--out",
        &p("list2.bin"),
    ]);
    assert!(!ok && err.contains("bad.bin"), "{err}");
    std::fs::write(dir.join("spec.toml"), spec(6, 3, "a.bin")).unwrap();
    let (ok, _, err) = admin(&[
        "server-list",
        "build",
        &p("spec.toml"),
        "--key",
        &p("foundation.key"),
        "--out",
        &p("list2.bin"),
    ]);
    assert!(!ok && err.contains("threshold"), "{err}");

    // Built where the descriptors are, signed where the key is: the
    // unsigned list carries no signature, and signing it gives a list that
    // verifies like one built with the key.
    std::fs::write(dir.join("spec.toml"), spec(7, 2, "a.bin")).unwrap();
    let (ok, _, err) = admin(&[
        "server-list",
        "build",
        &p("spec.toml"),
        "--out",
        &p("unsigned.bin"),
    ]);
    assert!(ok && err.contains("unsigned"), "{err}");
    let (unsigned_verifies, _, _) = admin(&[
        "server-list",
        "verify",
        &p("unsigned.bin"),
        "--foundation",
        &p("foundation.pub"),
    ]);
    assert!(!unsigned_verifies);
    let (ok, out, err) = admin(&[
        "server-list",
        "sign",
        &p("unsigned.bin"),
        "--key",
        &p("foundation.key"),
        "--out",
        &p("list7.bin"),
    ]);
    assert!(ok, "{err}");
    assert!(out.contains("a.example"), "shows what it signs: {out}");
    let list7 = ServerList::verify(
        &std::fs::read(dir.join("list7.bin")).unwrap(),
        &public,
        NOW,
        5,
    )
    .unwrap();
    assert_eq!(list7.seq, 7);
    // A signed list isn't something to sign again.
    let (ok, _, _) = admin(&[
        "server-list",
        "sign",
        &p("list7.bin"),
        "--key",
        &p("foundation.key"),
        "--out",
        &p("list8.bin"),
    ]);
    assert!(!ok);

    // descriptor verify, with the expected id.
    let hex: String = a_id.iter().map(|b| format!("{b:02x}")).collect();
    let (ok, out, _) = admin(&["descriptor", "verify", "server", &p("a.bin"), "--id", &hex]);
    assert!(ok && out.contains("a.example"), "{out}");
    let (ok, _, _) = admin(&["descriptor", "verify", "server", &p("b.bin"), "--id", &hex]);
    assert!(!ok, "wrong id refused");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `descriptor fetch` from a front over the Enclave TLS profile: the
/// descriptor is checked (and its id, if given) before it is written.
#[tokio::test(flavor = "multi_thread")]
async fn fetch_a_descriptor_from_a_front() {
    let dir = std::env::temp_dir().join(format!("enclave-admin-fetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).display().to_string();
    let mut rng = HedgedRng::new().unwrap();
    let (d, id) = server_descriptor("a.example", &mut rng);
    write(&dir, "descriptor.bin", &d.encode());

    // A front for 127.0.0.1 under a test CA.
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    write(&dir, "ca.pem", ca.pem().as_bytes());
    let certs = std::sync::Arc::new(enclave_front::CertStore::default());
    certs.set_pem(&leaf.pem(), &key.serialize_pem()).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("https://{}", l.local_addr().unwrap());
    let site = enclave_front::Site::new(dir.clone(), None).router();
    tokio::spawn(enclave_front::serve_https(l, site, certs));

    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let run = |args: Vec<String>| {
        tokio::task::spawn_blocking(move || {
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            admin(&a)
        })
    };
    let fetch = |out: &str, id: &str| {
        vec![
            "descriptor".into(),
            "fetch".into(),
            base.clone(),
            "--ca".into(),
            p("ca.pem"),
            "--out".into(),
            p(out),
            "--id".into(),
            id.into(),
        ]
    };
    let (ok, out, err) = run(fetch("fetched.bin", &hex)).await.unwrap();
    assert!(ok, "{err}");
    assert!(out.contains("a.example"), "{out}");
    assert_eq!(std::fs::read(dir.join("fetched.bin")).unwrap(), d.encode());

    // Another id: refused, nothing written.
    let (ok, _, err) = run(fetch("other.bin", &"00".repeat(16))).await.unwrap();
    assert!(!ok && err.contains("not"), "{err}");
    assert!(!dir.join("other.bin").exists());
    // A damaged descriptor: refused.
    let mut bad = d.encode();
    let n = bad.len();
    bad[n / 2] ^= 1;
    write(&dir, "descriptor.bin", &bad);
    let (ok, _, _) = run(fetch("bad.bin", &hex)).await.unwrap();
    assert!(!ok);
    assert!(!dir.join("bad.bin").exists());
    // Without the test CA, the front isn't trusted.
    let (ok, _, err) = run(vec![
        "descriptor".into(),
        "fetch".into(),
        base.clone(),
        "--out".into(),
        p("untrusted.bin"),
    ])
    .await
    .unwrap();
    assert!(!ok, "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `enclave-admin reports` and `console` against a server's console socket
/// (here a server in this process, served the way `enclave-server run`
/// serves it).
#[cfg(unix)]
#[test]
fn reports_through_a_server_console() {
    use std::io::{BufRead, BufReader, Write};
    let dir = std::env::temp_dir().join(format!("enclave-admin-console-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("admin.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let cfg = enclave_server::Config {
        id: [1; 16],
        ..enclave_server::Config::default()
    };
    let mut server = enclave_server::Server::new(cfg, (NOW / 86_400) as u32).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut conn = conn.unwrap();
            let mut line = String::new();
            BufReader::new(&conn).read_line(&mut line).unwrap();
            let answer = enclave_server::admin::command(&mut server, line.trim(), NOW);
            conn.write_all(answer.as_bytes()).unwrap();
        }
    });
    let s = sock.to_str().unwrap();
    let (ok, out, _) = admin(&["reports", "--socket", s]);
    assert!(ok && out.starts_with("ok 0 waiting"), "{out}");
    let (ok, out, err) = admin(&["reports", "show", "3", "--socket", s]);
    assert!(!ok && out.starts_with("error: no report #3"), "{out}{err}");
    let (ok, out, _) = admin(&["console", "stats", "--socket", s]);
    assert!(ok && out.contains("requests 0"), "{out}");
    let (ok, _, err) = admin(&["reports", "--socket", "/nonexistent/admin.sock"]);
    assert!(!ok && err.contains("is the server running"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
