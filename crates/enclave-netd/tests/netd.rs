//! netd carries requests and replies, and holds nothing else.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::KeyBundle;
use enclave_ipc::frame;
use enclave_ipc::net::{NetReply, NetRequest};
use enclave_rpc::ServerSecret;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIN: &str = env!("CARGO_BIN_EXE_enclave-netd");

/// RT-14 (`docs/15-client.md` §1.2): netd must not link the store, the
/// client engine or the protocol. Walks the path dependencies (not
/// dev-dependencies) from this crate's manifest.
#[test]
fn rt14_netd_has_no_key_material() {
    fn deps(dir: &Path, seen: &mut BTreeSet<String>) {
        let toml = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        let mut in_deps = false;
        for line in toml.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_deps = t.ends_with("dependencies]") && !t.contains("dev-");
                continue;
            }
            if !in_deps {
                continue;
            }
            if let Some(i) = t.find("path = \"") {
                let rel = &t[i + 8..];
                let rel = &rel[..rel.find('"').unwrap()];
                let name = t.split_whitespace().next().unwrap().to_string();
                if seen.insert(name) {
                    deps(&dir.join(rel), seen);
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    deps(Path::new(env!("CARGO_MANIFEST_DIR")), &mut seen);
    assert!(seen.contains("enclave-net"), "{seen:?}");
    for banned in [
        "enclave-store",
        "enclave-core",
        "enclave-proto",
        "enclave-vault",
    ] {
        assert!(!seen.contains(banned), "netd depends on {banned}: {seen:?}");
    }
}

/// A server that answers the dev framing: an empty request gets a signed
/// key bundle for `identity`, anything else comes back reversed.
async fn fake_server(identity: CompositeSigningKey) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let day = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400) as u32;
    let key = ServerSecret::from_seed(day, &[3; 32]).public().clone();
    let bundle = KeyBundle::sign(&identity, &[key], &mut HedgedRng::new().unwrap())
        .unwrap()
        .encode();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let bundle = bundle.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 4];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
                    s.read_exact(&mut buf).await.unwrap();
                    let reply = if buf.is_empty() {
                        bundle.clone()
                    } else {
                        buf.iter().rev().copied().collect()
                    };
                    s.write_all(&(reply.len() as u32).to_be_bytes())
                        .await
                        .unwrap();
                    s.write_all(&reply).await.unwrap();
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn carries_requests_and_keys() {
    let identity = CompositeSigningKey::generate(&mut HedgedRng::new().unwrap()).unwrap();
    let server = enclave_federation::server_id(identity.public());
    let addr = fake_server(identity).await;
    let hex: String = server.iter().map(|b| format!("{b:02x}")).collect();
    let mut child = tokio::process::Command::new(BIN)
        .args(["--server", &format!("{hex}={addr}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let requests = [
        NetRequest::Exchange {
            id: 1,
            server,
            bytes: vec![1, 2, 3],
        },
        NetRequest::ServerKey { id: 2, server },
        // Unknown server: an error reply, not a crash.
        NetRequest::Exchange {
            id: 3,
            server: [0; 16],
            bytes: vec![9],
        },
    ];
    for r in &requests {
        frame::write_frame(&mut stdin, &r.encode()).await.unwrap();
    }
    let mut replies = Vec::new();
    for _ in 0..requests.len() {
        let b = frame::read_frame(&mut stdout).await.unwrap();
        replies.push(NetReply::decode(&b).unwrap());
    }
    replies.sort_by_key(|r| r.id);
    assert_eq!(replies[0].result, Ok(vec![3, 2, 1]));
    // netd checked the bundle against the id and hands over the key.
    let key = replies[1].result.as_ref().unwrap();
    assert_eq!(key.len(), 4 + 56 + 1568);
    assert!(replies[2].result.is_err());

    // Garbage from the vault ends netd rather than confusing it.
    frame::write_frame(&mut stdin, &[0xff, 0, 0]).await.unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
}

/// A server named by a Nym address is reached over the mixnet, through the
/// mixnet client netd starts (here a stand-in, `examples/fake_nymd.rs`,
/// with an in-process mixnet and the real ingress in front of the server).
#[tokio::test]
async fn carries_requests_over_nym() {
    let identity = CompositeSigningKey::generate(&mut HedgedRng::new().unwrap()).unwrap();
    let server = enclave_federation::server_id(identity.public());
    let addr = fake_server(identity).await;
    let hex: String = server.iter().map(|b| format!("{b:02x}")).collect();
    // `cargo test` builds the examples next to the test binaries.
    let nymd = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_nymd{}", std::env::consts::EXE_SUFFIX));
    assert!(nymd.exists(), "{}", nymd.display());
    let mut child = tokio::process::Command::new(BIN)
        .args(["--server", &format!("{hex}=nym:ingress")])
        .args(["--nymd", nymd.to_str().unwrap()])
        .arg("--report")
        .env("ENCLAVE_FAKE_NYMD_SERVER", addr.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let poll: Vec<u8> = (0..enclave_wire::POLL_LEN).map(|i| i as u8).collect();
    let requests = [
        NetRequest::Exchange {
            id: 1,
            server,
            bytes: poll.clone(),
        },
        NetRequest::ServerKey { id: 2, server },
    ];
    for r in &requests {
        frame::write_frame(&mut stdin, &r.encode()).await.unwrap();
    }
    let mut replies = Vec::new();
    for _ in 0..requests.len() {
        let b = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            frame::read_frame(&mut stdout),
        )
        .await
        .unwrap()
        .unwrap();
        replies.push(NetReply::decode(&b).unwrap());
    }
    replies.sort_by_key(|r| r.id);
    let reversed: Vec<u8> = poll.iter().rev().copied().collect();
    assert_eq!(replies[0].result, Ok(reversed), "over the mixnet and back");
    assert_eq!(replies[1].result.as_ref().unwrap().len(), 4 + 56 + 1568);

    // With only Nym routes netd has the mixnet client's pipes and no
    // socket open, and (Linux) can open datagram sockets only: UDP for
    // calls, never TCP.
    let mut report = String::new();
    let mut stderr = child.stderr.take().unwrap();
    let mut b = [0u8; 256];
    while !report.contains('\n') {
        let n = stderr.read(&mut b).await.unwrap();
        assert!(n > 0, "no report: {report}");
        report.push_str(&String::from_utf8_lossy(&b[..n]));
    }
    assert!(report.contains("sockets udp"), "{report}");
    #[cfg(target_os = "linux")]
    {
        assert!(report.contains("syscalls filtered"), "{report}");
        let pid = child.id().unwrap();
        // netd is not dumpable, so only root may look at its descriptors;
        // as anyone else the report above is the check.
        let fds: Vec<String> = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(d) => d
                .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                .map(|l| l.display().to_string())
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("{e}"),
        };
        // Only Unix sockets (tokio's own signal pair for the child); no
        // IP socket is open.
        let unix = std::fs::read_to_string(format!("/proc/{pid}/net/unix")).unwrap();
        let unix: BTreeSet<&str> = unix
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().nth(6))
            .collect();
        for l in &fds {
            if let Some(inode) = l.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                assert!(unix.contains(inode), "an IP socket: {fds:?}");
            }
        }
    }
}

/// A Nym route the vault sends later (from the server list or a
/// descriptor) is used for the next request.
#[tokio::test]
async fn learns_nym_routes() {
    let identity = CompositeSigningKey::generate(&mut HedgedRng::new().unwrap()).unwrap();
    let server = enclave_federation::server_id(identity.public());
    let addr = fake_server(identity).await;
    let nymd = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_nymd{}", std::env::consts::EXE_SUFFIX));
    // Some other server over the mixnet, so netd starts its mixnet
    // client; ours has no route yet.
    let mut child = tokio::process::Command::new(BIN)
        .args(["--server", &format!("{}=nym:elsewhere", "11".repeat(16))])
        .args(["--nymd", nymd.to_str().unwrap()])
        .env("ENCLAVE_FAKE_NYMD_SERVER", addr.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reply = async |stdout: &mut tokio::process::ChildStdout| {
        let b = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            frame::read_frame(stdout),
        )
        .await
        .unwrap()
        .unwrap();
        NetReply::decode(&b).unwrap()
    };
    let key = |id| NetRequest::ServerKey { id, server }.encode();
    frame::write_frame(&mut stdin, &key(1)).await.unwrap();
    assert!(reply(&mut stdout).await.result.is_err(), "no route yet");
    let set = NetRequest::SetRoute {
        server,
        route: "nym:ingress".into(),
    };
    frame::write_frame(&mut stdin, &set.encode()).await.unwrap();
    frame::write_frame(&mut stdin, &key(2)).await.unwrap();
    let r = reply(&mut stdout).await;
    assert_eq!(r.id, 2);
    assert_eq!(r.result.unwrap().len(), 4 + 56 + 1568);
}

/// Where helpers share the app's process (Android, iOS), netd runs as a
/// thread on pipes and answers as the program does.
#[tokio::test]
async fn carries_requests_as_a_thread() {
    enclave_platform::process::register("enclave-netd", enclave_netd::main_with);
    let identity = CompositeSigningKey::generate(&mut HedgedRng::new().unwrap()).unwrap();
    let server = enclave_federation::server_id(identity.public());
    let addr = fake_server(identity).await;
    let hex: String = server.iter().map(|b| format!("{b:02x}")).collect();
    let p = enclave_platform::process::start(
        "enclave-netd",
        vec!["--server".into(), format!("{hex}={addr}")],
    )
    .unwrap()
    .expect("registered");
    let (mut stdin, mut stdout) = enclave_ipc::stdio::pipes(p);
    let req = NetRequest::Exchange {
        id: 7,
        server,
        bytes: vec![4, 5, 6],
    };
    frame::write_frame(&mut stdin, &req.encode()).await.unwrap();
    let reply = NetReply::decode(&frame::read_frame(&mut stdout).await.unwrap()).unwrap();
    assert_eq!((reply.id, reply.result), (7, Ok(vec![6, 5, 4])));
    // Closing its input ends it, as with the program.
    drop(stdin);
    let end = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        frame::read_frame(&mut stdout),
    )
    .await
    .unwrap();
    assert!(end.is_err());
}
