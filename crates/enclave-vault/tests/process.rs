//! The real vault binary over a Unix socket: token handshake, commands in,
//! snapshots out, and recovery words only on request.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::frame::{self, TOKEN_LEN};
use enclave_ipc::{Cmd, Out, Snapshot};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::net::UnixListener;

const BIN: &str = env!("CARGO_BIN_EXE_enclave-vault");

async fn next_snapshot<R: tokio::io::AsyncRead + Unpin>(
    rd: &mut R,
    want: impl Fn(&Snapshot) -> bool,
) -> Snapshot {
    loop {
        let body = tokio::time::timeout(Duration::from_secs(300), frame::read_frame(rd))
            .await
            .expect("vault answered in time")
            .unwrap();
        if let Out::Snapshot(s) = Out::decode(&body).unwrap()
            && want(&s)
        {
            return *s;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_process_serves_the_ui() {
    let dir = std::env::temp_dir().join(format!("enclave-vault-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("v.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let token = [0x5a; TOKEN_LEN];

    let mut child = Command::new(BIN)
        .arg("--connect")
        .arg(&sock)
        .arg("--demo")
        .arg("--report")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", frame::token_hex(&token)).unwrap();

    let (stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    frame::check_token(&mut rd, &token).await.unwrap();

    let send = |c: Cmd| c.encode();
    frame::write_frame(&mut wr, &send(Cmd::Create("Robin".into(), String::new())))
        .await
        .unwrap();
    let s = next_snapshot(&mut rd, |s| s.my_name == "Robin" && !s.requests.is_empty()).await;
    assert!(s.recovery_words.is_empty(), "words stay in the vault");
    assert_eq!(s.requests[0].name, "Sam (demo)");

    frame::write_frame(&mut wr, &send(Cmd::RevealWords(true)))
        .await
        .unwrap();
    frame::write_frame(&mut wr, &send(Cmd::Select(String::new())))
        .await
        .unwrap();
    let s = next_snapshot(&mut rd, |s| !s.recovery_words.is_empty()).await;
    assert_eq!(s.recovery_words.len(), 24);
    frame::write_frame(&mut wr, &send(Cmd::RevealWords(false)))
        .await
        .unwrap();
    frame::write_frame(&mut wr, &send(Cmd::Select(String::new())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| s.recovery_words.is_empty()).await;

    // Accept Sam's request, send a file, then save it back: the bytes cross
    // the process boundary both ways.
    let sam = s.requests[0].id.clone();
    frame::write_frame(&mut wr, &send(Cmd::Accept(sam.clone())))
        .await
        .unwrap();
    frame::write_frame(&mut wr, &send(Cmd::Select(sam.clone())))
        .await
        .unwrap();
    let file: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
    frame::write_frame(
        &mut wr,
        &send(Cmd::SendFile(
            sam.clone(),
            "notes.txt".into(),
            file.clone(),
            "for you".into(),
        )),
    )
    .await
    .unwrap();
    let s = next_snapshot(&mut rd, |s| {
        s.messages.iter().any(|m| m.file == "notes.txt")
    })
    .await;
    let seq = s
        .messages
        .iter()
        .find(|m| m.file == "notes.txt")
        .unwrap()
        .seq;
    frame::write_frame(&mut wr, &send(Cmd::SaveFile(sam, seq)))
        .await
        .unwrap();
    let saved = loop {
        let body = tokio::time::timeout(Duration::from_secs(120), frame::read_frame(&mut rd))
            .await
            .unwrap()
            .unwrap();
        if let Out::File(name, bytes) = Out::decode(&body).unwrap() {
            break (name, bytes);
        }
    };
    assert_eq!(saved, ("notes.txt".to_string(), file));

    // The UI goes away: the vault exits, reporting its hardening.
    drop(rd);
    drop(wr);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(out.status.success(), "{:?}", out.status);
    let report = String::from_utf8_lossy(&out.stderr);
    assert!(report.contains("no_core_dumps: true"), "{report}");
    if cfg!(target_os = "linux") {
        assert!(report.contains("not_dumpable: true"), "{report}");
        assert!(report.contains("no_new_privs: true"), "{report}");
        assert!(report.contains("syscalls: \"filtered\""), "{report}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vault_refuses_to_start_without_a_token() {
    let mut child = Command::new(BIN)
        .args(["--connect", "/nonexistent", "--demo"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "not-a-token").unwrap();
    assert!(!child.wait().unwrap().success());
    let status = Command::new(BIN).status().unwrap();
    assert!(!status.success());
}

/// A minimal dev server over TCP (the framing `enclave-server` uses), with
/// a real identity and key bundle. Returns its address and id.
async fn dev_server() -> (std::net::SocketAddr, [u8; 16]) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
    let identity = enclave_crypto::sig::CompositeSigningKey::generate(&mut rng).unwrap();
    let id = enclave_federation::server_id(identity.public());
    let mut server = enclave_server::Server::new(
        enclave_server::Config {
            id,
            effort_request: 4,
            effort_claim: 1,
            blob_tokens_per_day: 64,
            ..Default::default()
        },
        (now() / 86_400) as u32,
    )
    .unwrap();
    let key = server.public_key().unwrap();
    server.set_key_bundle(
        enclave_federation::KeyBundle::sign(&identity, &[key], &mut rng)
            .unwrap()
            .encode(),
    );
    let server = std::sync::Arc::new(tokio::sync::Mutex::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let server = std::sync::Arc::clone(&server);
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 4];
                    if sock.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
                    if sock.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let reply = {
                        let mut s = server.lock().await;
                        if buf.is_empty() {
                            s.key_bundle().to_vec()
                        } else {
                            s.handle(&buf, now())
                        }
                    };
                    if sock
                        .write_all(&(reply.len() as u32).to_be_bytes())
                        .await
                        .is_err()
                        || sock.write_all(&reply).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (addr, id)
}

/// Start the vault binary on `profile` against `addr` and connect to it.
async fn start_vault(
    dir: &std::path::Path,
    (addr, id): (std::net::SocketAddr, [u8; 16]),
    profile: &std::path::Path,
    name: &str,
) -> (
    std::process::Child,
    tokio::io::ReadHalf<tokio::net::UnixStream>,
    tokio::io::WriteHalf<tokio::net::UnixStream>,
) {
    let sock = dir.join(name);
    let listener = UnixListener::bind(&sock).unwrap();
    let token = [0x33; TOKEN_LEN];
    let mut child = Command::new(BIN)
        .arg("--connect")
        .arg(&sock)
        .args(["--server", &format!("{}={addr}", hex(&id)), "--profile"])
        .arg(profile)
        .arg("--report")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", frame::token_hex(&token)).unwrap();
    let (stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (mut rd, wr) = tokio::io::split(stream);
    frame::check_token(&mut rd, &token).await.unwrap();
    (child, rd, wr)
}

/// A profile on disk against a TCP server, with the vault confined to its
/// profile directory: creating the account (database, keystore) still works,
/// and a passphrase locks it: "Lock now", a wrong passphrase, the right one,
/// and a restarted vault that starts locked.
#[tokio::test(flavor = "multi_thread")]
async fn sandboxed_vault_keeps_its_profile() {
    let addr = dev_server().await;
    let dir = std::env::temp_dir().join(format!("enclave-vault-fs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let profile = dir.join("profile");
    let (child, mut rd, mut wr) = start_vault(&dir, addr, &profile, "v1.sock").await;
    let send = |c: Cmd| c.encode();
    frame::write_frame(
        &mut wr,
        &send(Cmd::Create("Robin".into(), "correct horse".into())),
    )
    .await
    .unwrap();
    let s = next_snapshot(&mut rd, |s| s.my_name == "Robin").await;
    assert!(s.my_link.starts_with("enclave:") && s.can_lock);
    assert!(profile.join("profile.redb").exists());

    frame::write_frame(&mut wr, &send(Cmd::Lock)).await.unwrap();
    let s = next_snapshot(&mut rd, |s| s.locked).await;
    assert!(s.my_name.is_empty(), "nothing shown while locked");
    frame::write_frame(&mut wr, &send(Cmd::Unlock("wrong".into())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| s.locked && !s.unlock_error.is_empty()).await;
    frame::write_frame(&mut wr, &send(Cmd::Unlock("correct horse".into())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| !s.locked && s.my_name == "Robin").await;
    drop(rd);
    drop(wr);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(out.status.success(), "{:?}", out.status);
    let report = String::from_utf8_lossy(&out.stderr);
    assert!(!report.contains("filesystem: \"error\""), "{report}");
    // The account was created against the server, through netd (when it
    // was built: `cargo test --workspace` builds it, `-p enclave-vault`
    // alone doesn't).
    let netd = std::path::Path::new(BIN).with_file_name("enclave-netd");
    if cfg!(target_os = "linux") && netd.exists() {
        assert!(report.contains("network: \"netd\""), "{report}");
    }
    if netd.with_file_name("enclave-mediad").exists() {
        assert!(report.contains("media: \"mediad\""), "{report}");
    }
    if cfg!(target_os = "linux") {
        assert!(report.contains("syscalls: \"filtered\""), "{report}");
    }
    eprintln!("{report}");

    // A new vault on the same profile starts locked.
    let (child, mut rd, mut wr) = start_vault(&dir, addr, &profile, "v2.sock").await;
    frame::write_frame(&mut wr, &send(Cmd::Select(String::new())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| s.locked).await;
    frame::write_frame(&mut wr, &send(Cmd::Unlock("correct horse".into())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| !s.locked && s.my_name == "Robin").await;
    // Change it: the old one stops working after a restart, the new one opens.
    frame::write_frame(&mut wr, &send(Cmd::SetPassphrase("battery staple".into())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| s.status.starts_with("Passphrase set")).await;
    drop(rd);
    drop(wr);
    let _ = tokio::task::spawn_blocking(move || child.wait_with_output()).await;
    let (child, mut rd, mut wr) = start_vault(&dir, addr, &profile, "v3.sock").await;
    frame::write_frame(&mut wr, &send(Cmd::Unlock("correct horse".into())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| s.locked && !s.unlock_error.is_empty()).await;
    frame::write_frame(&mut wr, &send(Cmd::Unlock("battery staple".into())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| !s.locked && s.my_name == "Robin").await;
    drop(rd);
    drop(wr);
    let _ = tokio::task::spawn_blocking(move || child.wait_with_output()).await;
    let _ = std::fs::remove_dir_all(&dir);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
