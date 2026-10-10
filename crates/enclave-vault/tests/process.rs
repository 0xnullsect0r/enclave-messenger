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
        .env("ENCLAVE_KEYSTORE", "file")
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
        .env("ENCLAVE_KEYSTORE", "file")
        .args(["--connect", "/nonexistent", "--demo"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "not-a-token").unwrap();
    assert!(!child.wait().unwrap().success());
    let status = Command::new(BIN)
        .env("ENCLAVE_KEYSTORE", "file")
        .status()
        .unwrap();
    assert!(!status.success());
}

/// A minimal dev server over TCP (the framing `enclave-server` uses), with
/// a real identity and key bundle. Returns its address and id.
async fn dev_server() -> (std::net::SocketAddr, [u8; 16]) {
    let (addr, id, _) = dev_server_with_identity().await;
    (addr, id)
}

/// [`dev_server`], with the server's identity key too (for a server list).
async fn dev_server_with_identity() -> (
    std::net::SocketAddr,
    [u8; 16],
    enclave_crypto::sig::CompositePublic,
) {
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
    let public = identity.public().clone();
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
    (addr, id, public)
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
        .env("ENCLAVE_KEYSTORE", "file")
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

/// The app lock and the emergency PIN (`docs/14-storage.md` §5): the window
/// locks after the idle time and only the app PIN opens it; the emergency
/// PIN can't be the app PIN, and entered at the lock screen it erases
/// everything and goes back to the welcome screen.
#[tokio::test(flavor = "multi_thread")]
async fn app_lock_and_emergency_pin() {
    let dir = std::env::temp_dir().join(format!("enclave-vault-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("v.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let token = [0x6b; TOKEN_LEN];
    let mut child = Command::new(BIN)
        .env("ENCLAVE_KEYSTORE", "file")
        .arg("--connect")
        .arg(&sock)
        .arg("--demo")
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", frame::token_hex(&token)).unwrap();
    let (stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    frame::check_token(&mut rd, &token).await.unwrap();
    macro_rules! send {
        ($c:expr) => {
            frame::write_frame(&mut wr, &$c.encode()).await.unwrap()
        };
    }

    send!(Cmd::Create("Robin".into(), String::new()));
    next_snapshot(&mut rd, |s| s.my_name == "Robin").await;
    send!(Cmd::SetAppLock("12".into()));
    next_snapshot(&mut rd, |s| s.status.contains("at least")).await;
    send!(Cmd::SetAppLock("2468".into()));
    next_snapshot(&mut rd, |s| s.app_lock).await;
    send!(Cmd::SetEmergencyPin("2468".into()));
    next_snapshot(&mut rd, |s| s.status.contains("app PIN")).await;
    send!(Cmd::SetEmergencyPin("1357".into()));
    next_snapshot(&mut rd, |s| s.status.starts_with("Emergency PIN set")).await;
    // Idle for a second: locked at the next tick, and nothing shows.
    send!(Cmd::SetLockTimeout(1));
    let s = next_snapshot(&mut rd, |s| s.locked).await;
    assert!(s.pin_lock && s.my_name.is_empty() && s.contacts.is_empty());
    send!(Cmd::Select(String::new()));
    send!(Cmd::Unlock("0000".into()));
    next_snapshot(&mut rd, |s| s.locked && !s.unlock_error.is_empty()).await;
    send!(Cmd::Unlock("2468".into()));
    let s = next_snapshot(&mut rd, |s| !s.locked).await;
    assert_eq!(s.my_name, "Robin");
    assert_eq!(s.lock_timeout, 1);

    // The emergency PIN at the lock screen: everything goes.
    send!(Cmd::Lock);
    next_snapshot(&mut rd, |s| s.locked).await;
    send!(Cmd::Unlock("1357".into()));
    let erased = loop {
        let body = tokio::time::timeout(Duration::from_secs(60), frame::read_frame(&mut rd))
            .await
            .unwrap()
            .unwrap();
        match Out::decode(&body).unwrap() {
            Out::Effect(enclave_ipc::Effect::Erased) => break true,
            _ => continue,
        }
    };
    assert!(erased);
    let s = next_snapshot(&mut rd, |s| !s.locked).await;
    assert!(s.my_name.is_empty() && !s.app_lock, "a new start");
    drop(rd);
    drop(wr);
    let _ = tokio::task::spawn_blocking(move || child.wait()).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The server picker, moving the account and voting a group onto another
/// server (`docs/15-client.md` §1.1a, `docs/12-servers.md` §4,
/// `docs/07-groups.md` §4): with a signed list and no home named, the vault
/// offers the listed servers taking accounts (not one with weight 0),
/// picks one, takes another choice, sets up there, and moves when asked.
#[tokio::test(flavor = "multi_thread")]
async fn picks_a_server_from_the_list_and_moves() {
    use enclave_federation::{FoundationKey, ListedServer, ServerList};
    let (a_addr, a, a_pk) = dev_server_with_identity().await;
    let (b_addr, b, b_pk) = dev_server_with_identity().await;
    let (c_addr, c, c_pk) = dev_server_with_identity().await;
    let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
    let foundation = FoundationKey::generate(&mut rng).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let listed = |identity, domain: &str, weight| ListedServer {
        identity,
        domain: domain.into(),
        operator: format!("Operator of {domain}"),
        family: domain.into(),
        nym_address: String::new(),
        weight,
        kt: None,
    };
    let list = ServerList {
        seq: 1,
        issued: now,
        expires: now + 30 * 86_400,
        witness_threshold: 0,
        servers: vec![
            listed(a_pk, "a.example", 1),
            listed(b_pk, "b.example", 0),
            listed(c_pk, "c.example", 1),
        ],
        witnesses: Vec::new(),
        relays: Vec::new(),
        push: Vec::new(),
        credgates: Vec::new(),
    };
    let dir = std::env::temp_dir().join(format!("enclave-vault-pick-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("list"), list.sign(&foundation, &mut rng).unwrap()).unwrap();
    std::fs::write(dir.join("foundation"), foundation.public().encode()).unwrap();
    let route = |addr: std::net::SocketAddr| enclave_net::transport::Route::Tcp(addr);
    let mode = enclave_vault::Mode::Server {
        profile: dir.join("profile"),
        home: None,
        // Development routes to all three (a list would give Nym ones).
        others: vec![(a, route(a_addr)), (b, route(b_addr)), (c, route(c_addr))],
        nym_env: false,
        kt_pins: None,
        foundation: Some(dir.join("foundation")),
        server_list: Some(dir.join("list")),
        shaping: false,
    };
    assert_eq!(
        enclave_vault::Mode::from_args(&mode.to_args()).unwrap(),
        mode,
        "round trip without a home"
    );
    enclave_vault::keystore::use_files_only();
    let (tx, mut rx) = enclave_vault::spawn(mode);
    async fn wait(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<Out>,
        what: &str,
        f: impl Fn(&enclave_ipc::Snapshot) -> bool,
    ) -> enclave_ipc::Snapshot {
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                match rx.recv().await {
                    Some(Out::Snapshot(s)) if f(&s) => return *s,
                    Some(_) => {}
                    None => panic!("the engine stopped"),
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no snapshot with {what}"))
    }
    tx.send(Cmd::Select(String::new())).unwrap();
    let s = wait(&mut rx, "the picker", |s| !s.servers.is_empty()).await;
    let ids: Vec<_> = s.servers.iter().map(|r| r.id.clone()).collect();
    assert_eq!(ids, vec![hex(&a), hex(&c)], "b takes no new accounts");
    assert!(
        s.home == hex(&a) || s.home == hex(&c),
        "picked one: {}",
        s.home
    );
    // b can't be picked; c can.
    tx.send(Cmd::PickServer(hex(&b))).unwrap();
    tx.send(Cmd::PickServer(hex(&c))).unwrap();
    wait(&mut rx, "c picked", |s| s.home == hex(&c)).await;
    tx.send(Cmd::Create("Robin".into(), String::new())).unwrap();
    let s = wait(&mut rx, "the account", |s| s.my_name == "Robin").await;
    assert_eq!(s.home, hex(&c));
    assert!(s.can_move && !s.moving);

    // A group of one: our vote is the majority, and it moves tomorrow.
    tx.send(Cmd::CreateGroup("Book club".into())).unwrap();
    let s = wait(&mut rx, "the group", |s| {
        s.contacts.iter().any(|r| r.kind == 1)
    })
    .await;
    let gid = s.contacts.iter().find(|r| r.kind == 1).unwrap().id.clone();
    tx.send(Cmd::Select(gid)).unwrap();
    let s = wait(&mut rx, "the group's server", |s| !s.group_host.is_empty()).await;
    assert_eq!(s.group_host, hex(&c), "made on our server");
    tx.send(Cmd::VoteGroupHost(hex(&a))).unwrap();
    let s = wait(&mut rx, "the vote", |s| {
        s.status.contains("moves to that server")
    })
    .await;
    assert_eq!(s.group_next, hex(&a));

    // Move the account to a.
    tx.send(Cmd::MoveHome(hex(&a))).unwrap();
    wait(&mut rx, "the move started", |s| {
        s.status.starts_with("Moving")
    })
    .await;
    wait(&mut rx, "the new home", |s| s.home == hex(&a) && !s.moving).await;
    drop(tx);
    let _ = std::fs::remove_dir_all(&dir);
}
