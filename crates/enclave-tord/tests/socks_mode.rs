//! `--tor-socks` (`docs/09-transport.md` §1): tord carrying netd's requests
//! through a system Tor's SocksPort instead of the embedded arti. A no-auth
//! SOCKS proxy that stands in for the system Tor maps every onion service to
//! a local server speaking the carrier framing, so the daemon runs end to
//! end: claim, `ready`, and an exchange through [`crate::socks::SocksDialer`].
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Stdio};
use std::time::Duration;

/// The carrier's exchange frame (kind 1): `1 ‖ u32 id ‖ u8 flags ‖
/// u16 host_len ‖ host ‖ u16 port ‖ request`, in a `u32 len` frame.
fn exchange(id: u32, host: &str, request: &[u8]) -> Vec<u8> {
    let mut f = vec![1u8];
    f.extend_from_slice(&id.to_be_bytes());
    f.push(0);
    f.extend_from_slice(&(host.len() as u16).to_be_bytes());
    f.extend_from_slice(host.as_bytes());
    f.extend_from_slice(&7443u16.to_be_bytes());
    f.extend_from_slice(request);
    let mut framed = (f.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&f);
    framed
}

fn read_exact(s: &mut impl Read, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).unwrap();
    b
}

/// A server speaking the carrier framing: every request answered with its
/// own bytes (a poll-sized round trip).
fn server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                loop {
                    let n = u32::from_be_bytes(read_exact(&mut s, 4).try_into().unwrap())
                        & !enclave_wire_one_way();
                    if n == 0 {
                        return;
                    }
                    let body = read_exact(&mut s, n as usize);
                    s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
                    s.write_all(&body).unwrap();
                }
            });
        }
    });
    port
}

/// The one-way bit, which the server side of the framing strips.
fn enclave_wire_one_way() -> u32 {
    0x8000_0000
}

/// A SOCKS5 proxy wanting no authentication, standing in for a system Tor:
/// every `.onion` address is really the local server.
fn socks(to: u16) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                // Greeting: only "no authentication".
                let m = read_exact(&mut s, 3);
                if m[1] != 1 || m[2] != 0 {
                    return;
                }
                s.write_all(&[5, 0]).unwrap();
                // Request: ver, cmd, rsv, atyp.
                let head = read_exact(&mut s, 4);
                if head[1] != 1 {
                    return;
                }
                let host: String = match head[3] {
                    1 => {
                        let a = read_exact(&mut s, 4);
                        std::net::Ipv4Addr::new(a[0], a[1], a[2], a[3]).to_string()
                    }
                    3 => {
                        let n = read_exact(&mut s, 1)[0] as usize;
                        String::from_utf8(read_exact(&mut s, n)).unwrap()
                    }
                    _ => return,
                };
                read_exact(&mut s, 2);
                let target = if host.ends_with(".onion") {
                    format!("127.0.0.1:{to}")
                } else {
                    format!("{host}:{to}")
                };
                let Ok(mut far) = TcpStream::connect(&target) else {
                    return;
                };
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                let mut a = far.try_clone().unwrap();
                let mut b = s.try_clone().unwrap();
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut s, &mut a);
                });
                let _ = std::io::copy(&mut far, &mut b);
            });
        }
    });
    port
}

struct Tord {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<std::process::ChildStdout>,
}

fn start(state: &std::path::Path, args: &[&str]) -> Tord {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_enclave-tord"));
    cmd.arg("--state").arg(state);
    for a in args {
        cmd.arg(a);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", "s".repeat(64)).unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    Tord { child, stdin, out }
}

fn state(name: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "enclave-tord-socks-{name}-{}-{n}",
        std::process::id()
    ))
}

impl Tord {
    /// One line from tord's stdout.
    fn line(&mut self) -> String {
        let mut l = String::new();
        self.out.read_line(&mut l).unwrap();
        l.trim_end().to_string()
    }
}

impl Drop for Tord {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A tord with `--tor-socks` carries an exchange through the proxy without
/// any arti: `ready` at once, the request answered.
#[test]
fn carries_requests_through_a_system_tor() {
    let port = server();
    let proxy = socks(port);
    let state = state("carried");
    let mut tord = start(
        &state,
        &["--carrier", "--tor-socks", &format!("127.0.0.1:{proxy}")],
    );
    let ready = tord.line();
    assert!(ready.starts_with("ready "), "{ready}");

    // The exchange: ask stack.onion for something, get it back.
    tord.stdin
        .write_all(&exchange(7, "stack.onion", b"a sealed unit"))
        .unwrap();
    tord.stdin.flush().unwrap();
    // The answer comes on tord's stdout: u32 len ‖ 1 ‖ u32 id ‖ 0 ‖ reply.
    let n = u32::from_be_bytes(read_exact(&mut tord.out, 4).try_into().unwrap()) as usize;
    let answer = read_exact(&mut tord.out, n);
    assert_eq!(&answer[..6], &[1, 0, 0, 0, 7, 0], "kind 1, id 7, ok");
    assert_eq!(&answer[6..], b"a sealed unit");
    let _ = std::fs::remove_dir_all(state);
}

/// No SOCKS port there: tord says why and exits, rather than waiting for an
/// arti bootstrap that never comes.
#[test]
fn a_missing_socks_port_fails_at_once() {
    let nothing = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = nothing.local_addr().unwrap().port();
    drop(nothing);
    let state = state("missing");
    let mut tord = start(
        &state,
        &["--carrier", "--tor-socks", &format!("127.0.0.1:{port}")],
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if tord.child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "tord didn't exit");
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_dir_all(state);
}
