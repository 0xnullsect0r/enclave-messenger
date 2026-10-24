//! The `enclave-tord` program ([`main_with`]; `src/bin/enclave-tord.rs`
//! runs it).
//!
//! `enclave-tord --state DIR [--port N] [--bridge LINE]… [--builtin-bridges] [--snowflake] [--pt PATH] [--carrier] [--standby] [--direct] [--report]`
//!
//! Reads the SOCKS5 secret from its stdin (one line), confines itself
//! (IP sockets only; the filesystem limited to `DIR` and what TLS needs),
//! bootstraps Tor keeping its state in `DIR`, listens on a loopback port,
//! and prints `ready PORT`. It exits when its stdin closes (netd went away).
//! If Tor isn't up within [`BOOTSTRAP`], it prints `blocked` and exits: the
//! network may be blocking Tor, and bridges may get through. `--bridge`
//! (bridge lines, from bridges.torproject.org), `--builtin-bridges` (the
//! Tor Project's built-in obfs4 bridges) and `--snowflake` (its built-in
//! Snowflake bridges) reach Tor through bridges (`docs/09-transport.md`
//! §7): obfs4 in this process, Snowflake and WebTunnel through lyrebird
//! (`--pt`, or next to this program), started before confinement.
//! `--direct` dials without Tor, in a `dev-direct` build only (tests and
//! the local mixnet). With `--carrier`, after `ready` its stdin and stdout
//! carry netd's requests to servers' onion services and its HTTPS fetches
//! ([`crate::carrier`], RFC 0010) instead of only telling it to exit.
//!
//! One tord at a time keeps Tor's state in a `DIR`: arti's cache can't be
//! set up by two at once. One that finds `DIR` taken prints `waiting`,
//! and `claimed` once it has it. With `--standby` (a spare netd's) it
//! waits for another to take `DIR` first, then for that one to go.

use std::process::ExitCode;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// What TLS and name resolution read (arti's own TLS to the Tor network),
/// and the user and group databases (arti checks who owns its state
/// directory before trusting it).
const READ_ONLY: &[&str] = &[
    "/etc/passwd",
    "/etc/group",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/usr/share/ca-certificates",
    "/usr/lib/ssl",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/gai.conf",
    "/run/systemd/resolve",
];

/// The program, given its arguments (without its name). As a thread of the
/// app (Android, iOS; `enclave_platform::process`) it leaves confining the
/// process alone and talks over the pipes it was given.
pub fn main_with(args: Vec<String>) -> ExitCode {
    let standalone = !enclave_platform::process::in_process();
    if standalone {
        let _ = enclave_sandbox::process();
    }
    #[cfg(feature = "tor")]
    crate::install_tls_provider();
    let flag = |n: &str| {
        args.iter()
            .position(|a| a == n)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let direct = args.iter().any(|a| a == "--direct");
    #[cfg_attr(not(feature = "tor"), allow(unused_mut))]
    let mut bridges: Vec<String> = args
        .windows(2)
        .filter(|p| p[0] == "--bridge")
        .map(|p| p[1].trim().to_string())
        .collect();
    #[cfg(feature = "tor")]
    if args.iter().any(|a| a == "--builtin-bridges") {
        bridges.extend(crate::obfs4pt::builtin());
    }
    if args.iter().any(|a| a == "--snowflake") {
        bridges.extend(crate::managed::builtin_snowflake());
    }
    let report = args.iter().any(|a| a == "--report");
    let carrier = args.iter().any(|a| a == "--carrier");
    let standby = args.iter().any(|a| a == "--standby");
    let Some(state) = flag("--state").map(std::path::PathBuf::from) else {
        eprintln!("enclave-tord: --state DIR is required");
        return ExitCode::FAILURE;
    };
    if std::fs::create_dir_all(&state).is_err() {
        eprintln!("enclave-tord: can't create {}", state.display());
        return ExitCode::FAILURE;
    }
    // Snowflake and WebTunnel run in lyrebird, started now: once confined,
    // this process can't start programs.
    let needed = crate::managed::needed(&bridges);
    let managed = if needed.is_empty() || direct {
        None
    } else {
        let started = crate::managed::in_process(&state, &needed).unwrap_or_else(|| {
            let bin = flag("--pt")
                .map(std::path::PathBuf::from)
                .or_else(crate::managed::binary);
            bin.ok_or_else(|| std::io::Error::other("no lyrebird"))
                .and_then(|b| crate::managed::launch(&b, &state, &needed, PT_START, report))
        });
        match started {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("enclave-tord: {e}");
                return ExitCode::FAILURE;
            }
        }
    };
    let methods = managed
        .as_ref()
        .map(|m| m.methods.clone())
        .unwrap_or_default();
    let ro: Vec<std::path::PathBuf> = READ_ONLY
        .iter()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    if standalone {
        let fs = enclave_sandbox::filesystem(std::slice::from_ref(&state), &ro, false);
        let sc = enclave_sandbox::syscalls(enclave_sandbox::Profile::Netd, false);
        if report {
            eprintln!("enclave-tord: filesystem {fs}, syscalls {sc}");
        }
    }
    if report {
        crate::socks::REPORT.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    let Ok(io) = enclave_platform::process::stdio() else {
        return ExitCode::FAILURE;
    };
    rt.block_on(async move {
        let mut stdin = tokio::io::BufReader::new(tokio::fs::File::from_std(io.input));
        let mut stdout = tokio::fs::File::from_std(io.output);
        let mut secret = String::new();
        if stdin.read_line(&mut secret).await.is_err() || secret.trim().len() < 32 {
            eprintln!("enclave-tord: no secret on stdin");
            return ExitCode::FAILURE;
        }
        let secret = Arc::new(secret.trim().to_string());
        // The state directory, ours alone while we run.
        let _claim = match claim(&state, standby, &mut stdin, &mut stdout).await {
            Ok(Some(c)) => c,
            // netd went away while we waited.
            Ok(None) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("enclave-tord: {}: {e}", state.join(CLAIM).display());
                return ExitCode::FAILURE;
            }
        };
        let boot = tokio::time::timeout(BOOTSTRAP, dialer(direct, &state, &bridges, &methods));
        let dialer: Arc<dyn crate::Dialer> = tokio::select! {
            r = boot => match r {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => {
                    eprintln!("enclave-tord: {}", chain(&e));
                    return ExitCode::FAILURE;
                }
                Err(_) => {
                    eprintln!("enclave-tord: Tor isn't up after {BOOTSTRAP:?}");
                    let _ = say(&mut stdout, "blocked").await;
                    return ExitCode::FAILURE;
                }
            },
            // netd went away while Tor came up: so do we, rather than
            // keep the state directory from the next one.
            () = gone(&mut stdin) => return ExitCode::SUCCESS,
        };
        // The port the app chose, where helpers share its process (the
        // proxy variables name it), else any.
        let port: u16 = flag("--port").and_then(|p| p.parse().ok()).unwrap_or(0);
        let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await else {
            return ExitCode::FAILURE;
        };
        let Ok(addr) = listener.local_addr() else {
            return ExitCode::FAILURE;
        };
        if say(&mut stdout, &format!("ready {}", addr.port())).await.is_err() {
            return ExitCode::FAILURE;
        }
        if carrier {
            // netd's requests to onion services and its fetches, over our
            // stdin and stdout (RFC 0010); the SOCKS port stays for nymd.
            #[cfg(feature = "carrier-serve")]
            tokio::select! {
                () = crate::serve(listener, secret, Arc::clone(&dialer)) => {}
                // netd closed our stdin: it's gone, so are we.
                () = crate::carrier::serve(dialer, stdin, stdout) => {}
            }
            #[cfg(not(feature = "carrier-serve"))]
            {
                eprintln!("enclave-tord: --carrier needs a build with Tor");
                return ExitCode::FAILURE;
            }
        } else {
            tokio::select! {
                () = crate::serve(listener, secret, dialer) => {}
                // netd closed our stdin: it's gone, so are we.
                _ = async { let mut l = String::new(); while stdin.read_line(&mut l).await.is_ok_and(|n| n > 0) { l.clear(); } } => {}
            }
        }
        drop(managed);
        ExitCode::SUCCESS
    })
}

/// The file in the state directory a running tord holds locked.
const CLAIM: &str = "enclave-tord.lock";

/// How often a waiting tord looks at the state directory again.
const CLAIM_POLL: std::time::Duration = std::time::Duration::from_millis(500);

/// Take the state directory for this process: lock [`CLAIM`] in it,
/// waiting (and saying so: `waiting`, then `claimed`) while another tord
/// has it. A `standby` one waits until it has seen another holding it, so
/// the netd in use always gets Tor first. `None`: our stdin closed while
/// we waited.
async fn claim(
    state: &std::path::Path,
    standby: bool,
    stdin: &mut (impl tokio::io::AsyncBufRead + Unpin),
    out: &mut tokio::fs::File,
) -> std::io::Result<Option<std::fs::File>> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state.join(CLAIM))?;
    let mut seen_held = !standby;
    let mut waited = false;
    loop {
        match f.try_lock() {
            Ok(()) if seen_held => break,
            // Not taken yet by the one we stand in for.
            Ok(()) => f.unlock()?,
            Err(std::fs::TryLockError::WouldBlock) => seen_held = true,
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
        if !waited {
            say(out, "waiting").await?;
            waited = true;
        }
        tokio::select! {
            () = tokio::time::sleep(CLAIM_POLL) => {}
            () = gone(stdin) => return Ok(None),
        }
    }
    if waited {
        say(out, "claimed").await?;
    }
    Ok(Some(f))
}

/// Returns once `stdin` has closed. Nothing is read from it: before
/// `ready` netd sends nothing more.
async fn gone(stdin: &mut (impl tokio::io::AsyncBufRead + Unpin)) {
    loop {
        match stdin.fill_buf().await {
            Ok(b) if !b.is_empty() => tokio::time::sleep(CLAIM_POLL).await,
            _ => return,
        }
    }
}

/// An error with what caused it (arti's say which file, which check).
fn chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        let c_s = c.to_string();
        if !s.contains(&c_s) {
            s.push_str(": ");
            s.push_str(&c_s);
        }
        cause = c.source();
    }
    s
}

/// How long lyrebird may take to name its transports' ports.
const PT_START: std::time::Duration = std::time::Duration::from_secs(20);

/// One line to the parent.
async fn say(out: &mut tokio::fs::File, line: &str) -> std::io::Result<()> {
    out.write_all(format!("{line}\n").as_bytes()).await?;
    out.flush().await
}

/// How long Tor may take to come up before this says the network may be
/// blocking it.
const BOOTSTRAP: std::time::Duration = std::time::Duration::from_secs(150);

async fn dialer(
    direct: bool,
    state: &std::path::Path,
    bridges: &[String],
    managed: &[(String, std::net::SocketAddr)],
) -> std::io::Result<Arc<dyn crate::Dialer>> {
    if direct {
        #[cfg(feature = "dev-direct")]
        return Ok(Arc::new(crate::DirectDialer));
        #[cfg(not(feature = "dev-direct"))]
        return Err(std::io::Error::other("--direct needs a dev-direct build"));
    }
    #[cfg(feature = "tor")]
    {
        let d = crate::ArtiDialer::bootstrap(state, bridges, managed).await?;
        Ok(Arc::new(d))
    }
    #[cfg(not(feature = "tor"))]
    {
        let _ = (state, bridges, managed);
        Err(std::io::Error::other("built without Tor"))
    }
}
