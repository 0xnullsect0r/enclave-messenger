//! `enclave-tord --state DIR [--bridge LINE]… [--builtin-bridges] [--snowflake] [--pt PATH] [--direct] [--report]`
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
//! the local mixnet).

use std::process::ExitCode;
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;

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

fn main() -> ExitCode {
    let _ = enclave_sandbox::process();
    #[cfg(feature = "tor")]
    enclave_tord::install_tls_provider();
    let args: Vec<String> = std::env::args().skip(1).collect();
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
        bridges.extend(enclave_tord::obfs4pt::builtin());
    }
    if args.iter().any(|a| a == "--snowflake") {
        bridges.extend(enclave_tord::managed::builtin_snowflake());
    }
    let report = args.iter().any(|a| a == "--report");
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
    let needed = enclave_tord::managed::needed(&bridges);
    let managed = if needed.is_empty() || direct {
        None
    } else {
        let bin = flag("--pt")
            .map(std::path::PathBuf::from)
            .or_else(enclave_tord::managed::binary);
        let started = bin
            .ok_or_else(|| std::io::Error::other("no lyrebird"))
            .and_then(|b| enclave_tord::managed::launch(&b, &state, &needed, PT_START, report));
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
    let fs = enclave_sandbox::filesystem(std::slice::from_ref(&state), &ro, false);
    let sc = enclave_sandbox::syscalls(enclave_sandbox::Profile::Netd, false);
    if report {
        eprintln!("enclave-tord: filesystem {fs}, syscalls {sc}");
        enclave_tord::socks::REPORT.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    rt.block_on(async move {
        let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
        let mut secret = String::new();
        if stdin.read_line(&mut secret).await.is_err() || secret.trim().len() < 32 {
            eprintln!("enclave-tord: no secret on stdin");
            return ExitCode::FAILURE;
        }
        let secret = Arc::new(secret.trim().to_string());
        let dialer: Arc<dyn enclave_tord::Dialer> =
            match tokio::time::timeout(BOOTSTRAP, dialer(direct, &state, &bridges, &methods)).await {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => {
                    eprintln!("enclave-tord: {e}");
                    return ExitCode::FAILURE;
                }
                Err(_) => {
                    eprintln!("enclave-tord: Tor isn't up after {BOOTSTRAP:?}");
                    println!("blocked");
                    return ExitCode::FAILURE;
                }
            };
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return ExitCode::FAILURE;
        };
        let Ok(addr) = listener.local_addr() else {
            return ExitCode::FAILURE;
        };
        println!("ready {}", addr.port());
        tokio::select! {
            () = enclave_tord::serve(listener, secret, dialer) => {}
            // netd closed our stdin: it's gone, so are we.
            _ = async { let mut l = String::new(); while stdin.read_line(&mut l).await.is_ok_and(|n| n > 0) { l.clear(); } } => {}
        }
        drop(managed);
        ExitCode::SUCCESS
    })
}

/// How long lyrebird may take to name its transports' ports.
const PT_START: std::time::Duration = std::time::Duration::from_secs(20);

/// How long Tor may take to come up before this says the network may be
/// blocking it.
const BOOTSTRAP: std::time::Duration = std::time::Duration::from_secs(150);

async fn dialer(
    direct: bool,
    state: &std::path::Path,
    bridges: &[String],
    managed: &[(String, std::net::SocketAddr)],
) -> std::io::Result<Arc<dyn enclave_tord::Dialer>> {
    if direct {
        #[cfg(feature = "dev-direct")]
        return Ok(Arc::new(enclave_tord::DirectDialer));
        #[cfg(not(feature = "dev-direct"))]
        return Err(std::io::Error::other("--direct needs a dev-direct build"));
    }
    #[cfg(feature = "tor")]
    {
        let d = enclave_tord::ArtiDialer::bootstrap(state, bridges, managed).await?;
        Ok(Arc::new(d))
    }
    #[cfg(not(feature = "tor"))]
    {
        let _ = (state, bridges, managed);
        Err(std::io::Error::other("built without Tor"))
    }
}
