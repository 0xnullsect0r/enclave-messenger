//! `enclave-tord --state DIR [--bridge LINE]… [--builtin-bridges] [--direct] [--report]`
//!
//! Reads the SOCKS5 secret from its stdin (one line), confines itself
//! (IP sockets only; the filesystem limited to `DIR` and what TLS needs),
//! bootstraps Tor keeping its state in `DIR`, listens on a loopback port,
//! and prints `ready PORT`. It exits when its stdin closes (netd went away).
//! If Tor isn't up within [`BOOTSTRAP`], it prints `blocked` and exits: the
//! network may be blocking Tor, and bridges may get through. `--bridge`
//! (obfs4 bridge lines, from bridges.torproject.org) and
//! `--builtin-bridges` (the Tor Project's built-in ones) reach Tor through
//! obfs4 bridges, run in this process (`docs/09-transport.md` §7).
//! `--direct` dials without Tor, in a `dev-direct` build only (tests and
//! the local mixnet).

use std::process::ExitCode;
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;

/// What TLS and name resolution read (arti's own TLS to the Tor network).
const READ_ONLY: &[&str] = &[
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
    let Some(state) = flag("--state").map(std::path::PathBuf::from) else {
        eprintln!("enclave-tord: --state DIR is required");
        return ExitCode::FAILURE;
    };
    if std::fs::create_dir_all(&state).is_err() {
        eprintln!("enclave-tord: can't create {}", state.display());
        return ExitCode::FAILURE;
    }
    let ro: Vec<std::path::PathBuf> = READ_ONLY
        .iter()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    let fs = enclave_sandbox::filesystem(std::slice::from_ref(&state), &ro, false);
    let sc = enclave_sandbox::syscalls(enclave_sandbox::Profile::Netd, false);
    if args.iter().any(|a| a == "--report") {
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
            match tokio::time::timeout(BOOTSTRAP, dialer(direct, &state, &bridges)).await {
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
        ExitCode::SUCCESS
    })
}

/// How long Tor may take to come up before this says the network may be
/// blocking it.
const BOOTSTRAP: std::time::Duration = std::time::Duration::from_secs(150);

async fn dialer(
    direct: bool,
    state: &std::path::Path,
    bridges: &[String],
) -> std::io::Result<Arc<dyn enclave_tord::Dialer>> {
    if direct {
        #[cfg(feature = "dev-direct")]
        return Ok(Arc::new(enclave_tord::DirectDialer));
        #[cfg(not(feature = "dev-direct"))]
        return Err(std::io::Error::other("--direct needs a dev-direct build"));
    }
    #[cfg(feature = "tor")]
    {
        let d = enclave_tord::ArtiDialer::bootstrap(state, bridges).await?;
        Ok(Arc::new(d))
    }
    #[cfg(not(feature = "tor"))]
    {
        let _ = (state, bridges);
        Err(std::io::Error::other("built without Tor"))
    }
}
