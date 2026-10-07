//! `enclave-nymd [--env] [--gateway ID] [--report]`
//!
//! A device's mixnet client. Started by `enclave-netd`, never by hand: it
//! connects to the mixnet with a fresh identity and serves
//! `enclave_nym::pipe` on its stdin and stdout, so netd drives it as a
//! mixnet client without linking nym-sdk (which needs another SQLite than
//! arti, `docs/09-transport.md` §1). It holds no Enclave keys and sees only
//! sealed requests. `--env` takes the network from `NYM_*` variables (a
//! local mixnet, the sandbox) instead of mainnet.
//!
//! It confines itself before connecting (Linux): its identity lives in
//! memory, so it reads only what name resolution and TLS need (resolver
//! configuration, CA certificates) and writes nothing; IPv4 and IPv6
//! sockets only; no programs, no debugging.

use enclave_nym::MixnetDriver;
use enclave_nym_sdk::{Network, NymDriver, Options, Role};
use std::process::ExitCode;
use std::sync::Arc;

/// What name resolution and TLS read; only those present are allowed (a
/// missing path would make the whole rule set fail).
const READ_ONLY: &[&str] = &[
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/localtime",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/usr/share/ca-certificates",
    "/usr/lib/ssl",
    "/run/systemd/resolve",
];

fn main() -> ExitCode {
    // No core dumps, not dumpable, no new privileges.
    let _ = enclave_sandbox::process();
    // Certificates named by the environment are read too, and a local
    // mixnet's topology file.
    let ro: Vec<std::path::PathBuf> = READ_ONLY
        .iter()
        .map(std::path::PathBuf::from)
        .chain(
            ["SSL_CERT_FILE", "SSL_CERT_DIR", "ENCLAVE_NYM_TOPOLOGY"]
                .iter()
                .filter_map(|v| std::env::var_os(v).map(std::path::PathBuf::from)),
        )
        .filter(|p| p.exists())
        .collect();
    let fs = enclave_sandbox::filesystem(&[], &ro, false);
    let sc = enclave_sandbox::syscalls(enclave_sandbox::Profile::Netd, false);
    if std::env::args().any(|a| a == "--report") {
        eprintln!("enclave-nymd: filesystem {fs}, syscalls {sc}");
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let gateway = args
        .iter()
        .position(|a| a == "--gateway")
        .and_then(|i| args.get(i + 1).cloned());
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    // netd started Tor for us: the gateway (and nym-api, through the proxy
    // variables netd set) only through it.
    if let Some(proxy) = std::env::var("ENCLAVE_TOR_SOCKS")
        .ok()
        .and_then(|p| p.parse().ok())
    {
        let secret = std::env::var("ENCLAVE_TOR_SECRET").unwrap_or_default();
        enclave_nym_sdk::dial_gateways_through(proxy, secret);
    }
    rt.block_on(async move {
        let driver = match NymDriver::connect(Options {
            role: Role::Client,
            gateway,
            network: Network::from_env(args.iter().any(|a| a == "--env")),
        })
        .await
        {
            Ok(d) => d,
            Err(e) => {
                eprintln!("enclave-nymd: {e}");
                return ExitCode::FAILURE;
            }
        };
        let driver: Arc<dyn MixnetDriver> = Arc::new(driver);
        enclave_nym::pipe::serve(driver, tokio::io::stdin(), tokio::io::stdout()).await;
        ExitCode::SUCCESS
    })
}
