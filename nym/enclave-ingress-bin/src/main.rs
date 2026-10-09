//! `enclave-ingress`: a stack's Nym client in front of its server
//! (`enclave_ingress`, `docs/12-servers.md` §6), and the same for push.
//!
//! ```text
//! enclave-ingress run      [--server HOST:PORT] [--dir DIR] [--public DIR] [--gateway ID] [--env]
//! enclave-ingress forward  --to NYM_ADDRESS … [--listen ADDR] [--public DIR] [--gateway ID] [--env]
//! enclave-ingress oneway   [--relay HOST:PORT] [--dir DIR] [--public DIR] [--gateway ID] [--env]
//! enclave-ingress healthcheck [--public DIR] [--addr-file NAME]
//! ```
//!
//! `run` connects to the mixnet with the identity kept in `--dir` (created
//! the first time), writes its Nym address to `PUBLIC/ingress.addr` (the
//! server puts it in its descriptor), and forwards every request to the
//! server on the stack's internal network. `forward` is the stack's push
//! egress: it listens for the server's wakes (`[push] forward`) and sends
//! each one way to every `--to` address (the push relays in the
//! foundation's list), with a fresh identity each start; it writes its
//! address to `PUBLIC/push-egress.addr` once connected. `oneway` sits in
//! front of a push relay with a persistent identity, writes its address to
//! `PUBLIC/push-ingress.addr` (for the foundation's list) and hands every
//! wake to the relay. `--env` takes the network from `NYM_*` variables (a
//! local mixnet, the sandbox) instead of mainnet. Defaults: `--server
//! server:7443`, `--listen 0.0.0.0:7446`, `--relay push-relay:7445`,
//! `--dir /var/lib/enclave/ingress`, `--public /var/lib/enclave/public`;
//! `healthcheck` looks for `--addr-file` (default `ingress.addr`).

use enclave_ingress::Stats;
use enclave_nym::MixnetDriver;
use enclave_nym_sdk::{Network, NymDriver, Options, Role};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let public =
        PathBuf::from(flag(&args, "--public").unwrap_or_else(|| "/var/lib/enclave/public".into()));
    let result = match args.first().map(String::as_str) {
        Some(mode @ ("run" | "forward" | "oneway")) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(run(mode, &args, &public))),
        Some("healthcheck") => {
            let file = flag(&args, "--addr-file").unwrap_or_else(|| "ingress.addr".into());
            if public.join(file).exists() {
                Ok(())
            } else {
                Err("not connected to the mixnet yet".into())
            }
        }
        _ => Err(
            "usage: enclave-ingress run|forward|oneway|healthcheck [options] (see the module docs)"
                .into(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-ingress: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A name on the stack's network (or an address), resolved.
fn resolve(addr: &str) -> Result<std::net::SocketAddr, String> {
    addr.to_socket_addrs()
        .map_err(|e| format!("{addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("{addr}: no address"))
}

async fn run(mode: &str, args: &[String], public: &std::path::Path) -> Result<(), String> {
    let relays: Vec<String> = args
        .windows(2)
        .filter(|p| p[0] == "--to" && !p[1].is_empty())
        .map(|p| p[1].clone())
        .collect();
    if mode == "forward" && relays.is_empty() {
        return Err("forward needs at least one --to NYM_ADDRESS".into());
    }
    let role = if mode == "forward" {
        // The egress needs no lasting address: nobody writes to it.
        Role::Client
    } else {
        let dir =
            PathBuf::from(flag(args, "--dir").unwrap_or_else(|| "/var/lib/enclave/ingress".into()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Role::Ingress { dir }
    };
    let driver = NymDriver::connect(Options {
        role,
        gateway: flag(args, "--gateway"),
        network: Network::from_env(args.iter().any(|a| a == "--env")),
        tickets: Vec::new(),
    })
    .await
    .map_err(|e| e.to_string())?;
    let address = driver.address();
    let file = match mode {
        "forward" => "push-egress.addr",
        "oneway" => "push-ingress.addr",
        _ => "ingress.addr",
    };
    std::fs::create_dir_all(public).map_err(|e| format!("{}: {e}", public.display()))?;
    std::fs::write(public.join(file), format!("{address}\n"))
        .map_err(|e| format!("{}: {e}", public.display()))?;
    let stats = Arc::new(Stats::default());
    {
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                eprintln!(
                    "enclave-ingress: answered {} failed {} dropped {}",
                    stats.answered.load(Ordering::Relaxed),
                    stats.failed.load(Ordering::Relaxed),
                    stats.dropped.load(Ordering::Relaxed)
                );
            }
        });
    }
    let driver: Arc<dyn MixnetDriver> = Arc::new(driver);
    let flusher = Arc::clone(&driver);
    let work: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> = match mode {
        "forward" => {
            let listen = flag(args, "--listen").unwrap_or_else(|| "0.0.0.0:7446".into());
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .map_err(|e| format!("{listen}: {e}"))?;
            eprintln!(
                "enclave-ingress: push egress {listen} → {} relay(s)",
                relays.len()
            );
            Box::pin(enclave_ingress::forward(
                driver,
                listener,
                Arc::new(relays),
                stats,
            ))
        }
        "oneway" => {
            let relay = flag(args, "--relay").unwrap_or_else(|| "push-relay:7445".into());
            eprintln!("enclave-ingress: {address} → push relay {relay}");
            Box::pin(enclave_ingress::oneway(driver, resolve(&relay)?, stats))
        }
        _ => {
            let server = flag(args, "--server").unwrap_or_else(|| "server:7443".into());
            eprintln!("enclave-ingress: {address} → {server}");
            // The server's address is resolved on the stack's network.
            Box::pin(enclave_ingress::serve(driver, resolve(&server)?, stats))
        }
    };
    tokio::select! {
        () = work => Err("the mixnet client stopped".into()),
        () = stop_signal() => {
            // Answers and wakes already handed to the client leave first.
            if !flusher.flush(Duration::from_secs(5)).await {
                eprintln!("enclave-ingress: stopping with sends not yet acknowledged");
            }
            Ok(())
        }
    }
}

/// Ctrl-C, or SIGTERM (`docker stop`).
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
