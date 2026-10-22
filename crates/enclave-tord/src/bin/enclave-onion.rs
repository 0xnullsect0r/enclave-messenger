//! A stack's onion services (RFC 0010): the route devices reach its server
//! by through Tor, and its push egress to a push relay's onion service.
//!
//! ```text
//! enclave-onion run [--state DIR] [--forward HOST:PORT] [--public DIR] [--addr-file NAME] [--max-streams N]
//! enclave-onion forward [--state DIR] [--listen ADDR] [--to NAME.onion]
//! enclave-onion healthcheck [--public DIR] [--addr-file NAME]
//! ```
//!
//! `run` starts a Tor client (arti) with its state, cache and keys under
//! `--state` (default `/var/lib/enclave/onion`; the service's identity
//! key lives there, so its address survives restarts: back it up with the
//! stack's keys), publishes the onion service and, once Tor says it is
//! reachable, writes its address (`….onion`) to `PUBLIC/ADDR-FILE`
//! (default `onion.addr`; the server puts it in its descriptor and the
//! foundation in its list). The file is removed at start, so it names a
//! service that is up now. Every stream to [`ONION_PORT`] is copied onto a
//! TCP connection to `--forward` (default `server:7443`, the server's
//! length-prefixed frames); streams to other ports are refused. At most
//! `--max-streams` (default 4,096) are open at once, and at most
//! [`STREAMS_PER_CIRCUIT`] on one circuit: a client that opens more loses
//! its circuit. A push relay's stack runs a second one, `--forward
//! push-relay:7445 --addr-file push-onion.addr`.
//!
//! `forward` is a stack's push egress over Tor: it takes the server's due
//! wakes on `--listen` (default `0.0.0.0:7446`) and sends them to the push
//! relay's onion service `--to` ([`enclave_tord::forward`]). Without `--to`
//! it takes them and drops them, until one is configured.
//!
//! Arti's proof-of-work defence for onion services is still experimental
//! and stays off; a flood of introductions is limited by the introduction
//! points' own rate limits and the stream caps above.

use futures::StreamExt;
use safelog::DisplayRedacted;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tor_proto::stream::IncomingStreamRequest;

/// The onion service's port, the one clients connect to.
pub const ONION_PORT: u16 = 7443;
/// Streams one circuit may hold open (a device keeps two to a server).
pub const STREAMS_PER_CIRCUIT: u32 = 16;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let _ = enclave_sandbox::process();
    #[cfg(feature = "tor")]
    enclave_tord::install_tls_provider();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let public =
        PathBuf::from(flag(&args, "--public").unwrap_or_else(|| "/var/lib/enclave/public".into()));
    let addr_file = flag(&args, "--addr-file").unwrap_or_else(|| "onion.addr".into());
    let runtime = || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
    };
    let result = match args.first().map(String::as_str) {
        Some("run") => runtime().and_then(|rt| rt.block_on(run(&args, &public, &addr_file))),
        Some("forward") => runtime().and_then(|rt| rt.block_on(forward(&args))),
        Some("healthcheck") => {
            if public.join(&addr_file).exists() {
                Ok(())
            } else {
                Err("the onion service isn't reachable yet".into())
            }
        }
        _ => Err(
            "usage: enclave-onion run|forward|healthcheck [options] (see the module docs)".into(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-onion: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn tor(
    state: &std::path::Path,
) -> Result<Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>, String> {
    let cfg = arti_client::config::TorClientConfigBuilder::from_directories(
        state.join("state"),
        state.join("cache"),
    )
    .build()
    .map_err(|e| e.to_string())?;
    arti_client::TorClient::create_bootstrapped(cfg)
        .await
        .map_err(|e| format!("Tor: {e}"))
}

async fn run(args: &[String], public: &std::path::Path, addr_file: &str) -> Result<(), String> {
    let state =
        PathBuf::from(flag(args, "--state").unwrap_or_else(|| "/var/lib/enclave/onion".into()));
    let forward = flag(args, "--forward").unwrap_or_else(|| "server:7443".into());
    let max_streams: usize = flag(args, "--max-streams")
        .map(|n| {
            n.parse()
                .map_err(|_| format!("--max-streams {n}: not a number"))
        })
        .transpose()?
        .unwrap_or(4096);
    // Whatever an earlier run wrote no longer says the service is up.
    std::fs::create_dir_all(public).map_err(|e| format!("{}: {e}", public.display()))?;
    let addr_path = public.join(addr_file);
    let _ = std::fs::remove_file(&addr_path);
    let client = tor(&state).await?;
    let svc_cfg = tor_hsservice::config::OnionServiceConfigBuilder::default()
        // The key is kept under this name in `--state`: unchanged, so the
        // address stays the one already published.
        .nickname("enclave".parse().map_err(|e| format!("{e}"))?)
        .max_concurrent_streams_per_circuit(STREAMS_PER_CIRCUIT)
        .build()
        .map_err(|e| e.to_string())?;
    let (service, rend) = client
        .launch_onion_service(svc_cfg)
        .map_err(|e| format!("onion service: {e}"))?
        .ok_or("the onion service is disabled")?;
    let address = service
        .onion_address()
        .ok_or("the onion service has no address")?
        .display_unredacted()
        .to_string();
    eprintln!("enclave-onion: {address}:{ONION_PORT} → {forward}, publishing");
    // The address goes out once Tor says the service can be reached.
    let mut events = service.status_events();
    let reachable = {
        let address = address.clone();
        let addr_path = addr_path.clone();
        async move {
            use tor_hsservice::status::State;
            while let Some(s) = events.next().await {
                if matches!(s.state(), State::Running | State::DegradedReachable) {
                    if let Err(e) = std::fs::write(&addr_path, format!("{address}\n")) {
                        eprintln!("enclave-onion: {}: {e}", addr_path.display());
                    } else {
                        eprintln!("enclave-onion: {address} is reachable");
                    }
                    return;
                }
            }
        }
    };
    tokio::spawn(reachable);
    let open = Arc::new(tokio::sync::Semaphore::new(max_streams));
    let mut streams = Box::pin(tor_hsservice::handle_rend_requests(rend));
    while let Some(req) = streams.next().await {
        let begin_ok =
            matches!(req.request(), IncomingStreamRequest::Begin(b) if b.port() == ONION_PORT);
        let forward = forward.clone();
        let permit = Arc::clone(&open).try_acquire_owned();
        tokio::spawn(async move {
            let Ok(_permit) = permit else {
                let _ = req.shutdown_circuit();
                return;
            };
            if !begin_ok {
                let _ = req.shutdown_circuit();
                return;
            }
            let Ok(mut tcp) = tokio::net::TcpStream::connect(&forward).await else {
                let _ = req.shutdown_circuit();
                return;
            };
            // Requests and replies are copied as they come: no waiting for
            // more to fill a segment.
            let _ = tcp.set_nodelay(true);
            let Ok(stream) = req
                .accept(tor_cell::relaycell::msg::Connected::new_empty())
                .await
            else {
                return;
            };
            let mut stream = stream;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
    }
    // Keep the service alive for as long as requests come.
    drop(service);
    let _ = std::fs::remove_file(&addr_path);
    Err("the onion service stopped".into())
}

async fn forward(args: &[String]) -> Result<(), String> {
    let listen = flag(args, "--listen").unwrap_or_else(|| "0.0.0.0:7446".into());
    let to = flag(args, "--to").filter(|t| !t.trim().is_empty());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| format!("can't listen on {listen}: {e}"))?;
    let Some(to) = to else {
        eprintln!("enclave-onion: no push relay set (PUSH_RELAY_ONION): wakes are dropped");
        enclave_tord::forward::run(listener, Arc::new(Nowhere), None).await;
        return Err("the listener stopped".into());
    };
    let state =
        PathBuf::from(flag(args, "--state").unwrap_or_else(|| "/var/lib/enclave/onion".into()));
    let dialer = enclave_tord::ArtiDialer::bootstrap(&state, &[], &[])
        .await
        .map_err(|e| format!("Tor: {e}"))?;
    eprintln!(
        "enclave-onion: wakes from {listen} → {to}:{}",
        enclave_tord::forward::PORT
    );
    enclave_tord::forward::run(listener, Arc::new(dialer), Some(to)).await;
    Err("the listener stopped".into())
}

/// No push relay: nothing is dialled.
struct Nowhere;

#[async_trait::async_trait]
impl enclave_tord::Dialer for Nowhere {
    async fn dial(&self, _: &str, _: u16) -> std::io::Result<Box<dyn enclave_tord::socks::Stream>> {
        Err(std::io::Error::other("no push relay"))
    }
}
