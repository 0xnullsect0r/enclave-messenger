//! A stack's onion service: the fallback route to its server when the
//! mixnet is unreachable (`docs/09-transport.md` §7, N4).
//!
//! ```text
//! enclave-onion run [--state DIR] [--forward HOST:PORT] [--public DIR]
//! enclave-onion healthcheck [--public DIR]
//! ```
//!
//! `run` starts a Tor client (arti) with its state, cache and keys under
//! `--state` (default `/var/lib/enclave/onion`; the service's identity
//! key lives there, so its address survives restarts), publishes the onion
//! service, writes its address (`….onion`) to `PUBLIC/onion.addr` (the
//! server puts it in its descriptor), and copies every stream to
//! [`ONION_PORT`] onto a TCP connection to `--forward` (default
//! `server:7443`, the server's length-prefixed frames, as on the dev
//! transport). Streams to other ports, and directory or resolve requests,
//! are refused. Clients reach it only with their user's consent and never
//! in Maximum privacy: the mixnet is the private route; this one hides the
//! client's address but not the timing of its requests.

use futures::StreamExt;
use safelog::DisplayRedacted;
use std::path::PathBuf;
use std::process::ExitCode;
use tor_proto::stream::IncomingStreamRequest;

/// The onion service's port, the one clients connect to.
pub const ONION_PORT: u16 = 7443;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let _ = enclave_sandbox::process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let public =
        PathBuf::from(flag(&args, "--public").unwrap_or_else(|| "/var/lib/enclave/public".into()));
    let result = match args.first().map(String::as_str) {
        Some("run") => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(run(&args, &public))),
        Some("healthcheck") => {
            if public.join("onion.addr").exists() {
                Ok(())
            } else {
                Err("the onion service isn't published yet".into())
            }
        }
        _ => Err("usage: enclave-onion run|healthcheck [options] (see the module docs)".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-onion: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String], public: &std::path::Path) -> Result<(), String> {
    let state =
        PathBuf::from(flag(args, "--state").unwrap_or_else(|| "/var/lib/enclave/onion".into()));
    let forward = flag(args, "--forward").unwrap_or_else(|| "server:7443".into());
    let cfg = arti_client::config::TorClientConfigBuilder::from_directories(
        state.join("state"),
        state.join("cache"),
    )
    .build()
    .map_err(|e| e.to_string())?;
    let client = arti_client::TorClient::create_bootstrapped(cfg)
        .await
        .map_err(|e| format!("Tor: {e}"))?;
    let svc_cfg = tor_hsservice::config::OnionServiceConfigBuilder::default()
        .nickname("enclave".parse().map_err(|e| format!("{e}"))?)
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
    std::fs::create_dir_all(public).map_err(|e| format!("{}: {e}", public.display()))?;
    std::fs::write(public.join("onion.addr"), format!("{address}\n"))
        .map_err(|e| format!("{}: {e}", public.display()))?;
    eprintln!("enclave-onion: {address}:{ONION_PORT} → {forward}");
    let mut streams = Box::pin(tor_hsservice::handle_rend_requests(rend));
    while let Some(req) = streams.next().await {
        let begin_ok =
            matches!(req.request(), IncomingStreamRequest::Begin(b) if b.port() == ONION_PORT);
        let forward = forward.clone();
        tokio::spawn(async move {
            if !begin_ok {
                let _ = req.shutdown_circuit();
                return;
            }
            let Ok(mut tcp) = tokio::net::TcpStream::connect(&forward).await else {
                let _ = req.shutdown_circuit();
                return;
            };
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
    Err("the onion service stopped".into())
}
