//! The credential gate (`docs/09-transport.md` §7, N3).
//!
//! ```text
//! enclave-credgate init        [--config FILE]   create the issuer seed
//! enclave-credgate run         [--config FILE]   serve plain HTTP for enclave-front
//! enclave-credgate show-key    [--config FILE] [--epochs N]
//!                                                print `EPOCH HEX` for this epoch and the N-1 after
//!                                                (the file `enclave-admin server-list build` lists)
//! enclave-credgate healthcheck [--config FILE]   exit 0 if the gate answers
//! ```
//!
//! `[credgate]` settings (each overridable as `ENCLAVE_CREDGATE__<KEY>`):
//! `listen`, `keys_dir`, `data_dir`, `effort`, `tokens_per_proof`,
//! `issuer_name` (the public host clients name in their token challenge),
//! `proxy_url` and `proxy_token_file` (the upstream `nym-credential-proxy`
//! and its bearer token). Tests and the local mixnet point `proxy_url` at
//! `enclave-dev-proxy` (`nym/enclave-dev-proxy`), whose signers are its
//! own, so the gate runs the same code everywhere.

use enclave_credgate::{Config, CredentialProxy, Gate, TicketSource};
use enclave_crypto::rng::HedgedRng;
use enclave_service::config::{ConfigError, flag, hex};
use enclave_service::keyfile::{create_key_dir, create_secret, read_array, read_secret};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    credgate: Section,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Section {
    listen: SocketAddr,
    keys_dir: PathBuf,
    data_dir: PathBuf,
    effort: u32,
    tokens_per_proof: usize,
    issuer_name: String,
    proxy_url: Option<String>,
    proxy_token_file: Option<PathBuf>,
}

impl Default for Section {
    fn default() -> Self {
        let d = Config::default();
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 7448)),
            keys_dir: PathBuf::from("/keys"),
            data_dir: PathBuf::from("/data"),
            effort: d.effort,
            tokens_per_proof: d.tokens_per_proof,
            issuer_name: d.issuer_name,
            proxy_url: None,
            proxy_token_file: None,
        }
    }
}

const SEED_FILE: &str = "credgate.seed";

fn load_config(args: &[String]) -> Result<Section, String> {
    let path = flag(args, "--config").map(PathBuf::from);
    let c: FileConfig = enclave_service::config::load(path.as_deref(), std::env::vars())
        .map_err(|e: ConfigError| e.to_string())?;
    Ok(c.credgate)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("init") => init(&args),
        Some("run") => runtime().and_then(|rt| rt.block_on(run(&args))),
        Some("show-key") => show_key(&args),
        Some("healthcheck") => runtime().and_then(|rt| rt.block_on(healthcheck(&args))),
        _ => Err("usage: enclave-credgate init|run|show-key|healthcheck [--config FILE]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-credgate: {e}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

fn init(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    create_key_dir(&cfg.keys_dir).map_err(|e| e.to_string())?;
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(rng.array("credgate/seed").map_err(|e| e.to_string())?);
    create_secret(&cfg.keys_dir.join(SEED_FILE), seed.as_slice()).map_err(|e| e.to_string())?;
    show_key(args)
}

fn source(cfg: &Section) -> Result<Arc<dyn TicketSource>, String> {
    let url = cfg
        .proxy_url
        .as_deref()
        .ok_or("set credgate.proxy_url (the nym-credential-proxy)")?;
    let file = cfg
        .proxy_token_file
        .as_deref()
        .ok_or("set credgate.proxy_token_file")?;
    let token = read_secret(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let token =
        String::from_utf8(token.to_vec()).map_err(|_| "the proxy token isn't text".to_string())?;
    Ok(Arc::new(CredentialProxy::new(
        url,
        Zeroizing::new(token.trim().to_string()),
    )))
}

fn gate(cfg: &Section) -> Result<Gate, String> {
    let seed = read_array::<32>(&cfg.keys_dir.join(SEED_FILE))
        .map_err(|e| format!("issuer seed: {e} (run init first)"))?;
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| e.to_string())?;
    Gate::open(
        Zeroizing::new(*seed),
        Config {
            effort: cfg.effort,
            tokens_per_proof: cfg.tokens_per_proof,
            issuer_name: cfg.issuer_name.clone(),
            ..Config::default()
        },
        source(cfg)?,
        Some(&cfg.data_dir.join("credgate.redb")),
    )
    .map_err(|e| e.to_string())
}

fn show_key(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let seed = read_array::<32>(&cfg.keys_dir.join(SEED_FILE)).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let n: u32 = match flag(args, "--epochs") {
        Some(n) => n
            .parse()
            .ok()
            .filter(|n| (1..=8).contains(n))
            .ok_or("--epochs is 1 to 8")?,
        None => 1,
    };
    let first = enclave_credgate::epoch_of(now);
    for epoch in first..first + n {
        let key =
            enclave_tokens::privpass::IssuerKey::derive(&seed, epoch).map_err(|e| e.to_string())?;
        println!("{epoch} {}", hex(&key.public().0));
    }
    Ok(())
}

async fn run(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let g = Arc::new(gate(&cfg)?);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| format!("{}: {e}", cfg.listen))?;
    eprintln!("enclave-credgate: serving on {}", cfg.listen);
    axum::serve(listener, g.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())
}

async fn healthcheck(args: &[String]) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let cfg = load_config(args)?;
    let mut s = tokio::net::TcpStream::connect(cfg.listen)
        .await
        .map_err(|e| e.to_string())?;
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: credgate\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    if buf.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err("unhealthy".into())
    }
}
