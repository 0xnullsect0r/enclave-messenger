//! The HTTPS front of an operator's stack (`docs/12-servers.md` §4.3).
//!
//! ```text
//! enclave-front run          [--config FILE]   serve
//! enclave-front healthcheck  [--config FILE]   exit 0 if the front answers
//! ```
//!
//! `front.tls` picks where the certificate comes from:
//!
//! - `acme` (default): from `front.acme_directory` (Let's Encrypt unless
//!   set) by HTTP-01 on `front.listen_http`; kept in `front.data_dir` and
//!   renewed when 30 days are left (checked twice a day).
//! - `files`: `front.cert` and `front.key` (PEM), re-read hourly.
//! - `self-signed`: made at start (development only).

use enclave_front::acme::{self, AcmeConfig};
use enclave_front::{CertStore, Challenges, Site};
use enclave_service::config::{ConfigError, flag};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    front: FrontSection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FrontSection {
    listen_https: SocketAddr,
    /// ACME answers and the redirect to HTTPS; empty to turn off (only
    /// with `tls = "files"` or `"self-signed"`).
    listen_http: Option<SocketAddr>,
    /// The public domain (in the server's descriptor and certificate).
    domain: String,
    /// Where the server writes `descriptor.bin`.
    public_dir: PathBuf,
    /// The stack's witness on the internal network, such as
    /// `http://witness:7446`; empty for none.
    witness: Option<String>,
    /// `http://credgate:7448` on the stack that runs the foundation's
    /// credential gate; empty for none.
    credgate: Option<String>,
    tls: TlsMode,
    acme_email: Option<String>,
    acme_directory: Option<String>,
    /// A PEM root to trust for the ACME CA itself (a test CA).
    acme_ca_root: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    /// ACME account and certificate.
    data_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum TlsMode {
    #[default]
    Acme,
    Files,
    SelfSigned,
}

impl Default for FrontSection {
    fn default() -> Self {
        Self {
            listen_https: SocketAddr::from(([0, 0, 0, 0], 443)),
            listen_http: Some(SocketAddr::from(([0, 0, 0, 0], 80))),
            domain: String::new(),
            public_dir: PathBuf::from("/var/lib/enclave/public"),
            witness: None,
            credgate: None,
            tls: TlsMode::Acme,
            acme_email: None,
            acme_directory: None,
            acme_ca_root: None,
            cert: None,
            key: None,
            data_dir: PathBuf::from("/var/lib/enclave/front"),
        }
    }
}

fn load_config(args: &[String]) -> Result<FrontSection, String> {
    let path = flag(args, "--config").map(PathBuf::from);
    let c: FileConfig = enclave_service::config::load(path.as_deref(), std::env::vars())
        .map_err(|e: ConfigError| e.to_string())?;
    let f = c.front;
    if f.domain.is_empty() {
        return Err("set front.domain".into());
    }
    if f.tls == TlsMode::Acme && f.listen_http.is_none() {
        return Err("front.tls = \"acme\" needs front.listen_http for HTTP-01".into());
    }
    if f.tls == TlsMode::Files && (f.cert.is_none() || f.key.is_none()) {
        return Err("front.tls = \"files\" needs front.cert and front.key".into());
    }
    Ok(f)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => runtime().and_then(|rt| rt.block_on(run(&args))),
        Some("healthcheck") => runtime().and_then(|rt| rt.block_on(healthcheck(&args))),
        _ => Err("usage: enclave-front run|healthcheck [--config FILE]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-front: {e}");
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

fn load_files(
    cert: &std::path::Path,
    key: &std::path::Path,
    certs: &CertStore,
) -> Result<(), String> {
    let chain = std::fs::read_to_string(cert).map_err(|e| format!("{}: {e}", cert.display()))?;
    let key = std::fs::read_to_string(key).map_err(|e| format!("{}: {e}", key.display()))?;
    certs.set_pem(&chain, &key)
}

async fn run(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let certs = Arc::new(CertStore::default());
    let challenges = Challenges::default();

    let https = tokio::net::TcpListener::bind(cfg.listen_https)
        .await
        .map_err(|e| format!("{}: {e}", cfg.listen_https))?;
    let site = Site::new(cfg.public_dir.clone(), cfg.witness.clone())
        .with_credgate(cfg.credgate.clone())
        .router();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(enclave_front::serve_https(https, site, Arc::clone(&certs)));
    if let Some(addr) = cfg.listen_http {
        let http = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("{addr}: {e}"))?;
        let router = enclave_front::http_router(cfg.domain.clone(), Arc::clone(&challenges));
        tasks.spawn(async move { axum::serve(http, router).await });
    }

    match cfg.tls {
        TlsMode::SelfSigned => {
            let (chain, key) = enclave_front::self_signed(&cfg.domain)?;
            certs.set_pem(&chain, &key)?;
        }
        TlsMode::Files => {
            let (Some(cert), Some(key)) = (cfg.cert.clone(), cfg.key.clone()) else {
                return Err("front.cert and front.key".into());
            };
            load_files(&cert, &key, &certs)?;
            let certs = Arc::clone(&certs);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(3600));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    if let Err(e) = load_files(&cert, &key, &certs) {
                        eprintln!("certificate: {e}");
                    }
                }
            });
        }
        TlsMode::Acme => {
            std::fs::create_dir_all(&cfg.data_dir)
                .map_err(|e| format!("{}: {e}", cfg.data_dir.display()))?;
            let acme_cfg = AcmeConfig {
                domain: cfg.domain.clone(),
                email: cfg.acme_email.clone(),
                directory: cfg
                    .acme_directory
                    .clone()
                    .unwrap_or_else(|| acme::LETS_ENCRYPT.into()),
                ca_root: cfg.acme_ca_root.clone(),
                data_dir: cfg.data_dir.clone(),
            };
            let certs = Arc::clone(&certs);
            let challenges = Arc::clone(&challenges);
            tokio::spawn(async move {
                // Twice a day once a certificate is held; every 10 minutes
                // until then.
                loop {
                    let wait = match acme::ensure(&acme_cfg, &challenges, &certs, now()).await {
                        Ok(()) => Duration::from_secs(12 * 3600),
                        Err(e) => {
                            eprintln!("{e}");
                            Duration::from_secs(600)
                        }
                    };
                    tokio::time::sleep(wait).await;
                }
            });
        }
    }
    eprintln!(
        "enclave-front {} on {}{}",
        cfg.domain,
        cfg.listen_https,
        cfg.listen_http
            .map(|a| format!(" and {a}"))
            .unwrap_or_default()
    );
    tokio::select! {
        r = tasks.join_next() => match r {
            Some(Ok(Err(e))) => Err(e.to_string()),
            Some(Err(e)) => Err(e.to_string()),
            _ => Ok(()),
        },
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

/// The front answers on its HTTPS port (a TCP connection; the certificate
/// names the public domain, not the local address), and on its HTTP port
/// if it has one.
async fn healthcheck(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let local = |a: SocketAddr| {
        if a.ip().is_unspecified() {
            SocketAddr::from(([127, 0, 0, 1], a.port()))
        } else {
            a
        }
    };
    let t = Duration::from_secs(5);
    tokio::time::timeout(t, tokio::net::TcpStream::connect(local(cfg.listen_https)))
        .await
        .map_err(|_| "https: timeout".to_string())?
        .map_err(|e| format!("https: {e}"))?;
    if let Some(a) = cfg.listen_http {
        tokio::time::timeout(t, tokio::net::TcpStream::connect(local(a)))
            .await
            .map_err(|_| "http: timeout".to_string())?
            .map_err(|e| format!("http: {e}"))?;
    }
    Ok(())
}
