//! The `enclave-registrar` program (RFC 0012).
//!
//! ```text
//! enclave-registrar run    [--config FILE]   serve applications, rebuild,
//!                                            sign and push the list
//! enclave-registrar list   [--config FILE]   print the list held
//! enclave-registrar approve ID [--config FILE]   take a queued application
//!                                              (guarded mode)
//! ```
//!
//! Configuration is `[registrar]` in the TOML file (`ENCLAVE_REGISTRAR__*`):
//! `listen` (the front proxies `/registrar/v1/*` here), `foundation_key`
//! (the foundation's signing key file — the one trust-relevant thing this
//! process holds), `static_spec` (the relays, push relays, credential
//! gates and any foundation-run witnesses, in the registrar's spec
//! shape), `list` (the signed list held, seeded from the last
//! `enclave-admin` one and replaced by every rebuild), `queue` (where
//! applications wait), `effort` (the proof-of-work effort asked of an
//! application), `open` (true: applications are taken at once; false:
//! each waits for `approve`), `rebuild_every_secs`, and `first_list`
//! (a file to seed `list` from when it doesn't exist yet).

use enclave_registrar::{Application, Static};
use http_body_util::BodyExt;
use serde::Deserialize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RegistrarSection {
    listen: std::net::SocketAddr,
    foundation_key: PathBuf,
    static_spec: PathBuf,
    list: PathBuf,
    first_list: Option<PathBuf>,
    queue: PathBuf,
    effort: u32,
    open: bool,
    rebuild_every_secs: u64,
}

impl Default for RegistrarSection {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 7451)),
            foundation_key: PathBuf::new(),
            static_spec: PathBuf::new(),
            list: PathBuf::from("/var/lib/enclave/registrar/list.bin"),
            first_list: None,
            queue: PathBuf::from("/var/lib/enclave/registrar/queue"),
            effort: 16,
            open: true,
            rebuild_every_secs: 6 * 3600,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    registrar: RegistrarSection,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_config(args: &[String]) -> Result<FileConfig, String> {
    let path = enclave_service::config::flag(args, "--config").map(PathBuf::from);
    let c: FileConfig = enclave_service::config::load(path.as_deref(), std::env::vars())
        .map_err(|e| e.to_string())?;
    if c.registrar.foundation_key.as_os_str().is_empty() {
        return Err("set registrar.foundation_key".into());
    }
    if c.registrar.static_spec.as_os_str().is_empty() {
        return Err("set registrar.static_spec".into());
    }
    Ok(c)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => runtime().and_then(|rt| rt.block_on(run(&args))),
        Some("list") => list(&args),
        Some("approve") => approve(&args),
        _ => Err("usage: enclave-registrar run|list|approve ID [--config FILE]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-registrar: {e}");
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

/// The shared state: the config, the signing key, and the list held.
struct Registrar {
    cfg: RegistrarSection,
    key: enclave_federation::FoundationKey,
    statik: Static,
    /// Woken by an accepted application, so it lands in minutes.
    wake: tokio::sync::Notify,
}

/// Most applications held at once: the queue is open to anyone.
const MAX_QUEUED: usize = 256;
/// A failing application gets retried this long, then it's let go.
const RETRY_FOR: Duration = Duration::from_secs(86_400);

fn load_registrar(args: &[String]) -> Result<Registrar, String> {
    let cfg = load_config(args)?.registrar;
    let secret = enclave_service::keyfile::read_secret(&cfg.foundation_key)
        .map_err(|e| format!("{}: {e}", cfg.foundation_key.display()))?;
    let key = enclave_federation::FoundationKey::from_bytes(&secret)
        .map_err(|e| format!("{}: {e}", cfg.foundation_key.display()))?;
    let text = std::fs::read_to_string(&cfg.static_spec)
        .map_err(|e| format!("{}: {e}", cfg.static_spec.display()))?;
    let statik: Static =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", cfg.static_spec.display()))?;
    std::fs::create_dir_all(&cfg.queue).map_err(|e| format!("{}: {e}", cfg.queue.display()))?;
    if !cfg.list.exists()
        && let Some(first) = &cfg.first_list
    {
        std::fs::copy(first, &cfg.list).map_err(|e| format!("{}: {e}", first.display()))?;
    }
    Ok(Registrar {
        cfg,
        key,
        statik,
        wake: tokio::sync::Notify::new(),
    })
}

impl Registrar {
    /// The list held, or an empty sequence-0 shell when none is seeded.
    fn held(&self) -> Result<enclave_federation::ServerList, String> {
        match std::fs::read(&self.cfg.list) {
            Ok(b) => enclave_federation::ServerList::decode_unverified(&b)
                .map_err(|e| format!("{}: {e}", self.cfg.list.display())),
            Err(_) => Ok(enclave_federation::ServerList {
                seq: 0,
                issued: 0,
                expires: 0,
                witness_threshold: 1,
                servers: Vec::new(),
                witnesses: Vec::new(),
                relays: Vec::new(),
                push: Vec::new(),
                credgates: Vec::new(),
            }),
        }
    }

    /// One rebuild: fetch every listed stack's descriptor, verify the
    /// applications again, sign the next list, store it, push it.
    async fn rebuild_once(&self) -> Result<String, String> {
        let held = self.held()?;
        let mut served = std::collections::HashMap::new();
        for s in &held.servers {
            // One that doesn't answer keeps its last entry (`rebuild`).
            match enclave_registrar::get_https(
                &format!("https://{}/.well-known/enclave", s.domain),
                Duration::from_secs(30),
            )
            .await
            {
                Ok((200, b)) => {
                    served.insert(s.domain.clone(), b);
                }
                Ok((status, _)) => {
                    eprintln!(
                        "enclave-registrar: {}: its front answered {status}",
                        s.domain
                    );
                }
                Err(e) => eprintln!("enclave-registrar: {}: {e}", s.domain),
            }
        }
        // A bad application is that application's problem, never the list's.
        let mut applications = Vec::new();
        let mut taken_files = Vec::new();
        for (path, body) in self.pending()? {
            match self.vet(&body).await {
                Ok(a) => {
                    applications.push(a);
                    taken_files.push(path);
                }
                Err(e) => {
                    eprintln!("enclave-registrar: {}: {e}", path.display());
                    let old = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > RETRY_FOR);
                    if old {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
        let mut rng = enclave_crypto::rng::HedgedRng::new().map_err(|e| e.to_string())?;
        let bytes = enclave_registrar::rebuild(
            &held,
            &served,
            &applications,
            &self.statik,
            now(),
            &self.key,
            &mut rng,
        )?;
        let list = enclave_federation::ServerList::decode_unverified(&bytes)
            .map_err(|e| format!("just-signed list: {e}"))?;
        std::fs::write(&self.cfg.list, &bytes)
            .map_err(|e| format!("{}: {e}", self.cfg.list.display()))?;
        // Only what this list took: one that arrived meanwhile stays.
        for path in taken_files {
            let _ = std::fs::remove_file(path);
        }
        // Push: a stack that misses it takes the next one.
        let domains: Vec<String> = list.servers.iter().map(|s| s.domain.clone()).collect();
        let mut taken = 0;
        for (d, r) in enclave_registrar::push(&bytes, &domains).await {
            match r {
                Ok((200, _)) => taken += 1,
                Ok((status, why)) => eprintln!(
                    "enclave-registrar: {d}: refused ({status}): {}",
                    String::from_utf8_lossy(&why)
                ),
                Err(e) => eprintln!("enclave-registrar: {d}: {e}"),
            }
        }
        Ok(format!(
            "list {}: {} servers, {} witnesses; {} of {} stacks took it",
            list.seq,
            list.servers.len(),
            list.witnesses.len(),
            taken,
            domains.len()
        ))
    }

    /// One application, checked in full, with the registrar fetching what
    /// its front really serves.
    async fn vet(&self, body: &[u8]) -> Result<Application, String> {
        let (a, proof) = Application::parse(body)?;
        let served_bytes = a.descriptor.encode();
        a.check(&proof, self.cfg.effort, now(), &served_bytes)?;
        let domain = a.descriptor.domain.clone();
        match enclave_registrar::get_https(
            &format!("https://{domain}/.well-known/enclave"),
            Duration::from_secs(30),
        )
        .await?
        {
            (200, b) if b == served_bytes => Ok(a),
            (200, _) => Err(format!("{domain}: its front serves a different descriptor")),
            (status, _) => Err(format!("{domain}: its front answered {status}")),
        }
    }

    /// The applications waiting: all of them in open mode, only approved
    /// ones in guarded mode.
    fn pending(&self) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
        let mut out = Vec::new();
        let read_dir = |d: &std::path::Path| -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
            let mut v = Vec::new();
            let entries = match std::fs::read_dir(d) {
                Ok(e) => e,
                Err(_) => return Ok(v), // not there yet: nothing waits in it
            };
            for e in entries {
                let p = e.map_err(|e| e.to_string())?.path();
                if p.extension().is_some_and(|x| x == "bin")
                    && let Ok(b) = std::fs::read(&p)
                {
                    v.push((p, b));
                }
            }
            v.sort();
            Ok(v)
        };
        if self.cfg.open {
            out.extend(read_dir(&self.cfg.queue)?);
        }
        out.extend(read_dir(&self.cfg.queue.join("approved"))?);
        Ok(out)
    }
}

async fn run(args: &[String]) -> Result<(), String> {
    let r = Arc::new(load_registrar(args)?);
    let effort = r.cfg.effort;
    let listener = tokio::net::TcpListener::bind(r.cfg.listen)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "enclave-registrar on {} (effort {effort}, {})",
        listener.local_addr().map_err(|e| e.to_string())?,
        if r.cfg.open { "open" } else { "guarded" }
    );

    // The HTTP side: parameters, applications, the list held.
    let state = std::sync::Arc::clone(&r);
    let router = axum::Router::new()
        .route(
            "/registrar/v1/params",
            axum::routing::get(move || {
                let effort = effort.to_string();
                async move { effort }
            }),
        )
        .route("/registrar/v1/apply", {
            let state = std::sync::Arc::clone(&state);
            axum::routing::any(move |req| apply(state, req))
        })
        .route(
            "/registrar/v1/list",
            axum::routing::get({
                let state = std::sync::Arc::clone(&state);
                move || async move {
                    std::fs::read(&state.cfg.list).map_or_else(
                        |_| axum::response::Response::new(axum::body::Body::from("no list yet")),
                        |b| {
                            // A static-header builder can only fail on
                            // header values, and these are constants.
                            #[allow(clippy::expect_used)]
                            axum::response::Response::builder()
                                .status(axum::http::StatusCode::OK)
                                .header("content-type", "application/octet-stream")
                                .body(axum::body::Body::from(b))
                                .expect("constant response headers")
                        },
                    )
                }
            }),
        );
    let svc = hyper_util::service::TowerToHyperService::new(router);
    let http = tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let svc = svc.clone();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(sock), svc)
                    .await;
            });
        }
    });

    // The worker: a rebuild now (which also renews a list that would
    // expire) and then on the clock.
    let worker_state = std::sync::Arc::clone(&r);
    let every = Duration::from_secs(r.cfg.rebuild_every_secs.max(60));
    let worker = tokio::spawn(async move {
        loop {
            match worker_state.rebuild_once().await {
                Ok(what) => eprintln!("enclave-registrar: {what}"),
                Err(e) => eprintln!("enclave-registrar: rebuild held back: {e}"),
            }
            tokio::select! {
                () = tokio::time::sleep(every) => {}
                () = worker_state.wake.notified() => {
                    // A burst of applications shares one signing.
                    tokio::time::sleep(every.min(Duration::from_secs(60))).await;
                }
            }
        }
    });
    tokio::select! {
        _ = http => Ok(()),
        _ = worker => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

/// Take an application: everything the wire and the proof must survive
/// now (the full check — including the registrar fetching the stack's
/// front itself — happens again at rebuild, so nothing rests on this
/// moment), then queue it.
async fn apply(r: Arc<Registrar>, req: axum::extract::Request) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(body) =
        http_body_util::Limited::new(req.into_body(), enclave_registrar::MAX_APPLICATION)
            .collect()
            .await
            .map(|b| b.to_bytes())
    else {
        return (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "too large".to_string(),
        )
            .into_response();
    };
    let answer = match Application::parse(&body).and_then(|(a, proof)| {
        let served = a.descriptor.encode();
        a.check(&proof, r.cfg.effort, now(), &served)
            .map(|id| (a, id))
    }) {
        Ok((a, id)) => {
            let name = format!("{}-{}.bin", &hex(&id)[..8], now());
            let path = r.cfg.queue.join(&name);
            let full = std::fs::read_dir(&r.cfg.queue).map_or(0, Iterator::count) >= MAX_QUEUED;
            if full {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "the queue is full: try again later".to_string(),
                )
                    .into_response();
            }
            match std::fs::write(&path, &body) {
                Ok(()) => {
                    if r.cfg.open {
                        r.wake.notify_one();
                    }
                    let what = if r.cfg.open {
                        format!(
                            "queued from {} ({}): the next list takes it",
                            a.descriptor.domain,
                            &hex(&id)[..8]
                        )
                    } else {
                        format!(
                            "queued from {} ({}): waiting for the registrar's approve",
                            a.descriptor.domain,
                            &hex(&id)[..8]
                        )
                    };
                    (axum::http::StatusCode::OK, what)
                }
                Err(e) => (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("couldn't queue it: {e}"),
                ),
            }
        }
        Err(e) => (axum::http::StatusCode::FORBIDDEN, e),
    };
    answer.into_response()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn list(args: &[String]) -> Result<(), String> {
    let r = load_registrar(args)?;
    let held = r.held()?;
    println!(
        "list {} ({} servers, {} witnesses, expires {})",
        held.seq,
        held.servers.len(),
        held.witnesses.len(),
        held.expires
    );
    for s in &held.servers {
        println!("  server {} {} op {}", hex(&s.id()), s.domain, s.operator);
    }
    let pending = r.pending()?;
    println!("{} application(s) waiting", pending.len());
    for (path, _) in pending {
        println!("  {}", path.display());
    }
    Ok(())
}

fn approve(args: &[String]) -> Result<(), String> {
    let r = load_registrar(args)?;
    let id = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .ok_or("usage: enclave-registrar approve ID")?;
    let from = r.cfg.queue.join(format!("{id}.bin"));
    let to_dir = r.cfg.queue.join("approved");
    std::fs::create_dir_all(&to_dir).map_err(|e| e.to_string())?;
    let to = to_dir.join(format!("{id}.bin"));
    std::fs::rename(&from, &to).map_err(|e| format!("{id}: {e}"))?;
    println!("{id} approved: the next list takes it");
    Ok(())
}
