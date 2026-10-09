//! The push relay (`docs/10-push.md`).
//!
//! ```text
//! enclave-push-relay init        [--config FILE]   create the key chain
//! enclave-push-relay run         [--config FILE]   serve (keys from disk)
//! enclave-push-relay show-key    [--config FILE]   print the published keys (hex)
//! enclave-push-relay healthcheck [--config FILE]   exit 0 if the relay accepts connections
//! enclave-push-relay dev [--listen ADDR]           random key, nothing persisted
//! ```
//!
//! Servers' push egresses connect with `u32 BE length ‖ sealed token` per
//! wake; in a deployment that port is reachable only from the Nym ingress.
//! `run` rotates keys at 30-day epochs (the previous epoch's key is kept 7
//! days) and writes the current and next public keys to
//! `public_dir/push-relay-keys.bin` for the foundation's list.
//!
//! Delivery to APNs needs an `[apns]` section (team id, key id, the `.p8`
//! key file, the app's bundle id) and to FCM an `[fcm]` section (the
//! service-account JSON file); without them only UnifiedPush is delivered.

use enclave_push_relay::deliver::{ApnsConfig, Deliverer, FcmConfig};
use enclave_push_relay::keys::RelayKeys;
use enclave_push_relay::{Relay, RelaySecret, SEALED_LEN, WAKE_LEN};
use enclave_service::config::{ConfigError, flag, hex};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    relay: RelaySection,
    apns: Option<ApnsSection>,
    fcm: Option<FcmSection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApnsSection {
    team_id: String,
    key_id: String,
    /// The `.p8` key.
    key_file: PathBuf,
    /// The app's bundle id.
    topic: String,
    /// `https://api.push.apple.com`, or the sandbox for development builds.
    #[serde(default = "apns_endpoint")]
    endpoint: String,
}

fn apns_endpoint() -> String {
    "https://api.push.apple.com".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FcmSection {
    /// The service account's JSON key file.
    service_account_file: PathBuf,
    #[serde(default = "fcm_endpoint")]
    endpoint: String,
}

fn fcm_endpoint() -> String {
    "https://fcm.googleapis.com".into()
}

fn deliverer(cfg: &FileConfig) -> Result<Deliverer, String> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let apns = match &cfg.apns {
        Some(a) => Some(ApnsConfig {
            team_id: a.team_id.clone(),
            key_id: a.key_id.clone(),
            key: read(&a.key_file)?,
            topic: a.topic.clone(),
            endpoint: a.endpoint.clone(),
        }),
        None => None,
    };
    let fcm = match &cfg.fcm {
        Some(f) => {
            let mut c = FcmConfig::from_service_account(&read(&f.service_account_file)?)
                .map_err(|e| e.to_string())?;
            c.endpoint = f.endpoint.clone();
            Some(c)
        }
        None => None,
    };
    Deliverer::new(apns, fcm).map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RelaySection {
    /// Where wakes arrive.
    listen: SocketAddr,
    /// Key directory.
    keys_dir: PathBuf,
    /// Where the published keys are written.
    public_dir: PathBuf,
}

impl Default for RelaySection {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 7445)),
            keys_dir: PathBuf::from("/var/lib/enclave/push-keys"),
            public_dir: PathBuf::from("/var/lib/enclave/public"),
        }
    }
}

fn load_config(args: &[String]) -> Result<FileConfig, String> {
    let path = flag(args, "--config").map(PathBuf::from);
    enclave_service::config::load(path.as_deref(), std::env::vars())
        .map_err(|e: ConfigError| e.to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn today() -> u32 {
    (now() / 86_400) as u32
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("dev");
    let result = match cmd {
        "init" => init(&args),
        "run" => runtime().and_then(|rt| rt.block_on(run(&args))),
        "show-key" => show_key(&args),
        "healthcheck" => runtime().and_then(|rt| rt.block_on(healthcheck(&args))),
        "dev" => runtime().and_then(|rt| rt.block_on(dev(&args))),
        "--help" | "-h" | "help" => {
            eprintln!(
                "usage: enclave-push-relay init|run|show-key|healthcheck [--config FILE]\n       enclave-push-relay dev [--listen ADDR]"
            );
            Ok(())
        }
        // Old form: `enclave-push-relay --listen ADDR`.
        _ => runtime().and_then(|rt| rt.block_on(dev(&args))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-push-relay: {e}");
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

fn published_hex(keys: &RelayKeys) -> String {
    keys.published()
        .iter()
        .map(|k| hex(&k.encode()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn init(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let keys = RelayKeys::init(&cfg.relay.keys_dir, today()).map_err(|e| e.to_string())?;
    println!("{}", published_hex(&keys));
    eprintln!(
        "keys created in {}; back this directory up somewhere safe and offline",
        cfg.relay.keys_dir.display()
    );
    Ok(())
}

fn show_key(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let mut keys = RelayKeys::load(&cfg.relay.keys_dir).map_err(|e| e.to_string())?;
    keys.advance(today()).map_err(|e| e.to_string())?;
    println!("{}", published_hex(&keys));
    Ok(())
}

async fn healthcheck(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(cfg.relay.listen),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Write the current and next public keys for the foundation's list.
fn publish(keys: &RelayKeys, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let bytes: Vec<u8> = keys.published().iter().flat_map(|k| k.encode()).collect();
    let path = dir.join("push-relay-keys.bin");
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

async fn run(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let mut keys = RelayKeys::load(&cfg.relay.keys_dir).map_err(|e| e.to_string())?;
    keys.advance(today()).map_err(|e| e.to_string())?;
    publish(&keys, &cfg.relay.public_dir)?;
    let out = Arc::new(deliverer(&cfg)?);
    let relay = Arc::new(Mutex::new(Relay::new(keys.secrets())));
    eprintln!(
        "enclave-push-relay (key epochs {:?}, delivering to {:?}) listening on {}",
        relay.lock().await.epochs(),
        out.platforms(),
        cfg.relay.listen
    );
    // Once a minute: rotate at epoch boundaries, drop the old key when the
    // overlap ends.
    {
        let relay = Arc::clone(&relay);
        let public_dir = cfg.relay.public_dir.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                match keys.advance(today()) {
                    Ok(true) => {
                        relay.lock().await.set_keys(keys.secrets());
                        if let Err(e) = publish(&keys, &public_dir) {
                            eprintln!("couldn't publish keys: {e}");
                        }
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("key rotation failed: {e}"),
                }
            }
        });
    }
    let listener = tokio::net::TcpListener::bind(cfg.relay.listen)
        .await
        .map_err(|e| format!("can't listen on {}: {e}", cfg.relay.listen))?;
    tokio::select! {
        r = serve(listener, relay, out) => r,
        _ = shutdown_signal() => {
            eprintln!("enclave-push-relay: stopped");
            Ok(())
        }
    }
}

async fn shutdown_signal() {
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

async fn dev(args: &[String]) -> Result<(), String> {
    let listen = flag(args, "--listen").unwrap_or_else(|| "127.0.0.1:7445".into());
    let epoch = flag(args, "--epoch")
        .and_then(|e| e.parse().ok())
        .unwrap_or(1);
    let mut rng = enclave_crypto::rng::HedgedRng::new().map_err(|e| e.to_string())?;
    let key = RelaySecret::generate(epoch, &mut rng).map_err(|e| e.to_string())?;
    println!("relay key: {}", hex(&key.public().encode()));
    let relay = Arc::new(Mutex::new(Relay::new(vec![key])));
    let out = Arc::new(Deliverer::new(None, None).map_err(|e| e.to_string())?);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| format!("can't listen on {listen}: {e}"))?;
    serve(listener, relay, out).await
}

async fn serve(
    listener: tokio::net::TcpListener,
    relay: Arc<Mutex<Relay>>,
    out: Arc<Deliverer>,
) -> Result<(), String> {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let relay = Arc::clone(&relay);
        let out = Arc::clone(&out);
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n != SEALED_LEN && n != WAKE_LEN {
                    return;
                }
                let mut sealed = vec![0u8; n];
                if sock.read_exact(&mut sealed).await.is_err() {
                    return;
                }
                let d = relay.lock().await.wake(&sealed, now());
                if let Some(d) = d {
                    // Each on its own, so a slow service holds up no other
                    // wake. Failures are only counted (no logs).
                    let out = Arc::clone(&out);
                    tokio::spawn(async move {
                        let _ = out.deliver(&d).await;
                    });
                }
            }
        });
    }
}
