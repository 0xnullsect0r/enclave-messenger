//! The call relay (`docs/11-calls.md` §3, `docs/12-servers.md` §5).
//!
//! ```text
//! enclave-relay init            [--config FILE]   create keys; print the descriptor
//! enclave-relay run             [--config FILE]   serve (keys from disk)
//! enclave-relay show-descriptor [--config FILE]   print the peer descriptor (hex)
//! enclave-relay descriptor OUT  [--config FILE]   write the signed descriptor for the server list
//! enclave-relay healthcheck     [--config FILE]   exit 0 if `run` is alive
//! enclave-relay dev ADDR FAMILY [PEER_DESCRIPTOR_HEX ...]   random keys, nothing kept
//! ```
//!
//! A descriptor is `id (16) ‖ link_key (56) ‖ address (UTF-8)`, in hex;
//! peers are configured with each other's descriptors. Tickets are
//! requested over the mixnet in production; this binary serves the data
//! plane.
#![forbid(unsafe_code)]

use enclave_relay::keys::RelayKeys;
use enclave_relay::ledger::RedbSpent;
use enclave_relay::{Descriptor, Relay, serve};
use enclave_service::config::{ConfigError, flag, hex, unhex};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    relay: RelaySection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RelaySection {
    /// UDP address to bind.
    listen: SocketAddr,
    /// Address published in the descriptor (default: `listen`).
    public_addr: Option<SocketAddr>,
    /// Operator family: callers pick relays from different families.
    family: String,
    /// Operator name (in the signed descriptor).
    operator: String,
    /// Key directory.
    keys_dir: PathBuf,
    /// Spent-token ledger and the heartbeat file.
    data_dir: PathBuf,
    /// Peer relays' descriptors (hex).
    peers: Vec<String>,
    /// Proof-of-work effort a ticket costs (`enclave_relay::TICKET_EFFORT`).
    ticket_effort: u32,
}

impl Default for RelaySection {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 51820)),
            public_addr: None,
            family: String::new(),
            operator: String::new(),
            keys_dir: PathBuf::from("/var/lib/enclave/relay-keys"),
            data_dir: PathBuf::from("/var/lib/enclave/relay"),
            peers: Vec::new(),
            ticket_effort: enclave_relay::TICKET_EFFORT,
        }
    }
}

/// Seconds after which a heartbeat counts as dead.
const HEARTBEAT_STALE_SECS: u64 = 90;

fn load_config(args: &[String]) -> Result<FileConfig, String> {
    let path = flag(args, "--config").map(PathBuf::from);
    let cfg: FileConfig = enclave_service::config::load(path.as_deref(), std::env::vars())
        .map_err(|e: ConfigError| e.to_string())?;
    if cfg.relay.family.is_empty() {
        return Err("set relay.family (the operator family of this relay)".into());
    }
    Ok(cfg)
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

/// `id(16) ‖ link_key(56) ‖ addr (utf-8)`.
fn encode(d: &Descriptor) -> String {
    hex(&[&d.id[..], &d.link_key[..], d.addr.to_string().as_bytes()].concat())
}

fn decode(s: &str, family: &str) -> Option<Descriptor> {
    let b = unhex(s)?;
    let addr = std::str::from_utf8(b.get(72..)?).ok()?.parse().ok()?;
    Some(Descriptor {
        id: b.get(..16)?.try_into().ok()?,
        family: family.into(),
        addr,
        link_key: b.get(16..72)?.try_into().ok()?,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let result = match cmd {
        "init" => init(&args),
        "run" => runtime().and_then(|rt| rt.block_on(run(&args))),
        "show-descriptor" => show_descriptor(&args),
        "descriptor" => write_descriptor(&args),
        "healthcheck" => healthcheck(&args),
        "dev" => runtime().and_then(|rt| rt.block_on(dev(&args[1..]))),
        "" | "--help" | "-h" | "help" => {
            eprintln!(
                "usage: enclave-relay init|run|show-descriptor|healthcheck [--config FILE]\n       enclave-relay dev ADDR FAMILY [PEER_DESCRIPTOR_HEX ...]"
            );
            Ok(())
        }
        // Old form: `enclave-relay ADDR FAMILY [PEER ...]`.
        _ => runtime().and_then(|rt| rt.block_on(dev(&args))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-relay: {e}");
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

fn descriptor(cfg: &FileConfig, keys: &RelayKeys) -> Descriptor {
    Descriptor {
        id: keys.id,
        family: cfg.relay.family.clone(),
        addr: cfg.relay.public_addr.unwrap_or(cfg.relay.listen),
        link_key: keys.link_secret().public().0,
    }
}

fn init(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let keys = RelayKeys::init(&cfg.relay.keys_dir, today()).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cfg.relay.data_dir).map_err(|e| e.to_string())?;
    println!("{}", encode(&descriptor(&cfg, &keys)));
    eprintln!(
        "keys created in {}; back this directory up somewhere safe and offline",
        cfg.relay.keys_dir.display()
    );
    Ok(())
}

fn show_descriptor(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let keys = RelayKeys::load(&cfg.relay.keys_dir).map_err(|e| e.to_string())?;
    println!("{}", encode(&descriptor(&cfg, &keys)));
    Ok(())
}

/// The signed descriptor (`enclave_federation::RelayDescriptor`) operators
/// submit for the foundation's list.
fn write_descriptor(args: &[String]) -> Result<(), String> {
    let out = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .ok_or("usage: enclave-relay descriptor OUT")?;
    let cfg = load_config(args)?;
    let mut keys = RelayKeys::load(&cfg.relay.keys_dir).map_err(|e| e.to_string())?;
    keys.advance(today()).map_err(|e| e.to_string())?;
    let addr = cfg
        .relay
        .public_addr
        .unwrap_or(cfg.relay.listen)
        .to_string();
    let d = keys
        .descriptor(&cfg.relay.operator, &cfg.relay.family, &addr, now())
        .map_err(|e| e.to_string())?;
    std::fs::write(out, d.encode()).map_err(|e| format!("{out}: {e}"))?;
    println!("{}", hex(&d.id()));
    Ok(())
}

fn heartbeat_path(cfg: &FileConfig) -> PathBuf {
    cfg.relay.data_dir.join("alive")
}

fn healthcheck(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let t = std::fs::read_to_string(heartbeat_path(&cfg)).map_err(|e| e.to_string())?;
    let t: u64 = t.trim().parse().map_err(|_| "bad heartbeat file")?;
    if now().saturating_sub(t) > HEARTBEAT_STALE_SECS {
        return Err("heartbeat is stale".into());
    }
    Ok(())
}

async fn run(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let mut keys = RelayKeys::load(&cfg.relay.keys_dir).map_err(|e| e.to_string())?;
    keys.advance(today()).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cfg.relay.data_dir).map_err(|e| e.to_string())?;
    let spent = RedbSpent::open(&cfg.relay.data_dir.join("relay.redb"))
        .map_err(|e| format!("ledger: {e}"))?;
    let desc = descriptor(&cfg, &keys);
    let mut relay = Relay::with_keys(
        desc.id,
        &cfg.relay.family,
        desc.addr,
        keys.link_secret(),
        keys.tickets(),
        Box::new(spent),
    )
    .map_err(|e| e.to_string())?;
    relay.set_ticket_effort(cfg.relay.ticket_effort);
    for p in &cfg.relay.peers {
        let d = decode(p, "peer").ok_or_else(|| format!("malformed peer descriptor {p}"))?;
        relay.add_peer(&d).map_err(|e| e.to_string())?;
    }
    let socket = tokio::net::UdpSocket::bind(cfg.relay.listen)
        .await
        .map_err(|e| format!("can't bind {}: {e}", cfg.relay.listen))?;
    eprintln!(
        "enclave-relay {} ({}) on {}",
        hex(&desc.id),
        cfg.relay.family,
        cfg.relay.listen
    );
    let relay = Arc::new(Mutex::new(relay));
    // Every 30 s: the heartbeat; ticket keys at midnight UTC; expiry.
    {
        let relay = Arc::clone(&relay);
        let beat = heartbeat_path(&cfg);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                let _ = std::fs::write(&beat, now().to_string());
                match keys.advance(today()) {
                    Ok(true) => relay.lock().await.set_ticket_keys(keys.tickets()),
                    Ok(false) => {}
                    Err(e) => eprintln!("ticket-key rotation failed: {e}"),
                }
                relay.lock().await.expire(now());
            }
        });
    }
    tokio::select! {
        r = serve(relay, socket) => r.map_err(|e| e.to_string()),
        _ = shutdown_signal() => {
            eprintln!("enclave-relay: stopped");
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
    let (Some(addr), Some(family)) = (args.first(), args.get(1)) else {
        return Err("usage: enclave-relay dev ADDR FAMILY [PEER_DESCRIPTOR_HEX ...]".into());
    };
    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .map_err(|e| e.to_string())?;
    let local = socket.local_addr().map_err(|e| e.to_string())?;
    let id: [u8; 16] = enclave_crypto::rng::HedgedRng::new()
        .and_then(|mut r| r.array("relay/id"))
        .map_err(|e| e.to_string())?;
    let mut relay = Relay::new(id, family, local, today()).map_err(|e| e.to_string())?;
    for p in &args[2..] {
        match decode(p, "peer") {
            Some(d) => relay.add_peer(&d).map_err(|e| e.to_string())?,
            None => eprintln!("ignoring malformed peer descriptor"),
        }
    }
    println!("{}", encode(relay.descriptor()));
    eprintln!("enclave-relay ({family}) on {local}");
    serve(Arc::new(Mutex::new(relay)), socket)
        .await
        .map_err(|e| e.to_string())
}
