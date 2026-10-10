//! The vault's side of `netd` (`docs/15-client.md` §1.1a).
//!
//! In server mode the vault starts `enclave-netd` (from next to its own
//! binary) before it confines itself, and talks to it over the child's stdin
//! and stdout. After that the vault denies itself every TCP connection
//! (Landlock), so the process holding the keys can't reach the network at
//! all: only sealed requests and replies cross to and from netd.

use enclave_ipc::frame;
use enclave_ipc::net::{NetReply, NetRequest};
use enclave_net::NetError;
use enclave_net::transport::{ServerId, Transport};
use enclave_rpc::ServerKey;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc, oneshot};

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Result<Vec<u8>, String>>>>>;

/// Tor bridges for this profile (censorship mode, `docs/09-transport.md`
/// §7), in the profile directory: `builtin` (Tor's obfs4 bridges),
/// `snowflake` (its Snowflake bridges), or bridge lines (obfs4, WebTunnel,
/// Snowflake). Kept
/// outside the sealed profile because netd starts Tor before the profile is
/// unlocked (Tor Browser keeps its bridges unencrypted too).
pub const BRIDGES_FILE: &str = "tor-bridges.txt";

/// netd's arguments for the bridges in `profile` (none without the file).
pub fn bridge_args(profile: &std::path::Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(profile.join(BRIDGES_FILE)) else {
        return Vec::new();
    };
    match text.trim() {
        "builtin" => return vec!["--builtin-bridges".into()],
        "snowflake" => return vec!["--snowflake".into()],
        _ => {}
    }
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .flat_map(|l| ["--bridge".to_string(), l.to_string()])
        .collect()
}

/// Check what someone typed as bridges: empty (none), `builtin`,
/// `snowflake`, or obfs4, WebTunnel or Snowflake bridge lines (`Bridge `
/// prefixes dropped, as bridges.torproject.org gives them). The text to
/// keep, or why not.
pub fn normalize_bridges(text: &str) -> Result<String, String> {
    let t = text.trim();
    if t.is_empty() || t == "builtin" || t == "snowflake" {
        return Ok(t.into());
    }
    let mut lines = Vec::new();
    for l in t.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let l = l.strip_prefix("Bridge ").unwrap_or(l).trim();
        let fields: Vec<&str> = l.split_whitespace().collect();
        // What each kind of line can't do without.
        let needs = match fields.first() {
            Some(&"obfs4") => "cert=",
            Some(&"webtunnel") | Some(&"snowflake") => "url=",
            _ => {
                return Err(
                    "Only obfs4, WebTunnel and Snowflake bridges work here. Get some at bridges.torproject.org."
                        .into(),
                );
            }
        };
        if fields.len() < 4 || !fields.iter().any(|f| f.starts_with(needs)) {
            return Err(
                "That doesn't look like a whole bridge line. Copy each line in full.".into(),
            );
        }
        lines.push(fields.join(" "));
    }
    Ok(lines.join("\n"))
}

/// Spare netd processes started with the first. The confined vault can't
/// start programs, so if netd dies the next request goes to a spare that is
/// already running; when all are gone, the network is down until restart.
pub const SPARES: usize = 1;

/// A [`Transport`] that forwards to a netd child process (the first one
/// still running, of the helper and its spares).
pub struct PipeTransport {
    links: Vec<Link>,
    /// The ticketbooks the mixnet client was connected with, so a spare
    /// that takes over connects with them too.
    tickets: std::sync::Mutex<Option<Vec<Vec<u8>>>>,
}

struct Link {
    /// Its mixnet client is connected (or was never waiting for tickets).
    connected: AtomicBool,
    next: AtomicU32,
    out: mpsc::UnboundedSender<Vec<u8>>,
    pending: Pending,
    alive: Arc<AtomicBool>,
    // Kept with the transport. When it goes, netd's stdin closes and netd
    // exits by itself once what was sent one way has left (at most 10 s),
    // so it isn't killed.
    _child: Mutex<Child>,
}

/// Where `enclave-netd` should be: next to this executable.
pub fn netd_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.with_file_name(format!("enclave-netd{}", std::env::consts::EXE_SUFFIX));
    p.exists().then_some(p)
}

impl Link {
    fn spawn(
        bin: &std::path::Path,
        servers: &[(ServerId, String)],
        extra: &[String],
    ) -> std::io::Result<Self> {
        let mut cmd = Command::new(bin);
        enclave_platform::process::no_window(cmd.as_std_mut());
        cmd.args(extra);
        for (id, addr) in servers {
            let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
            cmd.args(["--server", &format!("{hex}={addr}")]);
        }
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        let (out, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        tokio::spawn(async move {
            while let Some(body) = rx.recv().await {
                if frame::write_frame(&mut stdin, &body).await.is_err() {
                    break;
                }
            }
        });
        let p = Arc::clone(&pending);
        let a = Arc::clone(&alive);
        tokio::spawn(async move {
            while let Ok(body) = frame::read_frame(&mut stdout).await {
                let Ok(reply) = NetReply::decode(&body) else {
                    break;
                };
                if let Some(tx) = p.lock().await.remove(&reply.id) {
                    let _ = tx.send(reply.result);
                }
            }
            // netd went away: mark it, then fail everything still waiting.
            a.store(false, Ordering::SeqCst);
            p.lock().await.clear();
        });
        Ok(Self {
            connected: AtomicBool::new(false),
            next: AtomicU32::new(1),
            out,
            pending,
            alive,
            _child: Mutex::new(child),
        })
    }
}

impl PipeTransport {
    /// Start netd, and [`SPARES`] more, knowing `servers` (id and route,
    /// `nym:ADDRESS` or `HOST:PORT`), with `extra` arguments. Must run
    /// inside a tokio runtime, before the vault confines itself.
    pub fn spawn(
        bin: &std::path::Path,
        servers: &[(ServerId, String)],
        extra: &[String],
    ) -> std::io::Result<Self> {
        let mut links = vec![Link::spawn(bin, servers, extra)?];
        links.extend((0..SPARES).filter_map(|_| Link::spawn(bin, servers, extra).ok()));
        // Without --await-tickets every netd's client connects by itself.
        let waits = extra.iter().any(|a| a == "--await-tickets");
        for l in &links {
            l.connected.store(!waits, Ordering::SeqCst);
        }
        Ok(Self {
            links,
            tickets: std::sync::Mutex::new(None),
        })
    }

    /// netd processes still running.
    pub fn alive(&self) -> usize {
        self.links
            .iter()
            .filter(|l| l.alive.load(Ordering::SeqCst))
            .count()
    }

    async fn call(&self, make: impl FnOnce(u32) -> NetRequest) -> enclave_net::Result<Vec<u8>> {
        let l = self
            .links
            .iter()
            .find(|l| l.alive.load(Ordering::SeqCst))
            .ok_or(NetError::Unavailable("netd stopped"))?;
        // A spare taking over connects with the tickets the first had.
        let tickets = self.tickets.lock().ok().and_then(|t| t.clone());
        if let Some(t) = tickets
            && !l.connected.swap(true, Ordering::SeqCst)
        {
            Self::send(l, |id| NetRequest::Connect { id, tickets: t }).await?;
        }
        Self::send(l, make).await
    }

    async fn send(l: &Link, make: impl FnOnce(u32) -> NetRequest) -> enclave_net::Result<Vec<u8>> {
        let id = l.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        l.pending.lock().await.insert(id, tx);
        // A request added after the reader gave up would wait forever.
        if !l.alive.load(Ordering::SeqCst) {
            l.pending.lock().await.remove(&id);
            return Err(NetError::Unavailable("netd stopped"));
        }
        if l.out.send(make(id).encode()).is_err() {
            l.alive.store(false, Ordering::SeqCst);
            return Err(NetError::Unavailable("netd stopped"));
        }
        match rx.await {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(e)) => Err(NetError::Unreachable(e)),
            Err(_) => Err(NetError::Unavailable("netd stopped")),
        }
    }
}

#[async_trait::async_trait]
impl Transport for PipeTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        let server = *server;
        self.call(|id| NetRequest::Exchange {
            id,
            server,
            bytes: request,
        })
        .await
    }

    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<ServerKey> {
        let server = *server;
        let b = self.call(|id| NetRequest::ServerKey { id, server }).await?;
        enclave_net::transport::decode_server_key(&b)
    }

    async fn exchange_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> enclave_net::Result<Option<Vec<u8>>> {
        let server = *server;
        // An empty reply: it went one way (a real reply is never empty).
        let b = self
            .call(|id| NetRequest::Oneway {
                id,
                server,
                bytes: request,
            })
            .await?;
        Ok((!b.is_empty()).then_some(b))
    }

    async fn fetch(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
    ) -> enclave_net::Result<(u16, Vec<u8>)> {
        let (method, url) = (method.to_string(), url.to_string());
        let b = self
            .call(|id| NetRequest::Fetch {
                id,
                method,
                url,
                body,
            })
            .await?;
        if b.len() < 2 {
            return Err(NetError::BadReply);
        }
        Ok((u16::from_be_bytes([b[0], b[1]]), b[2..].to_vec()))
    }

    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> enclave_net::Result<Vec<u8>> {
        let (gate, token) = (gate.to_string(), token.to_vec());
        self.call(|id| NetRequest::BuyTickets { id, gate, token })
            .await
    }

    async fn connect_mixnet(&self, tickets: Vec<Vec<u8>>) -> enclave_net::Result<()> {
        if let Ok(mut t) = self.tickets.lock() {
            *t = Some(tickets);
        }
        // `call` connects the netd in use first.
        self.call(|id| NetRequest::Connect {
            id,
            tickets: Vec::new(),
        })
        .await
        .map(|_| ())
    }

    async fn tor_status(&self) -> enclave_net::Result<u8> {
        let b = self.call(|id| NetRequest::TorStatus { id }).await?;
        b.first().copied().ok_or(NetError::BadReply)
    }

    async fn tickets_spent(&self) -> enclave_net::Result<u64> {
        let b = self.call(|id| NetRequest::TicketsSpent { id }).await?;
        Ok(u64::from_be_bytes(
            b.as_slice().try_into().map_err(|_| NetError::BadReply)?,
        ))
    }

    fn require_private(&self, on: bool) {
        let body = NetRequest::RequirePrivate { on }.encode();
        for l in &self.links {
            let _ = l.out.send(body.clone());
        }
    }

    fn use_fallback(&self, on: bool) {
        let body = NetRequest::UseFallback { on }.encode();
        for l in &self.links {
            let _ = l.out.send(body.clone());
        }
    }

    fn set_pacing(&self, pacing: enclave_net::transport::Pacing) {
        // Only the first netd running has a mixnet client in use; the
        // spares get it too, so one taking over paces the same way.
        let body = NetRequest::SetPacing {
            pacing: pacing.encode().to_vec(),
        }
        .encode();
        for l in &self.links {
            let _ = l.out.send(body.clone());
        }
    }

    fn set_route(&self, server: ServerId, route: enclave_net::transport::Route) {
        // Every netd, so a spare taking over knows the route too.
        let body = NetRequest::SetRoute {
            server,
            route: route.to_string(),
        }
        .encode();
        for l in &self.links {
            let _ = l.out.send(body.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridges_are_checked_and_become_arguments() {
        assert_eq!(normalize_bridges("  ").as_deref(), Ok(""));
        assert_eq!(normalize_bridges("builtin").as_deref(), Ok("builtin"));
        let line =
            "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0";
        assert_eq!(
            normalize_bridges(&format!("Bridge {line}\n\n{line}  ")).as_deref(),
            Ok(format!("{line}\n{line}").as_str())
        );
        assert!(normalize_bridges("snowflake 192.0.2.3:80 AAAA").is_err());
        assert!(normalize_bridges("meek_lite 192.0.2.20:80 url=https://x/ front=y").is_err());
        assert!(normalize_bridges("obfs4 192.0.2.1:443").is_err());
        assert_eq!(normalize_bridges(" snowflake ").as_deref(), Ok("snowflake"));
        let wt = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.org/a ver=0.0.1";
        assert_eq!(normalize_bridges(wt).as_deref(), Ok(wt));
        assert!(normalize_bridges("webtunnel [2001:db8::1]:443 0123 ver=0.0.1").is_err());

        let dir = std::env::temp_dir().join(format!("enclave-bridges-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(bridge_args(&dir).is_empty());
        std::fs::write(dir.join(BRIDGES_FILE), "builtin").unwrap();
        assert_eq!(bridge_args(&dir), ["--builtin-bridges"]);
        std::fs::write(dir.join(BRIDGES_FILE), "snowflake\n").unwrap();
        assert_eq!(bridge_args(&dir), ["--snowflake"]);
        std::fs::write(dir.join(BRIDGES_FILE), format!("{line}\n{line}")).unwrap();
        assert_eq!(bridge_args(&dir), ["--bridge", line, "--bridge", line]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
