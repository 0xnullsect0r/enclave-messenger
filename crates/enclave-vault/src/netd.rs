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

/// Spare netd processes started with the first. The confined vault can't
/// start programs, so if netd dies the next request goes to a spare that is
/// already running; when all are gone, the network is down until restart.
pub const SPARES: usize = 1;

/// A [`Transport`] that forwards to a netd child process (the first one
/// still running, of the helper and its spares).
pub struct PipeTransport {
    links: Vec<Link>,
}

struct Link {
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
        Ok(Self { links })
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
