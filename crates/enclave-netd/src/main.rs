//! `enclave-netd --server HEXID=nym:ADDRESS … --server HEXID=HOST:PORT … [--nymd PATH] [--mixnet] [--nym-env] [--await-tickets] [--tor DIR [--tord PATH] [--tor-direct] [--bridge LINE]… [--builtin-bridges]] [--report]`
//!
//! Started by the vault, never by hand. Holds no keys: it carries sealed
//! requests from the vault (stdin) to servers and their sealed replies back
//! (stdout), and fetches servers' public request keys. A server named by a
//! Nym address is reached over the mixnet (`NymTransport`) through
//! `enclave-nymd`, a mixnet client netd starts next to itself (nym-sdk
//! can't be linked here: `docs/09-transport.md` §1); others over the
//! development TCP transport. The vault adds or changes routes as it
//! learns them (`NetRequest::SetRoute`: the server list, descriptors); a
//! Nym route needs the mixnet client, which netd starts only when a Nym
//! route is given at start. It confines itself first: no core dumps, not
//! dumpable, `no_new_privs`, and (Linux) no filesystem access at all, after
//! starting nymd; with only Nym routes it can't open a socket at all.

#![forbid(unsafe_code)]

use enclave_ipc::frame;
use enclave_ipc::net::{NetReply, NetRequest};
use enclave_net::NetError;
use enclave_net::transport::{
    NymTransport, Route, ServerId, TcpTransport, Transport, encode_server_key,
};
use std::collections::{HashMap, HashSet};
use std::process::ExitCode;
use std::sync::Arc;

/// How long netd waits on exit for what was sent to leave.
const EXIT_FLUSH: std::time::Duration = std::time::Duration::from_secs(10);

/// `--server` routes: TCP addresses, Nym addresses and onion services.
fn parse_servers(
    args: &[String],
) -> (
    HashMap<ServerId, std::net::SocketAddr>,
    HashMap<ServerId, String>,
    HashMap<ServerId, String>,
) {
    let mut tcp = HashMap::new();
    let mut nym = HashMap::new();
    let mut onion = HashMap::new();
    for p in args.windows(2).filter(|p| p[0] == "--server") {
        match enclave_net::transport::parse_route(&p[1]) {
            Some((id, Route::Tcp(a))) => {
                tcp.insert(id, a);
            }
            Some((id, Route::Nym(a))) => {
                nym.insert(id, a);
            }
            Some((id, Route::Onion(h))) => {
                onion.insert(id, h);
            }
            None => eprintln!("enclave-netd: --server {}: not a route", p[1]),
        }
    }
    (tcp, nym, onion)
}

/// Each server over the transport its route names.
struct Routed {
    tcp: TcpTransport,
    /// Whether this netd may open TCP connections: only when it was given
    /// TCP routes at start (development). Over Nym it needs no socket.
    tcp_allowed: bool,
    /// The mixnet transport, once the client is connected.
    nym: std::sync::OnceLock<NymTransport>,
    /// A mixnet client started (Nym routes are usable now or once it
    /// connects).
    has_nym: bool,
    /// A client waiting for its tickets (`--await-tickets`) and the Nym
    /// routes it will be given when it connects.
    waiting: tokio::sync::Mutex<Option<Waiting>>,
    pending_routes: std::sync::Mutex<HashMap<ServerId, String>>,
    over_nym: std::sync::RwLock<HashSet<ServerId>>,
    /// Whether Tor is in front of the mixnet client (`--tor`).
    tor: bool,
    /// Maximum privacy (`Transport::require_private`): the mixnet behind
    /// Tor only.
    private: std::sync::atomic::AtomicBool,
    /// Servers' onion services (from their descriptors): the fallback
    /// route, carried by nymd over its Tor.
    onion: std::sync::RwLock<HashMap<ServerId, String>>,
    /// The user chose the fallback route (`Transport::use_fallback`).
    fallback: std::sync::atomic::AtomicBool,
    /// Tor didn't come up (the network may be blocking it): no mixnet
    /// client was started.
    tor_blocked: bool,
}

impl Routed {
    /// The onion service to reach `server` at, when the user chose the
    /// fallback route and Maximum privacy is off.
    fn onion_for(&self, server: &ServerId) -> Option<String> {
        use std::sync::atomic::Ordering::SeqCst;
        if !self.fallback.load(SeqCst) || self.private.load(SeqCst) {
            return None;
        }
        self.onion.read().ok()?.get(server).cloned()
    }

    /// One request over the fallback route (nymd's Tor), connected or not.
    async fn via_tor(&self, host: &str, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        if let Some(n) = self.nym.get() {
            return n.exchange_tor(host, request).await;
        }
        match self.waiting.lock().await.as_mut() {
            Some(w) => w
                .exchange_tor(host, enclave_net::transport::ONION_PORT, &request)
                .await
                .map_err(|e| NetError::Unreachable(e.to_string())),
            None => Err(NetError::Unavailable("no Tor")),
        }
    }

    fn pick(&self, server: &ServerId) -> enclave_net::Result<&dyn Transport> {
        let private = self.private.load(std::sync::atomic::Ordering::SeqCst);
        let over_nym = self
            .over_nym
            .read()
            .map(|s| s.contains(server))
            .unwrap_or(false);
        match self.nym.get() {
            Some(_) if over_nym && private && !self.tor => Err(NetError::Unavailable(
                "Maximum privacy needs Tor, which isn't available on this device",
            )),
            Some(n) if over_nym => Ok(n),
            None if over_nym => Err(NetError::Unavailable(
                "the mixnet client is waiting for its tickets",
            )),
            _ if private => Err(NetError::Unavailable(
                "Maximum privacy needs the private route",
            )),
            _ => Ok(&self.tcp),
        }
    }
}

/// A nymd started with `--await-tickets`, not connected yet.
type Waiting = enclave_nym::pipe::Starting<
    Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
>;

#[async_trait::async_trait]
impl Transport for Routed {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        if let Some(h) = self.onion_for(server) {
            return self.via_tor(&h, request).await;
        }
        self.pick(server)?.exchange(server, request).await
    }

    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<enclave_rpc::ServerKey> {
        if let Some(h) = self.onion_for(server) {
            let bundle = self.via_tor(&h, Vec::new()).await?;
            return enclave_net::transport::verify_key_bundle(server, &bundle, self.now());
        }
        self.pick(server)?.server_key(server).await
    }

    async fn exchange_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> enclave_net::Result<Option<Vec<u8>>> {
        if let Some(h) = self.onion_for(server) {
            return self.via_tor(&h, request).await.map(Some);
        }
        self.pick(server)?.exchange_oneway(server, request).await
    }

    fn use_fallback(&self, on: bool) {
        self.fallback.store(on, std::sync::atomic::Ordering::SeqCst);
    }

    async fn tor_status(&self) -> enclave_net::Result<u8> {
        Ok(if self.tor_blocked {
            2
        } else if self.tor {
            1
        } else {
            0
        })
    }

    fn set_pacing(&self, pacing: enclave_net::transport::Pacing) {
        if let Some(n) = self.nym.get() {
            n.set_pacing(pacing);
        }
    }

    async fn flush(&self, within: std::time::Duration) -> enclave_net::Result<bool> {
        match self.nym.get() {
            Some(n) => n.flush(within).await,
            None => Ok(true),
        }
    }

    async fn fetch(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
    ) -> enclave_net::Result<(u16, Vec<u8>)> {
        if let Some(n) = self.nym.get() {
            return n.fetch(method, url, body).await;
        }
        match self.waiting.lock().await.as_mut() {
            Some(w) => w
                .fetch(method, url, &body)
                .await
                .map_err(|e| NetError::Unreachable(e.to_string())),
            None => Err(NetError::Unavailable("no mixnet client")),
        }
    }

    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> enclave_net::Result<Vec<u8>> {
        if let Some(n) = self.nym.get() {
            return n.buy_tickets(gate, token).await;
        }
        match self.waiting.lock().await.as_mut() {
            Some(w) => w
                .buy(gate, token)
                .await
                .map_err(|e| NetError::Unreachable(e.to_string())),
            None => Err(NetError::Unavailable("no mixnet client")),
        }
    }

    async fn tickets_spent(&self) -> enclave_net::Result<u64> {
        match self.nym.get() {
            Some(n) => n.tickets_spent().await,
            None => Ok(0),
        }
    }

    async fn connect_mixnet(&self, tickets: Vec<Vec<u8>>) -> enclave_net::Result<()> {
        let Some(starting) = self.waiting.lock().await.take() else {
            return Ok(());
        };
        let driver = starting
            .connect(&tickets)
            .await
            .map_err(|e| NetError::Unreachable(format!("enclave-nymd: {e}")))?;
        let routes = self
            .pending_routes
            .lock()
            .map(|r| r.clone())
            .unwrap_or_default();
        let _ = self.nym.set(NymTransport::new(
            Arc::new(driver),
            routes,
            NymTransport::TIMEOUT,
        ));
        Ok(())
    }

    fn require_private(&self, on: bool) {
        self.private.store(on, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_route(&self, server: ServerId, route: Route) {
        // An onion service is kept aside, for when the user chooses the
        // fallback route; it needs nymd (and its Tor) to carry it.
        if let Route::Onion(h) = &route {
            if self.has_nym
                && let Ok(mut o) = self.onion.write()
            {
                o.insert(server, h.clone());
            }
            return;
        }
        let nym = matches!(route, Route::Nym(_));
        // Maximum privacy takes no route but the mixnet.
        if !nym && self.private.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // A Nym route without the mixnet client can't be used: the
        // server stays on the route it had.
        if (nym && !self.has_nym) || (!nym && !self.tcp_allowed) {
            return;
        }
        if let Ok(mut s) = self.over_nym.write() {
            if nym {
                s.insert(server);
            } else {
                s.remove(&server);
            }
        }
        match (self.nym.get(), &route) {
            (Some(n), Route::Nym(_)) => n.set_route(server, route),
            (None, Route::Nym(a)) => {
                if let Ok(mut r) = self.pending_routes.lock() {
                    r.insert(server, a.clone());
                }
            }
            _ => self.tcp.set_route(server, route),
        }
    }
}

/// How long Tor may take to bootstrap.
const TOR_BOOTSTRAP: std::time::Duration = std::time::Duration::from_secs(300);

/// Start `enclave-tord` keeping its state in `state`, and wait until Tor is
/// up (`docs/09-transport.md` §1). `direct` (development) dials without Tor.
async fn start_tord(
    bin: &std::path::Path,
    state: &str,
    direct: bool,
    bridges: &[String],
) -> Result<enclave_tord::launch::Running, String> {
    let secret: String = enclave_crypto::rng::HedgedRng::new()
        .and_then(|mut r| r.array::<32>("netd/tor-secret"))
        .map_err(|_| "no randomness".to_string())?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    enclave_tord::launch::start(
        bin,
        std::path::Path::new(state),
        secret,
        direct,
        false,
        bridges,
        TOR_BOOTSTRAP,
    )
    .await
}

/// A started `enclave-nymd`: connected, or waiting for its tickets.
enum Nymd {
    Ready(Box<enclave_nym::pipe::PipeDriver>),
    Waiting(Waiting),
}

/// Start `enclave-nymd` and drive it over its stdin and stdout; with `tor`,
/// it reaches its gateway and nym-api only through Tor. With
/// `await_tickets` it waits for the vault's tickets before connecting
/// (`docs/09-transport.md` §7).
async fn start_nymd(
    bin: &std::path::Path,
    env: bool,
    await_tickets: bool,
    tor: Option<&enclave_tord::launch::Running>,
) -> Result<(Nymd, tokio::process::Child), String> {
    let mut cmd = tokio::process::Command::new(bin);
    if env {
        cmd.arg("--env");
    }
    if await_tickets {
        cmd.arg("--await-tickets");
    }
    if let Some(t) = tor {
        // The gateway connection (our nym-gateway-client patch) and nym-api
        // requests (reqwest's proxy variables), only through Tor.
        cmd.envs(t.nymd_env());
        for v in enclave_tord::launch::Running::NYMD_ENV_REMOVE {
            cmd.env_remove(v);
        }
    }
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err("no pipes to enclave-nymd".into());
    };
    if await_tickets {
        return Ok((
            Nymd::Waiting(enclave_nym::pipe::Starting::new(
                Box::new(stdout),
                Box::new(stdin),
            )),
            child,
        ));
    }
    let driver = enclave_nym::pipe::PipeDriver::new(stdout, stdin)
        .await
        .map_err(|e| format!("enclave-nymd: {e}"))?;
    Ok((Nymd::Ready(Box::new(driver)), child))
}

fn main() -> ExitCode {
    let _ = enclave_sandbox::process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (tcp, over_nym, onion) = parse_servers(&args);
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    // Tor and the mixnet client start before the sandbox forbids starting
    // programs.
    let flag = |n: &str| {
        args.iter()
            .position(|a| a == n)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    // Bridges for Tor (censorship mode): bridge lines, or the built-in ones.
    let mut bridges: Vec<String> = args
        .windows(2)
        .filter(|p| p[0] == "--bridge")
        .flat_map(|p| ["--bridge".to_string(), p[1].clone()])
        .collect();
    if args.iter().any(|a| a == "--builtin-bridges") {
        bridges.push("--builtin-bridges".into());
    }
    // The mixnet client starts for Nym routes given now, or (`--mixnet`)
    // for ones the vault gives later, from the server list.
    let mixnet = !over_nym.is_empty() || args.iter().any(|a| a == "--mixnet");
    let mut tor_blocked = false;
    let tor = match flag("--tor") {
        Some(state) if mixnet => {
            let bin = flag("--tord").map(std::path::PathBuf::from).or_else(|| {
                std::env::current_exe().ok().map(|e| {
                    e.with_file_name(format!("enclave-tord{}", std::env::consts::EXE_SUFFIX))
                })
            });
            let started = match bin {
                Some(bin) => rt.block_on(start_tord(
                    &bin,
                    &state,
                    args.iter().any(|a| a == "--tor-direct"),
                    &bridges,
                )),
                None => Err("no enclave-tord".into()),
            };
            match started {
                Ok(t) => Some(t),
                // Tor is blocked here: stay up to say so (the vault offers
                // bridges), without a mixnet client.
                Err(e) if e == enclave_tord::launch::BLOCKED => {
                    eprintln!("enclave-netd: {e}");
                    tor_blocked = true;
                    None
                }
                Err(e) => {
                    // Without Tor the mixnet client doesn't start: the
                    // entry gateway would see this device's address.
                    eprintln!("enclave-netd: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        _ => None,
    };
    let nymd = if !mixnet || tor_blocked {
        None
    } else {
        let bin = args
            .iter()
            .position(|a| a == "--nymd")
            .and_then(|i| args.get(i + 1))
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::current_exe().ok().map(|e| {
                    e.with_file_name(format!("enclave-nymd{}", std::env::consts::EXE_SUFFIX))
                })
            });
        match bin {
            Some(bin) => match rt.block_on(start_nymd(
                &bin,
                args.iter().any(|a| a == "--nym-env"),
                args.iter().any(|a| a == "--await-tickets"),
                tor.as_ref(),
            )) {
                Ok(n) => Some(n),
                Err(e) => {
                    eprintln!("enclave-netd: {e}");
                    None
                }
            },
            None => None,
        }
    };
    // Nothing on disk is needed from here on, and over Nym (no TCP route)
    // no socket either: nymd has the network.
    let tcp_allowed = !tcp.is_empty() || nymd.is_none();
    let fs = enclave_sandbox::filesystem(&[], &[], !tcp_allowed);
    // IPv4 and IPv6 sockets only (or none); no programs, no debugging.
    let profile = if tcp_allowed {
        enclave_sandbox::Profile::Netd
    } else {
        enclave_sandbox::Profile::Vault
    };
    let sc = enclave_sandbox::syscalls(profile, false);
    if args.iter().any(|a| a == "--report") {
        let sockets = if tcp_allowed { "ip" } else { "none" };
        eprintln!("enclave-netd: filesystem {fs}, syscalls {sc}, sockets {sockets}");
    }
    let has_nym = nymd.is_some();
    let nym = std::sync::OnceLock::new();
    let (waiting, _child) = match nymd {
        Some((Nymd::Ready(driver), child)) => {
            let n = rt.block_on(async {
                NymTransport::new(Arc::new(*driver), over_nym.clone(), NymTransport::TIMEOUT)
            });
            let _ = nym.set(n);
            (None, Some(child))
        }
        Some((Nymd::Waiting(w), child)) => (Some(w), Some(child)),
        None => (None, None),
    };
    let transport = Arc::new(Routed {
        tcp: TcpTransport::new(tcp),
        tcp_allowed,
        tor: tor.is_some(),
        private: std::sync::atomic::AtomicBool::new(false),
        onion: std::sync::RwLock::new(if has_nym { onion } else { HashMap::new() }),
        fallback: std::sync::atomic::AtomicBool::new(false),
        tor_blocked,
        over_nym: std::sync::RwLock::new(if has_nym {
            over_nym.keys().copied().collect()
        } else {
            HashSet::new()
        }),
        pending_routes: std::sync::Mutex::new(over_nym),
        waiting: tokio::sync::Mutex::new(waiting),
        has_nym,
        nym,
    });
    rt.block_on(async move {
        let mut stdin = tokio::io::stdin();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let writer = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            while let Some(body) = rx.recv().await {
                if frame::write_frame(&mut stdout, &body).await.is_err() {
                    break;
                }
            }
        });
        // One-way sends still being handed to the mixnet client, which the
        // flush at the end must come after.
        let mut oneway = tokio::task::JoinSet::new();
        while let Ok(body) = frame::read_frame(&mut stdin).await {
            while oneway.try_join_next().is_some() {}
            let req = match NetRequest::decode(&body) {
                Ok(NetRequest::SetPacing { pacing }) => {
                    match enclave_net::transport::Pacing::decode(&pacing) {
                        Some(p) => transport.set_pacing(p),
                        None => eprintln!("enclave-netd: malformed pacing"),
                    }
                    continue;
                }
                Ok(NetRequest::RequirePrivate { on }) => {
                    transport.require_private(on);
                    continue;
                }
                Ok(NetRequest::UseFallback { on }) => {
                    transport.use_fallback(on);
                    continue;
                }
                Ok(NetRequest::SetRoute { server, route }) => {
                    match Route::parse(&route) {
                        Some(r) => transport.set_route(server, r),
                        None => eprintln!("enclave-netd: {route}: not a route"),
                    }
                    continue;
                }
                Ok(r) => r,
                Err(_) => break,
            };
            let t = Arc::clone(&transport);
            let tx = tx.clone();
            let is_oneway = matches!(req, NetRequest::Oneway { .. });
            // Requests run concurrently; replies carry their request's id.
            let task = async move {
                let (id, result) = match req {
                    NetRequest::Exchange { id, server, bytes } => (
                        id,
                        t.exchange(&server, bytes).await.map_err(|e| e.to_string()),
                    ),
                    NetRequest::ServerKey { id, server } => (
                        id,
                        t.server_key(&server)
                            .await
                            .map(|k| encode_server_key(&k))
                            .map_err(|e| e.to_string()),
                    ),
                    // Empty: it went one way.
                    NetRequest::Oneway { id, server, bytes } => (
                        id,
                        t.exchange_oneway(&server, bytes)
                            .await
                            .map(Option::unwrap_or_default)
                            .map_err(|e| e.to_string()),
                    ),
                    NetRequest::Fetch {
                        id,
                        method,
                        url,
                        body,
                    } => (
                        id,
                        t.fetch(&method, &url, body)
                            .await
                            .map(|(status, b)| [&status.to_be_bytes()[..], &b].concat())
                            .map_err(|e| e.to_string()),
                    ),
                    NetRequest::BuyTickets { id, gate, token } => (
                        id,
                        t.buy_tickets(&gate, &token)
                            .await
                            .map_err(|e| e.to_string()),
                    ),
                    NetRequest::TicketsSpent { id } => (
                        id,
                        t.tickets_spent()
                            .await
                            .map(|n| n.to_be_bytes().to_vec())
                            .map_err(|e| e.to_string()),
                    ),
                    NetRequest::Connect { id, tickets } => (
                        id,
                        t.connect_mixnet(tickets)
                            .await
                            .map(|()| Vec::new())
                            .map_err(|e| e.to_string()),
                    ),
                    NetRequest::SetRoute { .. }
                    | NetRequest::SetPacing { .. }
                    | NetRequest::RequirePrivate { .. }
                    | NetRequest::UseFallback { .. } => return,
                    NetRequest::TorStatus { id } => (
                        id,
                        t.tor_status()
                            .await
                            .map(|s| vec![s])
                            .map_err(|e| e.to_string()),
                    ),
                };
                let _ = tx.send(NetReply { id, result }.encode());
            };
            if is_oneway {
                oneway.spawn(task);
            } else {
                tokio::spawn(task);
            }
        }
        // The vault is gone (closed or quit): what it sent one way leaves
        // before the mixnet client does (`docs/09-transport.md` §6.1).
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), oneway.join_all()).await;
        if let Ok(false) = transport.flush(EXIT_FLUSH).await {
            eprintln!("enclave-netd: exiting with sends not yet acknowledged");
        }
        drop(tx);
        let _ = writer.await;
    });
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use enclave_nym::fake::FakeMixnet;

    fn routed(tor: bool) -> (Routed, ServerId, ServerId) {
        let over_nym: ServerId = [1; 16];
        let over_tcp: ServerId = [2; 16];
        let net = FakeMixnet::default();
        let nym = NymTransport::new(
            Arc::new(net.client("phone")),
            HashMap::from([(over_nym, "ingress".to_string())]),
            std::time::Duration::from_millis(50),
        );
        let r = Routed {
            tcp: TcpTransport::new(HashMap::from([(over_tcp, "127.0.0.1:9".parse().unwrap())])),
            tcp_allowed: true,
            nym: std::sync::OnceLock::from(nym),
            has_nym: true,
            waiting: tokio::sync::Mutex::new(None),
            pending_routes: std::sync::Mutex::new(HashMap::new()),
            over_nym: std::sync::RwLock::new(HashSet::from([over_nym])),
            tor,
            private: std::sync::atomic::AtomicBool::new(false),
            onion: std::sync::RwLock::new(HashMap::new()),
            fallback: std::sync::atomic::AtomicBool::new(false),
            tor_blocked: false,
        };
        (r, over_nym, over_tcp)
    }

    /// A shop for the waiting nymd in the test below.
    struct Shop;

    #[async_trait::async_trait]
    impl enclave_nym::pipe::Purchaser for Shop {
        async fn fetch(
            &self,
            _: &str,
            url: &str,
            _: Vec<u8>,
        ) -> enclave_nym::Result<(u16, Vec<u8>)> {
            Ok((200, url.as_bytes().to_vec()))
        }
        async fn buy(&self, _: &str, token: &[u8]) -> enclave_nym::Result<Vec<u8>> {
            Ok(token.to_vec())
        }
        async fn exchange_tor(
            &self,
            host: &str,
            port: u16,
            request: Vec<u8>,
        ) -> enclave_nym::Result<Vec<u8>> {
            Ok([host.as_bytes(), &port.to_be_bytes(), &request].concat())
        }
    }

    /// The fallback route (a server's onion service, through nymd's Tor)
    /// is used only once the user chose it, never in Maximum privacy, and
    /// works while the mixnet client still waits for its tickets.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_fallback_route_needs_consent() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (ar, aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        tokio::spawn(
            async move { enclave_nym::pipe::serve_starting(&Shop, &mut br, &mut bw).await },
        );
        let id: ServerId = [3; 16];
        let r = Routed {
            tcp: TcpTransport::new(HashMap::new()),
            tcp_allowed: false,
            nym: std::sync::OnceLock::new(),
            has_nym: true,
            waiting: tokio::sync::Mutex::new(Some(enclave_nym::pipe::Starting::new(
                Box::new(ar),
                Box::new(aw),
            ))),
            pending_routes: std::sync::Mutex::new(HashMap::new()),
            over_nym: std::sync::RwLock::new(HashSet::new()),
            tor: true,
            private: std::sync::atomic::AtomicBool::new(false),
            onion: std::sync::RwLock::new(HashMap::new()),
            fallback: std::sync::atomic::AtomicBool::new(false),
            tor_blocked: false,
        };
        r.set_route(id, Route::Nym("ingress".into()));
        r.set_route(id, Route::Onion("stack.onion".into()));
        let unavailable =
            |x: enclave_net::Result<Vec<u8>>| matches!(x, Err(NetError::Unavailable(_)));
        // Not chosen: the mixnet (still waiting).
        assert!(unavailable(r.exchange(&id, vec![1; 4]).await));
        // Chosen: over Tor to the onion service's port.
        r.use_fallback(true);
        let over_tor = [
            &b"stack.onion"[..],
            &enclave_net::transport::ONION_PORT.to_be_bytes(),
            &[1; 4],
        ]
        .concat();
        assert_eq!(r.exchange(&id, vec![1; 4]).await.unwrap(), over_tor);
        assert_eq!(
            r.exchange_oneway(&id, vec![1; 4]).await.unwrap(),
            Some(over_tor)
        );
        // A server without an onion service isn't reached over Tor.
        assert!(r.exchange(&[4; 16], vec![1; 4]).await.is_err());
        // Maximum privacy ignores the choice.
        r.require_private(true);
        assert!(unavailable(r.exchange(&id, vec![1; 4]).await));
        r.require_private(false);
        r.use_fallback(false);
        assert!(unavailable(r.exchange(&id, vec![1; 4]).await));
    }

    /// With `--await-tickets`: Nym routes wait for the client, which
    /// fetches and buys before connecting and connects on `Connect` with
    /// the routes it learned meanwhile.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_mixnet_client_waits_for_its_tickets() {
        use enclave_nym::MixnetDriver as _;
        let net = FakeMixnet::default();
        let server = net.client("ingress");
        let (a, b) = tokio::io::duplex(1 << 20);
        let (ar, aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let phone: Arc<dyn enclave_nym::MixnetDriver> = Arc::new(net.client("phone"));
        let nymd = tokio::spawn(async move {
            let tickets = enclave_nym::pipe::serve_starting(&Shop, &mut br, &mut bw)
                .await
                .unwrap();
            tokio::spawn(enclave_nym::pipe::serve(phone, br, bw));
            tickets
        });
        let id: ServerId = [1; 16];
        let r = Routed {
            tcp: TcpTransport::new(HashMap::new()),
            tcp_allowed: false,
            nym: std::sync::OnceLock::new(),
            has_nym: true,
            waiting: tokio::sync::Mutex::new(Some(enclave_nym::pipe::Starting::new(
                Box::new(ar),
                Box::new(aw),
            ))),
            pending_routes: std::sync::Mutex::new(HashMap::new()),
            over_nym: std::sync::RwLock::new(HashSet::new()),
            tor: true,
            private: std::sync::atomic::AtomicBool::new(false),
            onion: std::sync::RwLock::new(HashMap::new()),
            fallback: std::sync::atomic::AtomicBool::new(false),
            tor_blocked: false,
        };
        r.set_route(id, Route::Nym("ingress".into()));
        assert!(matches!(
            r.exchange(&id, vec![0; 2_048]).await,
            Err(NetError::Unavailable(_))
        ));
        assert_eq!(
            r.fetch("GET", "https://gate/x", vec![]).await.unwrap(),
            (200, b"https://gate/x".to_vec())
        );
        let book = r.buy_tickets("https://gate", b"token").await.unwrap();
        r.connect_mixnet(vec![book]).await.unwrap();
        assert_eq!(nymd.await.unwrap(), vec![b"token".to_vec()]);
        // Connected, with the route learned while waiting.
        let r = Arc::new(r);
        let rr = Arc::clone(&r);
        let ask = tokio::spawn(async move { rr.exchange(&id, vec![5; 2_048]).await });
        let m = server.recv().await.unwrap();
        let req = enclave_nym::frame::Request::decode(&m.data).unwrap();
        server
            .reply(
                m.reply.unwrap(),
                enclave_nym::frame::Reply {
                    id: req.id,
                    data: Some(vec![6; enclave_wire::UNIT_LEN]),
                }
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ask.await.unwrap().unwrap(), vec![6; enclave_wire::UNIT_LEN]);
        // A second connect is a no-op.
        r.connect_mixnet(vec![]).await.unwrap();
    }

    /// Maximum privacy: the mixnet behind Tor or nothing. A TCP route is
    /// refused (and a new one not taken); without Tor even the mixnet is.
    #[tokio::test]
    async fn the_private_route_only() {
        let (r, nym, tcp) = routed(true);
        r.require_private(true);
        assert!(r.pick(&nym).is_ok(), "the mixnet behind Tor");
        assert!(matches!(r.pick(&tcp), Err(NetError::Unavailable(_))));
        let other: ServerId = [3; 16];
        r.set_route(other, Route::Tcp("127.0.0.1:9".parse().unwrap()));
        assert!(r.pick(&other).is_err(), "no TCP route learned");
        r.require_private(false);
        assert!(r.pick(&tcp).is_ok());

        let (r, nym, _) = routed(false);
        r.require_private(true);
        assert!(
            matches!(r.pick(&nym), Err(NetError::Unavailable(m)) if m.contains("Tor")),
            "no Tor, no mixnet in Maximum"
        );
        r.require_private(false);
        assert!(r.pick(&nym).is_ok());
    }
}
