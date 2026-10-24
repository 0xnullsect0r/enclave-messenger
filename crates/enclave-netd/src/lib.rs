//! The `enclave-netd` program ([`main_with`]; `src/main.rs` runs it).
//!
//! `enclave-netd --server HEXID=nym:ADDRESS … --server HEXID=HOST:PORT … [--nymd PATH] [--mixnet] [--nym-env] [--await-tickets] [--tor DIR [--tord PATH] [--tor-direct] [--tor-standby] [--bridge LINE]… [--builtin-bridges] [--snowflake]] [--report]`
//!
//! Started by the vault, never by hand. Holds no keys: it carries sealed
//! requests from the vault (stdin) to servers and their sealed replies back
//! (stdout), and fetches servers' public request keys. A server named by an
//! onion service is reached through Tor: `enclave-tord`, started next to
//! netd with `--tor`, carries each request over its own Tor client
//! (`enclave_tord::carrier`, RFC 0010), so netd itself opens no TCP
//! connection. A server named by a Nym address is reached over the mixnet
//! (`NymTransport`) through `enclave-nymd` (nym-sdk can't be linked here:
//! `docs/09-transport.md` §1), when the mixnet is enabled; others over the
//! development TCP transport. The vault adds or changes routes as it
//! learns them (`NetRequest::SetRoute`: the server list, descriptors); a
//! Nym route needs the mixnet client, which netd starts only when a Nym
//! route is given at start. It confines itself first: no core dumps, not
//! dumpable, `no_new_privs`, and (Linux) no filesystem access at all, after
//! starting its helpers; without development TCP routes it can make no TCP
//! socket at all, only the UDP sockets calls use.

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
    /// Tor (`--tor`): how far it has come. It comes up in the background
    /// (a bootstrap can take minutes), so netd answers at once.
    tor: tokio::sync::watch::Receiver<TorUp>,
    /// Tor was asked for (`--tor`): onion routes are kept for it.
    tor_wanted: bool,
    /// Maximum privacy (`Transport::require_private`): the private routes
    /// only (Tor, or the mixnet behind Tor).
    private: std::sync::atomic::AtomicBool,
    /// Servers' onion services (from the server list and descriptors): the
    /// route to a server with no Nym route, and the fallback route to one
    /// with a Nym route.
    onion: std::sync::RwLock<HashMap<ServerId, String>>,
    /// The user chose the fallback route (`Transport::use_fallback`).
    fallback: std::sync::atomic::AtomicBool,
}

/// How Tor is doing, as netd's requests see it.
#[derive(Clone)]
enum TorUp {
    /// Not asked for (no `--tor`).
    Off,
    /// tord is bootstrapping.
    Starting,
    /// Up; with the carrier when tord carries netd's requests.
    Up(Option<Arc<enclave_tord::carrier::Client>>),
    /// It didn't come up in time: the network may be blocking Tor.
    Blocked,
    /// It didn't start at all.
    Failed,
}

impl Routed {
    /// tord's carrier, once Tor is up: a request made while Tor is still
    /// coming up waits for it (at most as long as a request may take).
    async fn carrier(&self) -> Option<Arc<enclave_tord::carrier::Client>> {
        let mut rx = self.tor.clone();
        let _ = tokio::time::timeout(
            enclave_tord::carrier::TIMEOUT,
            rx.wait_for(|t| !matches!(t, TorUp::Starting)),
        )
        .await;
        let up = rx.borrow();
        match &*up {
            TorUp::Up(c) => c.clone(),
            _ => None,
        }
    }

    fn tor_up(&self) -> bool {
        matches!(*self.tor.borrow(), TorUp::Up(_))
    }

    /// The onion service to reach `server` at: always for a server with no
    /// Nym route; for one on the mixnet only when the user chose the
    /// fallback route, never in Maximum privacy.
    fn onion_for(&self, server: &ServerId) -> Option<String> {
        use std::sync::atomic::Ordering::SeqCst;
        let host = self.onion.read().ok()?.get(server).cloned()?;
        let over_nym = self
            .over_nym
            .read()
            .map(|s| s.contains(server))
            .unwrap_or(false);
        if over_nym && (!self.fallback.load(SeqCst) || self.private.load(SeqCst)) {
            return None;
        }
        Some(host)
    }

    /// One request to an onion service through Tor: tord's own Tor client,
    /// or (without it) nymd's, connected or not. `oneway` asks for no
    /// reply; the answer is then `None`.
    async fn via_tor(
        &self,
        host: &str,
        request: Vec<u8>,
        oneway: bool,
    ) -> enclave_net::Result<Option<Vec<u8>>> {
        if let Some(c) = self.carrier().await {
            let r = c
                .exchange(host, enclave_net::transport::ONION_PORT, &request, oneway)
                .await
                .map_err(|e| NetError::Unreachable(e.to_string()))?;
            return Ok((!oneway).then_some(r));
        }
        self.via_nymd_tor(host, request).await.map(Some)
    }

    async fn via_nymd_tor(&self, host: &str, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
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
            Some(_) if over_nym && private && !self.tor_up() => Err(NetError::Unavailable(
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
            return self
                .via_tor(&h, request, false)
                .await?
                .ok_or(NetError::BadReply);
        }
        self.pick(server)?.exchange(server, request).await
    }

    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<enclave_rpc::ServerKey> {
        if let Some(h) = self.onion_for(server) {
            let bundle = self
                .via_tor(&h, Vec::new(), false)
                .await?
                .ok_or(NetError::BadReply)?;
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
            return self.via_tor(&h, request, true).await;
        }
        self.pick(server)?.exchange_oneway(server, request).await
    }

    fn use_fallback(&self, on: bool) {
        self.fallback.store(on, std::sync::atomic::Ordering::SeqCst);
    }

    async fn tor_status(&self) -> enclave_net::Result<u8> {
        Ok(match &*self.tor.borrow() {
            TorUp::Blocked => 2,
            TorUp::Up(_) => 1,
            _ => 0,
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
        if let Some(c) = self.carrier().await {
            return c
                .fetch(method, url, &body)
                .await
                .map_err(|e| NetError::Unreachable(e.to_string()));
        }
        if let Some(n) = self.nym.get() {
            return n.fetch(method, url, body).await;
        }
        match self.waiting.lock().await.as_mut() {
            Some(w) => w
                .fetch(method, url, &body)
                .await
                .map_err(|e| NetError::Unreachable(e.to_string())),
            None => Err(NetError::Unavailable("no Tor")),
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
        // An onion service: the route for a server with no Nym route, kept
        // aside as the fallback for one with. It needs Tor to carry it.
        if let Route::Onion(h) = &route {
            if (self.tor_wanted || self.has_nym)
                && let Ok(mut o) = self.onion.write()
            {
                o.insert(server, h.clone());
            }
            return;
        }
        let nym = matches!(route, Route::Nym(_));
        // Maximum privacy takes no route but the private ones.
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

/// Start `enclave-tord` keeping its state in `state` (`docs/09-transport.md`
/// §1), as the carrier of netd's requests; [`enclave_tord::launch::Starting::ready`]
/// says when Tor is up. `direct` (development) dials without Tor.
async fn spawn_tord(
    bin: &std::path::Path,
    state: &str,
    direct: bool,
    bridges: &[String],
) -> Result<enclave_tord::launch::Starting, String> {
    // Where the helpers share the app's process (Android, iOS), the app
    // chose Tor's port and secret at start and named them in the proxy
    // variables the mixnet client reads; elsewhere they are this run's.
    let mut extra = bridges.to_vec();
    let shared = enclave_platform::process::registered("enclave-tord")
        .then(|| {
            let socks = std::env::var("ENCLAVE_TOR_SOCKS").ok()?;
            let secret = std::env::var("ENCLAVE_TOR_SECRET").ok()?;
            let port = socks.rsplit(':').next()?.to_string();
            Some((port, secret))
        })
        .flatten();
    let secret = match shared {
        Some((port, secret)) => {
            extra.extend(["--port".to_string(), port]);
            secret
        }
        None => enclave_crypto::rng::HedgedRng::new()
            .and_then(|mut r| r.array::<32>("netd/tor-secret"))
            .map_err(|_| "no randomness".to_string())?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    };
    enclave_tord::launch::spawn(
        bin,
        std::path::Path::new(state),
        secret,
        direct,
        false,
        true,
        &extra,
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
) -> Result<(Nymd, Option<tokio::process::Child>), String> {
    let mut args = Vec::new();
    if env {
        args.push("--env".to_string());
    }
    if await_tickets {
        args.push("--await-tickets".to_string());
    }
    // A thread of this process where the helpers are linked in (Android,
    // iOS: the proxy variables are the app's, set at start).
    if let Some(p) = enclave_platform::process::start("enclave-nymd", args.clone())
        .map_err(|e| format!("enclave-nymd: {e}"))?
    {
        let (stdin, stdout) = enclave_ipc::stdio::pipes(p);
        if await_tickets {
            return Ok((
                Nymd::Waiting(enclave_nym::pipe::Starting::new(
                    Box::new(stdout),
                    Box::new(stdin),
                )),
                None,
            ));
        }
        let driver = enclave_nym::pipe::PipeDriver::new(stdout, stdin)
            .await
            .map_err(|e| format!("enclave-nymd: {e}"))?;
        return Ok((Nymd::Ready(Box::new(driver)), None));
    }
    let mut cmd = tokio::process::Command::new(bin);
    enclave_platform::process::no_window(cmd.as_std_mut());
    cmd.args(&args);
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
            Some(child),
        ));
    }
    let driver = enclave_nym::pipe::PipeDriver::new(stdout, stdin)
        .await
        .map_err(|e| format!("enclave-nymd: {e}"))?;
    Ok((Nymd::Ready(Box::new(driver)), Some(child)))
}

/// The program, given its arguments (without its name). As a thread of the
/// app (Android, iOS; `enclave_platform::process`) it leaves confining the
/// process alone and talks over the pipes it was given.
pub fn main_with(args: Vec<String>) -> ExitCode {
    let standalone = !enclave_platform::process::in_process();
    if standalone {
        let _ = enclave_sandbox::process();
    }
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
    for f in ["--builtin-bridges", "--snowflake"] {
        if args.iter().any(|a| a == f) {
            bridges.push(f.into());
        }
    }
    // A spare netd's tord stands by until the one in use is gone: one Tor
    // per state directory.
    if args.iter().any(|a| a == "--tor-standby") {
        bridges.push("--standby".into());
    }
    // The mixnet client starts for Nym routes given now, or (`--mixnet`)
    // for ones the vault gives later, from the server list.
    let mixnet = !over_nym.is_empty() || args.iter().any(|a| a == "--mixnet");
    let mut tor_blocked = false;
    // Tor starts whenever the vault asks (`--tor`): it carries requests to
    // servers' onion services (RFC 0010), and the mixnet client's gateway
    // connection when there is one. Without a mixnet nothing waits for it:
    // tord is started now (netd can start no program once confined) and
    // comes up in the background, and requests for onion services wait
    // for it. The mixnet client needs Tor's port first, so with one netd
    // waits.
    let (tor_tx, tor_rx) = tokio::sync::watch::channel(if flag("--tor").is_some() {
        TorUp::Starting
    } else {
        TorUp::Off
    });
    let mut tor: Option<enclave_tord::launch::Running> = None;
    let mut tor_pending: Option<enclave_tord::launch::Starting> = None;
    if let Some(state) = flag("--tor") {
        let bin = flag("--tord").map(std::path::PathBuf::from).or_else(|| {
            std::env::current_exe()
                .ok()
                .map(|e| e.with_file_name(format!("enclave-tord{}", std::env::consts::EXE_SUFFIX)))
        });
        let spawned = match bin {
            Some(bin) => rt.block_on(spawn_tord(
                &bin,
                &state,
                args.iter().any(|a| a == "--tor-direct"),
                &bridges,
            )),
            None => Err("no enclave-tord".into()),
        };
        let started = match spawned {
            Ok(s) if !mixnet => {
                tor_pending = Some(s);
                Ok(None)
            }
            Ok(s) => rt.block_on(s.ready(TOR_BOOTSTRAP)).map(Some),
            Err(e) => Err(e),
        };
        match started {
            Ok(Some(t)) => {
                let _ = tor_tx.send(TorUp::Up(t.carrier.clone()));
                tor = Some(t);
            }
            Ok(None) => {}
            // Tor is blocked here: stay up to say so (the vault offers
            // bridges), without a mixnet client.
            Err(e) if e == enclave_tord::launch::BLOCKED => {
                eprintln!("enclave-netd: {e}");
                tor_blocked = true;
                let _ = tor_tx.send(TorUp::Blocked);
            }
            Err(e) if mixnet => {
                // Without Tor the mixnet client doesn't start: the
                // entry gateway would see this device's address.
                eprintln!("enclave-netd: {e}");
                return ExitCode::FAILURE;
            }
            // No onion service is reachable then; the vault sees its
            // requests fail and says so.
            Err(e) => {
                eprintln!("enclave-netd: {e}");
                let _ = tor_tx.send(TorUp::Failed);
            }
        }
    }
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
    let tor_spawned = tor.is_some() || tor_pending.is_some();
    // Nothing on disk is needed from here on, and no TCP socket either
    // when Tor or nymd carry the requests (development TCP routes aside):
    // only the UDP sockets calls use.
    let tcp_allowed = !tcp.is_empty() || (nymd.is_none() && !tor_spawned);
    // IPv4 and IPv6 sockets (datagrams only, without TCP); no programs, no
    // debugging.
    let profile = if tcp_allowed {
        enclave_sandbox::Profile::Netd
    } else {
        enclave_sandbox::Profile::NetdUdp
    };
    let (fs, sc) = if standalone {
        (
            enclave_sandbox::filesystem(&[], &[], !tcp_allowed),
            enclave_sandbox::syscalls(profile, false),
        )
    } else {
        ("the app's", "the app's")
    };
    if args.iter().any(|a| a == "--report") {
        let sockets = if tcp_allowed { "ip" } else { "udp" };
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
            (None, child)
        }
        Some((Nymd::Waiting(w), child)) => (Some(w), child),
        None => (None, None),
    };
    let transport = Arc::new(Routed {
        tcp: TcpTransport::new(tcp),
        tcp_allowed,
        tor: tor_rx,
        tor_wanted: tor_spawned,
        private: std::sync::atomic::AtomicBool::new(false),
        onion: std::sync::RwLock::new(if has_nym || tor_spawned {
            onion
        } else {
            HashMap::new()
        }),
        fallback: std::sync::atomic::AtomicBool::new(false),
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
    // Tor coming up, in the background; the running tord is kept as
    // long as netd runs.
    if let Some(starting) = tor_pending {
        rt.spawn(async move {
            match starting.ready(TOR_BOOTSTRAP).await {
                Ok(t) => {
                    let _ = tor_tx.send(TorUp::Up(t.carrier.clone()));
                    let _kept = t;
                    std::future::pending::<()>().await;
                }
                Err(e) => {
                    eprintln!("enclave-netd: {e}");
                    let _ = tor_tx.send(if e == enclave_tord::launch::BLOCKED {
                        TorUp::Blocked
                    } else {
                        TorUp::Failed
                    });
                }
            }
        });
    }
    let Ok((mut stdin, mut stdout)) = enclave_ipc::stdio::stdio() else {
        return ExitCode::FAILURE;
    };
    rt.block_on(async move {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let writer = tokio::spawn(async move {
            while let Some(body) = rx.recv().await {
                if frame::write_frame(&mut stdout, &body).await.is_err() {
                    break;
                }
            }
        });
        // UDP sockets for calls (`docs/11-calls.md` §3), by number.
        let sockets = Udp::default();
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
                Ok(NetRequest::UdpSend { socket, bytes }) => {
                    sockets.send(socket, &bytes).await;
                    continue;
                }
                Ok(NetRequest::UdpClose { socket }) => {
                    sockets.close(socket);
                    continue;
                }
                Ok(NetRequest::UdpOpen { id, remote }) => {
                    let result = sockets.open(&remote, tx.clone()).await;
                    let _ = tx.send(NetReply { id, result }.encode());
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
                    | NetRequest::UseFallback { .. }
                    | NetRequest::UdpOpen { .. }
                    | NetRequest::UdpSend { .. }
                    | NetRequest::UdpClose { .. } => return,
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

/// Most UDP sockets open at once (a group call needs one).
const MAX_SOCKETS: usize = 8;
/// Largest datagram read.
const MAX_DATAGRAM: usize = 2048;

/// A socket, its reader, and whether it talks to any address.
type Socket = (
    Arc<tokio::net::UdpSocket>,
    tokio::task::JoinHandle<()>,
    bool,
);

/// The UDP sockets calls use. Most are connected to one address (a relay);
/// a direct call's talks to any (its relay, for its address as seen from
/// outside, and the other person), with each datagram's address framed on
/// it both ways (`enclave_net::transport::addressed`). What arrives goes to
/// the vault as a [`enclave_ipc::net::SOCKET_EVENT`] reply, and an error
/// closes it.
#[derive(Default)]
struct Udp {
    next: std::sync::atomic::AtomicU32,
    open: std::sync::Mutex<HashMap<u32, Socket>>,
}

impl Udp {
    /// Open a socket to `remote`, or to any address when it is empty. The
    /// reply is the socket's number, then (any address) its own address on
    /// the local network if known.
    async fn open(
        &self,
        remote: &str,
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<Vec<u8>, String> {
        use enclave_ipc::net::SOCKET_EVENT;
        use enclave_net::transport::{addressed, local_ip};
        if self.open.lock().map(|o| o.len()).unwrap_or(MAX_SOCKETS) >= MAX_SOCKETS {
            return Err("too many call sockets".into());
        }
        let any = remote.is_empty();
        let sock = if any {
            tokio::net::UdpSocket::bind(("0.0.0.0", 0))
                .await
                .map_err(|e| e.to_string())?
        } else {
            let addr = tokio::net::lookup_host(remote)
                .await
                .map_err(|e| format!("{remote}: {e}"))?
                .next()
                .ok_or_else(|| format!("{remote}: no address"))?;
            let local: std::net::SocketAddr = if addr.is_ipv4() {
                ([0, 0, 0, 0], 0).into()
            } else {
                (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
            };
            let sock = tokio::net::UdpSocket::bind(local)
                .await
                .map_err(|e| e.to_string())?;
            sock.connect(addr).await.map_err(|e| e.to_string())?;
            sock
        };
        let sock = Arc::new(sock);
        let n = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % SOCKET_EVENT;
        let mut reply = n.to_be_bytes().to_vec();
        if any && let (Some(ip), Ok(bound)) = (local_ip(), sock.local_addr()) {
            reply.extend_from_slice(
                std::net::SocketAddr::new(ip, bound.port())
                    .to_string()
                    .as_bytes(),
            );
        }
        let reader = Arc::clone(&sock);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let got = if any {
                    reader
                        .recv_from(&mut buf)
                        .await
                        .map(|(len, from)| addressed(from, &buf[..len]))
                } else {
                    reader.recv(&mut buf).await.map(|len| buf[..len].to_vec())
                };
                let result = match got {
                    Ok(d) => Ok(d),
                    // ICMP unreachable doesn't close it: the relay may
                    // just not be up yet (Windows says "reset").
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => Err(e.to_string()),
                };
                let closed = result.is_err();
                let reply = NetReply {
                    id: SOCKET_EVENT | n,
                    result,
                };
                if tx.send(reply.encode()).is_err() || closed {
                    break;
                }
            }
        });
        if let Ok(mut o) = self.open.lock() {
            o.insert(n, (sock, task, any));
        }
        Ok(reply)
    }

    async fn send(&self, socket: u32, bytes: &[u8]) {
        let sock = self
            .open
            .lock()
            .ok()
            .and_then(|o| o.get(&socket).map(|s| (Arc::clone(&s.0), s.2)));
        // A datagram that can't go is lost, as on the network.
        match sock {
            Some((s, false)) => {
                let _ = s.send(bytes).await;
            }
            Some((s, true)) => {
                if let Some((to, bytes)) = enclave_net::transport::unaddressed(bytes) {
                    let _ = s.send_to(bytes, to).await;
                }
            }
            None => {}
        }
    }

    fn close(&self, socket: u32) {
        if let Some((_, task, _)) = self.open.lock().ok().and_then(|mut o| o.remove(&socket)) {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use enclave_nym::fake::FakeMixnet;

    #[tokio::test]
    async fn udp_sockets_carry_datagrams_both_ways() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap();
        let udp = Udp::default();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let n = udp.open(&addr.to_string(), tx.clone()).await.unwrap();
        let n = u32::from_be_bytes(n.try_into().unwrap());
        udp.send(n, b"to the relay").await;
        let mut buf = [0u8; 64];
        let (len, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"to the relay");
        peer.send_to(b"back", from).await.unwrap();
        let reply = NetReply::decode(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(reply.id, enclave_ipc::net::SOCKET_EVENT | n);
        assert_eq!(reply.result, Ok(b"back".to_vec()));
        udp.close(n);
        udp.send(n, b"gone").await;
        // A socket to any address: datagrams carry their address.
        use enclave_net::transport::{addressed, unaddressed};
        let opened = udp.open("", tx).await.unwrap();
        let n = u32::from_be_bytes(opened[..4].try_into().unwrap());
        udp.send(n, &addressed(addr, b"to anyone")).await;
        let (len, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"to anyone");
        peer.send_to(b"from the peer", from).await.unwrap();
        let reply = NetReply::decode(&rx.recv().await.unwrap()).unwrap();
        let dg = reply.result.unwrap();
        let (got_from, bytes) = unaddressed(&dg).unwrap();
        assert_eq!((got_from, bytes), (addr, &b"from the peer"[..]));
        udp.close(n);
        assert!(
            udp.open("not an address", tokio::sync::mpsc::unbounded_channel().0)
                .await
                .is_err()
        );
    }

    /// Tor as a test has it, settled.
    fn tor_state(t: TorUp) -> tokio::sync::watch::Receiver<TorUp> {
        tokio::sync::watch::channel(t).1
    }

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
            tor: tor_state(if tor { TorUp::Up(None) } else { TorUp::Off }),
            tor_wanted: tor,
            private: std::sync::atomic::AtomicBool::new(false),
            onion: std::sync::RwLock::new(HashMap::new()),
            fallback: std::sync::atomic::AtomicBool::new(false),
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
            tor: tor_state(TorUp::Up(None)),
            tor_wanted: true,
            private: std::sync::atomic::AtomicBool::new(false),
            onion: std::sync::RwLock::new(HashMap::new()),
            fallback: std::sync::atomic::AtomicBool::new(false),
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

    /// Dials every name at one address: a stack's onion service in a test.
    struct To(std::net::SocketAddr);

    #[async_trait::async_trait]
    impl enclave_tord::Dialer for To {
        async fn dial(
            &self,
            _: &str,
            _: u16,
        ) -> std::io::Result<Box<dyn enclave_tord::socks::Stream>> {
            Ok(Box::new(tokio::net::TcpStream::connect(self.0).await?))
        }
    }

    /// A server in Enclave's framing answering `echo:` + the request (an
    /// empty frame when sent one way), and tord carrying requests to it.
    async fn carried() -> Arc<enclave_tord::carrier::Client> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    loop {
                        let mut n = [0u8; 4];
                        if s.read_exact(&mut n).await.is_err() {
                            return;
                        }
                        let n = u32::from_be_bytes(n);
                        let oneway = n & enclave_tord::carrier::ONEWAY_BIT != 0;
                        let mut b = vec![0u8; (n & !enclave_tord::carrier::ONEWAY_BIT) as usize];
                        s.read_exact(&mut b).await.unwrap();
                        let reply = if oneway {
                            Vec::new()
                        } else {
                            [&b"echo:"[..], &b].concat()
                        };
                        s.write_all(&(reply.len() as u32).to_be_bytes())
                            .await
                            .unwrap();
                        s.write_all(&reply).await.unwrap();
                    }
                });
            }
        });
        let (to_tord, tord_in) = tokio::io::duplex(1 << 20);
        let (tord_out, from_tord) = tokio::io::duplex(1 << 20);
        tokio::spawn(enclave_tord::carrier::serve(
            Arc::new(To(addr)),
            tord_in,
            tord_out,
        ));
        Arc::new(enclave_tord::carrier::Client::new(from_tord, to_tord))
    }

    fn over_tor(carrier: Arc<enclave_tord::carrier::Client>) -> Routed {
        Routed {
            tcp: TcpTransport::new(HashMap::new()),
            tcp_allowed: false,
            nym: std::sync::OnceLock::new(),
            has_nym: false,
            waiting: tokio::sync::Mutex::new(None),
            pending_routes: std::sync::Mutex::new(HashMap::new()),
            over_nym: std::sync::RwLock::new(HashSet::new()),
            tor: tor_state(TorUp::Up(Some(carrier))),
            tor_wanted: true,
            private: std::sync::atomic::AtomicBool::new(false),
            onion: std::sync::RwLock::new(HashMap::new()),
            fallback: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// RFC 0010: a server with only an onion service is reached through
    /// tord without anyone choosing a fallback, in Maximum privacy too;
    /// one-way sends get no reply back.
    #[tokio::test(flavor = "multi_thread")]
    async fn onion_route_is_primary_without_consent() {
        let r = over_tor(carried().await);
        let id: ServerId = [7; 16];
        r.set_route(id, Route::Onion("stack.onion".into()));
        assert_eq!(r.exchange(&id, b"hi".to_vec()).await.unwrap(), b"echo:hi");
        assert_eq!(r.exchange_oneway(&id, vec![1; 8]).await.unwrap(), None);
        r.require_private(true);
        assert_eq!(r.exchange(&id, b"max".to_vec()).await.unwrap(), b"echo:max");
        // A server with no route at all isn't reached.
        assert!(r.exchange(&[8; 16], b"x".to_vec()).await.is_err());
    }

    /// Tor comes up in the background: netd answers at once, a request to
    /// an onion service made meanwhile waits for it, and Tor's status says
    /// "not yet" until then.
    #[tokio::test(flavor = "multi_thread")]
    async fn onion_requests_wait_for_tor_to_come_up() {
        let mut r = over_tor(carried().await);
        let (tx, rx) = tokio::sync::watch::channel(TorUp::Starting);
        r.tor = rx;
        let r = Arc::new(r);
        let id: ServerId = [11; 16];
        r.set_route(id, Route::Onion("stack.onion".into()));
        assert_eq!(r.tor_status().await.unwrap(), 0);
        let waiting = {
            let r = Arc::clone(&r);
            tokio::spawn(async move { r.exchange(&id, b"early".to_vec()).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!waiting.is_finished(), "it waits for Tor");
        let _ = tx.send(TorUp::Up(Some(carried().await)));
        assert_eq!(waiting.await.unwrap().unwrap(), b"echo:early");
        assert_eq!(r.tor_status().await.unwrap(), 1);
        // Tor that never came up: the request fails instead of waiting.
        let _ = tx.send(TorUp::Blocked);
        assert!(r.exchange(&id, b"late".to_vec()).await.is_err());
        assert_eq!(r.tor_status().await.unwrap(), 2);
    }

    /// Maximum privacy takes the onion route and refuses a direct one.
    #[tokio::test(flavor = "multi_thread")]
    async fn maximum_accepts_onion_refuses_tcp() {
        let mut r = over_tor(carried().await);
        let direct: ServerId = [9; 16];
        r.tcp = TcpTransport::new(HashMap::from([(direct, "127.0.0.1:9".parse().unwrap())]));
        r.tcp_allowed = true;
        let onion: ServerId = [10; 16];
        r.set_route(onion, Route::Onion("stack.onion".into()));
        r.require_private(true);
        assert!(matches!(
            r.exchange(&direct, b"x".to_vec()).await,
            Err(NetError::Unavailable(_))
        ));
        assert_eq!(r.exchange(&onion, b"y".to_vec()).await.unwrap(), b"echo:y");
    }

    /// Fetches go to tord when it carries (no mixnet client needed): its
    /// own rules answer, here refusing a plain-HTTP address.
    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_goes_to_tord_without_nymd() {
        let r = over_tor(carried().await);
        let e = r
            .fetch("GET", "web+http://example.org/", Vec::new())
            .await
            .unwrap_err();
        assert!(e.to_string().contains("https only"), "{e}");
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
            tor: tor_state(TorUp::Up(None)),
            tor_wanted: true,
            private: std::sync::atomic::AtomicBool::new(false),
            onion: std::sync::RwLock::new(HashMap::new()),
            fallback: std::sync::atomic::AtomicBool::new(false),
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
