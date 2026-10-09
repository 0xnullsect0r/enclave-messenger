//! Transports carry one sealed request to a server and bring back one sealed
//! reply (single-use-reply-block semantics in Nym).
//!
//! * [`TcpTransport`]: the development transport (`enclave-server` dev binary).
//!   Never used in production builds.
//! * `NymTransport` / `TorTransport`: production, behind the `nym` and `tor`
//!   features. The M4 feasibility spike (`docs/spikes/m4-network.md`) records
//!   what could and could not be validated.

use crate::{NetError, Result};
pub use enclave_nym::Pacing;
use enclave_rpc::ServerKey;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Server identifier.
pub type ServerId = [u8; 16];

/// Carries sealed requests to servers.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Send one sealed request and wait for the sealed reply.
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>>;
    /// Like [`Transport::exchange`] for something that may be dropped
    /// rather than ever add traffic (a typing indicator): a shaping
    /// transport sends it only in a slot that would otherwise carry cover.
    async fn exchange_droppable(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.exchange(server, request).await
    }
    /// Send a sealed unit that needs no answer (a write, cover). Over the
    /// mixnet it goes one way, with no reply blocks, and the result is
    /// `None`: whether it arrived is learned later (a delivery receipt).
    /// Other transports exchange as usual and return the reply, so its
    /// status can still be checked.
    async fn exchange_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        self.exchange(server, request).await.map(Some)
    }
    /// Send a sealed request whose answer is fetched afterwards by a status
    /// poll (`docs/09-transport.md` §6.1). The same as
    /// [`Transport::exchange_oneway`] unless a transport needs to tell
    /// questions from writes (a test network that loses only writes).
    async fn exchange_deferred(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        self.exchange_oneway(server, request).await
    }
    /// [`Transport::exchange_oneway`] for something that may be dropped
    /// (see [`Transport::exchange_droppable`]).
    async fn exchange_droppable_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        self.exchange_droppable(server, request).await.map(Some)
    }
    /// Start (`true`) or end a bulk transfer: a shaping transport may then
    /// send without waiting for the clock (a large file, catch-up, account
    /// setup), where its profile allows. Calls nest.
    fn set_bulk(&self, _on: bool) {}
    /// The server's current request key, authenticated as `server`'s: a
    /// network transport checks the signed key bundle against the id
    /// ([`verify_key_bundle`]).
    async fn server_key(&self, server: &ServerId) -> Result<ServerKey>;
    /// Reach `server` by `route` from now on (a Nym address from the
    /// server list or a descriptor). A transport that can't carry that
    /// kind of route ignores it.
    fn set_route(&self, _server: ServerId, _route: Route) {}
    /// Pace what goes over the mixnet from now on (the shaper calls this
    /// when the profile changes and around bulk transfers). Other
    /// transports ignore it.
    fn set_pacing(&self, _pacing: enclave_nym::Pacing) {}
    /// Use only the private route from now on (`on`), or not (Maximum
    /// privacy, `docs/09-transport.md` §6.6): no development TCP route or
    /// fallback, and nothing at all without Tor in front of the mixnet.
    /// Requests that would break that fail instead.
    fn require_private(&self, _on: bool) {}
    /// Reach servers that have an onion route ([`Route::Onion`]) over it
    /// from now on (`on`), or over the mixnet again: the fallback route,
    /// only ever with the user's consent, and ignored in Maximum privacy
    /// (`docs/09-transport.md` §7). Transports without one ignore it.
    fn use_fallback(&self, _on: bool) {}
    /// Wait, for at most `within`, until everything sent so far has left
    /// this device (over the mixnet: reached the far gateway). Called
    /// before exiting, since a one-way send still queued is lost with the
    /// process (its outbox re-sends it, but only much later). `false` if
    /// time ran out.
    async fn flush(&self, within: std::time::Duration) -> Result<bool> {
        let _ = within;
        Ok(true)
    }
    /// HTTP through the mixnet client's Tor, for the credential gate
    /// (`docs/09-transport.md` §7): the status and the body.
    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        let _ = (method, url, body);
        Err(NetError::Unavailable("fetching through Tor"))
    }
    /// Buy one zk-nym ticketbook from the credential gate at `gate` with
    /// one Privacy Pass token: the ticketbook, to keep.
    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
        let _ = (gate, token);
        Err(NetError::Unavailable("zk-nym tickets"))
    }
    /// Connect the mixnet client, spending these ticketbooks, if it is
    /// waiting for them (netd `--await-tickets`). Already connected or
    /// without a mixnet: nothing to do.
    async fn connect_mixnet(&self, tickets: Vec<Vec<u8>>) -> Result<()> {
        let _ = tickets;
        Ok(())
    }
    /// zk-nym tickets the mixnet client's process has spent so far
    /// (`enclave_nym::advance` says from which of the ticketbooks it
    /// connected with).
    async fn tickets_spent(&self) -> Result<u64> {
        Ok(0)
    }
    /// Current time, Unix seconds. The system clock, except in simulations
    /// that move time forward.
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Encode `key_id ‖ x448 ‖ mlkem` (inverse of [`decode_server_key`]).
pub fn encode_server_key(k: &ServerKey) -> Vec<u8> {
    k.to_bytes()
}

/// Decode `key_id ‖ x448 ‖ mlkem` as served by the dev transport.
pub fn decode_server_key(b: &[u8]) -> Result<ServerKey> {
    ServerKey::from_bytes(b).map_err(|_| NetError::BadReply)
}

/// How a server is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// The development TCP transport: `HOST:PORT`.
    Tcp(SocketAddr),
    /// Over the mixnet, to the server's ingress: `nym:ADDRESS`.
    Nym(String),
    /// The fallback route, over Tor to the stack's onion service:
    /// `onion:HOST.onion` (port [`ONION_PORT`]). Used only with the user's
    /// consent and never in Maximum privacy (`docs/09-transport.md` §7).
    Onion(String),
}

/// The port of a stack's onion service (`enclave-onion`).
pub const ONION_PORT: u16 = 7443;

impl Route {
    /// Parse `HOST:PORT`, `nym:ADDRESS` or `onion:HOST.onion`.
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(h) = s.strip_prefix("onion:") {
            return (h.len() > ".onion".len() && h.ends_with(".onion") && !h.contains(':'))
                .then(|| Route::Onion(h.into()));
        }
        match s.strip_prefix("nym:") {
            Some(a) if !a.is_empty() => Some(Route::Nym(a.into())),
            Some(_) => None,
            None => s.parse().ok().map(Route::Tcp),
        }
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Route::Tcp(a) => write!(f, "{a}"),
            Route::Nym(a) => write!(f, "nym:{a}"),
            Route::Onion(h) => write!(f, "onion:{h}"),
        }
    }
}

fn parse_id(hex: &str) -> Option<ServerId> {
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(id)
}

/// Parse `HEXID=HOST:PORT` or `HEXID=nym:ADDRESS` (a 32-hex-digit server
/// id and its route), the form `--server` takes in the app, the vault and
/// netd.
pub fn parse_route(s: &str) -> Option<(ServerId, Route)> {
    let (hex, route) = s.split_once('=')?;
    Some((parse_id(hex)?, Route::parse(route)?))
}

/// Parse `HEXID=HOST:PORT` (a TCP route only; see [`parse_route`]).
pub fn parse_server(s: &str) -> Option<(ServerId, SocketAddr)> {
    match parse_route(s)? {
        (id, Route::Tcp(a)) => Some((id, a)),
        _ => None,
    }
}

/// Check a key bundle (the reply to a zero-length request) against the id
/// the client expects and return the request key valid at `now`.
pub fn verify_key_bundle(server: &ServerId, bundle: &[u8], now: u64) -> Result<ServerKey> {
    enclave_federation::KeyBundle::decode(bundle)
        .and_then(|b| b.verify(server, now))
        .map_err(NetError::Untrusted)
}

/// Development transport: length-prefixed frames over TCP.
pub struct TcpTransport {
    addrs: std::sync::RwLock<HashMap<ServerId, SocketAddr>>,
    /// Maximum privacy: a direct connection is never the private route.
    private: std::sync::atomic::AtomicBool,
}

impl TcpTransport {
    /// New transport with an address book (TCP routes added later go in
    /// it too).
    pub fn new(addrs: HashMap<ServerId, SocketAddr>) -> Self {
        Self {
            addrs: std::sync::RwLock::new(addrs),
            private: std::sync::atomic::AtomicBool::new(false),
        }
    }

    async fn roundtrip(&self, server: &ServerId, frame: &[u8]) -> Result<Vec<u8>> {
        if self.private.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(NetError::Unavailable(
                "Maximum privacy needs the private route",
            ));
        }
        let addr = self
            .addrs
            .read()
            .ok()
            .and_then(|a| a.get(server).copied())
            .ok_or_else(|| NetError::Unreachable("unknown server".into()))?;
        let mut s = TcpStream::connect(addr).await?;
        s.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        s.write_all(frame).await?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > enclave_wire::UNIT_LEN {
            return Err(NetError::BadReply);
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

#[async_trait::async_trait]
impl Transport for TcpTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.roundtrip(server, &request).await
    }

    async fn server_key(&self, server: &ServerId) -> Result<ServerKey> {
        let bundle = self.roundtrip(server, &[]).await?;
        verify_key_bundle(server, &bundle, self.now())
    }

    fn require_private(&self, on: bool) {
        self.private.store(on, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_route(&self, server: ServerId, route: Route) {
        if let (Route::Tcp(a), Ok(mut addrs)) = (route, self.addrs.write()) {
            addrs.insert(server, a);
        }
    }
}

/// Tor transport (arti, embedded): the consented fallback route when the
/// mixnet is unreachable, and the underlay for Nym. Servers are addressed by
/// onion service. Requires the `tor` feature.
#[cfg(feature = "tor")]
pub struct TorTransport {
    client: std::sync::Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>,
    addrs: HashMap<ServerId, (String, u16)>,
}

#[cfg(feature = "tor")]
impl TorTransport {
    /// Bootstrap an embedded Tor client. `addrs` maps servers to their onion
    /// service `(host, port)`.
    pub async fn bootstrap(addrs: HashMap<ServerId, (String, u16)>) -> Result<Self> {
        let cfg = arti_client::TorClientConfig::default();
        let client = arti_client::TorClient::create_bootstrapped(cfg)
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))?;
        Ok(Self { client, addrs })
    }

    async fn roundtrip(&self, server: &ServerId, frame: &[u8]) -> Result<Vec<u8>> {
        let (host, port) = self
            .addrs
            .get(server)
            .ok_or_else(|| NetError::Unreachable("unknown server".into()))?;
        let mut s = self
            .client
            .connect((host.as_str(), *port))
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))?;
        s.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        s.write_all(frame).await?;
        s.flush().await?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > enclave_wire::UNIT_LEN {
            return Err(NetError::BadReply);
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

#[cfg(feature = "tor")]
#[async_trait::async_trait]
impl Transport for TorTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.roundtrip(server, &request).await
    }

    async fn server_key(&self, server: &ServerId) -> Result<ServerKey> {
        let bundle = self.roundtrip(server, &[]).await?;
        verify_key_bundle(server, &bundle, self.now())
    }
}

/// The Nym transport (`docs/09-transport.md` §1): each sealed request goes
/// to its server's Nym address (its ingress) as a mixframe
/// (`enclave_nym::frame`) with fresh reply blocks for one reply, under a
/// fresh request id that matches the reply. Works over any
/// [`enclave_nym::MixnetDriver`]: nym-sdk in production, the in-process
/// fake mixnet in tests. A request that gets no reply in time fails as
/// unreachable; its caller seals it anew to retry.
#[cfg(feature = "nym")]
pub struct NymTransport {
    driver: std::sync::Arc<dyn enclave_nym::MixnetDriver>,
    routes: std::sync::RwLock<HashMap<ServerId, String>>,
    pending: std::sync::Arc<std::sync::Mutex<HashMap<[u8; 16], PendingReply>>>,
    timeout: std::time::Duration,
    path: std::sync::Arc<GatewayPath>,
    reader: tokio::task::JoinHandle<()>,
    prober: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "nym")]
type PendingReply = tokio::sync::oneshot::Sender<Option<Vec<u8>>>;

/// The device's gateway path as measured (RT-02, `crate::monitor`): every
/// exchange and every self-loop probe is a sample, and a bad path makes
/// the driver move to another gateway.
#[cfg(feature = "nym")]
struct GatewayPath {
    driver: std::sync::Arc<dyn enclave_nym::MixnetDriver>,
    monitor: std::sync::Mutex<crate::monitor::LinkMonitor>,
    /// Probes on their way, by id, with when they left.
    probes: std::sync::Mutex<HashMap<[u8; 16], tokio::time::Instant>>,
    /// Mean delay between probes, in milliseconds.
    probe_ms: std::sync::atomic::AtomicU64,
    switches: std::sync::atomic::AtomicU64,
    switching: std::sync::atomic::AtomicBool,
    started: tokio::time::Instant,
}

#[cfg(feature = "nym")]
impl GatewayPath {
    /// A probe with no answer after this long counts as lost.
    const PROBE_LOST_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

    fn sample(self: &std::sync::Arc<Self>, latency: Option<std::time::Duration>) {
        let now = self.started.elapsed().as_secs();
        let verdict = {
            let Ok(mut m) = self.monitor.lock() else {
                return;
            };
            match latency {
                Some(l) => m.arrived(l),
                None => m.lost(),
            }
            m.should_switch(now)
        };
        let Some(verdict) = verdict else {
            return;
        };
        if self
            .switching
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let me = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let result = me.driver.switch_gateway().await;
            // The cooldown starts either way, so a path with nowhere to go
            // isn't retried on every sample.
            if let Ok(mut m) = me.monitor.lock() {
                m.switched(me.started.elapsed().as_secs());
            }
            match result {
                Ok(g) => {
                    me.switches
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    eprintln!("enclave-net: switched gateway to {g} ({verdict})");
                }
                Err(e) => eprintln!("enclave-net: gateway path bad ({verdict}), no switch: {e}"),
            }
            me.switching
                .store(false, std::sync::atomic::Ordering::SeqCst);
        });
    }

    /// A probe came back.
    fn probe_back(self: &std::sync::Arc<Self>, id: &[u8; 16]) {
        let sent = self.probes.lock().ok().and_then(|mut p| p.remove(id));
        if let Some(t) = sent {
            self.sample(Some(t.elapsed()));
        }
    }

    /// Send self-loop probes at random (exponential) intervals until the
    /// transport goes, counting those that never come back as lost.
    async fn probe_forever(self: std::sync::Arc<Self>) {
        let Ok(mut rng) = enclave_crypto::rng::HedgedRng::new() else {
            return;
        };
        let Ok(secret) = rng.array::<32>("net/loop-probe-secret") else {
            return;
        };
        for counter in 0u64.. {
            let mean = self.probe_ms.load(std::sync::atomic::Ordering::SeqCst);
            let u = rng
                .array::<8>("net/loop-probe-delay")
                .map(|b| (u64::from_be_bytes(b) >> 11) as f64 / (1u64 << 53) as f64)
                .unwrap_or(0.5);
            let wait = -(1.0 - u).ln() * mean as f64;
            tokio::time::sleep(std::time::Duration::from_millis(wait as u64)).await;
            // Probes that never came back.
            let lost: usize = {
                let Ok(mut p) = self.probes.lock() else {
                    return;
                };
                let before = p.len();
                p.retain(|_, t| t.elapsed() < Self::PROBE_LOST_AFTER);
                before - p.len()
            };
            for _ in 0..lost {
                self.sample(None);
            }
            let id: [u8; 16] = enclave_crypto::kmac::kmac256(
                &secret,
                &counter.to_be_bytes(),
                "enclave/v1/net/loop-probe",
            );
            if let Ok(mut p) = self.probes.lock() {
                p.insert(id, tokio::time::Instant::now());
            }
            let frame = enclave_nym::frame::Request::probe(id).encode();
            let me = self.driver.address();
            if self.driver.send(&me, frame, 0).await.is_err()
                && let Ok(mut p) = self.probes.lock()
            {
                p.remove(&id);
            }
        }
    }
}

#[cfg(feature = "nym")]
impl NymTransport {
    /// One request to a stack's onion service over the mixnet client's Tor
    /// (the fallback route), and its reply.
    pub async fn exchange_tor(&self, host: &str, request: Vec<u8>) -> Result<Vec<u8>> {
        self.driver
            .exchange_tor(host, ONION_PORT, request)
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))
    }

    /// How long a request waits for its reply by default.
    pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    /// A transport over `driver`, reaching each server at its Nym address
    /// in `routes` (from the servers' descriptors). It probes its own
    /// gateway path and switches gateway when the path goes bad (RT-02).
    pub fn new(
        driver: std::sync::Arc<dyn enclave_nym::MixnetDriver>,
        routes: HashMap<ServerId, String>,
        timeout: std::time::Duration,
    ) -> Self {
        let pending: std::sync::Arc<std::sync::Mutex<HashMap<[u8; 16], PendingReply>>> =
            std::sync::Arc::default();
        let path = std::sync::Arc::new(GatewayPath {
            driver: std::sync::Arc::clone(&driver),
            monitor: std::sync::Mutex::default(),
            probes: std::sync::Mutex::default(),
            probe_ms: std::sync::atomic::AtomicU64::new(
                crate::schedule::Profile::Foreground
                    .pacing(false)
                    .probe
                    .as_millis() as u64,
            ),
            switches: std::sync::atomic::AtomicU64::new(0),
            switching: std::sync::atomic::AtomicBool::new(false),
            started: tokio::time::Instant::now(),
        });
        let reader = {
            let driver = std::sync::Arc::clone(&driver);
            let pending = std::sync::Arc::clone(&pending);
            let path = std::sync::Arc::clone(&path);
            tokio::spawn(async move {
                while let Some(m) = driver.recv().await {
                    if let Ok(r) = enclave_nym::frame::Request::decode(&m.data)
                        && r.kind == enclave_nym::frame::Kind::Probe
                    {
                        path.probe_back(&r.id);
                        continue;
                    }
                    // Anything that isn't a reply to a request we're
                    // waiting for is dropped.
                    let Ok(r) = enclave_nym::frame::Reply::decode(&m.data) else {
                        continue;
                    };
                    let tx = pending.lock().ok().and_then(|mut p| p.remove(&r.id));
                    if let Some(tx) = tx {
                        let _ = tx.send(r.data);
                    }
                }
            })
        };
        let prober = tokio::spawn(std::sync::Arc::clone(&path).probe_forever());
        Self {
            driver,
            routes: std::sync::RwLock::new(routes),
            pending,
            timeout,
            path,
            reader,
            prober,
        }
    }

    /// Requests waiting for a reply.
    pub fn in_flight(&self) -> usize {
        self.pending.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Gateway switches so far (RT-02).
    pub fn switches(&self) -> u64 {
        self.path.switches.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn route(&self, server: &ServerId) -> Result<String> {
        self.routes
            .read()
            .ok()
            .and_then(|r| r.get(server).cloned())
            .ok_or_else(|| NetError::Unreachable("no Nym address for that server".into()))
    }

    /// A sealed unit with no reply blocks: nothing comes back.
    async fn send_oneway(&self, server: &ServerId, sealed: Vec<u8>) -> Result<()> {
        let to = self.route(server)?;
        let mut id = [0u8; 16];
        enclave_crypto::rng::HedgedRng::new()
            .and_then(|mut r| r.fill("net/nym-request-id", &mut id))
            .map_err(|_| NetError::Unavailable("randomness"))?;
        let frame = enclave_nym::frame::Request::oneway(id, sealed)
            .map_err(|_| NetError::BadReply)?
            .encode();
        self.driver
            .send(&to, frame, 0)
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))
    }

    async fn roundtrip(&self, server: &ServerId, sealed: Vec<u8>) -> Result<Vec<u8>> {
        let to = self.route(server)?;
        let mut id = [0u8; 16];
        enclave_crypto::rng::HedgedRng::new()
            .and_then(|mut r| r.fill("net/nym-request-id", &mut id))
            .map_err(|_| NetError::Unavailable("randomness"))?;
        let frame = enclave_nym::frame::Request::for_sealed(id, sealed)
            .map_err(|_| NetError::BadReply)?
            .encode();
        let (tx, rx) = tokio::sync::oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let forget = || {
            if let Ok(mut p) = self.pending.lock() {
                p.remove(&id);
            }
        };
        let sent = tokio::time::Instant::now();
        if let Err(e) = self
            .driver
            .send(&to, frame, enclave_nym::frame::REPLY_LEN)
            .await
        {
            forget();
            return Err(NetError::Unreachable(e.to_string()));
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(reply)) => {
                self.path.sample(Some(sent.elapsed()));
                reply.ok_or_else(|| {
                    NetError::Unreachable("the ingress couldn't reach its server".into())
                })
            }
            _ => {
                forget();
                self.path.sample(None);
                Err(NetError::Unreachable("no reply over the mixnet".into()))
            }
        }
    }
}

#[cfg(feature = "nym")]
impl Drop for NymTransport {
    fn drop(&mut self) {
        self.reader.abort();
        self.prober.abort();
    }
}

#[cfg(feature = "nym")]
#[async_trait::async_trait]
impl Transport for NymTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.roundtrip(server, request).await
    }

    async fn server_key(&self, server: &ServerId) -> Result<ServerKey> {
        let bundle = self.roundtrip(server, Vec::new()).await?;
        verify_key_bundle(server, &bundle, self.now())
    }

    async fn flush(&self, within: std::time::Duration) -> Result<bool> {
        Ok(self.driver.flush(within).await)
    }

    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        self.driver
            .fetch(method, url, body)
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))
    }

    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
        self.driver
            .buy_tickets(gate, token)
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))
    }

    async fn tickets_spent(&self) -> Result<u64> {
        self.driver
            .tickets_spent()
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))
    }

    fn set_pacing(&self, pacing: enclave_nym::Pacing) {
        self.path.probe_ms.store(
            u64::try_from(pacing.probe.as_millis())
                .unwrap_or(u64::MAX)
                .max(1),
            std::sync::atomic::Ordering::SeqCst,
        );
        self.driver.set_pacing(pacing);
    }

    async fn exchange_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        if request.len() != enclave_wire::UNIT_LEN {
            return self.roundtrip(server, request).await.map(Some);
        }
        self.send_oneway(server, request).await.map(|()| None)
    }

    async fn exchange_droppable_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        self.exchange_oneway(server, request).await
    }

    fn set_route(&self, server: ServerId, route: Route) {
        if let (Route::Nym(a), Ok(mut r)) = (route, self.routes.write()) {
            r.insert(server, a);
        }
    }
}
