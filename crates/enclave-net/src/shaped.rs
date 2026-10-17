//! Traffic shaping for a running client (`docs/09-transport.md` §9.4): a
//! [`Transport`] that only ever sends on the [`Scheduler`](crate::schedule)'s
//! clock.
//!
//! Every tick it sends exactly one 16,384-byte unit and one 2,048-byte poll.
//! A queued real request takes the slot of its size; an empty slot carries
//! cover that the wrapper seals itself (`Op::Cover` units, and polls of a
//! random mailbox, which the server refuses), byte for byte the same size
//! and sealed the same way. So an observer of the link sees the same
//! pattern whatever the user does: real traffic *replaces* cover and waits
//! for its slot. Requests are sent concurrently, so a slow reply never
//! delays the next tick.
//!
//! Two exceptions, both from the spec:
//!
//! * **Bulk**: in the Foreground and Background profiles, when more than
//!   [`BULK_AFTER`] requests of one size are waiting, up to
//!   [`BULK_PER_TICK`] more go out in that tick (large files, catch-up, a
//!   sync of many mailboxes). The app discloses bursts; the Maximum profile
//!   never bursts, so everything waits for its slot.
//! * **Droppable** requests ([`Transport::exchange_droppable`]: typing
//!   indicators) never take a slot a real request could use and never cause
//!   a burst; one that hasn't found a free slot within [`DROP_AFTER`] ticks
//!   is dropped. They therefore never add traffic.

use crate::schedule::Profile;
use crate::transport::{ServerId, Transport};
use crate::{NetError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_rpc::ServerKey;
use enclave_wire::{ENVELOPE_LEN, Op, POLL_LEN, RequestHeader, UNIT_LEN};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

/// Waiting requests of one size beyond which a bulk burst starts.
pub const BULK_AFTER: usize = 4;
/// Most extra requests of one size a burst adds to a tick (about 40 Sphinx
/// packets a second at the 3 s foreground tick).
pub const BULK_PER_TICK: usize = 12;
/// Ticks a droppable request waits for a free slot before it is dropped.
pub const DROP_AFTER: u32 = 2;

/// Whether traffic is shaped, and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shaping {
    /// Send at once (development, tests, the offline demo).
    Off,
    /// One of the three global profiles.
    On(Profile),
}

type Reply = oneshot::Sender<Result<Option<Vec<u8>>>>;

struct Job {
    server: ServerId,
    bytes: Vec<u8>,
    reply: Reply,
    droppable: bool,
    /// Sent with [`Transport::exchange_oneway`]: no answer over the mixnet.
    oneway: bool,
    /// A key fetch ([`Transport::server_key`]): poll-sized on the wire, so
    /// it takes a poll slot like any other request with an answer.
    key: bool,
    waited: u32,
}

/// What an observer of the link could log (tests): per tick, the sizes
/// sent, and which were real (only the client knows that).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TickLog {
    /// Sizes of everything sent in the tick.
    pub sizes: Vec<usize>,
    /// How many of them were real requests.
    pub real: usize,
}

struct State {
    shaping: Shaping,
    units: VecDeque<Job>,
    polls: VecDeque<Job>,
    /// Servers cover may go to (the home server first).
    servers: Vec<ServerId>,
    keys: HashMap<ServerId, ServerKey>,
    log: Option<Vec<TickLog>>,
}

/// The shaping wrapper. Create it with [`ShapedTransport::start`].
pub struct ShapedTransport {
    inner: Arc<dyn Transport>,
    state: Arc<Mutex<State>>,
    /// Open bulk transfers ([`Transport::set_bulk`]).
    bulk: std::sync::atomic::AtomicUsize,
    /// The pacing last given to `inner`.
    paced: Mutex<Option<enclave_nym::Pacing>>,
}

impl ShapedTransport {
    /// Wrap `inner`, sending cover to `servers` (at least the home server),
    /// and start the clock. Must run inside a tokio runtime.
    pub fn start(inner: Arc<dyn Transport>, shaping: Shaping, servers: Vec<ServerId>) -> Arc<Self> {
        let me = Arc::new(Self {
            inner,
            state: Arc::new(Mutex::new(State {
                shaping,
                units: VecDeque::new(),
                polls: VecDeque::new(),
                servers,
                keys: HashMap::new(),
                log: None,
            })),
            bulk: std::sync::atomic::AtomicUsize::new(0),
            paced: Mutex::new(None),
        });
        me.repace(false);
        let weak = Arc::downgrade(&me);
        tokio::spawn(async move {
            let mut rng = match HedgedRng::new() {
                Ok(r) => r,
                Err(_) => return,
            };
            loop {
                let delay = {
                    let Some(me) = weak.upgrade() else { return };
                    me.delay(&mut rng)
                };
                tokio::time::sleep(delay).await;
                let Some(me) = weak.upgrade() else { return };
                me.tick(&mut rng).await;
            }
        });
        me
    }

    /// Change profile (or switch shaping off).
    pub fn set_shaping(&self, s: Shaping) {
        if let Ok(mut st) = self.state.lock() {
            st.shaping = s;
        }
        self.repace(false);
    }

    /// The current setting.
    pub fn shaping(&self) -> Shaping {
        self.state.lock().map_or(Shaping::Off, |s| s.shaping)
    }

    /// Start keeping a per-tick log (tests).
    pub fn record(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.log = Some(Vec::new());
        }
    }

    /// Take the log so far.
    pub fn take_log(&self) -> Vec<TickLog> {
        self.state
            .lock()
            .ok()
            .and_then(|mut s| s.log.as_mut().map(std::mem::take))
            .unwrap_or_default()
    }

    /// Requests waiting for a slot.
    pub fn backlog(&self) -> usize {
        self.state
            .lock()
            .map_or(0, |s| s.units.len() + s.polls.len())
    }

    fn delay(&self, rng: &mut HedgedRng) -> Duration {
        let profile = match self.shaping() {
            Shaping::Off => return Duration::from_millis(500),
            Shaping::On(p) => p,
        };
        let mean = profile.mean_tick();
        if !profile.poisson() {
            return mean;
        }
        let r: [u8; 8] = rng.array("schedule/delay").unwrap_or([0x80; 8]);
        let u = ((u64::from_be_bytes(r) >> 11) as f64 + 1.0) / ((1u64 << 53) as f64 + 1.0);
        mean.mul_f64(-u.ln())
    }

    fn today(&self) -> u32 {
        (self.inner.now() / 86_400) as u32
    }

    /// Today's key for `server`, if fetched.
    fn cached_key(&self, server: &ServerId) -> Option<ServerKey> {
        let today = self.today();
        self.state
            .lock()
            .ok()?
            .keys
            .get(server)
            .filter(|k| k.key_id == today)
            .cloned()
    }

    /// A known server whose key for today hasn't been fetched yet: an empty
    /// poll slot fetches it, rather than a fetch outside the schedule (a
    /// first message to a server, or a new day, would show otherwise).
    fn missing_key(&self) -> Option<ServerId> {
        let today = self.today();
        let st = self.state.lock().ok()?;
        st.servers
            .iter()
            .find(|s| st.keys.get(*s).is_none_or(|k| k.key_id != today))
            .copied()
    }

    /// Fetch `server`'s key now (in a poll slot), keep it and answer.
    fn fetch_key(&self, server: ServerId, reply: Reply) {
        let inner = Arc::clone(&self.inner);
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let r = inner.server_key(&server).await;
            if let (Ok(k), Ok(mut st)) = (&r, state.lock()) {
                st.keys.insert(server, k.clone());
            }
            let _ = reply.send(r.map(|k| Some(crate::transport::encode_server_key(&k))));
        });
    }

    /// Cover of the given size for a random known server whose key is in
    /// hand.
    async fn cover(&self, size: usize, rng: &mut HedgedRng) -> Option<(ServerId, Vec<u8>)> {
        let servers: Vec<ServerId> = {
            let servers = self.state.lock().ok()?.servers.clone();
            servers
                .into_iter()
                .filter(|s| self.cached_key(s).is_some())
                .collect()
        };
        if servers.is_empty() {
            return None;
        }
        let pick: [u8; 2] = rng.array("shaped/server").ok()?;
        let server = servers[usize::from(u16::from_be_bytes(pick)) % servers.len()];
        let key = self.cached_key(&server)?;
        let h = RequestHeader {
            op: if size == UNIT_LEN {
                Op::Cover
            } else {
                Op::Poll
            },
            flags: 0,
            mailbox: rng.array("shaped/cover").ok()?,
            token: rng.array("shaped/cover").ok()?,
        };
        let bytes = if size == UNIT_LEN {
            let mut env = vec![0u8; ENVELOPE_LEN];
            rng.fill("shaped/cover", &mut env).ok()?;
            enclave_rpc::seal_request(&key, &h, &env, rng).ok()?.0
        } else {
            enclave_rpc::seal_poll(&key, &h, rng).ok()?.0
        };
        Some((server, bytes))
    }

    fn send(&self, job: Job) {
        if job.key {
            self.fetch_key(job.server, job.reply);
            return;
        }
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let r = if job.oneway {
                inner.exchange_oneway(&job.server, job.bytes).await
            } else {
                inner.exchange(&job.server, job.bytes).await.map(Some)
            };
            let _ = job.reply.send(r);
        });
    }

    /// Cover units go one way (nobody needs their answer); cover polls are
    /// answered like real polls, which they must look like.
    fn send_cover(&self, server: ServerId, bytes: Vec<u8>) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            if bytes.len() == UNIT_LEN {
                let _ = inner.exchange_oneway(&server, bytes).await;
            } else {
                let _ = inner.exchange(&server, bytes).await;
            }
        });
    }

    /// Take the jobs of one size for this tick: the slot, then a burst if
    /// allowed. Droppable jobs only take a slot no real request wants, and
    /// age out.
    fn take(q: &mut VecDeque<Job>, bulk: bool) -> (Vec<Job>, Vec<Job>) {
        let mut out = Vec::new();
        let real_waiting = q.iter().filter(|j| !j.droppable).count();
        let burst = if bulk && real_waiting > BULK_AFTER {
            BULK_PER_TICK
        } else {
            0
        };
        // Real requests first, in order.
        let mut i = 0;
        while i < q.len() && out.len() < 1 + burst {
            if !q[i].droppable {
                if let Some(j) = q.remove(i) {
                    out.push(j);
                }
            } else {
                i += 1;
            }
        }
        // A free slot may carry one droppable request.
        if out.is_empty()
            && let Some(pos) = q.iter().position(|j| j.droppable)
            && let Some(j) = q.remove(pos)
        {
            out.push(j);
        }
        // Droppable requests that waited too long are dropped.
        let mut dropped = Vec::new();
        let mut keep = VecDeque::with_capacity(q.len());
        while let Some(mut j) = q.pop_front() {
            if j.droppable {
                j.waited += 1;
                if j.waited > DROP_AFTER {
                    dropped.push(j);
                    continue;
                }
            }
            keep.push_back(j);
        }
        *q = keep;
        (out, dropped)
    }

    /// Tell `inner` how to pace, if that changed: the profile's pacing,
    /// at the bulk cap while a bulk window is open or `burst` (a tick
    /// sending more than one request of a size). Shaping off: no pacing.
    fn repace(&self, burst: bool) {
        let shaping = self.shaping();
        let bulk = burst || self.bulk.load(std::sync::atomic::Ordering::SeqCst) > 0;
        let want = match shaping {
            Shaping::Off => enclave_nym::Pacing {
                tick: Duration::ZERO,
                bulk: false,
                ..Profile::Foreground.pacing(false)
            },
            Shaping::On(p) => p.pacing(bulk),
        };
        let Ok(mut paced) = self.paced.lock() else {
            return;
        };
        if *paced != Some(want) {
            *paced = Some(want);
            self.inner.set_pacing(want);
        }
    }

    async fn tick(&self, rng: &mut HedgedRng) {
        let (units, polls, dropped_u, dropped_p) = {
            let Ok(mut st) = self.state.lock() else {
                return;
            };
            let bulk = match st.shaping {
                Shaping::Off => return,
                Shaping::On(p) => p.allows_bulk(),
            };
            let (u, du) = Self::take(&mut st.units, bulk);
            let (p, dp) = Self::take(&mut st.polls, bulk);
            (u, p, du, dp)
        };
        for j in dropped_u.into_iter().chain(dropped_p) {
            let _ = j.reply.send(Err(NetError::Dropped));
        }
        self.repace(units.len() > 1 || polls.len() > 1);
        let mut log = TickLog::default();
        // The poll slot first: when it fetches a key, the unit slot of the
        // same tick may need it for its cover.
        for (jobs, size) in [(polls, POLL_LEN), (units, UNIT_LEN)] {
            if jobs.is_empty() {
                // An empty poll slot fetches a key still missing, else
                // carries cover.
                if size == POLL_LEN
                    && let Some(server) = self.missing_key()
                {
                    log.sizes.push(POLL_LEN);
                    if let Ok(k) = self.inner.server_key(&server).await
                        && let Ok(mut st) = self.state.lock()
                    {
                        st.keys.insert(server, k);
                    }
                } else if let Some((server, bytes)) = self.cover(size, rng).await {
                    log.sizes.push(bytes.len());
                    self.send_cover(server, bytes);
                }
            } else {
                for j in jobs {
                    log.sizes.push(if j.key { POLL_LEN } else { j.bytes.len() });
                    log.real += 1;
                    self.send(j);
                }
            }
        }
        // Logged units first, as a tick has always been read.
        log.sizes.sort_unstable_by(|a, b| b.cmp(a));
        if let Ok(mut st) = self.state.lock()
            && let Some(l) = st.log.as_mut()
        {
            l.push(log);
        }
    }

    async fn enqueue(
        &self,
        server: &ServerId,
        request: Vec<u8>,
        droppable: bool,
        oneway: bool,
    ) -> Result<Option<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        // Decide under the lock, send (or wait) after releasing it.
        let direct = {
            let mut st = self
                .state
                .lock()
                .map_err(|_| NetError::Unavailable("shaper"))?;
            // In a bulk transfer, where the profile allows, real requests
            // go at the network's pace (the disclosed exception).
            let bulk_now = self.bulk.load(std::sync::atomic::Ordering::SeqCst) > 0
                && !droppable
                && matches!(st.shaping, Shaping::On(p) if p.allows_bulk());
            let shaped = st.shaping != Shaping::Off
                && !bulk_now
                && matches!(request.len(), UNIT_LEN | POLL_LEN);
            if shaped {
                if !st.servers.contains(server) {
                    st.servers.push(*server);
                }
                let size = request.len();
                let job = Job {
                    server: *server,
                    bytes: request,
                    reply: tx,
                    droppable,
                    oneway,
                    key: false,
                    waited: 0,
                };
                if size == UNIT_LEN {
                    st.units.push_back(job);
                } else {
                    st.polls.push_back(job);
                }
                None
            } else {
                // Off, or not shaped traffic: send it as it is.
                Some(request)
            }
        };
        match direct {
            Some(request) if oneway => self.inner.exchange_oneway(server, request).await,
            Some(request) => self.inner.exchange(server, request).await.map(Some),
            None => rx
                .await
                .map_err(|_| NetError::Unavailable("shaper stopped"))?,
        }
    }
}

#[async_trait::async_trait]
impl Transport for ShapedTransport {
    /// What was sent leaves; what is still queued for a tick stays queued
    /// (sending it now would break the shape; the outbox re-sends it).
    async fn flush(&self, within: std::time::Duration) -> Result<bool> {
        self.inner.flush(within).await
    }

    fn require_private(&self, on: bool) {
        self.inner.require_private(on);
    }

    fn use_fallback(&self, on: bool) {
        self.inner.use_fallback(on);
    }

    async fn tor_status(&self) -> Result<u8> {
        self.inner.tor_status().await
    }

    // Calls have their own constant-rate shape (`enclave_calls::shape`).
    async fn open_udp(&self, remote: &str) -> Result<crate::transport::Datagrams> {
        self.inner.open_udp(remote).await
    }

    async fn open_udp_any(
        &self,
    ) -> Result<(crate::transport::Datagrams, Option<std::net::SocketAddr>)> {
        self.inner.open_udp_any().await
    }

    // Outside the shape: Tor carries these, not the mixnet.
    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        self.inner.fetch(method, url, body).await
    }

    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
        self.inner.buy_tickets(gate, token).await
    }

    async fn connect_mixnet(&self, tickets: Vec<Vec<u8>>) -> Result<()> {
        self.inner.connect_mixnet(tickets).await
    }

    async fn tickets_spent(&self) -> Result<u64> {
        self.inner.tickets_spent().await
    }

    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.enqueue(server, request, false, false)
            .await?
            .ok_or(NetError::BadReply)
    }

    async fn exchange_droppable(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.enqueue(server, request, true, false)
            .await?
            .ok_or(NetError::BadReply)
    }

    async fn exchange_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        self.enqueue(server, request, false, true).await
    }

    async fn exchange_droppable_oneway(
        &self,
        server: &ServerId,
        request: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        self.enqueue(server, request, true, true).await
    }

    /// A key fetch is poll-sized on the wire: it waits for a poll slot
    /// (or comes from the keys the shaper already holds).
    async fn server_key(&self, server: &ServerId) -> Result<ServerKey> {
        if let Some(k) = self.cached_key(server) {
            return Ok(k);
        }
        let (tx, rx) = oneshot::channel();
        let off = {
            let mut st = self
                .state
                .lock()
                .map_err(|_| NetError::Unavailable("shaper"))?;
            let off = st.shaping == Shaping::Off;
            if !off && !st.servers.contains(server) {
                st.servers.push(*server);
            }
            if !off {
                st.polls.push_back(Job {
                    server: *server,
                    bytes: Vec::new(),
                    reply: tx,
                    droppable: false,
                    oneway: false,
                    key: true,
                    waited: 0,
                });
            }
            off
        };
        if off {
            return self.inner.server_key(server).await;
        }
        let bytes = rx
            .await
            .map_err(|_| NetError::Unavailable("shaper stopped"))??
            .ok_or(NetError::BadReply)?;
        crate::transport::decode_server_key(&bytes)
    }

    fn set_route(&self, server: ServerId, route: crate::transport::Route) {
        self.inner.set_route(server, route);
    }

    fn set_bulk(&self, on: bool) {
        use std::sync::atomic::Ordering::SeqCst;
        if on {
            self.bulk.fetch_add(1, SeqCst);
        } else {
            let _ = self
                .bulk
                .fetch_update(SeqCst, SeqCst, |n| Some(n.saturating_sub(1)));
        }
        self.repace(false);
    }

    fn now(&self) -> u64 {
        self.inner.now()
    }
}
