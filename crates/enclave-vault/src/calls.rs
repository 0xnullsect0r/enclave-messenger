//! Calls (`docs/11-calls.md`): the vault's side.
//!
//! Signalling rides in ratchet messages (`enclave_core::Client::send_call`);
//! media goes over UDP to a relay, through netd. Each side has its own
//! relay, picked from an operator family that neither home server nor the
//! other relay belongs to (RT-18):
//!
//! 1. [`open_leg`]: fetch the relay's signed descriptor (checked against
//!    the server list), pay for a ticket with proof of work, and set up
//!    the WireGuard link the ticket keys.
//! 2. [`run`]: join the call's rendezvous on the relay, then every 20 ms
//!    send exactly one 160-byte SFrame packet (an Opus frame, or padding
//!    when muted: RT-19) and play one frame from the jitter buffer.
//!
//! Opus, echo cancellation and decoding happen in mediad
//! ([`crate::media::CallCodec`]); the keys never leave the vault. Nothing
//! about a call is stored but the line the conversation shows afterwards.

use crate::media::{CallCodec, CallDecode};
use enclave_calls::direct::Candidates;
use enclave_calls::relay::{
    P_KEEPALIVE, P_MEDIA, descriptor_part, descriptor_request, reflect_request, reflected,
    ticket_datagrams, ticket_reply,
};
use enclave_calls::shape::{Inner, Shaper, Stream, decode_plaintext};
use enclave_calls::signal::{CALLEE, CALLER, CallKeys};
use enclave_calls::ticket::{self, TicketKey};
use enclave_calls::wg::{self, ClientLink, DirectLink};
use enclave_crypto::rng::HedgedRng;
use enclave_federation::{ListedRelay, RelayDescriptor};
use enclave_ipc::Out;
use enclave_net::transport::{Datagrams, Transport, addressed, unaddressed};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a ticket is asked for (the relay gives at most 4 h).
pub const TICKET_SECS: u32 = 4 * 3600;
/// Frames the jitter buffer holds before it starts playing (60 ms).
const PLAYOUT_DELAY: usize = 3;
/// Frames behind the newest past which playing skips ahead (300 ms).
const MAX_BEHIND: u32 = 15;
/// Microphone frames kept waiting (80 ms); older ones are dropped.
const MIC_QUEUE: usize = 4;
/// Lost frames in a row concealed before playing silence.
const CONCEAL: u32 = 5;
/// Nothing from the other side for this long: the call has dropped.
const SILENCE_LIMIT: Duration = Duration::from_secs(20);
/// Not connected after this long: give up.
const CONNECT_LIMIT: Duration = Duration::from_secs(30);
/// SFrame metadata of the audio stream.
const AUDIO_AD: &[u8] = b"audio";
/// The once-a-second control payload (a join, a keepalive) is padded to
/// this many bytes, so a call that takes over a Maximum-privacy standby
/// tunnel ([`Standby`]) looks the same from outside.
const CONTROL_LEN: usize = 64;

/// A control payload padded to [`CONTROL_LEN`] (the relay reads only its
/// start).
fn control(mut p: Vec<u8>) -> Vec<u8> {
    if p.len() < CONTROL_LEN {
        p.resize(CONTROL_LEN, 0);
    }
    p
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Our end of a call at our relay: its socket and WireGuard link.
pub struct Leg {
    /// The socket (through netd).
    pub dg: Datagrams,
    /// The link the ticket keys.
    pub link: ClientLink,
    /// The relay.
    pub relay: ListedRelay,
}

/// Send each datagram; false when the socket closed.
fn send_all(dg: &Datagrams, out: Vec<Vec<u8>>) -> bool {
    out.into_iter().all(|d| dg.send.send(d).is_ok())
}

/// The next datagram within `wait`, if any (Err: the socket closed).
async fn recv_within(dg: &mut Datagrams, wait: Duration) -> Result<Option<Vec<u8>>, String> {
    match tokio::time::timeout(wait, dg.recv.recv()).await {
        Ok(Some(d)) => Ok(Some(d)),
        Ok(None) => Err("the call's connection closed".into()),
        Err(_) => Ok(None),
    }
}

/// Fetch the relay's descriptor, part by part, and check it against what
/// the server list says about the relay.
pub async fn fetch_descriptor(
    dg: &mut Datagrams,
    relay: &ListedRelay,
    now: u64,
) -> Result<RelayDescriptor, String> {
    let mut parts: Vec<Option<Vec<u8>>> = Vec::new();
    for _round in 0..6 {
        // Ask for what is missing (part 0 first, to learn the count).
        let missing: Vec<u8> = if parts.is_empty() {
            vec![0]
        } else {
            (0..parts.len() as u8)
                .filter(|i| parts[usize::from(*i)].is_none())
                .collect()
        };
        if !send_all(dg, missing.iter().map(|p| descriptor_request(*p)).collect()) {
            return Err("the call's connection closed".into());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(800);
        while let Some(d) = recv_within(
            dg,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?
        {
            let Some((part, count, bytes)) = descriptor_part(&d) else {
                continue;
            };
            if parts.is_empty() {
                parts = vec![None; count];
            }
            if count == parts.len() {
                parts[part] = Some(bytes.to_vec());
            }
            if parts.iter().all(Option::is_some) {
                break;
            }
        }
        if !parts.is_empty() && parts.iter().all(Option::is_some) {
            let bytes: Vec<u8> = parts.into_iter().flatten().flatten().collect();
            let d = RelayDescriptor::decode(&bytes).map_err(|e| e.to_string())?;
            d.verify(now)
                .map_err(|e| format!("relay descriptor: {e}"))?;
            if d.identity != relay.identity || d.addr != relay.addr {
                return Err("the relay isn't the one the server list names".into());
            }
            return Ok(d);
        }
    }
    Err("the relay didn't answer".into())
}

/// Set up our end of a call at `relay`: descriptor, ticket, link.
pub async fn open_leg(transport: &dyn Transport, relay: &ListedRelay) -> Result<Leg, String> {
    let mut dg = transport
        .open_udp(&relay.addr)
        .await
        .map_err(|e| e.to_string())?;
    let now = unix_now();
    let desc = fetch_descriptor(&mut dg, relay, now).await?;
    let day = (now / 86_400) as u32;
    let listed = desc
        .ticket_key(day)
        .or_else(|| desc.ticket_key(day.wrapping_sub(1)))
        .ok_or("the relay lists no ticket key for today")?;
    let key = TicketKey::decode(desc.id(), listed).map_err(|e| e.to_string())?;
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let secret: [u8; 32] = rng.array("calls/wg-secret").map_err(|e| e.to_string())?;
    let public = wg::public_key(secret);
    let effort = desc.ticket_effort;
    // The proof of work takes a moment: off the engine's thread.
    let (request, client, id) = tokio::task::spawn_blocking(move || {
        let (req, client) = ticket::request(&key, public, TICKET_SECS, effort, &mut rng)?;
        let id: [u8; 8] = rng.array("calls/ticket-id")?;
        Ok::<_, enclave_calls::CallError>((req, client, id))
    })
    .await
    .map_err(|_| "the ticket request stopped".to_string())?
    .map_err(|e| e.to_string())?;
    let mut reply = None;
    'tries: for _ in 0..4 {
        if !send_all(&dg, ticket_datagrams(id, &request)) {
            return Err("the call's connection closed".into());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
        while let Some(d) = recv_within(
            &mut dg,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?
        {
            if let Some((rid, r)) = ticket_reply(&d)
                && rid == id
            {
                reply = Some(r.to_vec());
                break 'tries;
            }
        }
    }
    let reply = reply.ok_or("the relay didn't give a ticket")?;
    let issued = client
        .finish(&reply, unix_now())
        .map_err(|e| e.to_string())?;
    if issued.relay_wg != desc.wg_key {
        return Err("the relay's ticket names another key".into());
    }
    Ok(Leg {
        dg,
        link: ClientLink::new(secret, issued.relay_wg, issued.ticket, issued.offset),
        relay: relay.clone(),
    })
}

/// Maximum privacy's standby tunnel (`docs/11-calls.md` §7): while the
/// app is in front, a leg to a relay that sends exactly what a call's
/// audio sends (one padded packet every 20 ms of the audio packet's size,
/// a control payload each second). A call takes the leg over, so a global
/// observer can't see an audio call start or end.
pub struct Standby {
    /// The relay it goes to.
    pub relay: ListedRelay,
    take: mpsc::UnboundedSender<tokio::sync::oneshot::Sender<Leg>>,
}

impl Standby {
    /// Start the padding on `leg`; `ended` hears when it stops by itself
    /// (the ticket ran out, the socket closed).
    pub fn start(leg: Leg, ended: mpsc::UnboundedSender<CallEvent>) -> Self {
        let relay = leg.relay.clone();
        let (take, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            if standby_loop(leg, rx).await {
                let _ = ended.send(CallEvent::StandbyEnded);
            }
        });
        Self { relay, take }
    }

    /// The leg, for a call (none if the standby had stopped).
    pub async fn take(self) -> Option<Leg> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.take.send(tx).ok()?;
        rx.await.ok()
    }
}

/// Pad until asked for the leg (or dropped). True when it stopped by
/// itself.
async fn standby_loop(
    mut leg: Leg,
    mut take: mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<Leg>>,
) -> bool {
    let padding = [
        &[P_KEEPALIVE][..],
        &[0u8; enclave_calls::shape::AUDIO_PACKET],
    ]
    .concat();
    let keepalive = control(vec![P_KEEPALIVE]);
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut ticks: u64 = 0;
    loop {
        tokio::select! {
            t = take.recv() => {
                if let Some(t) = t {
                    let _ = t.send(leg);
                }
                return false;
            }
            d = leg.dg.recv.recv() => {
                let Some(d) = d else { return true };
                if let Ok(got) = leg.link.receive(unix_now(), &d)
                    && !send_all(&leg.dg, got.send)
                {
                    return true;
                }
            }
            _ = tick.tick() => {
                ticks += 1;
                let now = unix_now();
                let mut dgs = Vec::new();
                if ticks % 50 == 1 {
                    match leg.link.tick(now) {
                        Ok(d) => dgs.extend(d),
                        Err(_) => return true,
                    }
                    dgs.extend(leg.link.send(now, &keepalive).unwrap_or_default());
                }
                dgs.extend(leg.link.send(now, &padding).unwrap_or_default());
                if !send_all(&leg.dg, dgs) {
                    return true;
                }
            }
        }
    }
}

/// Our side of a direct call (`docs/11-calls.md` §4), before the other
/// side's addresses are known.
pub struct DirectSide {
    /// A socket that talks to any address (through netd).
    pub dg: Datagrams,
    /// Our WireGuard secret for the direct link.
    pub secret: [u8; 32],
    /// What we tell the other side: our key and addresses.
    pub ours: Candidates,
}

/// A direct link being tried, or up.
pub struct DirectPath {
    dg: Datagrams,
    link: DirectLink,
    /// The addresses the other side named.
    peers: Vec<SocketAddr>,
    /// Where the link answered from (once up).
    at: Option<SocketAddr>,
    /// When it was last heard.
    heard: Option<tokio::time::Instant>,
}

impl std::fmt::Debug for DirectPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectPath")
            .field("peers", &self.peers.len())
            .field("up", &self.link.established())
            .finish()
    }
}

impl DirectPath {
    /// Our side, the other side's candidates, the call's direct PSK, and
    /// whether we start the handshake (the caller).
    pub fn new(side: DirectSide, theirs: &Candidates, psk: [u8; 32], initiator: bool) -> Self {
        Self {
            link: DirectLink::new(side.secret, theirs.wg, psk, initiator),
            dg: side.dg,
            peers: theirs.addrs.clone(),
            at: None,
            heard: None,
        }
    }

    /// Up and heard from lately: the media goes this way.
    fn usable(&self) -> bool {
        self.link.established()
            && self.at.is_some()
            && self.heard.is_some_and(|h| h.elapsed() < DIRECT_QUIET)
    }

    fn send_to(&self, to: SocketAddr, dgs: Vec<Vec<u8>>) {
        for d in dgs {
            let _ = self.dg.send.send(addressed(to, &d));
        }
    }

    /// Once a second: handshake probes to every address until the link is
    /// up (the callee sends a byte to each instead, opening its NAT for the
    /// caller's probes), then the link's timers.
    fn tick(&mut self) {
        if let (true, Some(at)) = (self.link.established(), self.at) {
            // A keepalive each second, so both ends keep hearing the link
            // while the other still sends through the relays.
            let mut t = self.link.tick();
            t.extend(self.link.send(&[P_KEEPALIVE]).unwrap_or_default());
            self.send_to(at, t);
            return;
        }
        let probe = self.link.probe();
        let probe = if probe.is_empty() { vec![0] } else { probe };
        for p in self.peers.clone() {
            self.send_to(p, vec![probe.clone()]);
        }
    }

    /// A datagram on the socket: the payload it carried, if any.
    fn arrived(&mut self, dg: &[u8]) -> Option<Vec<u8>> {
        let (from, bytes) = unaddressed(dg)?;
        let got = self.link.receive(bytes).ok()?;
        // WireGuard authenticated it: this is where the other side is.
        self.at = Some(from);
        self.heard = Some(tokio::time::Instant::now());
        self.send_to(from, got.send);
        got.payload
    }

    /// Send a payload; false when it can't go this way.
    fn send(&mut self, payload: &[u8]) -> bool {
        let Some(at) = self.at.filter(|_| self.usable()) else {
            return false;
        };
        match self.link.send(payload) {
            Ok(dgs) => {
                self.send_to(at, dgs);
                true
            }
            Err(_) => false,
        }
    }
}

/// How long the direct link may be quiet before the media goes back
/// through the relays.
const DIRECT_QUIET: Duration = Duration::from_secs(3);

/// Our side of a direct call: a socket that talks to any address, our
/// address as `relay` sees it (through any NAT) and on the local network,
/// and a fresh WireGuard key.
pub async fn open_direct(
    transport: &dyn Transport,
    relay: &ListedRelay,
) -> Result<DirectSide, String> {
    let relay_addr: SocketAddr = relay
        .addr
        .parse()
        .map_err(|_| "the relay's address isn't an IP address".to_string())?;
    let (mut dg, local) = transport.open_udp_any().await.map_err(|e| e.to_string())?;
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let nonce: [u8; 8] = rng
        .array("calls/reflect-nonce")
        .map_err(|e| e.to_string())?;
    let mut seen = None;
    'tries: for _ in 0..3 {
        if dg
            .send
            .send(addressed(relay_addr, &reflect_request(nonce)))
            .is_err()
        {
            return Err("the call's connection closed".into());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1000);
        while let Some(d) = recv_within(
            &mut dg,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await?
        {
            if let Some((from, bytes)) = unaddressed(&d)
                && from == relay_addr
                && let Some((n, addr)) = reflected(bytes)
                && n == nonce
            {
                seen = Some(addr);
                break 'tries;
            }
        }
    }
    let mut addrs: Vec<SocketAddr> = seen.into_iter().chain(local).collect();
    addrs.dedup();
    if addrs.is_empty() {
        return Err("couldn't find an address for a direct call".into());
    }
    let secret: [u8; 32] = rng.array("calls/direct-wg").map_err(|e| e.to_string())?;
    Ok(DirectSide {
        dg,
        secret,
        ours: Candidates {
            wg: wg::public_key(secret),
            addrs,
        },
    })
}

/// What the window says to a running call.
#[derive(Debug)]
pub enum ToCall {
    /// The microphone's next 20 ms.
    Mic(Vec<i16>),
    /// Microphone off (padding, the same size and rate) or on.
    Mute(bool),
    /// Camera off (video padding, the same size and rate) or on.
    Camera(bool),
    /// A camera frame (RGBA at the call's video size).
    Frame(Vec<u8>),
    /// Both sides agreed to a direct call and named their addresses: try
    /// the direct link (the relays carry the call until it is up, and again
    /// if it fails).
    Direct(Box<DirectPath>),
    /// A group call: raise (true) or lower our hand.
    Hand(bool),
    /// A group call: a reaction everyone sees for a moment.
    React(String),
}

/// What call work in the background tells the engine.
pub enum CallEvent {
    /// Our end at our relay is ready (or why not).
    Leg([u8; 16], Result<Box<Leg>, String>),
    /// A running call's news.
    Media([u8; 16], FromCall),
    /// Our side of a direct call is ready: its socket, key and addresses
    /// (or why not).
    Direct([u8; 16], Result<Box<DirectSide>, String>),
    /// The Maximum-privacy standby tunnel stopped by itself.
    StandbyEnded,
}

/// What a running call tells the engine.
#[derive(Debug, PartialEq, Eq)]
pub enum FromCall {
    /// The other side's media arrived.
    Connected,
    /// It ended by itself (why).
    Dropped(String),
    /// The media goes directly (true) or through the relays again.
    Direct(bool),
    /// A group call: someone's media arrived for the first time.
    Heard(u32),
    /// A group call: someone raised (true) or lowered their hand.
    Hand(u32, bool),
    /// A group call: someone's reaction.
    React(u32, String),
    /// A group call: our camera waits (true) while eight others are on,
    /// or goes on again.
    CamerasFull(bool),
}

/// Frames that arrived, by sequence number, and which to play next.
#[derive(Default)]
struct Jitter {
    frames: BTreeMap<u32, Vec<u8>>,
    next: Option<u32>,
    lost_run: u32,
}

impl Jitter {
    fn push(&mut self, seq: u32, opus: Vec<u8>) {
        if self.next.is_some_and(|n| seq < n) {
            return; // too late
        }
        if self.frames.len() < 64 {
            self.frames.insert(seq, opus);
        }
    }

    /// What to decode for the next 20 ms, or None (nothing to play yet, or
    /// silence after too many losses).
    fn pop(&mut self) -> Option<(CallDecode, Vec<u8>)> {
        let next = match self.next {
            Some(n) => n,
            None if self.frames.len() >= PLAYOUT_DELAY => *self.frames.keys().next()?,
            None => return None,
        };
        // Far behind (the other side's clock runs fast, or a burst came
        // in): skip ahead.
        let next = match self.frames.keys().next_back() {
            Some(&top) if top > next + MAX_BEHIND => top - PLAYOUT_DELAY as u32,
            _ => next,
        };
        self.frames = self.frames.split_off(&next);
        self.next = Some(next + 1);
        if let Some(f) = self.frames.remove(&next) {
            self.lost_run = 0;
            return Some((CallDecode::Packet, f));
        }
        self.lost_run += 1;
        if let Some(f) = self.frames.get(&(next + 1)) {
            return Some((CallDecode::Recover, f.clone()));
        }
        (self.lost_run <= CONCEAL).then(|| (CallDecode::Lost, Vec::new()))
    }
}

/// Everything a running call needs besides its leg.
pub struct Plan {
    /// Call id.
    pub id: [u8; 16],
    /// The call's keys.
    pub keys: CallKeys,
    /// We called.
    pub caller: bool,
    /// The other side's relay (`IP:PORT`): our relay forwards there.
    pub peer_relay: std::net::SocketAddr,
    /// The call's audio in mediad.
    pub codec: CallCodec,
    /// A video call: its codec in mediad and its tier.
    pub video: Option<(crate::media::VideoCodec, usize)>,
}

/// SFrame metadata of the video stream.
const VIDEO_AD: &[u8] = b"video";
/// Control message on the video stream: send a key frame.
const KEY_PLEASE: &[u8] = b"K";
/// Least time between asking for key frames.
const KEY_ASK_EVERY: Duration = Duration::from_secs(1);

/// The video half of a call: encoding and decoding run on a task of their
/// own (frames take tens of milliseconds), so the audio never waits.
struct VideoSide {
    shaper: Shaper,
    reassembler: enclave_calls::shape::Reassembler,
    /// Camera frames to encode (the newest two; older ones are dropped).
    frames: mpsc::Sender<Vec<u8>>,
    /// Units that arrived, to decode.
    units: mpsc::Sender<Vec<u8>>,
    /// Units encoded, to send.
    encoded: mpsc::UnboundedReceiver<Vec<Vec<u8>>>,
    /// The next frame must be a key frame (the other side asked).
    key: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Decoding failed: ask the other side for a key frame.
    lost: std::sync::Arc<std::sync::atomic::AtomicBool>,
    asked: Option<tokio::time::Instant>,
    camera: bool,
    tick: tokio::time::Interval,
}

impl VideoSide {
    fn start(
        codec: crate::media::VideoCodec,
        tier: usize,
        out: mpsc::UnboundedSender<Out>,
    ) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stream = Stream::Video(tier);
        let (frames, mut frame_rx) = mpsc::channel::<Vec<u8>>(2);
        let (units, mut unit_rx) = mpsc::channel::<Vec<u8>>(64);
        let (enc_tx, encoded) = mpsc::unbounded_channel();
        let key = std::sync::Arc::new(AtomicBool::new(true));
        let lost = std::sync::Arc::new(AtomicBool::new(false));
        let (k, l) = (std::sync::Arc::clone(&key), std::sync::Arc::clone(&lost));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    f = frame_rx.recv() => {
                        let Some(f) = f else { return };
                        let key = k.swap(false, Ordering::SeqCst);
                        match codec.encode(f, key).await {
                            Ok(u) if !u.is_empty() => {
                                if enc_tx.send(u).is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => k.store(true, Ordering::SeqCst),
                        }
                    }
                    u = unit_rx.recv() => {
                        let Some(u) = u else { return };
                        match codec.decode(u).await {
                            Ok(Some(img)) => {
                                let _ = out.send(Out::CallVideo(img.width, img.height, img.pixels));
                            }
                            Ok(None) => {}
                            Err(_) => l.store(true, Ordering::SeqCst),
                        }
                    }
                }
            }
        });
        let mut tick = tokio::time::interval(Duration::from_micros(stream.interval_us()));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        Self {
            shaper: Shaper::new(stream),
            reassembler: Default::default(),
            frames,
            units,
            encoded,
            key,
            lost,
            asked: None,
            camera: true,
            tick,
        }
    }

    /// The next fixed-size plaintext: encoded frames as they fit, a key
    /// frame request, or padding.
    fn next_plaintext(&mut self) -> Vec<u8> {
        use std::sync::atomic::Ordering;
        // Frames queue at most half a second; past that, drop them and
        // start again from a key frame.
        let limit = (1_000_000 / self.shaper.stream().interval_us().max(1) / 2) as usize;
        while let Ok(units) = self.encoded.try_recv() {
            if self.shaper.backlog() > limit {
                self.key.store(true, Ordering::SeqCst);
                continue;
            }
            for u in units {
                let _ = self.shaper.push_video_frame(&u);
            }
        }
        if self.lost.swap(false, Ordering::SeqCst)
            && self.asked.is_none_or(|a| a.elapsed() > KEY_ASK_EVERY)
        {
            self.asked = Some(tokio::time::Instant::now());
            let _ = self.shaper.push_control(KEY_PLEASE);
        }
        self.shaper.next_plaintext()
    }

    /// A video plaintext that arrived.
    fn arrived(&mut self, pt: &[u8]) {
        use std::sync::atomic::Ordering;
        match decode_plaintext(pt) {
            Ok(Inner::Media(frag)) => {
                if let Some(unit) = self.reassembler.push(&frag) {
                    // A full queue drops the unit; the decoder then asks
                    // for a key frame.
                    if self.units.try_send(unit).is_err() {
                        self.lost.store(true, Ordering::SeqCst);
                    }
                }
            }
            Ok(Inner::Control(c)) if c == KEY_PLEASE => self.key.store(true, Ordering::SeqCst),
            _ => {}
        }
    }
}

/// Run a call until the engine drops `cmds` or the call drops.
pub async fn run(
    mut leg: Leg,
    plan: Plan,
    mut cmds: mpsc::UnboundedReceiver<ToCall>,
    out: mpsc::UnboundedSender<Out>,
    events: mpsc::UnboundedSender<CallEvent>,
) {
    let mut plan = plan;
    let video = plan.video.take();
    let why = media_loop(&mut leg, plan.id, &plan, video, &mut cmds, &out, &events).await;
    let _ = events.send(CallEvent::Media(plan.id, FromCall::Dropped(why)));
}

/// A payload from the other side (through the relays or directly): media
/// into the jitter buffer or the video side. Whether it was audio.
fn take_payload(
    p: &[u8],
    video_len: usize,
    video: &mut Option<VideoSide>,
    receiver: &mut enclave_calls::sframe::Receiver,
    jitter: &mut Jitter,
) -> bool {
    if p.first() != Some(&P_MEDIA) {
        return false;
    }
    if video_len > 0 && p.len() - 1 == video_len {
        if let Some(v) = video.as_mut()
            && let Ok(pt) = receiver.unprotect(&p[1..], VIDEO_AD)
        {
            v.arrived(&pt);
        }
        return false;
    }
    let Ok(pt) = receiver.unprotect(&p[1..], AUDIO_AD) else {
        return false;
    };
    if let Ok(Inner::Media(f)) = decode_plaintext(&pt)
        && f.len() > 4
    {
        let s = u32::from_be_bytes([f[0], f[1], f[2], f[3]]);
        jitter.push(s, f[4..].to_vec());
    }
    true
}

/// Send a payload directly when that works, else through our relay; false
/// when the relay's socket closed.
fn send_payload(leg: &mut Leg, direct: &mut Option<DirectPath>, now: u64, payload: &[u8]) -> bool {
    if direct.as_mut().is_some_and(|d| d.send(payload)) {
        return true;
    }
    match leg.link.send(now, payload) {
        Ok(dgs) => send_all(&leg.dg, dgs),
        Err(_) => true,
    }
}

async fn media_loop(
    leg: &mut Leg,
    id: [u8; 16],
    plan: &Plan,
    video_codec: Option<(crate::media::VideoCodec, usize)>,
    cmds: &mut mpsc::UnboundedReceiver<ToCall>,
    out: &mpsc::UnboundedSender<Out>,
    events: &mpsc::UnboundedSender<CallEvent>,
) -> String {
    let (us, them) = if plan.caller {
        (CALLER, CALLEE)
    } else {
        (CALLEE, CALLER)
    };
    let mut sender = enclave_calls::sframe::Sender::new(us, &plan.keys.sframe_base(us, 0));
    let mut receiver = enclave_calls::sframe::Receiver::new(them, &plan.keys.sframe_base(them, 0));
    let join = control(enclave_calls::relay::join_payload(
        &plan.keys.rendezvous(),
        plan.peer_relay,
    ));
    let keepalive = control(vec![P_KEEPALIVE]);
    let mut shaper = Shaper::new(Stream::Audio);
    let mut jitter = Jitter::default();
    let mut mic: VecDeque<Vec<i16>> = VecDeque::new();
    let mut muted = false;
    let mut seq: u32 = 0;
    let started = tokio::time::Instant::now();
    let mut heard: Option<tokio::time::Instant> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut ticks: u64 = 0;
    let video_len = video_codec
        .as_ref()
        .map_or(0, |(_, t)| Stream::Video(*t).packet_len());
    let mut video = video_codec.map(|(codec, tier)| VideoSide::start(codec, tier, out.clone()));
    let mut direct: Option<DirectPath> = None;
    let mut on_direct = false;
    loop {
        tokio::select! {
            cmd = cmds.recv() => match cmd {
                Some(ToCall::Mic(pcm)) => {
                    mic.push_back(pcm);
                    while mic.len() > MIC_QUEUE {
                        mic.pop_front();
                    }
                }
                Some(ToCall::Mute(on)) => muted = on,
                Some(ToCall::Camera(on)) => {
                    if let Some(v) = video.as_mut() {
                        v.camera = on;
                    }
                }
                Some(ToCall::Frame(rgba)) => {
                    if let Some(v) = video.as_ref().filter(|v| v.camera) {
                        // Busy encoding: this frame is dropped.
                        let _ = v.frames.try_send(rgba);
                    }
                }
                Some(ToCall::Direct(mut p)) => {
                    p.tick();
                    direct = Some(*p);
                }
                // Group calls only.
                Some(ToCall::Hand(_) | ToCall::React(_)) => {}
                // The engine hung up.
                None => return String::new(),
            },
            d = leg.dg.recv.recv() => {
                let Some(d) = d else { return "The call's connection closed.".into() };
                let Ok(got) = leg.link.receive(unix_now(), &d) else { continue };
                if !send_all(&leg.dg, got.send) {
                    return "The call's connection closed.".into();
                }
                let Some(p) = got.payload else { continue };
                if !take_payload(&p, video_len, &mut video, &mut receiver, &mut jitter) {
                    continue;
                }
                if heard.is_none() {
                    let _ = events.send(CallEvent::Media(id, FromCall::Connected));
                }
                heard = Some(tokio::time::Instant::now());
            }
            d = async {
                match direct.as_mut() {
                    Some(p) => p.dg.recv.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(d) = d else {
                    // netd closed the direct socket: the relays carry on.
                    direct = None;
                    continue;
                };
                let Some(p) = direct.as_mut().and_then(|p| p.arrived(&d)) else { continue };
                if !take_payload(&p, video_len, &mut video, &mut receiver, &mut jitter) {
                    continue;
                }
                if heard.is_none() {
                    let _ = events.send(CallEvent::Media(id, FromCall::Connected));
                }
                heard = Some(tokio::time::Instant::now());
            }
            _ = async {
                match video.as_mut() {
                    Some(v) => {
                        v.tick.tick().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                let Some(v) = video.as_mut() else { continue };
                let pt = v.next_plaintext();
                let elapsed = started.elapsed().as_millis() as u64;
                if let Ok(packet) = sender.protect(elapsed, VIDEO_AD, &pt) {
                    let payload = [&[P_MEDIA][..], &packet].concat();
                    if !send_payload(leg, &mut direct, unix_now(), &payload) {
                        return "The call's connection closed.".into();
                    }
                }
            }
            _ = tick.tick() => {
                ticks += 1;
                let now = unix_now();
                // Once a second: link timers; and the join again until the
                // other side is heard (a lost datagram must not end it).
                if ticks % 50 == 1 {
                    let mut dgs = match leg.link.tick(now) {
                        Ok(d) => d,
                        Err(_) => return "The call's ticket ran out.".into(),
                    };
                    if heard.is_none() {
                        dgs.extend(leg.link.send(now, &join).unwrap_or_default());
                    } else {
                        dgs.extend(leg.link.send(now, &keepalive).unwrap_or_default());
                    }
                    if !send_all(&leg.dg, dgs) {
                        return "The call's connection closed.".into();
                    }
                    if let Some(p) = direct.as_mut() {
                        p.tick();
                        if p.usable() != on_direct {
                            on_direct = p.usable();
                            let _ = events.send(CallEvent::Media(id, FromCall::Direct(on_direct)));
                        }
                    }
                }
                match heard {
                    Some(h) if h.elapsed() > SILENCE_LIMIT => return "The call dropped.".into(),
                    None if started.elapsed() > CONNECT_LIMIT => {
                        return "Couldn't connect the call.".into();
                    }
                    _ => {}
                }
                // One frame up: ours, or padding while muted.
                let frame = mic.pop_front();
                if !muted && let Some(pcm) = frame
                    && let Ok(opus) = plan.codec.encode(&pcm).await
                {
                    let mut f = seq.to_be_bytes().to_vec();
                    f.extend_from_slice(&opus);
                    let _ = shaper.push_frame(&f);
                }
                seq = seq.wrapping_add(1);
                let pt = shaper.next_plaintext();
                let elapsed = started.elapsed().as_millis() as u64;
                if let Ok(packet) = sender.protect(elapsed, AUDIO_AD, &pt) {
                    let payload = [&[P_MEDIA][..], &packet].concat();
                    if !send_payload(leg, &mut direct, now, &payload) {
                        return "The call's connection closed.".into();
                    }
                }
                // One frame down.
                if let Some((how, bytes)) = jitter.pop()
                    && let Ok(pcm) = plan.codec.decode(how, &bytes).await
                {
                    let _ = out.send(Out::CallAudio(pcm));
                }
            }
        }
    }
}

/// A group call (`docs/11-calls.md` §8), besides its leg.
pub struct GroupPlan {
    /// Call id.
    pub id: [u8; 16],
    /// The call's keys (`CallKeys::group`).
    pub keys: CallKeys,
    /// Our participant id.
    pub me: u32,
    /// The SFU relay (our leg's relay forwards there; it may be the same).
    pub sfu: SocketAddr,
    /// When the call started (Unix ms): SFrame epochs count from here.
    pub started_ms: u64,
    /// The call's audio in mediad.
    pub codec: CallCodec,
    /// A video call: its codec and tier.
    pub video: Option<(crate::media::VideoCodec, usize)>,
}

/// Control messages on a group call's audio stream.
const HAND_UP: &[u8] = b"H1";
const HAND_DOWN: &[u8] = b"H0";
const REACT: u8 = b'R';
/// Most bytes of a reaction.
pub const MAX_REACTION: usize = 32;
/// A sender silent this long drops out of the mix.
const GROUP_QUIET: Duration = Duration::from_secs(3);

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A group call's video: frames encoded on a task, and each other
/// participant's units decoded by their own decoder.
struct GroupVideo {
    shaper: Shaper,
    reassemblers: std::collections::HashMap<u32, enclave_calls::shape::Reassembler>,
    frames: mpsc::Sender<Vec<u8>>,
    units: mpsc::Sender<(u32, Vec<u8>)>,
    encoded: mpsc::UnboundedReceiver<Vec<Vec<u8>>>,
    key: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lost: std::sync::Arc<std::sync::atomic::AtomicBool>,
    asked: Option<tokio::time::Instant>,
    camera: bool,
    tick: tokio::time::Interval,
    /// When each other participant's last picture arrived.
    filming: std::collections::HashMap<u32, tokio::time::Instant>,
    /// When our last frame went to the encoder.
    filmed: Option<tokio::time::Instant>,
    /// Our camera waits for a free place (told to the engine on change).
    full: bool,
}

/// Most cameras on at once in a group call: the 2.5 Mbit/s downlink (§8)
/// carries eight 300 kbit/s pictures.
pub const MAX_CAMERAS: usize = 8;

impl GroupVideo {
    fn start(
        codec: crate::media::VideoCodec,
        tier: usize,
        out: mpsc::UnboundedSender<Out>,
    ) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stream = Stream::Video(tier);
        let (frames, mut frame_rx) = mpsc::channel::<Vec<u8>>(2);
        let (units, mut unit_rx) = mpsc::channel::<(u32, Vec<u8>)>(64);
        let (enc_tx, encoded) = mpsc::unbounded_channel();
        let key = std::sync::Arc::new(AtomicBool::new(true));
        let lost = std::sync::Arc::new(AtomicBool::new(false));
        let (k, l) = (std::sync::Arc::clone(&key), std::sync::Arc::clone(&lost));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    f = frame_rx.recv() => {
                        let Some(f) = f else { return };
                        let key = k.swap(false, Ordering::SeqCst);
                        match codec.encode(f, key).await {
                            Ok(u) if !u.is_empty() => {
                                if enc_tx.send(u).is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => k.store(true, Ordering::SeqCst),
                        }
                    }
                    u = unit_rx.recv() => {
                        let Some((from, u)) = u else { return };
                        match codec.decode_from(from, u).await {
                            Ok(Some(img)) => {
                                let _ = out.send(Out::CallTile(from, img.width, img.height, img.pixels));
                            }
                            Ok(None) => {}
                            Err(_) => l.store(true, Ordering::SeqCst),
                        }
                    }
                }
            }
        });
        let mut tick = tokio::time::interval(Duration::from_micros(stream.interval_us()));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        Self {
            shaper: Shaper::new(stream),
            reassemblers: std::collections::HashMap::new(),
            frames,
            units,
            encoded,
            key,
            lost,
            asked: None,
            camera: true,
            tick,
            filming: std::collections::HashMap::new(),
            filmed: None,
            full: false,
        }
    }

    /// Whether a frame from our camera may go: a camera already on stays
    /// on; one coming on waits while eight others are.
    fn may_film(&mut self) -> bool {
        let now = tokio::time::Instant::now();
        self.filming
            .retain(|_, at| now.duration_since(*at) < GROUP_QUIET);
        let on = self
            .filmed
            .is_some_and(|at| now.duration_since(at) < Duration::from_secs(1));
        let ok = on || self.filming.len() < MAX_CAMERAS;
        if ok {
            self.filmed = Some(now);
        }
        ok
    }

    fn next_plaintext(&mut self) -> Vec<u8> {
        use std::sync::atomic::Ordering;
        let limit = (1_000_000 / self.shaper.stream().interval_us().max(1) / 2) as usize;
        while let Ok(units) = self.encoded.try_recv() {
            if self.shaper.backlog() > limit {
                self.key.store(true, Ordering::SeqCst);
                continue;
            }
            for u in units {
                let _ = self.shaper.push_video_frame(&u);
            }
        }
        if self.lost.swap(false, Ordering::SeqCst)
            && self.asked.is_none_or(|a| a.elapsed() > KEY_ASK_EVERY)
        {
            self.asked = Some(tokio::time::Instant::now());
            let _ = self.shaper.push_control(KEY_PLEASE);
        }
        self.shaper.next_plaintext()
    }

    fn arrived(&mut self, from: u32, pt: &[u8]) {
        use std::sync::atomic::Ordering;
        match decode_plaintext(pt) {
            Ok(Inner::Media(frag)) => {
                self.filming.insert(from, tokio::time::Instant::now());
                let r = self.reassemblers.entry(from).or_default();
                if let Some(unit) = r.push(&frag)
                    && self.units.try_send((from, unit)).is_err()
                {
                    self.lost.store(true, Ordering::SeqCst);
                }
            }
            Ok(Inner::Control(c)) if c == KEY_PLEASE => self.key.store(true, Ordering::SeqCst),
            _ => {}
        }
    }
}

/// Run a group call until the engine drops `cmds` or the link fails.
pub async fn run_group(
    mut leg: Leg,
    plan: GroupPlan,
    mut cmds: mpsc::UnboundedReceiver<ToCall>,
    out: mpsc::UnboundedSender<Out>,
    events: mpsc::UnboundedSender<CallEvent>,
) {
    let mut plan = plan;
    let video = plan.video.take();
    let why = group_loop(&mut leg, &plan, video, &mut cmds, &out, &events).await;
    let _ = events.send(CallEvent::Media(plan.id, FromCall::Dropped(why)));
}

async fn group_loop(
    leg: &mut Leg,
    plan: &GroupPlan,
    video_codec: Option<(crate::media::VideoCodec, usize)>,
    cmds: &mut mpsc::UnboundedReceiver<ToCall>,
    out: &mpsc::UnboundedSender<Out>,
    events: &mpsc::UnboundedSender<CallEvent>,
) -> String {
    use enclave_calls::sframe::{Receiver, Sender, parse_header};
    use std::collections::HashMap;
    let id = plan.id;
    let mut sender = Sender::new(plan.me, &plan.keys.sframe_base(plan.me, 0));
    let mut receivers: HashMap<u32, Receiver> = HashMap::new();
    let mut jitters: HashMap<u32, (Jitter, tokio::time::Instant)> = HashMap::new();
    let mut join = enclave_calls::relay::join_payload(&plan.keys.rendezvous(), plan.sfu);
    join[0] = enclave_calls::relay::P_JOIN_GROUP;
    let join = control(join);
    let keepalive = control(vec![P_KEEPALIVE]);
    let mut shaper = Shaper::new(Stream::Audio);
    let mut mic: VecDeque<Vec<i16>> = VecDeque::new();
    let mut muted = false;
    let mut said: VecDeque<Vec<u8>> = VecDeque::new();
    let mut seq: u32 = 0;
    let mut joined = false;
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut ticks: u64 = 0;
    let started = tokio::time::Instant::now();
    let video_len = video_codec
        .as_ref()
        .map_or(0, |(_, t)| Stream::Video(*t).packet_len());
    let mut video = video_codec.map(|(codec, tier)| GroupVideo::start(codec, tier, out.clone()));
    let elapsed = || unix_ms().saturating_sub(plan.started_ms);
    loop {
        tokio::select! {
            cmd = cmds.recv() => match cmd {
                Some(ToCall::Mic(pcm)) => {
                    mic.push_back(pcm);
                    while mic.len() > MIC_QUEUE {
                        mic.pop_front();
                    }
                }
                Some(ToCall::Mute(on)) => muted = on,
                Some(ToCall::Camera(on)) => {
                    if let Some(v) = video.as_mut() {
                        v.camera = on;
                    }
                }
                Some(ToCall::Frame(rgba)) => {
                    if let Some(v) = video.as_mut().filter(|v| v.camera) {
                        let ok = v.may_film();
                        if ok {
                            let _ = v.frames.try_send(rgba);
                        }
                        if v.full == ok {
                            v.full = !ok;
                            let _ = events.send(CallEvent::Media(id, FromCall::CamerasFull(!ok)));
                        }
                    }
                }
                Some(ToCall::Hand(up)) => said.push_back(if up { HAND_UP } else { HAND_DOWN }.to_vec()),
                Some(ToCall::React(r)) if r.len() <= MAX_REACTION => {
                    said.push_back([&[REACT][..], r.as_bytes()].concat());
                }
                Some(ToCall::React(_) | ToCall::Direct(_)) => {}
                None => return String::new(),
            },
            d = leg.dg.recv.recv() => {
                let Some(d) = d else { return "The call's connection closed.".into() };
                let Ok(got) = leg.link.receive(unix_now(), &d) else { continue };
                if !send_all(&leg.dg, got.send) {
                    return "The call's connection closed.".into();
                }
                let Some(p) = got.payload else { continue };
                if p.first() != Some(&enclave_calls::relay::P_BUNDLE) {
                    continue;
                }
                if !joined {
                    joined = true;
                    let _ = events.send(CallEvent::Media(id, FromCall::Connected));
                }
                for packet in enclave_calls::relay::unbundle(&p) {
                    let Ok((kid, _, _)) = parse_header(packet) else { continue };
                    let (from, epoch) = ((kid >> 32) as u32, kid as u32);
                    if from == plan.me {
                        continue;
                    }
                    let fresh = !receivers.contains_key(&from);
                    if fresh && receivers.len() >= enclave_calls::group::MAX_PARTICIPANTS {
                        continue;
                    }
                    let rx = receivers
                        .entry(from)
                        .or_insert_with(|| Receiver::at_epoch(from, &plan.keys.sframe_base(from, 0), epoch));
                    if video_len > 0 && packet.len() == video_len {
                        if let Some(v) = video.as_mut()
                            && let Ok(pt) = rx.unprotect(packet, VIDEO_AD)
                        {
                            v.arrived(from, &pt);
                        }
                        continue;
                    }
                    let Ok(pt) = rx.unprotect(packet, AUDIO_AD) else {
                        if fresh {
                            receivers.remove(&from);
                        }
                        continue;
                    };
                    if fresh {
                        let _ = events.send(CallEvent::Media(id, FromCall::Heard(from)));
                    }
                    match decode_plaintext(&pt) {
                        Ok(Inner::Media(f)) if f.len() > 4 => {
                            let s = u32::from_be_bytes([f[0], f[1], f[2], f[3]]);
                            let j = jitters
                                .entry(from)
                                .or_insert_with(|| (Jitter::default(), tokio::time::Instant::now()));
                            j.0.push(s, f[4..].to_vec());
                            j.1 = tokio::time::Instant::now();
                        }
                        Ok(Inner::Control(c)) => {
                            let news = match c.as_slice() {
                                HAND_UP => Some(FromCall::Hand(from, true)),
                                HAND_DOWN => Some(FromCall::Hand(from, false)),
                                [REACT, r @ ..] if r.len() <= MAX_REACTION => {
                                    String::from_utf8(r.to_vec()).ok().map(|r| FromCall::React(from, r))
                                }
                                _ => None,
                            };
                            if let Some(n) = news {
                                let _ = events.send(CallEvent::Media(id, n));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ = async {
                match video.as_mut() {
                    Some(v) => {
                        v.tick.tick().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                let Some(v) = video.as_mut() else { continue };
                let pt = v.next_plaintext();
                if let Ok(packet) = sender.protect(elapsed(), VIDEO_AD, &pt) {
                    let payload = [&[P_MEDIA][..], &packet].concat();
                    if let Ok(dgs) = leg.link.send(unix_now(), &payload)
                        && !send_all(&leg.dg, dgs)
                    {
                        return "The call's connection closed.".into();
                    }
                }
            }
            _ = tick.tick() => {
                ticks += 1;
                let now = unix_now();
                if ticks % 50 == 1 {
                    let mut dgs = match leg.link.tick(now) {
                        Ok(d) => d,
                        Err(_) => return "The call's ticket ran out.".into(),
                    };
                    // The join each second until the SFU's bundles come.
                    let c = if joined { &keepalive } else { &join };
                    dgs.extend(leg.link.send(now, c).unwrap_or_default());
                    if !send_all(&leg.dg, dgs) {
                        return "The call's connection closed.".into();
                    }
                }
                if !joined && started.elapsed() > CONNECT_LIMIT {
                    return "Couldn't connect the call.".into();
                }
                // One frame up: a hand or reaction first, then our voice
                // or padding.
                if let Some(c) = said.pop_front() {
                    let _ = shaper.push_control(&c);
                } else {
                    let frame = mic.pop_front();
                    if !muted && let Some(pcm) = frame
                        && let Ok(opus) = plan.codec.encode(&pcm).await
                    {
                        let mut f = seq.to_be_bytes().to_vec();
                        f.extend_from_slice(&opus);
                        let _ = shaper.push_frame(&f);
                    }
                }
                seq = seq.wrapping_add(1);
                let pt = shaper.next_plaintext();
                if let Ok(packet) = sender.protect(elapsed(), AUDIO_AD, &pt) {
                    let payload = [&[P_MEDIA][..], &packet].concat();
                    if let Ok(dgs) = leg.link.send(now, &payload)
                        && !send_all(&leg.dg, dgs)
                    {
                        return "The call's connection closed.".into();
                    }
                }
                // One mixed frame down: everyone heard lately.
                jitters.retain(|_, (_, at)| at.elapsed() < GROUP_QUIET);
                let frames: Vec<(u32, CallDecode, Vec<u8>)> = jitters
                    .iter_mut()
                    .filter_map(|(who, (j, _))| j.pop().map(|(how, b)| (*who, how, b)))
                    .collect();
                if !frames.is_empty()
                    && let Ok(pcm) = plan.codec.mix(&frames).await
                {
                    let _ = out.send(Out::CallAudio(pcm));
                }
            }
        }
    }
}

/// The relays to pick from, as `enclave_calls::route` takes them.
pub fn candidates(relays: &[ListedRelay]) -> Vec<enclave_calls::route::Candidate> {
    relays
        .iter()
        .map(|r| enclave_calls::route::Candidate {
            id: enclave_federation::relay_id(&r.identity),
            family: r.family.clone(),
            weight: 1,
        })
        .collect()
}

/// A random draw for picking a relay.
pub fn draw() -> u64 {
    HedgedRng::new()
        .and_then(|mut r| r.array::<8>("calls/relay-pick"))
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn jitter_buffer_plays_in_order_recovers_and_skips_ahead() {
        let mut j = Jitter::default();
        assert!(j.pop().is_none());
        j.push(10, vec![10]);
        j.push(12, vec![12]);
        assert!(j.pop().is_none(), "waits for {PLAYOUT_DELAY} frames");
        j.push(11, vec![11]);
        assert_eq!(j.pop(), Some((CallDecode::Packet, vec![10])));
        assert_eq!(j.pop(), Some((CallDecode::Packet, vec![11])));
        assert_eq!(j.pop(), Some((CallDecode::Packet, vec![12])));
        // 13 lost, 14 here: recovered from 14's FEC, then 14.
        j.push(14, vec![14]);
        assert_eq!(j.pop(), Some((CallDecode::Recover, vec![14])));
        assert_eq!(j.pop(), Some((CallDecode::Packet, vec![14])));
        // Late frames are dropped.
        j.push(13, vec![13]);
        assert!(j.frames.is_empty());
        // Losses are concealed, then silence.
        for _ in 0..CONCEAL {
            assert_eq!(j.pop(), Some((CallDecode::Lost, Vec::new())));
        }
        assert_eq!(j.pop(), None);
        // A burst far ahead: skip to just behind the newest.
        for s in 100..120 {
            j.push(s, vec![s as u8]);
        }
        assert_eq!(j.pop(), Some((CallDecode::Packet, vec![116])));
    }
}
