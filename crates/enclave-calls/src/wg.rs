//! The client↔relay link: WireGuard (`docs/11-calls.md` §3.1, §3.3).
//!
//! boringtun's Noise_IKpsk2 implementation, run without a network device:
//! the client's key pair is fresh for each call, the relay's is its static
//! WireGuard key (sent in the ticket reply), and the pre-shared key is the
//! ticket's for the current 120 s period (`wg_psk_i`), so the tunnel is
//! post-quantum through the ticket's X448 + ML-KEM exchange. At each period
//! the client starts a new tunnel with the new period's key; the old one
//! carries traffic until the new handshake completes, then goes.
//!
//! WireGuard carries IP packets, so each payload rides behind a fixed
//! 20-byte IPv4 header (`10.73.0.1 → 10.73.0.2`, protocol 253, "for
//! experimentation"): every datagram of a stream still has one size.
//!
//! Periods are counted on the relay's clock: the ticket reply carries the
//! relay's time, and the client keeps the difference.

use crate::ticket::Ticket;
use crate::{CallError, Result};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::HashMap;

/// Bytes of the IPv4 header each payload rides behind.
pub const IP_HEADER: usize = 20;
/// WireGuard's data overhead: type, receiver index, counter, tag.
pub const WG_OVERHEAD: usize = 32;
/// Largest datagram handled.
pub const MAX_DATAGRAM: usize = 2048;
/// Keepalive while idle (seconds); calls send constantly anyway.
const KEEPALIVE: u16 = 25;

/// The public half of a WireGuard secret key.
pub fn public_key(secret: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret)).to_bytes()
}

/// The IPv4 packet a payload rides in.
fn wrap(payload: &[u8]) -> Vec<u8> {
    let total = (IP_HEADER + payload.len()) as u16;
    let mut p = Vec::with_capacity(total as usize);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 64, 253, 0, 0, 10, 73, 0, 1, 10, 73, 0, 2]);
    p.extend_from_slice(payload);
    p
}

/// The payload of an IPv4 packet from [`wrap`].
fn unwrap(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < IP_HEADER || packet[0] != 0x45 || packet[9] != 253 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    packet.get(IP_HEADER..total).map(<[u8]>::to_vec)
}

/// One WireGuard tunnel: one period's pre-shared key.
struct Tunnel {
    period: u32,
    index: u32,
    tunn: Tunn,
    established: bool,
}

/// What a datagram from the other end gave.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// Datagrams to send back (handshake answers, queued packets).
    pub send: Vec<Vec<u8>>,
    /// The payload it carried, if any.
    pub payload: Option<Vec<u8>>,
}

/// Run a tunnel on one incoming datagram.
fn decapsulate(t: &mut Tunnel, dg: &[u8], out: &mut Received) -> Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut first = true;
    loop {
        let input: &[u8] = if first { dg } else { &[] };
        first = false;
        match t.tunn.decapsulate(None, input, &mut buf) {
            TunnResult::WriteToNetwork(b) => {
                out.send.push(b.to_vec());
                // Queued packets may follow a completed handshake.
                continue;
            }
            TunnResult::WriteToTunnelV4(p, _) => {
                t.established = true;
                out.payload = unwrap(p);
                return Ok(());
            }
            TunnResult::Done => {
                if t.tunn.time_since_last_handshake().is_some() {
                    t.established = true;
                }
                return Ok(());
            }
            TunnResult::WriteToTunnelV6(..) => return Err(CallError::Malformed),
            TunnResult::Err(_) => return Err(CallError::Crypto),
        }
    }
}

fn encapsulate(t: &mut Tunnel, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    match t.tunn.encapsulate(&wrap(payload), &mut buf) {
        TunnResult::WriteToNetwork(b) => Ok(vec![b.to_vec()]),
        TunnResult::Done => Ok(Vec::new()),
        TunnResult::Err(_) => Err(CallError::Crypto),
        _ => Err(CallError::Malformed),
    }
}

fn timers(t: &mut Tunnel) -> Vec<Vec<u8>> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    match t.tunn.update_timers(&mut buf) {
        TunnResult::WriteToNetwork(b) => vec![b.to_vec()],
        _ => Vec::new(),
    }
}

/// The receiver index of a handshake answer or data packet: which tunnel
/// it is for (`index << 8`, boringtun's local index layout).
fn receiver(dg: &[u8]) -> Option<u32> {
    match Tunn::parse_incoming_packet(dg).ok()? {
        Packet::HandshakeResponse(p) => Some(p.receiver_idx >> 8),
        Packet::PacketCookieReply(p) => Some(p.receiver_idx >> 8),
        Packet::PacketData(p) => Some(p.receiver_idx >> 8),
        Packet::HandshakeInit(_) => None,
    }
}

/// The client's end of a link to its relay.
pub struct ClientLink {
    secret: StaticSecret,
    relay: PublicKey,
    ticket: Ticket,
    /// Relay clock minus ours, seconds.
    offset: i64,
    tunnels: Vec<Tunnel>,
    next_index: u32,
}

impl ClientLink {
    /// A link with this call's key pair (`secret`, whose public half went
    /// in the ticket request), the relay's WireGuard key, the ticket, and
    /// the relay's clock minus ours.
    pub fn new(secret: [u8; 32], relay: [u8; 32], ticket: Ticket, offset: i64) -> Self {
        Self {
            secret: StaticSecret::from(secret),
            relay: PublicKey::from(relay),
            ticket,
            offset,
            tunnels: Vec::new(),
            next_index: 1,
        }
    }

    /// Session id on the relay.
    pub fn session(&self) -> [u8; 16] {
        self.ticket.session
    }

    /// Whether the ticket has run out.
    pub fn expired(&self, now: u64) -> bool {
        self.relay_time(now) >= self.ticket.expiry
    }

    fn relay_time(&self, now: u64) -> u64 {
        now.saturating_add_signed(self.offset)
    }

    /// The tunnel for the current period, made if needed; and the
    /// handshake initiation that starts it.
    fn current(&mut self, now: u64) -> Result<Vec<Vec<u8>>> {
        if self.expired(now) {
            return Err(CallError::Stale);
        }
        let period = self.ticket.period(self.relay_time(now));
        if self.tunnels.iter().any(|t| t.period == period) {
            return Ok(Vec::new());
        }
        let index = self.next_index;
        self.next_index = (self.next_index + 1) & 0x00ff_ffff;
        let psk = self.ticket.psk(period);
        let mut tunnel = Tunnel {
            period,
            index,
            tunn: Tunn::new(
                self.secret.clone(),
                self.relay,
                Some(*psk),
                Some(KEEPALIVE),
                index,
                None,
            ),
            established: false,
        };
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let init = match tunnel.tunn.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(b) => vec![b.to_vec()],
            _ => Vec::new(),
        };
        self.tunnels.push(tunnel);
        Ok(init)
    }

    /// Datagrams that carry `payload` to the relay (with a handshake when a
    /// new period's tunnel starts).
    pub fn send(&mut self, now: u64, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut out = self.current(now)?;
        // The newest tunnel that is up, else the newest (which queues the
        // packet until its handshake completes).
        let pick = self
            .tunnels
            .iter()
            .rposition(|t| t.established)
            .unwrap_or(self.tunnels.len().saturating_sub(1));
        let t = self.tunnels.get_mut(pick).ok_or(CallError::Stale)?;
        out.extend(encapsulate(t, payload)?);
        Ok(out)
    }

    /// A datagram from the relay.
    pub fn receive(&mut self, now: u64, dg: &[u8]) -> Result<Received> {
        let index = receiver(dg).ok_or(CallError::Malformed)?;
        let t = self
            .tunnels
            .iter_mut()
            .find(|t| t.index == index)
            .ok_or(CallError::UnknownKey)?;
        let mut out = Received::default();
        decapsulate(t, dg, &mut out)?;
        self.prune(now);
        Ok(out)
    }

    /// Timers (retries, keepalives) and a new period's tunnel: what to
    /// send now. Call every second or so.
    pub fn tick(&mut self, now: u64) -> Result<Vec<Vec<u8>>> {
        let mut out = self.current(now)?;
        for t in &mut self.tunnels {
            out.extend(timers(t));
        }
        self.prune(now);
        Ok(out)
    }

    /// Once the current period's tunnel is up, the older ones go.
    fn prune(&mut self, now: u64) {
        let period = self.ticket.period(self.relay_time(now));
        if self
            .tunnels
            .iter()
            .any(|t| t.period == period && t.established)
        {
            self.tunnels.retain(|t| t.period >= period);
        }
    }
}

/// One session's tunnels on the relay.
struct RelaySession {
    ticket: Ticket,
    tunnels: Vec<Tunnel>,
}

/// The relay's ends of its clients' links.
pub struct RelayLinks {
    secret: StaticSecret,
    public: PublicKey,
    /// Client WireGuard key → session.
    by_key: HashMap<[u8; 32], [u8; 16]>,
    sessions: HashMap<[u8; 16], RelaySession>,
    /// Tunnel index → session.
    index: HashMap<u32, [u8; 16]>,
    next_index: u32,
}

impl RelayLinks {
    /// With the relay's static WireGuard secret.
    pub fn new(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            by_key: HashMap::new(),
            sessions: HashMap::new(),
            index: HashMap::new(),
            next_index: 1,
        }
    }

    /// The relay's WireGuard public key (sent in ticket replies).
    pub fn public(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// A ticket was issued: the client with WireGuard key `client` may
    /// connect.
    pub fn add(&mut self, client: [u8; 32], ticket: Ticket) {
        self.by_key.insert(client, ticket.session);
        self.sessions.insert(
            ticket.session,
            RelaySession {
                ticket,
                tunnels: Vec::new(),
            },
        );
    }

    /// Forget sessions whose tickets ran out.
    pub fn expire(&mut self, now: u64) {
        self.sessions.retain(|_, s| now < s.ticket.expiry);
        let live = &self.sessions;
        self.by_key.retain(|_, sid| live.contains_key(sid));
        self.index.retain(|_, sid| live.contains_key(sid));
    }

    /// Whether a session is live.
    pub fn has(&self, session: &[u8; 16]) -> bool {
        self.sessions.contains_key(session)
    }

    /// A datagram from a client: its session and what it gave.
    pub fn receive(&mut self, now: u64, dg: &[u8]) -> Result<([u8; 16], Received)> {
        let packet = Tunn::parse_incoming_packet(dg).map_err(|_| CallError::Malformed)?;
        if let Packet::HandshakeInit(init) = &packet {
            // A new tunnel: whose key, and this period's pre-shared key.
            let half = parse_handshake_anon(&self.secret, &self.public, init)
                .map_err(|_| CallError::Crypto)?;
            let sid = *self
                .by_key
                .get(&half.peer_static_public)
                .ok_or(CallError::UnknownKey)?;
            let s = self.sessions.get_mut(&sid).ok_or(CallError::UnknownKey)?;
            if now >= s.ticket.expiry {
                return Err(CallError::Stale);
            }
            let period = s.ticket.period(now);
            let index = self.next_index;
            self.next_index = (self.next_index + 1) & 0x00ff_ffff;
            let mut t = Tunnel {
                period,
                index,
                tunn: Tunn::new(
                    self.secret.clone(),
                    PublicKey::from(half.peer_static_public),
                    Some(*s.ticket.psk(period)),
                    None,
                    index,
                    None,
                ),
                established: false,
            };
            let mut out = Received::default();
            decapsulate(&mut t, dg, &mut out)?;
            // At most the current and the previous period's tunnels.
            s.tunnels.retain(|o| o.period + 1 >= period);
            s.tunnels.push(t);
            self.index.insert(index, sid);
            return Ok((sid, out));
        }
        let index = receiver(dg).ok_or(CallError::Malformed)?;
        let sid = *self.index.get(&index).ok_or(CallError::UnknownKey)?;
        let s = self.sessions.get_mut(&sid).ok_or(CallError::UnknownKey)?;
        let t = s
            .tunnels
            .iter_mut()
            .find(|t| t.index == index)
            .ok_or(CallError::UnknownKey)?;
        let mut out = Received::default();
        decapsulate(t, dg, &mut out)?;
        Ok((sid, out))
    }

    /// Datagrams that carry `payload` to a session's client.
    pub fn send(&mut self, session: &[u8; 16], payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        let s = self
            .sessions
            .get_mut(session)
            .ok_or(CallError::UnknownKey)?;
        let t = s
            .tunnels
            .iter_mut()
            .rev()
            .find(|t| t.established)
            .ok_or(CallError::UnknownKey)?;
        encapsulate(t, payload)
    }
}

/// A direct call's link to the other person (`docs/11-calls.md` §4):
/// WireGuard between the two ends' fresh per-call keys (exchanged in
/// ratchet messages, so authenticated), under the call's direct-mode
/// pre-shared key. The caller initiates; WireGuard's own handshake is the
/// connectivity check, sent to each address the other side named.
pub struct DirectLink {
    tunnel: Tunnel,
    initiator: bool,
}

impl DirectLink {
    /// Our secret key, the other end's public key, the call's direct PSK,
    /// and whether we start the handshake (the caller).
    pub fn new(secret: [u8; 32], peer: [u8; 32], psk: [u8; 32], initiator: bool) -> Self {
        Self {
            tunnel: Tunnel {
                period: 0,
                index: 1,
                tunn: Tunn::new(
                    StaticSecret::from(secret),
                    PublicKey::from(peer),
                    Some(psk),
                    Some(KEEPALIVE),
                    1,
                    None,
                ),
                established: false,
            },
            initiator,
        }
    }

    /// Whether the handshake has completed.
    pub fn established(&self) -> bool {
        self.tunnel.established
    }

    /// A handshake initiation (the initiator, until the link is up; sent
    /// to every candidate address), else nothing.
    pub fn probe(&mut self) -> Vec<u8> {
        if !self.initiator || self.tunnel.established {
            return Vec::new();
        }
        let mut buf = vec![0u8; MAX_DATAGRAM];
        match self.tunnel.tunn.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            _ => Vec::new(),
        }
    }

    /// Datagrams that carry `payload` (queued until the handshake is done).
    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        encapsulate(&mut self.tunnel, payload)
    }

    /// A datagram from the other end.
    pub fn receive(&mut self, dg: &[u8]) -> Result<Received> {
        Tunn::parse_incoming_packet(dg).map_err(|_| CallError::Malformed)?;
        let mut out = Received::default();
        decapsulate(&mut self.tunnel, dg, &mut out)?;
        Ok(out)
    }

    /// Timers (rekeys, keepalives): what to send now. Every second or so.
    pub fn tick(&mut self) -> Vec<Vec<u8>> {
        timers(&mut self.tunnel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ticket::Ticket;

    fn ticket(now: u64) -> (Ticket, Ticket) {
        let a = Ticket::for_test([7; 16], now, now + 3600, [9; 32]);
        let b = Ticket::for_test([7; 16], now, now + 3600, [9; 32]);
        (a, b)
    }

    /// Carry datagrams between the two ends until neither has more.
    fn exchange(
        client: &mut ClientLink,
        relay: &mut RelayLinks,
        now: u64,
        mut up: Vec<Vec<u8>>,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let (mut at_relay, mut at_client) = (Vec::new(), Vec::new());
        for _ in 0..8 {
            let mut down = Vec::new();
            for dg in up.drain(..) {
                if let Ok((_, r)) = relay.receive(now, &dg) {
                    down.extend(r.send);
                    at_relay.extend(r.payload);
                }
            }
            for dg in down {
                if let Ok(r) = client.receive(now, &dg) {
                    up.extend(r.send);
                    at_client.extend(r.payload);
                }
            }
            if up.is_empty() {
                break;
            }
        }
        (at_relay, at_client)
    }

    #[test]
    fn payloads_cross_a_wireguard_link_and_periods_rekey() {
        let now = 1_800_000_000;
        let (tc, tr) = ticket(now);
        let client_secret = [3u8; 32];
        let client_pub = PublicKey::from(&StaticSecret::from(client_secret)).to_bytes();
        let mut relay = RelayLinks::new([5; 32]);
        relay.add(client_pub, tr);
        let mut client = ClientLink::new(client_secret, relay.public(), tc, 0);

        // The first payload waits for the handshake, then arrives.
        let up = client.send(now, b"hello relay").unwrap_or_default();
        let (got, _) = exchange(&mut client, &mut relay, now, up);
        assert_eq!(got, vec![b"hello relay".to_vec()]);
        // Down, then up again: all sizes equal for equal payloads.
        let down = relay.send(&[7; 16], b"hi client").unwrap_or_default();
        assert_eq!(down.len(), 1);
        let r = client.receive(now, &down[0]).unwrap_or_default();
        assert_eq!(r.payload.as_deref(), Some(&b"hi client"[..]));
        let a = client.send(now, &[1; 100]).unwrap_or_default();
        let b = client.send(now, &[2; 100]).unwrap_or_default();
        assert_eq!(a[0].len(), b[0].len());
        assert_eq!(a[0].len(), 100 + IP_HEADER + WG_OVERHEAD);

        // The next period: a new tunnel under the next key.
        let later = now + crate::ticket::PERIOD_SECS + 1;
        let up = client.tick(later).unwrap_or_default();
        assert!(!up.is_empty(), "a handshake for the new period");
        let mut up = up;
        up.extend(client.send(later, b"after the rekey").unwrap_or_default());
        let (got, _) = exchange(&mut client, &mut relay, later, up);
        assert!(got.contains(&b"after the rekey".to_vec()), "{got:?}");

        // A stranger's key gets nowhere; nor does a tampered datagram.
        let mut stranger = ClientLink::new([4; 32], relay.public(), ticket(now).0, 0);
        for dg in stranger.send(now, b"let me in").unwrap_or_default() {
            assert!(relay.receive(now, &dg).is_err());
        }
        let mut dg = client
            .send(later, b"x")
            .unwrap_or_default()
            .pop()
            .unwrap_or_default();
        let last = dg.len() - 1;
        dg[last] ^= 1;
        assert!(relay.receive(later, &dg).is_err());
        // Expired tickets end the link.
        assert!(client.send(now + 3600, b"late").is_err());
    }

    #[test]
    fn direct_links_handshake_and_carry_payloads() {
        let (a, b) = ([11u8; 32], [12u8; 32]);
        let psk = [13u8; 32];
        let mut caller = DirectLink::new(a, public_key(b), psk, true);
        let mut callee = DirectLink::new(b, public_key(a), psk, false);
        assert!(callee.probe().is_empty(), "only the caller probes");
        let init = caller.probe();
        assert!(!init.is_empty());
        let r = callee.receive(&init).unwrap();
        assert!(callee.established() || !r.send.is_empty());
        for dg in r.send {
            let back = caller.receive(&dg).unwrap();
            assert!(back.send.is_empty() || back.payload.is_none());
        }
        assert!(caller.established());
        assert!(caller.probe().is_empty(), "no more probes once up");
        let up = caller.send(b"hello direct").unwrap();
        let mut got = None;
        for dg in up {
            let r = callee.receive(&dg).unwrap();
            got = got.or(r.payload);
        }
        assert_eq!(got.as_deref(), Some(&b"hello direct"[..]));
        assert!(callee.established());
        for dg in callee.send(b"and back").unwrap() {
            assert_eq!(
                caller.receive(&dg).unwrap().payload.as_deref(),
                Some(&b"and back"[..])
            );
        }
        // The wrong pre-shared key (not this call) gets nowhere.
        let mut stranger = DirectLink::new([14; 32], public_key(b), [0; 32], true);
        let mut other = DirectLink::new(b, public_key([14; 32]), psk, false);
        let r = other.receive(&stranger.probe());
        assert!(r.is_err() || r.unwrap().send.iter().all(|d| stranger.receive(d).is_err()));
        assert!(!stranger.established());
    }
}
