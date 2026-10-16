//! The Enclave call relay (`docs/11-calls.md` §3, `docs/12-servers.md` §5).
//!
//! ```text
//! caller ──WireGuard (ticket PSK)──▶ relay A ══relay link══ relay B ◀──WireGuard (ticket PSK)── callee
//! ```
//!
//! Each caller joins its own relay with the call's rendezvous id and the
//! address of the other relay. A relay sees its own client's address, the
//! peer relay's address, and packet sizes and timing, never the other
//! client's address and never media keys (media is SFrame end to end).
//!
//! The client hop is WireGuard (`enclave_calls::wg`) with the relay's
//! static WireGuard key and the ticket's per-period pre-shared key. Tickets
//! are asked for over UDP (`T_TICKET`, in two datagrams: a request is
//! larger than one) and paid with proof of work bound to the request
//! (ADR 0006). The relay-to-relay hop is sealed with a key from the two
//! relays' static X448 keys.
//!
//! The relay core is sans-I/O ([`Relay::handle`] maps one datagram to the
//! datagrams to send); [`serve`] runs it on a UDP socket.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use enclave_calls::ticket::TicketSecretKey;
use enclave_calls::wg::RelayLinks;
use enclave_calls::{CallError, labels};
use enclave_crypto::kem::{X448Public, X448Secret};
use enclave_crypto::kmac::kmac256_parts;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod keys;
pub mod ledger;

pub use ledger::{MemorySpent, Spent};

/// Datagram type: relay link (from a peer relay's address only).
pub const T_RELAY: u8 = 0x02;
/// Datagram type: a ticket request part, or a ticket reply. (A WireGuard
/// datagram starts with its type, 1 to 4, then three zero bytes.)
pub const T_TICKET: u8 = 0x10;
/// Datagram type: a request for one part of the signed descriptor, or
/// that part.
pub const T_DESC: u8 = 0x11;
/// A descriptor request is padded to this many bytes, so the relay never
/// answers with more than it was sent (no amplification).
pub const DESC_REQUEST: usize = 1100;
/// Bytes of the descriptor in one reply datagram.
pub const DESC_PART: usize = 1024;
/// Most parts a descriptor is sent in.
pub const MAX_DESC_PARTS: usize = 32;
/// Bytes of a ticket request in one datagram.
pub const TICKET_PART: usize = 1024;
/// Proof-of-work effort a relay asks for a ticket, by default.
pub const TICKET_EFFORT: u32 = 16;
/// Link payload: join a rendezvous.
pub const P_JOIN: u8 = 0x10;
/// Link payload: a media packet.
pub const P_MEDIA: u8 = 0x11;
/// Link payload: keepalive.
pub const P_KEEPALIVE: u8 = 0x12;

/// What a relay publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Relay id.
    pub id: [u8; 16],
    /// Operator family (callers pick relays from distinct families).
    pub family: String,
    /// UDP address.
    pub addr: SocketAddr,
    /// Static X448 key for relay links.
    pub link_key: [u8; 56],
}

struct Session {
    client: Option<SocketAddr>,
    rendezvous: Option<[u8; 16]>,
    peer: Option<SocketAddr>,
}

struct Peer {
    send: SealKey,
    recv: SealKey,
    counter: u64,
    top: Option<u64>,
    bits: u128,
}

/// Counters an operator may see (aggregate only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams forwarded to a peer relay.
    pub to_peer: u64,
    /// Datagrams delivered to clients.
    pub to_client: u64,
    /// Datagrams dropped (bad auth, unknown session, replay).
    pub dropped: u64,
}

/// A relay.
pub struct Relay {
    desc: Descriptor,
    link_secret: X448Secret,
    /// Ticket keys, newest first (today's, and yesterday's for requests
    /// sealed just before midnight).
    tickets: Vec<TicketSecretKey>,
    sessions: HashMap<[u8; 16], Session>,
    rendezvous: HashMap<[u8; 16], [u8; 16]>,
    peers: HashMap<SocketAddr, Peer>,
    spent: Box<dyn Spent + Send>,
    stats: Stats,
    rng: HedgedRng,
    /// Clients' WireGuard links.
    links: RelayLinks,
    /// Proof-of-work effort a ticket costs.
    effort: u32,
    /// Ticket requests arriving in parts: (from, request id) → parts.
    partial: HashMap<(SocketAddr, [u8; 8]), Partial>,
    /// The signed descriptor (`enclave_federation::RelayDescriptor`)
    /// clients fetch before asking for a ticket.
    published: Vec<u8>,
}

/// A ticket request still missing parts.
struct Partial {
    parts: Vec<Option<Vec<u8>>>,
    since: u64,
}

/// Most ticket requests held while their parts arrive.
const MAX_PARTIAL: usize = 1024;

impl Relay {
    /// A relay at `addr` with fresh random keys and an in-memory ledger
    /// (tests, development).
    pub fn new(id: [u8; 16], family: &str, addr: SocketAddr, day: u32) -> Result<Self, CallError> {
        let mut rng = HedgedRng::new()?;
        let (link_secret, _) = X448Secret::generate(&mut rng)?;
        let tickets = TicketSecretKey::generate(id, day, &mut rng)?;
        Self::with_keys(
            id,
            family,
            addr,
            link_secret,
            vec![tickets],
            Box::new(MemorySpent::default()),
        )
    }

    /// A relay with keys from disk (`keys::RelayKeys`) and a durable
    /// ledger of spent tokens.
    pub fn with_keys(
        id: [u8; 16],
        family: &str,
        addr: SocketAddr,
        link_secret: X448Secret,
        tickets: Vec<TicketSecretKey>,
        spent: Box<dyn Spent + Send>,
    ) -> Result<Self, CallError> {
        if tickets.is_empty() {
            return Err(CallError::UnknownKey);
        }
        let wg = wg_secret(&link_secret);
        Ok(Self {
            desc: Descriptor {
                id,
                family: family.into(),
                addr,
                link_key: link_secret.public().0,
            },
            links: RelayLinks::new(wg),
            effort: TICKET_EFFORT,
            partial: HashMap::new(),
            published: Vec::new(),
            link_secret,
            tickets,
            sessions: HashMap::new(),
            rendezvous: HashMap::new(),
            peers: HashMap::new(),
            spent,
            stats: Stats::default(),
            rng: HedgedRng::new()?,
        })
    }

    /// Replace the ticket keys (at midnight UTC), newest first.
    pub fn set_ticket_keys(&mut self, tickets: Vec<TicketSecretKey>) {
        if !tickets.is_empty() {
            self.tickets = tickets;
        }
    }

    /// Public descriptor.
    pub fn descriptor(&self) -> &Descriptor {
        &self.desc
    }

    /// The ticket key clients request tickets with (today's).
    pub fn ticket_key(&self) -> &enclave_calls::ticket::TicketKey {
        self.tickets[0].public()
    }

    /// Aggregate counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Addresses of clients this relay has seen (for tests and audits).
    pub fn client_addrs(&self) -> Vec<SocketAddr> {
        self.sessions.values().filter_map(|s| s.client).collect()
    }

    /// Trust a peer relay (in production: a Rosenpass/WireGuard peer).
    pub fn add_peer(&mut self, peer: &Descriptor) -> Result<(), CallError> {
        let dh = self
            .link_secret
            .diffie_hellman(&X448Public(peer.link_key))?;
        let dir = |from: &[u8; 16], to: &[u8; 16]| {
            SealKey::from_bytes(kmac256_parts(&dh[..], &[from, to], labels::RELAY_LINK))
        };
        self.peers.insert(
            peer.addr,
            Peer {
                send: dir(&self.desc.id, &peer.id),
                recv: dir(&peer.id, &self.desc.id),
                counter: 0,
                top: None,
                bits: 0,
            },
        );
        Ok(())
    }

    /// Serve this signed descriptor (re-signed when the ticket keys turn
    /// over at midnight UTC).
    pub fn set_published(&mut self, descriptor: Vec<u8>) {
        if descriptor.len() <= DESC_PART * MAX_DESC_PARTS {
            self.published = descriptor;
        }
    }

    /// Ask this much proof of work for a ticket.
    pub fn set_ticket_effort(&mut self, effort: u32) {
        self.effort = effort;
    }

    /// The proof-of-work effort a ticket costs here.
    pub fn ticket_effort(&self) -> u32 {
        self.effort
    }

    /// The relay's WireGuard key.
    pub fn wg_public(&self) -> [u8; 32] {
        self.links.public()
    }

    /// Ticket service: open a request, check and burn its proof of work,
    /// issue a ticket and let its WireGuard key connect.
    pub fn issue_ticket(&mut self, request: &[u8], now: u64) -> Result<Vec<u8>, CallError> {
        let epoch = request
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(CallError::Malformed)?;
        let key = self
            .tickets
            .iter()
            .find(|k| k.public().epoch == epoch)
            .ok_or(CallError::UnknownKey)?;
        let accepted = key.accept(request, self.effort)?;
        if !self.spent.spend(&accepted.spend, now)? {
            return Err(CallError::Replay);
        }
        let duration = u64::from(accepted.duration.min(4 * 3600));
        let session: [u8; 16] = self.rng.array("relay/session")?;
        let wg_client = accepted.wg_public;
        let (reply, ticket) = accepted.issue(
            session,
            now,
            now + duration,
            self.links.public(),
            &mut self.rng,
        )?;
        self.links.add(wg_client, ticket);
        self.sessions.insert(
            session,
            Session {
                client: None,
                rendezvous: None,
                peer: None,
            },
        );
        Ok(reply)
    }

    /// One part of a ticket request: the reply datagram once every part
    /// is in.
    fn on_ticket(
        &mut self,
        from: SocketAddr,
        dg: &[u8],
        now: u64,
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let (id, index, count, part) = match dg {
            [_, rest @ ..] if rest.len() > 10 => {
                let id: [u8; 8] = rest[..8].try_into().map_err(|_| CallError::Malformed)?;
                (id, usize::from(rest[8]), usize::from(rest[9]), &rest[10..])
            }
            _ => return Err(CallError::Malformed),
        };
        if count == 0 || count > 4 || index >= count || part.len() > TICKET_PART {
            return Err(CallError::Malformed);
        }
        self.partial.retain(|_, p| now < p.since + 10);
        if self.partial.len() >= MAX_PARTIAL && !self.partial.contains_key(&(from, id)) {
            return Err(CallError::Malformed);
        }
        let p = self.partial.entry((from, id)).or_insert_with(|| Partial {
            parts: vec![None; count],
            since: now,
        });
        if p.parts.len() != count {
            return Err(CallError::Malformed);
        }
        p.parts[index] = Some(part.to_vec());
        if p.parts.iter().any(Option::is_none) {
            return Ok(Vec::new());
        }
        let request: Vec<u8> = self
            .partial
            .remove(&(from, id))
            .map(|p| p.parts.into_iter().flatten().flatten().collect())
            .unwrap_or_default();
        let reply = self.issue_ticket(&request, now)?;
        Ok(vec![(from, [&[T_TICKET][..], &id, &reply].concat())])
    }

    /// One part of the signed descriptor, for a request at least as long
    /// as the answer.
    fn on_descriptor(
        &mut self,
        from: SocketAddr,
        dg: &[u8],
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        if dg.len() < DESC_REQUEST || self.published.is_empty() {
            return Err(CallError::Malformed);
        }
        let parts: Vec<&[u8]> = self.published.chunks(DESC_PART).collect();
        let part = usize::from(dg[1]);
        let chunk = parts.get(part).ok_or(CallError::Malformed)?;
        Ok(vec![(
            from,
            [&[T_DESC, part as u8, parts.len() as u8][..], chunk].concat(),
        )])
    }

    /// Drop expired sessions and spent tokens past their retention.
    pub fn expire(&mut self, now: u64) {
        if let Err(e) = self.spent.prune(now) {
            eprintln!("enclave-relay: pruning spent tokens failed: {e}");
        }
        self.links.expire(now);
        let links = &self.links;
        self.sessions.retain(|sid, _| links.has(sid));
        let live: std::collections::HashSet<[u8; 16]> = self.sessions.keys().copied().collect();
        self.rendezvous.retain(|_, s| live.contains(s));
    }

    /// Handle one datagram; returns what to send where.
    pub fn handle(&mut self, from: SocketAddr, dg: &[u8], now: u64) -> Vec<(SocketAddr, Vec<u8>)> {
        let out = if self.peers.contains_key(&from) {
            match dg.first() {
                Some(&T_RELAY) => self.on_peer(from, &dg[1..], now),
                _ => Err(CallError::Malformed),
            }
        } else if dg.first() == Some(&T_TICKET) {
            self.on_ticket(from, dg, now)
        } else if dg.first() == Some(&T_DESC) {
            self.on_descriptor(from, dg)
        } else {
            self.on_client(from, dg, now)
        };
        out.unwrap_or_else(|_| {
            self.stats.dropped += 1;
            Vec::new()
        })
    }

    fn on_client(
        &mut self,
        from: SocketAddr,
        dg: &[u8],
        now: u64,
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let (sid, got) = self.links.receive(now, dg)?;
        let s = self.sessions.get_mut(&sid).ok_or(CallError::UnknownKey)?;
        s.client = Some(from); // roaming: follow the latest authenticated address
        let mut out: Vec<(SocketAddr, Vec<u8>)> = got.send.into_iter().map(|d| (from, d)).collect();
        let Some(pt) = got.payload else {
            return Ok(out);
        };
        let routed = match pt.first() {
            Some(&P_JOIN) => {
                let (rv, peer) = decode_join(&pt[1..])?;
                if !self.peers.contains_key(&peer) && peer != self.desc.addr {
                    return Err(CallError::UnknownKey);
                }
                s.rendezvous = Some(rv);
                s.peer = Some(peer);
                self.rendezvous.insert(rv, sid);
                Ok(Vec::new())
            }
            Some(&P_MEDIA) => {
                let (rv, peer) = (
                    s.rendezvous.ok_or(CallError::UnknownKey)?,
                    s.peer.ok_or(CallError::UnknownKey)?,
                );
                if peer == self.desc.addr {
                    // Both legs on this relay (only when families allow it).
                    return self.deliver(&rv, Some(sid), &pt[1..], now);
                }
                let p = self.peers.get_mut(&peer).ok_or(CallError::UnknownKey)?;
                let mut hdr = [0u8; 24];
                hdr[..16].copy_from_slice(&rv);
                hdr[16..].copy_from_slice(&p.counter.to_be_bytes());
                let ct = seal::seal_compact(&p.send, &hdr[16..], &hdr, &pt[1..])?;
                p.counter += 1;
                self.stats.to_peer += 1;
                Ok(vec![(peer, [&[T_RELAY][..], &hdr, &ct].concat())])
            }
            Some(&P_KEEPALIVE) => Ok(Vec::new()),
            _ => Err(CallError::Malformed),
        };
        out.extend(routed?);
        Ok(out)
    }

    fn on_peer(
        &mut self,
        from: SocketAddr,
        dg: &[u8],
        now: u64,
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let p = self.peers.get_mut(&from).ok_or(CallError::UnknownKey)?;
        if dg.len() < 24 + seal::TAG_LEN {
            return Err(CallError::Malformed);
        }
        let counter = u64::from_be_bytes(dg[16..24].try_into().map_err(|_| CallError::Malformed)?);
        if let Some(top) = p.top
            && counter <= top
            && (top - counter >= 128 || p.bits & (1u128 << (top - counter)) != 0)
        {
            return Err(CallError::Replay);
        }
        let packet = seal::open_compact(&p.recv, &dg[16..24], &dg[..24], &dg[24..])?;
        match p.top {
            None => {
                p.top = Some(counter);
                p.bits = 1;
            }
            Some(top) if counter > top => {
                let sh = counter - top;
                p.bits = if sh >= 128 { 1 } else { p.bits << sh | 1 };
                p.top = Some(counter);
            }
            Some(top) => p.bits |= 1u128 << (top - counter),
        }
        let rv: [u8; 16] = dg[..16].try_into().map_err(|_| CallError::Malformed)?;
        self.deliver(&rv, None, &packet, now)
    }

    fn deliver(
        &mut self,
        rv: &[u8; 16],
        not: Option<[u8; 16]>,
        packet: &[u8],
        now: u64,
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let mut out = Vec::new();
        // The local leg(s) of this rendezvous other than the sender.
        let targets: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter(|(sid, s)| s.rendezvous.as_ref() == Some(rv) && Some(**sid) != not)
            .map(|(sid, _)| *sid)
            .collect();
        let _ = now;
        for sid in targets {
            let s = self.sessions.get(&sid).ok_or(CallError::UnknownKey)?;
            let Some(addr) = s.client else { continue };
            for dg in self.links.send(&sid, &[&[P_MEDIA][..], packet].concat())? {
                out.push((addr, dg));
            }
            self.stats.to_client += 1;
        }
        if out.is_empty() {
            return Err(CallError::UnknownKey);
        }
        Ok(out)
    }
}

/// A relay's static WireGuard secret, from its link key, so it is as
/// long-lived and needs no file of its own.
pub fn wg_secret(link: &X448Secret) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(&link.to_bytes()[..], b"", labels::RELAY_WG)
}

/// Encode a join payload: rendezvous id and the peer relay's address.
pub fn join_payload(rendezvous: &[u8; 16], peer: SocketAddr) -> Vec<u8> {
    let mut v = vec![P_JOIN];
    v.extend_from_slice(rendezvous);
    let s = peer.to_string();
    v.push(s.len() as u8);
    v.extend_from_slice(s.as_bytes());
    v
}

fn decode_join(b: &[u8]) -> Result<([u8; 16], SocketAddr), CallError> {
    let rv: [u8; 16] = b
        .get(..16)
        .ok_or(CallError::Malformed)?
        .try_into()
        .map_err(|_| CallError::Malformed)?;
    let n = usize::from(*b.get(16).ok_or(CallError::Malformed)?);
    let s = std::str::from_utf8(b.get(17..17 + n).ok_or(CallError::Malformed)?)
        .map_err(|_| CallError::Malformed)?;
    Ok((rv, s.parse().map_err(|_| CallError::Malformed)?))
}

/// Client helper: the request for part `part` of a relay's descriptor.
pub fn descriptor_request(part: u8) -> Vec<u8> {
    let mut v = vec![0u8; DESC_REQUEST];
    v[0] = T_DESC;
    v[1] = part;
    v
}

/// Client helper: a descriptor reply's part number, part count and bytes.
pub fn descriptor_part(dg: &[u8]) -> Option<(usize, usize, &[u8])> {
    match dg {
        [T_DESC, part, count, rest @ ..]
            if part < count && usize::from(*count) <= MAX_DESC_PARTS && rest.len() <= DESC_PART =>
        {
            Some((usize::from(*part), usize::from(*count), rest))
        }
        _ => None,
    }
}

/// Client helper: a ticket request as the datagrams that carry it.
pub fn ticket_datagrams(id: [u8; 8], request: &[u8]) -> Vec<Vec<u8>> {
    let parts: Vec<&[u8]> = request.chunks(TICKET_PART).collect();
    let count = parts.len() as u8;
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| [&[T_TICKET][..], &id, &[i as u8, count], p].concat())
        .collect()
}

/// Client helper: a ticket reply datagram's request id and reply.
pub fn ticket_reply(dg: &[u8]) -> Option<([u8; 8], &[u8])> {
    match dg {
        [T_TICKET, rest @ ..] if rest.len() > 8 => Some((rest[..8].try_into().ok()?, &rest[8..])),
        _ => None,
    }
}

/// Run a relay on a UDP socket until the socket fails.
pub async fn serve(relay: Arc<Mutex<Relay>>, socket: tokio::net::UdpSocket) -> std::io::Result<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let out = relay.lock().await.handle(from, &buf[..n], now);
        for (to, dg) in out {
            socket.send_to(&dg, to).await?;
        }
    }
}
