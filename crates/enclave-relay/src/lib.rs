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
//! (ADR 0006). The relay-to-relay hop is sealed with keys from the two
//! relays' static X448 keys and, every 120 s, a post-quantum exchange
//! (ADR 0007): the relay with the lower id sends an ephemeral ML-KEM-1024
//! key and a ciphertext to the other's static ML-KEM key; the answer is a
//! ciphertext to the ephemeral key and one to the initiator's static key.
//! Each epoch's keys come from all four secrets, and a side sends under
//! them only once it has received something sealed under them, which only
//! the holder of the other static key can produce.
//!
//! The relay core is sans-I/O ([`Relay::handle`] maps one datagram to the
//! datagrams to send); [`serve`] runs it on a UDP socket.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use enclave_calls::ticket::TicketSecretKey;
use enclave_calls::wg::RelayLinks;
use enclave_calls::{CallError, labels};
use enclave_crypto::kem::{MlKemCiphertext, MlKemPublic, MlKemSecret, X448Public, X448Secret};
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

pub use enclave_calls::relay::*;

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
    /// Static ML-KEM-1024 key for relay links (from the signed
    /// descriptor; without it the link stays classical).
    pub kem: Option<Vec<u8>>,
}

struct Session {
    client: Option<SocketAddr>,
    rendezvous: Option<[u8; 16]>,
    peer: Option<SocketAddr>,
    /// In a group call: the downlink goes in fixed-rate bundles from
    /// these queues (voices before pictures).
    group: bool,
    audio: std::collections::VecDeque<Vec<u8>>,
    video: std::collections::VecDeque<Vec<u8>>,
}

/// Most packets a group session's queue holds (the oldest go first).
const GROUP_QUEUE: usize = 128;
/// Packets up to this long are voices (audio is 160 bytes, video 1,200).
const AUDIO_MAX: usize = 400;

/// One epoch's keys of a relay link (epoch 0: the static X448 exchange
/// alone, until the first post-quantum exchange).
struct LinkKeys {
    epoch: u32,
    send: SealKey,
    recv: SealKey,
    counter: u64,
    top: Option<u64>,
    bits: u128,
}

/// An exchange this relay started (the initiator) for an epoch.
struct Kx {
    epoch: u32,
    eph: MlKemSecret,
    ss1: zeroize::Zeroizing<[u8; 32]>,
    /// The first message, kept to send again until the answer comes.
    msg: Vec<u8>,
    sent: u64,
}

struct Peer {
    id: [u8; 16],
    dh: zeroize::Zeroizing<Vec<u8>>,
    kem: Option<MlKemPublic>,
    /// We start the exchanges (the lower id).
    initiator: bool,
    /// Keys by epoch: the one we send with, and newer ones not yet
    /// confirmed by the other side.
    keys: Vec<LinkKeys>,
    sending: u32,
    kx: Option<Kx>,
    /// The responder's answer per epoch, to send again if asked again.
    answered: Option<(u32, Vec<u8>)>,
    /// Exchange messages arriving in parts: (kind, epoch) → parts.
    parts: HashMap<(u8, u32), Vec<Option<Vec<u8>>>>,
}

/// Seconds per post-quantum relay-link epoch.
pub const LINK_EPOCH_SECS: u64 = 120;
/// Datagram type: a relay-link key exchange part (from a peer relay).
pub const T_KX: u8 = 0x03;
/// Bytes of an exchange message per datagram.
const KX_PART: usize = 1100;
/// Seconds between sending the first message again.
const KX_RETRY: u64 = 5;

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
    link_kem: MlKemSecret,
    /// Ticket keys, newest first (today's, and yesterday's for requests
    /// sealed just before midnight).
    tickets: Vec<TicketSecretKey>,
    sessions: HashMap<[u8; 16], Session>,
    rendezvous: HashMap<[u8; 16], [u8; 16]>,
    /// Peer relays that sent us media for a rendezvous: a group call's SFU
    /// sends each one's packets on to the others.
    remotes: HashMap<[u8; 16], std::collections::HashSet<SocketAddr>>,
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
        let (link_kem, kem_public) = kem_secret(&link_secret);
        Ok(Self {
            desc: Descriptor {
                id,
                family: family.into(),
                addr,
                link_key: link_secret.public().0,
                kem: Some(kem_public.0.to_vec()),
            },
            link_kem,
            links: RelayLinks::new(wg),
            effort: TICKET_EFFORT,
            partial: HashMap::new(),
            published: Vec::new(),
            link_secret,
            tickets,
            sessions: HashMap::new(),
            rendezvous: HashMap::new(),
            remotes: HashMap::new(),
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

    /// Trust a peer relay (from the server list, with its signed
    /// descriptor's ML-KEM key; or configured by hand, classical only).
    /// A peer already known keeps its link.
    pub fn add_peer(&mut self, peer: &Descriptor) -> Result<(), CallError> {
        let kem = match &peer.kem {
            Some(k) => Some(MlKemPublic::from_slice(k)?),
            None => None,
        };
        if let Some(p) = self.peers.get_mut(&peer.addr)
            && p.id == peer.id
        {
            if p.kem.is_none() {
                p.kem = kem;
            }
            return Ok(());
        }
        let dh = self
            .link_secret
            .diffie_hellman(&X448Public(peer.link_key))?;
        let classical = LinkKeys::new(0, &dh[..], &[], &self.desc.id, &peer.id);
        self.peers.insert(
            peer.addr,
            Peer {
                id: peer.id,
                dh: zeroize::Zeroizing::new(dh[..].to_vec()),
                kem,
                initiator: self.desc.id < peer.id,
                keys: vec![classical],
                sending: 0,
                kx: None,
                answered: None,
                parts: HashMap::new(),
            },
        );
        Ok(())
    }

    /// Keep only these peers (the server list changed); new ones are
    /// added.
    pub fn set_peers(&mut self, peers: &[Descriptor]) -> Result<(), CallError> {
        let keep: std::collections::HashSet<SocketAddr> = peers.iter().map(|p| p.addr).collect();
        self.peers.retain(|a, _| keep.contains(a));
        for p in peers {
            if p.addr != self.desc.addr {
                self.add_peer(p)?;
            }
        }
        Ok(())
    }

    /// The epoch a peer link sends under now (0: classical only).
    pub fn link_epoch(&self, peer: &SocketAddr) -> Option<u32> {
        self.peers.get(peer).map(|p| p.sending)
    }

    /// Once a second: start each epoch's exchange with the peers this
    /// relay leads (and send its first message again until answered), and
    /// confirm keys the other side may not have heard under yet.
    pub fn peer_upkeep(&mut self, now: u64) -> Vec<(SocketAddr, Vec<u8>)> {
        let epoch = (now / LINK_EPOCH_SECS) as u32 + 1;
        let mut out = Vec::new();
        let addrs: Vec<SocketAddr> = self.peers.keys().copied().collect();
        for addr in addrs {
            let Some(p) = self.peers.get_mut(&addr) else {
                continue;
            };
            if p.initiator && p.kem.is_some() {
                let due = match &p.kx {
                    Some(k) if k.epoch >= epoch => now >= k.sent + KX_RETRY && p.sending < k.epoch,
                    _ => p.sending < epoch,
                };
                if due {
                    if p.kx.as_ref().is_none_or(|k| k.epoch < epoch)
                        && let Some(kem) = p.kem.clone()
                        && let Ok((eph, eph_pk)) = MlKemSecret::generate(&mut self.rng)
                        && let Ok((ct1, ss1)) = kem.encapsulate(&mut self.rng)
                    {
                        let msg = [&eph_pk.0[..], &ct1.0[..]].concat();
                        p.kx = Some(Kx {
                            epoch,
                            eph,
                            ss1,
                            msg,
                            sent: 0,
                        });
                    }
                    if let Some(k) = p.kx.as_mut() {
                        k.sent = now;
                        out.extend(kx_parts(1, k.epoch, &k.msg).into_iter().map(|d| (addr, d)));
                    }
                }
            }
            // Keys newer than the ones we send with: a sealed, empty
            // confirmation, so the other side can switch.
            let pending: Vec<u32> = p
                .keys
                .iter()
                .map(|k| k.epoch)
                .filter(|e| *e > p.sending)
                .collect();
            for e in pending {
                if let Ok(d) = p.seal(e, &[0; 16], &[]) {
                    out.push((addr, d));
                }
            }
        }
        out
    }

    fn on_kx(
        &mut self,
        from: SocketAddr,
        dg: &[u8],
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let [T_KX, kind, e0, e1, e2, e3, idx, count, data @ ..] = dg else {
            return Err(CallError::Malformed);
        };
        let epoch = u32::from_be_bytes([*e0, *e1, *e2, *e3]);
        let (kind, idx, count) = (*kind, usize::from(*idx), usize::from(*count));
        if !(1..=2).contains(&kind) || idx >= count || count > 4 || data.len() > KX_PART {
            return Err(CallError::Malformed);
        }
        let p = self.peers.get_mut(&from).ok_or(CallError::UnknownKey)?;
        // Only exchanges for an epoch newer than the one sent under.
        if epoch <= p.sending {
            return Ok(Vec::new());
        }
        let slot = p
            .parts
            .entry((kind, epoch))
            .or_insert_with(|| vec![None; count]);
        if slot.len() != count {
            return Err(CallError::Malformed);
        }
        slot[idx] = Some(data.to_vec());
        if slot.iter().any(Option::is_none) {
            return Ok(Vec::new());
        }
        let msg: Vec<u8> = p
            .parts
            .remove(&(kind, epoch))
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        p.parts.retain(|(_, e), _| *e > epoch.saturating_sub(2));
        let (pk_len, ct_len) = (
            enclave_crypto::kem::MLKEM_PK_LEN,
            enclave_crypto::kem::MLKEM_CT_LEN,
        );
        match (kind, p.initiator) {
            // The responder: answer, and derive the epoch's keys.
            (1, false) => {
                if let Some((e, answer)) = &p.answered
                    && *e == epoch
                {
                    return Ok(kx_parts(2, epoch, answer)
                        .into_iter()
                        .map(|d| (from, d))
                        .collect());
                }
                if msg.len() != pk_len + ct_len {
                    return Err(CallError::Malformed);
                }
                let kem = p.kem.clone().ok_or(CallError::UnknownKey)?;
                let eph_pk = MlKemPublic::from_slice(&msg[..pk_len])?;
                let ct1 = MlKemCiphertext::from_slice(&msg[pk_len..])?;
                let ss1 = self.link_kem.decapsulate(&ct1);
                let (ct2, ss2) = eph_pk.encapsulate(&mut self.rng)?;
                let (ct3, ss3) = kem.encapsulate(&mut self.rng)?;
                let keys = LinkKeys::new(
                    epoch,
                    &p.dh,
                    &[&ss1[..], &ss2[..], &ss3[..]],
                    &self.desc.id,
                    &p.id,
                );
                p.keys.retain(|k| k.epoch != epoch);
                p.keys.push(keys);
                let answer = [&ct2.0[..], &ct3.0[..]].concat();
                p.answered = Some((epoch, answer.clone()));
                Ok(kx_parts(2, epoch, &answer)
                    .into_iter()
                    .map(|d| (from, d))
                    .collect())
            }
            // The initiator: finish the exchange it started.
            (2, true) => {
                let Some(kx) = p.kx.as_ref().filter(|k| k.epoch == epoch) else {
                    return Ok(Vec::new());
                };
                if msg.len() != 2 * ct_len || p.keys.iter().any(|k| k.epoch == epoch) {
                    return Ok(Vec::new());
                }
                let ss2 = kx
                    .eph
                    .decapsulate(&MlKemCiphertext::from_slice(&msg[..ct_len])?);
                let ss3 = self
                    .link_kem
                    .decapsulate(&MlKemCiphertext::from_slice(&msg[ct_len..])?);
                let keys = LinkKeys::new(
                    epoch,
                    &p.dh,
                    &[&kx.ss1[..], &ss2[..], &ss3[..]],
                    &self.desc.id,
                    &p.id,
                );
                p.keys.push(keys);
                // Confirm at once: the other side switches on it.
                Ok(p.seal(epoch, &[0; 16], &[])
                    .map(|d| vec![(from, d)])
                    .unwrap_or_default())
            }
            _ => Err(CallError::Malformed),
        }
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
                group: false,
                audio: Default::default(),
                video: Default::default(),
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
                Some(&T_KX) => self.on_kx(from, dg),
                _ => Err(CallError::Malformed),
            }
        } else if dg.first() == Some(&T_TICKET) {
            self.on_ticket(from, dg, now)
        } else if dg.first() == Some(&T_DESC) {
            self.on_descriptor(from, dg)
        } else if dg.first() == Some(&enclave_calls::relay::T_REFLECT) {
            enclave_calls::relay::reflect_reply(dg, from)
                .map(|r| vec![(from, r)])
                .ok_or(CallError::Malformed)
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
            Some(&kind @ (P_JOIN | P_JOIN_GROUP)) => {
                let (rv, peer) = decode_join(&pt[1..])?;
                if !self.peers.contains_key(&peer) && peer != self.desc.addr {
                    return Err(CallError::UnknownKey);
                }
                s.rendezvous = Some(rv);
                s.peer = Some(peer);
                s.group = kind == P_JOIN_GROUP;
                self.rendezvous.insert(rv, sid);
                Ok(Vec::new())
            }
            Some(&P_MEDIA) => {
                let (rv, peer, group) = (
                    s.rendezvous.ok_or(CallError::UnknownKey)?,
                    s.peer.ok_or(CallError::UnknownKey)?,
                    s.group,
                );
                if peer == self.desc.addr {
                    // Both legs on this relay (only when families allow it),
                    // or this relay is the group call's SFU: the others here,
                    // and every relay that sent us the call's media.
                    let mut out = self.deliver(&rv, Some(sid), &pt[1..], now);
                    out.extend(self.fan_out(&rv, None, &pt[1..])?);
                    return if out.is_empty() && !group {
                        Err(CallError::UnknownKey)
                    } else {
                        Ok(out)
                    };
                }
                let p = self.peers.get_mut(&peer).ok_or(CallError::UnknownKey)?;
                let d = p.seal(p.sending, &rv, &pt[1..])?;
                self.stats.to_peer += 1;
                let mut out = vec![(peer, d)];
                // In a group call, others in it on this relay too.
                if group {
                    out.extend(self.deliver(&rv, Some(sid), &pt[1..], now));
                }
                Ok(out)
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
        let (rv, packet, switched) = p.open(dg)?;
        // Switched: confirm back, so the other side switches too.
        let mut out = Vec::new();
        if switched && let Ok(d) = p.seal(p.sending, &[0; 16], &[]) {
            out.push((from, d));
        }
        // A confirmation (no rendezvous, nothing in it).
        if rv == [0; 16] && packet.is_empty() {
            return Ok(out);
        }
        self.remotes.entry(rv).or_default().insert(from);
        let local = self.deliver(&rv, None, &packet, now);
        let fanned = self.fan_out(&rv, Some(from), &packet)?;
        if local.is_empty() && fanned.is_empty() {
            return Err(CallError::UnknownKey);
        }
        out.extend(local);
        out.extend(fanned);
        Ok(out)
    }

    /// A group call's SFU: the packet to every other relay that sent media
    /// for this rendezvous (none in a call between two people).
    fn fan_out(
        &mut self,
        rv: &[u8; 16],
        not: Option<SocketAddr>,
        packet: &[u8],
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let targets: Vec<SocketAddr> = self
            .remotes
            .get(rv)
            .map(|r| r.iter().copied().filter(|a| Some(*a) != not).collect())
            .unwrap_or_default();
        let mut out = Vec::new();
        for to in targets {
            if let Some(p) = self.peers.get_mut(&to) {
                out.push((to, p.seal(p.sending, rv, packet)?));
                self.stats.to_peer += 1;
            }
        }
        Ok(out)
    }

    /// Every [`BUNDLE_INTERVAL_US`]: one bundle to each group session (its
    /// queued packets, or padding), so its downlink is the same whatever
    /// the call carries.
    pub fn group_tick(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        let sids: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.group && s.client.is_some() && s.rendezvous.is_some())
            .map(|(sid, _)| *sid)
            .collect();
        for sid in sids {
            let Some(s) = self.sessions.get_mut(&sid) else {
                continue;
            };
            let Some(addr) = s.client else { continue };
            let b = bundle(&mut [&mut s.audio, &mut s.video]);
            if let Ok(dgs) = self.links.send(&sid, &b) {
                out.extend(dgs.into_iter().map(|d| (addr, d)));
            }
        }
        out
    }

    /// Whether any session is in a group call (the bundle timer runs).
    pub fn has_group_sessions(&self) -> bool {
        self.sessions.values().any(|s| s.group)
    }

    /// The local legs of this rendezvous other than the sender: sent at
    /// once, or (group calls) queued for the next bundle.
    fn deliver(
        &mut self,
        rv: &[u8; 16],
        not: Option<[u8; 16]>,
        packet: &[u8],
        now: u64,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        let targets: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter(|(sid, s)| s.rendezvous.as_ref() == Some(rv) && Some(**sid) != not)
            .map(|(sid, _)| *sid)
            .collect();
        let _ = now;
        for sid in targets {
            let Some(s) = self.sessions.get_mut(&sid) else {
                continue;
            };
            if s.group {
                let q = if packet.len() <= AUDIO_MAX {
                    &mut s.audio
                } else {
                    &mut s.video
                };
                if q.len() >= GROUP_QUEUE {
                    q.pop_front();
                }
                q.push_back(packet.to_vec());
                self.stats.to_client += 1;
                continue;
            }
            let Some(addr) = s.client else { continue };
            if let Ok(dgs) = self.links.send(&sid, &[&[P_MEDIA][..], packet].concat()) {
                out.extend(dgs.into_iter().map(|d| (addr, d)));
                self.stats.to_client += 1;
            }
        }
        out
    }
}

/// A relay's static WireGuard secret, from its link key, so it is as
/// long-lived and needs no file of its own.
pub fn wg_secret(link: &X448Secret) -> [u8; 32] {
    enclave_crypto::kmac::kmac256(&link.to_bytes()[..], b"", labels::RELAY_WG)
}

impl LinkKeys {
    /// Epoch keys from the static X448 secret and the epoch's ML-KEM
    /// secrets (none for epoch 0), per direction.
    fn new(epoch: u32, dh: &[u8], kems: &[&[u8]], us: &[u8; 16], them: &[u8; 16]) -> Self {
        let dir = |from: &[u8; 16], to: &[u8; 16]| {
            if epoch == 0 {
                SealKey::from_bytes(kmac256_parts(dh, &[from, to], labels::RELAY_LINK))
            } else {
                let mut material = dh.to_vec();
                for k in kems {
                    material.extend_from_slice(k);
                }
                let key = kmac256_parts(
                    &material,
                    &[from, to, &epoch.to_be_bytes()],
                    labels::RELAY_PQ,
                );
                zeroize::Zeroize::zeroize(&mut material);
                SealKey::from_bytes(key)
            }
        };
        Self {
            epoch,
            send: dir(us, them),
            recv: dir(them, us),
            counter: 0,
            top: None,
            bits: 0,
        }
    }

    /// Check a counter against the replay window and take it.
    fn accept(&mut self, counter: u64) -> Result<(), CallError> {
        if let Some(top) = self.top
            && counter <= top
            && (top - counter >= 128 || self.bits & (1u128 << (top - counter)) != 0)
        {
            return Err(CallError::Replay);
        }
        match self.top {
            None => {
                self.top = Some(counter);
                self.bits = 1;
            }
            Some(top) if counter > top => {
                let sh = counter - top;
                self.bits = if sh >= 128 { 1 } else { self.bits << sh | 1 };
                self.top = Some(counter);
            }
            Some(top) => self.bits |= 1u128 << (top - counter),
        }
        Ok(())
    }
}

impl Peer {
    /// `T_RELAY ‖ rendezvous ‖ epoch ‖ counter ‖ sealed packet` under the
    /// epoch's keys.
    fn seal(&mut self, epoch: u32, rv: &[u8; 16], packet: &[u8]) -> Result<Vec<u8>, CallError> {
        let k = self
            .keys
            .iter_mut()
            .find(|k| k.epoch == epoch)
            .ok_or(CallError::UnknownKey)?;
        let mut hdr = [0u8; 28];
        hdr[..16].copy_from_slice(rv);
        hdr[16..20].copy_from_slice(&epoch.to_be_bytes());
        hdr[20..].copy_from_slice(&k.counter.to_be_bytes());
        let ct = seal::seal_compact(&k.send, &hdr[16..], &hdr, packet)?;
        k.counter += 1;
        Ok([&[T_RELAY][..], &hdr, &ct].concat())
    }

    /// Open a datagram from the peer: its rendezvous and packet, and
    /// whether it switched sending to newer keys (a first datagram under
    /// them).
    fn open(&mut self, dg: &[u8]) -> Result<([u8; 16], Vec<u8>, bool), CallError> {
        if dg.len() < 28 + seal::TAG_LEN {
            return Err(CallError::Malformed);
        }
        let epoch = u32::from_be_bytes(dg[16..20].try_into().map_err(|_| CallError::Malformed)?);
        let counter = u64::from_be_bytes(dg[20..28].try_into().map_err(|_| CallError::Malformed)?);
        let k = self
            .keys
            .iter_mut()
            .find(|k| k.epoch == epoch)
            .ok_or(CallError::UnknownKey)?;
        let packet = seal::open_compact(&k.recv, &dg[16..28], &dg[..28], &dg[28..])?;
        k.accept(counter)?;
        let switched = epoch > self.sending;
        if switched {
            self.sending = epoch;
            // Keep the previous epoch's keys for what is still in flight.
            let floor = epoch.saturating_sub(1);
            self.keys.retain(|k| k.epoch >= floor);
            if self.kx.as_ref().is_some_and(|k| k.epoch <= epoch) {
                self.kx = None;
            }
        }
        let rv: [u8; 16] = dg[..16].try_into().map_err(|_| CallError::Malformed)?;
        Ok((rv, packet, switched))
    }
}

/// An exchange message as the datagrams that carry it.
fn kx_parts(kind: u8, epoch: u32, msg: &[u8]) -> Vec<Vec<u8>> {
    let parts: Vec<&[u8]> = msg.chunks(KX_PART).collect();
    let count = parts.len() as u8;
    let e = epoch.to_be_bytes();
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| [&[T_KX, kind][..], &e, &[i as u8, count], p].concat())
        .collect()
}

/// A relay's static ML-KEM-1024 key for relay links, from its link key (so
/// it needs no file of its own and stays as long as the link key).
pub fn kem_secret(link: &X448Secret) -> (MlKemSecret, MlKemPublic) {
    let a: [u8; 32] = enclave_crypto::kmac::kmac256(&link.to_bytes()[..], b"d", labels::RELAY_KEM);
    let b: [u8; 32] = enclave_crypto::kmac::kmac256(&link.to_bytes()[..], b"z", labels::RELAY_KEM);
    let mut seed = zeroize::Zeroizing::new([0u8; 64]);
    seed[..32].copy_from_slice(&a);
    seed[32..].copy_from_slice(&b);
    MlKemSecret::from_seed(&seed)
}

/// Run a relay on a UDP socket until the socket fails.
pub async fn serve(relay: Arc<Mutex<Relay>>, socket: tokio::net::UdpSocket) -> std::io::Result<()> {
    let mut buf = vec![0u8; 2048];
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut bundles = tokio::time::interval(std::time::Duration::from_micros(BUNDLE_INTERVAL_US));
    bundles.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let out = tokio::select! {
            got = socket.recv_from(&mut buf) => {
                let (n, from) = got?;
                relay.lock().await.handle(from, &buf[..n], now())
            }
            _ = tick.tick() => relay.lock().await.peer_upkeep(now()),
            _ = bundles.tick() => {
                let mut r = relay.lock().await;
                if r.has_group_sessions() { r.group_tick() } else { Vec::new() }
            }
        };
        for (to, dg) in out {
            socket.send_to(&dg, to).await?;
        }
    }
}
