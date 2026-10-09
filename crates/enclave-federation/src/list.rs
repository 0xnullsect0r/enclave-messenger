//! The foundation's server list (`docs/12-servers.md` §4.1).
//!
//! The list holds what changes rarely and what the foundation vouches for:
//! which servers, witnesses, relays and push relays exist, their identity
//! keys, operators and families, and the key-transparency keys clients pin.
//! Short-lived material (request keys, ticket keys) comes from the
//! services themselves, signed by the identity keys listed here.
//!
//! ```text
//! list    = u8(2) ‖ u64(seq) ‖ u64(issued) ‖ u64(expires) ‖ u8(witness threshold)
//!         ‖ u32(n) ‖ n × server   ‖ u32(n) ‖ n × witness
//!         ‖ u32(n) ‖ n × relay    ‖ u32(n) ‖ n × push relay
//!         ‖ u32(n) ‖ n × credential gate
//!         ‖ SLH-DSA-SHAKE-256s signature (29,792) ‖ composite signature (4,741)
//! server  = identity pk (2,649) ‖ bytes(domain) ‖ bytes(operator) ‖ bytes(family)
//!         ‖ bytes(Nym address) ‖ u32(weight) ‖ u8(has kt) [‖ head key (2,649) ‖ bytes(VRF public key)]
//! witness = key (2,649) ‖ bytes(operator) ‖ bytes(family) ‖ bytes(url)
//! relay   = identity pk (2,649) ‖ bytes(operator) ‖ bytes(family) ‖ bytes(addr) ‖ link key (56)
//! push    = bytes(Nym address) ‖ u8(n) ‖ n × (u32 epoch ‖ X448 (56) ‖ ML-KEM-1024 (1,568))
//! gate    = bytes(url) ‖ bytes(issuer name) ‖ u8(n) ‖ n × (u32 epoch ‖ P-384 key (49))
//! ```
//!
//! A credential gate (`enclave-credgate`, `docs/09-transport.md` §7) is
//! listed with its Privacy Pass issuer keys for the epochs the list covers:
//! a device blinds its token requests to the listed key, so the gate can't
//! hand one device a key of its own to tell its tokens apart later.
//!
//! ```text
//! ```
//!
//! Both signatures are under context `enclave/v1/update/server-list` and
//! both must verify: a break of either the hash-based or the
//! lattice-and-curve scheme alone can't forge a list. Clients only accept a
//! list whose `seq` is higher than the one they hold.

use crate::codec::{Reader, Writer};
use crate::descriptor::KtKeys;
use crate::{FedError, MAX_ADDRESS, MAX_DOMAIN, MAX_NAME, Result, read_composite, read_sig, utf8};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{
    COMPOSITE_PK_LEN, COMPOSITE_SEED_LEN, CompositePublic, CompositeSigningKey, ROOT_PK_LEN,
    ROOT_SIG_LEN, RootPublic, RootSigningKey,
};
use zeroize::Zeroizing;

/// Signature context of the list.
pub const CTX_SERVER_LIST: &str = "enclave/v1/update/server-list";
/// KMAC label deriving the foundation's SLH-DSA key from its seed.
pub const FOUNDATION_KEYGEN: &str = "enclave/v1/update/foundation-keygen";
const VERSION: u8 = 2;
/// Most entries of each kind.
pub const MAX_ENTRIES: usize = 1024;
const MAX_VRF: usize = 64;
const PUSH_KEY_LEN: usize = 4 + 56 + 1568;
/// Bytes of a Privacy Pass issuer key (compressed P-384).
pub const ISSUER_KEY_LEN: usize = 49;
/// Most issuer keys a gate lists (epochs are 30 days, lists last 90 at most).
pub const MAX_GATE_KEYS: usize = 8;

/// A listed server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedServer {
    /// Identity public key.
    pub identity: CompositePublic,
    /// Domain.
    pub domain: String,
    /// Operator.
    pub operator: String,
    /// Operator family.
    pub family: String,
    /// Nym address of the server's ingress (stable: a persistent identity
    /// on a fixed gateway; a server that moves publishes the new one in
    /// its descriptor).
    pub nym_address: String,
    /// Relative weight for new accounts (0: listed but not offered).
    pub weight: u32,
    /// Its key-transparency log.
    pub kt: Option<KtKeys>,
}

impl ListedServer {
    /// The server id.
    pub fn id(&self) -> [u8; 16] {
        crate::server_id(&self.identity)
    }
}

/// A listed witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedWitness {
    /// Cosigning key.
    pub key: CompositePublic,
    /// Operator.
    pub operator: String,
    /// Operator family.
    pub family: String,
    /// Cosigning API base URL.
    pub url: String,
}

impl ListedWitness {
    /// The witness id.
    pub fn id(&self) -> [u8; 16] {
        crate::witness_id(&self.key)
    }
}

/// A listed call relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedRelay {
    /// Identity public key.
    pub identity: CompositePublic,
    /// Operator.
    pub operator: String,
    /// Operator family.
    pub family: String,
    /// UDP address.
    pub addr: String,
    /// Relay↔relay link key.
    pub link_key: [u8; 56],
}

/// A push relay: where it is and its keys (current and next epoch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushRelayEntry {
    /// Nym address.
    pub nym_address: String,
    /// `u32 epoch ‖ X448 ‖ ML-KEM-1024` each.
    pub keys: Vec<Vec<u8>>,
}

/// A credential gate: where devices reach it and its issuer key per epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredGateEntry {
    /// Where it answers: `https://HOST`, under `/credgate/v1/`.
    pub url: String,
    /// The issuer name its token challenges carry.
    pub issuer_name: String,
    /// `(epoch, issuer key)`, epochs increasing.
    pub keys: Vec<(u32, [u8; ISSUER_KEY_LEN])>,
}

impl CredGateEntry {
    /// The issuer key of `epoch`.
    pub fn key(&self, epoch: u32) -> Option<&[u8; ISSUER_KEY_LEN]> {
        self.keys.iter().find(|(e, _)| *e == epoch).map(|(_, k)| k)
    }

    fn check(&self) -> Result<()> {
        if !self.url.starts_with("https://")
            || self.url.len() > MAX_ADDRESS
            || self.issuer_name.is_empty()
            || self.issuer_name.len() > MAX_DOMAIN
            || self.keys.is_empty()
            || self.keys.len() > MAX_GATE_KEYS
            || self.keys.windows(2).any(|w| w[0].0 >= w[1].0)
        {
            return Err(FedError::Malformed);
        }
        Ok(())
    }
}

/// The foundation's list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerList {
    /// Sequence number; only ever increases.
    pub seq: u64,
    /// When signed.
    pub issued: u64,
    /// Valid until.
    pub expires: u64,
    /// Cosignatures a client requires on a key-transparency head.
    pub witness_threshold: u8,
    /// Servers.
    pub servers: Vec<ListedServer>,
    /// Witnesses.
    pub witnesses: Vec<ListedWitness>,
    /// Call relays.
    pub relays: Vec<ListedRelay>,
    /// Push relays.
    pub push: Vec<PushRelayEntry>,
    /// Credential gates.
    pub credgates: Vec<CredGateEntry>,
}

/// The foundation's list-signing key: SLH-DSA-SHAKE-256s and composite
/// Ed448 + ML-DSA-87, both from one secret file.
pub struct FoundationKey {
    slh: RootSigningKey,
    composite: CompositeSigningKey,
    secret: Zeroizing<Vec<u8>>,
}

/// The foundation's public key, embedded in every client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundationPublic {
    /// SLH-DSA half.
    pub slh: RootPublic,
    /// Composite half.
    pub composite: CompositePublic,
}

/// Bytes of a foundation secret: SLH-DSA seed (32) ‖ composite seed (89).
pub const FOUNDATION_SECRET_LEN: usize = 32 + COMPOSITE_SEED_LEN;
/// Bytes of a foundation public key.
pub const FOUNDATION_PUBLIC_LEN: usize = ROOT_PK_LEN + COMPOSITE_PK_LEN;

impl FoundationKey {
    /// A fresh key.
    pub fn generate(rng: &mut HedgedRng) -> Result<Self> {
        let s: [u8; 32] = rng
            .array("update/foundation-key")
            .map_err(|_| FedError::Crypto)?;
        let c: [u8; COMPOSITE_SEED_LEN] = *CompositeSigningKey::generate(rng)
            .map_err(|_| FedError::Crypto)?
            .seed();
        Self::from_bytes(&[&s[..], &c[..]].concat())
    }

    /// The key from its secret encoding.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != FOUNDATION_SECRET_LEN {
            return Err(FedError::Malformed);
        }
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(&b[..32]);
        let mut c = Zeroizing::new([0u8; COMPOSITE_SEED_LEN]);
        c.copy_from_slice(&b[32..]);
        Ok(Self {
            slh: RootSigningKey::derive(&s, FOUNDATION_KEYGEN),
            composite: CompositeSigningKey::from_seed(&c).map_err(|_| FedError::Malformed)?,
            secret: Zeroizing::new(b.to_vec()),
        })
    }

    /// The secret encoding (keep it offline).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        self.secret.clone()
    }

    /// The public key.
    pub fn public(&self) -> FoundationPublic {
        FoundationPublic {
            slh: self.slh.public(),
            composite: self.composite.public().clone(),
        }
    }
}

impl FoundationPublic {
    /// `SLH-DSA pk (64) ‖ composite pk (2,649)`.
    pub fn encode(&self) -> Vec<u8> {
        [&self.slh.0[..], &self.composite.to_bytes()].concat()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != FOUNDATION_PUBLIC_LEN {
            return Err(FedError::Malformed);
        }
        let mut slh = [0u8; ROOT_PK_LEN];
        slh.copy_from_slice(&b[..ROOT_PK_LEN]);
        Ok(Self {
            slh: RootPublic(slh),
            composite: CompositePublic::from_slice(&b[ROOT_PK_LEN..])
                .map_err(|_| FedError::Malformed)?,
        })
    }
}

fn check_len(n: usize) -> Result<()> {
    if n > MAX_ENTRIES {
        return Err(FedError::Malformed);
    }
    Ok(())
}

impl ServerList {
    fn body(&self) -> Result<Vec<u8>> {
        for n in [
            self.servers.len(),
            self.witnesses.len(),
            self.relays.len(),
            self.push.len(),
            self.credgates.len(),
        ] {
            check_len(n)?;
        }
        let mut w = Writer::new();
        w.u8(VERSION)
            .u64(self.seq)
            .u64(self.issued)
            .u64(self.expires)
            .u8(self.witness_threshold);
        w.u32(self.servers.len() as u32);
        for s in &self.servers {
            if s.domain.is_empty()
                || s.domain.len() > MAX_DOMAIN
                || s.operator.len() > MAX_NAME
                || s.family.len() > MAX_NAME
                || s.nym_address.len() > MAX_ADDRESS
            {
                return Err(FedError::Malformed);
            }
            w.fixed(&s.identity.to_bytes())
                .bytes(s.domain.as_bytes())
                .bytes(s.operator.as_bytes())
                .bytes(s.family.as_bytes())
                .bytes(s.nym_address.as_bytes())
                .u32(s.weight);
            match &s.kt {
                Some(k) => {
                    if k.vrf_public.len() > MAX_VRF {
                        return Err(FedError::Malformed);
                    }
                    w.u8(1).fixed(&k.head_key.to_bytes()).bytes(&k.vrf_public);
                }
                None => {
                    w.u8(0);
                }
            }
        }
        w.u32(self.witnesses.len() as u32);
        for x in &self.witnesses {
            if x.operator.is_empty() || x.operator.len() > MAX_NAME || x.url.len() > MAX_ADDRESS {
                return Err(FedError::Malformed);
            }
            w.fixed(&x.key.to_bytes())
                .bytes(x.operator.as_bytes())
                .bytes(x.family.as_bytes())
                .bytes(x.url.as_bytes());
        }
        w.u32(self.relays.len() as u32);
        for r in &self.relays {
            if r.family.is_empty() || r.addr.len() > MAX_ADDRESS {
                return Err(FedError::Malformed);
            }
            w.fixed(&r.identity.to_bytes())
                .bytes(r.operator.as_bytes())
                .bytes(r.family.as_bytes())
                .bytes(r.addr.as_bytes())
                .fixed(&r.link_key);
        }
        w.u32(self.push.len() as u32);
        for p in &self.push {
            if p.nym_address.len() > MAX_ADDRESS
                || p.keys.is_empty()
                || p.keys.len() > 4
                || p.keys.iter().any(|k| k.len() != PUSH_KEY_LEN)
            {
                return Err(FedError::Malformed);
            }
            w.bytes(p.nym_address.as_bytes()).u8(p.keys.len() as u8);
            for k in &p.keys {
                w.fixed(k);
            }
        }
        w.u32(self.credgates.len() as u32);
        for g in &self.credgates {
            g.check()?;
            w.bytes(g.url.as_bytes())
                .bytes(g.issuer_name.as_bytes())
                .u8(g.keys.len() as u8);
            for (e, k) in &g.keys {
                w.u32(*e).fixed(k);
            }
        }
        Ok(w.finish())
    }

    /// The unsigned encoding (what the foundation key signs), so a list
    /// can be built on one machine and signed on another, offline one.
    pub fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.body()
    }

    /// Decode an unsigned list ([`Self::encode_unsigned`]).
    pub fn decode_unsigned(b: &[u8]) -> Result<Self> {
        let (list, body_len) = Self::read(b)?;
        if body_len != b.len() {
            return Err(FedError::Malformed);
        }
        Ok(list)
    }

    /// Sign the list.
    pub fn sign(&self, key: &FoundationKey, rng: &mut HedgedRng) -> Result<Vec<u8>> {
        if self.expires <= self.issued {
            return Err(FedError::Malformed);
        }
        let body = self.body()?;
        let ctx = CTX_SERVER_LIST.as_bytes();
        let a = key
            .slh
            .sign(ctx, &body, rng)
            .map_err(|_| FedError::Crypto)?;
        let b = key
            .composite
            .sign(ctx, &body, rng)
            .map_err(|_| FedError::Crypto)?;
        Ok([body, a, b].concat())
    }

    fn read(b: &[u8]) -> Result<(Self, usize)> {
        let mut r = Reader::new(b);
        if r.u8()? != VERSION {
            return Err(FedError::Malformed);
        }
        let seq = r.u64()?;
        let issued = r.u64()?;
        let expires = r.u64()?;
        let witness_threshold = r.u8()?;
        let n = r.u32()? as usize;
        check_len(n)?;
        let mut servers = Vec::with_capacity(n);
        for _ in 0..n {
            servers.push(ListedServer {
                identity: read_composite(&mut r)?,
                domain: utf8(r.bytes(MAX_DOMAIN)?)?,
                operator: utf8(r.bytes(MAX_NAME)?)?,
                family: utf8(r.bytes(MAX_NAME)?)?,
                nym_address: utf8(r.bytes(MAX_ADDRESS)?)?,
                weight: r.u32()?,
                kt: match r.u8()? {
                    0 => None,
                    1 => Some(KtKeys {
                        head_key: read_composite(&mut r)?,
                        vrf_public: r.bytes(MAX_VRF)?.to_vec(),
                    }),
                    _ => return Err(FedError::Malformed),
                },
            });
        }
        let n = r.u32()? as usize;
        check_len(n)?;
        let mut witnesses = Vec::with_capacity(n);
        for _ in 0..n {
            witnesses.push(ListedWitness {
                key: read_composite(&mut r)?,
                operator: utf8(r.bytes(MAX_NAME)?)?,
                family: utf8(r.bytes(MAX_NAME)?)?,
                url: utf8(r.bytes(MAX_ADDRESS)?)?,
            });
        }
        let n = r.u32()? as usize;
        check_len(n)?;
        let mut relays = Vec::with_capacity(n);
        for _ in 0..n {
            relays.push(ListedRelay {
                identity: read_composite(&mut r)?,
                operator: utf8(r.bytes(MAX_NAME)?)?,
                family: utf8(r.bytes(MAX_NAME)?)?,
                addr: utf8(r.bytes(MAX_ADDRESS)?)?,
                link_key: r.array::<56>()?,
            });
        }
        let n = r.u32()? as usize;
        check_len(n)?;
        let mut push = Vec::with_capacity(n);
        for _ in 0..n {
            let nym_address = utf8(r.bytes(MAX_ADDRESS)?)?;
            let k = usize::from(r.u8()?);
            if k == 0 || k > 4 {
                return Err(FedError::Malformed);
            }
            let keys = (0..k)
                .map(|_| Ok(r.fixed(PUSH_KEY_LEN)?.to_vec()))
                .collect::<Result<Vec<_>>>()?;
            push.push(PushRelayEntry { nym_address, keys });
        }
        let n = r.u32()? as usize;
        check_len(n)?;
        let mut credgates = Vec::with_capacity(n);
        for _ in 0..n {
            let url = utf8(r.bytes(MAX_ADDRESS)?)?;
            let issuer_name = utf8(r.bytes(MAX_DOMAIN)?)?;
            let k = usize::from(r.u8()?);
            if k > MAX_GATE_KEYS {
                return Err(FedError::Malformed);
            }
            let keys = (0..k)
                .map(|_| Ok((r.u32()?, r.array::<ISSUER_KEY_LEN>()?)))
                .collect::<Result<Vec<_>>>()?;
            let g = CredGateEntry {
                url,
                issuer_name,
                keys,
            };
            g.check()?;
            credgates.push(g);
        }
        let body_len = b.len() - r.remaining();
        Ok((
            Self {
                seq,
                issued,
                expires,
                witness_threshold,
                servers,
                witnesses,
                relays,
                push,
                credgates,
            },
            body_len,
        ))
    }

    /// Decode a signed list and check it: both signatures under `key`, not
    /// expired at `now`, and newer than `held_seq` (the sequence number of
    /// the list the client already has, or 0).
    pub fn verify(b: &[u8], key: &FoundationPublic, now: u64, held_seq: u64) -> Result<Self> {
        let (list, body_len) = Self::read(b)?;
        let mut r = Reader::new(&b[body_len..]);
        let slh = r.fixed(ROOT_SIG_LEN)?;
        let comp = read_sig(&mut r)?;
        r.end()?;
        let body = &b[..body_len];
        let ctx = CTX_SERVER_LIST.as_bytes();
        key.slh
            .verify(ctx, body, slh)
            .map_err(|_| FedError::Signature)?;
        key.composite
            .verify(ctx, body, comp)
            .map_err(|_| FedError::Signature)?;
        if now >= list.expires {
            return Err(FedError::Expired);
        }
        if list.seq <= held_seq {
            return Err(FedError::Stale);
        }
        Ok(list)
    }

    /// Decode a signed list without checking its signatures: for a server
    /// that serves its operator's copy and holds no foundation key (clients
    /// check it with [`ServerList::verify`]).
    pub fn decode_unchecked(b: &[u8]) -> Result<Self> {
        Ok(Self::read(b)?.0)
    }

    /// The server with `id`.
    pub fn server(&self, id: &[u8; 16]) -> Option<&ListedServer> {
        self.servers.iter().find(|s| s.id() == *id)
    }

    /// The server serving `domain` (case-insensitive).
    pub fn by_domain(&self, domain: &str) -> Option<&ListedServer> {
        self.servers
            .iter()
            .find(|s| s.domain.eq_ignore_ascii_case(domain))
    }

    /// Pick a server for a new account, weighted by `weight`, from a
    /// uniform `draw` in `0..u64::MAX`.
    pub fn pick(&self, draw: u64) -> Option<&ListedServer> {
        let total: u64 = self.servers.iter().map(|s| u64::from(s.weight)).sum();
        if total == 0 {
            return None;
        }
        let mut x = draw % total;
        for s in &self.servers {
            let w = u64::from(s.weight);
            if x < w {
                return Some(s);
            }
            x -= w;
        }
        None
    }
}
