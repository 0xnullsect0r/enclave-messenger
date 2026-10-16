//! The Enclave server (`docs/12-servers.md`).
//!
//! A server is an untrusted mailbox. It holds opaque fixed-size envelopes,
//! prekey publications, encrypted blobs and a key-transparency log. It keeps no
//! accounts, no phone numbers and no IP addresses (in production it is reached
//! only through the mixnet), and it cannot tell who writes to whom:
//!
//! * writes to an inbox need a single-use token whose hash the owner
//!   registered; the server burns it and learns nothing else;
//! * reading needs a credential only the owner has;
//! * first contact goes to a separate request inbox and costs a proof of work
//!   of work;
//! * every request and reply is sealed end to end to the server's daily
//!   X448 + ML-KEM-1024 key ([`enclave_rpc`]).
//!
//! [`Server::handle`] maps one sealed request to one sealed reply. It is
//! transport-agnostic: the dev binary serves it over TCP, `enclave-net`
//! serves it over Nym.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod admin;
pub mod config;
pub mod db;
pub mod keys;
mod pg;

use db::{Db, Tx};
use enclave_crypto::hash::sha3_512;
use enclave_crypto::rng::HedgedRng;
use enclave_kt::{KtError, KtInfo, KtService, UsernameClaim};
use enclave_proto::bundle::{Bundle, Publication};
use enclave_proto::manifest::{Manifest, SignedManifest};
use enclave_proto::otr;
use enclave_rpc::api::{
    self, DirAction, DirKind, DirReply, DirRequest, FLAG_CREATE, FLAG_EFFORT, FLAG_FOUND,
    FLAG_GROUP, FLAG_INVITE, FLAG_MORE, FLAG_REQUEST_INBOX, FLAG_REVOKE, Status,
};
use enclave_rpc::{ServerKey, ServerSecret};
use enclave_tokens::{PowProof, token_hash};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// Why a server could not start.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Key generation failed.
    #[error("crypto: {0}")]
    Crypto(#[from] enclave_crypto::Error),
    /// The database failed.
    #[error(transparent)]
    Db(#[from] db::DbError),
}

/// Width of a push window.
pub const PUSH_WINDOW_SECS: u64 = 60;
/// Latest offset of a wake into its window.
pub const PUSH_JITTER_SECS: u64 = 30;
/// Largest sealed push token accepted.
const MAX_PUSH_TOKEN: usize = 4096;
/// The holder recorded for a withdrawn username: no root, so no claim
/// ever matches it.
const WITHDRAWN: [u8; 64] = [0xff; 64];

/// A scheduled wake.
struct Wake {
    window: u64,
    release: u64,
    sealed: Vec<u8>,
    /// The newest written envelope's notification capsule (random when it
    /// had none), for previews on iOS (`10-push.md` §4).
    capsule: Vec<u8>,
    sent: bool,
}

/// Server policy.
#[derive(Clone, Debug)]
pub struct Config {
    /// Server identifier.
    pub id: [u8; 16],
    /// Proof-of-work effort for request-inbox writes.
    pub effort_request: u32,
    /// Proof-of-work effort for claiming a bundle.
    pub effort_claim: u32,
    /// Blob-upload Privacy Pass tokens one inbox may be issued a day
    /// (`BlobAlloc`).
    pub blob_tokens_per_day: u32,
    /// Proof-of-work effort for claiming a username.
    pub effort_username: u32,
    /// Proof-of-work effort for creating an inbox (0: none, development).
    pub effort_inbox: u32,
    /// Maximum stored envelopes per inbox.
    pub inbox_quota: usize,
    /// Maximum pending requests per request inbox.
    pub request_quota: usize,
    /// Maximum registered unspent tokens per inbox.
    pub token_quota: usize,
    /// Time-to-live for envelopes and blobs.
    pub ttl_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            id: [0; 16],
            effort_request: 64,
            effort_claim: 8,
            blob_tokens_per_day: 64,
            effort_username: 64,
            effort_inbox: 16,
            inbox_quota: 5_000,
            request_quota: 100,
            token_quota: 4_096,
            ttl_secs: 30 * 24 * 3600,
        }
    }
}

/// An inbox's metadata (`db::INBOXES`); its tokens and envelopes are in
/// their own tables, keyed by the mailbox.
#[derive(Clone, Copy)]
struct Inbox {
    owner: [u8; 32],
    /// The static read credential's hash, or zeros for an inbox read with
    /// daily credentials (`db::READ_CREDS`).
    read: [u8; 32],
    request: bool,
    group: bool,
    next_seq: u64,
    /// Proof-of-work effort its owner asks of request writers (0: the
    /// server's).
    effort: u32,
    /// The last day it has a read credential for (0: no end). A rotating
    /// inbox is deleted, with everything in it, once its envelopes would
    /// have expired after that day.
    until: u32,
}

impl Inbox {
    /// `owner ‖ read ‖ flags ‖ u64 next_seq ‖ u32 effort ‖ u32 until` (81
    /// B; records written before the effort existed are 73 B, before the
    /// end day 77 B, both with 0).
    fn encode(&self) -> [u8; 81] {
        let mut b = [0u8; 81];
        b[..32].copy_from_slice(&self.owner);
        b[32..64].copy_from_slice(&self.read);
        b[64] = u8::from(self.request) | u8::from(self.group) << 1;
        b[65..73].copy_from_slice(&self.next_seq.to_be_bytes());
        b[73..77].copy_from_slice(&self.effort.to_be_bytes());
        b[77..].copy_from_slice(&self.until.to_be_bytes());
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 73 && b.len() != 77 && b.len() != 81 {
            return None;
        }
        let u32_at = |r: std::ops::Range<usize>| {
            b.get(r)
                .and_then(|e| e.try_into().ok())
                .map_or(0, u32::from_be_bytes)
        };
        Some(Self {
            owner: b[..32].try_into().ok()?,
            read: b[32..64].try_into().ok()?,
            request: b[64] & 1 != 0,
            group: b[64] & 2 != 0,
            next_seq: u64::from_be_bytes(b[65..73].try_into().ok()?),
            effort: u32_at(73..77),
            until: u32_at(77..81),
        })
    }
}

/// Where an allocation (or a spent token) is kept: a hash of it, so the
/// database never holds a secret that uploads.
fn alloc_key(secret: &[u8]) -> [u8; 32] {
    let h = sha3_512(secret);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h[..32]);
    k
}

fn cat(a: &[u8], b: &[u8]) -> Vec<u8> {
    [a, b].concat()
}

fn be(t: u64) -> [u8; 8] {
    t.to_be_bytes()
}

/// `u64` at the start of a stored value.
fn head_u64(v: &[u8]) -> u64 {
    v.get(..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

/// The stored value without its leading `u64`.
fn tail(v: &[u8]) -> &[u8] {
    v.get(8..).unwrap_or_default()
}

fn get_inbox(tx: &Tx<'_>, mailbox: &[u8; 32]) -> db::Result<Option<Inbox>> {
    Ok(tx
        .get(db::INBOXES, mailbox)?
        .and_then(|b| Inbox::decode(&b)))
}

fn put_inbox(tx: &mut Tx<'_>, mailbox: &[u8; 32], ib: &Inbox) -> db::Result<()> {
    tx.put(db::INBOXES, mailbox, &ib.encode())
}

/// Devices an account's manifests have listed: `n × (root ‖ id ‖ u16 len ‖ key)`.
fn encode_seen(list: &[SeenDevice]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in list {
        let k = s.key.to_bytes();
        out.extend_from_slice(&s.root);
        out.extend_from_slice(&s.id);
        out.extend_from_slice(&(k.len() as u16).to_be_bytes());
        out.extend_from_slice(&k);
    }
    out
}

fn decode_seen(mut b: &[u8]) -> Vec<SeenDevice> {
    let mut out = Vec::new();
    while b.len() >= 82 {
        let n = usize::from(u16::from_be_bytes([b[80], b[81]]));
        let Some(k) = b.get(82..82 + n) else { break };
        let (Ok(root), Ok(id), Ok(key)) = (
            b[..64].try_into(),
            b[64..80].try_into(),
            enclave_crypto::sig::CompositePublic::from_slice(k),
        ) else {
            break;
        };
        out.push(SeenDevice { root, id, key });
        b = &b[82 + n..];
    }
    out
}

/// A list of byte strings: `n × (u32 len ‖ bytes)`.
fn encode_blobs(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for i in items {
        out.extend_from_slice(&(i.len() as u32).to_be_bytes());
        out.extend_from_slice(i);
    }
    out
}

fn decode_blobs(mut b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        let Some(item) = b.get(4..4 + n) else { break };
        out.push(item.to_vec());
        b = &b[4 + n..];
    }
    out
}

#[derive(Default)]
struct Upload {
    total: u32,
    started: u64,
    chunks: BTreeMap<u32, Vec<u8>>,
}

/// How long a directory upload may take before its chunks are dropped.
const UPLOAD_TTL_SECS: u64 = 600;

/// Aggregate counters (no per-user data), for operators and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Requests handled.
    pub requests: u64,
    /// Cover requests dropped.
    pub cover: u64,
    /// Stored envelopes.
    pub stored: u64,
    /// Tokens burned.
    pub tokens_burned: u64,
    /// Denied requests.
    pub denied: u64,
    /// Replayed requests refused.
    pub replays: u64,
}

/// Answers kept for status polls at most at once.
pub const MAX_DEFERRED: usize = 65_536;
/// Bytes of kept answers at most at once (they are kept unpadded and padded
/// when fetched).
pub const MAX_DEFERRED_BYTES: usize = 64 << 20;

/// An Enclave server.
pub struct Server {
    cfg: Config,
    keys: VecDeque<ServerSecret>,
    /// Everything that must survive a restart (`db.rs`): inboxes, tokens,
    /// envelopes, the directory, blobs, push tokens, usernames, reports.
    db: Db,
    /// Claimed bundles, kept for their follow-up chunk requests (600 s).
    claims: HashMap<[u8; 32], (Vec<u8>, u64)>,
    /// Directory uploads in progress, with when they started.
    uploads: HashMap<(u8, [u8; 32]), Upload>,
    kt: Option<KtService>,
    /// Accounts whose record the log hasn't taken yet (manifest keys),
    /// and whether the accounts stored before the log was enabled still
    /// need theirs.
    kt_accounts: (BTreeSet<[u8; 32]>, bool),
    /// Scheduled wakes by sealed-token hash.
    wakes: HashMap<[u8; 32], Wake>,
    /// When each inbox that asked for dummy wakes gets its next one
    /// (loaded from `push-dummy` on first use).
    dummies: Option<HashMap<[u8; 32], u64>>,
    /// A second log shown instead of `kt` (test hook, RT-04).
    #[cfg(feature = "test-hooks")]
    kt_fork: Option<KtService>,
    #[cfg(feature = "test-hooks")]
    kt_serve_fork: bool,
    /// Keep account records out of the log (test hook): a server hiding a
    /// manifest change from the log.
    #[cfg(feature = "test-hooks")]
    kt_withhold: bool,
    /// Answer every blob fetch "not found" (test hook): a file that can't
    /// be fetched.
    #[cfg(feature = "test-hooks")]
    blob_withhold: bool,
    /// What a curious server could log about tokens (test hook): each
    /// registration batch, and each burned hash in order.
    #[cfg(feature = "test-hooks")]
    token_log: (Vec<Vec<[u8; 32]>>, Vec<[u8; 32]>),
    /// What a curious server could log about downloads (test hook): each
    /// blob chunk id fetched, in order.
    #[cfg(feature = "test-hooks")]
    blob_gets: Vec<[u8; 32]>,
    /// A server showing readers different views of a mailbox (test hook,
    /// RT-11): whether envelopes stored now are marked, whether polls skip
    /// the marked ones now, and the marked `mailbox ‖ seq` keys.
    #[cfg(feature = "test-hooks")]
    hidden: (bool, bool, HashSet<Vec<u8>>),
    /// Chunked lookup replies by reply id.
    kt_replies: HashMap<[u8; 32], (Vec<u8>, u64)>,
    /// The day rotating inboxes were last swept for expiry.
    swept: u32,
    /// Answers to requests sent one way (`FLAG_DEFER`), by status id,
    /// with when they were made, until their status poll fetches them.
    deferred: HashMap<[u8; 32], (RequestHeader, Reply, u64)>,
    /// Their total size.
    deferred_bytes: usize,
    stats: Stats,
    /// Every object ever stored, by length, for invariant checks in tests.
    stored_lengths: HashSet<usize>,
    /// The signed key bundle served to a zero-length request.
    key_bundle: Vec<u8>,
    /// This server's signed descriptor (`DirKind::Descriptor`).
    descriptor: Vec<u8>,
    /// The foundation's server list as mirrored here (`DirKind::ServerList`).
    server_list: Vec<u8>,
    /// The release update bundle relayed here (`DirKind::Update`).
    update_bundle: Vec<u8>,
    /// Head keys of the logs the list names, to check equivocation proofs.
    listed_logs: HashMap<[u8; 16], enclave_crypto::sig::CompositePublic>,
    /// URLs of the witnesses the list names.
    listed_witnesses: Vec<String>,
    /// Equivocation proofs accepted and not yet passed on to witnesses.
    equivocations_out: Vec<enclave_kt::Equivocation>,
    /// Seed of the blob-token issuer keys (`blob_issuers`).
    blob_seed: zeroize::Zeroizing<[u8; 32]>,
    rng: HedgedRng,
}

/// The blob-token issuer keys at `now` (`docs/09-transport.md` §9): this
/// month's and next month's, derived from `seed`.
pub fn blob_issuers(seed: &[u8; 32], now: u64) -> Vec<enclave_federation::BlobIssuer> {
    let e = api::issuer_epoch(now);
    [e, e.saturating_add(1)]
        .into_iter()
        .filter_map(|epoch| {
            let k = enclave_tokens::privpass::IssuerKey::derive(seed, epoch).ok()?;
            Some(enclave_federation::BlobIssuer {
                epoch,
                public: k.public().0,
            })
        })
        .collect()
}

pub use enclave_rpc::api::{device_key, manifest_key};

/// Most reports kept for the operator; older ones are dropped.
pub const MAX_REPORTS: usize = 1000;

/// A user report as the operator sees it: the reported account's request
/// inbox, the day it arrived, and what the reporter chose to include.
/// Nothing names the reporter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The reported account's request inbox (from its contact card).
    pub request_inbox: [u8; 32],
    /// Day it arrived (Unix days).
    pub day: u64,
    /// Reason and quotes.
    pub body: api::ReportBody,
}

/// A device some manifest of an account listed.
struct SeenDevice {
    root: [u8; 64],
    id: [u8; 16],
    key: enclave_crypto::sig::CompositePublic,
}

impl Server {
    /// A server that keeps everything in memory, with a random request
    /// key for `day` (tests, the simulator, the offline demo).
    pub fn new(cfg: Config, day: u32) -> Result<Self, ServerError> {
        let mut rng = HedgedRng::new()?;
        let key = ServerSecret::generate(day, &mut rng).map_err(|_| enclave_crypto::Error::Rng)?;
        Self::with(cfg, Db::memory()?, vec![key], rng)
    }

    /// A server over a database file, with request keys from the persisted
    /// chain (`keys::RequestChain`): newest first, today's and yesterday's.
    pub fn open(cfg: Config, db: Db, keys: Vec<ServerSecret>) -> Result<Self, ServerError> {
        Self::with(cfg, db, keys, HedgedRng::new()?)
    }

    fn with(
        cfg: Config,
        db: Db,
        keys: Vec<ServerSecret>,
        mut rng: HedgedRng,
    ) -> Result<Self, ServerError> {
        // Random until the persisted one is set (`set_blob_seed`).
        let blob_seed = zeroize::Zeroizing::new(rng.array("server/blob-seed")?);
        Ok(Self {
            cfg,
            keys: keys.into_iter().collect(),
            db,
            claims: HashMap::new(),
            uploads: HashMap::new(),
            kt: None,
            kt_accounts: (BTreeSet::new(), false),
            wakes: HashMap::new(),
            dummies: None,
            #[cfg(feature = "test-hooks")]
            kt_fork: None,
            #[cfg(feature = "test-hooks")]
            kt_serve_fork: false,
            #[cfg(feature = "test-hooks")]
            kt_withhold: false,
            #[cfg(feature = "test-hooks")]
            blob_withhold: false,
            #[cfg(feature = "test-hooks")]
            token_log: (Vec::new(), Vec::new()),
            #[cfg(feature = "test-hooks")]
            blob_gets: Vec::new(),
            #[cfg(feature = "test-hooks")]
            hidden: (false, false, HashSet::new()),
            kt_replies: HashMap::new(),
            swept: 0,
            deferred: HashMap::new(),
            deferred_bytes: 0,
            stats: Stats::default(),
            stored_lengths: HashSet::new(),
            key_bundle: Vec::new(),
            descriptor: Vec::new(),
            server_list: Vec::new(),
            update_bundle: Vec::new(),
            listed_logs: HashMap::new(),
            listed_witnesses: Vec::new(),
            equivocations_out: Vec::new(),
            blob_seed,
            rng,
        })
        .inspect(|s| {
            // Replay ids of keys deleted while the server was down.
            let oldest = s.keys.iter().map(|k| k.key_id).min().unwrap_or(0);
            let r = s.db.write(|t| {
                t.remove_where(db::REPLAYS, &[], |k, _| {
                    k.get(..4)
                        .and_then(|b| b.try_into().ok())
                        .map(u32::from_be_bytes)
                        .is_none_or(|d| d < oldest)
                })
            });
            if let Err(e) = r {
                log_db_error(&e);
            }
        })
    }

    /// Set the signed key bundle (`enclave_federation::KeyBundle`) answered
    /// to a zero-length request: the identity key and certificates for
    /// today's and tomorrow's request keys. Replaced at every rotation.
    pub fn set_key_bundle(&mut self, bundle: Vec<u8>) {
        self.key_bundle = bundle;
    }

    /// The signed key bundle (empty until one is set).
    pub fn key_bundle(&self) -> &[u8] {
        &self.key_bundle
    }

    /// Commit a descriptor digest to this server's key-transparency log
    /// (`None` if the server runs no log).
    pub fn commit_descriptor(&self, digest: [u8; 64], now: u64) -> Option<Result<u64, KtError>> {
        self.kt.as_ref().map(|kt| kt.commit_descriptor(digest, now))
    }

    /// Set the signed descriptor served as `DirKind::Descriptor`.
    pub fn set_descriptor(&mut self, descriptor: Vec<u8>) {
        self.descriptor = descriptor;
    }

    /// Set the server list served as `DirKind::ServerList`. The server
    /// doesn't check it (it holds no foundation key); clients do.
    pub fn set_server_list(&mut self, list: Vec<u8>) {
        let parsed = enclave_federation::ServerList::decode_unchecked(&list).ok();
        self.listed_logs = parsed
            .iter()
            .flat_map(|l| &l.servers)
            .filter_map(|s| s.kt.as_ref().map(|k| (s.id(), k.head_key.clone())))
            .collect();
        self.listed_witnesses = parsed
            .iter()
            .flat_map(|l| &l.witnesses)
            .map(|w| w.url.clone())
            .filter(|u| !u.is_empty())
            .collect();
        self.server_list = list;
    }

    /// Set the release update bundle served as `DirKind::Update`. It is
    /// signed throughout and clients check it; the server only relays it.
    pub fn set_update_bundle(&mut self, bundle: Vec<u8>) {
        self.update_bundle = bundle;
    }

    /// Accept equivocation proofs for `server`'s log under `head_key`
    /// (the server list does this for every log it names).
    pub fn pin_log(&mut self, server: [u8; 16], head_key: enclave_crypto::sig::CompositePublic) {
        self.listed_logs.insert(server, head_key);
    }

    /// URLs of the witnesses the server list names.
    pub fn listed_witnesses(&self) -> &[String] {
        &self.listed_witnesses
    }

    /// Equivocation proofs accepted since the last call, for the operator's
    /// process to pass on to the witnesses (`12-servers.md` §3.8).
    pub fn take_equivocations(&mut self) -> Vec<enclave_kt::Equivocation> {
        std::mem::take(&mut self.equivocations_out)
    }

    /// The database (backups, operator tools).
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Run `f` in a write transaction; a storage failure answers
    /// `Unavailable` (the client tries again later) and nothing is applied.
    fn tx<R>(&self, f: impl FnOnce(&mut Tx<'_>) -> db::Result<R>) -> Result<R, Status> {
        self.db.write(f).map_err(|e| {
            log_db_error(&e);
            Status::Unavailable
        })
    }

    /// Current public request key (published in the server descriptor).
    pub fn public_key(&self) -> Option<ServerKey> {
        self.keys.front().map(|k| k.public().clone())
    }

    /// Rotate to a new random daily key (in-memory servers); keep
    /// yesterday's for late requests and delete anything older (forward
    /// secrecy for request metadata).
    pub fn rotate(&mut self, day: u32) -> enclave_crypto::Result<()> {
        let k =
            ServerSecret::generate(day, &mut self.rng).map_err(|_| enclave_crypto::Error::Rng)?;
        self.install_key(k);
        Ok(())
    }

    /// Make `key` current (from the persisted chain); keep one previous.
    pub fn install_key(&mut self, key: ServerSecret) {
        if self.keys.front().is_some_and(|k| k.key_id == key.key_id) {
            return;
        }
        self.keys.push_front(key);
        while self.keys.len() > 2 {
            self.keys.pop_back();
        }
        self.prune_replays(7);
    }

    fn garbage(&mut self) -> Vec<u8> {
        let mut r = vec![0u8; enclave_wire::UNIT_LEN];
        if self.rng.fill("server/garbage-reply", &mut r).is_err() {
            r.fill(0);
        }
        r
    }

    /// Check a proof of work made for today or yesterday (`ctx(day)` is its
    /// context) and spend it: each proof is accepted once (`12-servers.md`
    /// §1.1, RT-06). False if it doesn't verify, was spent, or can't be
    /// recorded.
    fn spend_pow(
        &mut self,
        ctx: impl Fn(u64) -> Vec<u8>,
        effort: u32,
        proof: &[u8; 32],
        now: u64,
    ) -> bool {
        let today = now / 86_400;
        let Some(day) = [today, today.saturating_sub(1)]
            .into_iter()
            .find(|d| enclave_tokens::verify(&ctx(*d), effort, &PowProof(*proof)))
        else {
            return false;
        };
        let k = cat(&u32::try_from(day).unwrap_or(u32::MAX).to_be_bytes(), proof);
        self.db
            .write_lazy(|t| {
                if t.has(db::POW_SPENT, &k)? {
                    return Ok(false);
                }
                t.put(db::POW_SPENT, &k, &[])?;
                Ok(true)
            })
            .unwrap_or_else(|e| {
                log_db_error(&e);
                false
            })
    }

    /// Record a request's replay id; false if it was seen (or can't be
    /// recorded).
    fn first_time(&mut self, key_id: u32, id: &[u8; 32]) -> bool {
        let k = cat(&key_id.to_be_bytes(), id);
        self.db
            .write_lazy(|t| {
                if t.has(db::REPLAYS, &k)? {
                    return Ok(false);
                }
                t.put(db::REPLAYS, &k, &[])?;
                Ok(true)
            })
            .unwrap_or_else(|e| {
                log_db_error(&e);
                false
            })
    }

    /// Forget the replay ids of keys this server no longer holds: their
    /// requests can't be opened any more. Looks back `days` days before the
    /// oldest key held.
    fn prune_replays(&mut self, days: u32) {
        let Some(oldest) = self.keys.iter().map(|k| k.key_id).min() else {
            return;
        };
        let r = self.db.write(|t| {
            let mut n = 0;
            for d in oldest.saturating_sub(days)..oldest {
                n += t.remove_where(db::REPLAYS, &d.to_be_bytes(), |_, _| true)?;
            }
            Ok(n)
        });
        if let Err(e) = r {
            log_db_error(&e);
        }
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Inboxes and vault-key blobs held now (diagnostics, tests).
    pub fn inboxes_held(&self) -> (usize, usize) {
        self.db
            .read(|r| {
                Ok((
                    r.scan(db::INBOXES, b"")?.len(),
                    r.scan(db::VAULTS, b"")?.len(),
                ))
            })
            .unwrap_or((0, 0))
    }

    /// Envelopes stored now, in every inbox (diagnostics, tests).
    pub fn envelopes_held(&self) -> usize {
        self.db
            .read(|r| r.scan(db::ENVELOPES, b"").map(|v| v.len()))
            .unwrap_or(0)
    }

    /// Test hook: every token-registration batch, and every burned token
    /// hash in order, as a curious server could log them.
    #[cfg(feature = "test-hooks")]
    pub fn token_log(&self) -> &(Vec<Vec<[u8; 32]>>, Vec<[u8; 32]>) {
        &self.token_log
    }

    /// Lengths of every envelope and blob chunk ever stored.
    pub fn stored_lengths(&self) -> &HashSet<usize> {
        &self.stored_lengths
    }

    /// Delete expired envelopes, blobs, claims, lookup replies and stalled
    /// uploads.
    pub fn expire(&mut self, now: u64) {
        let ttl = self.cfg.ttl_secs;
        // Spent proofs of days that can't be proven for any more.
        let oldest = u32::try_from((now / 86_400).saturating_sub(1)).unwrap_or(u32::MAX);
        // Rotating inboxes past their last read day and the envelope
        // lifetime after it go, with everything kept for them.
        let today = api::day_of(now);
        let ttl_days = u32::try_from(ttl.div_ceil(86_400)).unwrap_or(u32::MAX);
        let sweep = std::mem::replace(&mut self.swept, today) != today;
        let _ = self.tx(|t| {
            let gone: Vec<Vec<u8>> = if !sweep {
                Vec::new()
            } else {
                t.scan(db::INBOXES, b"")?
                    .into_iter()
                    .filter(|(_, v)| {
                        Inbox::decode(v).is_some_and(|ib| {
                            ib.until > 0 && ib.until.saturating_add(ttl_days) < today
                        })
                    })
                    .map(|(k, _)| k)
                    .collect()
            };
            for mb in &gone {
                t.del(db::INBOXES, mb)?;
                t.del(db::PUSH, mb)?;
                t.del(db::PUSH_DUMMY, mb)?;
                t.del(db::PUSH_CALL, mb)?;
                for table in [db::ENVELOPES, db::HINTS, db::TOKENS, db::READ_CREDS] {
                    t.remove_where(table, mb, |_, _| true)?;
                }
            }
            // Group push registrations from before yesterday: their
            // mailboxes are past.
            if sweep {
                t.remove_where(db::PUSH_GROUP, b"", |_, v| {
                    v.get(..4)
                        .and_then(|b| b.try_into().ok())
                        .map(u32::from_be_bytes)
                        .is_none_or(|d| d + 1 < today)
                })?;
            }
            // Read credentials for days that are over.
            if sweep {
                t.remove_where(db::READ_CREDS, b"", |k, _| {
                    k.get(32..36)
                        .and_then(|b| b.try_into().ok())
                        .map(u32::from_be_bytes)
                        .is_some_and(|d| d.saturating_add(1) < today)
                })?;
            }
            t.remove_where(db::ENVELOPES, b"", |_, v| now > head_u64(v) + ttl)?;
            t.remove_where(db::HINTS, b"", |_, v| now > head_u64(v) + ttl)?;
            t.remove_where(db::BLOBS, b"", |_, v| now > head_u64(v) + ttl)?;
            // Allocations past their day; issue counts of days before
            // yesterday; spent tokens of keys that no longer verify.
            t.remove_where(db::ALLOCS, b"", |_, v| now > head_u64(v))?;
            if sweep {
                t.remove_where(db::BLOB_ISSUED, b"", |k, _| {
                    k.get(32..36)
                        .and_then(|b| b.try_into().ok())
                        .map(u32::from_be_bytes)
                        .is_none_or(|d| d.saturating_add(1) < today)
                })?;
                let epoch = api::issuer_epoch(now);
                t.remove_where(db::BLOB_SPENT, b"", |_, v| {
                    v.get(..4)
                        .and_then(|b| b.try_into().ok())
                        .map(u32::from_be_bytes)
                        .is_some_and(|e| e.saturating_add(1) < epoch)
                })?;
            }
            t.remove_where(db::POW_SPENT, b"", |k, _| {
                k.get(..4)
                    .and_then(|b| b.try_into().ok())
                    .map(u32::from_be_bytes)
                    .is_none_or(|d| d < oldest)
            })
        });
        self.claims.retain(|_, (_, t)| now <= *t + 600);
        self.kt_replies.retain(|_, (_, t)| now <= *t + 600);
        self.expire_deferred(now);
        self.uploads
            .retain(|_, u| now <= u.started + UPLOAD_TTL_SECS);
    }

    /// Set the seed of the blob-token issuer keys (derived from the
    /// identity key, `keys::ServerKeys::blob_seed`, so it survives restarts).
    pub fn set_blob_seed(&mut self, seed: [u8; 32]) {
        self.blob_seed = zeroize::Zeroizing::new(seed);
    }

    /// The blob-token issuer keys at `now`, for the descriptor.
    pub fn blob_issuers(&self, now: u64) -> Vec<enclave_federation::BlobIssuer> {
        blob_issuers(&self.blob_seed, now)
    }

    /// **Test hook**: the blob chunk ids fetched since the last call.
    #[cfg(feature = "test-hooks")]
    pub fn take_blob_gets(&mut self) -> Vec<[u8; 32]> {
        std::mem::take(&mut self.blob_gets)
    }

    /// Attach a key-transparency log, enabling usernames.
    pub fn enable_kt(&mut self, kt: KtService) {
        self.kt = Some(kt);
        // Accounts stored before this log was enabled get their records
        // with the next commit (`commit_account`).
        self.kt_accounts.1 = true;
    }

    /// An account's record for the log: its manifest and attestation list
    /// as served here, or its migration once it moved to a new root.
    fn account_record(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.db
            .read(|r| {
                if let Some(mig) = r.get(db::MIGRATIONS, key)? {
                    return Ok(Some(enclave_kt::migration_record(&mig)));
                }
                if let Some(t) = r.get(db::TOMBSTONES, key)? {
                    return Ok(Some(enclave_kt::tombstone_record(&t)));
                }
                let Some(m) = r.get(db::MANIFESTS, key)? else {
                    return Ok(None);
                };
                let atts = r
                    .get(db::ATTESTATIONS, key)?
                    .map(|v| enclave_proto::attest::encode_list(&decode_blobs(&v)))
                    .unwrap_or_default();
                Ok(Some(enclave_kt::account_record(tail(&m), &atts).to_vec()))
            })
            .ok()
            .flatten()
    }

    /// Commit the record of the account at `key` (its manifest or
    /// attestations changed) to the log, with any earlier ones the log
    /// didn't take (`03-identity.md` §8.1). Contacts accept a manifest
    /// change only once its record is in the log.
    fn commit_account(&mut self, key: Option<[u8; 32]>, now: u64) {
        let Some(marker) = self
            .kt
            .as_ref()
            .map(|kt| enclave_crypto::hash::sha3_512(&kt.info().vrf_public))
        else {
            return;
        };
        if let Some(k) = key {
            self.kt_accounts.0.insert(k);
        }
        #[cfg(feature = "test-hooks")]
        if self.kt_withhold {
            return;
        }
        // Once per log: every account stored here, unless this log took
        // them before (a restart).
        let mut keys: BTreeSet<[u8; 32]> = std::mem::take(&mut self.kt_accounts.0);
        if self.kt_accounts.1 {
            let done = self
                .db
                .read(|r| r.get(db::META, b"kt-accounts"))
                .ok()
                .flatten()
                .is_some_and(|v| v == marker);
            if !done {
                let all = self
                    .db
                    .read(|r| r.scan(db::MANIFESTS, b""))
                    .unwrap_or_default();
                keys.extend(
                    all.into_iter()
                        .filter_map(|(k, _)| <[u8; 32]>::try_from(k.as_slice()).ok()),
                );
            }
        }
        let records: Vec<([u8; 31], Vec<u8>)> = keys
            .iter()
            .filter_map(|k| {
                let rec = self.account_record(k)?;
                Some((k[1..].try_into().ok()?, rec))
            })
            .collect();
        if records.is_empty() {
            self.kt_accounts.1 = false;
            return;
        }
        let Some(kt) = self.kt.as_ref() else {
            return;
        };
        match kt.commit_accounts(records, now) {
            Ok(_) => {
                if std::mem::take(&mut self.kt_accounts.1) {
                    let _ = self.tx(|t| t.put(db::META, b"kt-accounts", &marker));
                }
            }
            Err(e) => {
                eprintln!("enclave-server: key transparency: {e}");
                self.kt_accounts.0 = keys;
            }
        }
    }

    /// **Test hook**: a second log (`KtService::start_dev_twins`) this
    /// server can show instead of its real one, as an equivocating server
    /// would.
    #[cfg(feature = "test-hooks")]
    pub fn enable_kt_fork(&mut self, fork: KtService) {
        self.kt_fork = Some(fork);
    }

    /// **Test hook**: bind a name in the fork only.
    #[cfg(feature = "test-hooks")]
    pub fn kt_fork_force(&mut self, name: &str, value: Vec<u8>, now: u64) -> bool {
        self.kt_fork
            .as_ref()
            .is_some_and(|k| k.publish(name, value, now).is_ok())
    }

    /// **Test hook**: answer lookups from the fork (true) or the real log.
    #[cfg(feature = "test-hooks")]
    pub fn kt_serve_fork(&mut self, on: bool) {
        self.kt_serve_fork = on;
    }

    /// **Test hook**: keep account records out of the log (true) or put
    /// the ones held back in with the next commit (false).
    #[cfg(feature = "test-hooks")]
    pub fn kt_withhold(&mut self, on: bool) {
        self.kt_withhold = on;
    }

    /// **Test hook**: answer every blob fetch "not found" (true), or
    /// serve blobs again (false).
    #[cfg(feature = "test-hooks")]
    pub fn blob_withhold(&mut self, on: bool) {
        self.blob_withhold = on;
    }

    /// **Test hook**: mark every envelope stored from now on (true) until
    /// turned off (false), so [`Self::hide_marked`] can keep them from some
    /// readers.
    #[cfg(feature = "test-hooks")]
    pub fn mark_new(&mut self, on: bool) {
        self.hidden.0 = on;
    }

    /// **Test hook**: polls skip the marked envelopes (true) or see them
    /// again (false). Readers of one mailbox share its credential, so the
    /// test turns this on around the reader it deceives.
    #[cfg(feature = "test-hooks")]
    pub fn hide_marked(&mut self, on: bool) {
        self.hidden.1 = on;
    }

    /// The log lookups are answered from.
    fn kt_lookups(&self) -> Option<&KtService> {
        #[cfg(feature = "test-hooks")]
        if self.kt_serve_fork {
            return self.kt_fork.as_ref();
        }
        self.kt.as_ref()
    }

    /// **Tests only**: bind `name` to `value` in the log without any of the
    /// checks, as a dishonest operator could. Returns whether it published.
    #[cfg(feature = "test-hooks")]
    pub fn kt_force(&mut self, name: &str, value: Vec<u8>, now: u64) -> bool {
        self.kt
            .as_ref()
            .is_some_and(|k| k.publish(name, value, now).is_ok())
    }

    /// What clients pin for this server's log, if usernames are enabled.
    pub fn kt_info(&self) -> Option<KtInfo> {
        self.kt.as_ref().map(|k| k.info().clone())
    }

    /// Handle one sealed request (unit or poll) and return the sealed reply.
    /// Undecryptable input gets a random reply of the same size, so the
    /// network cannot tell rejected requests from accepted ones.
    pub fn handle(&mut self, request: &[u8], now: u64) -> Vec<u8> {
        self.stats.requests += 1;
        let keys: Vec<&ServerSecret> = self.keys.iter().collect();
        let opened = match enclave_rpc::open_request(&keys, request) {
            Ok(o) => o,
            Err(_) => return self.garbage(),
        };
        // A request opened before is a replay (`09-transport.md` §2.3): it
        // gets the same random bytes as one that doesn't open.
        if !self.first_time(opened.key_id, &opened.replay_id) {
            self.stats.replays += 1;
            return self.garbage();
        }
        // A status poll: the answer to an earlier one-way request, sealed
        // to this poll (`09-transport.md` §6.1).
        if opened.header.op == Op::Status {
            let (header, body) = match self.deferred.remove(&opened.header.mailbox) {
                Some((h, body, _)) => {
                    self.deferred_bytes -= body.len();
                    (h, body)
                }
                None => (
                    RequestHeader {
                        op: Op::Status,
                        flags: Status::NotFound as u8,
                        mailbox: opened.header.mailbox,
                        token: [0; 32],
                    },
                    Reply::Empty,
                ),
            };
            let envelope = self.reply_envelope(body);
            return opened
                .exchange
                .seal_reply(&header, &envelope, &mut self.rng)
                .unwrap_or_else(|_| vec![0u8; enclave_wire::UNIT_LEN]);
        }
        let (status, extra_flags, reply_token, payload) =
            self.dispatch(&opened.header, &opened.envelope, now);
        if status == Status::Denied {
            self.stats.denied += 1;
        }
        let reply_header = RequestHeader {
            op: opened.header.op,
            flags: status as u8 | extra_flags,
            mailbox: opened.header.mailbox,
            token: reply_token,
        };
        if opened.header.flags & api::FLAG_DEFER != 0 {
            // Kept for the status poll, which brings the answer back in
            // the poll slot. Bounded: past the limits, new answers aren't
            // kept (their senders' status polls find nothing and give up).
            let full = |s: &Self| {
                s.deferred.len() >= MAX_DEFERRED
                    || s.deferred_bytes + payload.len() > MAX_DEFERRED_BYTES
            };
            if full(self) {
                self.expire_deferred(now);
            }
            if !full(self) {
                self.deferred_bytes += payload.len();
                if let Some((_, old, _)) = self.deferred.insert(
                    opened.exchange.status_id(),
                    (reply_header, payload.clone(), now),
                ) {
                    self.deferred_bytes -= old.len();
                }
            }
        }
        // Over the mixnet nobody reads a deferred request's direct reply
        // (the ingress drops it); over TCP it is the answer.
        let envelope = self.reply_envelope(payload);
        opened
            .exchange
            .seal_reply(&reply_header, &envelope, &mut self.rng)
            .unwrap_or_else(|_| vec![0u8; enclave_wire::UNIT_LEN])
    }

    /// A reply's envelope region: stored bytes as they are, or an API frame
    /// padded with random bytes.
    fn reply_envelope(&mut self, body: Reply) -> Vec<u8> {
        match body {
            Reply::Envelope(e) => e,
            Reply::Payload(p) => {
                api::frame(&p, &mut self.rng).unwrap_or_else(|_| vec![0u8; ENVELOPE_LEN])
            }
            Reply::Empty => {
                api::frame(&[], &mut self.rng).unwrap_or_else(|_| vec![0u8; ENVELOPE_LEN])
            }
        }
    }

    fn expire_deferred(&mut self, now: u64) {
        self.deferred
            .retain(|_, (_, _, t)| now <= *t + api::DEFER_TTL_SECS);
        self.deferred_bytes = self.deferred.values().map(|(_, b, _)| b.len()).sum();
    }

    fn dispatch(
        &mut self,
        h: &RequestHeader,
        env: &[u8],
        now: u64,
    ) -> (Status, u8, [u8; 32], Reply) {
        let none = [0u8; 32];
        match h.op {
            Op::Cover => {
                self.stats.cover += 1;
                (Status::Ok, 0, none, Reply::Empty)
            }
            Op::RegisterTokens => (self.register_tokens(h, env, now), 0, none, Reply::Empty),
            Op::Write => (self.write(h, env, now), 0, none, Reply::Empty),
            Op::WriteRequest => (self.write_request(h, env, now), 0, none, Reply::Empty),
            Op::Poll => self.poll(h, now),
            Op::Ack => (self.ack(h, now), 0, none, Reply::Empty),
            Op::BlobPut => (self.blob_put(h, env, now), 0, none, Reply::Empty),
            Op::BlobAlloc => {
                let (s, p) = self.blob_alloc(h, env, now);
                (s, 0, none, p)
            }
            Op::BlobGet => {
                #[cfg(feature = "test-hooks")]
                self.blob_gets.push(h.mailbox);
                let got = self.db.read(|r| r.get(db::BLOBS, &h.mailbox));
                #[cfg(feature = "test-hooks")]
                let got = if self.blob_withhold { Ok(None) } else { got };
                match got {
                    Ok(Some(v)) => (Status::Ok, 0, none, Reply::Envelope(tail(&v).to_vec())),
                    Ok(None) => (Status::NotFound, 0, none, Reply::Empty),
                    Err(e) => {
                        log_db_error(&e);
                        (Status::Unavailable, 0, none, Reply::Empty)
                    }
                }
            }
            Op::Directory => match api::unframe(env).and_then(DirRequest::decode) {
                Ok(req) => {
                    let (s, p) = self.directory(req, now);
                    (s, 0, none, p)
                }
                Err(_) => (Status::Malformed, 0, none, Reply::Empty),
            },
            Op::KeyTransparency => (Status::NotFound, 0, none, Reply::Empty),
            Op::PushRegister => (self.push_register(h, env, now), 0, none, Reply::Empty),
            Op::Report => (self.report(h, env, now), 0, none, Reply::Empty),
            // Answered in `handle`.
            Op::Status => (Status::NotFound, 0, none, Reply::Empty),
        }
    }

    fn register_tokens(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let owner_hash = api::credential_hash(&h.token);
        let mb = h.mailbox;
        if h.flags & FLAG_CREATE != 0 {
            let body = api::unframe(env).ok();
            // A new inbox costs a proof of work for its address, today's or
            // yesterday's (`09-transport.md` §3.1).
            if self.cfg.effort_inbox > 0 {
                let proof: Option<[u8; 32]> = body
                    .and_then(|p| p.get(..32))
                    .and_then(|p| p.try_into().ok());
                let effort = self.cfg.effort_inbox;
                let ok = proof.is_some_and(|p| {
                    self.spend_pow(|d| api::pow_context_inbox(&mb, d), effort, &p, now)
                });
                if !ok {
                    return Status::Pow;
                }
            }
            // Daily read credentials, if the owner sent any: from yesterday
            // to three weeks ahead.
            let days = match body.filter(|p| p.len() > 32) {
                None => Vec::new(),
                Some(p) => match api::parse_create_payload(p) {
                    Some((_, d)) => d,
                    None => return Status::Malformed,
                },
            };
            let today = api::day_of(now);
            let window = today.saturating_sub(1)..=today.saturating_add(api::MAX_READ_DAYS as u32);
            if days.iter().any(|(d, _)| !window.contains(d)) {
                return Status::Malformed;
            }
            let mut owner = [0u8; 32];
            owner.copy_from_slice(&h.token);
            let ib = Inbox {
                owner: owner_hash,
                read: if days.is_empty() {
                    api::credential_hash(&api::read_credential(&owner))
                } else {
                    [0; 32]
                },
                request: h.flags & FLAG_REQUEST_INBOX != 0,
                group: false,
                next_seq: 1,
                effort: 0,
                until: days.iter().map(|(d, _)| *d).max().unwrap_or(0),
            };
            return self
                .tx(|t| {
                    if t.has(db::INBOXES, &mb)? {
                        return Ok(Status::Denied);
                    }
                    put_inbox(t, &mb, &ib)?;
                    for (d, hash) in &days {
                        t.put(db::READ_CREDS, &cat(&mb, &d.to_be_bytes()), hash)?;
                    }
                    Ok(Status::Ok)
                })
                .unwrap_or_else(|s| s);
        }
        if h.flags & api::FLAG_DELETE != 0 {
            return self
                .tx(|t| {
                    let Some(ib) = get_inbox(t, &mb)? else {
                        return Ok(Status::NotFound);
                    };
                    if ib.owner != owner_hash || ib.group {
                        return Ok(Status::Denied);
                    }
                    t.del(db::INBOXES, &mb)?;
                    t.del(db::PUSH, &mb)?;
                    t.del(db::PUSH_DUMMY, &mb)?;
                    t.del(db::PUSH_CALL, &mb)?;
                    for table in [db::ENVELOPES, db::HINTS, db::TOKENS, db::READ_CREDS] {
                        t.remove_where(table, &mb, |_, _| true)?;
                    }
                    Ok(Status::Ok)
                })
                .unwrap_or_else(|s| s);
        }
        let Ok(p) = api::unframe(env) else {
            return Status::Malformed;
        };
        if h.flags & FLAG_EFFORT != 0 {
            // The owner of a request inbox sets what writing to it costs.
            let Some(effort) = p
                .get(..4)
                .and_then(|e| e.try_into().ok())
                .map(u32::from_be_bytes)
                .filter(|e| *e <= api::MAX_INBOX_EFFORT)
            else {
                return Status::Malformed;
            };
            return self
                .tx(|t| {
                    let Some(mut ib) = get_inbox(t, &mb)? else {
                        return Ok(Status::NotFound);
                    };
                    if ib.owner != owner_hash || !ib.request {
                        return Ok(Status::Denied);
                    }
                    ib.effort = effort;
                    put_inbox(t, &mb, &ib)?;
                    Ok(Status::Ok)
                })
                .unwrap_or_else(|s| s);
        }
        if p.len() % 32 != 0 {
            return Status::Malformed;
        }
        let quota = self.cfg.token_quota;
        let revoke = h.flags & FLAG_REVOKE != 0;
        let status = self
            .tx(|t| {
                let Some(ib) = get_inbox(t, &mb)? else {
                    return Ok(Status::NotFound);
                };
                if ib.owner != owner_hash {
                    return Ok(Status::Denied);
                }
                if revoke {
                    for c in p.chunks_exact(32) {
                        t.del(db::TOKENS, &cat(&mb, c))?;
                    }
                    return Ok(Status::Ok);
                }
                if t.count(db::TOKENS, &mb)? + p.len() / 32 > quota {
                    return Ok(Status::Quota);
                }
                for c in p.chunks_exact(32) {
                    t.put(db::TOKENS, &cat(&mb, c), &[])?;
                }
                Ok(Status::Ok)
            })
            .unwrap_or_else(|s| s);
        #[cfg(feature = "test-hooks")]
        if status == Status::Ok && !revoke {
            self.token_log.0.push(
                p.chunks_exact(32)
                    .filter_map(|c| c.try_into().ok())
                    .collect(),
            );
        }
        status
    }

    /// Set or clear the sealed push token of an inbox (its owner only).
    /// The server can't open it: only the push relay can.
    fn push_register(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let Ok(sealed) = api::unframe(env) else {
            return Status::Malformed;
        };
        if h.flags & FLAG_GROUP != 0 {
            return self.push_register_group(h, sealed, now);
        }
        if sealed.len() > MAX_PUSH_TOKEN {
            return Status::Malformed;
        }
        let owner = api::credential_hash(&h.token);
        let mb = h.mailbox;
        if h.flags & api::FLAG_PUSH_CALL != 0 {
            return self
                .tx(|t| {
                    let Some(ib) = get_inbox(t, &mb)? else {
                        return Ok(Status::NotFound);
                    };
                    if ib.owner != owner || ib.group || ib.request {
                        return Ok(Status::Denied);
                    }
                    if sealed.is_empty() {
                        t.del(db::PUSH_CALL, &mb)?;
                    } else {
                        t.put(db::PUSH_CALL, &mb, sealed)?;
                    }
                    Ok(Status::Ok)
                })
                .unwrap_or_else(|s| s);
        }
        let old = self.db.read(|r| r.get(db::PUSH, &mb)).ok().flatten();
        let dummies = h.flags & api::FLAG_PUSH_DUMMIES != 0 && !sealed.is_empty();
        let gap = self.dummy_gap();
        if let Some(d) = self.dummies.as_mut() {
            if dummies {
                d.entry(mb).or_insert(now + gap);
            } else {
                d.remove(&mb);
            }
        }
        let status = self
            .tx(|t| {
                if dummies {
                    t.put(db::PUSH_DUMMY, &mb, &[])?;
                } else {
                    t.del(db::PUSH_DUMMY, &mb)?;
                }
                let Some(ib) = get_inbox(t, &mb)? else {
                    return Ok(Status::NotFound);
                };
                if ib.owner != owner || ib.group {
                    return Ok(Status::Denied);
                }
                if sealed.is_empty() {
                    t.del(db::PUSH, &mb)?;
                } else {
                    t.put(db::PUSH, &mb, sealed)?;
                }
                Ok(Status::Ok)
            })
            .unwrap_or_else(|s| s);
        if status == Status::Ok {
            self.drop_replaced_wake(old, sealed);
        }
        status
    }

    /// A registration was replaced or removed: a wake queued for its old
    /// sealed token and not yet handed out goes too.
    fn drop_replaced_wake(&mut self, old: Option<Vec<u8>>, new: &[u8]) {
        if let Some(old) = old.filter(|o| o != new) {
            let id = sha3_512(&old);
            self.wakes.retain(|k, w| w.sent || k[..] != id[..32]);
        }
    }

    /// A member device asks for wakes on a group mailbox: `id (8) ‖ sealed
    /// token` under its own id (an empty token removes it), authenticated
    /// by the mailbox's write token, which creates the mailbox like a
    /// first write.
    fn push_register_group(&mut self, h: &RequestHeader, payload: &[u8], now: u64) -> Status {
        let (Some(id), Some(sealed)) = (payload.get(..8), payload.get(8..)) else {
            return Status::Malformed;
        };
        if sealed.len() > MAX_PUSH_TOKEN {
            return Status::Malformed;
        }
        let owner = api::credential_hash(&h.token);
        let read = api::credential_hash(&api::read_credential(&h.token));
        let mb = h.mailbox;
        let key = cat(&mb, id);
        let old = self
            .db
            .read(|r| r.get(db::PUSH_GROUP, &key))
            .ok()
            .flatten()
            .and_then(|v| v.get(4..).map(<[u8]>::to_vec));
        let status = self
            .tx(|t| {
                match get_inbox(t, &mb)? {
                    None => put_inbox(
                        t,
                        &mb,
                        &Inbox {
                            owner,
                            read,
                            request: false,
                            group: true,
                            next_seq: 1,
                            effort: 0,
                            until: 0,
                        },
                    )?,
                    Some(ib) if ib.group && ib.owner == owner => {}
                    Some(_) => return Ok(Status::Denied),
                }
                if sealed.is_empty() {
                    t.del(db::PUSH_GROUP, &key)?;
                } else {
                    if !t.has(db::PUSH_GROUP, &key)?
                        && t.count(db::PUSH_GROUP, &mb)? >= api::MAX_GROUP_PUSH
                    {
                        return Ok(Status::Quota);
                    }
                    // With its day: a group's mailboxes are daily, and the
                    // registration goes with its day (`expire`).
                    t.put(
                        db::PUSH_GROUP,
                        &key,
                        &cat(&api::day_of(now).to_be_bytes(), sealed),
                    )?;
                }
                Ok(Status::Ok)
            })
            .unwrap_or_else(|s| s);
        if status == Status::Ok {
            self.drop_replaced_wake(old, sealed);
        }
        status
    }

    /// A write reached `mailbox`: schedule a wake for each sealed token
    /// registered there (the account's, or every member device's on a
    /// group mailbox), at most one per sealed token per window. The wake
    /// goes out in the *next* 60 s window at a random 0–30 s offset, so its
    /// time says little about the write's.
    fn schedule_wake(&mut self, mailbox: &[u8; 32], env: &[u8], now: u64) {
        let sealed: Vec<Vec<u8>> = self
            .db
            .read(|r| {
                let mut v: Vec<Vec<u8>> = r.get(db::PUSH, mailbox)?.into_iter().collect();
                v.extend(
                    r.scan(db::PUSH_GROUP, mailbox)?
                        .into_iter()
                        .filter_map(|(_, s)| s.get(4..).map(<[u8]>::to_vec)),
                );
                Ok(v)
            })
            .unwrap_or_default();
        for s in sealed {
            self.schedule_one(s, env, now);
        }
    }

    fn schedule_one(&mut self, sealed: Vec<u8>, env: &[u8], now: u64) {
        let id = sha3_512(&sealed);
        let mut key = [0u8; 32];
        key.copy_from_slice(&id[..32]);
        let capsule = match enclave_proto::envelope::capsule_of(env) {
            Some(c) => c.to_vec(),
            None => {
                let mut r = vec![0u8; enclave_wire::CAPSULE_LEN];
                if self.rng.fill("server/push-capsule", &mut r).is_err() {
                    return;
                }
                r
            }
        };
        let window = now / PUSH_WINDOW_SECS + 1;
        if let Some(w) = self.wakes.get_mut(&key)
            && w.window >= window
        {
            // One wake per window: it shows the newest message.
            w.capsule = capsule;
            return;
        }
        let jitter = self
            .rng
            .array::<1>("server/push-jitter")
            .map(|b| u64::from(b[0]) % (PUSH_JITTER_SECS + 1))
            .unwrap_or(0);
        self.wakes.insert(
            key,
            Wake {
                window,
                release: window * PUSH_WINDOW_SECS + jitter,
                sealed,
                capsule,
                sent: false,
            },
        );
    }

    /// Dummy wakes now due (`FLAG_PUSH_DUMMIES`): scheduled like a real
    /// write's, with a random capsule, then the next one drawn.
    fn schedule_dummies(&mut self, now: u64) {
        if self.dummies.is_none() {
            let inboxes = self
                .db
                .read(|r| r.scan(db::PUSH_DUMMY, b""))
                .unwrap_or_default();
            let mut m = HashMap::new();
            for (k, _) in inboxes {
                if let Ok(mb) = <[u8; 32]>::try_from(k.as_slice()) {
                    m.insert(mb, now + self.dummy_gap());
                }
            }
            self.dummies = Some(m);
        }
        let mut due = Vec::new();
        if let Some(d) = self.dummies.as_ref() {
            due = d
                .iter()
                .filter(|(_, t)| **t <= now)
                .map(|(mb, _)| *mb)
                .collect();
        }
        for mb in due {
            let gap = self.dummy_gap();
            if let Some(d) = self.dummies.as_mut() {
                d.insert(mb, now + gap);
            }
            if let Ok(Some(sealed)) = self.db.read(|r| r.get(db::PUSH, &mb)) {
                self.schedule_one(sealed, &[], now);
            }
        }
    }

    /// An exponential gap with mean [`api::DUMMY_WAKE_MEAN_SECS`].
    fn dummy_gap(&mut self) -> u64 {
        let r = self.rng.array::<8>("server/dummy-wake").unwrap_or([1; 8]);
        let u = (u64::from_be_bytes(r) >> 11) as f64 / (1u64 << 53) as f64;
        let u = u.max(1e-12);
        (-u.ln() * api::DUMMY_WAKE_MEAN_SECS as f64) as u64
    }

    /// Wakes due for the push relay, each `sealed token ‖ capsule`
    /// (2,976 B), returned once.
    pub fn due_wakes(&mut self, now: u64) -> Vec<Vec<u8>> {
        self.schedule_dummies(now);
        let mut out = Vec::new();
        for w in self.wakes.values_mut() {
            if !w.sent && w.release <= now {
                w.sent = true;
                out.push([&w.sealed[..], &w.capsule].concat());
            }
        }
        self.wakes
            .retain(|_, w| !w.sent || w.window * PUSH_WINDOW_SECS + 2 * PUSH_WINDOW_SECS > now);
        out
    }

    /// Append an envelope to `mailbox` inside the caller's transaction.
    fn store_in(
        t: &mut Tx<'_>,
        mailbox: &[u8; 32],
        env: &[u8],
        now: u64,
        quota: usize,
        hint: Option<&[u8; 32]>,
    ) -> db::Result<Status> {
        let Some(mut ib) = get_inbox(t, mailbox)? else {
            return Ok(Status::NotFound);
        };
        if t.count(db::ENVELOPES, mailbox)? >= quota {
            if ib.request {
                // Request inboxes drop their oldest pending request.
                if let Some((k, _)) = t.first_from(db::ENVELOPES, mailbox, mailbox)? {
                    t.del(db::ENVELOPES, &k)?;
                }
            } else {
                return Ok(Status::Quota);
            }
        }
        let seq = ib.next_seq;
        ib.next_seq += 1;
        put_inbox(t, mailbox, &ib)?;
        let key = cat(mailbox, &be(seq));
        t.put(db::ENVELOPES, &key, &cat(&be(now), env))?;
        if let Some(h) = hint {
            t.put(db::HINTS, &key, &cat(&be(now), &h[..24]))?;
        }
        Ok(Status::Ok)
    }

    /// After a stored envelope: counters and the owner's wake.
    fn stored(&mut self, mailbox: &[u8; 32], env: &[u8], now: u64) {
        #[cfg(feature = "test-hooks")]
        if self.hidden.0
            && let Ok(Some(ib)) = self
                .db
                .read(|r| r.get(db::INBOXES, mailbox))
                .map(|b| b.and_then(|b| Inbox::decode(&b)))
        {
            self.hidden
                .2
                .insert(cat(mailbox, &be(ib.next_seq.saturating_sub(1))));
        }
        self.stats.stored += 1;
        self.stored_lengths.insert(env.len());
        self.schedule_wake(mailbox, env, now);
    }

    fn write(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        if h.flags & FLAG_GROUP != 0 {
            return self.write_group(h, env, now);
        }
        let mb = h.mailbox;
        let th = token_hash(&h.token, &mb);
        let quota = self.cfg.inbox_quota;
        // The token burn and the stored envelope commit together: a crash
        // leaves both or neither, and a replay after a restart is refused.
        let status = self
            .tx(|t| {
                let Some(ib) = get_inbox(t, &mb)? else {
                    return Ok(Status::NotFound);
                };
                if ib.request || ib.group {
                    return Ok(Status::Denied);
                }
                if !t.del(db::TOKENS, &cat(&mb, &th))? {
                    return Ok(Status::Denied);
                }
                // The burned token's hash goes back to the owner with the
                // envelope: a session hint (`09-transport.md` §3.3).
                Self::store_in(t, &mb, env, now, quota, Some(&th))
            })
            .unwrap_or_else(|s| s);
        if status == Status::Ok {
            #[cfg(feature = "test-hooks")]
            self.token_log.1.push(th);
            self.stats.tokens_burned += 1;
            self.stored(&mb, env, now);
            if h.flags & api::FLAG_CALL != 0 {
                self.call_wake(&mb, env, now);
            }
        }
        status
    }

    /// A call is starting: wake the inbox's call token now, not in the
    /// next window (a call that rings a minute late has rung out).
    fn call_wake(&mut self, mailbox: &[u8; 32], env: &[u8], now: u64) {
        let Some(sealed) = self
            .db
            .read(|r| r.get(db::PUSH_CALL, mailbox))
            .ok()
            .flatten()
        else {
            return;
        };
        let id = sha3_512(&[&sealed[..], &now.to_be_bytes()].concat());
        let mut key = [0u8; 32];
        key.copy_from_slice(&id[..32]);
        let capsule = enclave_proto::envelope::capsule_of(env)
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|| {
                let mut r = vec![0u8; enclave_wire::CAPSULE_LEN];
                let _ = self.rng.fill("server/push-capsule", &mut r);
                r
            });
        self.wakes.insert(
            key,
            Wake {
                window: now / PUSH_WINDOW_SECS,
                release: now,
                sealed,
                capsule,
                sent: false,
            },
        );
    }

    fn write_group(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let owner_hash = api::credential_hash(&h.token);
        let read = api::credential_hash(&api::read_credential(&h.token));
        let mb = h.mailbox;
        let quota = self.cfg.inbox_quota;
        let status = self
            .tx(|t| {
                match get_inbox(t, &mb)? {
                    None => put_inbox(
                        t,
                        &mb,
                        &Inbox {
                            owner: owner_hash,
                            read,
                            request: false,
                            group: true,
                            next_seq: 1,
                            effort: 0,
                            until: 0,
                        },
                    )?,
                    Some(ib) if ib.group && ib.owner == owner_hash => {}
                    Some(_) => return Ok(Status::Denied),
                }
                Self::store_in(t, &mb, env, now, quota, None)
            })
            .unwrap_or_else(|s| s);
        if status == Status::Ok {
            self.stored(&mb, env, now);
        }
        status
    }

    fn write_request(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let invite = h.flags & FLAG_INVITE != 0;
        if !invite {
            // The server's effort, or more if the inbox's owner asked.
            let asked = self
                .db
                .read(|r| r.get(db::INBOXES, &h.mailbox))
                .ok()
                .flatten()
                .and_then(|b| Inbox::decode(&b))
                .map_or(0, |ib| ib.effort);
            let effort = self.cfg.effort_request.max(asked);
            let digest = sha3_512(env);
            let ctx = |d| api::pow_context_request(&h.mailbox, d, &digest);
            if !self.spend_pow(ctx, effort, &h.token, now) {
                return Status::Pow;
            }
        }
        let mb = h.mailbox;
        let th = api::cap_hash(&h.token, &mb);
        let quota = self.cfg.request_quota;
        let status = self
            .tx(|t| {
                let Some(ib) = get_inbox(t, &mb)? else {
                    return Ok(Status::NotFound);
                };
                if !ib.request {
                    return Ok(Status::Denied);
                }
                // An invite capability stands in for the proof of work.
                if invite && !t.del(db::TOKENS, &cat(&mb, &th))? {
                    return Ok(Status::Denied);
                }
                Self::store_in(t, &mb, env, now, quota, None)
            })
            .unwrap_or_else(|s| s);
        if status == Status::Ok {
            if invite {
                self.stats.tokens_burned += 1;
            }
            self.stored(&mb, env, now);
        }
        status
    }

    /// A user report about the account whose request inbox is `h.mailbox`
    /// (it must be one of ours). Costs a proof of work; the queue keeps the
    /// newest [`MAX_REPORTS`].
    fn report(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let digest = sha3_512(env);
        let ctx = |d| api::pow_context_report(&h.mailbox, d, &digest);
        if !self.spend_pow(ctx, self.cfg.effort_request, &h.token, now) {
            return Status::Pow;
        }
        let Ok(body) = api::unframe(env).and_then(api::ReportBody::decode) else {
            return Status::Malformed;
        };
        let mb = h.mailbox;
        self.tx(|t| {
            if !get_inbox(t, &mb)?.is_some_and(|ib| ib.request) {
                return Ok(Status::NotFound);
            }
            let all = t.scan(db::REPORTS, b"")?;
            let next = all.last().map_or(0, |(k, _)| head_u64(k) + 1);
            if all.len() >= MAX_REPORTS
                && let Some((k, _)) = all.first()
            {
                t.del(db::REPORTS, k)?;
            }
            let rec = [&be(now / 86_400)[..], &mb, &body.encode()].concat();
            t.put(db::REPORTS, &be(next), &rec)?;
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    /// Reports waiting for the operator, oldest first.
    pub fn reports(&self) -> Vec<Report> {
        self.db
            .read(|r| r.scan(db::REPORTS, b""))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, v)| {
                Some(Report {
                    day: head_u64(&v),
                    request_inbox: v.get(8..40)?.try_into().ok()?,
                    body: api::ReportBody::decode(v.get(40..)?).ok()?,
                })
            })
            .collect()
    }

    /// Reports waiting for the operator with their ids, oldest first.
    pub fn reports_by_id(&self) -> Vec<(u64, Report)> {
        self.db
            .read(|r| r.scan(db::REPORTS, b""))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v)| {
                Some((
                    head_u64(&k),
                    Report {
                        day: head_u64(&v),
                        request_inbox: v.get(8..40)?.try_into().ok()?,
                        body: api::ReportBody::decode(v.get(40..)?).ok()?,
                    },
                ))
            })
            .collect()
    }

    /// Check a report's signed quotes (`docs/13-operators.md` §2): for
    /// each, the text its author's device signed, or why it can't be
    /// confirmed. The device must be in the reported account's manifest
    /// held here, and that manifest must list the reported request inbox.
    pub fn verify_quotes(&self, r: &Report) -> Vec<std::result::Result<String, &'static str>> {
        let Some(root) = r.body.reported else {
            return Vec::new();
        };
        let manifest = self
            .db
            .read(|t| t.get(db::MANIFESTS, &manifest_key(&root)))
            .ok()
            .flatten()
            .and_then(|v| SignedManifest::from_bytes(tail(&v)).ok())
            .and_then(|sm| Manifest::decode(&sm.body).ok())
            .filter(|m| m.root.0 == root);
        r.body
            .signed
            .iter()
            .map(|q| {
                let m = manifest
                    .as_ref()
                    .ok_or("the reported account's manifest isn't on this server")?;
                if m.request_inbox.as_slice() != r.request_inbox {
                    return Err("that account's manifest doesn't list this request inbox");
                }
                let d = m
                    .devices
                    .iter()
                    .find(|d| d.id == q.device)
                    .ok_or("signed by a device that isn't in the account's manifest")?;
                let conv = otr::conv_id_of(&otr::root_hash(&root), &q.recipient);
                let payload =
                    otr::message_payload_of(&conv, &q.device, &q.recipient, q.counter, &q.content);
                otr::verify(&d.signing, otr::Kind::Message, &payload, &q.sig)
                    .map_err(|_| "the signature doesn't verify")?;
                api::quoted_text(&q.content).ok_or("signed, but not a text message")
            })
            .collect()
    }

    /// Forget report `id` (the operator dealt with it). Whether it existed.
    pub fn dismiss_report(&mut self, id: u64) -> bool {
        self.tx(|t| t.del(db::REPORTS, &be(id))).unwrap_or(false)
    }

    /// Hand the waiting reports to the operator and forget them here.
    pub fn take_reports(&mut self) -> Vec<Report> {
        let out = self.reports();
        let _ = self.tx(|t| t.remove_where(db::REPORTS, b"", |_, _| true));
        out
    }

    /// Operator action on a report: close the account's request inbox, so
    /// nobody can send it new requests and it can't receive replies to them.
    /// Returns whether it existed.
    pub fn disable_request_inbox(&mut self, request_inbox: &[u8; 32]) -> bool {
        let mb = *request_inbox;
        self.tx(|t| {
            if !get_inbox(t, &mb)?.is_some_and(|ib| ib.request) {
                return Ok(false);
            }
            t.del(db::INBOXES, &mb)?;
            t.remove_where(db::ENVELOPES, &mb, |_, _| true)?;
            t.remove_where(db::HINTS, &mb, |_, _| true)?;
            t.remove_where(db::TOKENS, &mb, |_, _| true)?;
            Ok(true)
        })
        .unwrap_or(false)
    }

    /// The inbox, if `h` carries its read credential: the static one, or
    /// a daily one for yesterday, today or tomorrow (clocks disagree).
    fn check_read(&self, h: &RequestHeader, now: u64) -> Option<Inbox> {
        let hash = api::credential_hash(&h.token[..24]);
        let today = api::day_of(now);
        self.db
            .read(|r| {
                let Some(ib) = r
                    .get(db::INBOXES, &h.mailbox)?
                    .and_then(|b| Inbox::decode(&b))
                else {
                    return Ok(None);
                };
                if ib.read != [0; 32] {
                    return Ok((hash == ib.read).then_some(ib));
                }
                for d in today.saturating_sub(1)..=today.saturating_add(1) {
                    let key = cat(&h.mailbox, &d.to_be_bytes());
                    if r.get(db::READ_CREDS, &key)?.is_some_and(|v| v == hash) {
                        return Ok(Some(ib));
                    }
                }
                Ok(None)
            })
            .ok()?
    }

    fn poll(&mut self, h: &RequestHeader, now: u64) -> (Status, u8, [u8; 32], Reply) {
        let none = [0u8; 32];
        if self.check_read(h, now).is_none() {
            return (Status::Denied, 0, none, Reply::Empty);
        }
        let mut cursor = [0u8; 8];
        cursor.copy_from_slice(&h.token[24..]);
        let from = cat(
            &h.mailbox,
            &be(u64::from_be_bytes(cursor).saturating_add(1)),
        );
        let next = match self.db.read(|r| {
            let next = r.next_two(db::ENVELOPES, &h.mailbox, &from)?;
            #[cfg(feature = "test-hooks")]
            let next = self.skip_hidden(r, &h.mailbox, next)?;
            let hint = match next.first() {
                Some((k, _)) => r.get(db::HINTS, k)?,
                None => None,
            };
            Ok((next, hint))
        }) {
            Ok(n) => n,
            Err(e) => {
                log_db_error(&e);
                return (Status::Unavailable, 0, none, Reply::Empty);
            }
        };
        let (next, hint) = next;
        match next.first() {
            Some((k, v)) => {
                let more = if next.len() > 1 { FLAG_MORE } else { 0 };
                let mut tok = [0u8; 32];
                if let Some(hint) = hint.as_deref().map(tail).filter(|h| h.len() == 24) {
                    tok[..24].copy_from_slice(hint);
                }
                tok[24..].copy_from_slice(&k[32..40]);
                (
                    Status::Ok,
                    FLAG_FOUND | more,
                    tok,
                    Reply::Envelope(tail(v).to_vec()),
                )
            }
            None => (Status::Ok, 0, none, Reply::Empty),
        }
    }

    /// Past the marked envelopes while they are hidden (test hook).
    #[cfg(feature = "test-hooks")]
    fn skip_hidden(
        &self,
        r: &db::Rx<'_>,
        mailbox: &[u8; 32],
        mut next: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> db::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        while self.hidden.1
            && let Some((k, _)) = next.first()
            && self.hidden.2.contains(k)
        {
            let from = cat(mailbox, &be(head_u64(&k[32..]).saturating_add(1)));
            next = r.next_two(db::ENVELOPES, mailbox, &from)?;
        }
        Ok(next)
    }

    fn ack(&mut self, h: &RequestHeader, now: u64) -> Status {
        if self.check_read(h, now).is_none() {
            return Status::Denied;
        }
        let mut w = [0u8; 8];
        w.copy_from_slice(&h.token[24..]);
        let watermark = u64::from_be_bytes(w);
        let mb = h.mailbox;
        let acked = |k: &[u8], _: &[u8]| {
            k.get(32..40)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_be_bytes)
                .is_some_and(|seq| seq <= watermark)
        };
        self.tx(|t| {
            t.remove_where(db::ENVELOPES, &mb, acked)?;
            t.remove_where(db::HINTS, &mb, acked)?;
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    /// Upload a chunk under an allocation (`BlobAlloc`): the token field
    /// is the allocation's secret, good for [`api::ALLOC_CHUNKS`] uploads
    /// for a day.
    fn blob_put(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let alloc = alloc_key(&h.token);
        let id = h.mailbox;
        let s = self
            .tx(|t| {
                // No allocation, or a used-up one: `Quota` (`Denied` means
                // the chunk id is taken).
                let Some(a) = t.get(db::ALLOCS, &alloc)? else {
                    return Ok(Status::Quota);
                };
                let (expires, left) = (
                    head_u64(&a),
                    a.get(8..12)
                        .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or_default())),
                );
                if expires < now || left == 0 {
                    t.del(db::ALLOCS, &alloc)?;
                    return Ok(Status::Quota);
                }
                if t.has(db::BLOBS, &id)? {
                    return Ok(Status::Denied);
                }
                t.put(db::BLOBS, &id, &cat(&be(now), env))?;
                t.put(
                    db::ALLOCS,
                    &alloc,
                    &cat(&be(expires), &(left - 1).to_be_bytes()),
                )?;
                Ok(Status::Ok)
            })
            .unwrap_or_else(|s| s);
        if s == Status::Ok {
            self.stored_lengths.insert(env.len());
        }
        s
    }

    /// Issue blob tokens to an inbox's owner, or turn one into an
    /// allocation (`docs/09-transport.md` §9).
    fn blob_alloc(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> (Status, Reply) {
        use enclave_tokens::privpass::{IssuerKey, Token, blob_challenge};
        let Ok(req) = api::unframe(env).and_then(api::BlobAlloc::decode) else {
            return (Status::Malformed, Reply::Empty);
        };
        match req {
            api::BlobAlloc::Key => {
                let epoch = api::issuer_epoch(now);
                match IssuerKey::derive(&self.blob_seed, epoch) {
                    Ok(key) => {
                        let reply = api::BlobAllocReply::Issued {
                            epoch,
                            public: key.public().0,
                            responses: Vec::new(),
                        };
                        (Status::Ok, Reply::Payload(reply.encode()))
                    }
                    Err(_) => (Status::Unavailable, Reply::Empty),
                }
            }
            api::BlobAlloc::Issue(reqs) => {
                let epoch = api::issuer_epoch(now);
                let Ok(key) = IssuerKey::derive(&self.blob_seed, epoch) else {
                    return (Status::Unavailable, Reply::Empty);
                };
                let mut responses = Vec::with_capacity(reqs.len());
                for q in &reqs {
                    match key.issue(q, &mut self.rng) {
                        Ok(r) => match r.try_into() {
                            Ok(r) => responses.push(r),
                            Err(_) => return (Status::Malformed, Reply::Empty),
                        },
                        Err(_) => return (Status::Malformed, Reply::Empty),
                    }
                }
                // Counted against the inbox only once every request is good.
                let owner = api::credential_hash(&h.token);
                let mb = h.mailbox;
                let n = reqs.len() as u32;
                let quota = self.cfg.blob_tokens_per_day;
                let key_day = cat(&mb, &api::day_of(now).to_be_bytes());
                let s = self
                    .tx(|t| {
                        match get_inbox(t, &mb)? {
                            Some(ib) if ib.owner == owner && !ib.group => {}
                            Some(_) => return Ok(Status::Denied),
                            None => return Ok(Status::NotFound),
                        }
                        let used = t
                            .get(db::BLOB_ISSUED, &key_day)?
                            .and_then(|v| v.try_into().ok())
                            .map_or(0, u32::from_be_bytes);
                        if used.saturating_add(n) > quota {
                            return Ok(Status::Quota);
                        }
                        t.put(db::BLOB_ISSUED, &key_day, &(used + n).to_be_bytes())?;
                        Ok(Status::Ok)
                    })
                    .unwrap_or_else(|s| s);
                if s != Status::Ok {
                    return (s, Reply::Empty);
                }
                let reply = api::BlobAllocReply::Issued {
                    epoch,
                    public: key.public().0,
                    responses,
                };
                (Status::Ok, Reply::Payload(reply.encode()))
            }
            api::BlobAlloc::Redeem(b) => {
                let Ok(token) = Token::decode(&b) else {
                    return (Status::Malformed, Reply::Empty);
                };
                let Ok(digest) = blob_challenge(&self.cfg.id).digest() else {
                    return (Status::Unavailable, Reply::Empty);
                };
                // This month's key, or last month's for a token kept over.
                let e = api::issuer_epoch(now);
                let good = [e, e.saturating_sub(1)].into_iter().find(|&epoch| {
                    IssuerKey::derive(&self.blob_seed, epoch)
                        .is_ok_and(|k| k.verify(&token, &digest))
                });
                let Some(epoch) = good else {
                    return (Status::Denied, Reply::Empty);
                };
                let spent = alloc_key(&cat(&token.nonce, &token.key_id));
                let Ok(alloc) = self.rng.array::<32>("server/blob-alloc") else {
                    return (Status::Unavailable, Reply::Empty);
                };
                let s = self
                    .tx(|t| {
                        if t.has(db::BLOB_SPENT, &spent)? {
                            return Ok(Status::Denied);
                        }
                        t.put(db::BLOB_SPENT, &spent, &epoch.to_be_bytes())?;
                        let v = cat(&be(now + api::ALLOC_SECS), &api::ALLOC_CHUNKS.to_be_bytes());
                        t.put(db::ALLOCS, &alloc_key(&alloc), &v)?;
                        Ok(Status::Ok)
                    })
                    .unwrap_or_else(|s| s);
                if s != Status::Ok {
                    return (s, Reply::Empty);
                }
                let reply = api::BlobAllocReply::Allocated {
                    alloc,
                    chunks: api::ALLOC_CHUNKS,
                };
                (Status::Ok, Reply::Payload(reply.encode()))
            }
        }
    }

    fn directory(&mut self, req: DirRequest, now: u64) -> (Status, Reply) {
        match (req.kind, req.action) {
            // Served from what the operator set, never uploaded.
            (DirKind::Descriptor | DirKind::ServerList, DirAction::Put) => {
                (Status::Denied, Reply::Empty)
            }
            (_, DirAction::Put) => self.dir_put(req, now),
            (DirKind::Manifest, DirAction::Get) => {
                let got = self.db.read(|r| {
                    if r.get(db::MIGRATIONS, &req.key)?.is_some() {
                        return Ok(None);
                    }
                    r.get(db::MANIFESTS, &req.key)
                });
                self.stored_reply(got, req.index, |v| tail(v))
            }
            (DirKind::Migration, DirAction::Get) => {
                let got = self.db.read(|r| r.get(db::MIGRATIONS, &req.key));
                self.stored_reply(got, req.index, |v| v)
            }
            (DirKind::Moved, DirAction::Get) => {
                let got = self.db.read(|r| r.get(db::SERVER_MOVES, &req.key));
                self.stored_reply(got, req.index, |v| v)
            }
            (DirKind::Tombstone, DirAction::Get) => {
                let got = self.db.read(|r| r.get(db::TOMBSTONES, &req.key));
                self.stored_reply(got, req.index, |v| v)
            }
            (DirKind::Equivocation, DirAction::Get) => {
                let got = self.db.read(|r| r.get(db::EQUIVOCATIONS, &req.key));
                self.stored_reply(got, req.index, |v| v)
            }
            (DirKind::Vault, DirAction::Get) => {
                let got = self.db.read(|r| r.get(db::VAULTS, &req.key));
                self.stored_reply(got, req.index, |v| v.get(32..).unwrap_or_default())
            }
            (DirKind::Bundle, DirAction::Claim) => self.claim_bundle(&req, now),
            (DirKind::Bundle, DirAction::Get) => match self.claims.get(&req.key) {
                Some((bytes, _)) => Self::chunk_reply(bytes, req.index, req.key),
                None => (Status::NotFound, Reply::Empty),
            },
            (DirKind::Attest, DirAction::Get) => {
                let got = self.db.read(|r| r.get(db::ATTESTATIONS, &req.key));
                match got {
                    Ok(Some(v)) => Self::chunk_reply(
                        &enclave_proto::attest::encode_list(&decode_blobs(&v)),
                        req.index,
                        [0; 32],
                    ),
                    other => self.stored_reply(other, req.index, |v| v),
                }
            }
            (DirKind::Username, DirAction::Get) if req.index == 0 => {
                self.lookup_username(&req, now)
            }
            (DirKind::Username, DirAction::Get) => match self.kt_replies.get(&req.key) {
                Some((bytes, _)) => Self::chunk_reply(bytes, req.index, req.key),
                None => (Status::NotFound, Reply::Empty),
            },
            (DirKind::Descriptor, DirAction::Get) if !self.descriptor.is_empty() => {
                Self::chunk_reply(&self.descriptor, req.index, [0; 32])
            }
            (DirKind::ServerList, DirAction::Get) if !self.server_list.is_empty() => {
                Self::chunk_reply(&self.server_list, req.index, [0; 32])
            }
            (DirKind::Update, DirAction::Get) if !self.update_bundle.is_empty() => {
                Self::chunk_reply(&self.update_bundle, req.index, [0; 32])
            }
            (DirKind::Descriptor | DirKind::ServerList | DirKind::Update, DirAction::Get) => {
                (Status::NotFound, Reply::Empty)
            }
            _ => (Status::Malformed, Reply::Empty),
        }
    }

    /// Chunk `index` of a stored object (after `view` strips its header).
    fn stored_reply(
        &self,
        got: db::Result<Option<Vec<u8>>>,
        index: u32,
        view: impl Fn(&[u8]) -> &[u8],
    ) -> (Status, Reply) {
        match got {
            Ok(Some(v)) => Self::chunk_reply(view(&v), index, [0; 32]),
            Ok(None) => (Status::NotFound, Reply::Empty),
            Err(e) => {
                log_db_error(&e);
                (Status::Unavailable, Reply::Empty)
            }
        }
    }

    fn chunk_reply(bytes: &[u8], index: u32, claim: [u8; 32]) -> (Status, Reply) {
        let chunks = api::chunks(bytes);
        match chunks.get(index as usize) {
            Some(c) => (
                Status::Ok,
                Reply::Payload(
                    DirReply {
                        total: chunks.len() as u32,
                        claim,
                        data: c.to_vec(),
                    }
                    .encode(),
                ),
            ),
            None => (Status::NotFound, Reply::Empty),
        }
    }

    fn claim_bundle(&mut self, req: &DirRequest, now: u64) -> (Status, Reply) {
        let ctx = |d| api::pow_context_claim(&req.key, d);
        if !self.spend_pow(ctx, self.cfg.effort_claim, &req.proof, now) {
            return (Status::Pow, Reply::Empty);
        }
        let device = req.key[..16].to_vec();
        // Each one-time prekey is served once: the pointer moves in the same
        // transaction that reads it.
        let bundle = self.tx(|t| {
            let Some(v) = t.get(db::BUNDLES, &device)? else {
                return Ok(None);
            };
            let Ok(p) = Publication::decode(tail(&v)) else {
                return Ok(None);
            };
            let next = head_u64(&v) as usize;
            let opk = if next < p.opks.len() {
                t.put(db::BUNDLES, &device, &cat(&be(next as u64 + 1), tail(&v)))?;
                Some((p.batch.clone(), p.opks[next].clone()))
            } else {
                None
            };
            Ok(Some(Bundle {
                spk: p.spk.clone(),
                opk,
                last_resort: p.last_resort.clone(),
            }))
        });
        let bundle = match bundle {
            Ok(Some(b)) => b,
            Ok(None) => return (Status::NotFound, Reply::Empty),
            Err(s) => return (s, Reply::Empty),
        };
        let bytes = bundle.encode();
        let claim: [u8; 32] = match self.rng.array("server/claim-id") {
            Ok(c) => c,
            Err(_) => return (Status::Malformed, Reply::Empty),
        };
        self.claims.insert(claim, (bytes.clone(), now));
        Self::chunk_reply(&bytes, 0, claim)
    }

    fn dir_put(&mut self, req: DirRequest, now: u64) -> (Status, Reply) {
        if req.total == 0 || req.total > 200 || req.index >= req.total {
            return (Status::Malformed, Reply::Empty);
        }
        let slot = (req.kind as u8, req.key);
        let up = self.uploads.entry(slot).or_default();
        if up.total != 0 && up.total != req.total {
            self.uploads.remove(&slot);
            return (Status::Malformed, Reply::Empty);
        }
        if up.total == 0 {
            up.started = now;
        }
        up.total = req.total;
        up.chunks.insert(req.index, req.data);
        if up.chunks.len() < up.total as usize {
            return (Status::Ok, Reply::Empty);
        }
        let Some(up) = self.uploads.remove(&slot) else {
            return (Status::Malformed, Reply::Empty);
        };
        let object: Vec<u8> = up.chunks.into_values().flatten().collect();
        let status = match req.kind {
            DirKind::Manifest => self.accept_manifest(&req.key, object, now),
            DirKind::Bundle => self.accept_publication(&req.key, object, now),
            DirKind::Vault => self.accept_vault(&req.key, &req.proof, object),
            DirKind::Username => self.accept_username(&req.key, &req.proof, &object, now),
            DirKind::Attest => self.accept_attestation(&req.key, object),
            DirKind::Migration => self.accept_migration(&req.key, &object, now),
            DirKind::Moved => self.accept_server_move(&req.key, &object, now),
            DirKind::Tombstone => self.accept_tombstone(&req.key, &object, now),
            DirKind::Equivocation => self.accept_equivocation(&req.key, &object),
            DirKind::Descriptor | DirKind::ServerList | DirKind::Update => Status::Denied,
        };
        if status == Status::Ok
            && matches!(
                req.kind,
                DirKind::Manifest | DirKind::Attest | DirKind::Migration | DirKind::Tombstone
            )
        {
            self.commit_account(Some(req.key), now);
        }
        (status, Reply::Empty)
    }

    /// A proof that a log equivocated (`12-servers.md` §3.8): for this
    /// server's own log or one the server list names, keyed by its server
    /// id, both heads signed with its head key. Kept (the first per log) and
    /// queued for the witnesses.
    fn accept_equivocation(&mut self, key: &[u8; 32], object: &[u8]) -> Status {
        let Ok(e) = enclave_kt::Equivocation::decode(object) else {
            return Status::Malformed;
        };
        if key[..16] != e.server() || key[16..] != [0; 16] {
            return Status::Invalid;
        }
        let head_key = match self.kt_info() {
            Some(i) if i.server == e.server() => Some(i.head_key),
            _ => self.listed_logs.get(&e.server()).cloned(),
        };
        let Some(head_key) = head_key else {
            return Status::NotFound;
        };
        if e.verify(&head_key).is_err() {
            return Status::Invalid;
        }
        let bytes = e.encode();
        let new = self.tx(|t| {
            if t.has(db::EQUIVOCATIONS, key)? {
                return Ok(false);
            }
            t.put(db::EQUIVOCATIONS, key, &bytes)?;
            Ok(true)
        });
        match new {
            Ok(true) => {
                self.equivocations_out.push(e);
                Status::Ok
            }
            Ok(false) => Status::Ok,
            Err(s) => s,
        }
    }

    fn lookup_username(&mut self, req: &DirRequest, now: u64) -> (Status, Reply) {
        let Some(kt) = self.kt_lookups() else {
            return (Status::NotFound, Reply::Empty);
        };
        let found = if req.key == api::DESCRIPTOR_LOOKUP_KEY {
            kt.lookup_descriptor(now)
        } else if req.key[0] == api::ACCOUNT_LOOKUP_TAG {
            let Ok(t) = <[u8; 31]>::try_from(&req.key[1..]) else {
                return (Status::Malformed, Reply::Empty);
            };
            // Records the log hasn't taken yet go in first.
            if self.kt_accounts.1 || !self.kt_accounts.0.is_empty() {
                self.commit_account(None, now);
            }
            let Some(kt) = self.kt_lookups() else {
                return (Status::NotFound, Reply::Empty);
            };
            kt.lookup_account(&t, now)
        } else {
            let Some(name) = api::key_name(&req.key) else {
                return (Status::Malformed, Reply::Empty);
            };
            kt.lookup_name(&name, now)
        };
        let Ok(bytes) = found else {
            return (Status::NotFound, Reply::Empty);
        };
        let Ok(id) = self.rng.array::<32>("server/kt-reply-id") else {
            return (Status::Malformed, Reply::Empty);
        };
        let r = Self::chunk_reply(&bytes, 0, id);
        self.kt_replies.insert(id, (bytes, now));
        r
    }

    /// Bind a username to an account. The claim must carry proof of work, be
    /// signed by a device in the account's root-signed manifest held here, be
    /// fresh, and not take a name another account holds. One name per
    /// account: claiming a new one publishes a tombstone (the bare root) for
    /// the old, which stays reserved for the same account.
    fn accept_username(
        &mut self,
        key: &[u8; 32],
        proof: &[u8; 32],
        object: &[u8],
        now: u64,
    ) -> Status {
        if self.kt.is_none() {
            return Status::NotFound;
        }
        let ctx = |d| api::pow_context_username(key, d);
        if !self.spend_pow(ctx, self.cfg.effort_username, proof, now) {
            return Status::Pow;
        }
        let Some(kt) = &self.kt else {
            return Status::NotFound;
        };
        let Ok(claim) = UsernameClaim::decode(object) else {
            return Status::Malformed;
        };
        let (Some(keyed), Ok(name)) = (
            api::key_name(key),
            enclave_kt::username::normalize(&claim.name),
        ) else {
            return Status::Invalid;
        };
        if keyed != claim.name || claim.name != name || claim.time.abs_diff(now) > 3600 {
            return Status::Invalid;
        }
        let Some(root) = claim.root() else {
            return Status::Malformed;
        };
        let mbytes = match self.db.read(|r| r.get(db::MANIFESTS, &manifest_key(&root))) {
            Ok(Some(v)) => v,
            Ok(None) => return Status::NotFound,
            Err(e) => {
                log_db_error(&e);
                return Status::Unavailable;
            }
        };
        let Some(m) = SignedManifest::from_bytes(tail(&mbytes))
            .ok()
            .and_then(|sm| Manifest::decode(&sm.body).ok())
        else {
            return Status::Invalid;
        };
        let msg = UsernameClaim::message(&self.cfg.id, &claim.name, &claim.value, claim.time);
        let signed = m.devices.iter().any(|d| {
            d.id == claim.device
                && d.signing
                    .verify(enclave_kt::wire::CTX_CLAIM, &msg, &claim.signature)
                    .is_ok()
        });
        if !signed {
            return Status::Invalid;
        }
        let state = self.db.read(|r| {
            let holder = r.get(db::USERNAMES, name.as_bytes())?;
            let moved = match &holder {
                Some(h) => r.get(db::MOVED, &h[..64.min(h.len())])?,
                None => None,
            };
            let old = r.get(db::NAMES_BY_ROOT, &root)?;
            Ok((holder, moved, old))
        });
        let (holder, moved_to, old) = match state {
            Ok(s) => s,
            Err(e) => {
                log_db_error(&e);
                return Status::Unavailable;
            }
        };
        let mut drop_owner = None;
        if let Some(h) = &holder {
            let owner: [u8; 64] = match h.get(..64).and_then(|o| o.try_into().ok()) {
                Some(o) => o,
                None => return Status::Invalid,
            };
            let last = head_u64(&h[64..]);
            // The owner changed their recovery words: the name moves along.
            let moved = moved_to.as_deref() == Some(&root[..]);
            if owner != root && !moved {
                return Status::Denied;
            }
            if moved {
                drop_owner = Some(owner);
            } else if last >= claim.time {
                return Status::Invalid;
            }
        }
        let old = old.and_then(|o| String::from_utf8(o).ok());
        if let Some(old) = &old
            && *old != name
            && kt.publish(old, root.to_vec(), now).is_err()
        {
            return Status::Invalid;
        }
        if kt.publish(&name, claim.value.clone(), now).is_err() {
            return Status::Denied;
        }
        let time = claim.time;
        self.tx(|t| {
            if let Some(o) = drop_owner {
                t.del(db::NAMES_BY_ROOT, &o)?;
            }
            t.put(db::USERNAMES, name.as_bytes(), &cat(&root, &be(time)))?;
            t.put(db::NAMES_BY_ROOT, &root, name.as_bytes())?;
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    /// Keep a device attestation if a device the account has ever listed
    /// signed it. At most 16 per account, newest last.
    fn accept_attestation(&mut self, key: &[u8; 32], bytes: Vec<u8>) -> Status {
        let Ok(a) = enclave_proto::attest::Attestation::decode(&bytes) else {
            return Status::Malformed;
        };
        let key = *key;
        self.tx(|t| {
            let seen = decode_seen(&t.get(db::DEVICES_SEEN, &key)?.unwrap_or_default());
            if !seen
                .iter()
                .any(|s| s.id == a.device && a.verify_key(&s.root, &s.key))
            {
                return Ok(Status::Invalid);
            }
            let mut list = decode_blobs(&t.get(db::ATTESTATIONS, &key)?.unwrap_or_default());
            if !list.contains(&bytes) {
                list.push(bytes);
                if list.len() > 16 {
                    list.remove(0);
                }
                t.put(db::ATTESTATIONS, &key, &encode_blobs(&list))?;
            }
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    /// Keep a change of recovery words: both roots signed it, and the new
    /// root's manifest (already stored) is the one it names. From then on
    /// the old root can't publish a manifest here.
    fn accept_migration(&mut self, key: &[u8; 32], bytes: &[u8], now: u64) -> Status {
        let Ok(mig) = enclave_proto::migration::Migration::decode(bytes) else {
            return Status::Malformed;
        };
        if &manifest_key(&mig.old.0) != key || !mig.cross_signed() {
            return Status::Invalid;
        }
        let key = *key;
        self.tx(|t| {
            let Some(v) = t.get(db::MANIFESTS, &manifest_key(&mig.new.0))? else {
                return Ok(Status::NotFound);
            };
            let Ok(sm) = SignedManifest::from_bytes(tail(&v)) else {
                return Ok(Status::Invalid);
            };
            if mig.verify(&sm, now).is_err() || t.has(db::MIGRATIONS, &key)? {
                return Ok(Status::Invalid);
            }
            t.put(db::MIGRATIONS, &key, bytes)?;
            t.put(db::MOVED, &mig.old.0, &mig.new.0)?;
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    /// Where an account of this server went (`12-servers.md` §4.4): signed
    /// by the root of a manifest held here, leaving this server, recent,
    /// and newer than any move already recorded.
    fn accept_server_move(&mut self, key: &[u8; 32], bytes: &[u8], now: u64) -> Status {
        let Ok(m) = enclave_proto::server_move::ServerMove::decode(bytes) else {
            return Status::Malformed;
        };
        if &manifest_key(&m.root.0) != key
            || m.from != self.cfg.id
            || m.time.abs_diff(now) > 86_400
            || m.verify().is_err()
        {
            return Status::Invalid;
        }
        let key = *key;
        self.tx(|t| {
            if !t.has(db::MANIFESTS, &key)? {
                return Ok(Status::NotFound);
            }
            if let Some(old) = t.get(db::SERVER_MOVES, &key)?
                && enclave_proto::server_move::ServerMove::decode(&old)
                    .is_ok_and(|o| o.time >= m.time)
            {
                return Ok(Status::Invalid);
            }
            t.put(db::SERVER_MOVES, &key, bytes)?;
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    /// An account's deletion (`03-identity.md` §8.5), signed by its root:
    /// its username is withdrawn for good (a tombstone in the log), its
    /// manifest and its devices' prekeys go, and no manifest for that root
    /// is taken again. Inboxes, the vault key and blobs are deleted by
    /// their owners' credentials, as always.
    fn accept_tombstone(&mut self, key: &[u8; 32], bytes: &[u8], now: u64) -> Status {
        let Ok(t) = enclave_proto::tombstone::Tombstone::decode(bytes) else {
            return Status::Malformed;
        };
        if &manifest_key(&t.root.0) != key || t.time.abs_diff(now) > 86_400 || t.verify().is_err() {
            return Status::Invalid;
        }
        let key = *key;
        let root = t.root.0;
        let state = self.db.read(|r| {
            Ok((
                r.get(db::TOMBSTONES, &key)?.is_some(),
                r.get(db::MANIFESTS, &key)?,
                r.get(db::NAMES_BY_ROOT, &root)?,
            ))
        });
        let (done, manifest, name) = match state {
            Ok(s) => s,
            Err(e) => {
                log_db_error(&e);
                return Status::Unavailable;
            }
        };
        if done {
            return Status::Ok;
        }
        let Some(manifest) = manifest else {
            return Status::NotFound;
        };
        let devices: Vec<[u8; 16]> = SignedManifest::from_bytes(tail(&manifest))
            .ok()
            .and_then(|sm| Manifest::decode(&sm.body).ok())
            .map(|m| m.devices.iter().map(|d| d.id).collect())
            .unwrap_or_default();
        let name = name.and_then(|n| String::from_utf8(n).ok());
        if let Some(n) = &name
            && self
                .withdraw_in_log(n, enclave_kt::username::Withdrawn::Deleted, now)
                .is_err()
        {
            return Status::Unavailable;
        }
        self.tx(|tx| {
            tx.put(db::TOMBSTONES, &key, bytes)?;
            tx.del(db::MANIFESTS, &key)?;
            tx.del(db::ATTESTATIONS, &key)?;
            tx.del(db::DEVICES_SEEN, &key)?;
            for d in &devices {
                tx.del(db::BUNDLES, d)?;
                tx.del(db::DEVICE_OWNER, d)?;
            }
            tx.del(db::NAMES_BY_ROOT, &root)?;
            if let Some(n) = &name {
                tx.put(db::USERNAMES, n.as_bytes(), &cat(&WITHDRAWN, &be(now)))?;
            }
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    /// Publish a tombstone for `name` in the key-transparency log.
    fn withdraw_in_log(
        &self,
        name: &str,
        why: enclave_kt::username::Withdrawn,
        now: u64,
    ) -> Result<(), KtError> {
        let kt = self.kt.as_ref().ok_or(KtError::Stopped)?;
        kt.publish(name, enclave_kt::username::tombstone(why), now)
            .map(|_| ())
    }

    /// The operator withdraws `name` for breaking its policy
    /// (`13-operators.md` §1): its log entry becomes a tombstone, its holder
    /// loses it, and nobody can claim it again. Doing it again changes
    /// nothing.
    pub fn withdraw_username(&mut self, name: &str, now: u64) -> Result<bool, KtError> {
        let name = enclave_kt::username::normalize(name)?;
        let holder = self
            .db
            .read(|r| r.get(db::USERNAMES, name.as_bytes()))
            .map_err(|e| KtError::Directory(e.to_string()))?;
        if holder.as_deref().is_some_and(|h| h.starts_with(&WITHDRAWN)) {
            return Ok(false);
        }
        self.withdraw_in_log(&name, enclave_kt::username::Withdrawn::ByOperator, now)?;
        let owner = holder.and_then(|h| h.get(..64).map(<[u8]>::to_vec));
        self.tx(|t| {
            if let Some(o) = &owner {
                t.del(db::NAMES_BY_ROOT, o)?;
            }
            t.put(db::USERNAMES, name.as_bytes(), &cat(&WITHDRAWN, &be(now)))?;
            Ok(Status::Ok)
        })
        .map_err(|s| KtError::Directory(format!("{s:?}")))?;
        Ok(true)
    }

    fn accept_manifest(&mut self, key: &[u8; 32], bytes: Vec<u8>, now: u64) -> Status {
        let Ok(sm) = SignedManifest::from_bytes(&bytes) else {
            return Status::Malformed;
        };
        let Ok(m) = Manifest::decode(&sm.body) else {
            return Status::Malformed;
        };
        if &manifest_key(&m.root.0) != key {
            return Status::Invalid;
        }
        if sm.verify(&m.root, now).is_err() {
            return Status::Invalid;
        }
        let key = *key;
        self.tx(|t| {
            if t.has(db::MIGRATIONS, &key)? || t.has(db::TOMBSTONES, &key)? {
                return Ok(Status::Denied);
            }
            if let Some(v) = t.get(db::MANIFESTS, &key)?
                && m.version <= head_u64(&v)
            {
                return Ok(Status::Invalid);
            }
            let mut seen = decode_seen(&t.get(db::DEVICES_SEEN, &key)?.unwrap_or_default());
            for d in &m.devices {
                if !seen.iter().any(|s| s.id == d.id) && seen.len() < 256 {
                    seen.push(SeenDevice {
                        root: m.root.0,
                        id: d.id,
                        key: d.signing.clone(),
                    });
                }
                // Which account a device belongs to, for its publications.
                t.put(db::DEVICE_OWNER, &d.id, &key)?;
            }
            t.put(db::DEVICES_SEEN, &key, &encode_seen(&seen))?;
            t.put(db::MANIFESTS, &key, &cat(&be(m.version), &bytes))?;
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    fn accept_publication(&mut self, key: &[u8; 32], bytes: Vec<u8>, now: u64) -> Status {
        let Ok(p) = Publication::decode(&bytes) else {
            return Status::Malformed;
        };
        // The device must appear in a stored manifest, and sign the publication.
        let device = p.spk.device;
        if device_key(&device) != *key {
            return Status::Invalid;
        }
        let signer = self.db.read(|r| {
            let Some(owner) = r.get(db::DEVICE_OWNER, &device)? else {
                return Ok(None);
            };
            let Some(v) = r.get(db::MANIFESTS, &owner)? else {
                return Ok(None);
            };
            Ok(SignedManifest::from_bytes(tail(&v))
                .ok()
                .and_then(|sm| Manifest::decode(&sm.body).ok())
                .and_then(|m| {
                    m.device(&device)
                        .map(|d| (d.signing.clone(), m.bundle_epoch))
                }))
        });
        let (signer, bundle_epoch) = match signer {
            Ok(Some(s)) => s,
            Ok(None) => return Status::NotFound,
            Err(e) => {
                log_db_error(&e);
                return Status::Unavailable;
            }
        };
        // Signed for the stored manifest's bundle epoch (RT-05).
        if p.verify(&signer, bundle_epoch, now).is_err() {
            return Status::Invalid;
        }
        self.tx(|t| {
            t.put(db::BUNDLES, &device, &cat(&be(0), &bytes))?;
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }

    fn accept_vault(&mut self, key: &[u8; 32], owner_secret: &[u8; 32], bytes: Vec<u8>) -> Status {
        let owner = api::credential_hash(owner_secret);
        let key = *key;
        self.tx(|t| {
            if let Some(v) = t.get(db::VAULTS, &key)?
                && v.get(..32) != Some(&owner[..])
            {
                return Ok(Status::Denied);
            }
            if bytes == api::VAULT_DELETE {
                t.del(db::VAULTS, &key)?;
                return Ok(Status::Ok);
            }
            t.put(db::VAULTS, &key, &cat(&owner, &bytes))?;
            Ok(Status::Ok)
        })
        .unwrap_or_else(|s| s)
    }
}

/// Storage errors go to the operator's log, never to clients.
fn log_db_error(e: &db::DbError) {
    eprintln!("enclave-server: {e}");
}

#[derive(Clone)]
enum Reply {
    Envelope(Vec<u8>),
    Payload(Vec<u8>),
    Empty,
}

impl Reply {
    fn len(&self) -> usize {
        match self {
            Reply::Envelope(b) | Reply::Payload(b) => b.len(),
            Reply::Empty => 0,
        }
    }
}
