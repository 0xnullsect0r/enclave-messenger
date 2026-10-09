//! The credential gate (`docs/09-transport.md` §7, N3): how a device that
//! has nothing but a Tor connection gets the zk-nym ticketbooks Nym's
//! gateways ask for, without the foundation that pays for them learning
//! who it is or linking its requests.
//!
//! ```text
//! GET  /credgate/v1/key        u32 epoch ‖ pkI (49)                    the current issuer key
//! POST /credgate/v1/challenge  → nonce (32) ‖ u32 effort               a single-use puzzle
//! POST /credgate/v1/tokens     nonce ‖ proof (32) ‖ u8 n ‖ n × TokenRequest (52)
//!                              → n × TokenResponse (145)               Privacy Pass tokens
//! POST /credgate/v1/ticketbook Token (146) ‖ request                   one token buys one ticketbook
//!                              → the ticket source's answer
//! GET  /credgate/v1/partial-keys                                       the signers' partial keys
//! ```
//!
//! 1. **Work for tokens.** A challenge is solved with Equi-X
//!    (`enclave_tokens::solve`, context `credgate ‖ nonce`); each solution
//!    buys up to [`Config::tokens_per_proof`] Privacy Pass tokens
//!    (`enclave_tokens::privpass`, VOPRF over P-384, RFC 0001), issued
//!    blind. Challenges are single use and expire.
//! 2. **A token for a ticketbook.** The gate checks the token against this
//!    epoch's key or the previous one, records it as spent, and hands the
//!    request to its [`TicketSource`]: the pinned upstream
//!    `nym-credential-proxy` (`POST /api/v1/ticketbook/obtain`), which the
//!    foundation funds. The request is the device's own withdrawal request
//!    (its ecash keys never leave it) and the answer the blinded wallet
//!    shares it aggregates itself. The gate sees neither the device's
//!    address (it is reached over Tor) nor which tokens came from which
//!    proof of work.
//!
//! Keys: one 32-byte seed; the issuer key of epoch `e` (30 days) is
//! `IssuerKey::derive(seed, e)`. Spent tokens are kept in redb for two
//! epochs. Nothing is logged about requests.

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use enclave_crypto::rng::HedgedRng;
use enclave_tokens::privpass::{
    self, IssuerKey, IssuerPublic, REQUEST_LEN, RESPONSE_LEN, TOKEN_LEN, Token,
};
use enclave_tokens::{PowProof, verify};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Largest ticketbook request passed on.
pub const MAX_TICKET_REQUEST: usize = 64 * 1024;
/// Challenges kept at once (oldest dropped first).
const MAX_CHALLENGES: usize = 100_000;

pub use enclave_tokens::gate::{
    EPOCH_SECS, MAX_TOKENS_PER_PROOF, TICKETBOOK_ORIGIN, epoch_of, pow_context,
    ticketbook_challenge, tokens_finish, tokens_request,
};

const SPENT: TableDefinition<'static, &[u8], u32> = TableDefinition::new("spent");

/// What can go wrong.
#[derive(Debug)]
pub enum GateError {
    /// Storage.
    Store(String),
    /// The ticket source failed.
    Source(String),
}

impl core::fmt::Display for GateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "credential gate storage: {e}"),
            Self::Source(e) => write!(f, "ticket source: {e}"),
        }
    }
}

impl std::error::Error for GateError {}

fn store_err(e: impl core::fmt::Display) -> GateError {
    GateError::Store(e.to_string())
}

/// Where ticketbooks come from.
#[async_trait]
pub trait TicketSource: Send + Sync {
    /// Answer a device's ticketbook request.
    async fn obtain(&self, request: &[u8]) -> Result<Vec<u8>, GateError>;
    /// The signers' partial verification keys for this epoch (public; a
    /// device needs them to unblind the shares it gets).
    async fn partial_keys(&self) -> Result<Vec<u8>, GateError>;
}

/// The upstream `nym-credential-proxy`, funded by the foundation's
/// mnemonic, which only the gate can reach (on the backend network, with
/// its bearer token).
pub struct CredentialProxy {
    url: String,
    bearer: Zeroizing<String>,
    http: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        http_body_util::Full<Bytes>,
    >,
}

impl CredentialProxy {
    /// The proxy at `url` (`http://host:port`), with its API bearer token.
    pub fn new(url: &str, bearer: Zeroizing<String>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            bearer,
            http: hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http(),
        }
    }
}

#[async_trait]
impl TicketSource for CredentialProxy {
    async fn obtain(&self, request: &[u8]) -> Result<Vec<u8>, GateError> {
        // The shares, plus everything the device needs to aggregate and
        // use them, in one answer.
        let uri = format!(
            "{}/api/v1/ticketbook/obtain?skip-webhook=true&include-master-verification-key=true\
             &include-coin-index-signatures=true&include-expiration-date-signatures=true",
            self.url
        );
        self.call(hyper::Method::POST, &uri, request).await
    }

    async fn partial_keys(&self) -> Result<Vec<u8>, GateError> {
        let uri = format!("{}/api/v1/ticketbook/partial-verification-keys", self.url);
        self.call(hyper::Method::GET, &uri, &[]).await
    }
}

impl CredentialProxy {
    async fn call(
        &self,
        method: hyper::Method,
        uri: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, GateError> {
        use http_body_util::BodyExt;
        let req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.bearer.as_str()))
            .body(http_body_util::Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| GateError::Source(e.to_string()))?;
        let res = self
            .http
            .request(req)
            .await
            .map_err(|e| GateError::Source(e.to_string()))?;
        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .map_err(|e| GateError::Source(e.to_string()))?
            .to_bytes();
        if !status.is_success() {
            return Err(GateError::Source(format!("proxy answered {status}")));
        }
        Ok(body.to_vec())
    }
}

/// A ticket source for tests of the token flow: the answer is
/// `enclave-dev-ticketbook ‖ SHA-256(request)`, not a ticketbook.
#[cfg(any(test, feature = "dev-tickets"))]
pub struct DevTickets;

#[cfg(any(test, feature = "dev-tickets"))]
#[async_trait]
impl TicketSource for DevTickets {
    async fn obtain(&self, request: &[u8]) -> Result<Vec<u8>, GateError> {
        use sha2::Digest;
        let mut out = b"enclave-dev-ticketbook".to_vec();
        out.extend_from_slice(&sha2::Sha256::digest(request));
        Ok(out)
    }

    async fn partial_keys(&self) -> Result<Vec<u8>, GateError> {
        Ok(br#"{"epochId":0,"keys":[]}"#.to_vec())
    }
}

/// Settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Equi-X effort a challenge asks for.
    pub effort: u32,
    /// Tokens one solved challenge buys (at most [`MAX_TOKENS_PER_PROOF`]).
    pub tokens_per_proof: usize,
    /// The issuer name in token challenges (the gate's public host).
    pub issuer_name: String,
    /// How long a challenge may be solved for.
    pub challenge_ttl: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            effort: 2_000,
            tokens_per_proof: 8,
            issuer_name: "credgate".into(),
            challenge_ttl: Duration::from_secs(600),
        }
    }
}

/// The gate.
pub struct Gate {
    seed: Zeroizing<[u8; 32]>,
    cfg: Config,
    source: Arc<dyn TicketSource>,
    db: redb::Database,
    challenges: Mutex<HashMap<[u8; 32], Instant>>,
    keys: Mutex<HashMap<u32, Arc<IssuerKey>>>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl Gate {
    /// A gate keeping spent tokens at `path` (`None`: in memory).
    pub fn open(
        seed: Zeroizing<[u8; 32]>,
        cfg: Config,
        source: Arc<dyn TicketSource>,
        path: Option<&Path>,
    ) -> Result<Self, GateError> {
        let db = match path {
            Some(p) => redb::Database::create(p).map_err(store_err)?,
            None => redb::Database::builder()
                .create_with_backend(redb::backends::InMemoryBackend::new())
                .map_err(store_err)?,
        };
        let w = db.begin_write().map_err(store_err)?;
        w.open_table(SPENT).map_err(store_err)?;
        w.commit().map_err(store_err)?;
        let mut cfg = cfg;
        cfg.tokens_per_proof = cfg.tokens_per_proof.clamp(1, MAX_TOKENS_PER_PROOF);
        Ok(Self {
            seed,
            cfg,
            source,
            db,
            challenges: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
            clock: Box::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
            }),
        })
    }

    /// Use `clock` for Unix time (tests).
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    fn key(&self, epoch: u32) -> Option<Arc<IssuerKey>> {
        let mut keys = self.keys.lock().ok()?;
        if let Some(k) = keys.get(&epoch) {
            return Some(Arc::clone(k));
        }
        let k = Arc::new(IssuerKey::derive(&self.seed, epoch).ok()?);
        keys.retain(|e, _| e + 1 >= epoch);
        keys.insert(epoch, Arc::clone(&k));
        Some(k)
    }

    /// The current epoch and issuer public key.
    pub fn public(&self) -> Option<(u32, IssuerPublic)> {
        let epoch = epoch_of((self.clock)());
        Some((epoch, self.key(epoch)?.public()))
    }

    /// A fresh single-use challenge: `nonce ‖ u32 effort`.
    pub fn challenge(&self, rng: &mut HedgedRng) -> Option<Vec<u8>> {
        let nonce: [u8; 32] = rng.array("credgate/challenge").ok()?;
        let now = Instant::now();
        let mut c = self.challenges.lock().ok()?;
        c.retain(|_, t| now.duration_since(*t) < self.cfg.challenge_ttl);
        if c.len() >= MAX_CHALLENGES
            && let Some(oldest) = c.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k)
        {
            c.remove(&oldest);
        }
        c.insert(nonce, now);
        let mut out = nonce.to_vec();
        out.extend_from_slice(&self.cfg.effort.to_be_bytes());
        Some(out)
    }

    /// Answer `nonce ‖ proof ‖ u8 n ‖ n × TokenRequest`.
    pub fn tokens(&self, body: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>, StatusCode> {
        if body.len() < 65 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&body[..32]);
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&body[32..64]);
        let n = usize::from(body[64]);
        if n == 0 || n > self.cfg.tokens_per_proof || body.len() != 65 + n * REQUEST_LEN {
            return Err(StatusCode::BAD_REQUEST);
        }
        // Single use: taken out before checking, so a wrong answer costs
        // the challenge too.
        let fresh = self
            .challenges
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .remove(&nonce)
            .is_some_and(|t| t.elapsed() < self.cfg.challenge_ttl);
        if !fresh {
            return Err(StatusCode::GONE);
        }
        if !verify(&pow_context(&nonce), self.cfg.effort, &PowProof(proof)) {
            return Err(StatusCode::FORBIDDEN);
        }
        let epoch = epoch_of((self.clock)());
        let key = self.key(epoch).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let mut out = Vec::with_capacity(n * RESPONSE_LEN);
        for req in body[65..].chunks(REQUEST_LEN) {
            match key.issue(req, rng) {
                Ok(r) => out.extend_from_slice(&r),
                Err(privpass::PrivPassError::WrongKey) => return Err(StatusCode::CONFLICT),
                Err(_) => return Err(StatusCode::BAD_REQUEST),
            }
        }
        Ok(out)
    }

    /// Redeem a token (`Token ‖ request`) for a ticketbook.
    pub async fn ticketbook(&self, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
        if body.len() <= TOKEN_LEN || body.len() > TOKEN_LEN + MAX_TICKET_REQUEST {
            return Err(StatusCode::BAD_REQUEST);
        }
        let token = Token::decode(&body[..TOKEN_LEN]).map_err(|_| StatusCode::BAD_REQUEST)?;
        let digest = ticketbook_challenge(&self.cfg.issuer_name)
            .digest()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let epoch = epoch_of((self.clock)());
        let good = [epoch, epoch.saturating_sub(1)]
            .into_iter()
            .filter_map(|e| self.key(e).map(|k| (e, k)))
            .find(|(_, k)| k.verify(&token, &digest))
            .map(|(e, _)| e);
        let Some(issued) = good else {
            return Err(StatusCode::FORBIDDEN);
        };
        // Spent before the source is asked: a token is good once, even if
        // the source then fails.
        if !self
            .spend(&token.nonce, issued, epoch)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            return Err(StatusCode::CONFLICT);
        }
        self.source
            .obtain(&body[TOKEN_LEN..])
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)
    }

    /// Record a token nonce as spent; false if it already was. Forgets
    /// tokens two epochs old.
    fn spend(&self, nonce: &[u8; 32], issued: u32, now: u32) -> Result<bool, GateError> {
        let w = self.db.begin_write().map_err(store_err)?;
        let fresh = {
            let mut t = w.open_table(SPENT).map_err(store_err)?;
            if t.get(&nonce[..]).map_err(store_err)?.is_some() {
                false
            } else {
                t.insert(&nonce[..], issued).map_err(store_err)?;
                let old: Vec<Vec<u8>> = t
                    .iter()
                    .map_err(store_err)?
                    .filter_map(|r| r.ok())
                    .filter(|(_, e)| e.value() + 2 <= now)
                    .map(|(k, _)| k.value().to_vec())
                    .collect();
                for k in old {
                    t.remove(&k[..]).map_err(store_err)?;
                }
                true
            }
        };
        w.commit().map_err(store_err)?;
        Ok(fresh)
    }

    /// Spent tokens on record.
    pub fn spent_count(&self) -> usize {
        self.db
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(SPENT).ok())
            .and_then(|t| t.len().ok())
            .map_or(0, |n| n as usize)
    }

    /// The HTTP routes (plain HTTP behind `enclave-front`).
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/credgate/v1/key", get(key))
            .route("/credgate/v1/challenge", post(challenge))
            .route("/credgate/v1/tokens", post(tokens))
            .route("/credgate/v1/ticketbook", post(ticketbook))
            .route("/credgate/v1/partial-keys", get(partial_keys))
            .route("/healthz", get(|| async { "ok" }))
            .with_state(self)
    }
}

fn octets(b: Vec<u8>) -> Response {
    ([("content-type", "application/octet-stream")], b).into_response()
}

async fn key(State(g): State<Arc<Gate>>) -> Response {
    match g.public() {
        Some((epoch, pk)) => {
            let mut out = epoch.to_be_bytes().to_vec();
            out.extend_from_slice(&pk.0);
            octets(out)
        }
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn challenge(State(g): State<Arc<Gate>>) -> Response {
    let made = HedgedRng::new()
        .ok()
        .and_then(|mut rng| g.challenge(&mut rng));
    match made {
        Some(c) => octets(c),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn tokens(State(g): State<Arc<Gate>>, body: Bytes) -> Response {
    let Ok(mut rng) = HedgedRng::new() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match g.tokens(&body, &mut rng) {
        Ok(b) => octets(b),
        Err(s) => s.into_response(),
    }
}

async fn partial_keys(State(g): State<Arc<Gate>>) -> Response {
    match g.source.partial_keys().await {
        Ok(b) => ([("content-type", "application/json")], b).into_response(),
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

async fn ticketbook(State(g): State<Arc<Gate>>, body: Bytes) -> Response {
    match g.ticketbook(&body).await {
        Ok(b) => octets(b),
        Err(s) => s.into_response(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn gate(now: Arc<std::sync::atomic::AtomicU64>) -> Gate {
        Gate::open(
            Zeroizing::new([5; 32]),
            Config {
                effort: 1,
                tokens_per_proof: 4,
                issuer_name: "credgate.test".into(),
                ..Config::default()
            },
            Arc::new(DevTickets),
            None,
        )
        .unwrap()
        .with_clock(move || now.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[tokio::test]
    async fn work_buys_tokens_and_a_token_buys_one_ticketbook() {
        let now = Arc::new(std::sync::atomic::AtomicU64::new(100 * EPOCH_SECS));
        let g = gate(Arc::clone(&now));
        let mut rng = HedgedRng::new().unwrap();
        let (_, pk) = g.public().unwrap();
        let c = g.challenge(&mut rng).unwrap();
        let (body, pending) = tokens_request(&c, pk, "credgate.test", 3, &mut rng).unwrap();
        let answer = g.tokens(&body, &mut rng).unwrap();
        let toks = tokens_finish(pending, &answer).unwrap();
        assert_eq!(toks.len(), 3);
        // The challenge was single use.
        assert_eq!(g.tokens(&body, &mut rng), Err(StatusCode::GONE));

        let mut redeem = toks[0].encode();
        redeem.extend_from_slice(b"{\"withdrawalRequest\":\"..\"}");
        let tb = g.ticketbook(&redeem).await.unwrap();
        assert!(tb.starts_with(b"enclave-dev-ticketbook"));
        // Spent.
        assert_eq!(g.ticketbook(&redeem).await, Err(StatusCode::CONFLICT));
        assert_eq!(g.spent_count(), 1);
        // A token of the last epoch still works; two epochs on, it doesn't.
        now.store(101 * EPOCH_SECS, std::sync::atomic::Ordering::SeqCst);
        let mut second = toks[1].encode();
        second.push(1);
        assert!(g.ticketbook(&second).await.is_ok());
        now.store(102 * EPOCH_SECS, std::sync::atomic::Ordering::SeqCst);
        let mut third = toks[2].encode();
        third.push(1);
        assert_eq!(g.ticketbook(&third).await, Err(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn bad_work_and_too_many_tokens_are_refused() {
        let now = Arc::new(std::sync::atomic::AtomicU64::new(7 * EPOCH_SECS));
        let g = gate(now);
        let mut rng = HedgedRng::new().unwrap();
        let (_, pk) = g.public().unwrap();
        // More tokens than one proof buys.
        let c = g.challenge(&mut rng).unwrap();
        let (mut body, _) = tokens_request(&c, pk, "credgate.test", 5, &mut rng).unwrap();
        assert_eq!(g.tokens(&body, &mut rng), Err(StatusCode::BAD_REQUEST));
        // A wrong solution costs the challenge.
        let c = g.challenge(&mut rng).unwrap();
        let (b2, _) = tokens_request(&c, pk, "credgate.test", 1, &mut rng).unwrap();
        body = b2;
        body[40] ^= 0xff;
        let first = g.tokens(&body, &mut rng);
        assert!(first == Err(StatusCode::FORBIDDEN), "{first:?}");
        assert_eq!(g.tokens(&body, &mut rng), Err(StatusCode::GONE));
        // An unknown challenge.
        let mut unknown = body.clone();
        unknown[0] ^= 1;
        assert_eq!(g.tokens(&unknown, &mut rng), Err(StatusCode::GONE));
        // A forged token.
        let mut forged = vec![0u8; TOKEN_LEN];
        forged[1] = 1;
        forged.push(0);
        assert_eq!(g.ticketbook(&forged).await, Err(StatusCode::FORBIDDEN));
    }
}
