//! Delivering wakes to Apple, Google and UnifiedPush distributors
//! (`docs/10-push.md` §1, §5).
//!
//! * **APNs**: HTTP/2 `POST /3/device/{token}` with a provider token (an
//!   ES256 JWT from the project's `.p8` key, refreshed every 50 minutes), an
//!   alert that says only "New message", `mutable-content` so the
//!   notification extension may replace it, and the capsule (base64, `c`)
//!   for it to open.
//! * **FCM** (HTTP v1): `POST /v1/projects/{project}/messages:send` with a
//!   content-free, high-priority data message, authorised by an OAuth access
//!   token from the service account (an RS256 JWT assertion, exchanged at
//!   its token URI and cached until a minute before it expires).
//! * **UnifiedPush**: a `POST` of one fixed byte (`1`, the same for every
//!   wake, so it says nothing; distributors deliver 1 to 4,096 bytes) to
//!   the distributor's endpoint,
//!   over TLS for `https://` (the WebPKI roots), or plain `http://` (a
//!   distributor on the device's own network).
//!
//! The project's credentials are an External Gate (G6); everything else is
//! here and tested against local stand-ins.

use crate::{Delivery, Platform};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Why a delivery failed.
#[derive(Debug, thiserror::Error)]
pub enum DeliverError {
    /// Nothing configured for this platform.
    #[error("no credentials for this platform")]
    NotConfigured,
    /// A bad URL, key or token.
    #[error("bad configuration: {0}")]
    Config(String),
    /// The connection or TLS failed.
    #[error("network: {0}")]
    Net(String),
    /// The service refused (status and body).
    #[error("refused: {0} {1}")]
    Refused(u16, String),
}

type Result<T> = std::result::Result<T, DeliverError>;

/// APNs credentials.
pub struct ApnsConfig {
    /// The team id.
    pub team_id: String,
    /// The key id of the `.p8` key.
    pub key_id: String,
    /// The `.p8` key (PKCS#8, PEM or DER).
    pub key: Vec<u8>,
    /// The app's bundle id (`apns-topic`).
    pub topic: String,
    /// `https://api.push.apple.com` (or the sandbox, or a test server).
    pub endpoint: String,
}

/// FCM credentials: a service account.
pub struct FcmConfig {
    /// The Firebase project id.
    pub project_id: String,
    /// The service account's e-mail address.
    pub client_email: String,
    /// Its private key (PKCS#8 RSA, PEM or DER).
    pub private_key: Vec<u8>,
    /// Where access tokens come from (`https://oauth2.googleapis.com/token`).
    pub token_uri: String,
    /// `https://fcm.googleapis.com` (or a test server).
    pub endpoint: String,
}

impl FcmConfig {
    /// From a service-account JSON file as Google issues it.
    pub fn from_service_account(json: &[u8]) -> Result<Self> {
        let v: serde_json::Value =
            serde_json::from_slice(json).map_err(|e| DeliverError::Config(e.to_string()))?;
        let s = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or_else(|| DeliverError::Config(format!("service account has no {k}")))
        };
        Ok(Self {
            project_id: s("project_id")?,
            client_email: s("client_email")?,
            private_key: s("private_key")?.into_bytes(),
            token_uri: s("token_uri")
                .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".into()),
            endpoint: "https://fcm.googleapis.com".into(),
        })
    }
}

/// DER from PEM (the first block), or the bytes as they are.
pub fn pem_to_der(b: &[u8]) -> Result<Vec<u8>> {
    let Ok(s) = std::str::from_utf8(b) else {
        return Ok(b.to_vec());
    };
    if !s.contains("-----BEGIN") {
        return Ok(b.to_vec());
    }
    let body: String = s
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .map(str::trim)
        .collect();
    b64_decode(&body).ok_or_else(|| DeliverError::Config("bad PEM".into()))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8], url: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let v = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i > n {
                if !url {
                    out.push('=');
                }
                continue;
            }
            let c = B64[((v >> (18 - 6 * i)) & 63) as usize];
            out.push(match (url, c) {
                (true, b'+') => '-',
                (true, b'/') => '_',
                (_, c) => c as char,
            });
        }
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A compact JWS: `header.claims.signature`, base64url.
fn jwt(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    sign: impl Fn(&[u8]) -> Result<Vec<u8>>,
) -> Result<String> {
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes(), true),
        b64(claims.to_string().as_bytes(), true)
    );
    let sig = sign(input.as_bytes())?;
    Ok(format!("{input}.{}", b64(&sig, true)))
}

/// A parsed `http(s)://host[:port]/path` URL.
struct Target {
    tls: bool,
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl Target {
    fn parse(url: &str) -> Result<Self> {
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(DeliverError::Config(format!("not an http(s) URL: {url}")));
        };
        let (authority, path) = rest
            .split_once('/')
            .map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{p}")));
        if authority.is_empty() || authority.contains('@') {
            return Err(DeliverError::Config(format!("bad host in {url}")));
        }
        let (host, port) = match authority.rsplit_once(':') {
            // `[v6]` alone has colons but no port.
            Some((h, p)) if !authority.ends_with(']') => (
                h.trim_start_matches('[').trim_end_matches(']').to_string(),
                p.parse::<u16>()
                    .map_err(|_| DeliverError::Config(format!("bad port in {url}")))?,
            ),
            _ => (
                authority
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string(),
                if tls { 443 } else { 80 },
            ),
        };
        Ok(Self {
            tls,
            host,
            port,
            authority: authority.to_string(),
            path,
        })
    }

    fn key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

type H2 = hyper::client::conn::http2::SendRequest<http_body_util::Full<Bytes>>;

/// Delivers wakes to the platforms configured. Shared between tasks:
/// HTTP/2 connections (APNs and FCM) are kept open and reused, as Apple
/// asks, and the provider and access tokens are cached.
pub struct Deliverer {
    apns: Option<(ApnsConfig, EcdsaKeyPair)>,
    fcm: Option<(FcmConfig, RsaKeyPair)>,
    tls: Arc<ClientConfig>,
    rng: SystemRandom,
    /// The APNs provider token and when it was made.
    apns_token: std::sync::Mutex<Option<(String, u64)>>,
    /// The FCM access token and when it expires (held while refreshing, so
    /// one refresh serves everyone waiting).
    fcm_token: tokio::sync::Mutex<Option<(String, u64)>>,
    /// Open HTTP/2 connections by `host:port`.
    h2: std::sync::Mutex<std::collections::HashMap<String, H2>>,
    /// Deliveries made and failed.
    pub stats: Stats,
}

/// Counters (no logs: `10-push.md` §6).
#[derive(Default)]
pub struct Stats {
    /// Delivered.
    pub sent: std::sync::atomic::AtomicU64,
    /// Refused or failed.
    pub failed: std::sync::atomic::AtomicU64,
}

impl Deliverer {
    /// A deliverer trusting the WebPKI roots.
    pub fn new(apns: Option<ApnsConfig>, fcm: Option<FcmConfig>) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(apns, fcm, roots)
    }

    /// A deliverer trusting `roots` (tests: a local CA).
    pub fn with_roots(
        apns: Option<ApnsConfig>,
        fcm: Option<FcmConfig>,
        roots: RootCertStore,
    ) -> Result<Self> {
        let rng = SystemRandom::new();
        let apns = match apns {
            Some(c) => {
                let der = pem_to_der(&c.key)?;
                let k = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
                    .map_err(|e| DeliverError::Config(format!("APNs key: {e}")))?;
                Some((c, k))
            }
            None => None,
        };
        let fcm = match fcm {
            Some(c) => {
                let der = pem_to_der(&c.private_key)?;
                let k = RsaKeyPair::from_pkcs8(&der)
                    .map_err(|e| DeliverError::Config(format!("FCM key: {e}")))?;
                Some((c, k))
            }
            None => None,
        };
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let mut tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| DeliverError::Config(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            apns,
            fcm,
            tls: Arc::new(tls),
            rng,
            apns_token: std::sync::Mutex::new(None),
            fcm_token: tokio::sync::Mutex::new(None),
            h2: std::sync::Mutex::new(std::collections::HashMap::new()),
            stats: Stats::default(),
        })
    }

    /// Which platforms can be delivered to.
    pub fn platforms(&self) -> Vec<Platform> {
        let mut v = vec![Platform::UnifiedPush];
        if self.apns.is_some() {
            v.push(Platform::Apns);
        }
        if self.fcm.is_some() {
            v.push(Platform::Fcm);
        }
        v
    }

    /// Deliver one wake.
    pub async fn deliver(&self, d: &Delivery) -> Result<()> {
        let r = match d.platform {
            Platform::UnifiedPush => self.unified_push(d).await,
            Platform::Apns => self.apns(d).await,
            Platform::Fcm => self.fcm(d).await,
        };
        let c = if r.is_ok() {
            &self.stats.sent
        } else {
            &self.stats.failed
        };
        c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        r
    }

    async fn unified_push(&self, d: &Delivery) -> Result<()> {
        let url = std::str::from_utf8(&d.token)
            .map_err(|_| DeliverError::Config("endpoint isn't text".into()))?;
        // The wake itself is the message: one fixed byte, as distributors
        // expect a body (UnifiedPush AND_3: 1 to 4,096 bytes).
        let headers = [("ttl", "60".to_string()), ("urgency", "high".to_string())];
        ok(self.request(url, "POST", &headers, b"1".to_vec()).await?)
    }

    fn apns_token(&self, now: u64) -> Result<String> {
        let (cfg, key) = self.apns.as_ref().ok_or(DeliverError::NotConfigured)?;
        let mut cached = self
            .apns_token
            .lock()
            .map_err(|_| DeliverError::Config("poisoned".into()))?;
        // Apple wants a new provider token at most every 20 minutes and at
        // least every hour.
        if let Some((t, at)) = cached.as_ref()
            && now < at + 50 * 60
        {
            return Ok(t.clone());
        }
        let t = jwt(
            &serde_json::json!({"alg": "ES256", "kid": cfg.key_id}),
            &serde_json::json!({"iss": cfg.team_id, "iat": now}),
            |m| {
                key.sign(&self.rng, m)
                    .map(|s| s.as_ref().to_vec())
                    .map_err(|_| DeliverError::Config("APNs signing".into()))
            },
        )?;
        *cached = Some((t.clone(), now));
        Ok(t)
    }

    async fn apns(&self, d: &Delivery) -> Result<()> {
        let token = self.apns_token(unix_now())?;
        let (cfg, _) = self.apns.as_ref().ok_or(DeliverError::NotConfigured)?;
        let device: String = d.token.iter().map(|b| format!("{b:02x}")).collect();
        let url = format!("{}/3/device/{device}", cfg.endpoint.trim_end_matches('/'));
        // The generic alert; the notification extension replaces it with
        // the capsule's name and preview when it opens (`10-push.md` §5.1).
        // `content-available` also lets the app, if it is still in memory,
        // fetch at once.
        let mut body = serde_json::json!({
            "aps": {
                "alert": {"body": "New message"},
                "mutable-content": 1,
                "content-available": 1,
                "sound": "default",
            },
        });
        if !d.capsule.is_empty() {
            body["c"] = serde_json::Value::String(b64(&d.capsule, false));
        }
        let headers = [
            ("authorization", format!("bearer {token}")),
            ("apns-topic", cfg.topic.clone()),
            ("apns-push-type", "alert".into()),
            ("apns-priority", "10".into()),
            ("apns-expiration", "0".into()),
            ("content-type", "application/json".into()),
        ];
        let r = self
            .request(&url, "POST", &headers, body.to_string().into_bytes())
            .await?;
        if r.0 == 403 {
            // An expired or refused provider token: a new one next time.
            if let Ok(mut t) = self.apns_token.lock() {
                *t = None;
            }
        }
        ok(r)
    }

    async fn fcm(&self, d: &Delivery) -> Result<()> {
        let token = self.fcm_access_token().await?;
        let (cfg, _) = self.fcm.as_ref().ok_or(DeliverError::NotConfigured)?;
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            cfg.endpoint.trim_end_matches('/'),
            cfg.project_id
        );
        let device = std::str::from_utf8(&d.token)
            .map_err(|_| DeliverError::Config("FCM token isn't text".into()))?;
        // Content-free: the app fetches what's new itself.
        let body = serde_json::json!({
            "message": {
                "token": device,
                "data": {"w": "1"},
                "android": {"priority": "high", "ttl": "60s"},
            }
        });
        let headers = [
            ("authorization", format!("Bearer {token}")),
            ("content-type", "application/json".into()),
        ];
        let r = self
            .request(&url, "POST", &headers, body.to_string().into_bytes())
            .await?;
        if r.0 == 401 {
            *self.fcm_token.lock().await = None;
        }
        ok(r)
    }

    async fn fcm_access_token(&self) -> Result<String> {
        let mut cached = self.fcm_token.lock().await;
        let now = unix_now();
        if let Some((t, until)) = cached.as_ref()
            && now + 60 < *until
        {
            return Ok(t.clone());
        }
        let (cfg, key) = self.fcm.as_ref().ok_or(DeliverError::NotConfigured)?;
        let assertion = jwt(
            &serde_json::json!({"alg": "RS256", "typ": "JWT"}),
            &serde_json::json!({
                "iss": cfg.client_email,
                "scope": "https://www.googleapis.com/auth/firebase.messaging",
                "aud": cfg.token_uri,
                "iat": now,
                "exp": now + 3600,
            }),
            |m| {
                let mut sig = vec![0u8; key.public().modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, &self.rng, m, &mut sig)
                    .map_err(|_| DeliverError::Config("FCM signing".into()))?;
                Ok(sig)
            },
        )?;
        let form = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );
        let (status, body) = self
            .request(
                &cfg.token_uri,
                "POST",
                &[("content-type", "application/x-www-form-urlencoded".into())],
                form.into_bytes(),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(DeliverError::Refused(status, body));
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| DeliverError::Net(e.to_string()))?;
        let t = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .ok_or_else(|| DeliverError::Net("no access token".into()))?
            .to_string();
        let expires = v.get("expires_in").and_then(|x| x.as_u64()).unwrap_or(3600);
        *cached = Some((t.clone(), now + expires));
        Ok(t)
    }

    /// One request, over a kept HTTP/2 connection when there is one, else
    /// a new connection (HTTP/2 if the server offers it, else HTTP/1.1):
    /// the status and body.
    async fn request(
        &self,
        url: &str,
        method: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<(u16, String)> {
        let t = Target::parse(url)?;
        let build = |h2: bool| -> Result<hyper::Request<http_body_util::Full<Bytes>>> {
            // HTTP/2 takes the full URI; HTTP/1.1 a path and a Host header.
            let mut req = if h2 {
                hyper::Request::builder().uri(format!(
                    "{}://{}{}",
                    if t.tls { "https" } else { "http" },
                    t.authority,
                    t.path
                ))
            } else {
                hyper::Request::builder()
                    .uri(t.path.as_str())
                    .header("host", t.authority.as_str())
            }
            .method(method);
            for (k, v) in headers {
                req = req.header(*k, v);
            }
            req.header("content-length", body.len())
                .body(http_body_util::Full::new(Bytes::from(body.clone())))
                .map_err(|e| DeliverError::Config(e.to_string()))
        };
        let fut = async {
            // A kept connection first; if it has gone, a new one.
            let kept = self.h2.lock().ok().and_then(|m| m.get(&t.key()).cloned());
            if let Some(mut s) = kept {
                if s.ready().await.is_ok()
                    && let Ok(r) = s.send_request(build(true)?).await
                {
                    return read(r).await;
                }
                if let Ok(mut m) = self.h2.lock() {
                    m.remove(&t.key());
                }
            }
            let tcp = tokio::time::timeout(
                Duration::from_secs(15),
                tokio::net::TcpStream::connect((t.host.as_str(), t.port)),
            )
            .await
            .map_err(|_| DeliverError::Net("connect timed out".into()))?
            .map_err(|e| DeliverError::Net(e.to_string()))?;
            if !t.tls {
                return http1(TokioIo::new(tcp), build(false)?).await;
            }
            let name = ServerName::try_from(t.host.clone())
                .map_err(|e| DeliverError::Config(e.to_string()))?;
            let s = TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, tcp)
                .await
                .map_err(|e| DeliverError::Net(e.to_string()))?;
            if s.get_ref().1.alpn_protocol() != Some(b"h2") {
                return http1(TokioIo::new(s), build(false)?).await;
            }
            let (mut send, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(s))
                    .await
                    .map_err(net)?;
            tokio::spawn(conn);
            if let Ok(mut m) = self.h2.lock() {
                m.insert(t.key(), send.clone());
            }
            read(send.send_request(build(true)?).await.map_err(net)?).await
        };
        tokio::time::timeout(Duration::from_secs(30), fut)
            .await
            .map_err(|_| DeliverError::Net("request timed out".into()))?
    }
}

fn net(e: hyper::Error) -> DeliverError {
    DeliverError::Net(e.to_string())
}

async fn http1<T>(
    io: TokioIo<T>,
    req: hyper::Request<http_body_util::Full<Bytes>>,
) -> Result<(u16, String)>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut s, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(net)?;
    tokio::spawn(conn);
    read(s.send_request(req).await.map_err(net)?).await
}

async fn read(resp: hyper::Response<hyper::body::Incoming>) -> Result<(u16, String)> {
    use http_body_util::BodyExt as _;
    let status = resp.status().as_u16();
    let body = http_body_util::Limited::new(resp.into_body(), 64 * 1024)
        .collect()
        .await
        .map_err(|e| DeliverError::Net(e.to_string()))?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn ok((status, body): (u16, String)) -> Result<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(DeliverError::Refused(status, body))
    }
}

#[cfg(test)]
mod tests;
