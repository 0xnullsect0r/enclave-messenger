//! Enclave's HTTPS front (`docs/12-servers.md` §4.3, `13-operators.md`).
//!
//! The key-holding server has no HTTP surface. The front is the one
//! process of a stack that faces the web:
//!
//! ```text
//! https://<domain>/.well-known/enclave   the server's signed descriptor (public_dir/descriptor.bin)
//! https://<domain>/witness/v1/…          the stack's witness, proxied to it on the internal network
//! https://<domain>/healthz               "ok"
//! http://<domain>/.well-known/acme-challenge/<token>   ACME HTTP-01 answers
//! http://<domain>/…                      redirected to https
//! ```
//!
//! HTTPS uses the Enclave TLS profile (`enclave-tls`: TLS 1.3, hybrid
//! SecP384r1MLKEM1024 only). Certificates come from ACME ([`acme`]), from
//! files, or (development) are self-signed; they're swapped in place on
//! renewal ([`CertStore`]). The front logs no requests and keeps no client
//! addresses.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod acme;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{any, get};
use http_body_util::BodyExt;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Longest body proxied to the witness.
const MAX_PROXY_BODY: usize = 8 << 20;

/// ACME HTTP-01 answers in flight: token → key authorization.
pub type Challenges = Arc<RwLock<HashMap<String, String>>>;

/// The certificate the front presents, replaceable while running.
#[derive(Debug, Default)]
pub struct CertStore(RwLock<Option<Arc<CertifiedKey>>>);

impl CertStore {
    /// Install a certificate chain and key (PEM).
    pub fn set_pem(&self, chain: &str, key: &str) -> Result<(), String> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let certs = CertificateDer::pem_slice_iter(chain.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("certificate: {e}"))?;
        if certs.is_empty() {
            return Err("certificate: empty chain".into());
        }
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).map_err(|e| format!("key: {e}"))?;
        let ck = CertifiedKey::from_der(certs, key, &enclave_tls::provider())
            .map_err(|e| format!("certificate and key: {e}"))?;
        if let Ok(mut g) = self.0.write() {
            *g = Some(Arc::new(ck));
        }
        Ok(())
    }

    /// Whether a certificate is installed.
    pub fn ready(&self) -> bool {
        self.0.read().map(|g| g.is_some()).unwrap_or(false)
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.read().ok()?.clone()
    }
}

/// A self-signed certificate for `domain` (development), as PEM chain and key.
pub fn self_signed(domain: &str) -> Result<(String, String), String> {
    let ck =
        rcgen::generate_simple_self_signed(vec![domain.to_string()]).map_err(|e| e.to_string())?;
    Ok((ck.cert.pem(), ck.key_pair.serialize_pem()))
}

/// What the HTTPS routes serve.
#[derive(Clone)]
pub struct Site {
    /// The directory the server writes its public files to.
    pub public_dir: PathBuf,
    /// The stack's witness on the internal network (`http://witness:7446`).
    pub witness: Option<String>,
    /// The foundation's credential gate on the internal network
    /// (`http://credgate:7448`), on the stack that runs one.
    pub credgate: Option<String>,
    http: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        http_body_util::Full<bytes::Bytes>,
    >,
}

impl Site {
    /// Serve `public_dir`, proxying the witness API to `witness`.
    pub fn new(public_dir: PathBuf, witness: Option<String>) -> Self {
        let http =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        Self {
            public_dir,
            witness: witness.map(|w| w.trim_end_matches('/').to_string()),
            credgate: None,
            http,
        }
    }

    /// Also proxy the credential gate's API (`/credgate/v1/*`) to `url`.
    pub fn with_credgate(mut self, url: Option<String>) -> Self {
        self.credgate = url.map(|u| u.trim_end_matches('/').to_string());
        self
    }

    /// The HTTPS routes.
    pub fn router(self) -> Router {
        Router::new()
            .route("/.well-known/enclave", get(descriptor))
            .route("/healthz", get(|| async { "ok" }))
            .route("/witness/v1/{*rest}", any(witness))
            .route("/credgate/v1/{*rest}", any(credgate))
            .with_state(Arc::new(self))
    }
}

async fn descriptor(State(site): State<Arc<Site>>) -> Response {
    match tokio::fs::read(site.public_dir.join("descriptor.bin")).await {
        Ok(b) => (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("max-age=300"),
                ),
            ],
            b,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Pass a witness API request through to the stack's witness.
async fn witness(
    State(site): State<Arc<Site>>,
    Path(rest): Path<String>,
    req: Request<Body>,
) -> Response {
    match &site.witness {
        Some(base) => proxy(&site, &format!("{base}/witness/v1/{rest}"), req).await,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Pass a credential gate request through to the gate.
async fn credgate(
    State(site): State<Arc<Site>>,
    Path(rest): Path<String>,
    req: Request<Body>,
) -> Response {
    match &site.credgate {
        Some(base) => proxy(&site, &format!("{base}/credgate/v1/{rest}"), req).await,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Only the method, path and body go upstream; no client address or other
/// header does.
async fn proxy(site: &Site, uri: &str, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let Ok(body) = http_body_util::Limited::new(req.into_body(), MAX_PROXY_BODY)
        .collect()
        .await
        .map(|b| b.to_bytes())
    else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let Ok(upstream) = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(http_body_util::Full::new(body))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match site.http.request(upstream).await {
        Ok(res) => {
            let status = res.status();
            match res.into_body().collect().await {
                Ok(b) => (status, b.to_bytes()).into_response(),
                Err(_) => StatusCode::BAD_GATEWAY.into_response(),
            }
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

/// The plain-HTTP routes: ACME answers, and a redirect to HTTPS for the rest.
pub fn http_router(domain: String, challenges: Challenges) -> Router {
    Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(
                |State(c): State<Challenges>, Path(token): Path<String>| async move {
                    c.read()
                        .ok()
                        .and_then(|m| m.get(&token).cloned())
                        .ok_or(StatusCode::NOT_FOUND)
                },
            ),
        )
        .with_state(challenges)
        .fallback(move |uri: Uri| {
            let domain = domain.clone();
            async move {
                let path = uri.path_and_query().map_or("/", |p| p.as_str());
                Redirect::permanent(&format!("https://{domain}{path}"))
            }
        })
}

/// Serve `router` over HTTPS with the Enclave TLS profile and the
/// certificate in `certs`.
pub async fn serve_https(
    listener: tokio::net::TcpListener,
    router: Router,
    certs: Arc<CertStore>,
) -> std::io::Result<()> {
    let cfg = enclave_tls::server_config_with_resolver(certs)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    loop {
        // The address is dropped here: nothing below sees it.
        let (sock, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let Ok(stream) = acceptor.accept(sock).await else {
                return;
            };
            let svc = hyper_util::service::TowerToHyperService::new(router);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });
    }
}
