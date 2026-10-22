//! HTTPS through Tor for the carrier's fetches ([`crate::carrier`]): what
//! a device asks of the web without its address showing. The same rules as
//! the mixnet client's own fetcher (`nym/enclave-nym-sdk`):
//!
//! - An Enclave service (`https://…`: a credential gate, a front): the
//!   Enclave TLS profile (`enclave_tls::client_config`), any method, the
//!   body sent as `application/octet-stream`, at most [`MAX_BODY`] back.
//! - An ordinary web site (`web+https://…`: a link preview, a GIF search,
//!   the transcription model): the usual TLS key exchanges, `GET` only, up
//!   to [`MAX_REDIRECTS`] redirects to `https` only, at most [`MAX_WEB`]
//!   back, no cookies, and the same user agent for every Enclave.
//! - A `#bytes=A-B` fragment never goes on the wire: it becomes a `Range`
//!   header, so a large download comes in pieces one frame holds.

use bytes::Bytes;
use http_body_util::BodyExt as _;
use std::sync::Arc;
use std::time::Duration;

/// The scheme prefix that asks for an ordinary web site.
pub const WEB: &str = "web+";
/// Most of a web answer read.
pub const MAX_WEB: usize = 960 * 1024;
/// Most of an Enclave service's answer read.
pub const MAX_BODY: usize = 1024 * 1024;
/// Redirects followed for a web site.
pub const MAX_REDIRECTS: usize = 5;
/// What web sites are told is asking: the same for every Enclave.
const WEB_AGENT: &str = "Enclave (+https://github.com/0xnullsect0r/enclave-messenger)";
/// How long an Enclave service and a web site may take.
const SERVICE_TIMEOUT: Duration = Duration::from_secs(120);
const WEB_TIMEOUT: Duration = Duration::from_secs(45);

/// Makes the requests, through `dialer`.
pub struct Fetcher {
    dialer: Arc<dyn crate::Dialer>,
    service: Option<Arc<rustls::ClientConfig>>,
    web: Option<Arc<rustls::ClientConfig>>,
}

fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // A development build's test stacks have their own CA (never in a
    // release build: `dev-direct` carries a marker the release check
    // refuses).
    #[cfg(feature = "dev-direct")]
    if let Some(path) = std::env::var_os("ENCLAVE_NYM_TEST_CA") {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        if let Ok(certs) = CertificateDer::pem_file_iter(&path) {
            for c in certs.flatten() {
                let _ = roots.add(c);
            }
        }
    }
    roots
}

impl Fetcher {
    /// A fetcher trusting the web PKI roots.
    pub fn new(dialer: Arc<dyn crate::Dialer>) -> Self {
        let service = enclave_tls::client_config(roots()).ok().map(Arc::new);
        let web =
            rustls::ClientConfig::builder_with_provider(Arc::new(enclave_tls::compat_provider()))
                .with_safe_default_protocol_versions()
                .ok()
                .map(|b| {
                    let mut c = b.with_root_certificates(roots()).with_no_client_auth();
                    c.alpn_protocols = vec![b"http/1.1".to_vec()];
                    Arc::new(c)
                });
        Self {
            dialer,
            service,
            web,
        }
    }

    /// `method` `url` with `body`: the status and the answer.
    pub async fn fetch(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), String> {
        let (url, range) = match url.split_once("#bytes=") {
            Some((u, r))
                if r.split_once('-')
                    .is_some_and(|(a, b)| a.parse::<u64>().is_ok() && b.parse::<u64>().is_ok()) =>
            {
                (u, Some(format!("bytes={r}")))
            }
            _ => (url, None),
        };
        if let Some(web) = url.strip_prefix(WEB) {
            if method != "GET" || !body.is_empty() {
                return Err("web: GET only".into());
            }
            let cfg = self.web.clone().ok_or("web: no TLS")?;
            return tokio::time::timeout(WEB_TIMEOUT, self.web_get(cfg, web, range))
                .await
                .map_err(|_| "web: timed out".to_string())?;
        }
        let cfg = self.service.clone().ok_or("no TLS")?;
        let method = hyper::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let (status, _, b) = tokio::time::timeout(
            SERVICE_TIMEOUT,
            self.request(cfg, method, url, range, body, false),
        )
        .await
        .map_err(|_| "timed out".to_string())??;
        Ok((status, b))
    }

    async fn web_get(
        &self,
        cfg: Arc<rustls::ClientConfig>,
        url: &str,
        range: Option<String>,
    ) -> Result<(u16, Vec<u8>), String> {
        let mut url = url.to_string();
        for _ in 0..=MAX_REDIRECTS {
            let (status, location, body) = self
                .request(
                    Arc::clone(&cfg),
                    hyper::Method::GET,
                    &url,
                    range.clone(),
                    Vec::new(),
                    true,
                )
                .await?;
            match (status, location) {
                (301 | 302 | 303 | 307 | 308, Some(to)) => url = resolve(&url, &to)?,
                _ => return Ok((status, body)),
            }
        }
        Err("web: too many redirects".into())
    }

    /// One HTTP/1.1 request over TLS through the dialer: the status, any
    /// `Location`, and at most [`MAX_WEB`] (`web`) or [`MAX_BODY`] bytes of
    /// body.
    async fn request(
        &self,
        cfg: Arc<rustls::ClientConfig>,
        method: hyper::Method,
        url: &str,
        range: Option<String>,
        body: Vec<u8>,
        web: bool,
    ) -> Result<(u16, Option<String>, Vec<u8>), String> {
        let limit = if web { MAX_WEB } else { MAX_BODY };
        if !url.starts_with("https://") {
            return Err("https only".into());
        }
        let uri: hyper::Uri = url.parse().map_err(|_| "not a URL".to_string())?;
        let host = uri.host().ok_or("no host")?.to_string();
        let port = uri.port_u16().unwrap_or(443);
        let authority = uri
            .authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_else(|| host.clone());
        let path = uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let stream = self
            .dialer
            .dial(&host, port)
            .await
            .map_err(|e| format!("{host}: {e}"))?;
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| format!("{host}: not a name"))?;
        let tls = tokio_rustls::TlsConnector::from(cfg)
            .connect(name, stream)
            .await
            .map_err(|e| format!("{host}: {e}"))?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, authority);
        if web {
            req = req.header(hyper::header::USER_AGENT, WEB_AGENT);
        }
        if let Some(r) = range {
            req = req.header(hyper::header::RANGE, r);
        } else if !web {
            req = req.header(hyper::header::CONTENT_TYPE, "application/octet-stream");
        }
        let req = req
            .body(http_body_util::Full::new(Bytes::from(body)))
            .map_err(|e| e.to_string())?;
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = http_body_util::Limited::new(resp.into_body(), limit)
            .collect()
            .await
            .map_err(|e| {
                if web {
                    "web: too large".to_string()
                } else {
                    e.to_string()
                }
            })?
            .to_bytes();
        Ok((status, location, body.to_vec()))
    }
}

/// Where a redirect from `from` to `to` leads: an absolute `https` URL, or
/// a path on the same site.
fn resolve(from: &str, to: &str) -> Result<String, String> {
    if to.starts_with("https://") {
        return Ok(to.to_string());
    }
    if to.starts_with('/') && !to.starts_with("//") {
        let uri: hyper::Uri = from.parse().map_err(|_| "not a URL".to_string())?;
        let authority = uri.authority().ok_or("no host")?;
        return Ok(format!("https://{authority}{to}"));
    }
    Err("web: redirect away from https".into())
}

#[cfg(test)]
mod tests {
    use super::resolve;

    #[test]
    fn redirects_stay_on_https() {
        assert_eq!(
            resolve("https://a.example/x", "/y?z=1").unwrap(),
            "https://a.example/y?z=1"
        );
        assert_eq!(
            resolve("https://a.example/x", "https://b.example/").unwrap(),
            "https://b.example/"
        );
        assert!(resolve("https://a.example/x", "http://b.example/").is_err());
        assert!(resolve("https://a.example/x", "//b.example/").is_err());
        assert!(resolve("https://a.example/x", "y").is_err());
    }
}
