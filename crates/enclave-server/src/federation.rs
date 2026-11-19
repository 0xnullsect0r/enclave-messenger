//! The server's federation API (RFC 0012): the front proxies
//! `/federation/*` here from the internal network. Two things answer:
//!
//! ```text
//! POST /federation/list    a doubly-signed server list: verified against
//!                          the foundation's public key and only taken when
//!                          fresher (seq above what's held, not expired);
//!                          possession of the signature is the authority,
//!                          and the file it swaps is the one clients are
//!                          served. No secret, no token.
//! POST /federation/apply   an application handed to the registrar
//!                          (`server.registrar`), so a new stack only ever
//!                          needs one existing address.
//! GET  /healthz            liveness for the front's proxy.
//! ```
//!
//! The body formats are the wire's own (no JSON): an application is
//! `u32 len ‖ ServerDescriptor ‖ u32 len ‖ WitnessDescriptor (0 = none) ‖
//! 64 B proof of work`; the registrar answers in kind. The proof of work
//! is `api::pow_context_join(server id, day)` at the effort the registrar
//! names (`GET /registrar/v1/params`).

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use enclave_federation::ServerList;
use http_body_util::BodyExt;
use std::path::PathBuf;
use std::sync::Arc;

/// Longest list or application accepted.
const MAX_BODY: usize = 4 << 20;

/// What the API needs: the verified-against foundation public key and the
/// list file a push may swap.
pub struct Federation {
    /// The foundation's pinned public key (`server.foundation`).
    pub foundation: enclave_federation::FoundationPublic,
    /// The list file served to clients (`server.server_list`).
    pub list: PathBuf,
    /// The registrar applications are handed to (`server.registrar`).
    pub registrar: Option<String>,
}

/// Serve the API on `listener` until it stops accepting.
pub async fn serve(listener: tokio::net::TcpListener, f: Arc<Federation>) {
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/federation/list", any(list))
        .route("/federation/apply", any(apply))
        .with_state(f);
    let svc = hyper_util::service::TowerToHyperService::new(router);
    loop {
        let Ok((sock, _)) = listener.accept().await else {
            continue;
        };
        let svc = svc.clone();
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(sock), svc)
                .await;
        });
    }
}

/// Take a pushed list: both signatures under the pinned foundation key,
/// not expired, and newer than anything held — then swap the file
/// atomically, which the running server picks up as it serves it.
async fn list(State(f): State<Arc<Federation>>, req: Request) -> Response {
    let Ok(bytes) = http_body_util::Limited::new(req.into_body(), MAX_BODY)
        .collect()
        .await
        .map(|b| b.to_bytes())
    else {
        return plain(StatusCode::PAYLOAD_TOO_LARGE, "too large".into());
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let held = std::fs::read(&f.list)
        .ok()
        .and_then(|b| ServerList::decode_unverified(&b).ok())
        .map(|l| l.seq)
        .unwrap_or(0);
    match ServerList::verify(&bytes, &f.foundation, now, held) {
        Ok(l) => {
            let tmp = f.list.with_extension("tmp");
            match std::fs::write(&tmp, &bytes).and_then(|()| std::fs::rename(&tmp, &f.list)) {
                Ok(()) => plain(StatusCode::OK, format!("list {} taken", l.seq)),
                Err(e) => plain(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("couldn't write the list: {e}"),
                ),
            }
        }
        Err(e) => plain(StatusCode::FORBIDDEN, format!("list refused: {e}")),
    }
}

/// Hand an application to the registrar unchanged: the new stack's one
/// existing address is enough.
async fn apply(State(f): State<Arc<Federation>>, req: Request) -> Response {
    let Some(registrar) = &f.registrar else {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "no registrar is set here".into(),
        );
    };
    let Ok(body) = http_body_util::Limited::new(req.into_body(), MAX_BODY)
        .collect()
        .await
        .map(|b| b.to_bytes())
    else {
        return plain(StatusCode::PAYLOAD_TOO_LARGE, "too large".into());
    };
    match post_https(&format!("{registrar}/registrar/v1/apply"), &body).await {
        Ok((status, answer)) => plain(
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            String::from_utf8_lossy(&answer).into_owned(),
        ),
        Err(e) => plain(StatusCode::BAD_GATEWAY, e),
    }
}

fn plain(status: StatusCode, text: String) -> Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        text,
    )
        .into_response()
}

/// POST `body` to `url` under the Enclave TLS profile with the public
/// roots (a registrar sits behind an Enclave front with a public CA's
/// certificate). The status and answer body.
pub async fn post_https(url: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
    use http_body_util::BodyExt;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = enclave_tls::client_config(roots).map_err(|e| e.to_string())?;
    tls.alpn_protocols.clear();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, http_body_util::Full<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    let req = hyper::Request::post(url)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .body(http_body_util::Full::new(bytes::Bytes::copy_from_slice(
            body,
        )))
        .map_err(|e| e.to_string())?;
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    let status = res.status().as_u16();
    let answer = res
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, answer.to_vec()))
}

/// `GET` the same way (a registrar's `params`, its mirrored list).
pub async fn get_https(url: &str) -> Result<(u16, Vec<u8>), String> {
    use http_body_util::BodyExt;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = enclave_tls::client_config(roots).map_err(|e| e.to_string())?;
    tls.alpn_protocols.clear();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    let req = hyper::Request::get(url)
        .body(http_body_util::Empty::new())
        .map_err(|e| e.to_string())?;
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    let status = res.status().as_u16();
    let answer = res
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, answer.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_crypto::rng::HedgedRng;
    use enclave_federation::{FoundationKey, ServerList};
    use std::io::{Read, Write};

    fn federation(dir: &std::path::Path, key: &FoundationKey) -> Arc<Federation> {
        Arc::new(Federation {
            foundation: key.public(),
            list: dir.join("server-list.bin"),
            registrar: None,
        })
    }

    /// POST to a served router over a real loopback connection.
    async fn post(f: Arc<Federation>, body: Vec<u8>) -> (u16, String, std::path::PathBuf) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, f));
        let mut sock = std::net::TcpStream::connect(addr).unwrap();
        let req = format!(
            "POST /federation/list HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        sock.write_all(req.as_bytes()).unwrap();
        sock.write_all(&body).unwrap();
        let mut answer = String::new();
        sock.read_to_string(&mut answer).unwrap();
        let status: u16 = answer
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let text = answer
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_string();
        (status, text, std::path::PathBuf::from(format!("/{}", addr)))
    }

    /// A pushed list is taken only signed and fresh: unsigned is refused,
    /// a stale sequence is refused, a good one swaps the file, and another
    /// foundation's signature never counts.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pushed_list_is_taken_when_signed_and_fresher() {
        let dir = std::env::temp_dir().join(format!("enclave-fed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut rng = HedgedRng::new().unwrap();
        let key = FoundationKey::generate(&mut rng).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let list = |seq: u64| ServerList {
            seq,
            issued: now,
            expires: now + 86_400,
            witness_threshold: 1,
            servers: Vec::new(),
            witnesses: Vec::new(),
            relays: Vec::new(),
            push: Vec::new(),
            credgates: Vec::new(),
        };
        let file = dir.join("server-list.bin");

        // Unsigned garbage: refused, nothing written.
        let (s, why, _) = post(federation(&dir, &key), vec![1, 2, 3]).await;
        assert_eq!(s, 403, "{why}");
        assert!(!file.exists());

        // Signed, sequence 2: taken.
        let two = list(2).sign(&key, &mut rng).unwrap();
        let (s, what, _) = post(federation(&dir, &key), two.clone()).await;
        assert_eq!(s, 200, "{what}");
        assert_eq!(std::fs::read(&file).unwrap(), two);

        // Its replay, and 1 under it: both stale.
        let (s, _, _) = post(federation(&dir, &key), two.clone()).await;
        assert_eq!(s, 403);
        let one = list(1).sign(&key, &mut rng).unwrap();
        let (s, _, _) = post(federation(&dir, &key), one).await;
        assert_eq!(s, 403);

        // 3 over 2.
        let three = list(3).sign(&key, &mut rng).unwrap();
        let (s, _, _) = post(federation(&dir, &key), three.clone()).await;
        assert_eq!(s, 200);
        assert_eq!(std::fs::read(&file).unwrap(), three);

        // Another foundation's word counts for nothing.
        let other = FoundationKey::generate(&mut rng).unwrap();
        let forged = list(4).sign(&other, &mut rng).unwrap();
        let (s, _, _) = post(federation(&dir, &key), forged).await;
        assert_eq!(s, 403);
        assert_eq!(std::fs::read(&file).unwrap(), three);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
