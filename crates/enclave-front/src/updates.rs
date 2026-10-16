//! The update bundle, fetched for the server to relay (`docs/19-ops.md`
//! §1.3).
//!
//! Clients fetch release metadata through the mixnet from their own
//! server (`DirKind::Update`), never from the web. The server has no web
//! client, so the front fetches the bundle (`enclave-update.bin`, attached
//! to every release) every few hours and keeps it in a folder the server
//! reads. Everything in the bundle is signed; the front only checks that
//! it reads as one and isn't older than the copy it has, so a bad
//! download can't replace a good one. Clients check the signatures.

use enclave_update::Bundle;
use http_body_util::BodyExt;
use std::path::Path;

/// The file the server reads.
pub const FILE: &str = "enclave-update.bin";
/// Where releases attach the bundle, by default.
pub const DEFAULT_URL: &str =
    "https://github.com/0xnullsect0r/enclave-messenger/releases/latest/download/enclave-update.bin";
const MAX_REDIRECTS: usize = 5;

/// Keep `bytes` in `dir` if they are a bundle at least as new as the one
/// there (by its timestamp's version). `Ok(true)` when it was written.
pub fn keep(dir: &Path, bytes: &[u8]) -> Result<bool, String> {
    let new = Bundle::decode(bytes).map_err(|e| format!("not an update bundle: {e}"))?;
    let version = new
        .timestamp_version()
        .ok_or("the bundle's timestamp doesn't read")?;
    let path = dir.join(FILE);
    if let Ok(old) = std::fs::read(&path) {
        if old == bytes {
            return Ok(false);
        }
        if let Some(have) = Bundle::decode(&old)
            .ok()
            .and_then(|b| b.timestamp_version())
            && have > version
        {
            return Err(format!(
                "the fetched bundle (timestamp {version}) is older than the one kept ({have})"
            ));
        }
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{FILE}.tmp"));
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

/// Where a redirect from `from` leads (`location` may be relative).
pub fn redirect(from: &hyper::Uri, location: &str) -> Option<hyper::Uri> {
    let to: hyper::Uri = location.parse().ok()?;
    if to.scheme().is_some() {
        return (to.scheme_str() == Some("https")).then_some(to);
    }
    let path = to.path_and_query()?.as_str();
    if !path.starts_with('/') {
        return None;
    }
    format!("https://{}{path}", from.authority()?).parse().ok()
}

/// Download `url` (HTTPS only, following redirects, at most
/// [`enclave_update::bundle::MAX_BUNDLE`] bytes).
pub async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        enclave_tls::compat_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    let mut uri: hyper::Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
    for _ in 0..=MAX_REDIRECTS {
        let req = hyper::Request::get(uri.clone())
            .header(hyper::header::USER_AGENT, "enclave-front")
            .body(http_body_util::Empty::new())
            .map_err(|e| e.to_string())?;
        let resp = client
            .request(req)
            .await
            .map_err(|e| format!("{uri}: {e}"))?;
        let status = resp.status();
        if status.is_redirection() {
            let location = resp
                .headers()
                .get(hyper::header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .ok_or("a redirect without a location")?;
            uri = redirect(&uri, location).ok_or("a redirect away from HTTPS")?;
            continue;
        }
        if !status.is_success() {
            return Err(format!("{uri}: {status}"));
        }
        let limited =
            http_body_util::Limited::new(resp.into_body(), enclave_update::bundle::MAX_BUNDLE);
        let body = limited.collect().await.map_err(|e| format!("{uri}: {e}"))?;
        return Ok(body.to_bytes().to_vec());
    }
    Err("too many redirects".into())
}

/// Fetch `url` into `dir` now and then every `every`, for as long as the
/// front runs. Failures are logged and retried at the next turn.
pub async fn run(url: String, dir: std::path::PathBuf, every: std::time::Duration) {
    loop {
        match fetch(&url).await.and_then(|b| keep(&dir, &b)) {
            Ok(true) => eprintln!("update bundle: a newer one is kept"),
            Ok(false) => {}
            Err(e) => eprintln!("update bundle: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(version: u32) -> Vec<u8> {
        // A timestamp document as `Signed` encodes it, unsigned: the front
        // reads only its version.
        let t = enclave_update::Timestamp {
            version,
            expires: 1,
            snapshot_version: 1,
            snapshot_hash: [0; 32],
        };
        Bundle {
            timestamp: enclave_update::Signed::timestamp(&t).encode(),
            ..Bundle::default()
        }
        .encode()
    }

    #[test]
    fn newer_bundles_replace_older_ones() {
        let dir =
            std::env::temp_dir().join(format!("enclave-front-updates-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(keep(&dir, b"junk").is_err());
        assert_eq!(keep(&dir, &bundle(3)), Ok(true));
        assert_eq!(keep(&dir, &bundle(3)), Ok(false));
        assert!(keep(&dir, &bundle(2)).is_err());
        assert_eq!(std::fs::read(dir.join(FILE)).ok(), Some(bundle(3)));
        assert_eq!(keep(&dir, &bundle(4)), Ok(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redirects_stay_on_https() {
        let from: hyper::Uri = "https://github.com/a/b".parse().unwrap_or_default();
        assert_eq!(
            redirect(&from, "https://objects.example/x?y=1").map(|u| u.to_string()),
            Some("https://objects.example/x?y=1".into())
        );
        assert_eq!(
            redirect(&from, "/c/d").map(|u| u.to_string()),
            Some("https://github.com/c/d".into())
        );
        assert_eq!(redirect(&from, "http://plain.example/x"), None);
        assert_eq!(redirect(&from, "relative"), None);
    }
}
