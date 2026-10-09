//! The front over the Enclave TLS profile: the descriptor, the witness API
//! proxied to a real witness (reached by `HttpWitness` through the front),
//! the HTTP side (ACME answers, redirect), a client without the hybrid
//! refused, and certificates from an ACME CA (pebble, when
//! `ENCLAVE_PEBBLE_DIRECTORY` is set; CI's `tls-interop` job).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bytes::Bytes;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::{WitnessDescriptor, witness_id};
use enclave_front::{CertStore, Challenges, Site};
use enclave_kt::{KtStore, Witness};
use http_body_util::{BodyExt, Full};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("enclave-front-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A CA (written to `dir/ca.pem`) and a certificate for `name` it signed.
fn ca_and_leaf(dir: &Path, name: &str) -> (PathBuf, String, String) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec![name.to_string()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let path = dir.join("ca.pem");
    std::fs::write(&path, ca.pem()).unwrap();
    (path, leaf.pem(), key.serialize_pem())
}

fn roots(ca: &Path) -> rustls::RootCertStore {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut r = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(ca).unwrap() {
        r.add(c.unwrap()).unwrap();
    }
    r
}

type Http = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

fn client(tls: rustls::ClientConfig) -> Http {
    let mut tls = tls;
    tls.alpn_protocols.clear();
    let c = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(c)
}

async fn get(http: &Http, url: &str) -> Result<(u16, hyper::HeaderMap, Vec<u8>), String> {
    let req = hyper::Request::get(url)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = http.request(req).await.map_err(|e| format!("{e:?}"))?;
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    Ok((status, headers, body))
}

/// A witness serving plain HTTP on the "internal network".
async fn start_witness(dir: &Path) -> (String, WitnessDescriptor) {
    let mut rng = HedgedRng::new().unwrap();
    let key = CompositeSigningKey::generate(&mut rng).unwrap();
    let d = WitnessDescriptor::sign(
        &key,
        "op",
        "fam",
        "https://front.test",
        now() - 5,
        now() + 86_400,
        &mut rng,
    )
    .unwrap();
    let store = KtStore::open(&dir.join("witness.redb")).unwrap();
    let w = Witness::with_store(witness_id(key.public()), "op", key, store).unwrap();
    let svc = Arc::new(enclave_witness::WitnessService::new(w, d.encode()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(enclave_witness::service::serve(l, svc.router(), None));
    (format!("http://{addr}"), d)
}

/// A header-echoing upstream: answers with the names of the headers it got.
async fn start_echo() -> String {
    let router = axum::Router::new().route(
        "/witness/v1/{*rest}",
        axum::routing::any(|req: axum::extract::Request| async move {
            let mut names: Vec<String> = req
                .headers()
                .keys()
                .map(|k| k.as_str().to_string())
                .collect();
            names.sort();
            format!("{} {} {}", req.method(), req.uri().path(), names.join(","))
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router).await });
    format!("http://{addr}")
}

async fn start_front(public: &Path, witness: Option<String>, certs: Arc<CertStore>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let site = Site::new(public.to_path_buf(), witness).router();
    tokio::spawn(enclave_front::serve_https(l, site, certs));
    format!("https://{addr}")
}

#[tokio::test(flavor = "multi_thread")]
async fn front_serves_descriptor_and_witness_over_enclave_tls() {
    let dir = temp("serve");
    let public = dir.join("public");
    std::fs::create_dir_all(&public).unwrap();
    let (ca, chain, key) = ca_and_leaf(&dir, "127.0.0.1");
    let certs = Arc::new(CertStore::default());
    certs.set_pem(&chain, &key).unwrap();
    assert!(certs.ready());

    let (witness, wd) = start_witness(&dir).await;
    let front = start_front(&public, Some(witness), Arc::clone(&certs)).await;
    let http = client(enclave_tls::client_config(roots(&ca)).unwrap());

    // No descriptor written yet; then the server's bytes, as written.
    assert_eq!(
        get(&http, &format!("{front}/.well-known/enclave"))
            .await
            .unwrap()
            .0,
        404
    );
    std::fs::write(public.join("descriptor.bin"), b"descriptor bytes").unwrap();
    let (status, headers, body) = get(&http, &format!("{front}/.well-known/enclave"))
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(body, b"descriptor bytes");
    assert_eq!(headers["content-type"], "application/octet-stream");
    assert_eq!(
        get(&http, &format!("{front}/healthz")).await.unwrap().2,
        b"ok"
    );
    assert_eq!(get(&http, &format!("{front}/other")).await.unwrap().0, 404);
    // The page behind an invite link: the same for every link (the invite
    // is in the fragment, never sent), no script allowed.
    let (status, headers, body) = get(&http, &format!("{front}/i")).await.unwrap();
    assert_eq!(status, 200);
    assert!(
        String::from_utf8(body)
            .unwrap()
            .contains("open the link again")
    );
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .starts_with("default-src 'none'")
    );

    // The witness, reached through the front by the client a log uses.
    let w = enclave_witness::HttpWitness::connect(&front, Some(&ca), now())
        .await
        .unwrap();
    assert_eq!(w.descriptor().unwrap().id(), wd.id());

    // A client offering only classical key exchange gets no connection.
    let classical = rustls::crypto::CryptoProvider {
        kx_groups: vec![rustls::crypto::ring::kx_group::X25519],
        ..enclave_tls::compat_provider()
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(classical))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(&ca))
        .with_no_client_auth();
    assert!(
        get(&client(tls), &format!("{front}/healthz"))
            .await
            .is_err()
    );

    // Certificate replaced in place (an ACME renewal): new connections
    // get the new one, under a CA the old client doesn't know.
    let second = dir.join("second");
    std::fs::create_dir_all(&second).unwrap();
    let (ca2, chain2, key2) = ca_and_leaf(&second, "127.0.0.1");
    certs.set_pem(&chain2, &key2).unwrap();
    let new_ca = client(enclave_tls::client_config(roots(&ca2)).unwrap());
    assert_eq!(
        get(&new_ca, &format!("{front}/healthz")).await.unwrap().0,
        200
    );
    let old_ca = client(enclave_tls::client_config(roots(&ca)).unwrap());
    assert!(get(&old_ca, &format!("{front}/healthz")).await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn witness_proxy_passes_only_method_path_and_body() {
    let dir = temp("proxy");
    let (ca, chain, key) = ca_and_leaf(&dir, "127.0.0.1");
    let certs = Arc::new(CertStore::default());
    certs.set_pem(&chain, &key).unwrap();
    let front = start_front(&dir, Some(start_echo().await), certs).await;
    let http = client(enclave_tls::client_config(roots(&ca)).unwrap());
    let req = hyper::Request::post(format!("{front}/witness/v1/cosign"))
        .header("x-forwarded-for", "203.0.113.9")
        .header("user-agent", "telltale/1.0")
        .header("cookie", "a=b")
        .body(Full::new(Bytes::from_static(b"heads")))
        .unwrap();
    let res = http.request(req).await.unwrap();
    assert_eq!(res.status(), 200);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.starts_with("POST /witness/v1/cosign "), "{body}");
    for leaked in [
        "x-forwarded-for",
        "user-agent",
        "cookie",
        "x-real-ip",
        "forwarded",
    ] {
        assert!(
            !body.contains(leaked),
            "{leaked} reached the witness: {body}"
        );
    }

    // Without a witness configured, the API isn't there.
    let (ca, chain, key) = ca_and_leaf(&dir, "127.0.0.1");
    let certs = Arc::new(CertStore::default());
    certs.set_pem(&chain, &key).unwrap();
    let bare = start_front(&dir, None, certs).await;
    let http = client(enclave_tls::client_config(roots(&ca)).unwrap());
    assert_eq!(
        get(&http, &format!("{bare}/witness/v1/descriptor"))
            .await
            .unwrap()
            .0,
        404
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn http_side_answers_acme_and_redirects() {
    let challenges = Challenges::default();
    challenges
        .write()
        .unwrap()
        .insert("tok123".into(), "tok123.thumb".into());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let router = enclave_front::http_router("front.test".into(), Arc::clone(&challenges));
    tokio::spawn(async move { axum::serve(l, router).await });
    let http: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let get = |path: &str| {
        let req = hyper::Request::get(format!("http://{addr}{path}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let fut = http.request(req);
        async move {
            let res = fut.await.unwrap();
            let status = res.status().as_u16();
            let loc = res
                .headers()
                .get("location")
                .map(|v| v.to_str().unwrap().to_string());
            let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
            (status, loc, body)
        }
    };
    let (s, _, b) = get("/.well-known/acme-challenge/tok123").await;
    assert_eq!((s, b.as_slice()), (200, b"tok123.thumb".as_slice()));
    assert_eq!(get("/.well-known/acme-challenge/other").await.0, 404);
    let (s, loc, _) = get("/.well-known/enclave?x=1").await;
    assert_eq!(s, 308);
    assert_eq!(
        loc.as_deref(),
        Some("https://front.test/.well-known/enclave?x=1")
    );
}

#[test]
fn self_signed_certificate_installs_and_has_a_lifetime() {
    let (chain, key) = enclave_front::self_signed("front.test").unwrap();
    CertStore::default().set_pem(&chain, &key).unwrap();
    let days = enclave_front::acme::days_left(&chain, now() as i64).unwrap();
    assert!(days > enclave_front::acme::RENEW_DAYS, "{days}");
    assert!(CertStore::default().set_pem("not pem", &key).is_err());
}

/// The whole ACME flow against pebble: an account, an HTTP-01 answer from
/// the front's HTTP side, a certificate on disk (key 0600) and in the
/// store, served over the Enclave profile and trusted under pebble's root;
/// a second `ensure` keeps it.
#[tokio::test(flavor = "multi_thread")]
async fn acme_certificate_from_pebble() {
    let Ok(directory) = std::env::var("ENCLAVE_PEBBLE_DIRECTORY") else {
        assert!(
            std::env::var_os("ENCLAVE_REQUIRE_INTEROP").is_none(),
            "ENCLAVE_PEBBLE_DIRECTORY must be set"
        );
        eprintln!("ENCLAVE_PEBBLE_DIRECTORY not set: runs in CI's tls-interop job");
        return;
    };
    let ca_root = PathBuf::from(std::env::var("ENCLAVE_PEBBLE_CA").unwrap());
    let http_port: u16 = std::env::var("ENCLAVE_PEBBLE_HTTP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5002);
    let dir = temp("acme");
    let challenges = Challenges::default();
    let l = tokio::net::TcpListener::bind(("127.0.0.1", http_port))
        .await
        .unwrap();
    let router = enclave_front::http_router("localhost".into(), Arc::clone(&challenges));
    tokio::spawn(async move { axum::serve(l, router).await });

    let cfg = enclave_front::acme::AcmeConfig {
        domain: "localhost".into(),
        email: Some("ops@example.org".into()),
        directory,
        ca_root: Some(ca_root.clone()),
        data_dir: dir.clone(),
    };
    let certs = Arc::new(CertStore::default());
    let t = now() as i64;
    enclave_front::acme::ensure(&cfg, &challenges, &certs, t)
        .await
        .unwrap();
    assert!(certs.ready());
    assert!(challenges.read().unwrap().is_empty(), "answers cleaned up");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let chain = std::fs::read_to_string(dir.join("cert.pem")).unwrap();
    assert!(enclave_front::acme::days_left(&chain, t).unwrap() > 0);

    // Served under pebble's issuing root (from its management API).
    {
        let root_url = std::env::var("ENCLAVE_PEBBLE_ROOT_URL").unwrap();
        let mgmt = client(
            rustls::ClientConfig::builder_with_provider(Arc::new(enclave_tls::compat_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots(&ca_root))
                .with_no_client_auth(),
        );
        let (_, _, root) = get(&mgmt, &root_url).await.unwrap();
        std::fs::write(dir.join("issuer.pem"), &root).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let site = Site::new(dir.clone(), None).router();
        tokio::spawn(enclave_front::serve_https(l, site, Arc::clone(&certs)));
        let http = client(enclave_tls::client_config(roots(&dir.join("issuer.pem"))).unwrap());
        assert_eq!(
            get(&http, &format!("https://localhost:{port}/healthz"))
                .await
                .unwrap()
                .2,
            b"ok"
        );
    }

    // Checked again: kept while it has more than RENEW_DAYS left, renewed
    // otherwise (pebble picks among its profiles, one of them 6 days).
    let before = std::fs::read(dir.join("cert.pem")).unwrap();
    let left = enclave_front::acme::days_left(&chain, t).unwrap();
    enclave_front::acme::ensure(&cfg, &challenges, &certs, t)
        .await
        .unwrap();
    let after = std::fs::read(dir.join("cert.pem")).unwrap();
    if left > enclave_front::acme::RENEW_DAYS {
        assert_eq!(after, before, "{left} days left: kept");
    } else {
        assert_ne!(after, before, "{left} days left: renewed");
    }
    assert!(dir.join("acme-account.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A certificate on disk with more than `RENEW_DAYS` left is used as is:
/// the CA (here an address nothing answers on) is never asked. One with
/// fewer days left is renewed, so the unreachable CA makes that fail.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_certificate_on_disk_is_kept() {
    let dir = temp("keep");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = |y| {
        let mut p = rcgen::CertificateParams::new(vec!["front.test".to_string()]).unwrap();
        p.not_after = rcgen::date_time_ymd(y, 1, 1);
        p.self_signed(&key).unwrap().pem()
    };
    std::fs::write(dir.join("cert.pem"), cert(2100)).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    let cfg = enclave_front::acme::AcmeConfig {
        domain: "front.test".into(),
        email: None,
        directory: "https://127.0.0.1:9/dir".into(),
        ca_root: None,
        data_dir: dir.clone(),
    };
    let certs = CertStore::default();
    let challenges = Challenges::default();
    enclave_front::acme::ensure(&cfg, &challenges, &certs, now() as i64)
        .await
        .unwrap();
    assert!(certs.ready());
    // Expiring within RENEW_DAYS: renewal is attempted (and fails here).
    std::fs::write(dir.join("cert.pem"), cert(2000)).unwrap();
    assert!(
        enclave_front::acme::ensure(&cfg, &challenges, &CertStore::default(), now() as i64)
            .await
            .is_err()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
