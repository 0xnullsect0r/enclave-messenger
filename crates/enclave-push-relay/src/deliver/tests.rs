//! Delivery against local stand-ins for APNs, Google's token endpoint, FCM
//! and a UnifiedPush distributor, over TLS with a local CA.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use http_body_util::BodyExt as _;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey,
};
use std::sync::Mutex;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A test-only RSA key standing in for a service account's.
const RSA_KEY: &[u8] = include_bytes!("test-rsa2048.pk8");

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    version: hyper::Version,
    headers: hyper::HeaderMap,
    body: Vec<u8>,
}

/// A TLS server for `localhost` answering every request with `answer` and
/// recording what came, and a client trust store for it.
async fn stand_in(
    answer: fn(&str) -> (u16, &'static str),
    alpn: &[&[u8]],
) -> (u16, Arc<Mutex<Vec<Seen>>>, RootCertStore, Arc<Mutex<u32>>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.der().to_vec())],
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(Mutex::new(0u32));
    let (s2, c2) = (Arc::clone(&seen), Arc::clone(&connections));
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            *c2.lock().unwrap() += 1;
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&s2);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let seen = Arc::clone(&seen);
                        async move {
                            let (parts, body) = req.into_parts();
                            let body = body.collect().await.unwrap().to_bytes().to_vec();
                            let (status, reply) = answer(parts.uri.path());
                            seen.lock().unwrap().push(Seen {
                                method: parts.method.to_string(),
                                path: parts.uri.path().to_string(),
                                version: parts.version,
                                headers: parts.headers,
                                body,
                            });
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .body(http_body_util::Full::new(Bytes::from(reply)))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, seen, roots, connections)
}

fn jwt_parts(t: &str) -> (serde_json::Value, serde_json::Value, String, Vec<u8>) {
    let p: Vec<&str> = t.split('.').collect();
    assert_eq!(p.len(), 3);
    (
        serde_json::from_slice(&b64_decode(p[0]).unwrap()).unwrap(),
        serde_json::from_slice(&b64_decode(p[1]).unwrap()).unwrap(),
        format!("{}.{}", p[0], p[1]),
        b64_decode(p[2]).unwrap(),
    )
}

fn header(s: &Seen, k: &str) -> String {
    s.headers.get(k).unwrap().to_str().unwrap().to_string()
}

#[test]
fn base64() {
    for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"\xff\xfe\xfd\x00"] {
        assert_eq!(b64_decode(&b64(data, false)).unwrap(), data);
        assert_eq!(b64_decode(&b64(data, true)).unwrap(), data);
    }
    assert_eq!(b64(b"foob", false), "Zm9vYg==");
    assert_eq!(b64(&[0xfb, 0xff], true), "-_8");
}

#[test]
fn urls() {
    let t = Target::parse("https://api.push.apple.com/3/device/ab").unwrap();
    assert_eq!(
        (t.host.as_str(), t.port, t.path.as_str()),
        ("api.push.apple.com", 443, "/3/device/ab")
    );
    let t = Target::parse("http://[::1]:8080").unwrap();
    assert_eq!(
        (t.host.as_str(), t.port, t.path.as_str()),
        ("::1", 8080, "/")
    );
    assert_eq!(Target::parse("https://[::1]/x").unwrap().port, 443);
    assert!(Target::parse("ftp://x/").is_err());
    assert!(Target::parse("https://user@x/").is_err());
    assert!(Target::parse("https://x:99999/").is_err());
}

fn delivery(platform: Platform, token: &[u8], capsule: Vec<u8>) -> Delivery {
    Delivery {
        platform,
        token: token.to_vec(),
        wake_class: 0,
        capsule,
    }
}

#[tokio::test]
async fn apns_over_http2_with_a_provider_token() {
    let (port, seen, roots, connections) = stand_in(|_| (200, ""), &[b"h2"]).await;
    let rng = SystemRandom::new();
    let p8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let public = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, p8.as_ref(), &rng)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    // As Apple issues it: PEM.
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        b64(p8.as_ref(), false)
    );
    let d = Deliverer::with_roots(
        Some(ApnsConfig {
            team_id: "TEAM123456".into(),
            key_id: "KEY1234567".into(),
            key: pem.into_bytes(),
            topic: "com.aricummings.enclave".into(),
            endpoint: format!("https://localhost:{port}"),
        }),
        None,
        roots,
    )
    .unwrap();
    assert_eq!(d.platforms(), [Platform::UnifiedPush, Platform::Apns]);
    let capsule = vec![0x5a; 1024];
    d.deliver(&delivery(Platform::Apns, &[0xab, 0x01], capsule.clone()))
        .await
        .unwrap();
    d.deliver(&delivery(Platform::Apns, &[0xcd], Vec::new()))
        .await
        .unwrap();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(*connections.lock().unwrap(), 1, "the connection is kept");
    let s = &seen[0];
    assert_eq!(
        (s.method.as_str(), s.path.as_str()),
        ("POST", "/3/device/ab01")
    );
    assert_eq!(s.version, hyper::Version::HTTP_2);
    assert_eq!(header(s, "apns-topic"), "com.aricummings.enclave");
    assert_eq!(header(s, "apns-push-type"), "alert");
    let body: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
    assert_eq!(body["aps"]["mutable-content"], 1);
    assert_eq!(body["aps"]["alert"]["body"], "New message");
    assert_eq!(b64_decode(body["c"].as_str().unwrap()).unwrap(), capsule);
    let none: serde_json::Value = serde_json::from_slice(&seen[1].body).unwrap();
    assert!(none.get("c").is_none());
    // The provider token: ES256 over the header and claims, reused.
    let auth = header(s, "authorization");
    let token = auth.strip_prefix("bearer ").unwrap();
    assert_eq!(header(&seen[1], "authorization"), auth);
    let (h, c, signed, sig) = jwt_parts(token);
    assert_eq!(
        (h["alg"].as_str(), h["kid"].as_str()),
        (Some("ES256"), Some("KEY1234567"))
    );
    assert_eq!(c["iss"], "TEAM123456");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public)
        .verify(signed.as_bytes(), &sig)
        .unwrap();
}

#[tokio::test]
async fn fcm_with_a_service_account() {
    let (port, seen, roots, _) = stand_in(
        |path| match path {
            "/token" => (
                200,
                r#"{"access_token":"ya29.test","expires_in":3599,"token_type":"Bearer"}"#,
            ),
            _ => (200, r#"{"name":"projects/p/messages/1"}"#),
        },
        &[b"h2", b"http/1.1"],
    )
    .await;
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        b64(RSA_KEY, false)
    );
    let json = serde_json::json!({
        "type": "service_account",
        "project_id": "enclave-test",
        "private_key": pem,
        "client_email": "relay@enclave-test.iam.gserviceaccount.com",
        "token_uri": format!("https://localhost:{port}/token"),
    });
    let mut cfg = FcmConfig::from_service_account(json.to_string().as_bytes()).unwrap();
    cfg.endpoint = format!("https://localhost:{port}");
    let d = Deliverer::with_roots(None, Some(cfg), roots).unwrap();
    for t in [&b"fcm-token-1"[..], b"fcm-token-2"] {
        d.deliver(&delivery(Platform::Fcm, t, vec![1; 1024]))
            .await
            .unwrap();
    }
    let seen = seen.lock().unwrap().clone();
    let paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/token",
            "/v1/projects/enclave-test/messages:send",
            "/v1/projects/enclave-test/messages:send"
        ],
        "one access token for both"
    );
    // The assertion: RS256, signed by the service account's key.
    let form = String::from_utf8(seen[0].body.clone()).unwrap();
    let assertion = form.split("assertion=").nth(1).unwrap();
    assert!(form.starts_with("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&"));
    let (h, c, signed, sig) = jwt_parts(assertion);
    assert_eq!(h["alg"], "RS256");
    assert_eq!(c["iss"], "relay@enclave-test.iam.gserviceaccount.com");
    assert_eq!(
        c["scope"],
        "https://www.googleapis.com/auth/firebase.messaging"
    );
    assert_eq!(c["aud"], format!("https://localhost:{port}/token"));
    let public = RsaKeyPair::from_pkcs8(RSA_KEY)
        .unwrap()
        .public()
        .as_ref()
        .to_vec();
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
        .verify(signed.as_bytes(), &sig)
        .unwrap();
    // The message: content-free, high priority.
    let s = &seen[1];
    assert_eq!(header(s, "authorization"), "Bearer ya29.test");
    let body: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
    assert_eq!(body["message"]["token"], "fcm-token-1");
    assert_eq!(body["message"]["data"], serde_json::json!({"w": "1"}));
    assert_eq!(body["message"]["android"]["priority"], "high");
    assert!(!s.body.windows(4).any(|w| w == b"AQEB"), "no capsule");
}

#[tokio::test]
async fn unified_push_over_tls_and_plain() {
    // A distributor that speaks only HTTP/1.1.
    let (port, seen, roots, _) = stand_in(
        |path| {
            if path == "/gone" {
                (404, "")
            } else {
                (201, "")
            }
        },
        &[b"http/1.1"],
    )
    .await;
    let d = Deliverer::with_roots(None, None, roots).unwrap();
    let url = format!("https://localhost:{port}/up/AbC123");
    d.deliver(&delivery(
        Platform::UnifiedPush,
        url.as_bytes(),
        vec![2; 1024],
    ))
    .await
    .unwrap();
    let s = seen.lock().unwrap()[0].clone();
    assert_eq!((s.method.as_str(), s.path.as_str()), ("POST", "/up/AbC123"));
    assert_eq!(s.version, hyper::Version::HTTP_11);
    assert_eq!(s.body, b"1", "one fixed byte, no content");
    assert_eq!(header(&s, "ttl"), "60");
    let gone = format!("https://localhost:{port}/gone");
    assert!(matches!(
        d.deliver(&delivery(
            Platform::UnifiedPush,
            gone.as_bytes(),
            Vec::new()
        ))
        .await,
        Err(DeliverError::Refused(404, _))
    ));
    // A certificate nobody vouches for is refused.
    let strict = Deliverer::new(None, None).unwrap();
    assert!(matches!(
        strict
            .deliver(&delivery(Platform::UnifiedPush, url.as_bytes(), Vec::new()))
            .await,
        Err(DeliverError::Net(_))
    ));
    // Nothing configured for APNs or FCM.
    assert!(matches!(
        d.deliver(&delivery(Platform::Apns, b"x", Vec::new())).await,
        Err(DeliverError::NotConfigured)
    ));
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(
        (d.stats.sent.load(Relaxed), d.stats.failed.load(Relaxed)),
        (1, 2)
    );

    // Plain http:// (a distributor on the device's own network).
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(b"HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });
    let url = format!("http://{addr}/up/x");
    d.deliver(&delivery(Platform::UnifiedPush, url.as_bytes(), Vec::new()))
        .await
        .unwrap();
    let req = h.await.unwrap().to_lowercase();
    assert!(req.starts_with("post /up/x http/1.1\r\n"), "{req}");
    assert!(req.contains(&format!("host: {addr}")), "{req}");
    assert!(
        req.contains("content-length: 1\r\n"),
        "one fixed byte: {req}"
    );
}
