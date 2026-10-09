//! The gate over HTTP, as a device reaches it through the front: key,
//! challenge, tokens for work, a ticketbook for a token, and a token
//! refused the second time.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use async_trait::async_trait;
use enclave_credgate::{Config, Gate, GateError, TicketSource, tokens_finish, tokens_request};
use enclave_crypto::rng::HedgedRng;
use enclave_tokens::privpass::IssuerPublic;
use std::sync::Arc;

/// Echoes the request, so the test sees it arrived intact.
struct Echo;

#[async_trait]
impl TicketSource for Echo {
    async fn obtain(&self, request: &[u8]) -> Result<Vec<u8>, GateError> {
        Ok([b"book:".as_slice(), request].concat())
    }
    async fn partial_keys(&self) -> Result<Vec<u8>, GateError> {
        Ok(b"keys".to_vec())
    }
}

async fn post(base: &str, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
    request("POST", base, path, body).await
}

async fn request(method: &str, base: &str, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = base.trim_start_matches("http://");
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: gate\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(&body).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status: u16 = std::str::from_utf8(&buf[9..12]).unwrap().parse().unwrap();
    (status, buf[split + 4..].to_vec())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_gets_a_ticketbook_over_http() {
    let gate = Gate::open(
        zeroize::Zeroizing::new([9; 32]),
        Config {
            effort: 1,
            tokens_per_proof: 2,
            issuer_name: "credgate.test".into(),
            ..Config::default()
        },
        Arc::new(Echo),
        None,
    )
    .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, Arc::new(gate).router()).await });

    let (status, keys) = request("GET", &base, "/credgate/v1/partial-keys", vec![]).await;
    assert_eq!((status, keys.as_slice()), (200, b"keys".as_slice()));
    let (status, key) = request("GET", &base, "/credgate/v1/key", vec![]).await;
    assert_eq!(status, 200);
    let pk = IssuerPublic(key[4..].try_into().unwrap());
    let (status, challenge) = post(&base, "/credgate/v1/challenge", vec![]).await;
    assert_eq!(status, 200);
    let mut rng = HedgedRng::new().unwrap();
    let (body, pending) = tokens_request(&challenge, pk, "credgate.test", 2, &mut rng).unwrap();
    let (status, answer) = post(&base, "/credgate/v1/tokens", body).await;
    assert_eq!(status, 200);
    let tokens = tokens_finish(pending, &answer).unwrap();

    let mut redeem = tokens[0].encode();
    redeem.extend_from_slice(b"withdrawal request");
    let (status, book) = post(&base, "/credgate/v1/ticketbook", redeem.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(book, b"book:withdrawal request");
    let (status, _) = post(&base, "/credgate/v1/ticketbook", redeem).await;
    assert_eq!(status, 409, "a token is good once");
}
