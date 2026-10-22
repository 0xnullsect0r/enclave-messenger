//! The server's stream framing (`u32 len ‖ request`): what the Nym ingress,
//! an onion service and the development transport all speak.
#![allow(clippy::unwrap_used)]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn frame(s: &mut tokio::net::TcpStream, len: u32, body: &[u8]) -> Vec<u8> {
    s.write_all(&len.to_be_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut n = [0u8; 4];
    s.read_exact(&mut n).await.unwrap();
    let mut b = vec![0u8; u32::from_be_bytes(n) as usize];
    s.read_exact(&mut b).await.unwrap();
    b
}

/// RFC 0010: a request marked one way gets an empty acknowledgement
/// instead of its sealed reply, on the same stream as requests that want
/// theirs.
#[tokio::test]
async fn oneway_bit_gets_empty_ack() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let addr = format!("127.0.0.1:{port}");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_enclave-server"))
        .arg(&addr)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut s = None;
    for _ in 0..100 {
        if let Ok(c) = tokio::net::TcpStream::connect(&addr).await {
            s = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut s = s.expect("the development server didn't start");
    // The request keys (an empty request).
    assert!(!frame(&mut s, 0, &[]).await.is_empty());
    let junk = vec![7u8; enclave_wire::UNIT_LEN];
    // A unit that wants its reply gets one (sealed, here a refusal)…
    assert!(!frame(&mut s, junk.len() as u32, &junk).await.is_empty());
    // …and one marked one way only the empty acknowledgement.
    let len = junk.len() as u32 | enclave_wire::STREAM_ONEWAY;
    assert!(frame(&mut s, len, &junk).await.is_empty());
    // The stream still serves requests after it.
    assert!(!frame(&mut s, 0, &[]).await.is_empty());
    let _ = child.kill().await;
}
