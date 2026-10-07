//! Round trip over the TCP development transport against the real server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::KeyBundle;
use enclave_net::transport::{TcpTransport, Transport};
use enclave_rpc::api::{self, FLAG_CREATE, Status};
use enclave_server::{Config, Server};
use enclave_wire::{Op, RequestHeader};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// A server with a real identity, answering a zero-length request with its
/// signed key bundle. Returns its address and id.
async fn spawn_server() -> (std::net::SocketAddr, [u8; 16]) {
    let mut rng = HedgedRng::new().unwrap();
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let id = enclave_federation::server_id(identity.public());
    let day = (now() / 86_400) as u32;
    let mut server = Server::new(
        Config {
            id,
            effort_inbox: 0,
            ..Config::default()
        },
        day,
    )
    .unwrap();
    let key = server.public_key().unwrap();
    server.set_key_bundle(
        KeyBundle::sign(&identity, &[key], &mut rng)
            .unwrap()
            .encode(),
    );
    serve(server).await.map(|a| (a, id)).unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn serve(server: Server) -> std::io::Result<std::net::SocketAddr> {
    let server = Arc::new(Mutex::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                let mut buf = vec![0u8; n];
                sock.read_exact(&mut buf).await.unwrap();
                let reply = {
                    let mut s = server.lock().await;
                    if n == 0 {
                        s.key_bundle().to_vec()
                    } else {
                        s.handle(&buf, now())
                    }
                };
                sock.write_all(&(reply.len() as u32).to_be_bytes())
                    .await
                    .unwrap();
                sock.write_all(&reply).await.unwrap();
            });
        }
    });
    Ok(addr)
}

/// A server whose key bundle is signed by some other identity than the id
/// the client dials (a man in the middle, or the wrong address) is refused.
#[tokio::test]
async fn a_key_from_the_wrong_identity_is_refused() {
    let (addr, real) = spawn_server().await;
    let wrong = [0x77u8; 16];
    let t = TcpTransport::new(HashMap::from([(wrong, addr), (real, addr)]));
    assert!(matches!(
        t.server_key(&wrong).await,
        Err(enclave_net::NetError::Untrusted(_))
    ));
    assert!(t.server_key(&real).await.is_ok());
}

/// Maximum privacy never takes the direct route: with the private route
/// required, the development transport refuses everything, and works again
/// when it is not.
#[tokio::test]
async fn a_direct_connection_is_refused_in_maximum_privacy() {
    let (addr, real) = spawn_server().await;
    let t = TcpTransport::new(HashMap::from([(real, addr)]));
    t.require_private(true);
    assert!(matches!(
        t.server_key(&real).await,
        Err(enclave_net::NetError::Unavailable(_))
    ));
    t.require_private(false);
    assert!(t.server_key(&real).await.is_ok());
}

/// Routes parse in both forms, print back the same, and a TCP route
/// learned later is used; a Nym route is ignored by the TCP transport.
#[tokio::test]
async fn routes_parse_and_are_learned() {
    use enclave_net::transport::{Route, parse_route, parse_server};
    let hex = "00112233445566778899aabbccddeeff";
    let (id, r) = parse_route(&format!("{hex}=nym:abc.def@ghi")).unwrap();
    assert_eq!(r, Route::Nym("abc.def@ghi".into()));
    assert_eq!(r.to_string(), "nym:abc.def@ghi");
    assert_eq!(id[0], 0x00);
    assert_eq!(id[15], 0xff);
    assert!(parse_server(&format!("{hex}=nym:abc")).is_none());
    assert!(parse_route(&format!("{hex}=nym:")).is_none());
    assert!(parse_route("0011=127.0.0.1:1").is_none());
    let (_, r) = parse_route(&format!("{hex}=127.0.0.1:7443")).unwrap();
    assert_eq!(Route::parse(&r.to_string()), Some(r));

    let (addr, real) = spawn_server().await;
    let t = TcpTransport::new(HashMap::new());
    assert!(t.server_key(&real).await.is_err());
    t.set_route(real, Route::Nym("somewhere".into()));
    assert!(t.server_key(&real).await.is_err());
    t.set_route(real, Route::Tcp(addr));
    assert!(t.server_key(&real).await.is_ok());
}

#[tokio::test]
async fn tcp_roundtrip_creates_inbox_and_polls() {
    let (addr, id) = spawn_server().await;
    let t = TcpTransport::new(HashMap::from([(id, addr)]));
    let key = t.server_key(&id).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();

    let owner = [8u8; 32];
    let h = RequestHeader {
        op: Op::RegisterTokens,
        flags: FLAG_CREATE,
        mailbox: [6; 32],
        token: owner,
    };
    let (req, ex) =
        enclave_rpc::seal_request(&key, &h, &api::frame(&[], &mut rng).unwrap(), &mut rng).unwrap();
    let reply = t.exchange(&id, req).await.unwrap();
    let (rh, _) = ex.open_reply(&reply).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);

    let mut token = [0u8; 32];
    token[..24].copy_from_slice(&api::read_credential(&owner));
    let h = RequestHeader {
        op: Op::Poll,
        flags: 0,
        mailbox: [6; 32],
        token,
    };
    let (req, ex) = enclave_rpc::seal_poll(&key, &h, &mut rng).unwrap();
    let reply = t.exchange(&id, req).await.unwrap();
    let (rh, _) = ex.open_reply(&reply).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);
}
