//! A SOCKS5 server (RFC 1928) with user/password authentication
//! (RFC 1929) that only connects: what a mixnet client needs to reach its
//! gateway through Tor, and nothing else.

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A connection the dialer opened.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// How connections are made (through Tor in the shipped build).
#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    /// Open a stream to `host:port`. `host` is a name or an address; names
    /// are resolved by the dialer (at the Tor exit), never locally.
    async fn dial(&self, host: &str, port: u16) -> std::io::Result<Box<dyn Stream>>;
}

/// Log each connection's destination to stderr (`--report`, for tests:
/// off in normal use, where nothing about connections is written).
pub static REPORT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

const VERSION: u8 = 5;
const USER_PASSWORD: u8 = 2;
const NO_METHOD: u8 = 0xff;
const CONNECT: u8 = 1;

/// Reply codes (RFC 1928 §6).
const SUCCEEDED: u8 = 0;
const FAILURE: u8 = 1;
const NOT_ALLOWED: u8 = 2;
const COMMAND_NOT_SUPPORTED: u8 = 7;
const ADDRESS_NOT_SUPPORTED: u8 = 8;

fn refused() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, "socks: refused")
}

/// Accept connections on `listener` and serve each: authenticate with
/// [`crate::USER`] and `secret`, then connect through `dialer` and relay.
pub async fn serve(listener: TcpListener, secret: Arc<String>, dialer: Arc<dyn Dialer>) {
    loop {
        let Ok((sock, _)) = listener.accept().await else {
            continue;
        };
        let secret = Arc::clone(&secret);
        let dialer = Arc::clone(&dialer);
        tokio::spawn(async move {
            let _ = session(sock, &secret, dialer.as_ref()).await;
        });
    }
}

/// One SOCKS5 session.
pub async fn session(
    mut sock: TcpStream,
    secret: &str,
    dialer: &dyn Dialer,
) -> std::io::Result<()> {
    // Greeting: version, methods. Only user/password is acceptable.
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(refused());
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&USER_PASSWORD) {
        sock.write_all(&[VERSION, NO_METHOD]).await?;
        return Err(refused());
    }
    sock.write_all(&[VERSION, USER_PASSWORD]).await?;

    // RFC 1929: ver 1, user, password.
    let mut v = [0u8; 1];
    sock.read_exact(&mut v).await?;
    let user = read_short(&mut sock).await?;
    let password = read_short(&mut sock).await?;
    let ok = v[0] == 1 && user == crate::USER.as_bytes() && same(&password, secret.as_bytes());
    sock.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    if !ok {
        return Err(refused());
    }

    // Request: ver, cmd, rsv, address, port.
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != VERSION {
        return Err(refused());
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => String::from_utf8(read_short(&mut sock).await?).map_err(|_| refused())?,
        4 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            reply(&mut sock, ADDRESS_NOT_SUPPORTED).await?;
            return Err(refused());
        }
    };
    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if req[1] != CONNECT {
        reply(&mut sock, COMMAND_NOT_SUPPORTED).await?;
        return Err(refused());
    }
    if host.is_empty() || port == 0 {
        reply(&mut sock, NOT_ALLOWED).await?;
        return Err(refused());
    }
    if REPORT.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("enclave-tord: connect {host}:{port}");
    }
    let mut far = match dialer.dial(&host, port).await {
        Ok(s) => s,
        Err(e) => {
            if REPORT.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("enclave-tord: connect {host}:{port} failed: {e}");
            }
            reply(&mut sock, FAILURE).await?;
            return Err(e);
        }
    };
    reply(&mut sock, SUCCEEDED).await?;
    tokio::io::copy_bidirectional(&mut sock, &mut far).await?;
    Ok(())
}

async fn read_short(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut n = [0u8; 1];
    sock.read_exact(&mut n).await?;
    let mut b = vec![0u8; usize::from(n[0])];
    sock.read_exact(&mut b).await?;
    Ok(b)
}

/// A reply with the unspecified IPv4 address (the client doesn't need
/// to know where the Tor exit bound).
async fn reply(sock: &mut TcpStream, code: u8) -> std::io::Result<()> {
    sock.write_all(&[VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
}

/// Equal, in time independent of where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// The client side, as `enclave-nymd` uses it: authenticate with `secret`
/// and connect to `host:port` through the proxy at `proxy`.
pub async fn connect(
    proxy: std::net::SocketAddr,
    secret: &str,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[VERSION, 1, USER_PASSWORD]).await?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await?;
    if m != [VERSION, USER_PASSWORD] {
        return Err(refused());
    }
    let short = |b: &[u8]| -> std::io::Result<u8> { u8::try_from(b.len()).map_err(|_| refused()) };
    let mut auth = vec![1, short(crate::USER.as_bytes())?];
    auth.extend_from_slice(crate::USER.as_bytes());
    auth.push(short(secret.as_bytes())?);
    auth.extend_from_slice(secret.as_bytes());
    s.write_all(&auth).await?;
    let mut a = [0u8; 2];
    s.read_exact(&mut a).await?;
    if a != [1, 0] {
        return Err(refused());
    }
    let mut req = vec![VERSION, CONNECT, 0, 3, short(host.as_bytes())?];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[1] != SUCCEEDED {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("socks: connect failed ({})", r[1]),
        ));
    }
    // The bound address, which we don't use.
    let rest = match r[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await?;
            usize::from(n[0])
        }
        _ => return Err(refused()),
    } + 2;
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::DirectDialer;

    async fn proxy(secret: &str) -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve(l, Arc::new(secret.into()), Arc::new(DirectDialer)));
        addr
    }

    async fn echo() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn connects_with_the_secret_only() {
        let p = proxy("s3cret").await;
        let port = echo().await;
        let mut s = connect(p, "s3cret", "localhost", port).await.unwrap();
        s.write_all(b"through the proxy").await.unwrap();
        let mut b = [0u8; 17];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"through the proxy");

        assert!(connect(p, "wrong", "localhost", port).await.is_err());
    }

    #[tokio::test]
    async fn refuses_no_auth_bind_and_udp() {
        let p = proxy("s3cret").await;
        // No authentication offered.
        let mut s = TcpStream::connect(p).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [5, NO_METHOD]);

        // BIND and UDP ASSOCIATE after a good login.
        for cmd in [2u8, 3] {
            let mut s = TcpStream::connect(p).await.unwrap();
            s.write_all(&[5, 1, 2]).await.unwrap();
            s.read_exact(&mut m).await.unwrap();
            let mut auth = vec![1, 7];
            auth.extend_from_slice(b"enclave");
            auth.push(6);
            auth.extend_from_slice(b"s3cret");
            s.write_all(&auth).await.unwrap();
            s.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [1, 0]);
            s.write_all(&[5, cmd, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut r = [0u8; 10];
            s.read_exact(&mut r).await.unwrap();
            assert_eq!(r[1], COMMAND_NOT_SUPPORTED, "command {cmd}");
        }
    }
}
