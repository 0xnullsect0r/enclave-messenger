//! obfs4 bridges for arti, in this process (`docs/09-transport.md` §7,
//! censorship mode).
//!
//! arti reaches a bridge through a pluggable transport speaking SOCKS5 on
//! a loopback port (an "unmanaged" transport, `proxy_addr`): it asks to
//! CONNECT to the bridge's address and passes the bridge line's arguments
//! (`cert=…;iat-mode=…`) as the user name and password (pt-spec §3.5). This
//! serves that, wrapping each connection in obfs4 (the `obfs4` crate,
//! checked against lyrebird, the reference Go implementation), so no
//! pluggable-transport program has to ship or run.

use base64::Engine;
use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The Tor Project's built-in obfs4 bridges (`ci/tor/builtin-bridges.sh`,
/// from its Circumvention Settings API), one bridge line each.
pub const BUILTIN: &str = include_str!("../bridges/obfs4.txt");

/// The built-in bridge lines.
pub fn builtin() -> Vec<String> {
    BUILTIN
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Serve arti's connections to obfs4 bridges on `listener` until it fails.
pub async fn serve(listener: TcpListener) {
    while let Ok((s, _)) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(e) = session(s).await
                && crate::socks::REPORT.load(std::sync::atomic::Ordering::Relaxed)
            {
                eprintln!("enclave-tord: obfs4: {e}");
            }
        });
    }
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("obfs4: {what}"))
}

/// pt-spec §3.5: `k=v;k=v`, with `\` escaping `;`, `=` and `\`.
fn parse_args(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let (mut key, mut val, mut in_val, mut esc) = (String::new(), String::new(), false, false);
    for c in s.chars() {
        match (esc, c) {
            (true, c) => {
                if in_val {
                    val.push(c)
                } else {
                    key.push(c)
                }
                esc = false;
            }
            (false, '\\') => esc = true,
            (false, '=') if !in_val => in_val = true,
            (false, ';') => {
                out.insert(std::mem::take(&mut key), std::mem::take(&mut val));
                in_val = false;
            }
            (false, c) => {
                if in_val {
                    val.push(c)
                } else {
                    key.push(c)
                }
            }
        }
    }
    if !key.is_empty() {
        out.insert(key, val);
    }
    out
}

/// The obfs4 client for a bridge's `cert` (base64 of node id ‖ public key)
/// and `iat-mode`.
fn client(args: &HashMap<String, String>) -> io::Result<obfs4::Client> {
    let cert = args.get("cert").ok_or_else(|| bad("no cert"))?;
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(cert.trim_end_matches('='))
        .map_err(|_| bad("cert isn't base64"))?;
    if raw.len() != 52 {
        return Err(bad("cert isn't 52 bytes"));
    }
    let mut id = [0u8; 20];
    id.copy_from_slice(&raw[..20]);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[20..]);
    let iat = match args.get("iat-mode").map(String::as_str) {
        None | Some("0") => obfs4::proto::IAT::Off,
        Some("1") => obfs4::proto::IAT::Enabled,
        Some("2") => obfs4::proto::IAT::Paranoid,
        Some(_) => return Err(bad("unknown iat-mode")),
    };
    Ok(obfs4::ClientBuilder::default()
        .with_node_id(id)
        .with_node_pubkey(pk)
        .with_iat_mode(iat)
        .with_handshake_timeout(std::time::Duration::from_secs(60))
        .build())
}

async fn read_short(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let n = s.read_u8().await?;
    let mut b = vec![0u8; usize::from(n)];
    s.read_exact(&mut b).await?;
    Ok(b)
}

/// One connection from arti: SOCKS5 with the bridge's arguments as the
/// user name and password, then CONNECT to the bridge.
async fn session(mut s: TcpStream) -> io::Result<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(bad("not SOCKS5"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        s.write_all(&[5, 0xff]).await?;
        return Err(bad("no bridge arguments"));
    }
    s.write_all(&[5, 2]).await?;
    if s.read_u8().await? != 1 {
        return Err(bad("bad authentication version"));
    }
    let mut args = read_short(&mut s).await?;
    args.extend(read_short(&mut s).await?);
    while args.last() == Some(&0) {
        args.pop();
    }
    let args = parse_args(&String::from_utf8(args).map_err(|_| bad("arguments"))?);
    let client = match client(&args) {
        Ok(c) => c,
        Err(e) => {
            s.write_all(&[1, 1]).await?;
            return Err(e);
        }
    };
    s.write_all(&[1, 0]).await?;
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(bad("only CONNECT"));
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        3 => String::from_utf8(read_short(&mut s).await?).map_err(|_| bad("host"))?,
        _ => return Err(bad("address type")),
    };
    let port = s.read_u16().await?;
    let bridge = match TcpStream::connect((host.as_str(), port)).await {
        Ok(b) => b,
        Err(e) => {
            s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(e);
        }
    };
    let mut wrapped = match client.wrap(bridge).await {
        Ok(w) => w,
        Err(e) => {
            s.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(io::Error::other(format!("obfs4 handshake: {e}")));
        }
    };
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut s, &mut wrapped).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_arguments_parse() {
        let a = parse_args("cert=ab+c/d;iat-mode=1");
        assert_eq!(a.get("cert").map(String::as_str), Some("ab+c/d"));
        assert_eq!(a.get("iat-mode").map(String::as_str), Some("1"));
        let a = parse_args(r"k=a\;b\=c");
        assert_eq!(a.get("k").map(String::as_str), Some("a;b=c"));
        assert!(client(&parse_args("cert=AAAA")).is_err());
        assert!(builtin().iter().all(|l| l.starts_with("obfs4 ")));
        assert!(!builtin().is_empty());
    }

    /// arti's side of a bridge connection, against an obfs4 server from
    /// the same crate: through the SOCKS5 front, the bytes come back.
    #[tokio::test]
    async fn socks_front_carries_obfs4() {
        // An obfs4 server echoing what it gets.
        let builder = obfs4::ServerBuilder::<TcpStream>::default();
        let cert = builder.client_params();
        let server = builder.build();
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let (t, _) = up.accept().await.unwrap();
            let mut s = server.wrap(t).await.unwrap();
            let mut b = vec![0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
            s.flush().await.unwrap();
        });
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        tokio::spawn(serve(front));

        let mut c = TcpStream::connect(front_addr).await.unwrap();
        c.write_all(&[5, 1, 2]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 2]);
        let user = cert.replace(',', ";");
        let mut auth = vec![1, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.extend_from_slice(&[1, 0]);
        c.write_all(&auth).await.unwrap();
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [1, 0]);
        let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
        req.extend_from_slice(&up_addr.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0);
        c.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
    }
}
