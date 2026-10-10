//! History over the local network, window to window
//! (`docs/03-identity.md` §4.3 step 8).
//!
//! The vault hands the window the sealed chunks of a history file and a
//! one-time token; the window listens on the local network and gives the
//! chunks, in order, to a connection that first presents the token. On
//! the other device the vault tells its window the addresses and the
//! token (which came end to end encrypted, through own-device sync); the
//! window fetches the chunks and hands them to its vault, which opens
//! them. Only ciphertext crosses the network or either window: the keys
//! never leave the vaults. Nothing is announced on the network (no mDNS):
//! the addresses travel in the encrypted message. Serving stops when the
//! other device has the history, or after [`SERVE_FOR`].
//!
//! Wire: the fetcher sends the 16-byte token; the server answers
//! `u32 n ‖ n × (u32 len ‖ chunk)`, big-endian, and closes.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long history is served at most.
pub const SERVE_FOR: Duration = Duration::from_secs(30 * 60);
/// Largest chunk accepted (they are about 14 KB).
const MAX_CHUNK: usize = 64 * 1024;
/// Most chunks accepted (a history file is at most 100 MB).
const MAX_CHUNKS: usize = 8_000;
/// Chunks per batch handed to the vault.
const BATCH: usize = enclave_ipc::LAN_BATCH;

/// History being served; dropping it stops.
pub struct Serving {
    stop: Arc<AtomicBool>,
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// This computer's address on the local network the system would use to
/// reach `probe` (a documentation address: nothing is sent).
fn local_ip(bind: &str, probe: &str) -> Option<IpAddr> {
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(probe).ok()?;
    let ip = s.local_addr().ok()?.ip();
    let link_local = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    (!ip.is_loopback() && !ip.is_unspecified() && !link_local).then_some(ip)
}

/// Equal without leaking where they differ.
fn same(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn answer(mut s: TcpStream, token: &[u8; 16], chunks: &[Vec<u8>]) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_nodelay(true)?;
    let mut got = [0u8; 16];
    s.read_exact(&mut got)?;
    if !same(&got, token) {
        return Ok(());
    }
    s.write_all(&(chunks.len() as u32).to_be_bytes())?;
    for c in chunks {
        s.write_all(&(c.len() as u32).to_be_bytes())?;
        s.write_all(c)?;
    }
    s.flush()
}

/// Serve `chunks` to whoever presents `token`, on IPv4 and IPv6; the
/// addresses to give the other device (none: this computer isn't on a
/// network it can serve on).
pub fn serve(token: [u8; 16], chunks: Vec<Vec<u8>>) -> (Serving, Vec<String>) {
    let stop = Arc::new(AtomicBool::new(false));
    let chunks = Arc::new(chunks);
    let mut addrs = Vec::new();
    for (bind, probe) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        let Some(ip) = local_ip(bind, probe) else {
            continue;
        };
        let Ok(listener) = TcpListener::bind(SocketAddr::new(ip, 0)) else {
            continue;
        };
        let Ok(addr) = listener.local_addr() else {
            continue;
        };
        if listener.set_nonblocking(true).is_err() {
            continue;
        }
        addrs.push(addr.to_string());
        let (stop, chunks) = (Arc::clone(&stop), Arc::clone(&chunks));
        let _ = std::thread::Builder::new()
            .name("enclave-lan-serve".into())
            .spawn(move || {
                let until = Instant::now() + SERVE_FOR;
                while !stop.load(Ordering::SeqCst) && Instant::now() < until {
                    match listener.accept() {
                        Ok((s, _)) => {
                            let _ = s.set_nonblocking(false);
                            let _ = answer(s, &token, &chunks);
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(200)),
                    }
                }
            });
    }
    (Serving { stop }, addrs)
}

/// What a fetch reports.
pub enum Fetched {
    /// Chunks, in order; `true` on the last batch.
    Batch(Vec<Vec<u8>>, bool),
    /// None of the addresses gave the history.
    Failed,
}

fn read_all(addr: &SocketAddr, token: &[u8; 16], count: u32) -> std::io::Result<Vec<Vec<u8>>> {
    let mut s = TcpStream::connect_timeout(addr, Duration::from_secs(3))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.write_all(token)?;
    let mut n = [0u8; 4];
    s.read_exact(&mut n)?;
    let n = u32::from_be_bytes(n);
    if n != count || n as usize > MAX_CHUNKS {
        return Err(std::io::Error::other("not the history offered"));
    }
    let mut chunks = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let mut len = [0u8; 4];
        s.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_CHUNK {
            return Err(std::io::Error::other("chunk too large"));
        }
        let mut c = vec![0u8; len];
        s.read_exact(&mut c)?;
        chunks.push(c);
    }
    Ok(chunks)
}

/// Fetch `count` chunks with `token` from the first of `addrs` that has
/// them, on a thread of its own; `report` gets them in batches, or
/// `Failed`.
pub fn fetch(
    token: [u8; 16],
    addrs: Vec<String>,
    count: u32,
    report: impl Fn(Fetched) + Send + 'static,
) {
    let _ = std::thread::Builder::new()
        .name("enclave-lan-fetch".into())
        .spawn(move || {
            for a in addrs.iter().filter_map(|a| a.parse::<SocketAddr>().ok()) {
                // Whole, or not at all: a broken connection doesn't hand the
                // vault half a file.
                if let Ok(chunks) = read_all(&a, &token, count) {
                    let batches: Vec<Vec<Vec<u8>>> =
                        chunks.chunks(BATCH).map(<[Vec<u8>]>::to_vec).collect();
                    if batches.is_empty() {
                        report(Fetched::Batch(Vec::new(), true));
                    }
                    let last = batches.len();
                    for (i, b) in batches.into_iter().enumerate() {
                        report(Fetched::Batch(b, i + 1 == last));
                    }
                    return;
                }
            }
            report(Fetched::Failed);
        });
}

/// A token from its hex form.
pub fn unhex(s: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    if s.len() != 32 {
        return None;
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Served chunks come back whole with the token and not without it.
    #[test]
    fn serves_with_the_token_only() {
        let token = [7u8; 16];
        let chunks: Vec<Vec<u8>> = (0..600u32).map(|i| vec![i as u8; 100]).collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let served = chunks.clone();
        std::thread::spawn(move || {
            for s in listener.incoming().take(2).flatten() {
                let _ = answer(s, &token, &served);
            }
        });
        assert!(read_all(&addr, &[8u8; 16], 600).is_err(), "wrong token");
        assert_eq!(read_all(&addr, &token, 600).unwrap(), chunks);
        assert_eq!(unhex(&"07".repeat(16)), Some(token));
        assert!(unhex("07").is_none());
    }
}
