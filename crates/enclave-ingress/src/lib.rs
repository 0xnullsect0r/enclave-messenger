//! The Nym ingress (`docs/09-transport.md` §1, `docs/12-servers.md` §6).
//!
//! The key-holding server never links a mixnet client: this sidecar does.
//! It takes each mixframe (`enclave_nym::frame::Request`) off the mixnet,
//! hands the sealed bytes to the server over the stack's internal network
//! with the server's own framing (`u32 len ‖ bytes`; a zero-length request
//! asks for the key bundle), and answers over the sender's reply blocks.
//! It sees only sealed bytes and never learns who sent them: the mixnet
//! gives it a single-use tag, not an address. A one-way unit
//! (`Kind::Oneway`: writes and cover) goes to the server the same way and
//! its answer is dropped, since nobody can be answered. Anything that
//! doesn't parse, or any other request without reply blocks, is dropped.
//!
//! Push wakes take two more roles of the same binary (`docs/10-push.md`):
//! [`forward`], the stack's push egress, takes wakes from the server
//! (`u32 len ‖ sealed token`, the server's `[push] forward`) and sends each
//! one way to the push relays' Nym addresses; [`oneway`], in front of a
//! push relay, hands each wake it receives to the relay on the same
//! framing. The relay can't tell which server sent a wake.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use enclave_nym::frame::{Kind, Reply, Request, WAKE_LEN, Wake};
use enclave_nym::{Incoming, MixnetDriver};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How long the server gets to answer.
pub const SERVER_TIMEOUT: Duration = Duration::from_secs(30);

/// Counters (aggregates only: no addresses, no timing per sender).
#[derive(Debug, Default)]
pub struct Stats {
    /// Requests forwarded and answered.
    pub answered: AtomicU64,
    /// Requests the server didn't answer.
    pub failed: AtomicU64,
    /// Messages dropped: malformed or without reply blocks.
    pub dropped: AtomicU64,
    /// One-way units handed to the server.
    pub oneway: AtomicU64,
}

/// Forward everything `driver` receives to the server at `server` until the
/// driver shuts down.
pub async fn serve(driver: Arc<dyn MixnetDriver>, server: SocketAddr, stats: Arc<Stats>) {
    while let Some(m) = driver.recv().await {
        let driver = Arc::clone(&driver);
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            handle(driver.as_ref(), server, m, &stats).await;
        });
    }
}

async fn handle(driver: &dyn MixnetDriver, server: SocketAddr, m: Incoming, stats: &Stats) {
    let Ok(req) = Request::decode(&m.data) else {
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if req.kind == Kind::Probe {
        // A device's self-loop probe never goes to a server.
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if req.kind == Kind::Oneway {
        // The server's answer has nowhere to go.
        let sent = tokio::time::timeout(SERVER_TIMEOUT, roundtrip(server, &req.body)).await;
        let counter = match sent {
            Ok(Ok(_)) => &stats.oneway,
            _ => &stats.failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some(tag) = m.reply else {
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let data = tokio::time::timeout(SERVER_TIMEOUT, roundtrip(server, &req.body))
        .await
        .ok()
        .and_then(Result::ok);
    let counter = if data.is_some() {
        &stats.answered
    } else {
        &stats.failed
    };
    counter.fetch_add(1, Ordering::Relaxed);
    let Ok(frame) = (Reply { id: req.id, data }).encode() else {
        return;
    };
    // The reply blocks may be gone (the client gave up); nothing to do.
    let _ = driver.reply(tag, frame).await;
}

/// One request on the server's framing.
async fn roundtrip(server: SocketAddr, body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(server).await?;
    s.write_all(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes())
        .await?;
    s.write_all(body).await?;
    s.flush().await?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > enclave_wire::UNIT_LEN {
        return Err(std::io::Error::other("reply too long"));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// The push egress: read wakes (`u32 len ‖ bytes`) from connections on
/// `listener` (the server's forwarder) and send each, one way, to every
/// Nym address in `relays`. A relay that holds no key for a wake drops it.
pub async fn forward(
    driver: Arc<dyn MixnetDriver>,
    listener: TcpListener,
    relays: Arc<Vec<String>>,
    stats: Arc<Stats>,
) {
    while let Ok((mut sock, _)) = listener.accept().await {
        let driver = Arc::clone(&driver);
        let relays = Arc::clone(&relays);
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n > WAKE_LEN - 2 {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let mut data = vec![0u8; n];
                if sock.read_exact(&mut data).await.is_err() {
                    return;
                }
                let Ok(frame) = Wake(data).encode() else {
                    return;
                };
                for r in relays.iter() {
                    let counter = match driver.send(r, frame.clone(), 0).await {
                        Ok(()) => &stats.answered,
                        Err(_) => &stats.failed,
                    };
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }
}

/// In front of a push relay: hand every wake `driver` receives to the relay
/// at `relay` (`u32 len ‖ bytes`). Anything else is dropped.
pub async fn oneway(driver: Arc<dyn MixnetDriver>, relay: SocketAddr, stats: Arc<Stats>) {
    while let Some(m) = driver.recv().await {
        let Ok(Wake(data)) = Wake::decode(&m.data) else {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let sent = tokio::time::timeout(SERVER_TIMEOUT, async {
                let mut s = TcpStream::connect(relay).await?;
                s.write_all(&u32::try_from(data.len()).unwrap_or(0).to_be_bytes())
                    .await?;
                s.write_all(&data).await?;
                s.flush().await
            })
            .await;
            let counter = match sent {
                Ok(Ok(())) => &stats.answered,
                _ => &stats.failed,
            };
            counter.fetch_add(1, Ordering::Relaxed);
        });
    }
}
