//! tord as the carrier of Enclave requests (`docs/rfcs/0010-tor-onion-primary.md`).
//!
//! netd holds no TCP sockets: it hands each request for a server's onion
//! service, and each HTTPS fetch, to tord over tord's stdin and stdout, and
//! tord makes them through its own Tor client. Many requests are in flight
//! at once; each carries an id its answer repeats. Frames are
//! `u32 len ‖ body`:
//!
//! ```text
//! to tord:   1 ‖ u32 id ‖ u8 flags ‖ u16 len ‖ host ‖ u16 port ‖ request    exchange
//!            2 ‖ u32 id ‖ u16 len ‖ method ‖ u16 len ‖ url ‖ body          fetch
//! from tord: 1 ‖ u32 id ‖ 0 ‖ reply | 1 ‖ u32 id ‖ 1 ‖ reason              exchanged or not
//!            2 ‖ u32 id ‖ 0 ‖ u16 status ‖ body | 2 ‖ u32 id ‖ 1 ‖ reason fetched or not
//! ```
//!
//! `flags` bit 0 asks for no reply ([`ONEWAY`]): the server answers an empty
//! acknowledgement instead of its sealed reply, so a write or a cover unit
//! costs nothing coming back.
//!
//! Toward a server, tord keeps [`STREAMS`] long-lived streams per onion
//! service and sends one request at a time on each, in the server's own
//! framing (`u32 len ‖ request`, [`ONEWAY_BIT`] set for one way; the answer
//! `u32 len ‖ reply`): a poll never waits behind a unit, and no request
//! pays for building a new stream.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, oneshot};

/// Flag: no reply wanted.
pub const ONEWAY: u8 = 1;
/// In the server's framing, a length with this bit set asks for no reply:
/// the server answers an empty frame (lengths are at most a unit's; the
/// same bit as `enclave_wire::STREAM_ONEWAY`).
pub const ONEWAY_BIT: u32 = 0x8000_0000;
/// Longest frame either way.
pub const MAX_FRAME: usize = 2 * 1024 * 1024;
/// Longest reply read from a server.
pub const MAX_REPLY: usize = 1024 * 1024;
/// Streams kept to each onion service.
pub const STREAMS: usize = 2;
/// How long one exchange may take, from asking tord to its answer.
pub const TIMEOUT: Duration = Duration::from_secs(90);
/// How long a server may take to answer on a stream (less than
/// [`TIMEOUT`], so tord's answer reaches netd first).
pub const STREAM_TIMEOUT: Duration = Duration::from_secs(60);

const EXCHANGE: u8 = 1;
const FETCH: u8 = 2;

fn lp16(out: &mut Vec<u8>, b: &[u8]) -> std::io::Result<()> {
    let n = u16::try_from(b.len()).map_err(|_| invalid("field too long"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn take16<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = usize::from(u16::from_be_bytes([*b.first()?, *b.get(1)?]));
    let v = b.get(2..2 + n)?;
    *b = &b[2 + n..];
    Some(v)
}

fn take32(b: &mut &[u8]) -> Option<u32> {
    let v = u32::from_be_bytes(b.get(..4)?.try_into().ok()?);
    *b = &b[4..];
    Some(v)
}

fn invalid(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string())
}

async fn read_frame(r: &mut (impl AsyncRead + Unpin)) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.ok()?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return None;
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await.ok()?;
    Some(b)
}

async fn write_frame(w: &mut (impl AsyncWrite + Unpin), body: &[u8]) -> std::io::Result<()> {
    let n = u32::try_from(body.len()).map_err(|_| invalid("frame too long"))?;
    w.write_all(&n.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

type Waiters = Arc<std::sync::Mutex<HashMap<u32, oneshot::Sender<Result<Vec<u8>, String>>>>>;

/// netd's side: requests to a tord started as a carrier.
pub struct Client {
    writer: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,
    waiters: Waiters,
    next: AtomicU32,
    reader: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Talk to the tord at the other end of `reader` and `writer` (its
    /// stdout and stdin, after its `ready` line).
    pub fn new(
        mut reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
    ) -> Self {
        let waiters: Waiters = Arc::default();
        let w = Arc::clone(&waiters);
        let reader = tokio::spawn(async move {
            while let Some(b) = read_frame(&mut reader).await {
                let mut rest = &b[..];
                let Some((_kind, r)) = rest.split_first() else {
                    break;
                };
                rest = r;
                let Some(id) = take32(&mut rest) else { break };
                let Some((ok, v)) = rest.split_first() else {
                    break;
                };
                let answer = if *ok == 0 {
                    Ok(v.to_vec())
                } else {
                    Err(String::from_utf8_lossy(v).into_owned())
                };
                let waiter = w.lock().ok().and_then(|mut m| m.remove(&id));
                if let Some(tx) = waiter {
                    let _ = tx.send(answer);
                }
            }
            // tord went away: everyone waiting learns it now.
            if let Ok(mut m) = w.lock() {
                for (_, tx) in m.drain() {
                    let _ = tx.send(Err("enclave-tord closed".into()));
                }
            }
        });
        Self {
            writer: Mutex::new(Box::new(writer)),
            waiters,
            next: AtomicU32::new(1),
            reader,
        }
    }

    async fn call(
        &self,
        kind: u8,
        body: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>,
    ) -> std::io::Result<Vec<u8>> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut frame = vec![kind];
        frame.extend_from_slice(&id.to_be_bytes());
        body(&mut frame)?;
        let (tx, rx) = oneshot::channel();
        if let Ok(mut m) = self.waiters.lock() {
            m.insert(id, tx);
        }
        let sent = write_frame(&mut *self.writer.lock().await, &frame).await;
        if let Err(e) = sent {
            if let Ok(mut m) = self.waiters.lock() {
                m.remove(&id);
            }
            return Err(e);
        }
        match tokio::time::timeout(TIMEOUT, rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(why))) => Err(std::io::Error::other(why)),
            Ok(Err(_)) => Err(std::io::Error::other("enclave-tord closed")),
            Err(_) => {
                if let Ok(mut m) = self.waiters.lock() {
                    m.remove(&id);
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no answer over Tor in time",
                ))
            }
        }
    }

    /// One request to `host:port` (an onion service) and its reply; with
    /// `oneway`, an empty acknowledgement instead.
    pub async fn exchange(
        &self,
        host: &str,
        port: u16,
        request: &[u8],
        oneway: bool,
    ) -> std::io::Result<Vec<u8>> {
        self.call(EXCHANGE, |f| {
            f.push(if oneway { ONEWAY } else { 0 });
            lp16(f, host.as_bytes())?;
            f.extend_from_slice(&port.to_be_bytes());
            f.extend_from_slice(request);
            Ok(())
        })
        .await
    }

    /// HTTPS through Tor: the status and the body (`url` as the transport's
    /// `fetch` takes it: `web+https://…` for an ordinary web site, a
    /// `#bytes=A-B` fragment for a range).
    pub async fn fetch(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
    ) -> std::io::Result<(u16, Vec<u8>)> {
        let v = self
            .call(FETCH, |f| {
                lp16(f, method.as_bytes())?;
                lp16(f, url.as_bytes())?;
                f.extend_from_slice(body);
                Ok(())
            })
            .await?;
        if v.len() < 2 {
            return Err(invalid("short fetch answer"));
        }
        Ok((u16::from_be_bytes([v[0], v[1]]), v[2..].to_vec()))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// tord's side: serve requests from `reader` until it closes, dialing
/// through `dialer`.
#[cfg(feature = "carrier-serve")]
pub async fn serve<R, W>(dialer: Arc<dyn crate::Dialer>, mut reader: R, writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let writer = Arc::new(Mutex::new(writer));
    let pool = Arc::new(Pool::new(Arc::clone(&dialer)));
    let fetcher = Arc::new(crate::fetch::Fetcher::new(dialer));
    while let Some(b) = read_frame(&mut reader).await {
        let mut rest = &b[..];
        let Some((&kind, r)) = rest.split_first() else {
            return;
        };
        rest = r;
        let Some(id) = take32(&mut rest) else { return };
        let (pool, fetcher, writer) =
            (Arc::clone(&pool), Arc::clone(&fetcher), Arc::clone(&writer));
        let rest = rest.to_vec();
        tokio::spawn(async move {
            let answer = match kind {
                EXCHANGE => exchange_request(&pool, &rest).await,
                FETCH => fetch_request(&fetcher, &rest).await,
                _ => Err("unknown request".to_string()),
            };
            let mut frame = vec![kind];
            frame.extend_from_slice(&id.to_be_bytes());
            match answer {
                Ok(v) => {
                    frame.push(0);
                    frame.extend_from_slice(&v);
                }
                Err(why) => {
                    frame.push(1);
                    frame.extend_from_slice(why.as_bytes());
                }
            }
            let _ = write_frame(&mut *writer.lock().await, &frame).await;
        });
    }
}

#[cfg(feature = "carrier-serve")]
async fn exchange_request(pool: &Pool, mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let (&flags, r) = rest.split_first().ok_or("malformed")?;
    rest = r;
    let host = take16(&mut rest).ok_or("malformed")?;
    let host = std::str::from_utf8(host)
        .map_err(|_| "malformed")?
        .to_string();
    let port = rest.get(..2).ok_or("malformed")?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    pool.exchange(&host, port, &rest[2..], flags & ONEWAY != 0)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(feature = "carrier-serve")]
async fn fetch_request(
    fetcher: &crate::fetch::Fetcher,
    mut rest: &[u8],
) -> Result<Vec<u8>, String> {
    let method = take16(&mut rest).ok_or("malformed")?;
    let url = take16(&mut rest).ok_or("malformed")?;
    let method = std::str::from_utf8(method).map_err(|_| "malformed")?;
    let url = std::str::from_utf8(url).map_err(|_| "malformed")?;
    let (status, body) = fetcher.fetch(method, url, rest.to_vec()).await?;
    Ok([&status.to_be_bytes()[..], &body].concat())
}

/// One service's streams: each slot open or not.
#[cfg(feature = "carrier-serve")]
type Slots = Arc<Vec<Mutex<Option<Box<dyn crate::socks::Stream>>>>>;

/// Long-lived streams to onion services, [`STREAMS`] per service.
#[cfg(feature = "carrier-serve")]
pub struct Pool {
    dialer: Arc<dyn crate::Dialer>,
    slots: std::sync::Mutex<HashMap<(String, u16), Slots>>,
    turn: AtomicU32,
}

#[cfg(feature = "carrier-serve")]
impl Pool {
    /// No streams yet; they are opened as requests need them.
    pub fn new(dialer: Arc<dyn crate::Dialer>) -> Self {
        Self {
            dialer,
            slots: std::sync::Mutex::new(HashMap::new()),
            turn: AtomicU32::new(0),
        }
    }

    fn slots_for(&self, host: &str, port: u16) -> std::io::Result<Slots> {
        let mut m = self
            .slots
            .lock()
            .map_err(|_| std::io::Error::other("pool poisoned"))?;
        Ok(Arc::clone(
            m.entry((host.to_string(), port))
                .or_insert_with(|| Arc::new((0..STREAMS).map(|_| Mutex::new(None)).collect())),
        ))
    }

    /// One request on a free stream to `host:port` (opened if needed), and
    /// its answer: the reply, or empty when sent `oneway`. A stream that
    /// turns out to be closed (it was idle too long) is replaced and the
    /// request tried once more on the new one.
    pub async fn exchange(
        &self,
        host: &str,
        port: u16,
        request: &[u8],
        oneway: bool,
    ) -> std::io::Result<Vec<u8>> {
        if request.len() >= ONEWAY_BIT as usize {
            return Err(invalid("request too long"));
        }
        let slots = self.slots_for(host, port)?;
        let mut guard = None;
        for s in slots.iter() {
            if let Ok(g) = s.try_lock() {
                guard = Some(g);
                break;
            }
        }
        let mut stream = match guard {
            Some(g) => g,
            None => {
                let i = self.turn.fetch_add(1, Ordering::Relaxed) as usize % slots.len();
                slots[i].lock().await
            }
        };
        let reused = stream.is_some();
        if stream.is_none() {
            *stream = Some(self.dialer.dial(host, port).await?);
        }
        let first = match stream.as_mut() {
            Some(s) => one(s.as_mut(), request, oneway).await,
            None => Err(std::io::Error::other("no stream")),
        };
        match first {
            Ok(v) => Ok(v),
            Err(e) => {
                *stream = None;
                // Only a stream we didn't just open may simply have gone
                // stale; a fresh one failing is the answer.
                if !reused || !stale(&e) {
                    return Err(e);
                }
                let mut s = self.dialer.dial(host, port).await?;
                let v = one(s.as_mut(), request, oneway).await?;
                *stream = Some(s);
                Ok(v)
            }
        }
    }
}

/// Whether an error is a stream the other end had already closed (before
/// anything of the answer arrived).
#[cfg(feature = "carrier-serve")]
fn stale(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        UnexpectedEof | BrokenPipe | ConnectionReset | ConnectionAborted | NotConnected
    )
}

/// One request and its answer on `s`, in the server's framing.
#[cfg(feature = "carrier-serve")]
async fn one(
    s: &mut dyn crate::socks::Stream,
    request: &[u8],
    oneway: bool,
) -> std::io::Result<Vec<u8>> {
    let mut len = request.len() as u32;
    if oneway {
        len |= ONEWAY_BIT;
    }
    // One write: a length on its own would wait for the peer's delayed
    // acknowledgement (Nagle) before the request followed.
    let frame = [&len.to_be_bytes()[..], request].concat();
    let work = async {
        s.write_all(&frame).await?;
        s.flush().await?;
        let mut n = [0u8; 4];
        s.read_exact(&mut n).await?;
        let n = u32::from_be_bytes(n) as usize;
        if n > MAX_REPLY {
            return Err(invalid("reply too long"));
        }
        let mut reply = vec![0u8; n];
        s.read_exact(&mut reply).await?;
        Ok(reply)
    };
    tokio::time::timeout(STREAM_TIMEOUT, work)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the server didn't answer in time",
            )
        })?
}

#[cfg(all(test, feature = "carrier-serve"))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A server in Enclave's framing: answers `echo:` + the request, an
    /// empty frame for one way, waits on a request starting `slow`, and
    /// closes each connection after `close_after` requests (0: never).
    async fn server(close_after: usize) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                c.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut served = 0;
                    loop {
                        let mut n = [0u8; 4];
                        if s.read_exact(&mut n).await.is_err() {
                            return;
                        }
                        let n = u32::from_be_bytes(n);
                        let oneway = n & ONEWAY_BIT != 0;
                        let mut b = vec![0u8; (n & !ONEWAY_BIT) as usize];
                        s.read_exact(&mut b).await.unwrap();
                        if b.starts_with(b"slow") {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                        }
                        let reply = if oneway {
                            Vec::new()
                        } else {
                            [&b"echo:"[..], &b].concat()
                        };
                        s.write_all(&(reply.len() as u32).to_be_bytes())
                            .await
                            .unwrap();
                        s.write_all(&reply).await.unwrap();
                        served += 1;
                        if close_after != 0 && served == close_after {
                            return;
                        }
                    }
                });
            }
        });
        (addr, connections)
    }

    /// A carrier client talking to `serve` over in-memory pipes.
    fn carrier() -> Client {
        let (to_tord, tord_in) = tokio::io::duplex(1 << 20);
        let (tord_out, from_tord) = tokio::io::duplex(1 << 20);
        tokio::spawn(serve(Arc::new(crate::DirectDialer), tord_in, tord_out));
        Client::new(from_tord, to_tord)
    }

    #[tokio::test]
    async fn exchanges_and_one_way_sends() {
        let (addr, connections) = server(0).await;
        let c = carrier();
        let r = c
            .exchange("127.0.0.1", addr.port(), b"hi", false)
            .await
            .unwrap();
        assert_eq!(r, b"echo:hi");
        // One way: the server's empty acknowledgement, nothing else.
        let r = c
            .exchange("127.0.0.1", addr.port(), b"unit", true)
            .await
            .unwrap();
        assert!(r.is_empty());
        // Later requests reuse the stream.
        c.exchange("127.0.0.1", addr.port(), b"again", false)
            .await
            .unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_poll_does_not_wait_behind_a_slow_request() {
        let (addr, _) = server(0).await;
        let c = Arc::new(carrier());
        let slow = {
            let c = Arc::clone(&c);
            tokio::spawn(async move {
                c.exchange("127.0.0.1", addr.port(), b"slow unit", false)
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = tokio::time::Instant::now();
        let r = c
            .exchange("127.0.0.1", addr.port(), b"poll", false)
            .await
            .unwrap();
        assert_eq!(r, b"echo:poll");
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "the poll waited"
        );
        assert_eq!(slow.await.unwrap().unwrap(), b"echo:slow unit");
    }

    #[tokio::test]
    async fn a_closed_stream_is_replaced() {
        // The server closes every connection after one request: each next
        // request finds its stream stale and goes again on a new one.
        let (addr, connections) = server(1).await;
        let c = carrier();
        for i in 0..3 {
            let r = c
                .exchange("127.0.0.1", addr.port(), format!("r{i}").as_bytes(), false)
                .await
                .unwrap();
            assert_eq!(r, format!("echo:r{i}").as_bytes());
        }
        assert!(connections.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn an_unreachable_service_is_an_error() {
        let c = carrier();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        assert!(c.exchange("127.0.0.1", port, b"x", false).await.is_err());
    }

    #[test]
    fn onion_names_map_to_test_addresses() {
        let map = "a.onion=127.0.0.1:1, b.onion=10.0.0.2:7443";
        assert_eq!(
            crate::dev_onion(map, "b.onion").as_deref(),
            Some("10.0.0.2:7443")
        );
        assert_eq!(crate::dev_onion(map, "c.onion"), None);
    }
}
