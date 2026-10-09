//! A mixnet client in another process (`enclave-nymd`), driven over a pair
//! of byte streams (its stdin and stdout).
//!
//! nym-sdk can't be linked into netd (it needs another SQLite than arti,
//! `docs/09-transport.md` §1), so netd starts `enclave-nymd` and drives it
//! as a [`MixnetDriver`] through [`PipeDriver`]; `enclave-nymd` runs
//! [`serve`] around its nym-sdk driver. Frames are `u32 len ‖ body`:
//!
//! ```text
//! to nymd:   1 ‖ u16 len ‖ address ‖ u32 reply_len ‖ data      send
//!            2 ‖ tag (16) ‖ data                               reply
//!            3 ‖ u32 millis                                    flush
//!            4 ‖ pacing (13, `Pacing::encode`)                 pace
//!            5                                                 switch gateway
//!            6 ‖ held ticketbook (`Held`)                      import (before 7)
//!            7                                                 connect (`--await-tickets`)
//!            8 ‖ u16 len ‖ method ‖ u16 len ‖ url ‖ body       fetch (through Tor)
//!            9 ‖ u16 len ‖ gate ‖ token                        buy a ticketbook
//!            10                                                tickets spent so far
//! from nymd: 1 ‖ address                                       ready (first, and
//!                                                              after a switch)
//!            2 ‖ u8 has_tag ‖ [tag (16)] ‖ data                a message
//!            3 ‖ u8 done                                       flushed
//!            5 ‖ 0 ‖ gateway | 5 ‖ 1 ‖ reason                  switched (after a
//!                                                              ready frame) or not
//!            8 ‖ 0 ‖ u16 status ‖ body | 8 ‖ 1 ‖ reason        fetched or not
//!            9 ‖ 0 ‖ held ticketbook | 9 ‖ 1 ‖ reason          bought or not
//!            10 ‖ 0 ‖ u64 spent                                the count
//! ```
//!
//! Started with `--await-tickets`, nymd answers 6, 8 and 9 before it
//! connects, and connects on 7 with the ticketbooks it was given
//! ([`PipeDriver::start`]): a device can buy its first ones over Tor before
//! a gateway that wants them would refuse it. Fetches and purchases also
//! work once connected; a ticketbook bought then is used from the next
//! connection (a gateway switch, a restart).
//!
//! Sends are fire and forget, as on the mixnet itself: a lost one shows as
//! a request that gets no reply.

use crate::{Incoming, MixnetDriver, NymError, Pacing, ReplyTag, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc, oneshot};

type FlushWaiter = Arc<std::sync::Mutex<Option<oneshot::Sender<bool>>>>;
type SwitchWaiter =
    Arc<std::sync::Mutex<Option<oneshot::Sender<std::result::Result<String, String>>>>>;
type CallWaiter =
    Arc<std::sync::Mutex<Option<(u8, oneshot::Sender<std::result::Result<Vec<u8>, String>>)>>>;

/// Longest frame either way (a mixframe and its header, or a ticketbook
/// with its signatures, with room).
pub const MAX_FRAME: usize = 1024 * 1024;

fn lp16(out: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u16::try_from(b.len())
            .map_err(|_| NymError::Malformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(b);
    Ok(())
}

fn take16<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = usize::from(u16::from_be_bytes([*b.first()?, *b.get(1)?]));
    let v = b.get(2..2 + n)?;
    *b = &b[2 + n..];
    Some(v)
}

/// Frame 8: a fetch.
fn fetch_frame(method: &str, url: &str, body: &[u8]) -> Result<Vec<u8>> {
    let mut b = vec![8u8];
    lp16(&mut b, method.as_bytes())?;
    lp16(&mut b, url.as_bytes())?;
    b.extend_from_slice(body);
    Ok(b)
}

fn parse_fetch(mut rest: &[u8]) -> Option<(String, String, Vec<u8>)> {
    let method = String::from_utf8(take16(&mut rest)?.to_vec()).ok()?;
    let url = String::from_utf8(take16(&mut rest)?.to_vec()).ok()?;
    Some((method, url, rest.to_vec()))
}

/// Frame 9: a purchase.
fn buy_frame(gate: &str, token: &[u8]) -> Result<Vec<u8>> {
    let mut b = vec![9u8];
    lp16(&mut b, gate.as_bytes())?;
    b.extend_from_slice(token);
    Ok(b)
}

fn parse_buy(mut rest: &[u8]) -> Option<(String, Vec<u8>)> {
    let gate = String::from_utf8(take16(&mut rest)?.to_vec()).ok()?;
    Some((gate, rest.to_vec()))
}

/// The answer to a fetch (8) or a purchase (9).
fn answer_frame(kind: u8, r: std::result::Result<Vec<u8>, String>) -> Vec<u8> {
    match r {
        Ok(v) => [&[kind, 0][..], &v].concat(),
        Err(e) => [&[kind, 1][..], e.as_bytes()].concat(),
    }
}

fn fetched(status: u16, body: &[u8]) -> Vec<u8> {
    [&status.to_be_bytes()[..], body].concat()
}

fn split_fetched(v: &[u8]) -> Result<(u16, Vec<u8>)> {
    if v.len() < 2 {
        return Err(NymError::Malformed);
    }
    Ok((u16::from_be_bytes([v[0], v[1]]), v[2..].to_vec()))
}

/// What nymd does for frames 8 and 9: the device's HTTP client (through
/// Tor) and its ticketbook purchase.
#[async_trait::async_trait]
pub trait Purchaser: Send + Sync {
    /// HTTP through Tor.
    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)>;
    /// One ticketbook for one token.
    async fn buy(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>>;
}

/// Answer frame 8 or 9 with `p`.
async fn purchase(p: &dyn Purchaser, b: &[u8]) -> Option<Vec<u8>> {
    match b.split_first() {
        Some((8, rest)) => {
            let (method, url, body) = parse_fetch(rest)?;
            Some(answer_frame(
                8,
                p.fetch(&method, &url, body)
                    .await
                    .map(|(s, b)| fetched(s, &b))
                    .map_err(|e| e.to_string()),
            ))
        }
        Some((9, rest)) => {
            let (gate, token) = parse_buy(rest)?;
            Some(answer_frame(
                9,
                p.buy(&gate, &token).await.map_err(|e| e.to_string()),
            ))
        }
        _ => None,
    }
}

/// A connected client's own fetch and purchase.
struct ViaDriver(Arc<dyn MixnetDriver>);

#[async_trait::async_trait]
impl Purchaser for ViaDriver {
    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        self.0.fetch(method, url, body).await
    }
    async fn buy(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
        self.0.buy_tickets(gate, token).await
    }
}

/// The nymd side before it connects (`--await-tickets`): answer fetches
/// and purchases, collect imported ticketbooks, and return them on the
/// connect frame. `None` if netd went away first.
pub async fn serve_starting<R, W>(
    purchaser: &dyn Purchaser,
    reader: &mut R,
    writer: &mut W,
) -> Option<Vec<Vec<u8>>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut tickets = Vec::new();
    loop {
        let b = read_frame(reader).await?;
        match b.split_first() {
            Some((6, t)) => tickets.push(t.to_vec()),
            Some((7, [])) => return Some(tickets),
            Some((8 | 9, _)) => {
                let answer = purchase(purchaser, &b).await?;
                write_frame(writer, &answer).await.ok()?;
            }
            _ => return None,
        }
    }
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
    w.write_all(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes())
        .await?;
    w.write_all(body).await?;
    w.flush().await
}

/// The netd side: a [`MixnetDriver`] whose client runs in another process.
pub struct PipeDriver {
    address: Arc<std::sync::RwLock<String>>,
    writer: Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    rx: Mutex<mpsc::UnboundedReceiver<Incoming>>,
    reader: tokio::task::JoinHandle<()>,
    flushed: FlushWaiter,
    flushing: Mutex<()>,
    switched: SwitchWaiter,
    switching: Mutex<()>,
    called: CallWaiter,
    calling: Mutex<()>,
}

/// A nymd started with `--await-tickets`, not connected yet: fetch and buy
/// through it, then [`Starting::connect`] with the ticketbooks to spend.
pub struct Starting<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> Starting<R, W>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    /// Talk to the nymd at the other end.
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    async fn call(&mut self, frame: &[u8], kind: u8) -> Result<Vec<u8>> {
        write_frame(&mut self.writer, frame)
            .await
            .map_err(|_| NymError::Closed)?;
        let b = read_frame(&mut self.reader).await.ok_or(NymError::Closed)?;
        match b.split_first() {
            Some((k, [0, v @ ..])) if *k == kind => Ok(v.to_vec()),
            Some((k, [1, why @ ..])) if *k == kind => {
                Err(NymError::Client(String::from_utf8_lossy(why).into_owned()))
            }
            _ => Err(NymError::Malformed),
        }
    }

    /// HTTP through nymd's Tor.
    pub async fn fetch(&mut self, method: &str, url: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let f = fetch_frame(method, url, body)?;
        split_fetched(&self.call(&f, 8).await?)
    }

    /// One ticketbook for one token.
    pub async fn buy(&mut self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
        let f = buy_frame(gate, token)?;
        self.call(&f, 9).await
    }

    /// Connect with these ticketbooks, and drive the client.
    pub async fn connect(mut self, tickets: &[Vec<u8>]) -> Result<PipeDriver> {
        for t in tickets {
            write_frame(&mut self.writer, &[&[6u8][..], t].concat())
                .await
                .map_err(|_| NymError::Closed)?;
        }
        write_frame(&mut self.writer, &[7])
            .await
            .map_err(|_| NymError::Closed)?;
        PipeDriver::new(self.reader, self.writer).await
    }
}

impl PipeDriver {
    /// Drive the client at the other end of `reader`/`writer`: waits for it
    /// to say it's connected.
    pub async fn new(
        mut reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
    ) -> Result<Self> {
        let ready = read_frame(&mut reader).await.ok_or(NymError::Closed)?;
        let address = match ready.split_first() {
            Some((1, a)) => String::from_utf8(a.to_vec()).map_err(|_| NymError::Malformed)?,
            _ => return Err(NymError::Malformed),
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let flushed: FlushWaiter = Arc::default();
        let waiter = Arc::clone(&flushed);
        let switched: SwitchWaiter = Arc::default();
        let switch_waiter = Arc::clone(&switched);
        let called: CallWaiter = Arc::default();
        let call_waiter = Arc::clone(&called);
        let address = Arc::new(std::sync::RwLock::new(address));
        let current = Arc::clone(&address);
        let reader = tokio::spawn(async move {
            let answer = |r: std::result::Result<String, String>| {
                if let Some(w) = switch_waiter.lock().ok().and_then(|mut w| w.take()) {
                    let _ = w.send(r);
                }
            };
            while let Some(b) = read_frame(&mut reader).await {
                match b.split_first() {
                    Some((3, [done])) => {
                        if let Some(w) = waiter.lock().ok().and_then(|mut w| w.take()) {
                            let _ = w.send(*done == 1);
                        }
                        continue;
                    }
                    // Through another gateway now, at a new address.
                    Some((1, a)) => {
                        let Ok(a) = String::from_utf8(a.to_vec()) else {
                            return;
                        };
                        if let Ok(mut c) = current.write() {
                            *c = a;
                        }
                        continue;
                    }
                    Some((5, [ok, text @ ..])) => {
                        let text = String::from_utf8_lossy(text).into_owned();
                        answer(if *ok == 0 { Ok(text) } else { Err(text) });
                        continue;
                    }
                    Some((kind @ (8..=10), [ok, v @ ..])) => {
                        let waiting = call_waiter.lock().ok().and_then(|mut w| w.take());
                        if let Some((k, w)) = waiting
                            && k == *kind
                        {
                            let _ = w.send(if *ok == 0 {
                                Ok(v.to_vec())
                            } else {
                                Err(String::from_utf8_lossy(v).into_owned())
                            });
                        }
                        continue;
                    }
                    _ => {}
                }
                let m = match b.split_first() {
                    Some((2, [0, data @ ..])) => Incoming {
                        data: data.to_vec(),
                        reply: None,
                    },
                    Some((2, [1, rest @ ..])) if rest.len() >= 16 => {
                        let (tag, data) = rest.split_at(16);
                        Incoming {
                            data: data.to_vec(),
                            reply: tag.try_into().ok().map(ReplyTag),
                        }
                    }
                    _ => return,
                };
                if tx.send(m).is_err() {
                    return;
                }
            }
        });
        Ok(Self {
            address,
            writer: Arc::new(Mutex::new(Box::new(writer))),
            rx: Mutex::new(rx),
            reader,
            flushed,
            flushing: Mutex::new(()),
            switched,
            switching: Mutex::new(()),
            called,
            calling: Mutex::new(()),
        })
    }

    /// Frame 8 or 9 and its answer, one at a time.
    async fn call(&self, frame: &[u8], kind: u8) -> Result<Vec<u8>> {
        let _one = self.calling.lock().await;
        let (tx, rx) = oneshot::channel();
        match self.called.lock() {
            Ok(mut w) => *w = Some((kind, tx)),
            Err(_) => return Err(NymError::Closed),
        }
        self.write(frame).await?;
        match tokio::time::timeout(Duration::from_secs(300), rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(why))) => Err(NymError::Client(why)),
            _ => Err(NymError::Closed),
        }
    }

    async fn write(&self, body: &[u8]) -> Result<()> {
        write_frame(&mut *self.writer.lock().await, body)
            .await
            .map_err(|_| NymError::Closed)
    }
}

impl Drop for PipeDriver {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[async_trait::async_trait]
impl MixnetDriver for PipeDriver {
    fn address(&self) -> String {
        self.address.read().map(|a| a.clone()).unwrap_or_default()
    }

    async fn switch_gateway(&self) -> Result<String> {
        let _one = self.switching.lock().await;
        let (tx, rx) = oneshot::channel();
        match self.switched.lock() {
            Ok(mut w) => *w = Some(tx),
            Err(_) => return Err(NymError::Closed),
        }
        self.write(&[5]).await?;
        // Connecting through another gateway can take a while.
        match tokio::time::timeout(Duration::from_secs(120), rx).await {
            Ok(Ok(Ok(gateway))) => Ok(gateway),
            Ok(Ok(Err(why))) => Err(NymError::Client(why)),
            _ => Err(NymError::Closed),
        }
    }

    async fn send(&self, to: &str, data: Vec<u8>, reply_len: usize) -> Result<()> {
        let to = to.as_bytes();
        let mut b = vec![1u8];
        b.extend_from_slice(
            &u16::try_from(to.len())
                .map_err(|_| NymError::Malformed)?
                .to_be_bytes(),
        );
        b.extend_from_slice(to);
        b.extend_from_slice(&u32::try_from(reply_len).unwrap_or(u32::MAX).to_be_bytes());
        b.extend_from_slice(&data);
        self.write(&b).await
    }

    async fn reply(&self, tag: ReplyTag, data: Vec<u8>) -> Result<()> {
        let mut b = vec![2u8];
        b.extend_from_slice(&tag.0);
        b.extend_from_slice(&data);
        self.write(&b).await
    }

    async fn recv(&self) -> Option<Incoming> {
        self.rx.lock().await.recv().await
    }

    fn set_pacing(&self, pacing: Pacing) {
        let mut b = vec![4u8];
        b.extend_from_slice(&pacing.encode());
        let writer = Arc::clone(&self.writer);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = write_frame(&mut *writer.lock().await, &b).await;
            });
        }
    }

    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        let f = fetch_frame(method, url, &body)?;
        split_fetched(&self.call(&f, 8).await?)
    }

    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
        let f = buy_frame(gate, token)?;
        self.call(&f, 9).await
    }

    async fn tickets_spent(&self) -> Result<u64> {
        let v = self.call(&[10], 10).await?;
        Ok(u64::from_be_bytes(
            v.as_slice().try_into().map_err(|_| NymError::Malformed)?,
        ))
    }

    async fn flush(&self, within: Duration) -> bool {
        // One flush at a time: the answer carries no id.
        let _one = self.flushing.lock().await;
        let (tx, rx) = oneshot::channel();
        match self.flushed.lock() {
            Ok(mut w) => *w = Some(tx),
            Err(_) => return false,
        }
        let millis = u32::try_from(within.as_millis()).unwrap_or(u32::MAX);
        let mut b = vec![3u8];
        b.extend_from_slice(&millis.to_be_bytes());
        if self.write(&b).await.is_err() {
            return false;
        }
        // A little longer than nymd's own limit, for the answer to come.
        tokio::time::timeout(within + Duration::from_secs(2), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(false)
    }
}

/// The `enclave-nymd` side: announce `driver`'s address, then carry sends
/// and replies from `reader` to it and what it receives to `writer`, until
/// either end closes.
pub async fn serve(
    driver: Arc<dyn MixnetDriver>,
    mut reader: impl AsyncRead + Send + Unpin + 'static,
    writer: impl AsyncWrite + Send + Unpin + 'static,
) {
    let writer = Arc::new(Mutex::new(writer));
    let ready = [&[1u8][..], driver.address().as_bytes()].concat();
    if write_frame(&mut *writer.lock().await, &ready)
        .await
        .is_err()
    {
        return;
    }
    let incoming = {
        let driver = Arc::clone(&driver);
        let writer = Arc::clone(&writer);
        tokio::spawn(async move {
            while let Some(m) = driver.recv().await {
                let mut b = vec![2u8];
                match m.reply {
                    Some(t) => {
                        b.push(1);
                        b.extend_from_slice(&t.0);
                    }
                    None => b.push(0),
                }
                b.extend_from_slice(&m.data);
                if write_frame(&mut *writer.lock().await, &b).await.is_err() {
                    return;
                }
            }
        })
    };
    // Sends and replies being handed to the client: a flush waits for those
    // that came before it.
    let mut handing: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    while let Some(b) = read_frame(&mut reader).await {
        handing.retain(|h| !h.is_finished());
        let driver = Arc::clone(&driver);
        match b.split_first() {
            Some((1, rest)) if rest.len() >= 2 => {
                let n = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
                let Some(to) = rest
                    .get(2..2 + n)
                    .and_then(|t| String::from_utf8(t.to_vec()).ok())
                else {
                    break;
                };
                let Some(len) = rest.get(2 + n..6 + n) else {
                    break;
                };
                let reply_len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
                let data = rest[6 + n..].to_vec();
                handing.push(tokio::spawn(async move {
                    let _ = driver.send(&to, data, reply_len).await;
                }));
            }
            Some((2, rest)) if rest.len() >= 16 => {
                let (tag, data) = rest.split_at(16);
                let Ok(tag) = tag.try_into().map(ReplyTag) else {
                    break;
                };
                let data = data.to_vec();
                handing.push(tokio::spawn(async move {
                    let _ = driver.reply(tag, data).await;
                }));
            }
            Some((10, [])) => {
                let writer = Arc::clone(&writer);
                tokio::spawn(async move {
                    let answer = answer_frame(
                        10,
                        driver
                            .tickets_spent()
                            .await
                            .map(|n| n.to_be_bytes().to_vec())
                            .map_err(|e| e.to_string()),
                    );
                    let _ = write_frame(&mut *writer.lock().await, &answer).await;
                });
            }
            Some((8 | 9, _)) => {
                let writer = Arc::clone(&writer);
                tokio::spawn(async move {
                    if let Some(answer) = purchase(&ViaDriver(driver), &b).await {
                        let _ = write_frame(&mut *writer.lock().await, &answer).await;
                    }
                });
            }
            Some((5, [])) => {
                let writer = Arc::clone(&writer);
                tokio::spawn(async move {
                    let mut w = writer.lock().await;
                    let _ = match driver.switch_gateway().await {
                        Ok(g) => {
                            let ready = [&[1u8][..], driver.address().as_bytes()].concat();
                            let _ = write_frame(&mut *w, &ready).await;
                            write_frame(&mut *w, &[&[5u8, 0][..], g.as_bytes()].concat()).await
                        }
                        Err(e) => {
                            let why = e.to_string();
                            write_frame(&mut *w, &[&[5u8, 1][..], why.as_bytes()].concat()).await
                        }
                    };
                });
            }
            Some((4, rest)) => {
                if let Some(p) = Pacing::decode(rest) {
                    driver.set_pacing(p);
                }
            }
            Some((3, &[a, b, c, d])) => {
                let within = Duration::from_millis(u64::from(u32::from_be_bytes([a, b, c, d])));
                let writer = Arc::clone(&writer);
                let before = std::mem::take(&mut handing);
                tokio::spawn(async move {
                    for h in before {
                        let _ = h.await;
                    }
                    let done = driver.flush(within).await;
                    let _ = write_frame(&mut *writer.lock().await, &[3, u8::from(done)]).await;
                });
            }
            _ => break,
        }
    }
    // netd went away: let what it handed over leave before nymd exits.
    for h in handing {
        let _ = h.await;
    }
    let _ = driver.flush(Duration::from_secs(10)).await;
    incoming.abort();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::fake::FakeMixnet;

    /// A pipe driver behaves like the client it drives.
    #[tokio::test]
    async fn through_a_pipe() {
        let net = FakeMixnet::default();
        let far: Arc<dyn MixnetDriver> = Arc::new(net.client("phone"));
        let (a, b) = tokio::io::duplex(1 << 20);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        tokio::spawn(serve(far, br, bw));
        let pipe = PipeDriver::new(ar, aw).await.unwrap();
        assert_eq!(pipe.address(), "phone");

        let server = net.client("server");
        pipe.send("server", vec![1, 2, 3], 100).await.unwrap();
        let m = server.recv().await.unwrap();
        assert_eq!(m.data, vec![1, 2, 3]);
        server
            .reply(m.reply.unwrap(), vec![9; 20_000])
            .await
            .unwrap();
        let r = pipe.recv().await.unwrap();
        assert_eq!((r.data.len(), r.reply), (20_000, None));

        // Something sent to the phone with reply blocks can be answered
        // through the pipe.
        server.send("phone", b"ask".to_vec(), 10).await.unwrap();
        let m = pipe.recv().await.unwrap();
        pipe.reply(m.reply.unwrap(), b"answer".to_vec())
            .await
            .unwrap();
        assert_eq!(server.recv().await.unwrap().data, b"answer");

        // Pacing reaches the driver at the far end.
        let p = Pacing {
            tick: Duration::from_secs(3),
            bulk: true,
            loop_cover: Duration::from_secs(15),
            probe: Duration::from_secs(30),
        };
        pipe.set_pacing(p);
        for _ in 0..100 {
            if net.pacing("phone") == Some(p) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(net.pacing("phone"), Some(p));

        // A gateway switch goes through; with nowhere to go it fails.
        assert!(pipe.switch_gateway().await.is_err(), "no gateways at all");
        net.set_gateway("gw-1", crate::fake::Faults::default());
        net.set_gateway("gw-2", crate::fake::Faults::default());
        let g = pipe.switch_gateway().await.unwrap();
        assert_eq!(net.client_gateway("phone").as_deref(), Some(g.as_str()));

        // A flush is answered (the fake mixnet has nothing in flight).
        assert!(pipe.flush(Duration::from_secs(1)).await);
        assert!(pipe.flush(Duration::from_secs(1)).await);

        // The fake client has spent no tickets.
        assert_eq!(pipe.tickets_spent().await.unwrap(), 0);

        // Fetching through a client that can't comes back as an error.
        assert!(pipe.fetch("GET", "https://x", vec![]).await.is_err());
        assert!(pipe.buy_tickets("https://x", b"t").await.is_err());
    }

    struct Shop;

    #[async_trait::async_trait]
    impl Purchaser for Shop {
        async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
            Ok((
                201,
                [method.as_bytes(), b" ", url.as_bytes(), b" ", &body].concat(),
            ))
        }
        async fn buy(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
            if token.is_empty() {
                return Err(NymError::Client("no token".into()));
            }
            Ok([gate.as_bytes(), token].concat())
        }
    }

    /// Before connecting (`--await-tickets`): fetches and purchases are
    /// answered, imported ticketbooks are collected, and connect hands them
    /// over and starts the client.
    #[tokio::test]
    async fn tickets_before_connecting() {
        let net = FakeMixnet::default();
        let (a, b) = tokio::io::duplex(1 << 20);
        let (ar, aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let far: Arc<dyn MixnetDriver> = Arc::new(net.client("phone"));
        let nymd = tokio::spawn(async move {
            let tickets = serve_starting(&Shop, &mut br, &mut bw).await.unwrap();
            tokio::spawn(serve(far, br, bw));
            tickets
        });
        let mut starting = Starting::new(ar, aw);
        assert_eq!(
            starting
                .fetch("POST", "https://gate/x", b"body")
                .await
                .unwrap(),
            (201, b"POST https://gate/x body".to_vec())
        );
        let book = starting.buy("https://gate", b"token").await.unwrap();
        assert_eq!(book, b"https://gatetoken");
        assert!(starting.buy("https://gate", b"").await.is_err());
        let pipe = starting
            .connect(&[book.clone(), vec![7; 300_000]])
            .await
            .unwrap();
        assert_eq!(pipe.address(), "phone");
        let tickets = nymd.await.unwrap();
        assert_eq!(tickets, vec![book, vec![7; 300_000]]);
    }
}
