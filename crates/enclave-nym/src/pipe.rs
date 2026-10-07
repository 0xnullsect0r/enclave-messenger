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
//!            4 ‖ pacing (9, `Pacing::encode`)                  pace
//! from nymd: 1 ‖ address                                       ready (first)
//!            2 ‖ u8 has_tag ‖ [tag (16)] ‖ data                a message
//!            3 ‖ u8 done                                       flushed
//! ```
//!
//! Sends are fire and forget, as on the mixnet itself: a lost one shows as
//! a request that gets no reply.

use crate::{Incoming, MixnetDriver, NymError, Pacing, ReplyTag, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc, oneshot};

type FlushWaiter = Arc<std::sync::Mutex<Option<oneshot::Sender<bool>>>>;

/// Longest frame either way (a mixframe and its header, with room).
pub const MAX_FRAME: usize = 64 * 1024;

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
    address: String,
    writer: Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    rx: Mutex<mpsc::UnboundedReceiver<Incoming>>,
    reader: tokio::task::JoinHandle<()>,
    flushed: FlushWaiter,
    flushing: Mutex<()>,
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
        let reader = tokio::spawn(async move {
            while let Some(b) = read_frame(&mut reader).await {
                if let Some((3, [done])) = b.split_first() {
                    if let Some(w) = waiter.lock().ok().and_then(|mut w| w.take()) {
                        let _ = w.send(*done == 1);
                    }
                    continue;
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
        })
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
        self.address.clone()
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
            loop_cover: Duration::from_secs(10),
        };
        pipe.set_pacing(p);
        for _ in 0..100 {
            if net.pacing("phone") == Some(p) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(net.pacing("phone"), Some(p));

        // A flush is answered (the fake mixnet has nothing in flight).
        assert!(pipe.flush(Duration::from_secs(1)).await);
        assert!(pipe.flush(Duration::from_secs(1)).await);
    }
}
