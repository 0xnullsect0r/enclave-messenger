//! A stack's push egress over Tor (RFC 0010): the server hands its due
//! wakes here (`[push] forward`, `u32 len ‖ wake` frames, as it would to a
//! push relay on its own network), and each goes over one long-lived
//! stream through Tor to the push relay's onion service, in the same
//! framing. Nothing comes back: a push relay answers nothing. The relay
//! sees wakes arrive from Tor, not which server sent them.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// The port the push relay's onion service listens on.
pub const PORT: u16 = 7443;
/// The largest wake frame taken from the server.
pub const MAX_WAKE: usize = 8 * 1024;

/// Take the server's wakes on `listener` and send each to `to` (an onion
/// service) through `dialer`, until the listener fails. With no `to`, the
/// wakes are read and dropped (no push relay configured yet), so the
/// server's forwarder doesn't keep failing.
pub async fn run(listener: TcpListener, dialer: Arc<dyn crate::Dialer>, to: Option<String>) {
    let link: Arc<Mutex<Option<Box<dyn crate::socks::Stream>>>> = Arc::default();
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let (dialer, link, to) = (Arc::clone(&dialer), Arc::clone(&link), to.clone());
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n > MAX_WAKE {
                    return;
                }
                let mut wake = vec![0u8; n];
                if sock.read_exact(&mut wake).await.is_err() {
                    return;
                }
                if let Some(to) = &to
                    && let Err(e) = send(dialer.as_ref(), &link, to, &wake).await
                {
                    // Counted, not detailed: what is woken stays private.
                    eprintln!(
                        "enclave-onion: a wake didn't reach the push relay ({})",
                        e.kind()
                    );
                }
            }
        });
    }
}

/// One wake on the shared stream, opened (or replaced, once, when it went
/// stale) as needed.
async fn send(
    dialer: &dyn crate::Dialer,
    link: &Mutex<Option<Box<dyn crate::socks::Stream>>>,
    to: &str,
    wake: &[u8],
) -> std::io::Result<()> {
    let mut frame = (wake.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(wake);
    let mut s = link.lock().await;
    for attempt in 0..2 {
        if s.is_none() {
            *s = Some(dialer.dial(to, PORT).await?);
        }
        let Some(stream) = s.as_mut() else {
            continue;
        };
        match async {
            stream.write_all(&frame).await?;
            stream.flush().await
        }
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                *s = None;
                if attempt == 1 {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Wakes from two server connections arrive at the relay, in order,
    /// over one stream; with no relay set they are taken and dropped.
    #[tokio::test]
    async fn wakes_reach_the_relay() {
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let got = tokio::spawn(async move {
            let (mut s, _) = relay.accept().await.unwrap();
            let mut wakes = Vec::new();
            for _ in 0..3 {
                let mut n = [0u8; 4];
                s.read_exact(&mut n).await.unwrap();
                let mut b = vec![0u8; u32::from_be_bytes(n) as usize];
                s.read_exact(&mut b).await.unwrap();
                wakes.push(b);
            }
            wakes
        });
        let egress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let egress_addr = egress.local_addr().unwrap();
        let map = format!("relay.onion={relay_addr}");
        struct Mapped(String);
        #[async_trait::async_trait]
        impl crate::Dialer for Mapped {
            async fn dial(
                &self,
                host: &str,
                _: u16,
            ) -> std::io::Result<Box<dyn crate::socks::Stream>> {
                let to = crate::dev_onion(&self.0, host)
                    .ok_or_else(|| std::io::Error::other("unknown"))?;
                Ok(Box::new(tokio::net::TcpStream::connect(to).await?))
            }
        }
        tokio::spawn(run(
            egress,
            Arc::new(Mapped(map)),
            Some("relay.onion".into()),
        ));
        for wakes in [&[&b"one"[..], b"two"][..], &[b"three"]] {
            let mut s = tokio::net::TcpStream::connect(egress_addr).await.unwrap();
            for w in wakes {
                s.write_all(&(w.len() as u32).to_be_bytes()).await.unwrap();
                s.write_all(w).await.unwrap();
            }
            s.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let wakes = got.await.unwrap();
        assert_eq!(
            wakes,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );

        // No relay: the server's frames are still taken.
        let idle = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let idle_addr = idle.local_addr().unwrap();
        tokio::spawn(run(idle, Arc::new(crate::DirectDialer), None));
        let mut s = tokio::net::TcpStream::connect(idle_addr).await.unwrap();
        s.write_all(&3u32.to_be_bytes()).await.unwrap();
        s.write_all(b"abc").await.unwrap();
    }
}
