//! An in-process mixnet for tests and the simulator: addresses, single-use
//! reply blocks under a fresh tag per message, and injected loss, delay and
//! reordering (the plan's tier-1 Nym tests, `docs/completion-plan.md` X16).

use crate::{Incoming, MixnetDriver, NymError, Pacing, ReplyTag, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// What the fake network does to messages.
#[derive(Clone, Copy, Debug, Default)]
pub struct Faults {
    /// Fraction of messages (and replies) lost, 0 to 1.
    pub loss: f64,
    /// Each message is delayed by a uniform time in `[0, max_delay]`, so
    /// messages overtake each other.
    pub max_delay: Duration,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Messages sent (requests).
    pub sent: u64,
    /// Replies sent over reply blocks.
    pub replies: u64,
    /// Messages or replies the network dropped.
    pub lost: u64,
    /// Replies refused: no reply blocks left for the tag.
    pub refused: u64,
}

struct Hub {
    endpoints: HashMap<String, mpsc::UnboundedSender<Incoming>>,
    /// Tag → the address its reply blocks lead to, and how many are left.
    tags: HashMap<[u8; 16], (String, u32)>,
    faults: Faults,
    rng: u64,
    stats: Stats,
    /// The pacing each client was last given.
    pacing: HashMap<String, Pacing>,
    /// Gateways in order, with their own faults (on top of the network's).
    gateways: Vec<(String, Faults)>,
    /// Each client's gateway.
    gateway_of: HashMap<String, String>,
}

impl Hub {
    fn next(&mut self) -> u64 {
        // xorshift64*: deterministic for a seed, plenty for fault injection.
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn gateway_faults(&self, client: &str) -> Faults {
        let Some(g) = self.gateway_of.get(client) else {
            return Faults::default();
        };
        self.gateways
            .iter()
            .find(|(n, _)| n == g)
            .map(|(_, f)| *f)
            .unwrap_or_default()
    }

    /// Deliver `msg` from `from` to `to`, or lose it: the network's faults
    /// apply, then those of each end's gateway.
    fn deliver(&mut self, from: &str, to: &str, msg: Incoming) -> Result<()> {
        let tx = self
            .endpoints
            .get(to)
            .cloned()
            .ok_or(NymError::UnknownRecipient)?;
        let mut delay = Duration::ZERO;
        for f in [
            self.faults,
            self.gateway_faults(from),
            self.gateway_faults(to),
        ] {
            if f.loss > 0.0 && self.unit() < f.loss {
                self.stats.lost += 1;
                return Ok(());
            }
            delay += f.max_delay.mul_f64(self.unit());
        }
        if delay.is_zero() {
            let _ = tx.send(msg);
        } else {
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = tx.send(msg);
            });
        }
        Ok(())
    }
}

/// The network. Cloning shares it.
#[derive(Clone)]
pub struct FakeMixnet {
    hub: Arc<Mutex<Hub>>,
}

impl Default for FakeMixnet {
    fn default() -> Self {
        Self::new(Faults::default(), 1)
    }
}

impl FakeMixnet {
    /// A network with these faults; `seed` makes them reproducible.
    pub fn new(faults: Faults, seed: u64) -> Self {
        Self {
            hub: Arc::new(Mutex::new(Hub {
                endpoints: HashMap::new(),
                tags: HashMap::new(),
                faults,
                rng: seed | 1,
                stats: Stats::default(),
                pacing: HashMap::new(),
                gateways: Vec::new(),
                gateway_of: HashMap::new(),
            })),
        }
    }

    /// Change the faults (a gateway going bad, then recovering).
    pub fn set_faults(&self, faults: Faults) {
        if let Ok(mut h) = self.hub.lock() {
            h.faults = faults;
        }
    }

    /// A client on this network at `address`.
    pub fn client(&self, address: &str) -> FakeClient {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut h) = self.hub.lock() {
            h.endpoints.insert(address.to_string(), tx);
        }
        FakeClient {
            hub: Arc::clone(&self.hub),
            address: address.to_string(),
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    /// Add a gateway with its own faults (or change them).
    pub fn set_gateway(&self, name: &str, faults: Faults) {
        if let Ok(mut h) = self.hub.lock() {
            match h.gateways.iter_mut().find(|(n, _)| n == name) {
                Some(g) => g.1 = faults,
                None => h.gateways.push((name.to_string(), faults)),
            }
        }
    }

    /// A client at `address` behind `gateway` (added with
    /// [`FakeMixnet::set_gateway`]).
    pub fn client_at(&self, address: &str, gateway: &str) -> FakeClient {
        let c = self.client(address);
        if let Ok(mut h) = self.hub.lock() {
            h.gateway_of
                .insert(address.to_string(), gateway.to_string());
        }
        c
    }

    /// The gateway the client at `address` is behind.
    pub fn client_gateway(&self, address: &str) -> Option<String> {
        self.hub.lock().ok()?.gateway_of.get(address).cloned()
    }

    /// The pacing the client at `address` was last given.
    pub fn pacing(&self, address: &str) -> Option<Pacing> {
        self.hub.lock().ok()?.pacing.get(address).copied()
    }

    /// The counters.
    pub fn stats(&self) -> Stats {
        self.hub.lock().map(|h| h.stats).unwrap_or_default()
    }
}

/// One client of a [`FakeMixnet`].
pub struct FakeClient {
    hub: Arc<Mutex<Hub>>,
    address: String,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Incoming>>,
}

#[async_trait::async_trait]
impl MixnetDriver for FakeClient {
    fn address(&self) -> String {
        self.address.clone()
    }

    async fn send(&self, to: &str, data: Vec<u8>, reply_len: usize) -> Result<()> {
        let mut h = self.hub.lock().map_err(|_| NymError::Closed)?;
        h.stats.sent += 1;
        let reply = if reply_len > 0 {
            // A fresh tag for every message: replies can't be linked to
            // each other by tag.
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&h.next().to_le_bytes());
            tag[8..].copy_from_slice(&h.next().to_le_bytes());
            h.tags.insert(tag, (self.address.clone(), 1));
            Some(ReplyTag(tag))
        } else {
            None
        };
        h.deliver(&self.address, to, Incoming { data, reply })
    }

    async fn reply(&self, tag: ReplyTag, data: Vec<u8>) -> Result<()> {
        let mut h = self.hub.lock().map_err(|_| NymError::Closed)?;
        let to = match h.tags.get_mut(&tag.0) {
            Some((to, left)) if *left > 0 => {
                *left -= 1;
                to.clone()
            }
            _ => {
                h.stats.refused += 1;
                return Err(NymError::NoSurbs);
            }
        };
        h.tags.retain(|_, (_, left)| *left > 0);
        h.stats.replies += 1;
        h.deliver(&self.address, &to, Incoming { data, reply: None })
    }

    async fn recv(&self) -> Option<Incoming> {
        self.rx.lock().await.recv().await
    }

    fn set_pacing(&self, pacing: Pacing) {
        if let Ok(mut h) = self.hub.lock() {
            h.pacing.insert(self.address.clone(), pacing);
        }
    }

    fn gateway(&self) -> Option<String> {
        self.hub.lock().ok()?.gateway_of.get(&self.address).cloned()
    }

    /// Move to the next gateway after the current one (the address stays).
    async fn switch_gateway(&self) -> Result<String> {
        let mut h = self.hub.lock().map_err(|_| NymError::Closed)?;
        let current = h.gateway_of.get(&self.address).cloned();
        let names: Vec<String> = h.gateways.iter().map(|(n, _)| n.clone()).collect();
        let at = current
            .as_ref()
            .and_then(|c| names.iter().position(|n| n == c))
            .unwrap_or(0);
        let next = (1..names.len())
            .map(|i| &names[(at + i) % names.len()])
            .find(|n| Some(*n) != current.as_ref())
            .cloned()
            .ok_or_else(|| NymError::Client("no other gateway".into()))?;
        h.gateway_of.insert(self.address.clone(), next.clone());
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn reply_blocks_are_single_use() {
        let net = FakeMixnet::default();
        let a = net.client("a");
        let b = net.client("b");
        a.send("b", b"hi".to_vec(), 100).await.unwrap();
        let got = b.recv().await.unwrap();
        assert_eq!(got.data, b"hi");
        let tag = got.reply.unwrap();
        b.reply(tag, b"yo".to_vec()).await.unwrap();
        assert_eq!(a.recv().await.unwrap().data, b"yo");
        assert_eq!(
            b.reply(tag, b"again".to_vec()).await,
            Err(NymError::NoSurbs)
        );
        // Two messages, two different tags.
        a.send("b", b"1".to_vec(), 1).await.unwrap();
        a.send("b", b"2".to_vec(), 1).await.unwrap();
        let (x, y) = (b.recv().await.unwrap(), b.recv().await.unwrap());
        assert_ne!(x.reply, y.reply);
        // No reply blocks asked for: no tag.
        a.send("b", b"oneway".to_vec(), 0).await.unwrap();
        assert_eq!(b.recv().await.unwrap().reply, None);
        assert_eq!(
            a.send("nobody", vec![], 0).await,
            Err(NymError::UnknownRecipient)
        );
        let s = net.stats();
        assert_eq!((s.sent, s.replies, s.refused), (5, 1, 1));
    }

    #[tokio::test]
    async fn loss_is_injected() {
        let net = FakeMixnet::new(
            Faults {
                loss: 1.0,
                ..Faults::default()
            },
            7,
        );
        let a = net.client("a");
        let _b = net.client("b");
        a.send("b", vec![1], 0).await.unwrap();
        assert_eq!(net.stats().lost, 1);
    }
}
