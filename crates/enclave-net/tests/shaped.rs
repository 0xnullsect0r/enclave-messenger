//! The shaping transport: what leaves the device per tick doesn't depend on
//! what the user does (`docs/09-transport.md` §9.4).
#![allow(clippy::unwrap_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_net::schedule::Profile;
use enclave_net::shaped::{BULK_PER_TICK, ShapedTransport, Shaping};
use enclave_net::transport::{ServerId, Transport};
use enclave_net::{NetError, Result};
use enclave_rpc::{ServerKey, ServerSecret};
use enclave_wire::{POLL_LEN, UNIT_LEN};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const HOME: ServerId = [7; 16];

/// A network that answers everything at once and counts what it saw.
struct Net {
    key: ServerKey,
    seen: AtomicUsize,
    paced: std::sync::Mutex<Vec<enclave_nym::Pacing>>,
}

#[async_trait::async_trait]
impl Transport for Net {
    async fn exchange(&self, _: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.seen.fetch_add(1, Ordering::SeqCst);
        Ok(vec![0; request.len()])
    }
    /// A key fetch is a request on the link too (a poll-sized one).
    async fn server_key(&self, _: &ServerId) -> Result<ServerKey> {
        self.seen.fetch_add(1, Ordering::SeqCst);
        Ok(self.key.clone())
    }
    fn now(&self) -> u64 {
        86_400 * 20_000
    }
    fn set_pacing(&self, pacing: enclave_nym::Pacing) {
        self.paced.lock().unwrap().push(pacing);
    }
}

fn net() -> Arc<Net> {
    let mut rng = HedgedRng::new().unwrap();
    Arc::new(Net {
        key: ServerSecret::generate(20_000, &mut rng)
            .unwrap()
            .public()
            .clone(),
        seen: AtomicUsize::new(0),
        paced: std::sync::Mutex::default(),
    })
}

fn shaper(p: Profile) -> (Arc<ShapedTransport>, Arc<Net>) {
    let n = net();
    let s = ShapedTransport::start(n.clone(), Shaping::On(p), vec![HOME]);
    s.record();
    (s, n)
}

fn spawn_requests(
    s: &Arc<ShapedTransport>,
    n: usize,
    len: usize,
) -> Vec<tokio::task::JoinHandle<Result<Vec<u8>>>> {
    (0..n)
        .map(|i| {
            let s = Arc::clone(s);
            tokio::spawn(async move { s.exchange(&HOME, vec![i as u8; len]).await })
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn every_tick_is_one_unit_and_one_poll_whatever_the_load() {
    let (s, _) = shaper(Profile::Foreground);
    tokio::time::sleep(Duration::from_secs(15)).await; // idle
    let units = spawn_requests(&s, 3, UNIT_LEN);
    let polls = spawn_requests(&s, 2, POLL_LEN);
    tokio::time::sleep(Duration::from_secs(30)).await;
    for h in units.into_iter().chain(polls) {
        assert!(h.await.unwrap().is_ok(), "every real request was answered");
    }
    let log = s.take_log();
    assert!(log.len() >= 14);
    for t in &log {
        assert_eq!(t.sizes, vec![UNIT_LEN, POLL_LEN], "same shape idle or busy");
    }
    assert_eq!(
        log.iter().map(|t| t.real).sum::<usize>(),
        5,
        "real replaced cover"
    );
    assert!(
        log[..4].iter().all(|t| t.real == 0),
        "idle ticks are all cover"
    );
}

#[tokio::test(start_paused = true)]
async fn bursts_in_foreground_never_in_maximum() {
    let (fg, _) = shaper(Profile::Foreground);
    let hs = spawn_requests(&fg, 20, UNIT_LEN);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let log = fg.take_log();
    assert_eq!(log[0].real, 1 + BULK_PER_TICK, "a disclosed burst");
    tokio::time::sleep(Duration::from_secs(10)).await;
    for h in hs {
        assert!(h.await.unwrap().is_ok());
    }

    let (max, _) = shaper(Profile::Maximum);
    let hs = spawn_requests(&max, 6, UNIT_LEN);
    tokio::time::sleep(Duration::from_secs(3 * 8)).await;
    for h in hs {
        assert!(h.await.unwrap().is_ok());
    }
    let log = max.take_log();
    assert!(
        log.iter().all(|t| t.sizes == vec![UNIT_LEN, POLL_LEN]),
        "never a burst"
    );
    assert_eq!(log.iter().map(|t| t.real).sum::<usize>(), 6);
}

#[tokio::test(start_paused = true)]
async fn droppable_requests_never_add_traffic() {
    let (s, _) = shaper(Profile::Maximum);
    // Alone, it takes the next free slot.
    let typing = {
        let s = Arc::clone(&s);
        tokio::spawn(async move { s.exchange_droppable(&HOME, vec![1; UNIT_LEN]).await })
    };
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(typing.await.unwrap().is_ok());

    // Behind real traffic that fills every slot, it is dropped.
    let real = spawn_requests(&s, 4, UNIT_LEN);
    tokio::task::yield_now().await;
    let typing = {
        let s = Arc::clone(&s);
        tokio::spawn(async move { s.exchange_droppable(&HOME, vec![2; UNIT_LEN]).await })
    };
    tokio::time::sleep(Duration::from_secs(3 * 6)).await;
    assert!(matches!(typing.await.unwrap(), Err(NetError::Dropped)));
    for h in real {
        assert!(h.await.unwrap().is_ok());
    }
    let log = s.take_log();
    assert!(log.iter().all(|t| t.sizes == vec![UNIT_LEN, POLL_LEN]));
}

#[tokio::test(start_paused = true)]
async fn off_sends_at_once() {
    let n = net();
    let s = ShapedTransport::start(n.clone(), Shaping::Off, vec![HOME]);
    s.record();
    let r = s.exchange(&HOME, vec![0; UNIT_LEN]).await;
    assert!(r.is_ok());
    assert_eq!(n.seen.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(s.take_log().is_empty(), "no ticks, no cover");
}

#[tokio::test(start_paused = true)]
async fn bulk_transfers_skip_the_clock_except_in_maximum() {
    let (s, n) = shaper(Profile::Foreground);
    s.set_bulk(true);
    for _ in 0..5 {
        assert!(s.exchange(&HOME, vec![0; UNIT_LEN]).await.is_ok());
    }
    s.set_bulk(false);
    assert_eq!(
        n.seen.load(Ordering::SeqCst),
        5,
        "sent at once, no tick needed"
    );

    let (m, n) = shaper(Profile::Maximum);
    m.set_bulk(true);
    let h = spawn_requests(&m, 2, UNIT_LEN);
    tokio::time::sleep(Duration::from_secs(7)).await;
    for h in h {
        assert!(h.await.unwrap().is_ok());
    }
    let log = m.take_log();
    assert!(
        log.iter().all(|t| t.sizes == vec![UNIT_LEN, POLL_LEN]),
        "Maximum ignores bulk: {log:?}"
    );
    assert!(n.seen.load(Ordering::SeqCst) >= 4);
}

/// The mixnet client is told how to pace: the profile's pacing from the
/// start and at each change, the bulk cap around bulk windows and bursts
/// (never in Maximum), and only when something changed.
#[tokio::test(start_paused = true)]
async fn pacing_follows_the_profile_and_bulk() {
    let (s, n) = shaper(Profile::Foreground);
    let paced = || n.paced.lock().unwrap().clone();
    let fg = Profile::Foreground.pacing(false);
    assert_eq!(fg.tick, Duration::from_secs(3));
    assert_eq!(paced(), vec![fg]);

    s.set_bulk(true);
    s.set_bulk(true);
    s.set_bulk(false);
    assert_eq!(paced().last(), Some(&Profile::Foreground.pacing(true)));
    s.set_bulk(false);
    assert_eq!(paced().last(), Some(&fg));
    assert_eq!(paced().len(), 3, "only changes are sent");

    // A burst is paced at the bulk cap, then back at the next tick.
    let hs = spawn_requests(&s, 20, UNIT_LEN);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(paced()[3..].iter().any(|p| p.bulk), "{:?}", paced());
    tokio::time::sleep(Duration::from_secs(10)).await;
    for h in hs {
        assert!(h.await.unwrap().is_ok());
    }
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(paced().last(), Some(&fg));

    // Background: loop cover once per tick on average.
    s.set_shaping(Shaping::On(Profile::Background));
    let bg = *paced().last().unwrap();
    assert_eq!(
        (bg.loop_cover, bg.probe),
        (Duration::from_secs(160), Duration::from_secs(480))
    );

    // Maximum never paces for bulk.
    s.set_shaping(Shaping::On(Profile::Maximum));
    s.set_bulk(true);
    assert!(!paced().last().unwrap().bulk);
    s.set_bulk(false);
    let max = paced()
        .iter()
        .filter(|p| **p == Profile::Maximum.pacing(false))
        .count();
    assert!(max >= 1);
}

/// A first message to another server needs its key: the fetch waits for
/// a poll slot instead of going out between ticks (the CI capture showed
/// one at the start of every busy phase), so every tick keeps its shape.
#[tokio::test(start_paused = true)]
async fn a_key_fetch_takes_a_poll_slot() {
    let (s, n) = shaper(Profile::Foreground);
    tokio::time::sleep(Duration::from_secs(10)).await;
    let before = n.seen.load(Ordering::SeqCst);
    let other: ServerId = [9; 16];
    let k = {
        let s = Arc::clone(&s);
        tokio::spawn(async move { s.server_key(&other).await })
    };
    tokio::task::yield_now().await;
    assert_eq!(
        n.seen.load(Ordering::SeqCst),
        before,
        "nothing leaves between ticks"
    );
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(k.await.unwrap().is_ok(), "the key came in a slot");
    let log = s.take_log();
    assert!(
        log.iter().all(|t| t.sizes == vec![UNIT_LEN, POLL_LEN]),
        "{log:?}"
    );
    // Held from now on: no second fetch.
    let seen = n.seen.load(Ordering::SeqCst);
    assert!(s.server_key(&other).await.is_ok());
    assert_eq!(n.seen.load(Ordering::SeqCst), seen);
}

/// A real poll queued before the first tick, when no key is held yet:
/// the first poll slot fetches a key (the unit slot's cover needs one) and
/// the poll goes a tick later, so even the first tick carries both sizes.
#[tokio::test(start_paused = true)]
async fn the_first_tick_has_both_sizes_with_a_poll_waiting() {
    let (s, _) = shaper(Profile::Background);
    let polls = spawn_requests(&s, 1, POLL_LEN);
    tokio::time::sleep(Duration::from_secs(120 * 20)).await;
    for h in polls {
        assert!(h.await.unwrap().is_ok(), "the poll was answered");
    }
    let log = s.take_log();
    assert!(log.len() >= 2);
    assert!(
        log.iter().all(|t| t.sizes == vec![UNIT_LEN, POLL_LEN]),
        "{log:?}"
    );
}
