//! The "Shape" rows of the red-team matrix (RT-01, RT-12): what an
//! observer of the device's link records, request by request, on the
//! running shaper, with tokio's clock paused so hours pass in moments.
//! `cargo xtask shape` runs these with the scheduler-level checks in
//! `shape.rs`.
#![allow(clippy::unwrap_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_net::Result;
use enclave_net::schedule::Profile;
use enclave_net::shaped::{ShapedTransport, Shaping};
use enclave_net::transport::{ServerId, Transport};
use enclave_rpc::{ServerKey, ServerSecret};
use enclave_wire::{POLL_LEN, UNIT_LEN};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

/// What a watcher of the link sees: when each request left, and its size.
struct Link {
    key: ServerKey,
    seen: Mutex<Vec<(Instant, usize)>>,
    paced: Mutex<Vec<enclave_nym::Pacing>>,
}

#[async_trait::async_trait]
impl Transport for Link {
    async fn exchange(&self, _: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.seen
            .lock()
            .unwrap()
            .push((Instant::now(), request.len()));
        Ok(vec![0; request.len()])
    }
    /// On the mixnet a key fetch is a poll-sized frame with a poll-sized
    /// answer (`enclave_nym::frame`), so the watcher sees a poll.
    async fn server_key(&self, _: &ServerId) -> Result<ServerKey> {
        self.seen.lock().unwrap().push((Instant::now(), POLL_LEN));
        Ok(self.key.clone())
    }
    fn now(&self) -> u64 {
        86_400 * 20_000
    }
    fn set_pacing(&self, pacing: enclave_nym::Pacing) {
        self.paced.lock().unwrap().push(pacing);
    }
}

fn link() -> Arc<Link> {
    let mut rng = HedgedRng::new().unwrap();
    Arc::new(Link {
        key: ServerSecret::generate(20_000, &mut rng)
            .unwrap()
            .public()
            .clone(),
        seen: Mutex::default(),
        paced: Mutex::default(),
    })
}

/// One client: its servers (contacts on other servers add some) and how
/// many real requests it makes, at random moments, while it runs.
struct Client {
    servers: Vec<ServerId>,
    real: usize,
}

/// Run `client` for `ticks` mean ticks of `profile`; the link's log, the
/// pacing it was given, and how many real requests were answered.
async fn observe(
    profile: Profile,
    client: Client,
    ticks: u32,
) -> (Vec<(Instant, usize)>, Vec<enclave_nym::Pacing>, usize) {
    let l = link();
    let shaper = ShapedTransport::start(l.clone(), Shaping::On(profile), client.servers.clone());
    let span = profile.mean_tick() * ticks;
    let mut rng = HedgedRng::new().unwrap();
    // Real requests at random moments, one in each of `real` equal parts
    // of the run, to every server the client knows, in both sizes. (Fully
    // uniform moments now and then put more than BULK_AFTER of one size in
    // one long Background gap, which the shaper rightly answers with a
    // disclosed burst: a different workload from the one these tests
    // describe.)
    let mut jobs = Vec::new();
    let part = span.as_millis() / client.real.max(1) as u128;
    for i in 0..client.real {
        let at = Duration::from_millis(
            (i as u128 * part
                + u128::from(rng.array::<4>("t").map(u32::from_le_bytes).unwrap()) * part
                    / u128::from(u32::MAX)) as u64,
        );
        let server = client.servers[i % client.servers.len()];
        let len = if i % 3 == 0 { POLL_LEN } else { UNIT_LEN };
        let s = Arc::clone(&shaper);
        jobs.push(tokio::spawn(async move {
            tokio::time::sleep(at).await;
            s.exchange(&server, vec![i as u8; len]).await
        }));
    }
    tokio::time::sleep(span).await;
    // Let the last real requests find a slot.
    tokio::time::sleep(profile.mean_tick() * 40).await;
    let answered = {
        let mut n = 0;
        for j in jobs {
            if matches!(j.await, Ok(Ok(_))) {
                n += 1;
            }
        }
        n
    };
    drop(shaper);
    let seen = std::mem::take(&mut *l.seen.lock().unwrap());
    let paced = std::mem::take(&mut *l.paced.lock().unwrap());
    // Only the observed span counts: the tail let real requests finish.
    let start = seen.first().map(|s| s.0).unwrap_or_else(Instant::now);
    let seen = seen
        .into_iter()
        .filter(|(t, _)| t.duration_since(start) < span)
        .collect();
    (seen, paced, answered)
}

/// Gaps between the units, in seconds (one unit leaves per tick).
fn unit_gaps(seen: &[(Instant, usize)]) -> Vec<f64> {
    let units: Vec<Instant> = seen
        .iter()
        .filter(|(_, n)| *n == UNIT_LEN)
        .map(|(t, _)| *t)
        .collect();
    units
        .windows(2)
        .map(|w| w[1].duration_since(w[0]).as_secs_f64())
        .collect()
}

/// Requests per tick: the sizes leaving at one instant.
fn ticks(seen: &[(Instant, usize)]) -> Vec<Vec<usize>> {
    let mut out: Vec<(Instant, Vec<usize>)> = Vec::new();
    for (t, n) in seen {
        match out.last_mut() {
            Some((at, sizes)) if at == t => sizes.push(*n),
            _ => out.push((*t, vec![*n])),
        }
    }
    out.into_iter()
        .map(|(_, mut s)| {
            s.sort_unstable();
            s
        })
        .collect()
}

/// Two-sample Kolmogorov–Smirnov statistic.
fn ks2(mut a: Vec<f64>, mut b: Vec<f64>) -> f64 {
    a.sort_by(f64::total_cmp);
    b.sort_by(f64::total_cmp);
    let (mut i, mut j, mut d) = (0usize, 0usize, 0f64);
    while i < a.len() && j < b.len() {
        let x = a[i].min(b[j]);
        while i < a.len() && a[i] <= x {
            i += 1;
        }
        while j < b.len() && b[j] <= x {
            j += 1;
        }
        d = d.max((i as f64 / a.len() as f64 - j as f64 / b.len() as f64).abs());
    }
    d
}

/// The two-sample bound at α = 10⁻⁶ (the draws come from OS randomness, so
/// a looser α fails by chance now and then; a queue-dependent delay still
/// lands far above this).
fn ks2_bound(n: usize, m: usize) -> f64 {
    let c = (-(1e-6f64 / 2.0).ln() / 2.0).sqrt();
    c * ((n + m) as f64 / (n * m) as f64).sqrt()
}

/// One-sample KS statistic against the exponential with mean `mean`.
fn ks_exponential(mut a: Vec<f64>, mean: f64) -> f64 {
    a.sort_by(f64::total_cmp);
    let n = a.len() as f64;
    a.iter()
        .enumerate()
        .map(|(i, x)| {
            let f = 1.0 - (-x / mean).exp();
            (f - i as f64 / n).abs().max((f - (i + 1) as f64 / n).abs())
        })
        .fold(0.0, f64::max)
}

const HOME: ServerId = [7; 16];

/// RT-01: a device left alone in the Background profile still sends one
/// unit and one poll per tick, at Poisson times with the profile's mean,
/// so its link looks the same whether or not anyone is talking to it and
/// whether or not it is open.
#[tokio::test(start_paused = true)]
async fn rt01_background_profile_constant_when_idle() {
    const N: u32 = 2_000;
    let idle = Client {
        servers: vec![HOME],
        real: 0,
    };
    let (seen, _, _) = observe(Profile::Background, idle, N).await;
    let per_tick = ticks(&seen);
    assert!(
        per_tick.len() as f64 > f64::from(N) * 0.9,
        "{} ticks in {N} mean tick lengths",
        per_tick.len()
    );
    for t in &per_tick {
        assert_eq!(
            t,
            &vec![POLL_LEN, UNIT_LEN],
            "every tick: one poll, one unit"
        );
    }
    let gaps = unit_gaps(&seen);
    let mean = Profile::Background.mean_tick().as_secs_f64();
    let d = ks_exponential(gaps.clone(), mean);
    let c = (-(1e-6f64 / 2.0).ln() / 2.0).sqrt();
    let bound = c / (gaps.len() as f64).sqrt();
    assert!(
        d < bound,
        "gaps not Poisson with mean {mean} s: D = {d} ≥ {bound}"
    );
    // The byte budget at the request level: one 16,384 B unit and one
    // 2,048 B poll per 120 s mean tick (`docs/math/cover-traffic.md` §1),
    // 553 KB/h, within 10 %.
    let hours = gaps.iter().sum::<f64>() / 3600.0;
    let bytes: usize = seen.iter().map(|(_, n)| n).sum();
    let per_hour = bytes as f64 / hours;
    let model = (UNIT_LEN + POLL_LEN) as f64 * 3600.0 / mean;
    assert!(
        (per_hour - model).abs() / model < 0.1,
        "{per_hour:.0} B/h against the model's {model:.0}"
    );
}

/// RT-01: real requests replace cover in the fixed slots. Whatever the
/// user does, the times requests leave and their sizes are those of an
/// idle device, in every profile, and every real request still went out.
#[tokio::test(start_paused = true)]
async fn rt01_send_slots_independent_of_real_traffic() {
    for (profile, n) in [
        (Profile::Foreground, 1_500),
        (Profile::Background, 1_000),
        (Profile::Maximum, 1_500),
    ] {
        let idle = observe(
            profile,
            Client {
                servers: vec![HOME],
                real: 0,
            },
            n,
        )
        .await;
        // Busy, but below the bulk threshold: a message every few ticks.
        let real = (n / 4) as usize;
        let busy = observe(
            profile,
            Client {
                servers: vec![HOME],
                real,
            },
            n,
        )
        .await;
        assert_eq!(busy.2, real, "{profile:?}: every real request was answered");
        let (a, b) = (unit_gaps(&idle.0), unit_gaps(&busy.0));
        let d = ks2(a.clone(), b.clone());
        let bound = ks2_bound(a.len(), b.len());
        assert!(
            d < bound,
            "{profile:?}: send times depend on real traffic: D = {d} ≥ {bound}"
        );
        for t in ticks(&busy.0) {
            assert_eq!(
                t,
                vec![POLL_LEN, UNIT_LEN],
                "{profile:?}: a busy tick looks idle"
            );
        }
        assert_eq!(idle.1, busy.1, "{profile:?}: the same packet pacing");
    }
}

/// RT-12: the three profiles are global. Two different clients (one with
/// every contact at home, one with contacts on five servers and much more
/// to send) in the same profile produce the same request sizes per tick,
/// the same distribution of send times and the same packet pacing, so
/// the traffic tells nothing about which client, or whose, it is.
#[tokio::test(start_paused = true)]
async fn rt12_profiles_identical_across_clients() {
    for (profile, n) in [
        (Profile::Foreground, 1_500),
        (Profile::Background, 1_000),
        (Profile::Maximum, 1_500),
    ] {
        let a = observe(
            profile,
            Client {
                servers: vec![HOME],
                real: 10,
            },
            n,
        )
        .await;
        let b = observe(
            profile,
            Client {
                servers: vec![HOME, [1; 16], [2; 16], [3; 16], [4; 16]],
                real: (n / 5) as usize,
            },
            n,
        )
        .await;
        let (ga, gb) = (unit_gaps(&a.0), unit_gaps(&b.0));
        let d = ks2(ga.clone(), gb.clone());
        let bound = ks2_bound(ga.len(), gb.len());
        assert!(
            d < bound,
            "{profile:?}: the clients' timing differs: D = {d} ≥ {bound}"
        );
        let shape = |s: &[(Instant, usize)]| {
            let mut t = ticks(s);
            t.dedup();
            t
        };
        assert_eq!(shape(&a.0), vec![vec![POLL_LEN, UNIT_LEN]], "{profile:?}");
        assert_eq!(shape(&b.0), vec![vec![POLL_LEN, UNIT_LEN]], "{profile:?}");
        assert_eq!(a.1, b.1, "{profile:?}: the pacing is the profile's alone");
        assert_eq!(a.1.first(), Some(&profile.pacing(false)), "{profile:?}");
        let mean = ga.iter().sum::<f64>() / ga.len() as f64;
        let expect = profile.mean_tick().as_secs_f64();
        assert!(
            (mean - expect).abs() / expect < 0.1,
            "{profile:?}: {mean} s"
        );
    }
}
