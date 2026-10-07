//! Traffic-shape tests (`docs/20-assurance.md`): what an observer who sees
//! every packet can learn must not depend on whether the user is talking.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_net::schedule::{Mailbox, Outgoing, Priority, Profile, Scheduler};
use enclave_rpc::ServerSecret;
use enclave_wire::{ENVELOPE_LEN, Op, POLL_LEN, RequestHeader, UNIT_LEN};

fn boxes() -> Vec<Mailbox> {
    vec![
        Mailbox {
            server: [1; 16],
            weight: 1,
        },
        Mailbox {
            server: [2; 16],
            weight: 1,
        },
    ]
}

/// Two-sample Kolmogorov–Smirnov statistic (ties consumed together).
fn ks(mut a: Vec<f64>, mut b: Vec<f64>) -> f64 {
    a.sort_by(|x, y| x.total_cmp(y));
    b.sort_by(|x, y| x.total_cmp(y));
    let (mut i, mut j, mut d) = (0usize, 0usize, 0f64);
    while i < a.len() || j < b.len() {
        let x = match (a.get(i), b.get(j)) {
            (Some(p), Some(q)) => p.min(*q),
            (Some(p), None) => *p,
            (None, Some(q)) => *q,
            (None, None) => break,
        };
        while i < a.len() && a[i] <= x {
            i += 1;
        }
        while j < b.len() && b[j] <= x {
            j += 1;
        }
        let fa = i as f64 / a.len() as f64;
        let fb = j as f64 / b.len() as f64;
        d = d.max((fa - fb).abs());
    }
    d
}

fn run(profile: Profile, busy: bool, ticks: usize, rng: &mut HedgedRng) -> (Vec<f64>, Vec<usize>) {
    let mut s = Scheduler::new(profile, boxes());
    let mut delays = Vec::with_capacity(ticks);
    let mut polls = Vec::with_capacity(ticks);
    for i in 0..ticks {
        if busy && i % 3 == 0 {
            // Bursts of real traffic, including high-priority peer messages.
            for _ in 0..(i % 5) {
                s.enqueue(Outgoing {
                    server: [7; 16],
                    unit: vec![0; UNIT_LEN],
                    priority: Priority::Peer,
                });
            }
        }
        let t = s.tick(rng);
        delays.push(t.after.as_secs_f64());
        polls.push(t.poll.mailbox);
    }
    (delays, polls)
}

#[test]
fn tick_timing_is_independent_of_real_traffic() {
    let mut rng = HedgedRng::new().unwrap();
    for profile in [Profile::Foreground, Profile::Background, Profile::Maximum] {
        let (idle, idle_polls) = run(profile, false, 3000, &mut rng);
        let (busy, busy_polls) = run(profile, true, 3000, &mut rng);
        let d = ks(idle.clone(), busy.clone());
        // Critical value for alpha = 0.001 with n = m = 3000. The draws come
        // from fresh OS randomness (the hedged RNG can't be seeded), so at
        // 0.01 the Background profile failed by chance about 1 run in 100;
        // a delay that depended on the queue would give a far larger D.
        let crit = 1.949 * ((6000.0) / (3000.0 * 3000.0f64)).sqrt();
        assert!(d < crit, "{profile:?}: KS D = {d} ≥ {crit}");
        // Poll pattern is identical whatever is queued.
        assert_eq!(idle_polls, busy_polls, "{profile:?}");
        let mean: f64 = idle.iter().sum::<f64>() / idle.len() as f64;
        let expect = profile.mean_tick().as_secs_f64();
        assert!(
            (mean - expect).abs() / expect < 0.1,
            "{profile:?}: mean {mean} vs {expect}"
        );
    }
}

#[test]
fn real_and_cover_requests_are_the_same_size_and_look_random() {
    let mut rng = HedgedRng::new().unwrap();
    let server = ServerSecret::generate(1, &mut rng).unwrap();
    let mut real_hist = [0u64; 256];
    let mut cover_hist = [0u64; 256];
    for i in 0..40 {
        let real = RequestHeader {
            op: Op::Write,
            flags: 0,
            mailbox: [3; 32],
            token: [4; 32],
        };
        let cover = RequestHeader {
            op: Op::Cover,
            flags: 0,
            mailbox: [0; 32],
            token: [0; 32],
        };
        // A highly structured real envelope (all zeros) and a cover envelope.
        let (r, _) =
            enclave_rpc::seal_request(server.public(), &real, &vec![0u8; ENVELOPE_LEN], &mut rng)
                .unwrap();
        let (c, _) = enclave_rpc::seal_request(
            server.public(),
            &cover,
            &vec![i as u8; ENVELOPE_LEN],
            &mut rng,
        )
        .unwrap();
        assert_eq!(r.len(), UNIT_LEN);
        assert_eq!(c.len(), UNIT_LEN);
        // Skip the 4-byte cleartext version/suite prefix, identical for all.
        for b in &r[4..] {
            real_hist[*b as usize] += 1;
        }
        for b in &c[4..] {
            cover_hist[*b as usize] += 1;
        }
        let (p, _) = enclave_rpc::seal_poll(server.public(), &real, &mut rng).unwrap();
        assert_eq!(p.len(), POLL_LEN);
    }
    // Chi-square of each against uniform (255 degrees of freedom, alpha 0.001 → 330.5).
    for hist in [real_hist, cover_hist] {
        let n: u64 = hist.iter().sum();
        let e = n as f64 / 256.0;
        let chi: f64 = hist.iter().map(|o| (*o as f64 - e).powi(2) / e).sum();
        assert!(chi < 330.5, "byte distribution not uniform: chi2 = {chi}");
    }
}
