//! Watching the gateway path for an n-1 attack (RT-02,
//! `docs/09-transport.md` §6.3).
//!
//! A malicious gateway or mix can hold back or flood everything but one
//! target's traffic. The device measures its own path, from its exchanges
//! with servers and from self-loop probes, and moves to another gateway when
//! the path goes bad: more than 10% of the last 50 samples lost, or the
//! median latency of the last 10 more than 5× the median of all 50. It
//! never switches twice within 10 minutes, and starts measuring afresh
//! after a switch.

use std::collections::VecDeque;
use std::time::Duration;

/// Samples a decision looks at.
pub const WINDOW: usize = 50;
/// The most recent samples compared with the window's median.
pub const RECENT: usize = 10;
/// Lost fraction above which the path is bad.
pub const MAX_LOSS: f64 = 0.10;
/// How many times the window's median latency the recent median may be.
pub const MAX_SLOWDOWN: u32 = 5;
/// Shortest time between two switches.
pub const COOLDOWN: Duration = Duration::from_secs(600);

/// Why the path is bad.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Verdict {
    /// This fraction of the window was lost.
    Loss(f64),
    /// Recent latency is this many times the window's median.
    Latency(f64),
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Loss(x) => write!(f, "loss {:.0}%", x * 100.0),
            Verdict::Latency(x) => write!(f, "latency {x:.1}× the median"),
        }
    }
}

/// Samples of one gateway path, in order.
#[derive(Debug, Default)]
pub struct LinkMonitor {
    /// A latency, or `None` for an exchange or probe that never came back.
    samples: VecDeque<Option<Duration>>,
    /// When the last switch happened (seconds on the caller's clock).
    last_switch: Option<u64>,
}

fn median(mut v: Vec<Duration>) -> Option<Duration> {
    if v.is_empty() {
        return None;
    }
    v.sort();
    Some(v[v.len() / 2])
}

impl LinkMonitor {
    /// A monitor with no samples.
    pub fn new() -> Self {
        Self::default()
    }

    /// Something came back after `latency`.
    pub fn arrived(&mut self, latency: Duration) {
        self.push(Some(latency));
    }

    /// Something never came back.
    pub fn lost(&mut self) {
        self.push(None);
    }

    fn push(&mut self, s: Option<Duration>) {
        if self.samples.len() == WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(s);
    }

    /// Samples held.
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether there are no samples.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Whether the path is bad by the rules above (a full window is
    /// needed). Doesn't look at the cooldown.
    pub fn verdict(&self) -> Option<Verdict> {
        if self.samples.len() < WINDOW {
            return None;
        }
        let lost = self.samples.iter().filter(|s| s.is_none()).count();
        let loss = lost as f64 / WINDOW as f64;
        if loss > MAX_LOSS {
            return Some(Verdict::Loss(loss));
        }
        let all = median(self.samples.iter().flatten().copied().collect())?;
        let recent = median(
            self.samples
                .iter()
                .skip(WINDOW - RECENT)
                .flatten()
                .copied()
                .collect(),
        )?;
        if !all.is_zero() && recent > all * MAX_SLOWDOWN {
            return Some(Verdict::Latency(recent.as_secs_f64() / all.as_secs_f64()));
        }
        None
    }

    /// Whether to switch now (`now` in seconds): the path is bad and the
    /// last switch was at least [`COOLDOWN`] ago.
    pub fn should_switch(&self, now: u64) -> Option<Verdict> {
        if let Some(t) = self.last_switch
            && now < t + COOLDOWN.as_secs()
        {
            return None;
        }
        self.verdict()
    }

    /// A switch happened at `now`: measure the new path afresh.
    pub fn switched(&mut self, now: u64) {
        self.last_switch = Some(now);
        self.samples.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn fill(m: &mut LinkMonitor, n: usize, latency: Duration) {
        for _ in 0..n {
            m.arrived(latency);
        }
    }

    #[test]
    fn loss_over_ten_percent() {
        let mut m = LinkMonitor::new();
        fill(&mut m, 45, 400 * MS);
        for _ in 0..5 {
            m.lost();
        }
        assert_eq!(m.verdict(), None, "exactly 10% is still fine");
        m.lost();
        assert_eq!(m.verdict(), Some(Verdict::Loss(0.12)));
    }

    #[test]
    fn latency_over_five_times_the_median() {
        let mut m = LinkMonitor::new();
        fill(&mut m, 40, 400 * MS);
        fill(&mut m, 10, 1_900 * MS);
        assert_eq!(m.verdict(), None, "4.75×");
        fill(&mut m, 10, 2_500 * MS);
        assert!(matches!(m.verdict(), Some(Verdict::Latency(x)) if x > 5.0));
    }

    #[test]
    fn needs_a_full_window_and_respects_the_cooldown() {
        let mut m = LinkMonitor::new();
        for _ in 0..WINDOW - 1 {
            m.lost();
        }
        assert_eq!(m.should_switch(0), None, "49 samples");
        m.lost();
        assert!(m.should_switch(0).is_some());
        m.switched(100);
        assert!(m.is_empty());
        for _ in 0..WINDOW {
            m.lost();
        }
        assert_eq!(m.should_switch(100 + 599), None, "within 10 minutes");
        assert!(m.should_switch(100 + 600).is_some());
    }
}
