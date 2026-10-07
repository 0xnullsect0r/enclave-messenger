//! The cover-traffic scheduler (`docs/09-transport.md` §9.4).
//!
//! Each *tick* the client emits exactly one 16,384-byte unit (a real write or a
//! cover request) and one 2,048-byte poll (to one mailbox), and receives one
//! unit per request. Tick timing depends only on the profile and randomness,
//! never on whether real traffic is waiting, so an observer who sees every
//! packet learns nothing about when the user is actually talking.
//!
//! | Profile      | When                                  | Tick                  |
//! |--------------|---------------------------------------|-----------------------|
//! | Foreground   | App visible                           | every 3 s             |
//! | Background   | Android service, desktop tray         | Poisson, mean 120 s   |
//! | Maximum      | Opt-in, always                        | every 3 s             |
//!
//! Bulk transfers (media, the McEliece key, catch-up) are the one visible
//! exception and are disclosed to the user; in Maximum they are throttled to
//! the tick rate instead.

use enclave_crypto::rng::HedgedRng;
use std::collections::VecDeque;
use std::time::Duration;

/// The three global profiles. There are deliberately no others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// App in the foreground.
    Foreground,
    /// App in the background (Android foreground service or desktop tray).
    Background,
    /// Maximum privacy: foreground rate at all times.
    Maximum,
}

impl Profile {
    /// Mean time between ticks.
    pub fn mean_tick(self) -> Duration {
        match self {
            Profile::Foreground | Profile::Maximum => Duration::from_secs(3),
            Profile::Background => Duration::from_secs(120),
        }
    }

    /// Whether tick spacing is exponential (Poisson) rather than fixed.
    pub fn poisson(self) -> bool {
        matches!(self, Profile::Background)
    }

    /// Whether bulk bursts are allowed (otherwise bulk rides normal ticks).
    pub fn allows_bulk(self) -> bool {
        !matches!(self, Profile::Maximum)
    }

    /// How the mixnet client paces packets in this profile
    /// (`docs/09-transport.md` §6.3): a tick's packets leave evenly over
    /// 3 s (in Background too: its ticks start at random times, and pacing
    /// over its 120 s mean would delay every answer by up to 2 minutes),
    /// at the bulk cap during a bulk transfer (never in Maximum), and loop
    /// cover is 1 per 10 s, or 1 per tick on average in Background.
    pub fn pacing(self, bulk: bool) -> enclave_nym::Pacing {
        enclave_nym::Pacing {
            tick: Duration::from_secs(3),
            bulk: bulk && self.allows_bulk(),
            loop_cover: match self {
                Profile::Foreground | Profile::Maximum => Duration::from_secs(10),
                Profile::Background => Duration::from_secs(120),
            },
        }
    }
}

/// Priority of queued real traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Delivery to a contact.
    Peer = 0,
    /// Control: token registration, acks, prekey refills.
    Control = 1,
    /// Sync to our own other devices.
    Sync = 2,
    /// Prefetch (blobs the user has not opened yet).
    Prefetch = 3,
}

/// A queued real request (already sealed for its server by the caller).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// Destination server.
    pub server: [u8; 16],
    /// Opaque request bytes (a 16,384-byte unit).
    pub unit: Vec<u8>,
    /// Priority.
    pub priority: Priority,
}

/// What to poll this tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollTarget {
    /// Server holding the mailbox.
    pub server: [u8; 16],
    /// Mailbox index in the caller's list (the caller builds the sealed poll).
    pub mailbox: usize,
}

/// One tick's worth of traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tick {
    /// Delay since the previous tick.
    pub after: Duration,
    /// The unit to send: real if `Some`, otherwise the caller sends cover.
    pub send: Option<Outgoing>,
    /// The mailbox to poll.
    pub poll: PollTarget,
}

/// A mailbox the client polls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    /// Server.
    pub server: [u8; 16],
    /// Relative weight (the account inbox always gets the first poll slot of a
    /// cycle; groups are weighted by recent activity).
    pub weight: u32,
}

/// The scheduler. Deterministic given its RNG, which makes the traffic-shape
/// tests exact.
pub struct Scheduler {
    profile: Profile,
    queue: VecDeque<Outgoing>,
    mailboxes: Vec<Mailbox>,
    rr: usize,
    credit: Vec<u64>,
}

impl Scheduler {
    /// New scheduler. `mailboxes[0]` must be the account inbox.
    pub fn new(profile: Profile, mailboxes: Vec<Mailbox>) -> Self {
        let n = mailboxes.len();
        Self {
            profile,
            queue: VecDeque::new(),
            mailboxes,
            rr: 0,
            credit: vec![0; n],
        }
    }

    /// Switch profile (only at foreground/background transitions).
    pub fn set_profile(&mut self, p: Profile) {
        self.profile = p;
    }

    /// Current profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Queue real traffic. It goes out in the next free tick, in priority order.
    pub fn enqueue(&mut self, o: Outgoing) {
        let pos = self
            .queue
            .iter()
            .position(|x| x.priority > o.priority)
            .unwrap_or(self.queue.len());
        self.queue.insert(pos, o);
    }

    /// Queued real requests.
    pub fn backlog(&self) -> usize {
        self.queue.len()
    }

    /// Replace the polled mailboxes (index 0 stays the account inbox).
    pub fn set_mailboxes(&mut self, m: Vec<Mailbox>) {
        self.credit = vec![0; m.len()];
        self.mailboxes = m;
        self.rr = 0;
    }

    fn delay(&self, rng: &mut HedgedRng) -> Duration {
        let mean = self.profile.mean_tick();
        if !self.profile.poisson() {
            return mean;
        }
        // Exponential: -ln(U) * mean, with U in (0, 1].
        let r: [u8; 8] = rng.array("schedule/delay").unwrap_or([0x80; 8]);
        let u = ((u64::from_be_bytes(r) >> 11) as f64 + 1.0) / ((1u64 << 53) as f64 + 1.0);
        mean.mul_f64(-u.ln())
    }

    /// One tick in this many polls the other mailboxes; the rest poll the
    /// account inbox. Every other tick, except in Background, where ticks
    /// are rare and every 4th keeps the median text latency under 2 min
    /// (`docs/09-transport.md` §6).
    pub fn other_mailbox_period(profile: Profile) -> usize {
        match profile {
            Profile::Background => 4,
            _ => 2,
        }
    }

    fn next_poll(&mut self) -> PollTarget {
        // Most ticks poll the account inbox; one in `period` goes to the
        // other mailboxes by weighted round robin (smooth weighted), falling
        // back to the inbox.
        let period = Self::other_mailbox_period(self.profile);
        let idx = if self.rr % period != period - 1 || self.mailboxes.len() <= 1 {
            0
        } else {
            let total: u64 = self
                .mailboxes
                .iter()
                .skip(1)
                .map(|m| u64::from(m.weight.max(1)))
                .sum();
            let mut best = 1;
            for i in 1..self.mailboxes.len() {
                self.credit[i] += u64::from(self.mailboxes[i].weight.max(1));
                if self.credit[i] > self.credit[best] {
                    best = i;
                }
            }
            self.credit[best] = self.credit[best].saturating_sub(total);
            best
        };
        self.rr = self.rr.wrapping_add(1);
        let server = self.mailboxes.get(idx).map_or([0; 16], |m| m.server);
        PollTarget {
            server,
            mailbox: idx,
        }
    }

    /// Produce the next tick.
    pub fn tick(&mut self, rng: &mut HedgedRng) -> Tick {
        let after = self.delay(rng);
        let send = self.queue.pop_front();
        let poll = self.next_poll();
        Tick { after, send, poll }
    }

    /// Bulk burst: up to `max` queued requests at once, if the profile allows.
    pub fn bulk(&mut self, max: usize) -> Vec<Outgoing> {
        if !self.profile.allows_bulk() {
            return Vec::new();
        }
        let n = max.min(self.queue.len());
        self.queue.drain(..n).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxes() -> Vec<Mailbox> {
        vec![
            Mailbox {
                server: [1; 16],
                weight: 1,
            },
            Mailbox {
                server: [2; 16],
                weight: 3,
            },
            Mailbox {
                server: [3; 16],
                weight: 1,
            },
        ]
    }

    #[test]
    fn priorities_and_replacement() {
        let mut rng = HedgedRng::new().unwrap();
        let mut s = Scheduler::new(Profile::Foreground, boxes());
        s.enqueue(Outgoing {
            server: [9; 16],
            unit: vec![1],
            priority: Priority::Sync,
        });
        s.enqueue(Outgoing {
            server: [9; 16],
            unit: vec![2],
            priority: Priority::Peer,
        });
        assert_eq!(s.tick(&mut rng).send.unwrap().unit, vec![2]);
        assert_eq!(s.tick(&mut rng).send.unwrap().unit, vec![1]);
        assert!(
            s.tick(&mut rng).send.is_none(),
            "empty queue means a cover slot"
        );
    }

    #[test]
    fn inbox_polled_every_other_tick_and_weights_respected() {
        let mut rng = HedgedRng::new().unwrap();
        let mut s = Scheduler::new(Profile::Foreground, boxes());
        let mut counts = [0usize; 3];
        for i in 0..400 {
            let t = s.tick(&mut rng);
            if i % 2 == 0 {
                assert_eq!(t.poll.mailbox, 0);
            }
            counts[t.poll.mailbox] += 1;
        }
        assert_eq!(counts[0], 200);
        assert_eq!(counts[1], 150);
        assert_eq!(counts[2], 50);
    }

    /// In Background the other mailboxes get every 4th tick.
    #[test]
    fn background_polls_the_inbox_three_ticks_in_four() {
        let mut rng = HedgedRng::new().unwrap();
        let mut s = Scheduler::new(Profile::Background, boxes());
        let mut counts = [0usize; 3];
        for i in 0..400 {
            let t = s.tick(&mut rng);
            if i % 4 != 3 {
                assert_eq!(t.poll.mailbox, 0);
            }
            counts[t.poll.mailbox] += 1;
        }
        assert_eq!(counts, [300, 75, 25]);
    }

    #[test]
    fn maximum_has_no_bulk() {
        let mut s = Scheduler::new(Profile::Maximum, boxes());
        s.enqueue(Outgoing {
            server: [9; 16],
            unit: vec![1],
            priority: Priority::Prefetch,
        });
        assert!(s.bulk(10).is_empty());
        s.set_profile(Profile::Foreground);
        assert_eq!(s.bulk(10).len(), 1);
    }
}
