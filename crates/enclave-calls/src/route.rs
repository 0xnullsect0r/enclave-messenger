//! Choosing the two relays of a call (`docs/11-calls.md` §3.2, RT-18).
//!
//! No single operator should see both ends of a call. The caller takes a
//! relay whose operator family is neither the caller's home server's nor
//! the callee's; the callee takes one whose family is neither its own home
//! server's nor the caller relay's. Among the relays that qualify the
//! choice is random, weighted by declared capacity (equal when none is
//! declared). Family distinctness is never relaxed: with no relay that
//! qualifies there is no private route, and the app says so.

/// A relay as the server list names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Relay id.
    pub id: [u8; 16],
    /// Operator family.
    pub family: String,
    /// Declared capacity (0 counts as 1).
    pub weight: u32,
}

/// The relays not run by any of `avoid` families, picked by `draw`
/// (uniform in `0..u64::MAX`), weighted by capacity.
pub fn pick<'a>(relays: &'a [Candidate], avoid: &[&str], draw: u64) -> Option<&'a Candidate> {
    let eligible: Vec<&Candidate> = relays
        .iter()
        .filter(|r| !r.family.is_empty() && !avoid.iter().any(|f| *f == r.family))
        .collect();
    let total: u64 = eligible.iter().map(|r| u64::from(r.weight.max(1))).sum();
    if total == 0 {
        return None;
    }
    let mut at = draw % total;
    for r in eligible {
        let w = u64::from(r.weight.max(1));
        if at < w {
            return Some(r);
        }
        at -= w;
    }
    None
}

/// The caller's relay: not the caller's home family, not the callee's.
pub fn caller_relay<'a>(
    relays: &'a [Candidate],
    caller_home: &str,
    callee_home: &str,
    draw: u64,
) -> Option<&'a Candidate> {
    pick(relays, &[caller_home, callee_home], draw)
}

/// The callee's relay: not the callee's home family, not the caller
/// relay's family.
pub fn callee_relay<'a>(
    relays: &'a [Candidate],
    callee_home: &str,
    caller_relay_family: &str,
    draw: u64,
) -> Option<&'a Candidate> {
    pick(relays, &[callee_home, caller_relay_family], draw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(n: u8, family: &str, weight: u32) -> Candidate {
        Candidate {
            id: [n; 16],
            family: family.into(),
            weight,
        }
    }

    #[test]
    fn rt18_relays_from_distinct_operator_families() {
        let relays = vec![
            relay(1, "alpha", 1),
            relay(2, "alpha", 1),
            relay(3, "beta", 1),
            relay(4, "gamma", 3),
            relay(5, "delta", 1),
            relay(6, "", 9),
        ];
        // Caller at alpha, callee at beta.
        let mut seen = std::collections::HashSet::new();
        for draw in 0..1_000u64 {
            let draw = draw.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let a = caller_relay(&relays, "alpha", "beta", draw).unwrap_or(&relays[0]);
            assert!(!["alpha", "beta", ""].contains(&a.family.as_str()));
            let b = callee_relay(&relays, "beta", &a.family, draw ^ 0xa5a5).unwrap_or(&relays[0]);
            assert!(!["beta", a.family.as_str(), ""].contains(&b.family.as_str()));
            assert_ne!(a.family, b.family, "one family would see both ends");
            seen.insert((a.id[0], b.id[0]));
        }
        // Every allowed pairing turns up: the choice is random.
        assert!(seen.contains(&(4, 1)) && seen.contains(&(5, 4)) && seen.contains(&(4, 5)));
        // Weighted by capacity: gamma (3) is picked about three times as
        // often as delta (1).
        let gamma = (0..4_000u64)
            .filter(|d| caller_relay(&relays, "alpha", "beta", *d).map(|r| r.id[0]) == Some(4))
            .count();
        assert!((2_800..=3_200).contains(&gamma), "{gamma}");
        // Never relaxed: no relay outside the two homes' families, no route.
        let only = vec![relay(1, "alpha", 1), relay(3, "beta", 1)];
        assert_eq!(caller_relay(&only, "alpha", "beta", 7), None);
        // The callee can't be left with the caller relay's family either.
        let two = vec![relay(4, "gamma", 1)];
        assert_eq!(callee_relay(&two, "beta", "gamma", 0), None);
    }
}
