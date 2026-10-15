//! Equihash⟨60,3⟩ over BLAKE2b: the asymmetric puzzle under Enclave's proof
//! of work (`docs/02-cryptography.md` §10, ADR 0004).
//!
//! The generalized birthday problem (Biryukov and Khovratovich, "Equihash:
//! asymmetric proof-of-work based on the generalized birthday problem",
//! NDSS 2016) with n = 60 and k = 3: find eight distinct indices below
//! 2^16 whose 60-bit hashes XOR to zero, built as Wagner's tree, so a
//! solver needs the whole list (2^16 entries, about 1 MiB with its
//! levels) while a verifier computes eight hashes. Each round zeroes the
//! next 15 bits (the last round 30), and the tree's order is fixed (the
//! smaller first index on the left at every level), so one set of indices
//! is one solution.
//!
//! `H(i)` is the first 8 bytes of BLAKE2b-64 over `digest ‖ u16le(i)`, its
//! low 60 bits, with `digest` = BLAKE2b-256 over the challenge. The same
//! structure as Equi-X (Equihash⟨60,3⟩ over HashX), with a standard hash
//! in place of HashX and none of its LGPL code.

use blake2::digest::consts::U32;
use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b, Blake2bVar, Digest};

type Blake2b256 = Blake2b<U32>;

/// Indices per solution (2^k).
pub const INDICES: usize = 8;
/// Bytes in an encoded solution: eight little-endian `u16`.
pub const SOLUTION_LEN: usize = 2 * INDICES;
/// The list's size (2^(n/(k+1)+1)).
const LIST: usize = 1 << 16;
/// Bits zeroed by each of the first two rounds.
const STEP: u32 = 15;
const MASK60: u64 = (1 << 60) - 1;

/// A solution: eight indices in tree order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Solution(pub [u16; INDICES]);

impl Solution {
    /// The 16-byte encoding.
    pub fn to_bytes(&self) -> [u8; SOLUTION_LEN] {
        let mut out = [0u8; SOLUTION_LEN];
        for (k, i) in self.0.iter().enumerate() {
            out[2 * k..2 * k + 2].copy_from_slice(&i.to_le_bytes());
        }
        out
    }

    /// From the 16-byte encoding.
    pub fn from_bytes(b: &[u8; SOLUTION_LEN]) -> Self {
        let mut idx = [0u16; INDICES];
        for (k, i) in idx.iter_mut().enumerate() {
            *i = u16::from_le_bytes([b[2 * k], b[2 * k + 1]]);
        }
        Solution(idx)
    }
}

/// The challenge's hash function.
struct Hasher {
    digest: [u8; 32],
}

impl Hasher {
    fn new(challenge: &[u8]) -> Self {
        let mut h = Blake2b256::new();
        Digest::update(&mut h, challenge);
        Hasher {
            digest: h.finalize().into(),
        }
    }

    fn hash(&self, i: u16) -> u64 {
        let mut h =
            Blake2bVar::new(8).unwrap_or_else(|_| unreachable!("8 is a valid BLAKE2b size"));
        h.update(&self.digest);
        h.update(&i.to_le_bytes());
        let mut out = [0u8; 8];
        let _ = h.finalize_variable(&mut out);
        u64::from_le_bytes(out) & MASK60
    }
}

fn bits(v: u64, from: u32, n: u32) -> u64 {
    (v >> from) & ((1 << n) - 1)
}

/// Whether `s` solves `challenge`.
pub fn verify(challenge: &[u8], s: &Solution) -> bool {
    let i = s.0;
    // Tree order: each pair ascending, then by first index at each level.
    let ordered = i[0] < i[1]
        && i[2] < i[3]
        && i[4] < i[5]
        && i[6] < i[7]
        && i[0] < i[2]
        && i[4] < i[6]
        && i[0] < i[4];
    if !ordered {
        return false;
    }
    let mut sorted = i;
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return false;
    }
    let h = Hasher::new(challenge);
    let v: Vec<u64> = i.iter().map(|&x| h.hash(x)).collect();
    let pairs = [v[0] ^ v[1], v[2] ^ v[3], v[4] ^ v[5], v[6] ^ v[7]];
    if pairs.iter().any(|p| bits(*p, 0, STEP) != 0) {
        return false;
    }
    let quads = [pairs[0] ^ pairs[1], pairs[2] ^ pairs[3]];
    if quads.iter().any(|q| bits(*q, STEP, STEP) != 0) {
        return false;
    }
    quads[0] ^ quads[1] == 0
}

/// Pair up `items` (value, indices) whose bits `[from, from + n)` agree;
/// each joined item keeps the left one first (the smaller first index)
/// and drops pairs that share an index.
fn join<const A: usize, const B: usize>(
    mut items: Vec<(u64, [u16; A])>,
    from: u32,
    n: u32,
) -> Vec<(u64, [u16; B])> {
    debug_assert_eq!(2 * A, B);
    items.sort_unstable_by_key(|(v, _)| bits(*v, from, n));
    let mut out = Vec::with_capacity(items.len());
    let mut start = 0;
    while start < items.len() {
        let key = bits(items[start].0, from, n);
        let mut end = start + 1;
        while end < items.len() && bits(items[end].0, from, n) == key {
            end += 1;
        }
        for a in start..end {
            for b in a + 1..end {
                let (x, y) = if items[a].1[0] < items[b].1[0] {
                    (&items[a], &items[b])
                } else {
                    (&items[b], &items[a])
                };
                if x.1.iter().any(|i| y.1.contains(i)) {
                    continue;
                }
                let mut idx = [0u16; B];
                idx[..A].copy_from_slice(&x.1);
                idx[A..].copy_from_slice(&y.1);
                out.push((x.0 ^ y.0, idx));
            }
        }
        start = end;
    }
    out
}

/// Every solution to `challenge` (about two on average; sometimes none).
pub fn solve(challenge: &[u8]) -> Vec<Solution> {
    let h = Hasher::new(challenge);
    let list: Vec<(u64, [u16; 1])> = (0..LIST)
        .map(|i| {
            let i = i as u16;
            (h.hash(i), [i])
        })
        .collect();
    let pairs: Vec<(u64, [u16; 2])> = join(list, 0, STEP);
    let quads: Vec<(u64, [u16; 4])> = join(pairs, STEP, STEP);
    let octs: Vec<(u64, [u16; 8])> = join(quads, 2 * STEP, 60 - 2 * STEP);
    let mut out: Vec<Solution> = octs
        .into_iter()
        .filter(|(v, _)| *v == 0)
        .map(|(_, idx)| Solution(idx))
        .filter(|s| verify(challenge, s))
        .collect();
    out.sort_unstable_by_key(|s| s.0);
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solutions_verify_and_only_for_their_challenge() {
        let mut found = 0;
        for n in 0u8..8 {
            let c = [b"enclave-equihash-test-".as_slice(), &[n]].concat();
            for s in solve(&c) {
                found += 1;
                assert!(verify(&c, &s));
                assert!(!verify(b"another challenge", &s));
                assert_eq!(Solution::from_bytes(&s.to_bytes()), s);
            }
        }
        assert!(found > 0, "eight challenges give some solutions");
    }

    #[test]
    fn order_and_distinctness_are_enforced() {
        let c = b"enclave-equihash-order";
        let mut sols = Vec::new();
        for n in 0u8..16 {
            let c = [c.as_slice(), &[n]].concat();
            sols.extend(solve(&c).into_iter().map(|s| (c.clone(), s)));
            if !sols.is_empty() {
                break;
            }
        }
        let (c, s) = sols.first().cloned().expect("a solution");
        // Swapping a pair, the halves of a pair of pairs, or the two halves
        // makes another order of the same indices: refused.
        for (a, b) in [(0, 1), (6, 7)] {
            let mut t = s;
            t.0.swap(a, b);
            assert!(!verify(&c, &t));
        }
        let mut t = s;
        t.0[..4].rotate_left(2);
        assert!(!verify(&c, &t));
        let mut t = s;
        t.0.rotate_left(4);
        assert!(!verify(&c, &t));
        // A repeated index is refused.
        let mut t = s;
        t.0[1] = t.0[0];
        assert!(!verify(&c, &t));
    }

    /// The puzzle is fixed: these challenges give these solutions on every
    /// platform (a change to the hash or the order would break proofs
    /// already made).
    #[test]
    fn known_answers() {
        let start = std::time::Instant::now();
        let c = b"enclave/v1/tokens/equihash-kat";
        let sols: Vec<String> = solve(c)
            .iter()
            .map(|s| s.to_bytes().iter().map(|b| format!("{b:02x}")).collect())
            .collect();
        eprintln!("one solve: {:?}", start.elapsed());
        assert_eq!(sols, KAT.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    }

    const KAT: &[&str] = &[
        "dd01a89dee9da5c7401fcffb628ddffe",
        "f1134f21c27ddcf41a253e5c0d38c1f0",
        "332e1b7c694327f711471de20a9021fd",
    ];
}
