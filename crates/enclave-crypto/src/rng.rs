//! Hedged randomness.
//!
//! Every key generation and encapsulation draws its randomness through
//! [`HedgedRng`]: fresh OS entropy is mixed with a long-term per-device hedge
//! secret and a counter under KMAC256. Output stays unpredictable if either the
//! OS RNG or the hedge secret is good, and a VM snapshot that replays OS
//! entropy still gets distinct output once the counter has moved on.

use crate::error::{Error, Result};
use crate::kmac::Kmac256;
use crate::labels;
use enclave_platform::mem::Secret;
use zeroize::{Zeroize, Zeroizing};

/// Fill `out` from the operating system RNG.
pub fn os_random(out: &mut [u8]) -> Result<()> {
    getrandom::fill(out).map_err(|_| Error::Rng)
}

/// Hedged random number generator.
pub struct HedgedRng {
    /// In locked memory, zeroized on drop.
    hedge: Secret<32>,
    counter: u64,
}

impl HedgedRng {
    /// Create a generator with a device hedge secret (stored in the keystore).
    pub fn with_hedge(hedge: [u8; 32]) -> Self {
        Self {
            hedge: Secret::new(hedge),
            counter: 0,
        }
    }

    /// Create a generator whose hedge secret is itself drawn from the OS.
    /// Useful before a device secret exists (first launch) and in tests.
    pub fn new() -> Result<Self> {
        let mut h = [0u8; 32];
        os_random(&mut h)?;
        let rng = Self::with_hedge(h);
        h.zeroize();
        Ok(rng)
    }

    /// Fill `out` with hedged random bytes. `purpose` is bound into the output
    /// so that draws for different uses are independent even if the OS RNG
    /// repeats.
    pub fn fill(&mut self, purpose: &str, out: &mut [u8]) -> Result<()> {
        let mut os = Zeroizing::new([0u8; 64]);
        os_random(&mut os[..])?;
        let mut k = Kmac256::new(&*self.hedge, labels::RNG_HEDGE.as_bytes());
        k.update_framed(&os[..]);
        k.update(&self.counter.to_be_bytes());
        k.update_framed(purpose.as_bytes());
        k.finalize_xof().read(out);
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    /// Return `N` hedged random bytes.
    pub fn array<const N: usize>(&mut self, purpose: &str) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        self.fill(purpose, &mut out)?;
        Ok(out)
    }
}

/// Deterministic KMACXOF256 byte stream. Used to expand one seed into many
/// keys, and as a reproducible RNG in tests. Not for fresh randomness.
pub struct XofRng {
    reader: crate::kmac::KmacReader,
}

impl XofRng {
    /// Create a stream from `seed` under customization `label`.
    pub fn new(seed: &[u8], label: &str) -> Self {
        Self {
            reader: Kmac256::new(seed, label.as_bytes()).finalize_xof(),
        }
    }

    /// Read the next bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

// Adapters for dependencies that take a `rand_core` 0.6 RNG (Classic McEliece).
// A failure of the OS RNG inside such a callback cannot be reported through the
// 0.6 trait's infallible methods, so `fill_bytes` falls back to aborting the
// draw by panicking; callers use `try_fill_bytes` paths where possible.
impl rand_core_06::RngCore for HedgedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    #[allow(clippy::panic)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.fill("rand_core", dest).is_err() {
            panic!("operating system RNG failure");
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core_06::Error> {
        self.fill("rand_core", dest)
            .map_err(|_| rand_core_06::Error::from(core::num::NonZeroU32::MIN))
    }
}
impl rand_core_06::CryptoRng for HedgedRng {}

impl rand_core_06::RngCore for XofRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core_06::Error> {
        self.fill(dest);
        Ok(())
    }
}
impl rand_core_06::CryptoRng for XofRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_differ() {
        let mut r = HedgedRng::with_hedge([7u8; 32]);
        let a: [u8; 32] = r.array("t").unwrap();
        let b: [u8; 32] = r.array("t").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn xof_is_deterministic() {
        let mut a = XofRng::new(b"seed", "l");
        let mut b = XofRng::new(b"seed", "l");
        let mut x = [0u8; 64];
        let mut y = [0u8; 64];
        a.fill(&mut x);
        b.fill(&mut y);
        assert_eq!(x, y);
        let mut c = XofRng::new(b"seed", "other");
        c.fill(&mut y);
        assert_ne!(x, y);
    }
}
