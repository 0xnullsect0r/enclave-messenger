//! SFrame (RFC 9605) with the EnclaveSeal suite (`docs/11-calls.md` §5).
//!
//! Every header is emitted in the long form with 8-byte KID and CTR fields,
//! so the header, and with it every packet of a stream, has a constant size.

use crate::{CallError, Result, labels};
use enclave_crypto::kmac::kmac256;
use enclave_crypto::seal::{self, SealKey};
use zeroize::Zeroizing;

/// Suite identifier (private use).
pub const SUITE_ID: u16 = 0xF0E1;
/// Header length as emitted (config byte, 8-byte KID, 8-byte CTR).
pub const HEADER_LEN: usize = 17;
/// Tag length.
pub const TAG_LEN: usize = seal::TAG_LEN;
/// Per-frame overhead.
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;
/// Base keys ratchet every this many milliseconds.
pub const EPOCH_MS: u64 = 5_000;
/// A receiver follows at most this many epochs ahead in one jump (60 s).
pub const MAX_EPOCH_JUMP: u32 = 12;
const WINDOW: u64 = 128;

/// Parse an RFC 9605 header: returns `(kid, ctr, header_len)`.
pub fn parse_header(b: &[u8]) -> Result<(u64, u64, usize)> {
    let cfg = *b.first().ok_or(CallError::Malformed)?;
    let mut off = 1usize;
    let mut field = |ext: bool, v: u8| -> Result<u64> {
        if !ext {
            return Ok(u64::from(v));
        }
        let n = usize::from(v) + 1;
        let bytes = b.get(off..off + n).ok_or(CallError::Malformed)?;
        off += n;
        Ok(bytes.iter().fold(0u64, |a, x| a << 8 | u64::from(*x)))
    };
    let kid = field(cfg & 0x80 != 0, (cfg >> 4) & 0x07)?;
    let ctr = field(cfg & 0x08 != 0, cfg & 0x07)?;
    Ok((kid, ctr, off))
}

/// Emit the constant-size header.
pub fn header(kid: u64, ctr: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = 0x80 | (7 << 4) | 0x08 | 7;
    h[1..9].copy_from_slice(&kid.to_be_bytes());
    h[9..].copy_from_slice(&ctr.to_be_bytes());
    h
}

fn kid(participant: u32, epoch: u32) -> u64 {
    u64::from(participant) << 32 | u64::from(epoch)
}

struct EpochKey {
    epoch: u32,
    key: SealKey,
    salt: [u8; 32],
}

fn epoch_key(base: &[u8; 32], participant: u32, epoch: u32) -> EpochKey {
    let out: Zeroizing<[u8; 64]> = Zeroizing::new(kmac256(
        base,
        &kid(participant, epoch).to_be_bytes(),
        labels::SFRAME_KEY,
    ));
    let mut k = [0u8; 32];
    let mut salt = [0u8; 32];
    k.copy_from_slice(&out[..32]);
    salt.copy_from_slice(&out[32..]);
    EpochKey {
        epoch,
        key: SealKey::from_bytes(k),
        salt,
    }
}

fn ratchet(base: &mut Zeroizing<[u8; 32]>, next_epoch: u32) {
    let next: [u8; 32] = kmac256(&base[..], &next_epoch.to_be_bytes(), labels::SFRAME_RATCHET);
    base.copy_from_slice(&next);
}

fn nonce(salt: &[u8; 32], ctr: u64) -> [u8; 32] {
    let mut n = *salt;
    for (i, b) in ctr.to_be_bytes().iter().enumerate() {
        n[24 + i] ^= b;
    }
    n
}

fn ad(hdr: &[u8], metadata: &[u8]) -> Vec<u8> {
    [labels::AD_SFRAME.as_bytes(), hdr, metadata].concat()
}

/// One participant's sending side.
pub struct Sender {
    participant: u32,
    base: Zeroizing<[u8; 32]>,
    current: EpochKey,
    ctr: u64,
}

impl Sender {
    /// Start from `base_{p,0}`.
    pub fn new(participant: u32, base0: &[u8; 32]) -> Self {
        let base = Zeroizing::new(*base0);
        let current = epoch_key(&base, participant, 0);
        Self {
            participant,
            base,
            current,
            ctr: 0,
        }
    }

    /// Protect one frame at `elapsed_ms` since the call started.
    pub fn protect(&mut self, elapsed_ms: u64, metadata: &[u8], frame: &[u8]) -> Result<Vec<u8>> {
        let epoch = u32::try_from(elapsed_ms / EPOCH_MS).map_err(|_| CallError::Malformed)?;
        while self.current.epoch < epoch {
            let next = self.current.epoch + 1;
            ratchet(&mut self.base, next);
            self.current = epoch_key(&self.base, self.participant, next);
            self.ctr = 0;
        }
        let hdr = header(kid(self.participant, self.current.epoch), self.ctr);
        let n = nonce(&self.current.salt, self.ctr);
        let ct = seal::seal_compact(&self.current.key, &n, &ad(&hdr, metadata), frame)?;
        self.ctr += 1;
        Ok([&hdr[..], &ct].concat())
    }

    /// Current epoch.
    pub fn epoch(&self) -> u32 {
        self.current.epoch
    }
}

struct Window {
    top: u64,
    bits: u128,
    any: bool,
}

impl Window {
    fn check(&self, ctr: u64) -> bool {
        if !self.any || ctr > self.top {
            return true;
        }
        let d = self.top - ctr;
        d < WINDOW && self.bits & (1u128 << d) == 0
    }

    fn commit(&mut self, ctr: u64) {
        if !self.any {
            self.any = true;
            self.top = ctr;
            self.bits = 1;
        } else if ctr > self.top {
            let shift = ctr - self.top;
            self.bits = if shift >= WINDOW {
                0
            } else {
                self.bits << shift
            };
            self.bits |= 1;
            self.top = ctr;
        } else {
            self.bits |= 1u128 << (self.top - ctr);
        }
    }
}

/// One remote participant's receiving side. Keeps the current and the
/// previous epoch key (for reordering across a boundary) and nothing older.
pub struct Receiver {
    participant: u32,
    base: Zeroizing<[u8; 32]>,
    current: EpochKey,
    window: Window,
    previous: Option<(EpochKey, Window)>,
}

impl Receiver {
    /// Start from the sender's `base_{p,0}`.
    pub fn new(participant: u32, base0: &[u8; 32]) -> Self {
        let base = Zeroizing::new(*base0);
        let current = epoch_key(&base, participant, 0);
        Self {
            participant,
            base,
            current,
            window: Window {
                top: 0,
                bits: 0,
                any: false,
            },
            previous: None,
        }
    }

    /// Start from the sender's `base_{p,0}`, already at `epoch` (a group
    /// call joined late: epochs count from the call's start).
    pub fn at_epoch(participant: u32, base0: &[u8; 32], epoch: u32) -> Self {
        let mut base = Zeroizing::new(*base0);
        for e in 1..=epoch {
            ratchet(&mut base, e);
        }
        let current = epoch_key(&base, participant, epoch);
        Self {
            participant,
            base,
            current,
            window: Window {
                top: 0,
                bits: 0,
                any: false,
            },
            previous: None,
        }
    }

    /// Verify and decrypt one packet.
    pub fn unprotect(&mut self, packet: &[u8], metadata: &[u8]) -> Result<Vec<u8>> {
        let (k, ctr, hl) = parse_header(packet)?;
        let (p, e) = ((k >> 32) as u32, k as u32);
        if p != self.participant {
            return Err(CallError::UnknownKey);
        }
        let hdr = &packet[..hl];
        let body = &packet[hl..];
        // Epochs come from the packet: compare without overflowing.
        if e == self.current.epoch || e.checked_add(1) == Some(self.current.epoch) {
            let (key, win) = if e == self.current.epoch {
                (&self.current, &mut self.window)
            } else {
                let (k, w) = self.previous.as_mut().ok_or(CallError::UnknownKey)?;
                (&*k, w)
            };
            if !win.check(ctr) {
                return Err(CallError::Replay);
            }
            let pt =
                seal::open_compact(&key.key, &nonce(&key.salt, ctr), &ad(hdr, metadata), body)?;
            win.commit(ctr);
            return Ok(pt);
        }
        if e < self.current.epoch || e - self.current.epoch > MAX_EPOCH_JUMP {
            return Err(CallError::UnknownKey);
        }
        // Newer epoch: derive it on a copy and commit only if the frame opens.
        let mut base = self.base.clone();
        let mut cur = self.current.epoch;
        let mut prev_key = None;
        while cur < e {
            cur += 1;
            ratchet(&mut base, cur);
            if cur + 1 == e {
                prev_key = Some(epoch_key(&base, self.participant, cur));
            }
        }
        let key = epoch_key(&base, self.participant, e);
        let pt = seal::open_compact(&key.key, &nonce(&key.salt, ctr), &ad(hdr, metadata), body)?;
        let old = std::mem::replace(&mut self.current, key);
        let old_window = std::mem::replace(
            &mut self.window,
            Window {
                top: 0,
                bits: 0,
                any: false,
            },
        );
        self.window.commit(ctr);
        self.previous = match prev_key {
            Some(k) => Some((
                k,
                Window {
                    top: 0,
                    bits: 0,
                    any: false,
                },
            )),
            None => Some((old, old_window)),
        };
        self.base = base;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn header_forms() {
        let h = header(0x0000_0001_0000_0002, 77);
        assert_eq!(
            parse_header(&h).unwrap(),
            (0x0000_0001_0000_0002, 77, HEADER_LEN)
        );
        // RFC 9605 short form: KID 5, CTR 3 in the config byte alone.
        assert_eq!(parse_header(&[0x53]).unwrap(), (5, 3, 1));
        // KID in 1 extra byte, CTR short.
        assert_eq!(parse_header(&[0x81, 0xAB]).unwrap(), (0xAB, 1, 2));
        assert!(parse_header(&[0xF8, 1, 2]).is_err(), "truncated");
    }

    #[test]
    fn a_late_receiver_starts_at_the_senders_epoch() {
        let base = [9u8; 32];
        let mut tx = Sender::new(3, &base);
        // Ten minutes into the call (120 epochs, past MAX_EPOCH_JUMP).
        let p = tx.protect(600_000, b"audio", b"hello").unwrap();
        let mut late = Receiver::at_epoch(3, &base, 120);
        assert_eq!(late.unprotect(&p, b"audio").unwrap(), b"hello");
        let mut fresh = Receiver::new(3, &base);
        assert!(fresh.unprotect(&p, b"audio").is_err());
    }

    #[test]
    fn window() {
        let mut w = Window {
            top: 0,
            bits: 0,
            any: false,
        };
        for c in [5u64, 3, 7, 6] {
            assert!(w.check(c));
            w.commit(c);
        }
        assert!(!w.check(5) && !w.check(7));
        assert!(w.check(4));
        w.commit(500);
        assert!(!w.check(300), "too old");
    }
}
