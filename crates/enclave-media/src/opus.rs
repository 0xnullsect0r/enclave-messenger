//! Opus for calls and voice notes: `opus-pure`, a pure-Rust port of
//! libopus (RFC 6716) that both encodes and decodes, 48 kHz mono, at a
//! constant bit rate (every packet one size).
//!
//! Measured against libopus with PESQ (ITU-T P.862.2, wideband) on the
//! nightly job's recording (`docs/11-calls.md` §10): its packets decode in
//! libopus exactly as in its own decoder, and its decoder's loss
//! concealment and FEC recovery score as libopus's do. The SIMD kernels it
//! picks at run time (SSE2, AVX2, NEON) are its only `unsafe`; it runs in
//! mediad's sandbox and the `media` fuzz target covers what it decodes.

use crate::{MediaError, Result};

/// Sample rate.
pub const RATE: u32 = 48_000;
/// Samples per 20 ms frame.
pub const FRAME: usize = (RATE as usize) / 50;
/// The longest a packet may decode to (120 ms), per Opus.
const MAX_DECODED: usize = FRAME * 6;

/// An encoder for one stream: speech, constant bit rate, the highest
/// complexity.
pub struct Encoder(opus_pure::OpusEncoder);

impl Encoder {
    /// At `bitrate` (bits a second), with in-band FEC when `fec` (a copy
    /// of each frame in the next, worth it only where packets get lost).
    pub fn new(bitrate: i32, fec: bool) -> Result<Self> {
        let mut e = opus_pure::OpusEncoder::new(RATE as i32, 1, opus_pure::Application::Voip)
            .map_err(|_| MediaError::Encode)?;
        e.bitrate_bps = bitrate;
        e.rate_control = opus_pure::RateControl::Cbr;
        e.complexity = 10;
        e.use_inband_fec = fec;
        e.use_dtx = false;
        e.packet_loss_perc = 0;
        Ok(Self(e))
    }

    /// The loss the other side reports, in percent (0 to 100): how much of
    /// each packet goes to the copy of the frame before.
    pub fn set_loss(&mut self, percent: u8) {
        self.0.packet_loss_perc = i32::from(percent.min(100));
    }

    /// One 20 ms frame ([`FRAME`] samples; shorter is padded with silence).
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>> {
        let mut frame = [0i16; FRAME];
        let n = pcm.len().min(FRAME);
        frame[..n].copy_from_slice(&pcm[..n]);
        let mut out = vec![0u8; 400];
        let len = self
            .0
            .encode_s16(&frame, FRAME, &mut out)
            .map_err(|_| MediaError::Encode)?;
        if len == 0 {
            return Err(MediaError::Encode);
        }
        out.truncate(len);
        Ok(out)
    }
}

/// A decoder for one stream.
pub struct Decoder(opus_pure::OpusDecoder);

impl Decoder {
    /// A fresh decoder.
    pub fn new() -> Result<Self> {
        opus_pure::OpusDecoder::new(RATE as i32, 1)
            .map(Self)
            .map_err(|_| MediaError::Damaged)
    }

    /// A packet, to its samples (20 ms for ours; up to 120 ms for any).
    pub fn decode(&mut self, packet: &[u8]) -> Result<Vec<i16>> {
        if packet.is_empty() {
            return Err(MediaError::Damaged);
        }
        let mut out = vec![0i16; MAX_DECODED];
        let n = self
            .0
            .decode_s16(packet, MAX_DECODED, &mut out)
            .map_err(|_| MediaError::Damaged)?;
        out.truncate(n);
        Ok(out)
    }

    /// A lost frame rebuilt from the next packet's in-band FEC (or
    /// concealed, when that packet carries none).
    pub fn recover(&mut self, next: &[u8]) -> Result<Vec<i16>> {
        let mut out = vec![0i16; FRAME];
        let n = self
            .0
            .decode_fec_s16(next, FRAME, &mut out)
            .map_err(|_| MediaError::Damaged)?;
        out.truncate(n);
        Ok(out)
    }

    /// A lost frame concealed.
    pub fn conceal(&mut self) -> Result<Vec<i16>> {
        let mut out = vec![0i16; FRAME];
        let n = self
            .0
            .decode_s16(&[], FRAME, &mut out)
            .map_err(|_| MediaError::Damaged)?;
        out.truncate(n);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A voice-like signal through the codec: constant-size packets, and
    /// what comes back follows what went in (after the codec's delay).
    #[test]
    fn speech_comes_back_close() {
        let pcm: Vec<i16> = (0..FRAME * 100)
            .map(|i| {
                let t = i as f32 / RATE as f32;
                let voice: f32 = (1..=8)
                    .map(|h| (2.0 * std::f32::consts::PI * 140.0 * h as f32 * t).sin() / h as f32)
                    .sum();
                (6_000.0 * voice) as i16
            })
            .collect();
        let mut e = Encoder::new(32_000, true).unwrap();
        e.set_loss(10);
        let mut d = Decoder::new().unwrap();
        let mut out = Vec::new();
        let mut sizes = std::collections::BTreeSet::new();
        for f in pcm.chunks(FRAME) {
            let p = e.encode(f).unwrap();
            sizes.insert(p.len());
            out.extend(d.decode(&p).unwrap());
        }
        assert_eq!(sizes.len(), 1, "constant bit rate: {sizes:?}");
        // The best match over the codec's delay (up to 10 ms), on the last
        // second (past the start-up).
        let tail = &pcm[FRAME * 50..FRAME * 95];
        let best = (0..480)
            .map(|lag| {
                let got = &out[FRAME * 50 + lag..FRAME * 95 + lag];
                let (mut sxy, mut sxx, mut syy) = (0f64, 0f64, 0f64);
                for (x, y) in tail.iter().zip(got) {
                    let (x, y) = (f64::from(*x), f64::from(*y));
                    sxy += x * y;
                    sxx += x * x;
                    syy += y * y;
                }
                sxy / (sxx * syy).sqrt().max(1.0)
            })
            .fold(f64::MIN, f64::max);
        assert!(best > 0.9, "correlation {best:.3}");
        // A lost frame is rebuilt from the next packet, or concealed.
        let p1 = e.encode(&pcm[..FRAME]).unwrap();
        let p2 = e.encode(&pcm[FRAME..2 * FRAME]).unwrap();
        let _ = p1;
        assert_eq!(d.recover(&p2).unwrap().len(), FRAME);
        assert_eq!(d.conceal().unwrap().len(), FRAME);
    }
}
