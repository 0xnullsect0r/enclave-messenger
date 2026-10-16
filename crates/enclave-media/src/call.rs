//! Call audio (`docs/11-calls.md` §6, §10).
//!
//! Opus at a constant 32 kbit/s in 20 ms frames of 48 kHz mono, DTX off
//! and in-band FEC on, so every frame costs the same whether anyone speaks.
//! The microphone is cleaned up first by WebRTC's audio processing
//! (`sonora`: AEC3 echo cancellation against what was just played, noise
//! suppression, automatic gain), in 10 ms halves. Decoding uses
//! `opus-decoder`, which has no unsafe code; all of this runs in mediad.

use crate::{MediaError, Result};
use sonora::config::{EchoCanceller, GainController2, NoiseSuppression};
use sonora::{AudioProcessing, Config, StreamConfig};

/// Sample rate.
pub const RATE: u32 = 48_000;
/// Samples per frame (20 ms).
pub const FRAME: usize = (RATE as usize) / 50;
/// Encoded bit rate.
pub const BITRATE: i32 = 32_000;
/// Most bytes of one encoded frame (at 32 kbit/s a frame is about 80).
pub const MAX_PACKET: usize = 100;
/// Samples sonora takes at once (10 ms).
const HALF: usize = FRAME / 2;

/// How to decode the next frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decode<'a> {
    /// This frame's packet arrived.
    Packet(&'a [u8]),
    /// It was lost, but the next frame's packet is here: recover it from
    /// that packet's forward error correction.
    Recover(&'a [u8]),
    /// It was lost: conceal it.
    Lost,
}

/// One call's audio: an encoder for the microphone, a decoder for the
/// other person, and the echo canceller between them.
pub struct CallAudio {
    enc: opus_rs::OpusEncoder,
    dec: opus_decoder::OpusDecoder,
    apm: AudioProcessing,
    /// A group call's decoders, one per other participant.
    decoders: std::collections::HashMap<u32, opus_decoder::OpusDecoder>,
}

/// Most other participants one group call decodes.
pub const MAX_SENDERS: usize = 64;

impl CallAudio {
    /// A fresh call.
    pub fn new() -> Result<Self> {
        let mut enc = opus_rs::OpusEncoder::new(RATE as i32, 1, opus_rs::Application::Voip)
            .map_err(|_| MediaError::Encode)?;
        enc.bitrate_bps = BITRATE;
        enc.use_cbr = true;
        enc.use_inband_fec = true;
        enc.packet_loss_perc = 10;
        let dec = opus_decoder::OpusDecoder::new(RATE, 1).map_err(|_| MediaError::Encode)?;
        let apm = AudioProcessing::builder()
            .config(Config {
                echo_canceller: Some(EchoCanceller::default()),
                noise_suppression: Some(NoiseSuppression::default()),
                gain_controller2: Some(GainController2::default()),
                ..Default::default()
            })
            .capture_config(StreamConfig::new(RATE, 1))
            .render_config(StreamConfig::new(RATE, 1))
            .build();
        Ok(Self {
            enc,
            dec,
            apm,
            decoders: std::collections::HashMap::new(),
        })
    }

    /// The microphone's next 20 ms ([`FRAME`] samples; shorter is padded
    /// with silence), echo-cancelled and encoded.
    pub fn encode(&mut self, mic: &[i16]) -> Result<Vec<u8>> {
        let mut pcm = vec![0i16; FRAME];
        let n = mic.len().min(FRAME);
        pcm[..n].copy_from_slice(&mic[..n]);
        let mut clean = vec![0i16; FRAME];
        for (src, dst) in pcm.chunks(HALF).zip(clean.chunks_mut(HALF)) {
            // A failure leaves the frame as it was.
            if self.apm.process_capture_i16(src, dst).is_err() {
                dst.copy_from_slice(src);
            }
        }
        let mut out = vec![0u8; 400];
        let len = self
            .enc
            .encode_i16(&clean, FRAME, &mut out)
            .map_err(|_| MediaError::Encode)?;
        if len == 0 || len > MAX_PACKET {
            return Err(MediaError::Encode);
        }
        out.truncate(len);
        Ok(out)
    }

    /// The next 20 ms to play ([`FRAME`] samples). What is played is the
    /// echo canceller's reference, so call this as frames are played.
    pub fn decode(&mut self, what: Decode<'_>) -> Result<Vec<i16>> {
        let mut pcm = vec![0i16; FRAME];
        let (packet, fec): (&[u8], bool) = match what {
            Decode::Packet(p) => (p, false),
            Decode::Recover(p) => (p, true),
            Decode::Lost => (&[], false),
        };
        if packet.len() > MAX_PACKET {
            return Err(MediaError::Damaged);
        }
        let n = self
            .dec
            .decode(packet, &mut pcm, fec)
            .map_err(|_| MediaError::Damaged)?;
        if n != FRAME {
            return Err(MediaError::Damaged);
        }
        let mut ignored = vec![0i16; HALF];
        for half in pcm.chunks(HALF) {
            let _ = self.apm.process_render_i16(half, &mut ignored);
        }
        Ok(pcm)
    }
}

impl CallAudio {
    /// A group call's next 20 ms: each sender's frame decoded by that
    /// sender's own decoder, mixed (clipped at full scale), and played as
    /// the echo canceller's reference.
    pub fn mix(&mut self, frames: &[(u32, Decode<'_>)]) -> Result<Vec<i16>> {
        let mut sum = vec![0i32; FRAME];
        for (sender, what) in frames {
            if !self.decoders.contains_key(sender) {
                if self.decoders.len() >= MAX_SENDERS {
                    continue;
                }
                let d = opus_decoder::OpusDecoder::new(RATE, 1).map_err(|_| MediaError::Encode)?;
                self.decoders.insert(*sender, d);
            }
            let Some(dec) = self.decoders.get_mut(sender) else {
                continue;
            };
            let (packet, fec): (&[u8], bool) = match what {
                Decode::Packet(p) => (p, false),
                Decode::Recover(p) => (p, true),
                Decode::Lost => (&[], false),
            };
            if packet.len() > MAX_PACKET {
                continue;
            }
            let mut pcm = vec![0i16; FRAME];
            // A damaged frame from one person leaves the others' voices.
            if dec.decode(packet, &mut pcm, fec).is_ok_and(|n| n == FRAME) {
                for (s, p) in sum.iter_mut().zip(pcm) {
                    *s += i32::from(p);
                }
            }
        }
        let mixed: Vec<i16> = sum
            .into_iter()
            .map(|s| s.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16)
            .collect();
        let mut ignored = vec![0i16; HALF];
        for half in mixed.chunks(HALF) {
            let _ = self.apm.process_render_i16(half, &mut ignored);
        }
        Ok(mixed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn tone(frame: usize, hz: f32) -> Vec<i16> {
        (0..FRAME)
            .map(|i| {
                let t = (frame * FRAME + i) as f32 / RATE as f32;
                (8_000.0 * (2.0 * std::f32::consts::PI * hz * t).sin()) as i16
            })
            .collect()
    }

    fn energy(pcm: &[i16]) -> f64 {
        pcm.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / pcm.len() as f64
    }

    #[test]
    fn group_frames_are_decoded_per_sender_and_mixed() {
        let (mut a, mut b, mut me) = (
            CallAudio::new().unwrap(),
            CallAudio::new().unwrap(),
            CallAudio::new().unwrap(),
        );
        // Each sender decoded on its own, for comparison.
        let (mut only_a, mut only_b) = (CallAudio::new().unwrap(), CallAudio::new().unwrap());
        let mut heard = 0;
        for f in 0..40 {
            let pa = a.encode(&tone(f, 440.0)).unwrap();
            let pb = b.encode(&tone(f, 660.0)).unwrap();
            let mixed = me
                .mix(&[(7, Decode::Packet(&pa)), (9, Decode::Packet(&pb))])
                .unwrap();
            let (da, db) = (
                only_a.decode(Decode::Packet(&pa)).unwrap(),
                only_b.decode(Decode::Packet(&pb)).unwrap(),
            );
            let expect: Vec<i16> = da
                .iter()
                .zip(&db)
                .map(|(x, y)| (i32::from(*x) + i32::from(*y)).clamp(-32768, 32767) as i16)
                .collect();
            assert_eq!(mixed, expect, "frame {f}: the sum of both voices");
            if energy(&da) > 1e5 && energy(&db) > 1e5 {
                heard += 1;
            }
        }
        assert!(heard > 20, "both voices came through ({heard} frames)");
        // A lost frame from one sender, garbage from another: still a frame.
        assert_eq!(
            me.mix(&[(7, Decode::Lost), (9, Decode::Packet(&[0xff; 50]))])
                .unwrap()
                .len(),
            FRAME
        );
    }

    #[test]
    fn frames_are_constant_size_and_decode() {
        let mut a = CallAudio::new().unwrap();
        let mut b = CallAudio::new().unwrap();
        let mut sizes = std::collections::BTreeSet::new();
        let mut heard = 0.0;
        for f in 0..100 {
            // Speech, then silence: the size stays the same (CBR, no DTX).
            let mic = if f < 50 {
                tone(f, 440.0)
            } else {
                vec![0; FRAME]
            };
            let p = a.encode(&mic).unwrap();
            sizes.insert(p.len());
            let out = b.decode(Decode::Packet(&p)).unwrap();
            assert_eq!(out.len(), FRAME);
            if (10..50).contains(&f) {
                heard += energy(&out);
            }
        }
        assert_eq!(sizes.len(), 1, "{sizes:?}");
        let size = *sizes.iter().next().unwrap();
        assert!((70..=MAX_PACKET).contains(&size), "{size}");
        assert!(heard / 40.0 > 1e5, "the tone comes through: {heard}");
    }

    #[test]
    fn lost_frames_are_concealed_or_recovered() {
        let mut a = CallAudio::new().unwrap();
        let mut b = CallAudio::new().unwrap();
        let packets: Vec<Vec<u8>> = (0..30)
            .map(|f| a.encode(&tone(f, 300.0)).unwrap())
            .collect();
        for p in &packets[..20] {
            b.decode(Decode::Packet(p)).unwrap();
        }
        // Frame 20 lost; 21 arrived: recover 20 from 21's FEC, then 21.
        let rec = b.decode(Decode::Recover(&packets[21])).unwrap();
        assert_eq!(rec.len(), FRAME);
        b.decode(Decode::Packet(&packets[21])).unwrap();
        // Two lost in a row: concealed.
        assert_eq!(b.decode(Decode::Lost).unwrap().len(), FRAME);
        assert_eq!(b.decode(Decode::Lost).unwrap().len(), FRAME);
        b.decode(Decode::Packet(&packets[24])).unwrap();
        assert!(b.decode(Decode::Packet(&[0xff; 200])).is_err());
    }

    #[test]
    fn echo_is_cancelled() {
        // What the far end says is played and picked up by our
        // microphone 40 ms later, a little quieter. After the canceller
        // has adapted, what we send back carries much less of it.
        let mut far = CallAudio::new().unwrap();
        let mut near = CallAudio::new().unwrap();
        let mut listener = CallAudio::new().unwrap();
        let mut played: Vec<Vec<i16>> = Vec::new();
        let (mut early, mut late) = (0.0, 0.0);
        for f in 0..400 {
            let speech = tone(f, 200.0 + (f % 7) as f32 * 90.0);
            let p = far.encode(&speech).unwrap();
            played.push(near.decode(Decode::Packet(&p)).unwrap());
            let mic: Vec<i16> = if f >= 2 {
                played[f - 2].iter().map(|s| s / 2).collect()
            } else {
                vec![0; FRAME]
            };
            let sent = near.encode(&mic).unwrap();
            let back = listener.decode(Decode::Packet(&sent)).unwrap();
            if (10..60).contains(&f) {
                early += energy(&back);
            }
            if (350..400).contains(&f) {
                late += energy(&back);
            }
        }
        assert!(late < early / 4.0, "echo {early} → {late}");
    }
}
