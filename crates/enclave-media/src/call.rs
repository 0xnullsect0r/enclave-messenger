//! Call audio (`docs/11-calls.md` §6, §10).
//!
//! Opus at a constant 32 kbit/s in 20 ms frames of 48 kHz mono, DTX off
//! and in-band FEC on, so every frame costs the same whether anyone speaks;
//! how much of each packet the FEC copy takes follows the loss the other
//! side reports ([`CallAudio::set_loss`]). The microphone is cleaned up
//! first by WebRTC's audio processing (`sonora`: AEC3 echo cancellation
//! against what was just played, noise suppression, automatic gain), in
//! 10 ms halves. The codec is [`crate::opus`]; all of this runs in mediad.

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
    enc: crate::opus::Encoder,
    dec: crate::opus::Decoder,
    apm: AudioProcessing,
    /// A group call's decoders, one per other participant.
    decoders: std::collections::HashMap<u32, crate::opus::Decoder>,
}

/// One frame decoded as `what` says.
fn decode_one(dec: &mut crate::opus::Decoder, what: Decode<'_>) -> Result<Vec<i16>> {
    let pcm = match what {
        Decode::Packet(p) if p.len() <= MAX_PACKET => dec.decode(p)?,
        Decode::Recover(p) if p.len() <= MAX_PACKET => dec.recover(p)?,
        Decode::Lost => dec.conceal()?,
        _ => return Err(MediaError::Damaged),
    };
    if pcm.len() != FRAME {
        return Err(MediaError::Damaged);
    }
    Ok(pcm)
}

/// Most other participants one group call decodes.
pub const MAX_SENDERS: usize = 64;

impl CallAudio {
    /// A fresh call.
    pub fn new() -> Result<Self> {
        let enc = crate::opus::Encoder::new(BITRATE, true)?;
        let dec = crate::opus::Decoder::new()?;
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
        let out = self.enc.encode(&clean)?;
        if out.len() > MAX_PACKET {
            return Err(MediaError::Encode);
        }
        Ok(out)
    }

    /// The loss the other side reports hearing from us, in percent: the
    /// encoder spends more of each packet on the copy of the frame before
    /// as it rises (none at 0, where it would only cost quality).
    pub fn set_loss(&mut self, percent: u8) {
        self.enc.set_loss(percent);
    }

    /// The next 20 ms to play ([`FRAME`] samples). What is played is the
    /// echo canceller's reference, so call this as frames are played.
    pub fn decode(&mut self, what: Decode<'_>) -> Result<Vec<i16>> {
        let pcm = decode_one(&mut self.dec, what)?;
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
                self.decoders.insert(*sender, crate::opus::Decoder::new()?);
            }
            let Some(dec) = self.decoders.get_mut(sender) else {
                continue;
            };
            // A damaged frame from one person leaves the others' voices.
            if let Ok(pcm) = decode_one(dec, *what) {
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
        // microphone 40 ms later, at half the level. Once the canceller has
        // adapted, what we send back carries almost none of it.
        let mut far = CallAudio::new().unwrap();
        let mut near = CallAudio::new().unwrap();
        let mut listener = CallAudio::new().unwrap();
        let mut played: Vec<Vec<i16>> = Vec::new();
        let (mut picked_up, mut late) = (0.0, 0.0);
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
            if (350..400).contains(&f) {
                picked_up += energy(&mic);
                late += energy(&back);
            }
        }
        // The echo the microphone picked up, at least 30 dB down in what
        // we send.
        assert!(late < picked_up / 1000.0, "echo {picked_up} → {late}");
    }
}
