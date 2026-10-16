//! Call video (`docs/11-calls.md` §6, §10): AV1, encoded by rav1e at its
//! fastest preset in low-latency mode and decoded by rav1d (feature `av1`,
//! mediad only).
//!
//! A call's video tier is chosen when it starts and only ever steps down
//! (`enclave_calls::shape`). Each tier fixes the picture size, the frame
//! rate and the encoder's bit rate, set below what the tier's fixed-rate
//! packets carry so frames don't queue. The window hands over frames
//! already cropped and scaled to the tier's size, as RGBA.

#[cfg(feature = "av1")]
use crate::video::i420_to_rgba;
use crate::video::to_i420;
use crate::{MediaError, Result, Rgba};

/// One video tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tier {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Frames a second.
    pub fps: u32,
    /// Encoder target, kbit/s.
    pub kbps: usize,
}

/// The tiers, matching `enclave_calls::shape::VIDEO_TIERS` (300, 800 and
/// 1,500 kbit/s on the wire; about 85 % of it is picture).
pub const TIERS: [Tier; 3] = [
    Tier {
        width: 320,
        height: 240,
        fps: 15,
        kbps: 240,
    },
    Tier {
        width: 480,
        height: 360,
        fps: 20,
        kbps: 650,
    },
    Tier {
        width: 640,
        height: 480,
        fps: 24,
        kbps: 1_250,
    },
];

/// A shared screen: a bigger picture at fewer frames a second, for the
/// same bits as the camera's tier (so the stream on the wire is the same
/// whichever is sent).
pub const SCREEN: Tier = Tier {
    width: 960,
    height: 540,
    fps: 5,
    kbps: 240,
};

/// The screen's picture for a call at tier `index`: [`SCREEN`] at that
/// tier's bit rate.
pub fn screen(index: usize) -> Tier {
    Tier {
        kbps: tier(index).kbps,
        ..SCREEN
    }
}

/// The tier at `index` (the lowest when out of range).
pub fn tier(index: usize) -> Tier {
    TIERS.get(index).copied().unwrap_or(TIERS[0])
}

/// A call's video encoder.
pub struct VideoEncoder {
    tier: Tier,
    ctx: rav1e::Context<u8>,
    /// The sequence header OBU from the first key frame, repeated in every
    /// later one so a receiver that missed the start can begin there.
    seq_header: Option<Vec<u8>>,
}

/// AV1 OBU types used here.
const OBU_SEQUENCE_HEADER: u8 = 1;
const OBU_TEMPORAL_DELIMITER: u8 = 2;

/// The OBUs of a temporal unit: (type, start, end). Stops at anything
/// it can't read (rav1e writes every OBU with its size).
fn obus(unit: &[u8]) -> Vec<(u8, usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < unit.len() {
        let h = unit[at];
        let (kind, ext, sized) = ((h >> 3) & 0x0f, (h >> 2) & 1 == 1, (h >> 1) & 1 == 1);
        if !sized {
            break;
        }
        let mut i = at + 1 + usize::from(ext);
        let (mut size, mut shift) = (0usize, 0);
        loop {
            let Some(&b) = unit.get(i) else { return out };
            size |= usize::from(b & 0x7f) << shift;
            i += 1;
            shift += 7;
            if b & 0x80 == 0 || shift > 28 {
                break;
            }
        }
        let end = i + size;
        if end > unit.len() {
            break;
        }
        out.push((kind, at, end));
        at = end;
    }
    out
}

impl VideoEncoder {
    /// An encoder for tier `index`.
    pub fn new(index: usize) -> Result<Self> {
        Self::for_tier(tier(index))
    }

    /// An encoder for a shared screen in a call at tier `index`
    /// ([`screen`]).
    pub fn screen(index: usize) -> Result<Self> {
        Self::for_tier(screen(index))
    }

    fn for_tier(t: Tier) -> Result<Self> {
        use rav1e::prelude::*;
        let mut enc = EncoderConfig::with_speed_preset(10);
        enc.width = t.width as usize;
        enc.height = t.height as usize;
        enc.bit_depth = 8;
        enc.chroma_sampling = ChromaSampling::Cs420;
        enc.time_base = Rational::new(1, u64::from(t.fps));
        enc.bitrate = i32::try_from(t.kbps * 1000).map_err(|_| MediaError::Encode)?;
        enc.low_latency = true;
        // No lookahead: each frame comes out as soon as it goes in.
        enc.speed_settings.rdo_lookahead_frames = 1;
        enc.speed_settings.scene_detection_mode = SceneDetectionSpeed::None;
        // A key frame every 3 s, so a picture lost to the network comes
        // back on its own; the other side can also ask for one.
        enc.max_key_frame_interval = u64::from(t.fps) * 3;
        enc.min_key_frame_interval = 1;
        let cfg = Config::new().with_encoder_config(enc).with_threads(1);
        let ctx = cfg.new_context().map_err(|_| MediaError::Encode)?;
        Ok(Self {
            tier: t,
            ctx,
            seq_header: None,
        })
    }

    /// The tier it encodes.
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// Encode one frame (RGBA at the tier's size); `key` forces a key
    /// frame. Returns the temporal units that came out (in low-latency
    /// mode, this frame's).
    pub fn encode(&mut self, rgba: &[u8], key: bool) -> Result<Vec<Vec<u8>>> {
        use rav1e::prelude::*;
        let (w, h) = (self.tier.width, self.tier.height);
        if rgba.len() != (w * h * 4) as usize {
            return Err(MediaError::Damaged);
        }
        let img = Rgba {
            width: w,
            height: h,
            pixels: rgba.to_vec(),
        };
        let (y, u, v) = to_i420(&img);
        let mut f = self.ctx.new_frame();
        let wu = w as usize;
        f.planes[0].copy_from_raw_u8(&y, wu, 1);
        f.planes[1].copy_from_raw_u8(&u, wu / 2, 1);
        f.planes[2].copy_from_raw_u8(&v, wu / 2, 1);
        let params = FrameParameters {
            frame_type_override: if key {
                FrameTypeOverride::Key
            } else {
                FrameTypeOverride::No
            },
            ..Default::default()
        };
        self.ctx
            .send_frame((std::sync::Arc::new(f), params))
            .map_err(|_| MediaError::Encode)?;
        let mut units = Vec::new();
        loop {
            match self.ctx.receive_packet() {
                Ok(p) => {
                    let mut data = p.data;
                    if p.frame_type == FrameType::KEY {
                        let parts = obus(&data);
                        match parts.iter().find(|o| o.0 == OBU_SEQUENCE_HEADER) {
                            Some(&(_, a, b)) => self.seq_header = Some(data[a..b].to_vec()),
                            None => {
                                if let Some(seq) = &self.seq_header {
                                    let at = parts
                                        .first()
                                        .filter(|o| o.0 == OBU_TEMPORAL_DELIMITER)
                                        .map_or(0, |o| o.2);
                                    data.splice(at..at, seq.iter().copied());
                                }
                            }
                        }
                    }
                    units.push(data);
                }
                Err(EncoderStatus::Encoded) => {}
                Err(EncoderStatus::NeedMoreData | EncoderStatus::LimitReached) => break,
                Err(_) => return Err(MediaError::Encode),
            }
        }
        Ok(units)
    }
}

/// A call's video decoder (mediad only).
#[cfg(feature = "av1")]
pub struct VideoDecoder {
    dec: enclave_av1::Decoder,
}

#[cfg(feature = "av1")]
impl VideoDecoder {
    /// A decoder.
    pub fn new() -> Result<Self> {
        Ok(Self {
            dec: enclave_av1::Decoder::new().map_err(|_| MediaError::Unsupported)?,
        })
    }

    /// Decode one temporal unit: the newest picture it completed, if any.
    /// Pictures larger than the largest tier or a shared screen
    /// ([`SCREEN`]) are refused.
    pub fn decode(&mut self, unit: &[u8]) -> Result<Option<Rgba>> {
        let frames = self.dec.decode(unit).map_err(|_| MediaError::Damaged)?;
        let Some(f) = frames.into_iter().last() else {
            return Ok(None);
        };
        let top = TIERS[TIERS.len() - 1];
        let (max_w, max_h) = (top.width.max(SCREEN.width), top.height.max(SCREEN.height));
        if f.width > max_w || f.height > max_h {
            return Err(MediaError::TooLarge);
        }
        i420_to_rgba(f.width, f.height, &f.y, &f.u, &f.v).map(Some)
    }
}

#[cfg(all(test, feature = "av1"))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A moving gradient at the tier's size.
    fn picture(t: Tier, n: u32) -> Vec<u8> {
        let mut px = Vec::with_capacity((t.width * t.height * 4) as usize);
        for y in 0..t.height {
            for x in 0..t.width {
                px.extend_from_slice(&[
                    ((x + n * 4) % 256) as u8,
                    ((y * 2) % 256) as u8,
                    ((x + y + n) % 256) as u8,
                    255,
                ]);
            }
        }
        px
    }

    #[test]
    fn frames_round_trip_at_the_tier_rate() {
        let mut enc = VideoEncoder::new(0).unwrap();
        let mut dec = VideoDecoder::new().unwrap();
        let t = enc.tier();
        let mut bytes = 0usize;
        let mut shown = 0;
        for n in 0..30 {
            for unit in enc.encode(&picture(t, n), false).unwrap() {
                bytes += unit.len();
                if let Some(img) = dec.decode(&unit).unwrap() {
                    assert_eq!((img.width, img.height), (t.width, t.height));
                    shown += 1;
                }
            }
        }
        assert!(shown >= 25, "{shown} pictures");
        // Two seconds of video near the tier's rate (key frames cost more).
        let kbps = bytes * 8 / 2 / 1000;
        assert!(kbps < t.kbps * 3, "{kbps} kbit/s");
        // A key frame on request (it comes out a few frames later: the
        // encoder's lookahead) decodes on a fresh decoder, which shows it
        // and everything after.
        let mut fresh = VideoDecoder::new().unwrap();
        let mut after = 0;
        for n in 31..40 {
            for unit in enc.encode(&picture(t, n), n == 31).unwrap() {
                if fresh.decode(&unit).ok().flatten().is_some() {
                    after += 1;
                }
            }
        }
        assert!(after >= 4, "{after} pictures after the key frame");
        assert!(enc.encode(&[0; 16], false).is_err());
    }
}
