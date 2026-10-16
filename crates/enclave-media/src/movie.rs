//! Videos (`docs/15-client.md` §5.1, §5.5): a camera recording or a video
//! file, sent as AV1 at [`VIDEO_FPS`] frames a second and Opus sound in
//! version 2 of the clip container ([`crate::video`]).
//!
//! The person's own video is read by the platform's decoder in the app
//! (`enclave-platform`) and arrives here as RGBA frames and 48 kHz mono
//! samples; [`VideoWriter`] encodes them as they come, so a long video is
//! never held decoded. Version 2 adds to version 1's layout: the header
//! (`"EVC2" ‖ u8 2 ‖ u16 width ‖ u16 height ‖ u16 fps ‖ u32 frames ‖ u32
//! duration_ms ‖ u8 codec ‖ u8 sound ‖ u32 packets ‖ u16 packet_len ‖ u32
//! poster_len ‖ poster JPEG`), then the video records (track 1, as in
//! version 1), then the sound records (track 2: `count` Opus packets of
//! `packet_len` bytes each, constant bit rate, 20 ms each). At most
//! [`MAX_VIDEO_RECORDS`] records (100 MiB) and [`MAX_VIDEO_MS`].
//!
//! The receiver plays it in mediad ([`VideoPlayer`], feature `av1`): a
//! second at a time, frames shrunk for the screen and the sound decoded.

use crate::video::{RECORD, i420_to_rgba, to_i420};
use crate::{MediaError, Result, Rgba, resize};

/// Frames per second of a video.
pub const VIDEO_FPS: u32 = 30;
/// Longest side of a video.
pub const MAX_VIDEO_SIDE: u32 = 720;
/// Longest video.
pub const MAX_VIDEO_MS: u32 = 10 * 60 * 1000;
/// Most frames in a video.
pub const MAX_VIDEO_FRAMES: u32 = MAX_VIDEO_MS / 1000 * VIDEO_FPS;
/// Most records in a video (100 MiB, the largest attachment).
pub const MAX_VIDEO_RECORDS: usize = 1600;
/// Video bit rate, kbit/s (about 1 MiB a minute of sound and picture at 720
/// px is 9 minutes in 100 MiB).
pub const VIDEO_KBPS: i32 = 1_200;
/// Sound bit rate, bits a second (constant: every packet the same size).
pub const SOUND_BITRATE: i32 = 32_000;
/// Samples a second of the sound.
pub const SOUND_RATE: u32 = 48_000;
/// Samples per 20 ms sound packet.
const SOUND_FRAME: usize = (SOUND_RATE as usize) / 50;

const MAGIC2: &[u8; 4] = b"EVC2";
const RECORD_HEAD: usize = 1 + 4 + 2;
const HEADER_FIXED2: usize = 4 + 1 + 2 + 2 + 2 + 4 + 4 + 1 + 1 + 4 + 2 + 4;
const CODEC_AV1: u8 = 1;
const POSTER_QUALITY: u8 = 80;

/// The size to record or read a video at: `width × height` shrunk to at
/// most [`MAX_VIDEO_SIDE`] on the long side, both even, at least 16.
pub fn video_size(width: u32, height: u32) -> (u32, u32) {
    let (w, h) = (width.max(1), height.max(1));
    let scale = (MAX_VIDEO_SIDE as f64 / w.max(h) as f64).min(1.0);
    let even = |v: f64| ((v.round() as u32).max(16) / 2) * 2;
    (even(w as f64 * scale), even(h as f64 * scale))
}

/// A video being encoded.
pub struct VideoWriter {
    width: u32,
    height: u32,
    ctx: rav1e::Context<u8>,
    units: Vec<Vec<u8>>,
    bytes: usize,
    poster: Option<Vec<u8>>,
    frames: u32,
    sound: crate::opus::Encoder,
    pcm: Vec<i16>,
    packets: Vec<Vec<u8>>,
}

impl VideoWriter {
    /// A video `width × height` (as [`video_size`] gives).
    pub fn new(width: u32, height: u32) -> Result<Self> {
        use rav1e::prelude::*;
        if (width, height) != video_size(width, height) {
            return Err(MediaError::TooLarge);
        }
        let mut enc = EncoderConfig::with_speed_preset(10);
        enc.width = width as usize;
        enc.height = height as usize;
        enc.bit_depth = 8;
        enc.chroma_sampling = ChromaSampling::Cs420;
        enc.time_base = Rational::new(1, u64::from(VIDEO_FPS));
        enc.bitrate = VIDEO_KBPS;
        enc.low_latency = true;
        // A key frame every 2 s.
        enc.max_key_frame_interval = u64::from(VIDEO_FPS) * 2;
        let ctx = Config::new()
            .with_encoder_config(enc)
            .with_threads(1)
            .new_context()
            .map_err(|_| MediaError::Encode)?;
        Ok(Self {
            width,
            height,
            ctx,
            units: Vec::new(),
            bytes: 0,
            poster: None,
            frames: 0,
            sound: crate::opus::Encoder::new(SOUND_BITRATE, false)?,
            pcm: Vec::new(),
            packets: Vec::new(),
        })
    }

    /// The next frame: `width × height` RGBA. A video full in length or
    /// size refuses more ([`MediaError::TooLarge`]); what came stays.
    pub fn frame(&mut self, rgba: &[u8]) -> Result<()> {
        if rgba.len() != self.width as usize * self.height as usize * 4 {
            return Err(MediaError::Damaged);
        }
        if self.full() {
            return Err(MediaError::TooLarge);
        }
        let img = Rgba {
            width: self.width,
            height: self.height,
            pixels: rgba
                .iter()
                .copied()
                .enumerate()
                .map(|(i, b)| if i % 4 == 3 { 255 } else { b })
                .collect(),
        };
        if self.poster.is_none() {
            self.poster = Some(poster(&img)?);
        }
        let (y, u, v) = to_i420(&img);
        let mut f = self.ctx.new_frame();
        let w = self.width as usize;
        f.planes[0].copy_from_raw_u8(&y, w, 1);
        f.planes[1].copy_from_raw_u8(&u, w / 2, 1);
        f.planes[2].copy_from_raw_u8(&v, w / 2, 1);
        self.ctx.send_frame(f).map_err(|_| MediaError::Encode)?;
        self.frames += 1;
        self.drain(false)
    }

    /// More sound: 48 kHz mono samples, in any amounts. Sound past the
    /// pictures' end is dropped at [`VideoWriter::finish`].
    pub fn sound(&mut self, pcm: &[i16]) -> Result<()> {
        self.pcm.extend_from_slice(pcm);
        while self.pcm.len() >= SOUND_FRAME {
            let frame: Vec<i16> = self.pcm.drain(..SOUND_FRAME).collect();
            if self.packets.len() < (MAX_VIDEO_MS / 20) as usize {
                let p = self.sound.encode(&frame)?;
                self.bytes += p.len();
                self.packets.push(p);
            }
        }
        Ok(())
    }

    /// Frames so far.
    pub fn frames(&self) -> u32 {
        self.frames
    }

    /// No room for more: at [`MAX_VIDEO_MS`], or near 100 MiB.
    pub fn full(&self) -> bool {
        self.frames >= MAX_VIDEO_FRAMES
            || self.bytes + 2 * RECORD >= (MAX_VIDEO_RECORDS - 8) * RECORD
    }

    fn drain(&mut self, flushing: bool) -> Result<()> {
        use rav1e::EncoderStatus;
        loop {
            match self.ctx.receive_packet() {
                Ok(p) => {
                    self.bytes += p.data.len() + 4;
                    self.units.push(p.data);
                }
                Err(EncoderStatus::Encoded) => {}
                Err(EncoderStatus::NeedMoreData) if !flushing => return Ok(()),
                Err(EncoderStatus::LimitReached) => return Ok(()),
                Err(_) => return Err(MediaError::Encode),
            }
        }
    }

    /// The video, in the container.
    pub fn finish(mut self) -> Result<crate::video::Clip> {
        if self.frames == 0 {
            return Err(MediaError::Damaged);
        }
        self.ctx.flush();
        self.drain(true)?;
        if self.units.len() != self.frames as usize {
            return Err(MediaError::Encode);
        }
        let duration_ms = self.frames * 1000 / VIDEO_FPS;
        // The sound as long as the pictures, padded with silence.
        let want = (duration_ms / 20) as usize;
        if !self.pcm.is_empty() && self.packets.len() < want {
            let rest = std::mem::take(&mut self.pcm);
            let p = self.sound.encode(&rest)?;
            self.packets.push(p);
        }
        self.packets.truncate(want);
        let poster = self.poster.take().ok_or(MediaError::Damaged)?;
        let bytes = pack2(
            self.width,
            self.height,
            self.frames,
            duration_ms,
            &poster,
            &self.units,
            &self.packets,
        )?;
        Ok(crate::video::Clip {
            bytes,
            width: self.width,
            height: self.height,
            frames: self.frames,
            duration_ms,
        })
    }
}

fn poster(img: &Rgba) -> Result<Vec<u8>> {
    // At most 480 px, so it fits the header record.
    let small = resize::fit(img, 480);
    let rgb: Vec<u8> = small
        .pixels
        .chunks_exact(4)
        .flat_map(|p| [p[0], p[1], p[2]])
        .collect();
    let mut out = Vec::new();
    jpeg_encoder::Encoder::new(&mut out, POSTER_QUALITY)
        .encode(
            &rgb,
            u16::try_from(small.width).map_err(|_| MediaError::TooLarge)?,
            u16::try_from(small.height).map_err(|_| MediaError::TooLarge)?,
            jpeg_encoder::ColorType::Rgb,
        )
        .map_err(|_| MediaError::Encode)?;
    if out.len() > RECORD - RECORD_HEAD - HEADER_FIXED2 {
        return Err(MediaError::TooLarge);
    }
    Ok(out)
}

fn pack2(
    width: u32,
    height: u32,
    frames: u32,
    duration_ms: u32,
    poster: &[u8],
    units: &[Vec<u8>],
    packets: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let packet_len = packets.first().map_or(0, Vec::len);
    if packets.iter().any(|p| p.len() != packet_len) || packet_len > 1_000 {
        return Err(MediaError::Encode);
    }
    let mut out = Vec::new();
    let mut h = vec![0u8; RECORD_HEAD];
    h.extend_from_slice(MAGIC2);
    h.push(2);
    for d in [width, height, VIDEO_FPS] {
        h.extend_from_slice(
            &u16::try_from(d)
                .map_err(|_| MediaError::TooLarge)?
                .to_be_bytes(),
        );
    }
    h.extend_from_slice(&frames.to_be_bytes());
    h.extend_from_slice(&duration_ms.to_be_bytes());
    h.push(CODEC_AV1);
    h.push(u8::from(!packets.is_empty()));
    h.extend_from_slice(&(packets.len() as u32).to_be_bytes());
    h.extend_from_slice(&(packet_len as u16).to_be_bytes());
    h.extend_from_slice(&(poster.len() as u32).to_be_bytes());
    h.extend_from_slice(poster);
    if h.len() > RECORD {
        return Err(MediaError::TooLarge);
    }
    h.resize(RECORD, 0);
    out.extend_from_slice(&h);
    // Pictures.
    let mut i = 0usize;
    while i < units.len() {
        let mut rec = vec![0u8; RECORD];
        let mut at = RECORD_HEAD;
        let first = i;
        while i < units.len() && at + 4 + units[i].len() <= RECORD {
            rec[at..at + 4].copy_from_slice(&(units[i].len() as u32).to_be_bytes());
            rec[at + 4..at + 4 + units[i].len()].copy_from_slice(&units[i]);
            at += 4 + units[i].len();
            i += 1;
        }
        if i == first {
            return Err(MediaError::TooLarge);
        }
        rec[0] = 1;
        rec[1..5].copy_from_slice(&((first as u32) * 1000 / VIDEO_FPS).to_be_bytes());
        rec[5..7].copy_from_slice(&((i - first) as u16).to_be_bytes());
        out.extend_from_slice(&rec);
    }
    // Sound.
    if packet_len > 0 {
        let per = (RECORD - RECORD_HEAD) / packet_len;
        for (r, chunk) in packets.chunks(per).enumerate() {
            let mut rec = vec![0u8; RECORD];
            rec[0] = 2;
            rec[1..5].copy_from_slice(&((r * per) as u32 * 20).to_be_bytes());
            rec[5..7].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
            for (k, p) in chunk.iter().enumerate() {
                rec[RECORD_HEAD + k * packet_len..][..packet_len].copy_from_slice(p);
            }
            out.extend_from_slice(&rec);
        }
    }
    if out.len() / RECORD > MAX_VIDEO_RECORDS {
        return Err(MediaError::TooLarge);
    }
    Ok(out)
}

fn be16(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 2).ok_or(MediaError::Damaged)?;
    Ok(u32::from(u16::from_be_bytes([s[0], s[1]])))
}

fn be32(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 4).ok_or(MediaError::Damaged)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// What a version 2 clip's header says, and where its pieces are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VideoInfo<'a> {
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
    /// Frames a second.
    pub fps: u32,
    /// Frames.
    pub frames: u32,
    /// Length in milliseconds.
    pub duration_ms: u32,
    /// The first frame, as a JPEG.
    pub poster: &'a [u8],
    /// One AV1 temporal unit per frame.
    pub units: Vec<&'a [u8]>,
    /// The sound: 20 ms Opus packets (none: silent).
    pub packets: Vec<&'a [u8]>,
}

/// Whether `bytes` start like a version 2 clip (a video).
pub fn is_video(bytes: &[u8]) -> bool {
    bytes.len() >= RECORD && bytes.get(RECORD_HEAD..RECORD_HEAD + 4) == Some(&MAGIC2[..])
}

/// Parse and check a video (or, through [`crate::video::parse_clip`], a
/// version 1 clip, as a silent video) without decoding anything.
pub fn parse_video(bytes: &[u8]) -> Result<VideoInfo<'_>> {
    if !is_video(bytes) {
        let c = crate::video::parse_clip(bytes)?;
        return Ok(VideoInfo {
            width: c.width,
            height: c.height,
            fps: crate::video::CLIP_FPS,
            frames: c.frames,
            duration_ms: c.duration_ms,
            poster: c.poster,
            units: c.units,
            packets: Vec::new(),
        });
    }
    let n = bytes.len() / RECORD;
    if !bytes.len().is_multiple_of(RECORD) || !(2..=MAX_VIDEO_RECORDS).contains(&n) {
        return Err(MediaError::Damaged);
    }
    let head = &bytes[..RECORD];
    if head[..RECORD_HEAD] != [0; RECORD_HEAD] {
        return Err(MediaError::Damaged);
    }
    let mut at = RECORD_HEAD + 4;
    if head[at] != 2 {
        return Err(MediaError::Unsupported);
    }
    at += 1;
    let (width, height, fps) = (be16(head, at)?, be16(head, at + 2)?, be16(head, at + 4)?);
    at += 6;
    let frames = be32(head, at)?;
    let duration_ms = be32(head, at + 4)?;
    let codec = head[at + 8];
    let sound = head[at + 9];
    let packets_n = be32(head, at + 10)? as usize;
    let packet_len = be16(head, at + 14)? as usize;
    let poster_len = be32(head, at + 16)? as usize;
    at += 20;
    if width == 0
        || height == 0
        || width % 2 != 0
        || height % 2 != 0
        || width.max(height) > MAX_VIDEO_SIDE
        || fps != VIDEO_FPS
        || frames == 0
        || frames > MAX_VIDEO_FRAMES
        || duration_ms != frames * 1000 / VIDEO_FPS
        || codec != CODEC_AV1
        || sound > 1
        || (sound == 0) != (packets_n == 0)
        || (sound == 1 && !(1..=1_000).contains(&packet_len))
        || packets_n > (duration_ms / 20) as usize
        || poster_len == 0
        || at + poster_len > RECORD
        || head[at + poster_len..].iter().any(|&b| b != 0)
    {
        return Err(MediaError::Damaged);
    }
    let poster = &head[at..at + poster_len];
    let mut units = Vec::with_capacity(frames as usize);
    let mut packets = Vec::with_capacity(packets_n);
    for r in 1..n {
        let rec = &bytes[r * RECORD..(r + 1) * RECORD];
        let count = be16(rec, 5)? as usize;
        let pts = be32(rec, 1)?;
        let mut at = RECORD_HEAD;
        match rec[0] {
            // Pictures, all before any sound.
            1 if packets.is_empty() => {
                if count == 0 || pts != (units.len() as u32) * 1000 / VIDEO_FPS {
                    return Err(MediaError::Damaged);
                }
                for _ in 0..count {
                    let len = be32(rec, at)? as usize;
                    let unit = rec
                        .get(at + 4..at + 4 + len)
                        .filter(|u| !u.is_empty())
                        .ok_or(MediaError::Damaged)?;
                    units.push(unit);
                    at += 4 + len;
                }
            }
            2 if sound == 1 && units.len() == frames as usize => {
                if count == 0
                    || pts != (packets.len() as u32) * 20
                    || at + count * packet_len > RECORD
                {
                    return Err(MediaError::Damaged);
                }
                for _ in 0..count {
                    packets.push(&rec[at..at + packet_len]);
                    at += packet_len;
                }
            }
            _ => return Err(MediaError::Damaged),
        }
        if rec[at..].iter().any(|&b| b != 0) {
            return Err(MediaError::Damaged);
        }
    }
    if units.len() != frames as usize || packets.len() != packets_n {
        return Err(MediaError::Damaged);
    }
    Ok(VideoInfo {
        width,
        height,
        fps,
        frames,
        duration_ms,
        poster,
        units,
        packets,
    })
}

/// A second (or so) of a video, to show and hear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    /// The frames, shrunk to the player's size.
    pub frames: Vec<Rgba>,
    /// The sound for them: 48 kHz mono.
    pub pcm: Vec<i16>,
    /// The video has no more.
    pub done: bool,
}

/// A video playing, in mediad: it holds the file and the decoders, and
/// gives it out a piece at a time from the start.
#[cfg(feature = "av1")]
pub struct VideoPlayer {
    bytes: Vec<u8>,
    max_side: u32,
    units: Vec<(usize, usize)>,
    packets: Vec<(usize, usize)>,
    fps: u32,
    width: u32,
    height: u32,
    duration_ms: u32,
    dec: enclave_av1::Decoder,
    sound: crate::opus::Decoder,
    next_unit: usize,
    next_packet: usize,
}

#[cfg(feature = "av1")]
impl VideoPlayer {
    /// Check `bytes` and get ready to play it, frames at most `max_side`.
    pub fn new(bytes: Vec<u8>, max_side: u32) -> Result<Self> {
        let base = bytes.as_ptr() as usize;
        let span = |s: &[u8]| (s.as_ptr() as usize - base, s.len());
        let info = parse_video(&bytes)?;
        let units = info.units.iter().map(|u| span(u)).collect();
        let packets = info.packets.iter().map(|p| span(p)).collect();
        let (fps, width, height, duration_ms) =
            (info.fps, info.width, info.height, info.duration_ms);
        Ok(Self {
            bytes,
            max_side: max_side.max(16),
            units,
            packets,
            fps,
            width,
            height,
            duration_ms,
            dec: enclave_av1::Decoder::new().map_err(|_| MediaError::Unsupported)?,
            sound: crate::opus::Decoder::new()?,
            next_unit: 0,
            next_packet: 0,
        })
    }

    /// Its size, frames a second and length (ms).
    pub fn info(&self) -> (u32, u32, u32, u32) {
        (self.width, self.height, self.fps, self.duration_ms)
    }

    /// The next `ms` of it.
    pub fn piece(&mut self, ms: u32) -> Result<Piece> {
        let want = (u64::from(ms.clamp(20, 2_000)) * u64::from(self.fps) / 1000).max(1) as usize;
        let mut frames = Vec::with_capacity(want);
        while frames.len() < want && self.next_unit < self.units.len() {
            let (at, len) = self.units[self.next_unit];
            self.next_unit += 1;
            for f in self
                .dec
                .decode(&self.bytes[at..at + len])
                .map_err(|_| MediaError::Damaged)?
            {
                if f.width != self.width || f.height != self.height {
                    return Err(MediaError::Damaged);
                }
                let img = i420_to_rgba(f.width, f.height, &f.y, &f.u, &f.v)?;
                frames.push(resize::fit(&img, self.max_side));
            }
        }
        // The sound for those frames: up to the time they end.
        let until = (self.next_unit as u64 * 1000 / u64::from(self.fps) / 20) as usize;
        let mut pcm = Vec::new();
        while self.next_packet < until.min(self.packets.len()) {
            let (at, len) = self.packets[self.next_packet];
            self.next_packet += 1;
            pcm.extend(self.sound.decode(&self.bytes[at..at + len])?);
        }
        let done = self.next_unit >= self.units.len();
        if done {
            while self.next_packet < self.packets.len() {
                let (at, len) = self.packets[self.next_packet];
                self.next_packet += 1;
                pcm.extend(self.sound.decode(&self.bytes[at..at + len])?);
            }
        }
        Ok(Piece { frames, pcm, done })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn frame(w: u32, h: u32, i: u32) -> Vec<u8> {
        (0..w * h)
            .flat_map(|p| {
                let x = p % w;
                let on = ((x / 8) + i).is_multiple_of(4);
                if on {
                    [210, 50, 40, 255]
                } else {
                    [30, 90, 160, 255]
                }
            })
            .collect()
    }

    fn tone(samples: usize) -> Vec<i16> {
        (0..samples)
            .map(|i| {
                ((i as f32 * 440.0 * 2.0 * std::f32::consts::PI / 48_000.0).sin() * 8_000.0) as i16
            })
            .collect()
    }

    #[test]
    fn sizes() {
        assert_eq!(video_size(1920, 1080), (720, 404));
        assert_eq!(video_size(1080, 1920), (404, 720));
        assert_eq!(video_size(640, 480), (640, 480));
        assert_eq!(video_size(7, 5), (16, 16));
        assert!(VideoWriter::new(721, 400).is_err());
    }

    #[test]
    fn a_video_with_sound_and_its_checks() {
        let (w, h) = (64, 48);
        let mut v = VideoWriter::new(w, h).unwrap();
        for i in 0..45 {
            v.frame(&frame(w, h, i)).unwrap();
            v.sound(&tone(1_600)).unwrap(); // 1/30 s
        }
        assert!(v.frame(&[0; 3]).is_err(), "wrong size");
        let clip = v.finish().unwrap();
        assert_eq!((clip.frames, clip.duration_ms), (45, 1_500));
        assert!(is_video(&clip.bytes));
        let info = parse_video(&clip.bytes).unwrap();
        assert_eq!((info.width, info.height, info.fps), (64, 48, 30));
        assert_eq!(info.units.len(), 45);
        assert_eq!(info.packets.len(), 75, "1.5 s of 20 ms packets");
        crate::decode(info.poster).unwrap();

        // Any change to the layout is refused.
        let mut b = clip.bytes.clone();
        b.push(0);
        assert!(parse_video(&b).is_err());
        let mut b = clip.bytes.clone();
        b[RECORD - 1] = 1;
        assert!(parse_video(&b).is_err(), "header padding");
        let mut b = clip.bytes.clone();
        let last = b.len() - RECORD;
        b[last] = 1; // a sound record claiming to be pictures
        assert!(parse_video(&b).is_err());
        let mut b = clip.bytes.clone();
        b[RECORD_HEAD + 5 + 4..][..2].copy_from_slice(&15u16.to_be_bytes());
        assert!(parse_video(&b).is_err(), "frame rate");

        // A version 1 clip reads as a silent video.
        let gif = {
            let mut out = Vec::new();
            {
                let mut e = gif::Encoder::new(&mut out, 32, 32, &[]).unwrap();
                let mut px = [9u8, 99, 199, 255].repeat(32 * 32);
                e.write_frame(&gif::Frame::from_rgba_speed(32, 32, &mut px, 10))
                    .unwrap();
            }
            out
        };
        let old = crate::video::clip_from_gif(&gif).unwrap();
        let info = parse_video(&old.bytes).unwrap();
        assert_eq!(info.fps, crate::video::CLIP_FPS);
        assert!(info.packets.is_empty());
    }

    #[test]
    fn silence_and_a_full_video() {
        let mut v = VideoWriter::new(32, 32).unwrap();
        v.frame(&frame(32, 32, 0)).unwrap();
        let clip = v.finish().unwrap();
        assert!(parse_video(&clip.bytes).unwrap().packets.is_empty());
        assert!(
            VideoWriter::new(32, 32).unwrap().finish().is_err(),
            "no frames"
        );
    }

    #[cfg(feature = "av1")]
    #[test]
    fn plays_back_in_pieces() {
        let (w, h) = (64, 48);
        let mut v = VideoWriter::new(w, h).unwrap();
        for i in 0..45 {
            v.frame(&frame(w, h, i)).unwrap();
            v.sound(&tone(1_600)).unwrap();
        }
        let clip = v.finish().unwrap();
        let mut p = VideoPlayer::new(clip.bytes, 32).unwrap();
        assert_eq!(p.info(), (64, 48, 30, 1_500));
        let a = p.piece(1_000).unwrap();
        assert_eq!(a.frames.len(), 30);
        assert_eq!((a.frames[0].width, a.frames[0].height), (32, 24));
        assert_eq!(a.pcm.len(), 48_000, "a second of sound");
        assert!(!a.done);
        // Colours survive: the first frame's left edge is the red stripe.
        let px = &a.frames[0].pixels[..4];
        assert!(px[0] > 150 && px[2] < 110, "{px:?}");
        let b = p.piece(1_000).unwrap();
        assert_eq!(b.frames.len(), 15);
        assert!(b.done);
        assert_eq!(b.pcm.len(), 24_000);
        // The tone is there, not silence.
        let loud = b.pcm.iter().map(|s| i32::from(*s).abs()).max().unwrap();
        assert!(loud > 2_000, "{loud}");
    }
}
