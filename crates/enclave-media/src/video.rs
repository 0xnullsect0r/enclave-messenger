//! Animated pictures as short AV1 clips (`docs/15-client.md` §5.1, §5.3).
//!
//! The receiver never decodes GIF (or APNG, or WebP): the **sender** turns
//! an animated GIF into a short AV1 clip, and the receiver decodes AV1 in
//! `mediad`. The sender's GIF decoder only sees the person's own file.
//!
//! A clip is the fixed-record container of §5.1: a whole number of
//! [`RECORD`]-byte records, each `u8 track ‖ u32 pts_ms ‖ u16 count ‖
//! payload`, zero-padded. Record 0 (track 0) is the header: `"EVC1" ‖ u8
//! version ‖ u16 width ‖ u16 height ‖ u16 fps ‖ u32 frames ‖ u32
//! duration_ms ‖ u8 codec (1 = AV1) ‖ u32 poster_len ‖ poster JPEG`. Every
//! other record is track 1: `count` AV1 temporal units, each `u32 len ‖
//! bytes`, one per displayed frame, in order. No boxes, no nesting, no
//! index, nothing variable but lengths that are checked against the record.
//!
//! Clips are at most [`MAX_CLIP_SIDE`] pixels on the long side,
//! [`CLIP_FPS`] frames a second and [`MAX_CLIP_MS`] long, encoded by rav1e
//! (pure Rust, no assembly) at about 400 kbit/s without frame reordering.
//! The poster (the first frame as a JPEG) is what the receiver shows before
//! anything is decoded, through the ordinary picture path.

use crate::{MediaError, Result, Rgba, check_size, resize};

/// Size of every record.
pub const RECORD: usize = 65_536;
/// Frames per second of every clip.
pub const CLIP_FPS: u32 = 15;
/// Longest side of a clip.
pub const MAX_CLIP_SIDE: u32 = 480;
/// Longest clip.
pub const MAX_CLIP_MS: u32 = 15_000;
/// Most frames in a clip.
pub const MAX_CLIP_FRAMES: u32 = MAX_CLIP_MS * CLIP_FPS / 1000;
/// Most records in a clip (4 MiB).
pub const MAX_RECORDS: usize = 64;
/// MIME type of a clip attachment.
pub const CLIP_MIME: &str = "video/x-enclave-clip";
/// Most frames read from a GIF.
pub const MAX_GIF_FRAMES: usize = 2_000;

const MAGIC: &[u8; 4] = b"EVC1";
const RECORD_HEAD: usize = 1 + 4 + 2;
const HEADER_FIXED: usize = 4 + 1 + 2 + 2 + 2 + 4 + 4 + 1 + 4;
const CODEC_AV1: u8 = 1;
const TARGET_KBPS: i32 = 400;
const POSTER_QUALITY: u8 = 80;

/// A clip, ready to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clip {
    /// The container bytes.
    pub bytes: Vec<u8>,
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
    /// Displayed frames.
    pub frames: u32,
    /// Length in milliseconds.
    pub duration_ms: u32,
}

/// What a clip's header says, and its AV1 units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipInfo<'a> {
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
    /// Displayed frames.
    pub frames: u32,
    /// Length in milliseconds.
    pub duration_ms: u32,
    /// The first frame, as a JPEG.
    pub poster: &'a [u8],
    /// One AV1 temporal unit per frame, in order.
    pub units: Vec<&'a [u8]>,
}

/// Whether `bytes` start like a GIF.
pub fn is_gif(bytes: &[u8]) -> bool {
    bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")
}

/// Whether `bytes` look like a clip (checked properly by [`parse_clip`]).
pub fn is_clip(bytes: &[u8]) -> bool {
    bytes.len() >= RECORD && bytes.get(RECORD_HEAD..RECORD_HEAD + 4) == Some(&MAGIC[..])
}

// ---------------------------------------------------------------------------
// Sender: GIF → clip
// ---------------------------------------------------------------------------

/// Turn an animated (or still) GIF into a clip: composited frames resampled
/// to [`CLIP_FPS`], shrunk to [`MAX_CLIP_SIDE`], transparency flattened onto
/// white, cut at [`MAX_CLIP_MS`].
pub fn clip_from_gif(bytes: &[u8]) -> Result<Clip> {
    if bytes.len() > crate::MAX_INPUT {
        return Err(MediaError::TooLarge);
    }
    if !is_gif(bytes) {
        return Err(MediaError::NotAnImage);
    }
    let mut opts = gif::DecodeOptions::new();
    opts.set_color_output(gif::ColorOutput::RGBA);
    let mut d = opts.read_info(bytes).map_err(|_| MediaError::Damaged)?;
    let (sw, sh) = (u32::from(d.width()), u32::from(d.height()));
    check_size(u64::from(sw), u64::from(sh))?;
    let mut canvas = vec![0u8; sw as usize * sh as usize * 4];
    let mut enc: Option<Encoder> = None;
    let mut elapsed = 0u32; // ms, start of the current GIF frame
    let mut emitted = 0u32;
    let mut poster = None;
    let mut read = 0usize;
    while let Some(f) = d.read_next_frame().map_err(|_| MediaError::Damaged)? {
        read += 1;
        if read > MAX_GIF_FRAMES {
            break;
        }
        let (fx, fy, fw, fh) = (
            u32::from(f.left),
            u32::from(f.top),
            u32::from(f.width),
            u32::from(f.height),
        );
        let previous = (f.dispose == gif::DisposalMethod::Previous).then(|| canvas.clone());
        for y in 0..fh {
            for x in 0..fw {
                let (cx, cy) = (fx + x, fy + y);
                if cx >= sw || cy >= sh {
                    continue;
                }
                let s = ((y * fw + x) * 4) as usize;
                let Some(px) = f.buffer.get(s..s + 4) else {
                    return Err(MediaError::Damaged);
                };
                if px[3] != 0 {
                    let o = ((cy * sw + cx) * 4) as usize;
                    canvas[o..o + 4].copy_from_slice(px);
                }
            }
        }
        // Browsers play a 0 or 1 cs delay as 100 ms.
        let delay = if f.delay < 2 {
            100
        } else {
            u32::from(f.delay) * 10
        };
        let end = (elapsed + delay).min(MAX_CLIP_MS);
        // Every output frame whose time falls in this GIF frame shows it.
        let mut shown: Option<Rgba> = None;
        while emitted < MAX_CLIP_FRAMES && emitted * 1000 / CLIP_FPS < end {
            let img = match &shown {
                Some(i) => i.clone(),
                None => {
                    let i = prepare(&canvas, sw, sh);
                    shown = Some(i.clone());
                    i
                }
            };
            if poster.is_none() {
                poster = Some(jpeg(&img)?);
            }
            let e = match enc.as_mut() {
                Some(e) => e,
                None => enc.insert(Encoder::new(img.width, img.height)?),
            };
            e.push(&img)?;
            emitted += 1;
        }
        match f.dispose {
            gif::DisposalMethod::Background => {
                for y in fy..(fy + fh).min(sh) {
                    for x in fx..(fx + fw).min(sw) {
                        let o = ((y * sw + x) * 4) as usize;
                        canvas[o..o + 4].fill(0);
                    }
                }
            }
            gif::DisposalMethod::Previous => {
                if let Some(p) = previous {
                    canvas = p;
                }
            }
            _ => {}
        }
        elapsed = end;
        if elapsed >= MAX_CLIP_MS {
            break;
        }
    }
    let (Some(enc), Some(poster)) = (enc, poster) else {
        return Err(MediaError::Damaged);
    };
    let (width, height) = (enc.width, enc.height);
    let units = enc.finish()?;
    if units.len() != emitted as usize {
        return Err(MediaError::Encode);
    }
    let duration_ms = emitted * 1000 / CLIP_FPS;
    let bytes = pack(width, height, emitted, duration_ms, &poster, &units)?;
    Ok(Clip {
        bytes,
        width,
        height,
        frames: emitted,
        duration_ms,
    })
}

/// Flatten onto white, shrink, and pad to an even size of at least 16.
fn prepare(canvas: &[u8], w: u32, h: u32) -> Rgba {
    let flat: Vec<u8> = canvas
        .chunks_exact(4)
        .flat_map(|p| {
            let a = u32::from(p[3]);
            let mix = |c: u8| ((u32::from(c) * a + 255 * (255 - a) + 127) / 255) as u8;
            [mix(p[0]), mix(p[1]), mix(p[2]), 255]
        })
        .collect();
    let img = resize::fit(
        &Rgba {
            width: w,
            height: h,
            pixels: flat,
        },
        MAX_CLIP_SIDE,
    );
    let (nw, nh) = (
        img.width.max(16).next_multiple_of(2),
        img.height.max(16).next_multiple_of(2),
    );
    if (nw, nh) == (img.width, img.height) {
        return img;
    }
    let mut pixels = vec![255u8; nw as usize * nh as usize * 4];
    for y in 0..img.height as usize {
        let src = &img.pixels[y * img.width as usize * 4..][..img.width as usize * 4];
        pixels[y * nw as usize * 4..][..src.len()].copy_from_slice(src);
    }
    Rgba {
        width: nw,
        height: nh,
        pixels,
    }
}

fn jpeg(img: &Rgba) -> Result<Vec<u8>> {
    let rgb: Vec<u8> = img
        .pixels
        .chunks_exact(4)
        .flat_map(|p| [p[0], p[1], p[2]])
        .collect();
    let mut out = Vec::new();
    jpeg_encoder::Encoder::new(&mut out, POSTER_QUALITY)
        .encode(
            &rgb,
            u16::try_from(img.width).map_err(|_| MediaError::TooLarge)?,
            u16::try_from(img.height).map_err(|_| MediaError::TooLarge)?,
            jpeg_encoder::ColorType::Rgb,
        )
        .map_err(|_| MediaError::Encode)?;
    if out.len() > RECORD - RECORD_HEAD - HEADER_FIXED {
        return Err(MediaError::TooLarge);
    }
    Ok(out)
}

/// BT.601 limited-range 4:2:0 from opaque RGBA (even dimensions).
pub(crate) fn to_i420(img: &Rgba) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (w, h) = (img.width as usize, img.height as usize);
    let px = |x: usize, y: usize| {
        let p = &img.pixels[(y * w + x) * 4..][..3];
        (f32::from(p[0]), f32::from(p[1]), f32::from(p[2]))
    };
    let mut y_plane = Vec::with_capacity(w * h);
    for y in 0..h {
        for x in 0..w {
            let (r, g, b) = px(x, y);
            y_plane.push((16.0 + 0.257 * r + 0.504 * g + 0.098 * b).round() as u8);
        }
    }
    let (cw, ch) = (w / 2, h / 2);
    let mut u = Vec::with_capacity(cw * ch);
    let mut v = Vec::with_capacity(cw * ch);
    for y in 0..ch {
        for x in 0..cw {
            let mut acc = (0f32, 0f32, 0f32);
            for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                let (r, g, b) = px(2 * x + dx, 2 * y + dy);
                acc = (acc.0 + r / 4.0, acc.1 + g / 4.0, acc.2 + b / 4.0);
            }
            let (r, g, b) = acc;
            u.push(
                (128.0 - 0.148 * r - 0.291 * g + 0.439 * b)
                    .round()
                    .clamp(0.0, 255.0) as u8,
            );
            v.push(
                (128.0 + 0.439 * r - 0.368 * g - 0.071 * b)
                    .round()
                    .clamp(0.0, 255.0) as u8,
            );
        }
    }
    (y_plane, u, v)
}

/// RGBA from BT.601 limited-range I420 planes.
pub fn i420_to_rgba(w: u32, h: u32, y: &[u8], u: &[u8], v: &[u8]) -> Result<Rgba> {
    let (wu, hu) = (w as usize, h as usize);
    let cw = wu.div_ceil(2);
    if y.len() != wu * hu || u.len() != cw * hu.div_ceil(2) || v.len() != u.len() {
        return Err(MediaError::Damaged);
    }
    let mut pixels = Vec::with_capacity(wu * hu * 4);
    for row in 0..hu {
        for col in 0..wu {
            let yy = 1.164 * (f32::from(y[row * wu + col]) - 16.0);
            let c = (row / 2) * cw + col / 2;
            let (uu, vv) = (f32::from(u[c]) - 128.0, f32::from(v[c]) - 128.0);
            let px = |f: f32| f.round().clamp(0.0, 255.0) as u8;
            pixels.extend_from_slice(&[
                px(yy + 1.596 * vv),
                px(yy - 0.392 * uu - 0.813 * vv),
                px(yy + 2.017 * uu),
                255,
            ]);
        }
    }
    Ok(Rgba {
        width: w,
        height: h,
        pixels,
    })
}

struct Encoder {
    width: u32,
    height: u32,
    ctx: rav1e::Context<u8>,
    units: Vec<Vec<u8>>,
}

impl Encoder {
    fn new(width: u32, height: u32) -> Result<Self> {
        use rav1e::prelude::*;
        let mut enc = EncoderConfig::with_speed_preset(10);
        enc.width = width as usize;
        enc.height = height as usize;
        enc.bit_depth = 8;
        enc.chroma_sampling = ChromaSampling::Cs420;
        enc.time_base = Rational::new(1, u64::from(CLIP_FPS));
        enc.bitrate = TARGET_KBPS;
        enc.low_latency = true;
        enc.max_key_frame_interval = 64;
        let cfg = Config::new().with_encoder_config(enc).with_threads(1);
        let ctx = cfg.new_context().map_err(|_| MediaError::Encode)?;
        Ok(Self {
            width,
            height,
            ctx,
            units: Vec::new(),
        })
    }

    fn push(&mut self, img: &Rgba) -> Result<()> {
        let (y, u, v) = to_i420(img);
        let mut f = self.ctx.new_frame();
        let w = self.width as usize;
        f.planes[0].copy_from_raw_u8(&y, w, 1);
        f.planes[1].copy_from_raw_u8(&u, w / 2, 1);
        f.planes[2].copy_from_raw_u8(&v, w / 2, 1);
        self.ctx.send_frame(f).map_err(|_| MediaError::Encode)?;
        self.drain(false)
    }

    fn drain(&mut self, flushing: bool) -> Result<()> {
        use rav1e::EncoderStatus;
        loop {
            match self.ctx.receive_packet() {
                Ok(p) => self.units.push(p.data),
                Err(EncoderStatus::Encoded) => {}
                Err(EncoderStatus::NeedMoreData) if !flushing => return Ok(()),
                Err(EncoderStatus::LimitReached) => return Ok(()),
                Err(_) => return Err(MediaError::Encode),
            }
        }
    }

    fn finish(mut self) -> Result<Vec<Vec<u8>>> {
        self.ctx.flush();
        self.drain(true)?;
        Ok(self.units)
    }
}

// ---------------------------------------------------------------------------
// The container
// ---------------------------------------------------------------------------

fn pack(
    width: u32,
    height: u32,
    frames: u32,
    duration_ms: u32,
    poster: &[u8],
    units: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut rec = vec![0u8; RECORD];
    let mut h = Vec::with_capacity(RECORD);
    h.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    h.extend_from_slice(MAGIC);
    h.push(1);
    for d in [width, height, CLIP_FPS] {
        h.extend_from_slice(
            &u16::try_from(d)
                .map_err(|_| MediaError::TooLarge)?
                .to_be_bytes(),
        );
    }
    h.extend_from_slice(&frames.to_be_bytes());
    h.extend_from_slice(&duration_ms.to_be_bytes());
    h.push(CODEC_AV1);
    h.extend_from_slice(&(poster.len() as u32).to_be_bytes());
    h.extend_from_slice(poster);
    if h.len() > RECORD {
        return Err(MediaError::TooLarge);
    }
    rec[..h.len()].copy_from_slice(&h);
    out.extend_from_slice(&rec);

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
            return Err(MediaError::TooLarge); // one frame bigger than a record
        }
        rec[0] = 1;
        let pts = (first as u32) * 1000 / CLIP_FPS;
        rec[1..5].copy_from_slice(&pts.to_be_bytes());
        rec[5..7].copy_from_slice(&((i - first) as u16).to_be_bytes());
        out.extend_from_slice(&rec);
    }
    if out.len() / RECORD > MAX_RECORDS {
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

/// Parse and check a clip without decoding any frame: every length, count
/// and padding byte is checked against the fixed layout.
pub fn parse_clip(bytes: &[u8]) -> Result<ClipInfo<'_>> {
    let n = bytes.len() / RECORD;
    if !bytes.len().is_multiple_of(RECORD) || !(2..=MAX_RECORDS).contains(&n) {
        return Err(MediaError::Damaged);
    }
    let head = &bytes[..RECORD];
    if head[..RECORD_HEAD] != [0; RECORD_HEAD] || head[RECORD_HEAD..RECORD_HEAD + 4] != MAGIC[..] {
        return Err(MediaError::Unsupported);
    }
    let mut at = RECORD_HEAD + 4;
    if head[at] != 1 {
        return Err(MediaError::Unsupported);
    }
    at += 1;
    let (width, height, fps) = (be16(head, at)?, be16(head, at + 2)?, be16(head, at + 4)?);
    at += 6;
    let frames = be32(head, at)?;
    let duration_ms = be32(head, at + 4)?;
    let codec = head[at + 8];
    let poster_len = be32(head, at + 9)? as usize;
    at += 13;
    if width == 0
        || height == 0
        || width.max(height) > MAX_CLIP_SIDE.max(16)
        || fps != CLIP_FPS
        || frames == 0
        || frames > MAX_CLIP_FRAMES
        || duration_ms != frames * 1000 / CLIP_FPS
        || codec != CODEC_AV1
        || poster_len == 0
        || at + poster_len > RECORD
        || head[at + poster_len..].iter().any(|&b| b != 0)
    {
        return Err(MediaError::Damaged);
    }
    let poster = &head[at..at + poster_len];
    let mut units = Vec::with_capacity(frames as usize);
    for r in 1..n {
        let rec = &bytes[r * RECORD..(r + 1) * RECORD];
        let count = be16(rec, 5)? as usize;
        if rec[0] != 1 || count == 0 || be32(rec, 1)? != (units.len() as u32) * 1000 / CLIP_FPS {
            return Err(MediaError::Damaged);
        }
        let mut at = RECORD_HEAD;
        for _ in 0..count {
            let len = be32(rec, at)? as usize;
            let unit = rec
                .get(at + 4..at + 4 + len)
                .filter(|u| !u.is_empty())
                .ok_or(MediaError::Damaged)?;
            units.push(unit);
            at += 4 + len;
        }
        if rec[at..].iter().any(|&b| b != 0) {
            return Err(MediaError::Damaged);
        }
    }
    if units.len() != frames as usize {
        return Err(MediaError::Damaged);
    }
    Ok(ClipInfo {
        width,
        height,
        frames,
        duration_ms,
        poster,
        units,
    })
}

/// A clip's poster decoded and shrunk to `max_side`, and its length (ms).
/// No AV1 is decoded: the poster is the JPEG in the header.
pub fn clip_poster(bytes: &[u8], max_side: u32) -> Result<(Rgba, u32)> {
    let info = parse_clip(bytes)?;
    let img = crate::thumbnail(info.poster, max_side)?;
    Ok((img, info.duration_ms))
}

/// Decode a clip's frames (in `mediad` only), each shrunk to at most
/// `max_side`, keeping at most `max_frames` evenly spaced ones.
#[cfg(feature = "av1")]
pub fn clip_frames(bytes: &[u8], max_side: u32, max_frames: usize) -> Result<Vec<Rgba>> {
    let info = parse_clip(bytes)?;
    let mut dec = enclave_av1::Decoder::new().map_err(|_| MediaError::Unsupported)?;
    let keep = max_frames.clamp(1, info.frames as usize);
    let mut out = Vec::with_capacity(keep);
    let mut index = 0usize;
    for unit in &info.units {
        for f in dec.decode(unit).map_err(|_| MediaError::Damaged)? {
            if f.width != info.width || f.height != info.height {
                return Err(MediaError::Damaged);
            }
            // Frame `index` is kept when it starts a new step of the sampling.
            if index * keep / info.frames as usize != (index + 1) * keep / info.frames as usize
                || keep == info.frames as usize
            {
                let img = i420_to_rgba(f.width, f.height, &f.y, &f.u, &f.v)?;
                out.push(resize::fit(&img, max_side.max(1)));
            }
            index += 1;
        }
    }
    if index != info.frames as usize {
        return Err(MediaError::Damaged);
    }
    Ok(out)
}

/// Feed raw bytes to the AV1 decoder as temporal units (`u32 len ‖ bytes`
/// each), for fuzzing the decoder itself; returns the frames it produced.
#[cfg(feature = "av1")]
pub fn decode_units(bytes: &[u8]) -> Result<usize> {
    let mut dec = enclave_av1::Decoder::new().map_err(|_| MediaError::Unsupported)?;
    let mut at = 0usize;
    let mut frames = 0usize;
    while at + 4 <= bytes.len() && frames < 8 {
        let len = be32(bytes, at)? as usize;
        let unit = bytes
            .get(at + 4..at + 4 + len.min(bytes.len()))
            .ok_or(MediaError::Damaged)?;
        frames += dec.decode(unit).map(|f| f.len()).unwrap_or(0);
        at += 4 + unit.len();
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A GIF of `n` frames, `w × h`, each a solid colour block moving right,
    /// with delays in centiseconds.
    pub(crate) fn gif(w: u16, h: u16, n: usize, delay: u16) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut e = gif::Encoder::new(&mut out, w, h, &[]).unwrap();
            e.set_repeat(gif::Repeat::Infinite).unwrap();
            for i in 0..n {
                let mut px = vec![0u8; w as usize * h as usize * 4];
                for y in 0..h as usize {
                    for x in 0..w as usize {
                        let on = (x / 8 + i).is_multiple_of(4);
                        let p = &mut px[(y * w as usize + x) * 4..][..4];
                        p.copy_from_slice(if on {
                            &[200, 40, 40, 255]
                        } else {
                            &[30, 90, 70, 255]
                        });
                    }
                }
                let mut f = gif::Frame::from_rgba_speed(w, h, &mut px, 10);
                f.delay = delay;
                e.write_frame(&f).unwrap();
            }
        }
        out
    }

    #[test]
    fn gif_to_clip_and_container_checks() {
        let g = gif(64, 48, 6, 10); // 6 × 100 ms
        let clip = clip_from_gif(&g).unwrap();
        assert_eq!((clip.width, clip.height), (64, 48));
        assert_eq!(clip.frames, 9, "600 ms at 15 fps");
        assert_eq!(clip.duration_ms, 600);
        assert_eq!(clip.bytes.len() % RECORD, 0);
        let info = parse_clip(&clip.bytes).unwrap();
        assert_eq!(info.frames, 9);
        assert_eq!(info.units.len(), 9);
        crate::decode(info.poster).unwrap();

        // Any change to the layout is refused.
        let mut b = clip.bytes.clone();
        b.push(0);
        assert!(parse_clip(&b).is_err(), "not whole records");
        let mut b = clip.bytes.clone();
        b[RECORD - 1] = 1;
        assert!(parse_clip(&b).is_err(), "header padding");
        let mut b = clip.bytes.clone();
        b[RECORD + 5..RECORD + 7].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse_clip(&b).is_err(), "unit count");
        let mut b = clip.bytes.clone();
        b[RECORD_HEAD + 4 + 1 + 4..][..2].copy_from_slice(&30u16.to_be_bytes());
        assert!(parse_clip(&b).is_err(), "frame rate");
        assert!(parse_clip(&clip.bytes[..RECORD]).is_err(), "no frames");
    }

    #[test]
    fn long_and_large_gifs_are_cut_and_shrunk() {
        let g = gif(960, 200, 3, 80); // 2.4 s, wide
        let clip = clip_from_gif(&g).unwrap();
        assert_eq!(clip.width, 480);
        assert_eq!(clip.height, 100);
        assert_eq!(clip.frames, 36);
        let g = gif(32, 32, 40, 50); // 20 s
        let clip = clip_from_gif(&g).unwrap();
        assert_eq!(clip.duration_ms, MAX_CLIP_MS);
        assert_eq!(clip.frames, MAX_CLIP_FRAMES);
        assert!(clip_from_gif(b"GIF89a\x01").is_err());
        assert!(clip_from_gif(b"\x89PNG").is_err());
    }

    #[cfg(feature = "av1")]
    #[test]
    fn clip_decodes_back() {
        let g = gif(64, 48, 6, 10);
        let clip = clip_from_gif(&g).unwrap();
        let frames = clip_frames(&clip.bytes, 480, 100).unwrap();
        assert_eq!(frames.len(), 9);
        // The first frame's block is where the GIF put it, within codec loss.
        let f = &frames[0];
        let at = |x: usize, y: usize| &f.pixels[(y * 64 + x) * 4..][..3];
        assert!(
            at(3, 20)[0] > 150 && at(3, 20)[1] < 90,
            "red block: {:?}",
            at(3, 20)
        );
        assert!(
            at(12, 20)[1] > 60 && at(12, 20)[0] < 90,
            "green: {:?}",
            at(12, 20)
        );
        assert_eq!(clip_frames(&clip.bytes, 480, 3).unwrap().len(), 3);
        // A damaged unit decodes to garbage or fails; it never panics.
        let mut b = clip.bytes.clone();
        b[RECORD + RECORD_HEAD + 4 + 10] ^= 0xff;
        let _ = clip_frames(&b, 480, 100);
    }
}
