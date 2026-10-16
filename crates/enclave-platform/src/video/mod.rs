//! Reading the person's own video files with the platform's decoder
//! (`docs/15-client.md` §5.5): GStreamer on Linux, AVFoundation on macOS
//! and iOS, Media Foundation on Windows, MediaCodec on Android. These are
//! the system's own decoders for the system's own formats (MP4, MOV, …);
//! they run in the app on the sender's side only, on a file the person
//! chose. What comes out is pictures and sound, which Enclave encodes
//! again (AV1 and Opus in mediad): no byte of the original file is sent,
//! and the receiver never meets these decoders.
//!
//! [`read_video`] hands frames as RGBA at the file's own size (turned the
//! way the camera held it), at 30 a second (a slower file's frames
//! repeat, a faster one's are skipped), and the sound as 48 kHz mono.

/// What a video file gives, in order: [`VideoEvent::Start`] once, then
/// frames and sound as they come.
#[derive(Debug)]
pub enum VideoEvent<'a> {
    /// The picture's size, and the file's length if it says (ms; 0 if
    /// not).
    Start {
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// Length.
        duration_ms: u64,
    },
    /// The next frame (1/30 s after the last): `width × height` RGBA.
    Frame(&'a [u8]),
    /// More sound: 48 kHz mono.
    Sound(&'a [i16]),
}

/// Frames a second [`read_video`] gives.
pub const FPS: u32 = 30;

/// Why a video couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoError {
    /// This system has no decoder for videos (on Linux, GStreamer isn't
    /// installed).
    NoDecoder,
    /// Not a video this system can read.
    Unreadable(String),
    /// The caller stopped.
    Stopped,
}

impl std::fmt::Display for VideoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VideoError::NoDecoder => write!(f, "no video decoder on this system"),
            VideoError::Unreadable(why) => write!(f, "can't read this video: {why}"),
            VideoError::Stopped => write!(f, "stopped"),
        }
    }
}

/// Read the video file at `path`, calling `each` with what it holds;
/// `each` returns false to stop.
pub fn read_video(
    path: &std::path::Path,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> Result<(), VideoError> {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    return gstreamer::read(path, each);
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    return avfoundation::read(path, each);
    #[cfg(windows)]
    return mediafoundation::read(path, each);
    #[cfg(target_os = "android")]
    return mediacodec::read(path, each);
    #[allow(unreachable_code)]
    {
        let _ = (path, each);
        Err(VideoError::NoDecoder)
    }
}

/// Frames at a steady 30 a second from frames stamped in nanoseconds: each
/// output tick shows the newest frame at or before it.
#[cfg_attr(
    all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android")),
        not(test)
    ),
    allow(dead_code)
)]
pub(crate) struct Pacer {
    next_ns: u64,
    last: Vec<u8>,
}

#[cfg_attr(
    all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android")),
        not(test)
    ),
    allow(dead_code)
)]
impl Pacer {
    pub(crate) fn new() -> Self {
        Self {
            next_ns: 0,
            last: Vec::new(),
        }
    }

    /// A decoded frame at `pts_ns`: emits the ticks up to it with the
    /// frame before, then keeps this one. False when `each` says stop.
    pub(crate) fn frame(
        &mut self,
        pts_ns: u64,
        rgba: Vec<u8>,
        each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
    ) -> bool {
        let tick = 1_000_000_000 / u64::from(FPS);
        if self.last.is_empty() {
            self.next_ns = pts_ns;
        }
        while !self.last.is_empty() && self.next_ns + tick / 2 <= pts_ns {
            if !each(VideoEvent::Frame(&self.last)) {
                return false;
            }
            self.next_ns += tick;
        }
        self.last = rgba;
        true
    }

    /// The end: the last frame once more.
    pub(crate) fn finish(&mut self, each: &mut dyn FnMut(VideoEvent<'_>) -> bool) -> bool {
        self.last.is_empty() || each(VideoEvent::Frame(&self.last))
    }
}

/// Mono 48 kHz from interleaved samples at another rate (linear).
#[cfg_attr(not(any(windows, target_os = "android", test)), allow(dead_code))]
pub(crate) struct Resampler {
    rate: u32,
    channels: usize,
    pos: f64,
    prev: f32,
}

#[cfg_attr(not(any(windows, target_os = "android", test)), allow(dead_code))]
impl Resampler {
    pub(crate) fn new(rate: u32, channels: usize) -> Self {
        Self {
            rate: rate.max(1),
            channels: channels.max(1),
            pos: 0.0,
            prev: 0.0,
        }
    }

    pub(crate) fn push(&mut self, interleaved: &[i16]) -> Vec<i16> {
        let mono: Vec<f32> = interleaved
            .chunks(self.channels)
            .map(|c| c.iter().map(|s| f32::from(*s)).sum::<f32>() / c.len() as f32)
            .collect();
        let step = f64::from(self.rate) / 48_000.0;
        let mut out = Vec::with_capacity((mono.len() as f64 / step) as usize + 1);
        // `pos` runs from -1 (the previous block's last sample) on.
        while self.pos < mono.len() as f64 - 1.0 {
            let i = self.pos.floor();
            let t = (self.pos - i) as f32;
            let a = if i < 0.0 { self.prev } else { mono[i as usize] };
            let b = mono[(i + 1.0) as usize];
            out.push((a + (b - a) * t).round().clamp(-32_768.0, 32_767.0) as i16);
            self.pos += step;
        }
        if let Some(&last) = mono.last() {
            self.prev = last;
            self.pos -= mono.len() as f64;
        }
        out
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod avfoundation;
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
mod gstreamer;
#[cfg(target_os = "android")]
mod mediacodec;
#[cfg(windows)]
mod mediafoundation;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steady_frames() {
        let mut p = Pacer::new();
        let mut shown = Vec::new();
        let mut each = |e: VideoEvent<'_>| {
            if let VideoEvent::Frame(f) = e {
                shown.push(f[0]);
            }
            true
        };
        // 15 fps in: every frame twice.
        for k in 0..4u8 {
            assert!(p.frame(u64::from(k) * 66_666_667, vec![k], &mut each));
        }
        assert!(p.finish(&mut each));
        assert_eq!(shown, vec![0, 0, 1, 1, 2, 2, 3]);
        // 60 fps in: every other one.
        let mut p = Pacer::new();
        let mut shown = Vec::new();
        let mut each = |e: VideoEvent<'_>| {
            if let VideoEvent::Frame(f) = e {
                shown.push(f[0]);
            }
            true
        };
        for k in 0..8u8 {
            p.frame(u64::from(k) * 16_666_667, vec![k], &mut each);
        }
        p.finish(&mut each);
        assert_eq!(shown, vec![0, 2, 4, 6, 7]);
    }

    #[test]
    fn resampled_to_48k_mono() {
        let mut r = Resampler::new(44_100, 2);
        let stereo: Vec<i16> = (0..44_100)
            .flat_map(|i| [(i % 100) as i16, (i % 100) as i16])
            .collect();
        let mut out = Vec::new();
        for c in stereo.chunks(4410) {
            out.extend(r.push(c));
        }
        assert!((47_900..=48_000).contains(&out.len()), "{}", out.len());
        let mut same = Resampler::new(48_000, 1);
        assert_eq!(same.push(&[1, 2, 3, 4]), vec![1, 2, 3]);
        assert_eq!(same.push(&[5, 6]), vec![4, 5]);
    }
}
