//! macOS and iOS: AVFoundation's `AVAssetReader`, the system's own decoder
//! for its formats (MOV, MP4, M4V; H.264, HEVC, ProRes …). Pictures come
//! as 32-bit BGRA pixel buffers, turned here the way the track says the
//! camera held it; sound as 16-bit 48 kHz mono, which AVFoundation
//! converts to.

use super::{Pacer, VideoError, VideoEvent};
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_av_foundation::{
    AVAsset, AVAssetReader, AVAssetReaderStatus, AVAssetReaderTrackOutput, AVMediaTypeAudio,
    AVMediaTypeVideo,
};
use objc2_avf_audio::{
    AVFormatIDKey, AVLinearPCMBitDepthKey, AVLinearPCMIsBigEndianKey, AVLinearPCMIsFloatKey,
    AVLinearPCMIsNonInterleaved, AVNumberOfChannelsKey, AVSampleRateKey,
};
use objc2_core_media::CMSampleBuffer;
use objc2_core_video::{
    CVPixelBufferGetBaseAddress, CVPixelBufferGetBytesPerRow, CVPixelBufferGetHeight,
    CVPixelBufferGetWidth, CVPixelBufferLockBaseAddress, CVPixelBufferLockFlags,
    CVPixelBufferUnlockBaseAddress,
};
use objc2_foundation::{NSDictionary, NSNumber, NSString, NSURL};

/// `kAudioFormatLinearPCM` ('lpcm').
const LINEAR_PCM: u32 = u32::from_be_bytes(*b"lpcm");

/// Quarter turns clockwise the picture needs, from a track's transform.
fn quarter_turns(a: f64, b: f64, c: f64, d: f64) -> u8 {
    match (
        a.round() as i32,
        b.round() as i32,
        c.round() as i32,
        d.round() as i32,
    ) {
        (0, 1, -1, 0) => 1,
        (-1, 0, 0, -1) => 2,
        (0, -1, 1, 0) => 3,
        _ => 0,
    }
}

/// RGBA `w × h` turned clockwise `turns` quarter turns: the new size and
/// pixels.
fn turn(w: usize, h: usize, rgba: Vec<u8>, turns: u8) -> (usize, usize, Vec<u8>) {
    if turns == 0 {
        return (w, h, rgba);
    }
    let (nw, nh) = if turns % 2 == 1 { (h, w) } else { (w, h) };
    let mut out = vec![0u8; rgba.len()];
    for y in 0..h {
        for x in 0..w {
            let (nx, ny) = match turns {
                1 => (h - 1 - y, x),
                2 => (w - 1 - x, h - 1 - y),
                _ => (y, w - 1 - x),
            };
            out[(ny * nw + nx) * 4..][..4].copy_from_slice(&rgba[(y * w + x) * 4..][..4]);
        }
    }
    (nw, nh, out)
}

/// RGBA from a BGRA pixel buffer.
///
/// # Safety
///
/// `buffer` must be a valid sample buffer for the duration of the call.
unsafe fn frame(buffer: &CMSampleBuffer) -> Option<(usize, usize, Vec<u8>)> {
    // SAFETY: the image buffer belongs to the sample buffer; it is locked
    // read-only around the reads, and holds `height` rows of `stride`
    // bytes.
    unsafe {
        let image = buffer.image_buffer()?;
        if CVPixelBufferLockBaseAddress(&image, CVPixelBufferLockFlags::ReadOnly) != 0 {
            return None;
        }
        let (w, h) = (
            CVPixelBufferGetWidth(&image),
            CVPixelBufferGetHeight(&image),
        );
        let stride = CVPixelBufferGetBytesPerRow(&image);
        let base = CVPixelBufferGetBaseAddress(&image).cast::<u8>();
        let out = if base.is_null() || stride < 4 * w || w == 0 || h == 0 {
            None
        } else {
            let mut out = Vec::with_capacity(w * h * 4);
            for row in 0..h {
                for px in std::slice::from_raw_parts(base.add(row * stride), 4 * w).chunks_exact(4)
                {
                    out.extend_from_slice(&[px[2], px[1], px[0], 255]);
                }
            }
            Some((w, h, out))
        };
        CVPixelBufferUnlockBaseAddress(&image, CVPixelBufferLockFlags::ReadOnly);
        out
    }
}

/// The 16-bit samples in a sample buffer.
///
/// # Safety
///
/// `buffer` must be a valid sample buffer for the duration of the call.
unsafe fn sound(buffer: &CMSampleBuffer) -> Vec<i16> {
    // SAFETY: the block buffer belongs to the sample buffer; we copy its
    // `len` bytes out into memory of that size.
    unsafe {
        let Some(block) = buffer.data_buffer() else {
            return Vec::new();
        };
        let len = block.data_length();
        let mut bytes = vec![0u8; len];
        let Some(dst) = std::ptr::NonNull::new(bytes.as_mut_ptr().cast()) else {
            return Vec::new();
        };
        if len == 0 || block.copy_data_bytes(0, len, dst) != 0 {
            return Vec::new();
        }
        bytes
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect()
    }
}

/// CFString constants are NSStrings (toll-free bridged).
///
/// # Safety
///
/// `key` must be a valid CFString.
unsafe fn ns(key: &objc2_core_foundation::CFString) -> &NSString {
    // SAFETY: as documented, a CFString is an NSString.
    unsafe { &*std::ptr::from_ref(key).cast::<NSString>() }
}

pub(super) fn read(
    path: &std::path::Path,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> Result<(), VideoError> {
    let unreadable = |why: &str| VideoError::Unreadable(why.into());
    let path = path.to_str().ok_or_else(|| unreadable("the file's name"))?;
    // SAFETY: AVFoundation's documented, synchronous reading API, used
    // from one thread; every object is retained while used, and the
    // framework's constant keys are valid statics.
    #[allow(deprecated)]
    unsafe {
        let url = NSURL::fileURLWithPath(&NSString::from_str(path));
        let asset = AVAsset::assetWithURL(&url);
        let video_type = AVMediaTypeVideo.ok_or_else(|| unreadable("AVFoundation"))?;
        let tracks = asset.tracksWithMediaType(video_type);
        let track = tracks
            .firstObject()
            .ok_or_else(|| unreadable("it has no picture"))?;
        let t = track.preferredTransform();
        let turns = quarter_turns(t.a, t.b, t.c, t.d);
        let reader = AVAssetReader::assetReaderWithAsset_error(&asset)
            .map_err(|e| unreadable(&e.localizedDescription().to_string()))?;

        let format = NSNumber::new_u32(objc2_core_video::kCVPixelFormatType_32BGRA);
        let key = ns(objc2_core_video::kCVPixelBufferPixelFormatTypeKey);
        let settings: Retained<NSDictionary<NSString, AnyObject>> =
            NSDictionary::from_slices(&[key], &[format.as_ref()]);
        let video = AVAssetReaderTrackOutput::assetReaderTrackOutputWithTrack_outputSettings(
            &track,
            Some(&settings),
        );
        video.setAlwaysCopiesSampleData(false);
        reader.addOutput(&video);

        let audio = match AVMediaTypeAudio
            .map(|a| asset.tracksWithMediaType(a))
            .and_then(|t| t.firstObject())
        {
            Some(a) => {
                let keys = [
                    AVFormatIDKey,
                    AVSampleRateKey,
                    AVNumberOfChannelsKey,
                    AVLinearPCMBitDepthKey,
                    AVLinearPCMIsFloatKey,
                    AVLinearPCMIsBigEndianKey,
                    AVLinearPCMIsNonInterleaved,
                ];
                let values = [
                    NSNumber::new_u32(LINEAR_PCM),
                    NSNumber::new_f64(48_000.0),
                    NSNumber::new_u32(1),
                    NSNumber::new_u32(16),
                    NSNumber::new_bool(false),
                    NSNumber::new_bool(false),
                    NSNumber::new_bool(false),
                ];
                let keys: Option<Vec<&NSString>> = keys.into_iter().collect();
                match keys {
                    Some(keys) => {
                        let values: Vec<&AnyObject> = values.iter().map(|v| v.as_ref()).collect();
                        let s: Retained<NSDictionary<NSString, AnyObject>> =
                            NSDictionary::from_slices(&keys, &values);
                        let out = AVAssetReaderTrackOutput::assetReaderTrackOutputWithTrack_outputSettings(&a, Some(&s));
                        reader.canAddOutput(&out).then(|| {
                            reader.addOutput(&out);
                            out
                        })
                    }
                    None => None,
                }
            }
            None => None,
        };
        if !reader.startReading() {
            return Err(unreadable("it won't play"));
        }
        let duration = asset.duration();
        let duration_ms = if duration.timescale > 0 && duration.value > 0 {
            (duration.value as u64).saturating_mul(1000) / duration.timescale as u64
        } else {
            0
        };
        let mut pacer = Pacer::new();
        let mut size: Option<(usize, usize)> = None;
        let mut sound_done = audio.is_none();
        while let Some(buffer) = video.copyNextSampleBuffer() {
            if let Some((w, h, rgba)) = frame(&buffer) {
                let (w, h, rgba) = turn(w, h, rgba, turns);
                match size {
                    None => {
                        size = Some((w, h));
                        if !each(VideoEvent::Start {
                            width: w as u32,
                            height: h as u32,
                            duration_ms,
                        }) {
                            reader.cancelReading();
                            return Err(VideoError::Stopped);
                        }
                    }
                    Some(s) if s != (w, h) => {
                        reader.cancelReading();
                        return Err(unreadable("a frame of another size"));
                    }
                    Some(_) => {}
                }
                let pts = buffer.presentation_time_stamp();
                let ns = if pts.timescale > 0 && pts.value >= 0 {
                    (pts.value as u64).saturating_mul(1_000_000_000) / pts.timescale as u64
                } else {
                    0
                };
                if !pacer.frame(ns, rgba, each) {
                    reader.cancelReading();
                    return Err(VideoError::Stopped);
                }
            }
            // The sound up to here (AVFoundation interleaves its reads).
            if let Some(a) = &audio
                && !sound_done
            {
                match a.copyNextSampleBuffer() {
                    Some(b) => {
                        let pcm = sound(&b);
                        if !pcm.is_empty() && !each(VideoEvent::Sound(&pcm)) {
                            reader.cancelReading();
                            return Err(VideoError::Stopped);
                        }
                    }
                    None => sound_done = true,
                }
            }
        }
        if reader.status() == AVAssetReaderStatus::Failed {
            let why = reader
                .error()
                .map(|e| e.localizedDescription().to_string())
                .unwrap_or_default();
            return Err(VideoError::Unreadable(why));
        }
        if size.is_none() {
            return Err(unreadable("it has no picture"));
        }
        pacer.finish(each);
        if let Some(a) = &audio {
            while !sound_done {
                match a.copyNextSampleBuffer() {
                    Some(b) => {
                        let pcm = sound(&b);
                        if !pcm.is_empty() && !each(VideoEvent::Sound(&pcm)) {
                            return Err(VideoError::Stopped);
                        }
                    }
                    None => sound_done = true,
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turns() {
        assert_eq!(quarter_turns(0.0, 1.0, -1.0, 0.0), 1);
        assert_eq!(quarter_turns(1.0, 0.0, 0.0, 1.0), 0);
        // 2 × 1, a red then a blue pixel, turned once: 1 × 2, red on top.
        let (w, h, px) = turn(2, 1, vec![255, 0, 0, 255, 0, 0, 255, 255], 1);
        assert_eq!((w, h), (1, 2));
        assert_eq!(px, vec![255, 0, 0, 255, 0, 0, 255, 255]);
    }
}
