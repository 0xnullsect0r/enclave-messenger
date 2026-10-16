//! Windows: Media Foundation's source reader, the system's own decoders
//! (MP4, MOV, WMV …; H.264, HEVC where installed). Its video processor
//! converts pictures to 32-bit RGB; sound comes as 16-bit PCM at the file's
//! rate and channels, made 48 kHz mono here.

use super::{Pacer, Resampler, VideoError, VideoEvent};
use windows::Win32::Media::MediaFoundation::{
    IMF2DBuffer, IMFAttributes, IMFMediaType, IMFSample, IMFSourceReader,
    MF_MT_AUDIO_BITS_PER_SAMPLE, MF_MT_AUDIO_NUM_CHANNELS, MF_MT_AUDIO_SAMPLES_PER_SECOND,
    MF_MT_FRAME_SIZE, MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE, MF_MT_VIDEO_ROTATION,
    MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, MF_SOURCE_READER_FIRST_AUDIO_STREAM,
    MF_SOURCE_READER_FIRST_VIDEO_STREAM, MF_SOURCE_READERF_ENDOFSTREAM, MF_VERSION,
    MFAudioFormat_PCM, MFCreateAttributes, MFCreateMediaType, MFCreateSourceReaderFromURL,
    MFMediaType_Audio, MFMediaType_Video, MFSTARTUP_FULL, MFShutdown, MFStartup,
    MFVideoFormat_RGB32,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};
use windows::core::{HSTRING, Interface};

fn err(e: windows::core::Error) -> VideoError {
    VideoError::Unreadable(e.message())
}

/// RGBA `w × h` turned clockwise `turns` quarter turns.
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

/// One sample's picture: RGBA from Media Foundation's BGRX rows.
///
/// # Safety
///
/// `sample` must be a video sample in the reader's RGB32 type, `w × h`.
unsafe fn picture(sample: &IMFSample, w: usize, h: usize) -> Result<Vec<u8>, VideoError> {
    // SAFETY: the buffer is locked around the reads; `Lock2D` gives the
    // first row and the (possibly negative) pitch between rows, each of at
    // least `4 w` bytes.
    unsafe {
        let buffer = sample.ConvertToContiguousBuffer().map_err(err)?;
        let two_d: IMF2DBuffer = buffer.cast().map_err(err)?;
        let mut first: *mut u8 = std::ptr::null_mut();
        let mut pitch = 0i32;
        two_d.Lock2D(&mut first, &mut pitch).map_err(err)?;
        let out = if first.is_null() || (pitch.unsigned_abs() as usize) < 4 * w {
            None
        } else {
            let mut out = Vec::with_capacity(w * h * 4);
            for row in 0..h {
                let line = first.offset(row as isize * pitch as isize);
                for px in std::slice::from_raw_parts(line, 4 * w).chunks_exact(4) {
                    out.extend_from_slice(&[px[2], px[1], px[0], 255]);
                }
            }
            Some(out)
        };
        let _ = two_d.Unlock2D();
        out.ok_or_else(|| VideoError::Unreadable("a picture it can't read".into()))
    }
}

/// One sample's sound: 16-bit little-endian samples.
///
/// # Safety
///
/// `sample` must be an audio sample in the reader's PCM type.
unsafe fn samples(sample: &IMFSample) -> Vec<i16> {
    // SAFETY: the buffer is locked around the copy of its `len` bytes.
    unsafe {
        let Ok(buffer) = sample.ConvertToContiguousBuffer() else {
            return Vec::new();
        };
        let mut data: *mut u8 = std::ptr::null_mut();
        let mut len = 0u32;
        if buffer.Lock(&mut data, None, Some(&mut len)).is_err() || data.is_null() {
            return Vec::new();
        }
        let pcm = std::slice::from_raw_parts(data, len as usize)
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let _ = buffer.Unlock();
        pcm
    }
}

/// Ask the reader for `major`/`subtype` on `stream`, with `extra` set.
///
/// # Safety
///
/// `reader` must be a live source reader.
unsafe fn want(
    reader: &IMFSourceReader,
    stream: u32,
    major: windows::core::GUID,
    subtype: windows::core::GUID,
    extra: &[(windows::core::GUID, u32)],
) -> windows::core::Result<()> {
    // SAFETY: a new media type, filled in and handed to the live reader.
    unsafe {
        let t: IMFMediaType = MFCreateMediaType()?;
        t.SetGUID(&MF_MT_MAJOR_TYPE, &major)?;
        t.SetGUID(&MF_MT_SUBTYPE, &subtype)?;
        for (k, v) in extra {
            t.SetUINT32(k, *v)?;
        }
        reader.SetCurrentMediaType(stream, None, &t)
    }
}

pub(super) fn read(
    path: &std::path::Path,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> Result<(), VideoError> {
    // SAFETY: COM and Media Foundation are started for this thread and
    // stopped at the end; every interface is used while it is alive.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        MFStartup(MF_VERSION, MFSTARTUP_FULL).map_err(|_| VideoError::NoDecoder)?;
        let result = read_started(path, each);
        let _ = MFShutdown();
        result
    }
}

/// [`read`] with Media Foundation started.
///
/// # Safety
///
/// Media Foundation must be started on this thread.
unsafe fn read_started(
    path: &std::path::Path,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> Result<(), VideoError> {
    let video = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;
    let audio = MF_SOURCE_READER_FIRST_AUDIO_STREAM.0 as u32;
    let end = MF_SOURCE_READERF_ENDOFSTREAM.0 as u32;
    // SAFETY: as in `read`.
    unsafe {
        let mut attrs: Option<IMFAttributes> = None;
        MFCreateAttributes(&mut attrs, 1).map_err(err)?;
        let attrs = attrs.ok_or_else(|| VideoError::Unreadable("attributes".into()))?;
        attrs
            .SetUINT32(&MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, 1)
            .map_err(err)?;
        let reader =
            MFCreateSourceReaderFromURL(&HSTRING::from(path.as_os_str()), &attrs).map_err(err)?;
        want(&reader, video, MFMediaType_Video, MFVideoFormat_RGB32, &[])
            .map_err(|_| VideoError::Unreadable("it has no picture Windows can read".into()))?;
        let has_sound = want(
            &reader,
            audio,
            MFMediaType_Audio,
            MFAudioFormat_PCM,
            &[(MF_MT_AUDIO_BITS_PER_SAMPLE, 16)],
        )
        .is_ok();
        let vt = reader.GetCurrentMediaType(video).map_err(err)?;
        let size = vt.GetUINT64(&MF_MT_FRAME_SIZE).map_err(err)?;
        let (w, h) = ((size >> 32) as usize, (size & 0xffff_ffff) as usize);
        if w == 0 || h == 0 {
            return Err(VideoError::Unreadable("no picture size".into()));
        }
        let turns = (vt.GetUINT32(&MF_MT_VIDEO_ROTATION).unwrap_or(0) / 90 % 4) as u8;
        let (tw, th) = if turns % 2 == 1 { (h, w) } else { (w, h) };
        let mut resampler = if has_sound {
            let at = reader.GetCurrentMediaType(audio).map_err(err)?;
            Some(Resampler::new(
                at.GetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND)
                    .unwrap_or(48_000),
                at.GetUINT32(&MF_MT_AUDIO_NUM_CHANNELS).unwrap_or(1) as usize,
            ))
        } else {
            None
        };
        if !each(VideoEvent::Start {
            width: tw as u32,
            height: th as u32,
            duration_ms: 0,
        }) {
            return Err(VideoError::Stopped);
        }
        let mut pacer = Pacer::new();
        let mut sound_at: i64 = 0;
        let mut sound_done = resampler.is_none();
        let mut read_sound =
            |until: i64, each: &mut dyn FnMut(VideoEvent<'_>) -> bool| -> Result<(), VideoError> {
                while !sound_done && sound_at <= until {
                    let (mut flags, mut t, mut s) = (0u32, 0i64, None::<IMFSample>);
                    reader
                        .ReadSample(audio, 0, None, Some(&mut flags), Some(&mut t), Some(&mut s))
                        .map_err(err)?;
                    if let (Some(s), Some(r)) = (&s, resampler.as_mut()) {
                        let pcm = r.push(&samples(s));
                        if !pcm.is_empty() && !each(VideoEvent::Sound(&pcm)) {
                            return Err(VideoError::Stopped);
                        }
                    }
                    sound_at = t;
                    if flags & end != 0 {
                        sound_done = true;
                    }
                }
                Ok(())
            };
        loop {
            let (mut flags, mut t, mut s) = (0u32, 0i64, None::<IMFSample>);
            reader
                .ReadSample(video, 0, None, Some(&mut flags), Some(&mut t), Some(&mut s))
                .map_err(err)?;
            if let Some(s) = &s {
                let (_, _, rgba) = turn(w, h, picture(s, w, h)?, turns);
                // 100 ns units.
                if !pacer.frame(t.max(0) as u64 * 100, rgba, each) {
                    return Err(VideoError::Stopped);
                }
            }
            read_sound(t, each)?;
            if flags & end != 0 {
                break;
            }
        }
        pacer.finish(each);
        read_sound(i64::MAX, each)?;
        Ok(())
    }
}
