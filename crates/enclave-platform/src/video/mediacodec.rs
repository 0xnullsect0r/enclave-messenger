//! Android: MediaExtractor and MediaCodec, the system's own decoders,
//! through the app's `VideoReader` (Java; `apps/android`). Frames come as
//! I420, made RGBA and turned here; sound as 16-bit PCM at the file's rate
//! and channels, made 48 kHz mono here.

use super::{Pacer, Resampler, VideoError, VideoEvent};
use jni::objects::{JByteArray, JObject, JShortArray, JValue};

/// RGBA from BT.601 limited-range I420.
fn rgba(w: usize, h: usize, i420: &[u8]) -> Option<Vec<u8>> {
    let (cw, ch) = (w / 2, h / 2);
    if i420.len() < w * h + 2 * cw * ch {
        return None;
    }
    let (y, rest) = i420.split_at(w * h);
    let (u, v) = rest.split_at(cw * ch);
    let mut out = Vec::with_capacity(w * h * 4);
    for row in 0..h {
        for col in 0..w {
            let yy = 1.164 * (f32::from(y[row * w + col]) - 16.0);
            let c = (row / 2).min(ch.saturating_sub(1)) * cw + (col / 2).min(cw.saturating_sub(1));
            let (uu, vv) = (f32::from(u[c]) - 128.0, f32::from(v[c]) - 128.0);
            let px = |f: f32| f.round().clamp(0.0, 255.0) as u8;
            out.extend_from_slice(&[
                px(yy + 1.596 * vv),
                px(yy - 0.392 * uu - 0.813 * vv),
                px(yy + 2.017 * uu),
                255,
            ]);
        }
    }
    Some(out)
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

pub(super) fn read(
    path: &std::path::Path,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> Result<(), VideoError> {
    let path = path
        .to_str()
        .ok_or_else(|| VideoError::Unreadable("the file's name".into()))?
        .to_string();
    crate::jvm::with(|env, activity| {
        let jpath = env.new_string(&path)?;
        let reader = env
            .call_method(
                activity,
                "openVideo",
                "(Ljava/lang/String;)Lcom/aricummings/enclave/VideoReader;",
                &[JValue::Object(&jpath)],
            )?
            .l()?;
        if reader.is_null() {
            return Ok(Err(VideoError::Unreadable("Android can't read it".into())));
        }
        let result = pump(env, &reader, each);
        let _ = env.call_method(&reader, "close", "()V", &[]);
        Ok(result.unwrap_or_else(|e| Err(VideoError::Unreadable(e.to_string()))))
    })
    .unwrap_or(Err(VideoError::NoDecoder))
}

fn pump(
    env: &mut jni::JNIEnv<'_>,
    reader: &JObject<'_>,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> jni::errors::Result<Result<(), VideoError>> {
    let int = |env: &mut jni::JNIEnv<'_>, m: &str| -> jni::errors::Result<i32> {
        env.call_method(reader, m, "()I", &[])?.i()
    };
    let turns = (int(env, "rotation")?.rem_euclid(360) / 90) as u8;
    let duration_ms = env
        .call_method(reader, "durationMs", "()J", &[])?
        .j()?
        .max(0) as u64;
    let mut pacer = Pacer::new();
    let mut started = false;
    let mut resampler: Option<Resampler> = None;
    loop {
        let more = env.with_local_frame(
            8,
            |env| -> jni::errors::Result<Option<Result<(), VideoError>>> {
                if !env.call_method(reader, "next", "()Z", &[])?.z()? {
                    return Ok(None);
                }
                let (w, h) = (int(env, "width")? as usize, int(env, "height")? as usize);
                let bytes = JByteArray::from(env.call_method(reader, "frame", "()[B", &[])?.l()?);
                let i420 = env.convert_byte_array(&bytes)?;
                let us = env.call_method(reader, "frameUs", "()J", &[])?.j()?.max(0) as u64;
                let Some(px) = rgba(w, h, &i420) else {
                    return Ok(Some(Err(VideoError::Unreadable(
                        "a picture it can't read".into(),
                    ))));
                };
                let (tw, th, px) = turn(w, h, px, turns);
                if !started {
                    started = true;
                    if !each(VideoEvent::Start {
                        width: tw as u32,
                        height: th as u32,
                        duration_ms,
                    }) {
                        return Ok(Some(Err(VideoError::Stopped)));
                    }
                }
                if !pacer.frame(us * 1000, px, each) {
                    return Ok(Some(Err(VideoError::Stopped)));
                }
                if !sound(env, reader, &mut resampler, each)? {
                    return Ok(Some(Err(VideoError::Stopped)));
                }
                Ok(Some(Ok(())))
            },
        )?;
        match more {
            None => break,
            Some(Err(e)) => return Ok(Err(e)),
            Some(Ok(())) => {}
        }
    }
    if !started {
        return Ok(Err(VideoError::Unreadable("it has no picture".into())));
    }
    pacer.finish(each);
    env.with_local_frame(8, |env| sound(env, reader, &mut resampler, each))?;
    Ok(Ok(()))
}

/// The sound decoded so far, to `each`; false when it says stop.
fn sound(
    env: &mut jni::JNIEnv<'_>,
    reader: &JObject<'_>,
    resampler: &mut Option<Resampler>,
    each: &mut dyn FnMut(VideoEvent<'_>) -> bool,
) -> jni::errors::Result<bool> {
    let arr = JShortArray::from(env.call_method(reader, "sound", "()[S", &[])?.l()?);
    let n = env.get_array_length(&arr)? as usize;
    if n == 0 {
        return Ok(true);
    }
    let mut pcm = vec![0i16; n];
    env.get_short_array_region(&arr, 0, &mut pcm)?;
    let rate = env
        .call_method(reader, "soundRate", "()I", &[])?
        .i()?
        .max(1) as u32;
    let channels = env
        .call_method(reader, "soundChannels", "()I", &[])?
        .i()?
        .max(1) as usize;
    let r = resampler.get_or_insert_with(|| Resampler::new(rate, channels));
    let out = r.push(&pcm);
    Ok(out.is_empty() || each(VideoEvent::Sound(&out)))
}
