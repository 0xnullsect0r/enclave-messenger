//! `enclave-mediad`: the program ([`main_with`]; `src/main.rs` runs it).
//!
//! Started by the vault, never by hand. Decodes and re-encodes pictures
//! (`enclave-media`) for the vault over its stdin and stdout
//! (`enclave-ipc::media`). It holds no keys and sees only the pictures
//! themselves. It confines itself before reading anything: no core dumps,
//! not dumpable, `no_new_privs`, a 2 GiB address-space cap, and (Linux) no
//! filesystem, no TCP (Landlock) and no sockets, programs or debugging
//! (seccomp). A decoder bug here can crash this process; the vault then
//! shows the file without a preview.
#![forbid(unsafe_code)]

use enclave_ipc::frame;
use enclave_ipc::media::{MediaOp, MediaOut, MediaReply, MediaRequest};
use std::io::{Read, Write};
use std::process::ExitCode;

/// Address-space cap: a 25-megapixel picture plus shrinking buffers.
#[cfg(not(target_os = "wasi"))]
const MEMORY_LIMIT: u64 = 2 << 30;

/// Calls' audio and video state, by the vault's number for each.
#[derive(Default)]
struct Calls {
    audio: std::collections::HashMap<u32, enclave_media::call::CallAudio>,
    video: std::collections::HashMap<
        u32,
        (
            enclave_media::callvideo::VideoEncoder,
            enclave_media::callvideo::VideoDecoder,
        ),
    >,
    /// A group call's video decoders, one per other participant.
    from: std::collections::HashMap<(u32, u32), enclave_media::callvideo::VideoDecoder>,
}

/// Most calls at once.
const MAX_CALLS: usize = 4;

/// PCM as 16-bit little-endian bytes and back.
fn pcm_bytes(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().flat_map(|s| s.to_le_bytes()).collect()
}

fn bytes_pcm(b: &[u8]) -> Vec<i16> {
    b.chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// A [`MediaOp::CallMix`]'s frames: `count ‖ (u32 sender ‖ u8 how ‖ u16
/// len ‖ frame)…`.
fn mix_frames(b: &[u8]) -> Option<Vec<(u32, enclave_ipc::media::CallDecode, &[u8])>> {
    use enclave_ipc::media::CallDecode;
    let (&count, mut rest) = b.split_first()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let (head, more) = rest.split_at_checked(7)?;
        let sender = u32::from_be_bytes(head[..4].try_into().ok()?);
        let how = match head[4] {
            0 => CallDecode::Packet,
            1 => CallDecode::Recover,
            2 => CallDecode::Lost,
            _ => return None,
        };
        let len = usize::from(u16::from_be_bytes([head[5], head[6]]));
        let (frame, more) = more.split_at_checked(len)?;
        out.push((sender, how, frame));
        rest = more;
    }
    rest.is_empty().then_some(out)
}

fn call_op(op: MediaOp, bytes: &[u8], calls: &mut Calls) -> enclave_media::Result<MediaOut> {
    use enclave_ipc::media::CallDecode;
    use enclave_media::MediaError;
    use enclave_media::call::{CallAudio, Decode, FRAME};
    let missing = MediaError::Unsupported;
    match op {
        MediaOp::CallOpen(n) => {
            if calls.audio.len() >= MAX_CALLS && !calls.audio.contains_key(&n) {
                return Err(MediaError::TooLarge);
            }
            calls.audio.insert(n, CallAudio::new()?);
            Ok(MediaOut::Raw(Vec::new()))
        }
        MediaOp::VideoOpen(n, tier) => {
            use enclave_media::callvideo::{VideoDecoder, VideoEncoder};
            if calls.video.len() >= MAX_CALLS && !calls.video.contains_key(&n) {
                return Err(MediaError::TooLarge);
            }
            let codec = (VideoEncoder::new(usize::from(tier))?, VideoDecoder::new()?);
            calls.video.insert(n, codec);
            Ok(MediaOut::Raw(Vec::new()))
        }
        MediaOp::VideoEncode(n, key) => {
            let (enc, _) = calls.video.get_mut(&n).ok_or(missing)?;
            let units = enc.encode(bytes, key)?;
            let mut out = Vec::new();
            for u in units {
                out.extend_from_slice(&(u.len() as u32).to_be_bytes());
                out.extend_from_slice(&u);
            }
            Ok(MediaOut::Raw(out))
        }
        MediaOp::VideoDecode(n) => {
            let (_, dec) = calls.video.get_mut(&n).ok_or(missing)?;
            Ok(match dec.decode(bytes)? {
                Some(img) => MediaOut::Rgba {
                    width: img.width,
                    height: img.height,
                    pixels: img.pixels,
                },
                None => MediaOut::Raw(Vec::new()),
            })
        }
        MediaOp::VideoScreen(n, tier, on) => {
            use enclave_media::callvideo::VideoEncoder;
            let (enc, _) = calls.video.get_mut(&n).ok_or(missing)?;
            *enc = if on {
                VideoEncoder::screen(usize::from(tier))?
            } else {
                VideoEncoder::new(usize::from(tier))?
            };
            Ok(MediaOut::Raw(Vec::new()))
        }
        MediaOp::VideoClose(n) => {
            calls.video.remove(&n);
            calls.from.retain(|(c, _), _| *c != n);
            Ok(MediaOut::Raw(Vec::new()))
        }
        MediaOp::VideoDecodeFrom(n, sender) => {
            use enclave_media::callvideo::VideoDecoder;
            if !calls.video.contains_key(&n) {
                return Err(missing);
            }
            if !calls.from.contains_key(&(n, sender)) {
                let count = calls.from.keys().filter(|(c, _)| *c == n).count();
                if count >= enclave_media::call::MAX_SENDERS {
                    return Err(MediaError::TooLarge);
                }
                calls.from.insert((n, sender), VideoDecoder::new()?);
            }
            let dec = calls.from.get_mut(&(n, sender)).ok_or(missing)?;
            Ok(match dec.decode(bytes)? {
                Some(img) => MediaOut::Rgba {
                    width: img.width,
                    height: img.height,
                    pixels: img.pixels,
                },
                None => MediaOut::Raw(Vec::new()),
            })
        }
        MediaOp::CallMix(n) => {
            let c = calls.audio.get_mut(&n).ok_or(missing)?;
            let frames = mix_frames(bytes).ok_or(MediaError::Damaged)?;
            let what: Vec<(u32, Decode<'_>)> = frames
                .iter()
                .map(|(s, how, b)| {
                    (
                        *s,
                        match how {
                            CallDecode::Packet => Decode::Packet(b),
                            CallDecode::Recover => Decode::Recover(b),
                            CallDecode::Lost => Decode::Lost,
                        },
                    )
                })
                .collect();
            c.mix(&what).map(|pcm| MediaOut::Raw(pcm_bytes(&pcm)))
        }
        MediaOp::CallEncode(n) => {
            if bytes.len() > FRAME * 2 {
                return Err(MediaError::TooLarge);
            }
            let c = calls.audio.get_mut(&n).ok_or(missing)?;
            c.encode(&bytes_pcm(bytes)).map(MediaOut::Raw)
        }
        MediaOp::CallDecode(n, how) => {
            let c = calls.audio.get_mut(&n).ok_or(missing)?;
            let what = match how {
                CallDecode::Packet => Decode::Packet(bytes),
                CallDecode::Recover => Decode::Recover(bytes),
                CallDecode::Lost => Decode::Lost,
            };
            c.decode(what).map(|pcm| MediaOut::Raw(pcm_bytes(&pcm)))
        }
        MediaOp::CallClose(n) => {
            calls.audio.remove(&n);
            Ok(MediaOut::Raw(Vec::new()))
        }
        _ => Err(missing),
    }
}

fn handle(req: MediaRequest, calls: &mut Calls) -> MediaReply {
    let result = match req.op {
        MediaOp::CallOpen(_)
        | MediaOp::CallEncode(_)
        | MediaOp::CallDecode(..)
        | MediaOp::CallClose(_)
        | MediaOp::VideoOpen(..)
        | MediaOp::VideoEncode(..)
        | MediaOp::VideoDecode(_)
        | MediaOp::VideoClose(_)
        | MediaOp::CallMix(_)
        | MediaOp::VideoDecodeFrom(..)
        | MediaOp::VideoScreen(..) => call_op(req.op, &req.bytes, calls),
        MediaOp::Sanitize => enclave_media::sanitize(&req.bytes).map(|s| MediaOut::Sanitized {
            png: s.format == enclave_media::Format::Png,
            width: s.width,
            height: s.height,
            bytes: s.bytes,
        }),
        MediaOp::VoiceNote => {
            enclave_media::voice::voice_note_from_wav(&req.bytes).and_then(|note| {
                let info = enclave_media::voice::voice_info(&note)?;
                Ok(MediaOut::Audio {
                    duration_ms: info.duration_ms,
                    waveform: info.waveform,
                    bytes: note,
                })
            })
        }
        MediaOp::VoiceInfo => {
            enclave_media::voice::voice_info(&req.bytes).map(|i| MediaOut::Audio {
                duration_ms: i.duration_ms,
                waveform: i.waveform,
                bytes: Vec::new(),
            })
        }
        MediaOp::VoiceWav => enclave_media::voice::voice_info(&req.bytes).and_then(|i| {
            Ok(MediaOut::Audio {
                duration_ms: i.duration_ms,
                waveform: i.waveform,
                bytes: enclave_media::voice::voice_to_wav(&req.bytes)?,
            })
        }),
        MediaOp::Shrink(side) => {
            enclave_media::sanitize_max(&req.bytes, u32::from(side)).map(|s| MediaOut::Sanitized {
                png: s.format == enclave_media::Format::Png,
                width: s.width,
                height: s.height,
                bytes: s.bytes,
            })
        }
        MediaOp::Thumbnail(side) => {
            enclave_media::thumbnail(&req.bytes, u32::from(side)).map(|t| MediaOut::Rgba {
                width: t.width,
                height: t.height,
                pixels: t.pixels,
            })
        }
        MediaOp::Clip => enclave_media::video::clip_from_gif(&req.bytes).map(|c| MediaOut::Clip {
            width: c.width,
            height: c.height,
            duration_ms: c.duration_ms,
            bytes: c.bytes,
            frames: Vec::new(),
        }),
        MediaOp::ClipPoster(side) => enclave_media::video::clip_poster(&req.bytes, u32::from(side))
            .map(|(img, ms)| MediaOut::Clip {
                width: img.width,
                height: img.height,
                duration_ms: ms,
                bytes: Vec::new(),
                frames: vec![img.pixels],
            }),
        MediaOp::ClipFrames(side) => {
            let ms = enclave_media::video::parse_clip(&req.bytes).map(|i| i.duration_ms);
            ms.and_then(|ms| {
                let frames = enclave_media::video::clip_frames(
                    &req.bytes,
                    u32::from(side),
                    enclave_ipc::media::MAX_CLIP_FRAMES,
                )?;
                let (width, height) = frames.first().map_or((0, 0), |f| (f.width, f.height));
                Ok(MediaOut::Clip {
                    width,
                    height,
                    duration_ms: ms,
                    bytes: Vec::new(),
                    frames: frames.into_iter().map(|f| f.pixels).collect(),
                })
            })
        }
    };
    MediaReply {
        id: req.id,
        result: result.map_err(|e| e.to_string()),
    }
}

/// Blocking framing (`u32 BE length ‖ body`, as `enclave_ipc::frame`).
fn read_frame(r: &mut impl Read) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let n = u32::from_be_bytes(len) as usize;
    if n > frame::MAX_FRAME {
        return None;
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).ok()?;
    Some(body)
}

fn write_frame(w: &mut impl Write, body: &[u8]) -> bool {
    w.write_all(&(body.len() as u32).to_be_bytes()).is_ok()
        && w.write_all(body).is_ok()
        && w.flush().is_ok()
}

/// The program, given its arguments (none). As a thread of the app
/// (Android, iOS; `enclave_platform::process`) it leaves confining the
/// process alone and talks over the pipes it was given.
#[cfg(not(target_os = "wasi"))]
pub fn main_with(_args: Vec<String>) -> ExitCode {
    if !enclave_platform::process::in_process() {
        let _ = enclave_sandbox::process();
        let _ = enclave_sandbox::memory_limit(MEMORY_LIMIT);
        let _ = enclave_sandbox::filesystem(&[], &[], true);
        let _ = enclave_sandbox::syscalls(enclave_sandbox::Profile::Media, false);
    }
    let Ok(io) = enclave_platform::process::stdio() else {
        return ExitCode::FAILURE;
    };
    serve(io.input, io.output)
}

/// In WebAssembly (`enclave-wasmbox`): standard input and output are the
/// host's pipes, and the interpreter is the confinement.
#[cfg(target_os = "wasi")]
pub fn main_with(_args: Vec<String>) -> ExitCode {
    serve(std::io::stdin(), std::io::stdout())
}

/// Answer requests from `input` on `output` until `input` closes.
fn serve(input: impl Read, output: impl Write) -> ExitCode {
    let mut stdin = std::io::BufReader::new(input);
    let mut stdout = std::io::BufWriter::new(output);
    // One request at a time: pictures are decoded in order.
    let mut calls = Calls::default();
    while let Some(body) = read_frame(&mut stdin) {
        let Ok(req) = MediaRequest::decode(&body) else {
            break;
        };
        if !write_frame(&mut stdout, &handle(req, &mut calls).encode()) {
            break;
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use enclave_ipc::media::CallDecode;

    fn ask(op: MediaOp, bytes: Vec<u8>, calls: &mut Calls) -> Result<MediaOut, String> {
        handle(MediaRequest { id: 1, op, bytes }, calls).result
    }

    #[test]
    fn calls_keep_their_codec_state() {
        let mut calls = Calls::default();
        assert!(ask(MediaOp::CallEncode(7), vec![0; 1920], &mut calls).is_err());
        ask(MediaOp::CallOpen(7), Vec::new(), &mut calls).unwrap();
        let mic: Vec<u8> = (0..960i16)
            .flat_map(|i| ((i % 48) * 300).to_le_bytes())
            .collect();
        let Ok(MediaOut::Raw(frame)) = ask(MediaOp::CallEncode(7), mic, &mut calls) else {
            panic!()
        };
        assert!(!frame.is_empty() && frame.len() <= 100);
        let Ok(MediaOut::Raw(pcm)) = ask(
            MediaOp::CallDecode(7, CallDecode::Packet),
            frame,
            &mut calls,
        ) else {
            panic!()
        };
        assert_eq!(pcm.len(), 1920);
        let Ok(MediaOut::Raw(pcm)) = ask(
            MediaOp::CallDecode(7, CallDecode::Lost),
            Vec::new(),
            &mut calls,
        ) else {
            panic!()
        };
        assert_eq!(pcm.len(), 1920);
        assert!(ask(MediaOp::CallEncode(7), vec![0; 4000], &mut calls).is_err());
        for n in 8..11 {
            ask(MediaOp::CallOpen(n), Vec::new(), &mut calls).unwrap();
        }
        assert!(ask(MediaOp::CallOpen(11), Vec::new(), &mut calls).is_err());
        ask(MediaOp::CallClose(7), Vec::new(), &mut calls).unwrap();
        assert!(ask(MediaOp::CallEncode(7), vec![0; 1920], &mut calls).is_err());
        ask(MediaOp::CallOpen(11), Vec::new(), &mut calls).unwrap();
    }
}
