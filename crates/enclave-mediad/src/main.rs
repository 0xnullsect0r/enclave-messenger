//! `enclave-mediad`
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
const MEMORY_LIMIT: u64 = 2 << 30;

fn handle(req: MediaRequest) -> MediaReply {
    let result = match req.op {
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

fn main() -> ExitCode {
    let _ = enclave_sandbox::process();
    let _ = enclave_sandbox::memory_limit(MEMORY_LIMIT);
    let _ = enclave_sandbox::filesystem(&[], &[], true);
    let _ = enclave_sandbox::syscalls(enclave_sandbox::Profile::Media, false);
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    // One request at a time: pictures are decoded in order.
    while let Some(body) = read_frame(&mut stdin) {
        let Ok(req) = MediaRequest::decode(&body) else {
            break;
        };
        if !write_frame(&mut stdout, &handle(req).encode()) {
            break;
        }
    }
    ExitCode::SUCCESS
}
