//! Messages between the vault and `mediad` (`docs/15-client.md` §1.1a).
//!
//! `mediad` holds no keys: the vault hands it the bytes of a picture (one
//! the person is sending, or a decrypted attachment) and gets back a
//! re-encoded file or raw RGBA pixels.

use crate::codec::{MAX_BYTES, Reader, Writer};
use crate::{IpcError, Result};

/// Most clip frames in one reply.
pub const MAX_CLIP_FRAMES: usize = 64;

/// What to do with the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaOp {
    /// Re-encode a picture for sending (metadata stripped, shrunk).
    Sanitize,
    /// Decode and shrink to at most this many pixels on the long side.
    Thumbnail(u16),
    /// Re-encode like `Sanitize`, at most this many pixels on the long
    /// side (stickers).
    Shrink(u16),
    /// A WAV recording to a voice note.
    VoiceNote,
    /// Check a voice note and read its duration and waveform.
    VoiceInfo,
    /// A voice note as a WAV file.
    VoiceWav,
    /// An animated GIF (ours) to an AV1 clip.
    Clip,
    /// A clip's poster, shrunk to at most this many pixels (no AV1 decoding).
    ClipPoster(u16),
    /// A clip's frames for playing, shrunk to at most this many pixels.
    ClipFrames(u16),
    /// Start a call's audio (`enclave_media::call`) with this number.
    CallOpen(u32),
    /// A call's next 20 ms from the microphone (16-bit little-endian PCM,
    /// 48 kHz mono) to an Opus frame ([`MediaOut::Raw`]).
    CallEncode(u32),
    /// A call's next 20 ms to play ([`MediaOut::Raw`], PCM as above) from
    /// the other person's frame ([`CallDecode::Packet`]), the next one's
    /// forward error correction (`Recover`), or nothing (`Lost`; empty
    /// bytes).
    CallDecode(u32, CallDecode),
    /// End a call's audio.
    CallClose(u32),
    /// Start a call's video with this number at a tier
    /// (`enclave_media::callvideo::TIERS`).
    VideoOpen(u32, u8),
    /// Encode one camera frame (RGBA at the tier's size), as a key frame
    /// or not: the temporal units that came out, each `u32 length ‖
    /// bytes`, in [`MediaOut::Raw`].
    VideoEncode(u32, bool),
    /// Decode one temporal unit: the picture ([`MediaOut::Rgba`]) or
    /// nothing yet (an empty [`MediaOut::Raw`]).
    VideoDecode(u32),
    /// End a call's video.
    VideoClose(u32),
    /// A group call's next 20 ms ([`MediaOut::Raw`], PCM as above): each
    /// other participant's frame, decoded by its own decoder, mixed. The
    /// bytes are `count ‖ (u32 sender ‖ u8 how ‖ u16 len ‖ frame)…`, `how`
    /// as [`CallDecode`].
    CallMix(u32),
    /// Decode one temporal unit from one participant of a group call (its
    /// own decoder), as [`MediaOp::VideoDecode`].
    VideoDecodeFrom(u32, u32),
    /// Switch a call's encoder, at its tier, to a shared screen (true;
    /// `enclave_media::callvideo::screen`) or back to the camera.
    VideoScreen(u32, u8, bool),
}

/// How [`MediaOp::CallDecode`] uses its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallDecode {
    /// This frame arrived.
    Packet,
    /// It was lost; these are the next frame's.
    Recover,
    /// It was lost.
    Lost,
}

/// Vault → mediad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaRequest {
    /// Request number.
    pub id: u32,
    /// Operation.
    pub op: MediaOp,
    /// The picture.
    pub bytes: Vec<u8>,
}

/// A successful result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaOut {
    /// A new file: JPEG (`png` false) or PNG.
    Sanitized {
        /// PNG rather than JPEG.
        png: bool,
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// The file.
        bytes: Vec<u8>,
    },
    /// Audio: a file (voice note or WAV; empty for `VoiceInfo`), its
    /// duration and a 64-point waveform.
    Audio {
        /// Milliseconds.
        duration_ms: u32,
        /// Peak levels, 0 to 255.
        waveform: Vec<u8>,
        /// The file.
        bytes: Vec<u8>,
    },
    /// A clip (`Clip`; `frames` empty) or decoded frames (`ClipPoster`,
    /// `ClipFrames`; `bytes` empty), all `width × height` RGBA.
    Clip {
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// Length of the clip.
        duration_ms: u32,
        /// The clip file.
        bytes: Vec<u8>,
        /// Frames, evenly spaced over the clip.
        frames: Vec<Vec<u8>>,
    },
    /// Bytes as they are (call audio; empty when there is nothing to
    /// say).
    Raw(Vec<u8>),
    /// 8-bit RGBA pixels.
    Rgba {
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// `width × height × 4` bytes.
        pixels: Vec<u8>,
    },
}

/// mediad → vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaReply {
    /// The request it answers.
    pub id: u32,
    /// The result, or why there is none.
    pub result: core::result::Result<MediaOut, String>,
}

impl MediaRequest {
    /// Encode (`bytes` must fit [`MAX_BYTES`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.id);
        match self.op {
            MediaOp::Sanitize => w.u8(1),
            MediaOp::Thumbnail(side) => w.u8(2).u32(u32::from(side)),
            MediaOp::Shrink(side) => w.u8(3).u32(u32::from(side)),
            MediaOp::VoiceNote => w.u8(4),
            MediaOp::VoiceInfo => w.u8(5),
            MediaOp::VoiceWav => w.u8(6),
            MediaOp::Clip => w.u8(7),
            MediaOp::ClipPoster(side) => w.u8(8).u32(u32::from(side)),
            MediaOp::ClipFrames(side) => w.u8(9).u32(u32::from(side)),
            MediaOp::CallOpen(n) => w.u8(10).u32(n),
            MediaOp::CallEncode(n) => w.u8(11).u32(n),
            MediaOp::CallDecode(n, how) => w.u8(12).u32(n).u8(match how {
                CallDecode::Packet => 0,
                CallDecode::Recover => 1,
                CallDecode::Lost => 2,
            }),
            MediaOp::CallClose(n) => w.u8(13).u32(n),
            MediaOp::VideoOpen(n, tier) => w.u8(14).u32(n).u8(tier),
            MediaOp::VideoEncode(n, key) => w.u8(15).u32(n).bool(key),
            MediaOp::VideoDecode(n) => w.u8(16).u32(n),
            MediaOp::VideoClose(n) => w.u8(17).u32(n),
            MediaOp::CallMix(n) => w.u8(18).u32(n),
            MediaOp::VideoDecodeFrom(n, sender) => w.u8(19).u32(n).u32(sender),
            MediaOp::VideoScreen(n, tier, on) => w.u8(20).u32(n).u8(tier).bool(on),
        };
        w.bytes(&self.bytes[..self.bytes.len().min(MAX_BYTES)]);
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let id = r.u32()?;
        let op = match r.u8()? {
            1 => MediaOp::Sanitize,
            2 => MediaOp::Thumbnail(u16::try_from(r.u32()?).map_err(|_| IpcError::Malformed)?),
            3 => MediaOp::Shrink(u16::try_from(r.u32()?).map_err(|_| IpcError::Malformed)?),
            4 => MediaOp::VoiceNote,
            5 => MediaOp::VoiceInfo,
            6 => MediaOp::VoiceWav,
            7 => MediaOp::Clip,
            8 => MediaOp::ClipPoster(u16::try_from(r.u32()?).map_err(|_| IpcError::Malformed)?),
            9 => MediaOp::ClipFrames(u16::try_from(r.u32()?).map_err(|_| IpcError::Malformed)?),
            10 => MediaOp::CallOpen(r.u32()?),
            11 => MediaOp::CallEncode(r.u32()?),
            12 => {
                let n = r.u32()?;
                MediaOp::CallDecode(
                    n,
                    match r.u8()? {
                        0 => CallDecode::Packet,
                        1 => CallDecode::Recover,
                        2 => CallDecode::Lost,
                        _ => return Err(IpcError::Malformed),
                    },
                )
            }
            13 => MediaOp::CallClose(r.u32()?),
            14 => {
                let n = r.u32()?;
                MediaOp::VideoOpen(n, r.u8()?)
            }
            15 => {
                let n = r.u32()?;
                MediaOp::VideoEncode(n, r.bool()?)
            }
            16 => MediaOp::VideoDecode(r.u32()?),
            17 => MediaOp::VideoClose(r.u32()?),
            18 => MediaOp::CallMix(r.u32()?),
            19 => {
                let n = r.u32()?;
                MediaOp::VideoDecodeFrom(n, r.u32()?)
            }
            20 => {
                let n = r.u32()?;
                let tier = r.u8()?;
                MediaOp::VideoScreen(n, tier, r.bool()?)
            }
            _ => return Err(IpcError::Malformed),
        };
        let bytes = r.bytes()?;
        r.end()?;
        Ok(Self { id, op, bytes })
    }
}

impl MediaReply {
    /// Encode. A result over [`MAX_BYTES`] becomes an error.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.id);
        match &self.result {
            Ok(MediaOut::Sanitized {
                png,
                width,
                height,
                bytes,
            }) if bytes.len() <= MAX_BYTES => {
                w.u8(1).bool(*png).u32(*width).u32(*height).bytes(bytes);
            }
            Ok(MediaOut::Rgba {
                width,
                height,
                pixels,
            }) if pixels.len() <= MAX_BYTES => {
                w.u8(2).u32(*width).u32(*height).bytes(pixels);
            }
            Ok(MediaOut::Audio {
                duration_ms,
                waveform,
                bytes,
            }) if bytes.len() <= MAX_BYTES && waveform.len() <= 64 => {
                w.u8(3).u32(*duration_ms).bytes(waveform).bytes(bytes);
            }
            Ok(MediaOut::Clip {
                width,
                height,
                duration_ms,
                bytes,
                frames,
            }) if bytes.len() + frames.iter().map(Vec::len).sum::<usize>() <= MAX_BYTES
                && frames.len() <= MAX_CLIP_FRAMES =>
            {
                w.u8(4)
                    .u32(*width)
                    .u32(*height)
                    .u32(*duration_ms)
                    .bytes(bytes)
                    .u32(frames.len() as u32);
                for f in frames {
                    w.bytes(f);
                }
            }
            Ok(MediaOut::Raw(bytes)) if bytes.len() <= MAX_BYTES => {
                w.u8(5).bytes(bytes);
            }
            Ok(_) => {
                w.u8(0).str("too large");
            }
            Err(e) => {
                w.u8(0).str(e);
            }
        }
        w.0
    }

    /// Decode. RGBA must be exactly `width × height × 4` bytes.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let id = r.u32()?;
        let result = match r.u8()? {
            0 => Err(r.str()?),
            1 => Ok(MediaOut::Sanitized {
                png: r.bool()?,
                width: r.u32()?,
                height: r.u32()?,
                bytes: r.bytes()?,
            }),
            2 => {
                let (width, height) = (r.u32()?, r.u32()?);
                let pixels = r.bytes()?;
                if crate::rgba_len(width, height) != Some(pixels.len()) {
                    return Err(IpcError::Malformed);
                }
                Ok(MediaOut::Rgba {
                    width,
                    height,
                    pixels,
                })
            }
            3 => {
                let duration_ms = r.u32()?;
                let waveform = r.bytes()?;
                if waveform.len() > 64 {
                    return Err(IpcError::Malformed);
                }
                Ok(MediaOut::Audio {
                    duration_ms,
                    waveform,
                    bytes: r.bytes()?,
                })
            }
            4 => {
                let (width, height, duration_ms) = (r.u32()?, r.u32()?, r.u32()?);
                let bytes = r.bytes()?;
                let n = r.u32()? as usize;
                if n > MAX_CLIP_FRAMES {
                    return Err(IpcError::Malformed);
                }
                let mut frames = Vec::with_capacity(n);
                for _ in 0..n {
                    let f = r.bytes()?;
                    if crate::rgba_len(width, height) != Some(f.len()) {
                        return Err(IpcError::Malformed);
                    }
                    frames.push(f);
                }
                Ok(MediaOut::Clip {
                    width,
                    height,
                    duration_ms,
                    bytes,
                    frames,
                })
            }
            5 => Ok(MediaOut::Raw(r.bytes()?)),
            _ => return Err(IpcError::Malformed),
        };
        r.end()?;
        Ok(Self { id, result })
    }
}
