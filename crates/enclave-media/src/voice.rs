//! Voice notes (`docs/15-client.md` §5: "Voice notes: Opus").
//!
//! A voice note is Opus in a small fixed-chunk container of our own, so
//! there is no Ogg demuxer to attack:
//!
//! ```text
//! "EVN1" ‖ u32 frames ‖ u16 packet_len ‖ 64 B waveform ‖ frames × packet_len
//! ```
//!
//! Every frame is 20 ms of 48 kHz mono, encoded at a constant 24 kbit/s
//! (`packet_len` = 60), so the size depends only on the duration. The
//! waveform is 64 peak levels (0–255) for the bubble. The sender's audio
//! comes in as a WAV file (any common rate, mono or stereo, 8 or 16 bit),
//! which is resampled and re-encoded: nothing of the original file but its
//! sound leaves the device. The codec is [`crate::opus`] (`opus-pure`, which
//! encodes and decodes).

use crate::{MediaError, Result};

/// Sample rate of every voice note.
pub const RATE: u32 = 48_000;
/// Samples per frame (20 ms).
pub const FRAME: usize = (RATE as usize) / 50;
/// Encoded bit rate.
pub const BITRATE: i32 = 24_000;
/// Longest voice note: 15 minutes.
pub const MAX_FRAMES: u32 = 15 * 60 * 50;
/// Waveform points.
pub const WAVEFORM: usize = 64;
const MAGIC: &[u8; 4] = b"EVN1";
const HEADER: usize = 4 + 4 + 2 + WAVEFORM;

/// What a voice note's header says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceInfo {
    /// Length in milliseconds.
    pub duration_ms: u32,
    /// 64 peak levels, 0 to 255.
    pub waveform: Vec<u8>,
}

/// Mono 16-bit PCM from a WAV file, at its own rate.
fn read_wav(b: &[u8]) -> Result<(Vec<i16>, u32)> {
    let bad = MediaError::Damaged;
    if b.len() < 12 || &b[..4] != b"RIFF" || &b[8..12] != b"WAVE" {
        return Err(MediaError::NotAnImage);
    }
    let mut at = 12;
    let mut fmt: Option<(u16, u16, u32, u16)> = None;
    while at + 8 <= b.len() {
        let id = &b[at..at + 4];
        let len = u32::from_le_bytes(b[at + 4..at + 8].try_into().map_err(|_| bad)?) as usize;
        let body = b.get(at + 8..at + 8 + len).ok_or(bad)?;
        if id == b"fmt " && len >= 16 {
            let u16le = |o: usize| u16::from_le_bytes([body[o], body[o + 1]]);
            let rate = u32::from_le_bytes(body[4..8].try_into().map_err(|_| bad)?);
            fmt = Some((u16le(0), u16le(2), rate, u16le(14)));
        } else if id == b"data" {
            let (format, channels, rate, bits) = fmt.ok_or(bad)?;
            if format != 1 || !(1..=2).contains(&channels) || !(8_000..=96_000).contains(&rate) {
                return Err(MediaError::Unsupported);
            }
            let ch = usize::from(channels);
            let samples: Vec<i16> = match bits {
                16 => body
                    .chunks_exact(2 * ch)
                    .map(|f| {
                        let sum: i32 = f
                            .chunks_exact(2)
                            .map(|s| i32::from(i16::from_le_bytes([s[0], s[1]])))
                            .sum();
                        (sum / ch as i32) as i16
                    })
                    .collect(),
                8 => body
                    .chunks_exact(ch)
                    .map(|f| {
                        let sum: i32 = f.iter().map(|&s| (i32::from(s) - 128) << 8).sum();
                        (sum / ch as i32) as i16
                    })
                    .collect(),
                _ => return Err(MediaError::Unsupported),
            };
            return Ok((samples, rate));
        }
        at += 8 + len + (len & 1);
    }
    Err(bad)
}

/// Linear resampling to [`RATE`].
fn resample(pcm: &[i16], rate: u32) -> Vec<i16> {
    if rate == RATE || pcm.is_empty() {
        return pcm.to_vec();
    }
    let n = (pcm.len() as u64 * u64::from(RATE) / u64::from(rate)) as usize;
    (0..n)
        .map(|i| {
            let pos = i as f64 * f64::from(rate) / f64::from(RATE);
            let j = pos as usize;
            let t = pos - j as f64;
            let a = f64::from(pcm[j.min(pcm.len() - 1)]);
            let b = f64::from(pcm[(j + 1).min(pcm.len() - 1)]);
            (a + (b - a) * t) as i16
        })
        .collect()
}

fn waveform(pcm: &[i16]) -> Vec<u8> {
    let chunk = pcm.len().div_ceil(WAVEFORM).max(1);
    let mut w: Vec<u8> = pcm
        .chunks(chunk)
        .map(|c| {
            let peak = c
                .iter()
                .map(|s| i32::from(*s).unsigned_abs())
                .max()
                .unwrap_or(0);
            (peak * 255 / 32_768) as u8
        })
        .collect();
    w.resize(WAVEFORM, 0);
    w
}

/// A WAV recording as a voice note.
pub fn voice_note_from_wav(wav: &[u8]) -> Result<Vec<u8>> {
    if wav.len() > crate::MAX_INPUT {
        return Err(MediaError::TooLarge);
    }
    let (pcm, rate) = read_wav(wav)?;
    let pcm = resample(&pcm, rate);
    let frames = pcm.len().div_ceil(FRAME);
    if frames == 0 {
        return Err(MediaError::Damaged);
    }
    if frames > MAX_FRAMES as usize {
        return Err(MediaError::TooLarge);
    }
    // Nothing is lost from a file: no FEC.
    let mut enc = crate::opus::Encoder::new(BITRATE, false)?;
    let mut packets = Vec::with_capacity(frames);
    for i in 0..frames {
        let part = &pcm[i * FRAME..((i + 1) * FRAME).min(pcm.len())];
        packets.push(enc.encode(part)?);
    }
    // Constant bit rate: every packet the same size. If the encoder ever
    // differs, pad to the largest (Opus decoders ignore trailing zeros
    // only in padding frames, so refuse instead).
    let len = packets[0].len();
    if packets.iter().any(|p| p.len() != len) || len == 0 || len > u16::MAX as usize {
        return Err(MediaError::Encode);
    }
    let mut b = Vec::with_capacity(HEADER + frames * len);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&(frames as u32).to_be_bytes());
    b.extend_from_slice(&(len as u16).to_be_bytes());
    b.extend_from_slice(&waveform(&pcm));
    for p in &packets {
        b.extend_from_slice(p);
    }
    Ok(b)
}

/// Check a voice note's container and read its header.
pub fn voice_info(b: &[u8]) -> Result<VoiceInfo> {
    let (frames, _, wave, _) = parse(b)?;
    Ok(VoiceInfo {
        duration_ms: frames * 20,
        waveform: wave.to_vec(),
    })
}

fn parse(b: &[u8]) -> Result<(u32, usize, &[u8], &[u8])> {
    let bad = MediaError::Damaged;
    if b.len() < HEADER || &b[..4] != MAGIC {
        return Err(MediaError::NotAnImage);
    }
    let frames = u32::from_be_bytes(b[4..8].try_into().map_err(|_| bad)?);
    let len = usize::from(u16::from_be_bytes([b[8], b[9]]));
    if frames == 0 || frames > MAX_FRAMES || len == 0 || len > 1275 {
        return Err(bad);
    }
    let body = &b[HEADER..];
    if body.len() != frames as usize * len {
        return Err(bad);
    }
    Ok((frames, len, &b[10..HEADER], body))
}

/// Decode a voice note to 48 kHz mono PCM.
pub fn decode_voice(b: &[u8]) -> Result<Vec<i16>> {
    let (frames, len, _, body) = parse(b)?;
    let mut dec = crate::opus::Decoder::new()?;
    let mut pcm = Vec::with_capacity(frames as usize * FRAME);
    for p in body.chunks_exact(len) {
        pcm.extend(dec.decode(p)?);
    }
    Ok(pcm)
}

/// Frames decoded (and thrown away) before a range, so the decoder's
/// state matches the note's at the range's start.
const PREROLL: u32 = 4;
/// Frames in one piece of playback (10 s).
pub const CHUNK_FRAMES: u32 = 500;

/// Decode `count` frames of a voice note from frame `start` (48 kHz mono
/// PCM; empty past the end): playback in pieces.
pub fn decode_voice_range(b: &[u8], start: u32, count: u32) -> Result<Vec<i16>> {
    let (frames, len, _, body) = parse(b)?;
    if start >= frames {
        return Ok(Vec::new());
    }
    let from = start.saturating_sub(PREROLL);
    let end = start.saturating_add(count).min(frames);
    let mut dec = crate::opus::Decoder::new()?;
    let mut pcm = Vec::with_capacity((end - start) as usize * FRAME);
    for (i, p) in body
        .chunks_exact(len)
        .enumerate()
        .skip(from as usize)
        .take((end - from) as usize)
    {
        let out = dec.decode(p)?;
        if i as u32 >= start {
            pcm.extend(out);
        }
    }
    Ok(pcm)
}

/// Ogg's CRC-32 (polynomial 0x04C11DB7, not reflected, no final xor).
fn ogg_crc(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &b in data {
        crc ^= u32::from(b) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04C1_1DB7
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// One Ogg page holding whole `packets`.
fn ogg_page(out: &mut Vec<u8>, seq: u32, granule: u64, flags: u8, packets: &[&[u8]]) {
    /// "ENCL": the only stream.
    const SERIAL: u32 = 0x454e_434c;
    let mut lacing = Vec::new();
    for p in packets {
        lacing.extend(std::iter::repeat_n(255u8, p.len() / 255));
        lacing.push((p.len() % 255) as u8);
    }
    let start = out.len();
    out.extend_from_slice(b"OggS");
    out.push(0);
    out.push(flags);
    out.extend_from_slice(&granule.to_le_bytes());
    out.extend_from_slice(&SERIAL.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.push(lacing.len() as u8);
    out.extend_from_slice(&lacing);
    for p in packets {
        out.extend_from_slice(p);
    }
    let crc = ogg_crc(&out[start..]);
    out[start + 22..start + 26].copy_from_slice(&crc.to_le_bytes());
}

/// A voice note as an Ogg Opus file (RFC 7845), to listen to elsewhere:
/// the note's own Opus packets, so a 15-minute note stays under 3 MB.
pub fn voice_to_ogg(b: &[u8]) -> Result<Vec<u8>> {
    let (_, len, _, body) = parse(b)?;
    let mut out = Vec::with_capacity(body.len() + body.len() / 8 + 256);
    let mut head = b"OpusHead".to_vec();
    head.extend_from_slice(&[1, 1]); // version, mono
    head.extend_from_slice(&0u16.to_le_bytes()); // pre-skip
    head.extend_from_slice(&RATE.to_le_bytes());
    head.extend_from_slice(&0i16.to_le_bytes()); // gain
    head.push(0); // mapping family 0
    ogg_page(&mut out, 0, 0, 0x02, &[&head]);
    let mut tags = b"OpusTags".to_vec();
    tags.extend_from_slice(&7u32.to_le_bytes());
    tags.extend_from_slice(b"Enclave");
    tags.extend_from_slice(&0u32.to_le_bytes());
    ogg_page(&mut out, 1, 0, 0, &[&tags]);
    let packets: Vec<&[u8]> = body.chunks_exact(len).collect();
    let pages = packets.chunks(50).count();
    let mut samples = 0u64;
    for (i, page) in packets.chunks(50).enumerate() {
        samples += (page.len() * FRAME) as u64;
        let flags = if i + 1 == pages { 0x04 } else { 0 };
        ogg_page(&mut out, i as u32 + 2, samples, flags, page);
    }
    Ok(out)
}

/// A voice note as a 16-bit mono WAV file, to listen to elsewhere.
pub fn voice_to_wav(b: &[u8]) -> Result<Vec<u8>> {
    let pcm = decode_voice(b)?;
    let data = pcm.len() * 2;
    let mut w = Vec::with_capacity(44 + data);
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&((36 + data) as u32).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&RATE.to_le_bytes());
    w.extend_from_slice(&(RATE * 2).to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&(data as u32).to_le_bytes());
    for s in pcm {
        w.extend_from_slice(&s.to_le_bytes());
    }
    Ok(w)
}

/// Whether `b` looks like a WAV file.
pub fn is_wav(b: &[u8]) -> bool {
    b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WAVE"
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn wav(rate: u32, channels: u16, secs: f32) -> Vec<u8> {
        let n = (rate as f32 * secs) as usize;
        let mut pcm = Vec::new();
        for i in 0..n {
            let s = ((i as f32 * 440.0 * 2.0 * std::f32::consts::PI / rate as f32).sin() * 9000.0)
                as i16;
            for _ in 0..channels {
                pcm.extend_from_slice(&s.to_le_bytes());
            }
        }
        let mut w = b"RIFF".to_vec();
        w.extend_from_slice(&((36 + pcm.len()) as u32).to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&channels.to_le_bytes());
        w.extend_from_slice(&rate.to_le_bytes());
        w.extend_from_slice(&(rate * 2 * u32::from(channels)).to_le_bytes());
        w.extend_from_slice(&(2 * channels).to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        // A metadata chunk the note must not carry.
        w.extend_from_slice(b"LIST");
        w.extend_from_slice(&12u32.to_le_bytes());
        w.extend_from_slice(b"INFOIART\0\0\0\0");
        w.extend_from_slice(b"data");
        w.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
        w.extend_from_slice(&pcm);
        w
    }

    #[test]
    fn a_wav_becomes_a_voice_note_and_back() {
        let note = voice_note_from_wav(&wav(44_100, 2, 1.5)).unwrap();
        let info = voice_info(&note).unwrap();
        assert_eq!(info.duration_ms, 1500);
        assert_eq!(info.waveform.len(), WAVEFORM);
        assert!(info.waveform[10] > 50, "a loud tone shows in the waveform");
        assert_eq!(
            note.len(),
            HEADER + 75 * 60,
            "constant bit rate: size from duration"
        );
        assert!(!note.windows(4).any(|w| w == b"IART"), "no WAV metadata");
        let pcm = decode_voice(&note).unwrap();
        assert_eq!(pcm.len(), 75 * FRAME);
        let energy =
            |v: &[i16]| v.iter().map(|&s| f64::from(s).powi(2)).sum::<f64>() / v.len() as f64;
        assert!(energy(&pcm[FRAME * 20..]) > 1e7, "the tone survives");
        let back = voice_to_wav(&note).unwrap();
        assert!(is_wav(&back));
        assert_eq!(read_wav(&back).unwrap().0.len(), pcm.len());
    }

    #[test]
    fn played_in_pieces_and_exported_as_ogg_opus() {
        let note = voice_note_from_wav(&wav(48_000, 1, 12.5)).unwrap();
        let whole = decode_voice(&note).unwrap();
        // Pieces: the right lengths, and past the first one's pre-roll the
        // same sound as decoding the whole note.
        let a = decode_voice_range(&note, 0, CHUNK_FRAMES).unwrap();
        let b = decode_voice_range(&note, CHUNK_FRAMES, CHUNK_FRAMES).unwrap();
        assert_eq!(a.len(), CHUNK_FRAMES as usize * FRAME);
        assert_eq!(b.len(), (625 - CHUNK_FRAMES) as usize * FRAME);
        assert!(decode_voice_range(&note, 625, 10).unwrap().is_empty());
        assert_eq!(&a[..], &whole[..a.len()]);
        let diff: f64 = b
            .iter()
            .zip(&whole[a.len()..])
            .map(|(x, y)| (f64::from(*x) - f64::from(*y)).abs())
            .sum::<f64>()
            / b.len() as f64;
        assert!(diff < 50.0, "a piece sounds like the whole ({diff})");
        // Ogg Opus: pages that check out, every packet once, the end marked.
        let ogg = voice_to_ogg(&note).unwrap();
        let (mut at, mut packets, mut last_flags, mut seq) = (0, 0usize, 0u8, 0u32);
        while at < ogg.len() {
            assert_eq!(&ogg[at..at + 4], b"OggS");
            let flags = ogg[at + 5];
            assert_eq!(
                u32::from_le_bytes(ogg[at + 18..at + 22].try_into().unwrap()),
                seq
            );
            let segs = usize::from(ogg[at + 26]);
            let lacing = &ogg[at + 27..at + 27 + segs];
            let body: usize = lacing.iter().map(|l| usize::from(*l)).sum();
            let end = at + 27 + segs + body;
            let mut page = ogg[at..end].to_vec();
            let crc = u32::from_le_bytes(page[22..26].try_into().unwrap());
            page[22..26].fill(0);
            assert_eq!(ogg_crc(&page), crc, "page {seq}'s CRC");
            if seq >= 2 {
                packets += lacing.iter().filter(|l| **l < 255).count();
            }
            last_flags = flags;
            at = end;
            seq += 1;
        }
        assert_eq!(packets, 625);
        assert_eq!(last_flags & 0x04, 0x04, "end of stream");
        assert!(ogg.len() < note.len() + 2_000);
    }

    #[test]
    fn damaged_notes_and_odd_wavs_are_refused() {
        let note = voice_note_from_wav(&wav(16_000, 1, 0.2)).unwrap();
        assert!(voice_info(&note[..note.len() - 1]).is_err(), "truncated");
        let mut huge = note.clone();
        huge[4..8].copy_from_slice(&(MAX_FRAMES + 1).to_be_bytes());
        assert!(voice_info(&huge).is_err());
        let mut fmt = wav(16_000, 1, 0.2);
        fmt[20] = 3; // IEEE float
        assert!(voice_note_from_wav(&fmt).is_err());
        assert!(voice_note_from_wav(b"RIFF\0\0\0\0WAVE").is_err());
        assert!(voice_note_from_wav(b"not a wav").is_err());
    }
}
