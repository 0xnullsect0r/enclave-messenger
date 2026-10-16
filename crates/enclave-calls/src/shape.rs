//! Constant-rate traffic shaping (`docs/11-calls.md` §6, RT-19).
//!
//! A stream has a fixed packet size and a fixed rate chosen at call start.
//! Each tick emits exactly one packet whether or not there is media: real
//! frames, fragments of larger frames, control messages and padding all
//! produce plaintexts of the same length, which SFrame turns into packets of
//! the same length. Muting or turning the camera off changes nothing on the
//! wire. Quality only steps down, at most once per 30 s.

use crate::sframe::OVERHEAD;
use crate::{CallError, Result};
use std::collections::VecDeque;

/// Audio packet size on the wire (before the link layer).
pub const AUDIO_PACKET: usize = 160;
/// Audio packets per second (20 ms Opus frames).
pub const AUDIO_PPS: u32 = 50;
/// Video packet size.
pub const VIDEO_PACKET: usize = 1200;
/// Video tiers in kbit/s.
pub const VIDEO_TIERS: [u32; 3] = [300, 800, 1500];
/// Minimum time between step-downs.
pub const STEP_DOWN_MS: u64 = 30_000;

const KIND_PADDING: u8 = 0;
const KIND_MEDIA: u8 = 1;
const KIND_CONTROL: u8 = 2;
const INNER_HEADER: usize = 3;

/// What a received plaintext carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inner {
    /// Nothing (padding).
    Padding,
    /// A media frame or fragment.
    Media(Vec<u8>),
    /// A control message (step-down, hang-up, rekey request).
    Control(Vec<u8>),
}

/// Which stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    /// Audio.
    Audio,
    /// Video at a tier index into [`VIDEO_TIERS`].
    Video(usize),
}

impl Stream {
    /// Packet size on the wire.
    pub fn packet_len(self) -> usize {
        match self {
            Stream::Audio => AUDIO_PACKET,
            Stream::Video(_) => VIDEO_PACKET,
        }
    }

    /// Plaintext length SFrame protects.
    pub fn plaintext_len(self) -> usize {
        self.packet_len() - OVERHEAD
    }

    /// Largest payload per packet.
    pub fn capacity(self) -> usize {
        self.plaintext_len() - INNER_HEADER
    }

    /// Microseconds between packets.
    pub fn interval_us(self) -> u64 {
        match self {
            Stream::Audio => 1_000_000 / u64::from(AUDIO_PPS),
            Stream::Video(t) => {
                let bits = (VIDEO_PACKET * 8) as u64;
                bits * 1_000_000 / (u64::from(VIDEO_TIERS[t.min(VIDEO_TIERS.len() - 1)]) * 1000)
            }
        }
    }
}

/// One outgoing stream.
pub struct Shaper {
    stream: Stream,
    queue: VecDeque<(u8, Vec<u8>)>,
    last_step_down: Option<u64>,
    frame_id: u32,
}

impl Shaper {
    /// A shaper for `stream`.
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            queue: VecDeque::new(),
            last_step_down: None,
            frame_id: 0,
        }
    }

    /// Current stream.
    pub fn stream(&self) -> Stream {
        self.stream
    }

    /// Queue an audio frame (must fit one packet).
    pub fn push_frame(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() > self.stream.capacity() {
            return Err(CallError::TooLarge);
        }
        self.queue.push_back((KIND_MEDIA, frame.to_vec()));
        Ok(())
    }

    /// Queue a video frame, split into fragments
    /// `frame_id u32 ‖ index u16 ‖ count u16 ‖ bytes`.
    pub fn push_video_frame(&mut self, frame: &[u8]) -> Result<()> {
        let per = self.stream.capacity() - 8;
        let count = frame.len().div_ceil(per).max(1);
        if count > usize::from(u16::MAX) {
            return Err(CallError::TooLarge);
        }
        let id = self.frame_id;
        self.frame_id = self.frame_id.wrapping_add(1);
        for (i, part) in frame.chunks(per).enumerate() {
            let mut f = Vec::with_capacity(8 + part.len());
            f.extend_from_slice(&id.to_be_bytes());
            f.extend_from_slice(&(i as u16).to_be_bytes());
            f.extend_from_slice(&(count as u16).to_be_bytes());
            f.extend_from_slice(part);
            self.queue.push_back((KIND_MEDIA, f));
        }
        Ok(())
    }

    /// Queue a control message; control jumps the media queue.
    pub fn push_control(&mut self, msg: &[u8]) -> Result<()> {
        if msg.len() > self.stream.capacity() {
            return Err(CallError::TooLarge);
        }
        self.queue.push_front((KIND_CONTROL, msg.to_vec()));
        Ok(())
    }

    /// The plaintext for the next tick: always exactly `plaintext_len` bytes.
    ///
    /// Records follow one another while they fit (`kind ‖ u16 len ‖ body`,
    /// then the next; zeros after the last read as padding), so a short
    /// control rides beside an audio frame instead of taking its slot: on a
    /// constant-rate stream a slot taken is latency that never comes back.
    pub fn next_plaintext(&mut self) -> Vec<u8> {
        let mut pt = vec![0u8; self.stream.plaintext_len()];
        let mut at = 0;
        while let Some((_, payload)) = self.queue.front() {
            if at + INNER_HEADER + payload.len() > pt.len() {
                break;
            }
            let Some((kind, payload)) = self.queue.pop_front() else {
                break;
            };
            pt[at] = kind;
            pt[at + 1..at + 3].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            pt[at + INNER_HEADER..at + INNER_HEADER + payload.len()].copy_from_slice(&payload);
            at += INNER_HEADER + payload.len();
        }
        pt
    }

    /// Frames waiting (backpressure for the encoder).
    pub fn backlog(&self) -> usize {
        self.queue.len()
    }

    /// Step video down one tier if allowed now. Never steps up.
    pub fn step_down(&mut self, now_ms: u64) -> bool {
        let Stream::Video(t) = self.stream else {
            return false;
        };
        if t == 0
            || self
                .last_step_down
                .is_some_and(|l| now_ms.saturating_sub(l) < STEP_DOWN_MS)
        {
            return false;
        }
        self.stream = Stream::Video(t - 1);
        self.last_step_down = Some(now_ms);
        true
    }
}

/// Decode a received plaintext.
pub fn decode_plaintext(pt: &[u8]) -> Result<Inner> {
    if pt.len() < INNER_HEADER {
        return Err(CallError::Malformed);
    }
    let len = usize::from(u16::from_be_bytes([pt[1], pt[2]]));
    let body = pt
        .get(INNER_HEADER..INNER_HEADER + len)
        .ok_or(CallError::Malformed)?;
    Ok(match pt[0] {
        KIND_PADDING => Inner::Padding,
        KIND_MEDIA => Inner::Media(body.to_vec()),
        KIND_CONTROL => Inner::Control(body.to_vec()),
        _ => return Err(CallError::Malformed),
    })
}

/// Every record of a received plaintext ([`Shaper::next_plaintext`]), up to
/// the padding: a control and an audio frame may share one.
pub fn decode_plaintexts(pt: &[u8]) -> Result<Vec<Inner>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + INNER_HEADER <= pt.len() {
        if pt[at] == KIND_PADDING {
            break;
        }
        let len = usize::from(u16::from_be_bytes([pt[at + 1], pt[at + 2]]));
        let body = pt
            .get(at + INNER_HEADER..at + INNER_HEADER + len)
            .ok_or(CallError::Malformed)?;
        out.push(match pt[at] {
            KIND_MEDIA => Inner::Media(body.to_vec()),
            KIND_CONTROL => Inner::Control(body.to_vec()),
            _ => return Err(CallError::Malformed),
        });
        at += INNER_HEADER + len;
    }
    if out.is_empty() {
        out.push(Inner::Padding);
    }
    Ok(out)
}

/// A frame being reassembled: id, fragment count, fragments so far.
type Partial = (u32, u16, Vec<Option<Vec<u8>>>);

/// Reassembles video fragments.
#[derive(Default)]
pub struct Reassembler {
    current: Option<Partial>,
}

impl Reassembler {
    /// Add a fragment; returns a complete frame when one finishes. A newer
    /// frame id abandons an incomplete older one (late video is useless).
    pub fn push(&mut self, frag: &[u8]) -> Option<Vec<u8>> {
        if frag.len() < 8 {
            return None;
        }
        let id = u32::from_be_bytes([frag[0], frag[1], frag[2], frag[3]]);
        let idx = u16::from_be_bytes([frag[4], frag[5]]);
        let count = u16::from_be_bytes([frag[6], frag[7]]);
        if count == 0 || idx >= count {
            return None;
        }
        let fresh = match &self.current {
            Some((cid, _, _)) => id != *cid,
            None => true,
        };
        if fresh {
            self.current = Some((id, count, vec![None; usize::from(count)]));
        }
        let (_, c, parts) = self.current.as_mut()?;
        if *c != count {
            return None;
        }
        parts[usize::from(idx)] = Some(frag[8..].to_vec());
        if parts.iter().all(Option::is_some) {
            let frame = parts.iter().flatten().flatten().copied().collect();
            self.current = None;
            return Some(frame);
        }
        None
    }
}
