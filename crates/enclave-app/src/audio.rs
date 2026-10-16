//! The microphone and the speaker during a call (`docs/11-calls.md` §10:
//! capture with `cpal`).
//!
//! The window only moves sound: 20 ms frames of 48 kHz mono go to the
//! vault ([`enclave_ipc::Cmd::CallMic`]), which has mediad clean them up
//! (echo cancellation) and encode them; decoded frames come back
//! ([`enclave_ipc::Out::CallAudio`]) and are played. Devices that run at
//! another rate or with more channels are converted here, linearly.

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// The call's sample rate.
pub const RATE: u32 = 48_000;
/// Samples in one frame (20 ms).
pub const FRAME: usize = 960;
/// Seconds the microphone is tried for when it won't open.
const MIC_TRIES: u32 = 60;
/// Most audio waiting to play (200 ms); older audio is dropped so the
/// delay can't grow.
const MAX_QUEUED: usize = 10 * FRAME;

/// Linear rate conversion of a stream, in pieces.
struct Linear {
    /// Input samples per output sample.
    step: f64,
    /// Where the next output falls after `prev` (0 to 1).
    pos: f64,
    prev: f32,
}

impl Linear {
    fn new(from: u32, to: u32) -> Self {
        Self {
            step: f64::from(from) / f64::from(to),
            pos: 0.0,
            prev: 0.0,
        }
    }

    /// Convert the next stretch of input.
    fn push(&mut self, input: &[f32], out: &mut Vec<f32>) {
        for &x in input {
            while self.pos <= 1.0 {
                out.push(self.prev + (x - self.prev) * self.pos as f32);
                self.pos += self.step;
            }
            self.pos -= 1.0;
            self.prev = x;
        }
    }
}

/// Playing from a queue of 48 kHz samples at the device's rate.
struct Player {
    step: f64,
    pos: f64,
    prev: f32,
    cur: f32,
}

impl Player {
    fn new(device_rate: u32) -> Self {
        Self {
            step: f64::from(RATE) / f64::from(device_rate),
            pos: 0.0,
            prev: 0.0,
            cur: 0.0,
        }
    }

    fn next(&mut self, queue: &mut VecDeque<i16>) -> f32 {
        while self.pos >= 1.0 {
            self.prev = self.cur;
            self.cur = queue.pop_front().map_or(0.0, |s| f32::from(s) / 32_768.0);
            self.pos -= 1.0;
        }
        let v = self.prev + (self.cur - self.prev) * self.pos as f32;
        self.pos += self.step;
        v
    }
}

fn to_i16(x: f32) -> i16 {
    (x.clamp(-1.0, 1.0) * 32_767.0) as i16
}

/// The microphone, in 20 ms frames, from samples at `rate` with
/// `channels` interleaved.
struct Capture {
    channels: usize,
    rate: Linear,
    mono: Vec<f32>,
    pending: Vec<f32>,
    frame: Sink,
}

/// Where microphone frames go (shared, so a microphone that couldn't open
/// yet can be tried again).
type Sink = Arc<Mutex<Box<dyn FnMut(Vec<i16>) + Send>>>;

impl Capture {
    fn push(&mut self, data: &[f32]) {
        self.mono.clear();
        self.mono.extend(
            data.chunks(self.channels.max(1))
                .map(|c| c.iter().sum::<f32>() / c.len() as f32),
        );
        let mono = std::mem::take(&mut self.mono);
        self.rate.push(&mono, &mut self.pending);
        self.mono = mono;
        while self.pending.len() >= FRAME {
            let f: Vec<i16> = self.pending.drain(..FRAME).map(to_i16).collect();
            if let Ok(mut sink) = self.frame.lock() {
                (sink)(f);
            }
        }
    }
}

/// Sound for a call, while it lasts (dropping it stops both).
pub struct CallAudio {
    queue: Arc<Mutex<VecDeque<i16>>>,
    stop: Option<std::sync::mpsc::Sender<()>>,
}

impl CallAudio {
    /// Open the default microphone and speaker; each 20 ms frame from the
    /// microphone goes to `mic`.
    pub fn start(mic: impl FnMut(Vec<i16>) + Send + 'static) -> Result<Self, String> {
        let queue: Arc<Mutex<VecDeque<i16>>> = Arc::default();
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let (ready, started) = std::sync::mpsc::channel::<Result<(), String>>();
        let q = Arc::clone(&queue);
        // The streams stay on a thread of their own (they aren't Send on
        // every platform) until the call ends.
        std::thread::Builder::new()
            .name("enclave-call-audio".into())
            .spawn(move || {
                let speaker = match speaker(q) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let _ = ready.send(Ok(()));
                // The microphone may not be allowed yet (a phone asks when
                // the call starts): keep trying for a minute.
                let sink: Sink = Arc::new(Mutex::new(Box::new(mic)));
                let mut input = None;
                for _ in 0..MIC_TRIES {
                    if input.is_none() {
                        match microphone(Arc::clone(&sink)) {
                            Ok(m) => input = Some(m),
                            Err(e) => eprintln!("enclave: microphone: {e}"),
                        }
                    }
                    match stopped.recv_timeout(std::time::Duration::from_secs(1)) {
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        _ => return,
                    }
                }
                let _ = stopped.recv();
                drop((input, speaker));
            })
            .map_err(|e| e.to_string())?;
        started
            .recv()
            .map_err(|_| "the audio thread stopped".to_string())??;
        Ok(Self {
            queue,
            stop: Some(stop),
        })
    }

    /// Play the next 20 ms.
    pub fn play(&self, pcm: &[i16]) {
        if let Ok(mut q) = self.queue.lock() {
            q.extend(pcm.iter().copied());
            let over = q.len().saturating_sub(MAX_QUEUED);
            q.drain(..over);
        }
    }
}

impl Drop for CallAudio {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

/// Open and start the microphone.
fn microphone(frame: Sink) -> Result<cpal::Stream, String> {
    let host = cpal::default_host();
    let input = host
        .default_input_device()
        .ok_or("There's no microphone.")?;
    let in_cfg = input.default_input_config().map_err(|e| e.to_string())?;
    let mut capture = Capture {
        channels: usize::from(in_cfg.channels()),
        rate: Linear::new(in_cfg.sample_rate(), RATE),
        mono: Vec::new(),
        pending: Vec::new(),
        frame,
    };
    let err = |e: cpal::Error| eprintln!("enclave: audio: {e}");
    let config = in_cfg.config();
    let mic = match in_cfg.sample_format() {
        cpal::SampleFormat::F32 => input.build_input_stream::<f32, _, _>(
            config,
            move |d: &[f32], _| capture.push(d),
            err,
            None,
        ),
        cpal::SampleFormat::I16 => {
            let mut buf = Vec::new();
            input.build_input_stream::<i16, _, _>(
                config,
                move |d: &[i16], _| {
                    buf.clear();
                    buf.extend(d.iter().map(|s| f32::from(*s) / 32_768.0));
                    capture.push(&buf);
                },
                err,
                None,
            )
        }
        f => {
            return Err(format!(
                "The microphone gives {f} samples, which Enclave can't read."
            ));
        }
    }
    .map_err(|e| e.to_string())?;
    mic.play().map_err(|e| e.to_string())?;
    Ok(mic)
}

/// Open and start the speaker, playing from `queue`.
fn speaker(queue: Arc<Mutex<VecDeque<i16>>>) -> Result<cpal::Stream, String> {
    let host = cpal::default_host();
    let output = host.default_output_device().ok_or("There's no speaker.")?;
    let out_cfg = output.default_output_config().map_err(|e| e.to_string())?;
    let err = |e: cpal::Error| eprintln!("enclave: audio: {e}");
    let channels = usize::from(out_cfg.channels()).max(1);
    let mut player = Player::new(out_cfg.sample_rate());
    let config = out_cfg.config();
    let speaker = match out_cfg.sample_format() {
        cpal::SampleFormat::F32 => output.build_output_stream::<f32, _, _>(
            config,
            move |d: &mut [f32], _| {
                let mut q = queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for f in d.chunks_mut(channels) {
                    let v = player.next(&mut q);
                    f.fill(v);
                }
            },
            err,
            None,
        ),
        cpal::SampleFormat::I16 => output.build_output_stream::<i16, _, _>(
            config,
            move |d: &mut [i16], _| {
                let mut q = queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for f in d.chunks_mut(channels) {
                    let v = to_i16(player.next(&mut q));
                    f.fill(v);
                }
            },
            err,
            None,
        ),
        f => {
            return Err(format!(
                "The speaker takes {f} samples, which Enclave can't write."
            ));
        }
    }
    .map_err(|e| e.to_string())?;
    speaker.play().map_err(|e| e.to_string())?;
    Ok(speaker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_convert_without_drift() {
        // 44.1 kHz stereo in: one second gives 50 frames of 48 kHz mono.
        let frames = Arc::new(Mutex::new(Vec::new()));
        let f = Arc::clone(&frames);
        let mut c = Capture {
            channels: 2,
            rate: Linear::new(44_100, RATE),
            mono: Vec::new(),
            pending: Vec::new(),
            frame: Arc::new(Mutex::new(Box::new(move |v| {
                f.lock().unwrap_or_else(|e| e.into_inner()).push(v)
            }))),
        };
        let second: Vec<f32> = (0..44_100 * 2)
            .map(|i| ((i / 2) as f32 * 0.01).sin() * 0.5)
            .collect();
        for chunk in second.chunks(882) {
            c.push(chunk);
        }
        let n = frames.lock().unwrap_or_else(|e| e.into_inner()).len();
        assert!((49..=50).contains(&n), "{n}");
        // Playing 48 kHz on a 44.1 kHz device takes 44,100 samples a
        // second, and silence once the queue is empty.
        let mut q: VecDeque<i16> = std::iter::repeat_n(1000, 48_000).collect();
        let mut p = Player::new(44_100);
        let mut played = 0;
        while !q.is_empty() {
            p.next(&mut q);
            played += 1;
        }
        assert!((44_090..=44_110).contains(&played), "{played}");
        for _ in 0..10 {
            p.next(&mut q);
        }
        assert_eq!(p.next(&mut q), 0.0);
    }

    #[test]
    fn the_play_queue_stays_short() {
        let a = CallAudio {
            queue: Arc::default(),
            stop: None,
        };
        for _ in 0..30 {
            a.play(&[1; FRAME]);
        }
        assert_eq!(a.queue.lock().map(|q| q.len()).unwrap_or(0), MAX_QUEUED);
    }
}

/// Longest voice note (`enclave_media::voice`: 15 minutes).
pub const MAX_NOTE_SAMPLES: usize = RATE as usize * 15 * 60;

/// Recording a voice note from the microphone: 48 kHz mono, until
/// [`Recorder::finish`] (or dropped, which throws it away).
pub struct Recorder {
    samples: Arc<Mutex<Vec<i16>>>,
    stop: Option<std::sync::mpsc::Sender<()>>,
}

impl Recorder {
    /// Open the default microphone and start.
    pub fn start() -> Result<Self, String> {
        let samples: Arc<Mutex<Vec<i16>>> = Arc::default();
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let (ready, started) = std::sync::mpsc::channel::<Result<(), String>>();
        let s = Arc::clone(&samples);
        std::thread::Builder::new()
            .name("enclave-voice-note".into())
            .spawn(move || {
                let sink: Sink = Arc::new(Mutex::new(Box::new(move |f: Vec<i16>| {
                    if let Ok(mut s) = s.lock()
                        && s.len() < MAX_NOTE_SAMPLES
                    {
                        s.extend_from_slice(&f);
                    }
                })));
                match microphone(sink) {
                    Ok(input) => {
                        let _ = ready.send(Ok(()));
                        let _ = stopped.recv();
                        drop(input);
                    }
                    Err(e) => {
                        let _ = ready.send(Err(e));
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        started
            .recv()
            .map_err(|_| "the microphone stopped".to_string())??;
        Ok(Self {
            samples,
            stop: Some(stop),
        })
    }

    /// Stop: the recording, as a 16-bit 48 kHz mono WAV file.
    pub fn finish(mut self) -> Vec<u8> {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        let pcm = self.samples.lock().map(|s| s.clone()).unwrap_or_default();
        wav(&pcm)
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

/// 16-bit 48 kHz mono PCM as a WAV file.
pub fn wav(pcm: &[i16]) -> Vec<u8> {
    let data = (pcm.len() * 2) as u32;
    let mut w = Vec::with_capacity(44 + pcm.len() * 2);
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + data).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes()); // PCM
    w.extend_from_slice(&1u16.to_le_bytes()); // mono
    w.extend_from_slice(&RATE.to_le_bytes());
    w.extend_from_slice(&(RATE * 2).to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&data.to_le_bytes());
    for s in pcm {
        w.extend_from_slice(&s.to_le_bytes());
    }
    w
}

/// Playing a voice note through the speaker: stops at its end, or when
/// dropped.
pub struct Playback {
    queue: Arc<Mutex<VecDeque<i16>>>,
    stop: Option<std::sync::mpsc::Sender<()>>,
}

impl Playback {
    /// Play 48 kHz mono samples; `done` runs when they have all played.
    pub fn start(pcm: Vec<i16>, done: impl FnOnce() + Send + 'static) -> Result<Self, String> {
        let queue: Arc<Mutex<VecDeque<i16>>> = Arc::new(Mutex::new(pcm.into()));
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let (ready, started) = std::sync::mpsc::channel::<Result<(), String>>();
        let q = Arc::clone(&queue);
        std::thread::Builder::new()
            .name("enclave-voice-play".into())
            .spawn(move || {
                let out = match speaker(Arc::clone(&q)) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let _ = ready.send(Ok(()));
                loop {
                    match stopped.recv_timeout(std::time::Duration::from_millis(100)) {
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if q.lock().map(|q| q.is_empty()).unwrap_or(true) {
                                // The device's own buffer plays out.
                                std::thread::sleep(std::time::Duration::from_millis(150));
                                drop(out);
                                done();
                                return;
                            }
                        }
                        _ => return,
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        started
            .recv()
            .map_err(|_| "the speaker stopped".to_string())??;
        Ok(Self {
            queue,
            stop: Some(stop),
        })
    }

    /// More of the note (its next piece).
    pub fn extend(&self, pcm: &[i16]) {
        if let Ok(mut q) = self.queue.lock() {
            q.extend(pcm.iter().copied());
        }
    }

    /// Whether it still plays.
    pub fn playing(&self) -> bool {
        self.queue.lock().map(|q| !q.is_empty()).unwrap_or(false)
    }
}

impl Drop for Playback {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

#[cfg(test)]
mod note_tests {
    use super::*;

    #[test]
    fn a_recording_is_a_wav_the_voice_note_reader_takes() {
        let pcm: Vec<i16> = (0..4_800).map(|i| ((i % 100) * 300) as i16).collect();
        let w = wav(&pcm);
        assert_eq!(&w[..4], b"RIFF");
        assert_eq!(&w[8..16], b"WAVEfmt ");
        assert_eq!(u32::from_le_bytes([w[24], w[25], w[26], w[27]]), RATE);
        assert_eq!(w.len(), 44 + pcm.len() * 2);
    }
}
