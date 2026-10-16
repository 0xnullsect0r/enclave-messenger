//! On-device voice transcription (`docs/18-a11y-i18n.md` §4): Whisper
//! (OpenAI's speech model, the multilingual "tiny" size, 8-bit quantized)
//! running here, on samples a voice note decoded to in the media sandbox.
//! Nothing leaves the device; the model is an optional download
//! ([`MODEL_FILES`], pinned by hash).
//!
//! Each 30 seconds of sound becomes a log-mel spectrogram (80 bands, the
//! filter bank computed here as Whisper's), goes through the encoder once,
//! and the decoder writes text greedily (temperature 0): the language
//! first, detected from the opening token, then words until the end token,
//! with timestamps off and Whisper's suppressed tokens never chosen.

use crate::MediaError;
use candle::{DType, Device, IndexOp, Tensor};
use candle_transformers::models::whisper::{self as w, Config, quantized_model::Whisper};
use std::collections::HashMap;

type Result<T> = std::result::Result<T, MediaError>;

/// The files of the model: where they are published (a pinned revision of
/// `lmz/candle-whisper` on Hugging Face), their size and SHA-256.
pub const MODEL_FILES: [(&str, u64, &str); 3] = [
    (
        "config-tiny.json",
        1_983,
        "ffdccec4f3211f4c63310f2b7098f309fe70f3952cedc5e4d11e43f5b2379b98",
    ),
    (
        "tokenizer-tiny.json",
        2_480_452,
        "dfc530298b6fbed1a97c6472c575b026453706e2a204c7f7038f2c9d208b0759",
    ),
    (
        "model-tiny-q80.gguf",
        41_841_632,
        "edcc907db61aef092f1244dc1e53c55056b472be343e9bbb4dc12ebd4740392f",
    ),
];

/// The revision the files come from.
pub const MODEL_URL: &str =
    "https://huggingface.co/lmz/candle-whisper/resolve/02d8350e5402f18725eadb6101b4963d181b0b5e/";

/// The sample rate the model listens at.
pub const RATE: u32 = w::SAMPLE_RATE as u32;
/// Most tokens written for one 30-second window.
const MAX_TOKENS: usize = 224;

fn err<E: std::fmt::Display>(e: E) -> MediaError {
    let _ = e.to_string();
    MediaError::Damaged
}

/// Whisper's mel filter bank (Slaney's scale and normalisation, as
/// librosa computes it for `n_fft` 400 at 16 kHz): `bands` rows of
/// `n_fft / 2 + 1`.
fn mel_filters(bands: usize) -> Vec<f32> {
    let bins = w::N_FFT / 2 + 1;
    let sr = w::SAMPLE_RATE as f64;
    // Slaney's mel scale: linear below 1 kHz, logarithmic above.
    let (f_sp, min_log_hz) = (200.0 / 3.0, 1000.0);
    let min_log_mel = min_log_hz / f_sp;
    let logstep = (6.4f64).ln() / 27.0;
    let hz_to_mel = |f: f64| {
        if f < min_log_hz {
            f / f_sp
        } else {
            min_log_mel + (f / min_log_hz).ln() / logstep
        }
    };
    let mel_to_hz = |m: f64| {
        if m < min_log_mel {
            m * f_sp
        } else {
            min_log_hz * ((m - min_log_mel) * logstep).exp()
        }
    };
    let (lo, hi) = (hz_to_mel(0.0), hz_to_mel(sr / 2.0));
    let points: Vec<f64> = (0..bands + 2)
        .map(|i| mel_to_hz(lo + (hi - lo) * i as f64 / (bands + 1) as f64))
        .collect();
    let freqs: Vec<f64> = (0..bins).map(|i| i as f64 * sr / w::N_FFT as f64).collect();
    let mut out = vec![0f32; bands * bins];
    for m in 0..bands {
        let (l, c, r) = (points[m], points[m + 1], points[m + 2]);
        let norm = 2.0 / (r - l);
        for (k, f) in freqs.iter().enumerate() {
            let up = (f - l) / (c - l);
            let down = (r - f) / (r - c);
            out[m * bins + k] = (up.min(down).max(0.0) * norm) as f32;
        }
    }
    out
}

/// GPT-2's byte-to-character map, reversed: the bytes a token stands for.
fn unicode_to_byte() -> HashMap<char, u8> {
    let mut bs: Vec<u32> = (u32::from('!')..=u32::from('~'))
        .chain(0xA1..=0xAC)
        .chain(0xAE..=0xFF)
        .collect();
    let mut cs = bs.clone();
    let mut n = 0;
    for b in 0..=255u32 {
        if !bs.contains(&b) {
            bs.push(b);
            cs.push(256 + n);
            n += 1;
        }
    }
    bs.into_iter()
        .zip(cs)
        .filter_map(|(b, c)| Some((char::from_u32(c)?, b as u8)))
        .collect()
}

/// The words of the tokenizer: each token's bytes, the special tokens by
/// name.
struct Vocab {
    bytes: HashMap<u32, Vec<u8>>,
    special: HashMap<String, u32>,
}

impl Vocab {
    fn parse(json: &[u8]) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(json).map_err(err)?;
        let to_byte = unicode_to_byte();
        let mut bytes = HashMap::new();
        for (piece, id) in v["model"]["vocab"].as_object().ok_or(MediaError::Damaged)? {
            let Some(id) = id.as_u64() else { continue };
            let b: Option<Vec<u8>> = piece.chars().map(|c| to_byte.get(&c).copied()).collect();
            if let Some(b) = b {
                bytes.insert(id as u32, b);
            }
        }
        let mut special = HashMap::new();
        for t in v["added_tokens"].as_array().ok_or(MediaError::Damaged)? {
            if let (Some(name), Some(id)) = (t["content"].as_str(), t["id"].as_u64()) {
                special.insert(name.to_string(), id as u32);
            }
        }
        Ok(Self { bytes, special })
    }

    fn id(&self, name: &str) -> Result<u32> {
        self.special.get(name).copied().ok_or(MediaError::Damaged)
    }

    fn text(&self, tokens: &[u32]) -> String {
        let b: Vec<u8> = tokens
            .iter()
            .filter_map(|t| self.bytes.get(t))
            .flatten()
            .copied()
            .collect();
        String::from_utf8_lossy(&b).trim().to_string()
    }
}

/// A loaded model.
pub struct Model {
    whisper: Whisper,
    vocab: Vocab,
    filters: Vec<f32>,
    device: Device,
    sot: u32,
    eot: u32,
    transcribe: u32,
    no_timestamps: u32,
    /// Language tokens (`<|en|>`, `<|de|>`, …).
    languages: Vec<u32>,
    /// Never written: the config's, and timestamps.
    suppress: Tensor,
}

impl Model {
    /// Load from the three files' bytes ([`MODEL_FILES`], checked by the
    /// caller against their hashes).
    pub fn load(config: &[u8], tokenizer: &[u8], gguf: &[u8]) -> Result<Self> {
        let device = Device::Cpu;
        let config: Config = serde_json::from_slice(config).map_err(err)?;
        let vocab = Vocab::parse(tokenizer)?;
        let vb =
            candle_transformers::quantized_var_builder::VarBuilder::from_gguf_buffer(gguf, &device)
                .map_err(err)?;
        let whisper = Whisper::load(&vb, config.clone()).map_err(err)?;
        let filters = mel_filters(config.num_mel_bins);
        let (sot, eot) = (vocab.id(w::SOT_TOKEN)?, vocab.id(w::EOT_TOKEN)?);
        let (transcribe, no_timestamps) = (
            vocab.id(w::TRANSCRIBE_TOKEN)?,
            vocab.id(w::NO_TIMESTAMPS_TOKEN)?,
        );
        let not_languages = [
            w::SOT_TOKEN,
            w::EOT_TOKEN,
            w::TRANSCRIBE_TOKEN,
            w::TRANSLATE_TOKEN,
            w::NO_TIMESTAMPS_TOKEN,
            "<|startoflm|>",
            "<|startofprev|>",
            "<|nocaptions|>",
            "<|nospeech|>",
        ];
        let mut languages: Vec<u32> = vocab
            .special
            .iter()
            .filter(|(name, _)| {
                name.starts_with("<|")
                    && name.ends_with("|>")
                    && name.len() <= 7
                    && name[2..name.len() - 2]
                        .chars()
                        .all(|c| c.is_ascii_lowercase())
                    && !not_languages.contains(&name.as_str())
            })
            .map(|(_, id)| *id)
            .collect();
        languages.sort_unstable();
        let mut mask = vec![0f32; config.vocab_size];
        for &t in &config.suppress_tokens {
            if let Some(m) = mask.get_mut(t as usize) {
                *m = f32::NEG_INFINITY;
            }
        }
        // Timestamps (everything after <|notimestamps|>).
        for m in mask.iter_mut().skip(no_timestamps as usize + 1) {
            *m = f32::NEG_INFINITY;
        }
        let suppress = Tensor::new(mask.as_slice(), &device).map_err(err)?;
        Ok(Self {
            whisper,
            vocab,
            filters,
            device,
            sot,
            eot,
            transcribe,
            no_timestamps,
            languages,
            suppress,
        })
    }

    /// The text spoken in `pcm` (mono at [`RATE`], -1 to 1).
    pub fn transcribe(&mut self, pcm: &[f32]) -> Result<String> {
        let mut text = Vec::new();
        for window in pcm.chunks(w::N_SAMPLES) {
            let t = self.window(window)?;
            if !t.is_empty() {
                text.push(t);
            }
        }
        Ok(text.join(" "))
    }

    fn window(&mut self, pcm: &[f32]) -> Result<String> {
        let cfg = self.whisper.config.clone();
        let mel = w::audio::pcm_to_mel(&cfg, pcm, &self.filters);
        let frames = mel.len() / cfg.num_mel_bins;
        let mel =
            Tensor::from_vec(mel, (1, cfg.num_mel_bins, frames), &self.device).map_err(err)?;
        // The encoder takes exactly 3,000 frames (30 s), padded.
        let mel = if frames < w::N_FRAMES {
            let pad = Tensor::zeros(
                (1, cfg.num_mel_bins, w::N_FRAMES - frames),
                DType::F32,
                &self.device,
            )
            .map_err(err)?;
            Tensor::cat(&[&mel, &pad], 2).map_err(err)?
        } else {
            mel.narrow(2, 0, w::N_FRAMES).map_err(err)?
        };
        self.whisper.reset_kv_cache();
        let audio = self.whisper.encoder.forward(&mel, true).map_err(err)?;
        let language = self.language(&audio)?;
        let mut tokens = vec![self.sot, language, self.transcribe, self.no_timestamps];
        let start = tokens.len();
        for i in 0..MAX_TOKENS {
            // Every token so far, each step: the decoder keeps only the
            // audio's keys and values between steps, not its own.
            let input = Tensor::new(tokens.as_slice(), &self.device)
                .and_then(|t| t.unsqueeze(0))
                .map_err(err)?;
            let ys = self
                .whisper
                .decoder
                .forward(&input, &audio, i == 0)
                .map_err(err)?;
            let (_, n, _) = ys.dims3().map_err(err)?;
            let logits = self
                .whisper
                .decoder
                .final_linear(&ys.i((..1, n - 1..)).map_err(err)?)
                .and_then(|l| l.i(0))
                .and_then(|l| l.i(0))
                .map_err(err)?;
            let logits = logits.broadcast_add(&self.suppress).map_err(err)?;
            let next = logits
                .argmax(0)
                .and_then(|t| t.to_scalar::<u32>())
                .map_err(err)?;
            if next == self.eot || tokens.len() > cfg.max_target_positions {
                break;
            }
            tokens.push(next);
        }
        Ok(self.vocab.text(&tokens[start..]))
    }

    /// The language spoken: the language token most likely after the
    /// start token.
    fn language(&mut self, audio: &Tensor) -> Result<u32> {
        let input = Tensor::new(&[self.sot], &self.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(err)?;
        let ys = self
            .whisper
            .decoder
            .forward(&input, audio, true)
            .map_err(err)?;
        let logits = self
            .whisper
            .decoder
            .final_linear(&ys.i((..1, ..1)).map_err(err)?)
            .and_then(|l| l.i(0))
            .and_then(|l| l.i(0))
            .and_then(|l| l.to_vec1::<f32>())
            .map_err(err)?;
        self.languages
            .iter()
            .copied()
            .max_by(|a, b| {
                let (x, y) = (logits[*a as usize], logits[*b as usize]);
                x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal)
            })
            .ok_or(MediaError::Damaged)
    }
}

/// Voice-note audio (48 kHz) at the model's rate: every third sample of a
/// low-passed signal (a short moving average, enough for speech).
pub fn from_48k(pcm: &[i16]) -> Vec<f32> {
    pcm.chunks(3)
        .map(|c| c.iter().map(|s| f32::from(*s)).sum::<f32>() / (c.len() as f32 * 32_768.0))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn the_filter_bank_has_whisper_s_shape() {
        let f = mel_filters(80);
        assert_eq!(f.len(), 80 * 201);
        // Every band has weight somewhere, and none past Nyquist.
        for m in 0..80 {
            assert!(
                f[m * 201..(m + 1) * 201].iter().any(|x| *x > 0.0),
                "band {m}"
            );
        }
        // Slaney normalisation: the first band's peak is 2 / width (Hz).
        let peak = f[..201].iter().cloned().fold(0.0f32, f32::max);
        assert!((0.02..0.03).contains(&peak), "{peak}");
    }

    #[test]
    fn tokens_decode_to_their_bytes() {
        let m = unicode_to_byte();
        assert_eq!(m.len(), 256);
        assert_eq!(m[&'Ġ'], b' ');
        assert_eq!(m[&'a'], b'a');
    }

    /// With the model at hand (`ENCLAVE_WHISPER_DIR`, the three files) and a
    /// recording of speech (`ENCLAVE_WHISPER_SAMPLE`, 16 kHz mono 16-bit
    /// WAV, with `ENCLAVE_WHISPER_EXPECT` words it must contain): the
    /// nightly job downloads them.
    #[test]
    fn transcribes_speech_with_the_model() {
        let (Ok(dir), Ok(sample), Ok(expect)) = (
            std::env::var("ENCLAVE_WHISPER_DIR"),
            std::env::var("ENCLAVE_WHISPER_SAMPLE"),
            std::env::var("ENCLAVE_WHISPER_EXPECT"),
        ) else {
            eprintln!("transcribes_speech_with_the_model: no model given; skipped");
            return;
        };
        let dir = std::path::Path::new(&dir);
        let read = |n: &str| std::fs::read(dir.join(n)).unwrap();
        let mut model = Model::load(
            &read("config-tiny.json"),
            &read("tokenizer-tiny.json"),
            &read("model-tiny-q80.gguf"),
        )
        .unwrap();
        let wav = std::fs::read(sample).unwrap();
        // The samples are in the "data" chunk (others, like LIST, may come
        // first).
        let mut at = 12;
        let data = loop {
            let id = &wav[at..at + 4];
            let len = u32::from_le_bytes(wav[at + 4..at + 8].try_into().unwrap()) as usize;
            if id == b"data" {
                break &wav[at + 8..(at + 8 + len).min(wav.len())];
            }
            at += 8 + len + (len & 1);
        };
        let pcm: Vec<f32> = data
            .chunks_exact(2)
            .map(|c| f32::from(i16::from_le_bytes([c[0], c[1]])) / 32_768.0)
            .collect();
        let text = model.transcribe(&pcm).unwrap().to_lowercase();
        eprintln!("transcript: {text}");
        for word in expect.split(',') {
            assert!(text.contains(word), "{word:?} in {text:?}");
        }
    }
}
