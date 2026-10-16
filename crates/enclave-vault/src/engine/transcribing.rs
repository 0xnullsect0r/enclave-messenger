//! Voice notes transcribed on this device (`docs/18-a11y-i18n.md` §4):
//! the model is an optional download, through Tor in pieces, each file
//! checked against the size and SHA-256 the build pins
//! (`enclave_media::transcribe::MODEL_FILES`); a note is decoded in the
//! media sandbox and only its samples reach the model, here. The
//! transcript stays in the message's own record.

use super::Engine;
use enclave_net::transport::Transport;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The pieces a file is fetched in (a pipe frame holds a mebibyte).
const PIECE: u64 = 512 * 1024;

/// Where the model download stands.
#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct Download {
    /// 0 no model, 1 downloading, 2 ready.
    pub(super) state: u8,
    /// Percent downloaded.
    pub(super) percent: u8,
    /// Why the last download failed.
    pub(super) error: String,
}

/// The engine's transcription: the download's state, and the model once
/// loaded.
#[derive(Default)]
pub(super) struct Transcription {
    pub(super) download: Arc<Mutex<Download>>,
    /// The download, while it runs (stopped when transcription is turned
    /// off).
    task: Option<tokio::task::AbortHandle>,
    model: Option<Arc<Mutex<enclave_media::transcribe::Model>>>,
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// Whether the files in `dir` are the model's, whole.
pub(super) fn model_present(dir: &Path) -> bool {
    enclave_media::transcribe::MODEL_FILES
        .iter()
        .all(|(name, size, _)| std::fs::metadata(dir.join(name)).is_ok_and(|m| m.len() == *size))
}

/// Fetch one file in pieces through `fetch` (`GET`, URL, the status and
/// body), check it, and write it to `to` (whole or not at all).
pub(super) async fn fetch_file<F, Fut>(
    fetch: &F,
    url: &str,
    size: u64,
    sha256: &str,
    to: &Path,
    mut progress: impl FnMut(u64),
) -> Result<(), String>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(u16, Vec<u8>), String>>,
{
    let mut bytes = Vec::with_capacity(size as usize);
    while (bytes.len() as u64) < size {
        let from = bytes.len() as u64;
        let to_byte = (from + PIECE).min(size) - 1;
        let (status, body) = fetch(format!("{url}#bytes={from}-{to_byte}")).await?;
        if !(200..300).contains(&status) || body.is_empty() {
            return Err(format!("the download answered {status}"));
        }
        // A server that ignores the range sends the whole file at once.
        if status == 200 && body.len() as u64 == size && from == 0 {
            bytes = body;
            break;
        }
        if body.len() as u64 != to_byte - from + 1 {
            return Err("a piece of the download was the wrong size".into());
        }
        bytes.extend_from_slice(&body);
        progress(body.len() as u64);
    }
    if bytes.len() as u64 != size || sha256_hex(&bytes) != sha256 {
        return Err("the download wasn't the expected file".into());
    }
    let tmp = to.with_extension("part");
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, to).map_err(|e| e.to_string())
}

/// Download every file of the model into `dir` through Tor.
async fn download(transport: Arc<dyn Transport>, dir: PathBuf, state: Arc<Mutex<Download>>) {
    let set = |f: &dyn Fn(&mut Download)| {
        if let Ok(mut d) = state.lock() {
            f(&mut d);
        }
    };
    let total: u64 = enclave_media::transcribe::MODEL_FILES
        .iter()
        .map(|f| f.1)
        .sum();
    let mut done = 0u64;
    let fetch = |url: String| {
        let t = Arc::clone(&transport);
        async move {
            t.fetch("GET", &url, Vec::new())
                .await
                .map_err(|e| e.to_string())
        }
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return set(&|d| {
            d.state = 0;
            d.error = e.to_string();
        });
    }
    for (name, size, sha) in enclave_media::transcribe::MODEL_FILES {
        let path = dir.join(name);
        let have =
            std::fs::read(&path).is_ok_and(|b| b.len() as u64 == size && sha256_hex(&b) == sha);
        if !have {
            let url = format!("{}{name}", enclave_media::transcribe::MODEL_URL);
            let r = fetch_file(&fetch, &url, size, sha, &path, |n| {
                done += n;
                let p = (done * 100 / total.max(1)).min(99) as u8;
                set(&|d| d.percent = p);
            })
            .await;
            if let Err(e) = r {
                let e = format!("Couldn't download the transcription model: {e}");
                return set(&|d| {
                    d.state = 0;
                    d.error = e.clone();
                });
            }
        } else {
            done += size;
        }
    }
    set(&|d| {
        *d = Download {
            state: 2,
            percent: 100,
            error: String::new(),
        }
    });
}

impl Engine {
    /// Where the model lives: in the profile (none in the demo).
    pub(super) fn model_dir(&self) -> Option<PathBuf> {
        match &self.mode {
            super::Mode::Server { profile, .. } => {
                Some(profile.join("models").join("whisper-tiny"))
            }
            // The demo keeps nothing on disk: a model given to it (tests).
            super::Mode::Demo => std::env::var_os("ENCLAVE_WHISPER_DIR").map(PathBuf::from),
        }
    }

    /// Where the model stands, for the window: (0 none, 1 downloading,
    /// 2 ready; percent; the last download's error).
    pub(super) fn transcription_state(&self) -> (u8, u8, String) {
        let d = self
            .transcription
            .download
            .lock()
            .map(|d| d.clone())
            .unwrap_or_default();
        if d.state == 1 {
            return (1, d.percent, String::new());
        }
        if self.model_dir().is_some_and(|dir| model_present(&dir)) {
            return (2, 100, String::new());
        }
        (0, 0, d.error)
    }

    /// Turn transcription on (download the model) or off (delete it).
    pub(super) fn transcription_model(&mut self, on: bool) {
        let Some(dir) = self.model_dir() else {
            self.status = "Transcription isn't available here.".into();
            return;
        };
        if !on {
            self.transcription.model = None;
            if let Some(t) = self.transcription.task.take() {
                t.abort();
            }
            // Only the profile's own copy is ever deleted.
            if matches!(self.mode, super::Mode::Server { .. }) {
                let _ = std::fs::remove_dir_all(&dir);
            }
            if let Ok(mut d) = self.transcription.download.lock() {
                *d = Download::default();
            }
            return;
        }
        if self.model_dir().is_some_and(|d| model_present(&d)) {
            return;
        }
        if let Ok(mut d) = self.transcription.download.lock() {
            if d.state == 1 {
                return;
            }
            *d = Download {
                state: 1,
                percent: 0,
                error: String::new(),
            };
        }
        let task = tokio::spawn(download(
            Arc::clone(&self.transport),
            dir,
            Arc::clone(&self.transcription.download),
        ));
        self.transcription.task = Some(task.abort_handle());
    }

    /// Transcribe a voice note (conversation, message) and keep the text
    /// with it.
    pub(super) async fn transcribe(&mut self, id: &str, seq: u64) {
        let Some(dir) = self.model_dir().filter(|d| model_present(d)) else {
            self.status = "Turn on transcription in Settings first.".into();
            return;
        };
        let Some(note) = self.attachment_bytes(id, seq).await else {
            self.status = "Couldn't download the voice note. Check your connection.".into();
            return;
        };
        // Decoded in the media sandbox; only samples come back.
        let mut pcm = Vec::new();
        let mut start = 0u32;
        loop {
            match self.media.voice_piece(note.clone(), start).await {
                Ok(p) if !p.is_empty() => pcm.extend(p),
                Ok(_) => break,
                Err(_) => {
                    self.status = "That voice note couldn't be read.".into();
                    return;
                }
            }
            start += enclave_media::voice::CHUNK_FRAMES;
        }
        let model = match &self.transcription.model {
            Some(m) => Arc::clone(m),
            None => {
                let loaded = tokio::task::spawn_blocking(move || {
                    let read = |n: &str| std::fs::read(dir.join(n)).map_err(|e| e.to_string());
                    enclave_media::transcribe::Model::load(
                        &read("config-tiny.json")?,
                        &read("tokenizer-tiny.json")?,
                        &read("model-tiny-q80.gguf")?,
                    )
                    .map_err(|e| e.to_string())
                })
                .await;
                match loaded {
                    Ok(Ok(m)) => {
                        let m = Arc::new(Mutex::new(m));
                        self.transcription.model = Some(Arc::clone(&m));
                        m
                    }
                    _ => {
                        self.status = "The transcription model couldn't be opened. Turn transcription off and on again.".into();
                        return;
                    }
                }
            }
        };
        self.status = "Transcribing…".into();
        self.push();
        let text = tokio::task::spawn_blocking(move || {
            let samples = enclave_media::transcribe::from_48k(&pcm);
            model
                .lock()
                .map_err(|_| "busy".to_string())
                .and_then(|mut m| m.transcribe(&samples).map_err(|e| e.to_string()))
        })
        .await;
        let text = match text {
            Ok(Ok(t)) if !t.is_empty() => t,
            Ok(Ok(_)) => "(no words heard)".to_string(),
            _ => {
                self.status = "Couldn't transcribe that voice note.".into();
                return;
            }
        };
        self.status.clear();
        let (group, root) = if id.starts_with('g') {
            (self.group_of(id), None)
        } else {
            (None, self.root_of(id))
        };
        let Some(c) = self.client.as_mut() else {
            return;
        };
        let saved = match (group, root) {
            (Some(g), _) => c.set_group_transcript(&g, seq, &text),
            (_, Some(r)) => c.set_transcript(&r, seq, &text),
            _ => return,
        };
        if let Err(e) = saved {
            eprintln!("enclave-vault: transcript: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn a_file_comes_in_checked_pieces() {
        let file: Vec<u8> = (0..1_300_000u32).map(|i| (i % 251) as u8).collect();
        let sha = sha256_hex(&file);
        let dir = std::env::temp_dir().join(format!("enclave-model-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let to = dir.join("m.bin");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (f2, a2) = (file.clone(), Arc::clone(&asked));
        let fetch = move |url: String| {
            let (f, a) = (f2.clone(), Arc::clone(&a2));
            async move {
                let (_, range) = url.split_once("#bytes=").unwrap();
                let (x, y) = range.split_once('-').unwrap();
                let (x, y): (usize, usize) = (x.parse().unwrap(), y.parse().unwrap());
                a.lock().unwrap().push((x, y));
                Ok((206, f[x..=y].to_vec()))
            }
        };
        let mut seen = 0;
        fetch_file(
            &fetch,
            "https://x/m.bin",
            file.len() as u64,
            &sha,
            &to,
            |n| seen += n,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), file);
        assert_eq!(seen, file.len() as u64);
        let pieces = asked.lock().unwrap().clone();
        assert_eq!(pieces.len(), 3);
        assert!(pieces.iter().all(|(x, y)| y - x < PIECE as usize));
        // A file that isn't the pinned one is never written.
        std::fs::remove_file(&to).unwrap();
        let bad = fetch_file(
            &fetch,
            "https://x/m.bin",
            file.len() as u64,
            &"0".repeat(64),
            &to,
            |_| {},
        )
        .await;
        assert!(bad.is_err());
        assert!(!to.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
