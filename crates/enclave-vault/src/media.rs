//! The vault's side of `mediad` (`docs/15-client.md` §1.1a).
//!
//! Pictures are decoded and re-encoded in `enclave-mediad`, a confined
//! process with no keys, no files and no sockets, started (like netd)
//! before the vault confines itself. Where it is missing, the same code runs
//! in the vault on a blocking thread and the hardening report says so.

use enclave_ipc::frame;
use enclave_ipc::media::{MediaOp, MediaOut, MediaReply, MediaRequest};
use enclave_media::{Format, Rgba, Sanitized};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc, oneshot};

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Result<MediaOut, String>>>>>;

/// Spare `mediad` processes started with the first: the vault can't start
/// programs once it is confined, so a helper that dies (a picture that
/// crashes the decoder, say) is replaced by a spare that is already
/// running. When all are gone, pictures fail until the app restarts.
pub const SPARES: usize = 2;

/// Where pictures are handled.
pub struct Media {
    /// The helpers, first live one used; empty means in this process.
    procs: Vec<Arc<Proc>>,
}

struct Proc {
    next: AtomicU32,
    out: mpsc::UnboundedSender<Vec<u8>>,
    pending: Pending,
    alive: Arc<AtomicBool>,
    /// Ends the helper when dropped.
    _child: Box<dyn Send + Sync>,
}

/// Where `enclave-mediad` should be: next to this executable (or linked
/// into it, where helpers run as threads: `enclave_platform::process`).
pub fn mediad_binary() -> Option<std::path::PathBuf> {
    if enclave_platform::process::registered("enclave-mediad") {
        return Some("enclave-mediad".into());
    }
    let exe = std::env::current_exe().ok()?;
    let p = exe.with_file_name(format!("enclave-mediad{}", std::env::consts::EXE_SUFFIX));
    p.exists().then_some(p)
}

impl Proc {
    fn spawn(bin: &std::path::Path) -> std::io::Result<Self> {
        // A thread of this process where the helpers are linked in.
        if let Some(p) = enclave_platform::process::start("enclave-mediad", Vec::new())? {
            let (w, r) = enclave_ipc::stdio::pipes(p);
            return Ok(Self::run(w, r, Box::new(())));
        }
        // Windows: in an AppContainer with no capabilities (no network, no
        // files of the user's), where the program is readable by it (an
        // installed build); otherwise as an ordinary process.
        #[cfg(windows)]
        if let Ok(c) =
            enclave_platform::appcontainer::spawn(bin, &[], "com.aricummings.Enclave.mediad")
        {
            let stdin = tokio::fs::File::from_std(c.stdin.try_clone()?);
            let stdout = tokio::fs::File::from_std(c.stdout.try_clone()?);
            return Ok(Self::run(stdin, stdout, Box::new(c)));
        }
        let mut cmd = Command::new(bin);
        enclave_platform::process::no_window(cmd.as_std_mut());
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        Ok(Self::run(stdin, stdout, Box::new(Mutex::new(child))))
    }

    /// Talk to a started helper over its stdin and stdout.
    fn run(
        mut stdin: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
        mut stdout: impl tokio::io::AsyncRead + Unpin + Send + 'static,
        child: Box<dyn Send + Sync>,
    ) -> Self {
        let (out, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        tokio::spawn(async move {
            while let Some(body) = rx.recv().await {
                if frame::write_frame(&mut stdin, &body).await.is_err() {
                    break;
                }
            }
        });
        let p = Arc::clone(&pending);
        let a = Arc::clone(&alive);
        tokio::spawn(async move {
            while let Ok(body) = frame::read_frame(&mut stdout).await {
                let Ok(reply) = MediaReply::decode(&body) else {
                    break;
                };
                if let Some(tx) = p.lock().await.remove(&reply.id) {
                    let _ = tx.send(reply.result);
                }
            }
            // This helper stopped: what was waiting on it fails, and the
            // next call goes to a spare.
            a.store(false, Ordering::SeqCst);
            p.lock().await.clear();
        });
        Self {
            next: AtomicU32::new(1),
            out,
            pending,
            alive,
            _child: child,
        }
    }
}

impl Proc {
    async fn call(&self, op: MediaOp, bytes: Vec<u8>) -> Result<MediaOut, String> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        // The reader marks a helper dead before failing what's pending, so
        // a request added after that is caught here instead of waiting
        // forever.
        if !self.alive.load(Ordering::SeqCst) {
            self.pending.lock().await.remove(&id);
            return Err("mediad stopped".into());
        }
        if self
            .out
            .send(MediaRequest { id, op, bytes }.encode())
            .is_err()
        {
            self.alive.store(false, Ordering::SeqCst);
            return Err("mediad stopped".into());
        }
        rx.await.map_err(|_| "mediad stopped".to_string())?
    }
}

/// One call's audio: its encoder, decoder and echo canceller live in one
/// helper (or, without helpers, here) until it is dropped.
pub struct CallCodec {
    n: u32,
    at: CallAt,
}

enum CallAt {
    Helper(Arc<Proc>),
    Here(Arc<std::sync::Mutex<enclave_media::call::CallAudio>>),
}

/// One call's video: its encoder and decoder live in one helper,
/// another than the call's audio where there are two, so encoding a frame
/// never holds up the audio.
pub struct VideoCodec {
    n: u32,
    at: VideoAt,
}

enum VideoAt {
    Helper(Arc<Proc>),
    #[cfg(feature = "demo")]
    Here(
        Arc<
            std::sync::Mutex<(
                enclave_media::callvideo::VideoEncoder,
                enclave_media::callvideo::VideoDecoder,
            )>,
        >,
    ),
}

impl VideoCodec {
    /// Encode a camera frame (RGBA at the tier's size): the temporal units.
    pub async fn encode(&self, rgba: Vec<u8>, key: bool) -> Result<Vec<Vec<u8>>, String> {
        match &self.at {
            VideoAt::Helper(p) => match p.call(MediaOp::VideoEncode(self.n, key), rgba).await? {
                MediaOut::Raw(b) => {
                    let mut units = Vec::new();
                    let mut at = 0;
                    while at + 4 <= b.len() {
                        let n =
                            u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize;
                        let unit = b.get(at + 4..at + 4 + n).ok_or("bad reply")?;
                        units.push(unit.to_vec());
                        at += 4 + n;
                    }
                    Ok(units)
                }
                _ => Err("unexpected reply".into()),
            },
            #[cfg(feature = "demo")]
            VideoAt::Here(c) => c
                .lock()
                .map_err(|_| "poisoned".to_string())?
                .0
                .encode(&rgba, key)
                .map_err(|e| e.to_string()),
        }
    }

    /// Decode a temporal unit: the picture it completed, if any.
    pub async fn decode(&self, unit: Vec<u8>) -> Result<Option<Rgba>, String> {
        match &self.at {
            VideoAt::Helper(p) => match p.call(MediaOp::VideoDecode(self.n), unit).await? {
                MediaOut::Rgba {
                    width,
                    height,
                    pixels,
                } => Ok(Some(Rgba {
                    width,
                    height,
                    pixels,
                })),
                MediaOut::Raw(_) => Ok(None),
                _ => Err("unexpected reply".into()),
            },
            #[cfg(feature = "demo")]
            VideoAt::Here(c) => c
                .lock()
                .map_err(|_| "poisoned".to_string())?
                .1
                .decode(&unit)
                .map_err(|e| e.to_string()),
        }
    }
}

impl Drop for VideoCodec {
    // Refutable only with the demo's in-process codec.
    #[allow(irrefutable_let_patterns)]
    fn drop(&mut self) {
        if let VideoAt::Helper(p) = &self.at {
            let _ = p.out.send(
                MediaRequest {
                    id: 0,
                    op: MediaOp::VideoClose(self.n),
                    bytes: Vec::new(),
                }
                .encode(),
            );
        }
    }
}

/// How [`CallCodec::decode`] takes its bytes.
pub use enclave_ipc::media::CallDecode;

impl CallCodec {
    /// The microphone's next 20 ms (960 samples) to an Opus frame.
    pub async fn encode(&self, mic: &[i16]) -> Result<Vec<u8>, String> {
        match &self.at {
            CallAt::Helper(p) => {
                let pcm: Vec<u8> = mic.iter().flat_map(|s| s.to_le_bytes()).collect();
                match p.call(MediaOp::CallEncode(self.n), pcm).await? {
                    MediaOut::Raw(b) => Ok(b),
                    _ => Err("unexpected reply".into()),
                }
            }
            CallAt::Here(a) => a
                .lock()
                .map_err(|_| "poisoned".to_string())?
                .encode(mic)
                .map_err(|e| e.to_string()),
        }
    }

    /// The next 20 ms to play.
    pub async fn decode(&self, how: CallDecode, bytes: &[u8]) -> Result<Vec<i16>, String> {
        match &self.at {
            CallAt::Helper(p) => {
                match p
                    .call(MediaOp::CallDecode(self.n, how), bytes.to_vec())
                    .await?
                {
                    MediaOut::Raw(b) if b.len() == enclave_media::call::FRAME * 2 => Ok(b
                        .chunks_exact(2)
                        .map(|c| i16::from_le_bytes([c[0], c[1]]))
                        .collect()),
                    _ => Err("unexpected reply".into()),
                }
            }
            CallAt::Here(a) => {
                use enclave_media::call::Decode;
                let what = match how {
                    CallDecode::Packet => Decode::Packet(bytes),
                    CallDecode::Recover => Decode::Recover(bytes),
                    CallDecode::Lost => Decode::Lost,
                };
                a.lock()
                    .map_err(|_| "poisoned".to_string())?
                    .decode(what)
                    .map_err(|e| e.to_string())
            }
        }
    }
}

impl Drop for CallCodec {
    fn drop(&mut self) {
        if let CallAt::Helper(p) = &self.at {
            // No one waits for the answer (id 0 is never pending).
            let _ = p.out.send(
                MediaRequest {
                    id: 0,
                    op: MediaOp::CallClose(self.n),
                    bytes: Vec::new(),
                }
                .encode(),
            );
        }
    }
}

impl Media {
    /// Decode in this process (demo, tests, or no mediad).
    pub fn in_process() -> Self {
        Self { procs: Vec::new() }
    }

    /// Whether pictures are handled by a separate process.
    pub fn separate(&self) -> bool {
        !self.procs.is_empty()
    }

    /// Helpers still running.
    pub fn alive(&self) -> usize {
        self.procs
            .iter()
            .filter(|p| p.alive.load(Ordering::SeqCst))
            .count()
    }

    /// Start `mediad` and `spares` more. Must run inside a tokio runtime,
    /// before the vault confines itself.
    pub fn spawn(bin: &std::path::Path, spares: usize) -> std::io::Result<Self> {
        let bins = vec![bin.to_path_buf(); spares + 1];
        Self::spawn_each(&bins)
    }

    /// Start one helper per program, in order of use (the first must start;
    /// a spare that doesn't is skipped). `spawn` uses the same program for
    /// all; tests use this to start a helper that dies at once.
    pub fn spawn_each(bins: &[std::path::PathBuf]) -> std::io::Result<Self> {
        let (first, rest) = bins
            .split_first()
            .ok_or_else(|| std::io::Error::other("no helper"))?;
        let mut procs = vec![Arc::new(Proc::spawn(first)?)];
        procs.extend(
            rest.iter()
                .filter_map(|b| Proc::spawn(b).ok())
                .map(Arc::new),
        );
        Ok(Self { procs })
    }

    async fn call(&self, op: MediaOp, bytes: Vec<u8>) -> Result<MediaOut, String> {
        if self.procs.is_empty() {
            return tokio::task::spawn_blocking(move || local(op, &bytes))
                .await
                .map_err(|_| "the decoder stopped".to_string())?;
        }
        let Some(p) = self.procs.iter().find(|p| p.alive.load(Ordering::SeqCst)) else {
            return Err("mediad stopped".into());
        };
        p.call(op, bytes).await
    }

    /// Start a call's video at a tier. Without helpers, only the demo
    /// can (decoding other people's video happens in mediad only).
    pub async fn open_video(&self, tier: u8) -> Result<VideoCodec, String> {
        static NEXT: AtomicU32 = AtomicU32::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        if self.procs.is_empty() {
            #[cfg(feature = "demo")]
            {
                use enclave_media::callvideo::{VideoDecoder, VideoEncoder};
                let codec = (
                    VideoEncoder::new(usize::from(tier)).map_err(|e| e.to_string())?,
                    VideoDecoder::new().map_err(|e| e.to_string())?,
                );
                return Ok(VideoCodec {
                    n,
                    at: VideoAt::Here(Arc::new(std::sync::Mutex::new(codec))),
                });
            }
            #[cfg(not(feature = "demo"))]
            return Err("video needs the media process".into());
        }
        let alive: Vec<&Arc<Proc>> = self
            .procs
            .iter()
            .filter(|p| p.alive.load(Ordering::SeqCst))
            .collect();
        // The audio takes the last; video the one before it.
        let p = alive
            .len()
            .checked_sub(2)
            .and_then(|i| alive.get(i))
            .or_else(|| alive.last())
            .ok_or("mediad stopped")?;
        p.call(MediaOp::VideoOpen(n, tier), Vec::new()).await?;
        Ok(VideoCodec {
            n,
            at: VideoAt::Helper(Arc::clone(p)),
        })
    }

    /// Start a call's audio (`enclave_media::call`). It goes to the last
    /// helper still running, so pictures (on the first) don't hold up its
    /// frames; with one helper they share it.
    pub async fn open_call(&self) -> Result<CallCodec, String> {
        static NEXT: AtomicU32 = AtomicU32::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        if self.procs.is_empty() {
            let audio = enclave_media::call::CallAudio::new().map_err(|e| e.to_string())?;
            return Ok(CallCodec {
                n,
                at: CallAt::Here(Arc::new(std::sync::Mutex::new(audio))),
            });
        }
        let p = self
            .procs
            .iter()
            .rev()
            .find(|p| p.alive.load(Ordering::SeqCst))
            .ok_or("mediad stopped")?;
        p.call(MediaOp::CallOpen(n), Vec::new()).await?;
        Ok(CallCodec {
            n,
            at: CallAt::Helper(Arc::clone(p)),
        })
    }

    /// Re-encode a picture for sending.
    pub async fn sanitize(&self, bytes: Vec<u8>) -> Result<Sanitized, String> {
        match self.call(MediaOp::Sanitize, bytes).await? {
            MediaOut::Sanitized {
                png,
                width,
                height,
                bytes,
            } => Ok(Sanitized {
                format: if png { Format::Png } else { Format::Jpeg },
                width,
                height,
                bytes,
            }),
            _ => Err("unexpected reply".into()),
        }
    }

    /// Re-encode a picture at most `side` pixels on the long side (a sticker).
    pub async fn shrink(&self, bytes: Vec<u8>, side: u16) -> Result<Sanitized, String> {
        match self.call(MediaOp::Shrink(side), bytes).await? {
            MediaOut::Sanitized {
                png,
                width,
                height,
                bytes,
            } => Ok(Sanitized {
                format: if png { Format::Png } else { Format::Jpeg },
                width,
                height,
                bytes,
            }),
            _ => Err("unexpected reply".into()),
        }
    }

    /// A WAV recording as a voice note: (note, duration ms, waveform).
    pub async fn voice_note(&self, wav: Vec<u8>) -> Result<(Vec<u8>, u32, Vec<u8>), String> {
        match self.call(MediaOp::VoiceNote, wav).await? {
            MediaOut::Audio {
                duration_ms,
                waveform,
                bytes,
            } => Ok((bytes, duration_ms, waveform)),
            _ => Err("unexpected reply".into()),
        }
    }

    /// A voice note's duration (ms) and waveform, after checking it.
    pub async fn voice_info(&self, note: Vec<u8>) -> Result<(u32, Vec<u8>), String> {
        match self.call(MediaOp::VoiceInfo, note).await? {
            MediaOut::Audio {
                duration_ms,
                waveform,
                ..
            } => Ok((duration_ms, waveform)),
            _ => Err("unexpected reply".into()),
        }
    }

    /// A voice note decoded to a WAV file.
    pub async fn voice_wav(&self, note: Vec<u8>) -> Result<Vec<u8>, String> {
        match self.call(MediaOp::VoiceWav, note).await? {
            MediaOut::Audio { bytes, .. } => Ok(bytes),
            _ => Err("unexpected reply".into()),
        }
    }

    /// Our animated GIF as a clip: (clip, width, height, length in ms).
    pub async fn clip(&self, gif: Vec<u8>) -> Result<(Vec<u8>, u32, u32, u32), String> {
        match self.call(MediaOp::Clip, gif).await? {
            MediaOut::Clip {
                width,
                height,
                duration_ms,
                bytes,
                ..
            } => Ok((bytes, width, height, duration_ms)),
            _ => Err("unexpected reply".into()),
        }
    }

    /// A clip's poster at most `side` pixels, and its length in ms.
    pub async fn clip_poster(&self, clip: Vec<u8>, side: u16) -> Result<(Rgba, u32), String> {
        match self.call(MediaOp::ClipPoster(side), clip).await? {
            MediaOut::Clip {
                width,
                height,
                duration_ms,
                mut frames,
                ..
            } if frames.len() == 1 => Ok((
                Rgba {
                    width,
                    height,
                    pixels: frames.remove(0),
                },
                duration_ms,
            )),
            _ => Err("unexpected reply".into()),
        }
    }

    /// A clip's frames for playing, and its length in ms.
    pub async fn clip_frames(&self, clip: Vec<u8>, side: u16) -> Result<(Vec<Rgba>, u32), String> {
        match self.call(MediaOp::ClipFrames(side), clip).await? {
            MediaOut::Clip {
                width,
                height,
                duration_ms,
                frames,
                ..
            } => Ok((
                frames
                    .into_iter()
                    .map(|pixels| Rgba {
                        width,
                        height,
                        pixels,
                    })
                    .collect(),
                duration_ms,
            )),
            _ => Err("unexpected reply".into()),
        }
    }

    /// Decode a picture to at most `side` pixels on the long side.
    pub async fn thumbnail(&self, bytes: Vec<u8>, side: u16) -> Result<Rgba, String> {
        match self.call(MediaOp::Thumbnail(side), bytes).await? {
            MediaOut::Rgba {
                width,
                height,
                pixels,
            } => Ok(Rgba {
                width,
                height,
                pixels,
            }),
            _ => Err("unexpected reply".into()),
        }
    }
}

fn local(op: MediaOp, bytes: &[u8]) -> Result<MediaOut, String> {
    match op {
        MediaOp::Sanitize => enclave_media::sanitize(bytes).map(|s| MediaOut::Sanitized {
            png: s.format == Format::Png,
            width: s.width,
            height: s.height,
            bytes: s.bytes,
        }),
        MediaOp::VoiceNote => enclave_media::voice::voice_note_from_wav(bytes).and_then(|note| {
            let info = enclave_media::voice::voice_info(&note)?;
            Ok(MediaOut::Audio {
                duration_ms: info.duration_ms,
                waveform: info.waveform,
                bytes: note,
            })
        }),
        MediaOp::VoiceInfo => enclave_media::voice::voice_info(bytes).map(|i| MediaOut::Audio {
            duration_ms: i.duration_ms,
            waveform: i.waveform,
            bytes: Vec::new(),
        }),
        MediaOp::VoiceWav => enclave_media::voice::voice_info(bytes).and_then(|i| {
            Ok(MediaOut::Audio {
                duration_ms: i.duration_ms,
                waveform: i.waveform,
                bytes: enclave_media::voice::voice_to_wav(bytes)?,
            })
        }),
        MediaOp::Shrink(side) => {
            enclave_media::sanitize_max(bytes, u32::from(side)).map(|s| MediaOut::Sanitized {
                png: s.format == Format::Png,
                width: s.width,
                height: s.height,
                bytes: s.bytes,
            })
        }
        MediaOp::Thumbnail(side) => {
            enclave_media::thumbnail(bytes, u32::from(side)).map(|t| MediaOut::Rgba {
                width: t.width,
                height: t.height,
                pixels: t.pixels,
            })
        }
        // Our own GIF, and a poster JPEG: the ordinary picture path.
        MediaOp::Clip => enclave_media::video::clip_from_gif(bytes).map(|c| MediaOut::Clip {
            width: c.width,
            height: c.height,
            duration_ms: c.duration_ms,
            bytes: c.bytes,
            frames: Vec::new(),
        }),
        MediaOp::ClipPoster(side) => {
            enclave_media::video::clip_poster(bytes, u32::from(side)).map(|(img, ms)| {
                MediaOut::Clip {
                    width: img.width,
                    height: img.height,
                    duration_ms: ms,
                    bytes: Vec::new(),
                    frames: vec![img.pixels],
                }
            })
        }
        // Other people's AV1 is decoded in mediad only, never in the vault.
        MediaOp::ClipFrames(_) => return Err("playing clips needs the media process".into()),
        // Calls keep state (`Media::open_call`).
        MediaOp::CallOpen(_)
        | MediaOp::CallEncode(_)
        | MediaOp::CallDecode(..)
        | MediaOp::CallClose(_)
        | MediaOp::VideoOpen(..)
        | MediaOp::VideoEncode(..)
        | MediaOp::VideoDecode(_)
        | MediaOp::VideoClose(_) => {
            return Err("calls go through Media::open_call and open_video".into());
        }
    }
    .map_err(|e| e.to_string())
}
