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

/// A video being encoded (`enclave_media::movie::VideoWriter`): in a
/// helper, or here without one (it encodes only our own frames).
pub struct VideoWrite {
    n: u32,
    at: WriteAt,
}

enum WriteAt {
    Helper(Arc<Proc>),
    Here(Option<Box<enclave_media::movie::VideoWriter>>),
}

impl VideoWrite {
    /// The next frame (RGBA at the video's size).
    pub async fn frame(&mut self, rgba: Vec<u8>) -> Result<(), String> {
        match &mut self.at {
            WriteAt::Helper(p) => p.call(MediaOp::WriterFrame(self.n), rgba).await.map(|_| ()),
            WriteAt::Here(w) => w
                .as_mut()
                .ok_or("finished")?
                .frame(&rgba)
                .map_err(|e| e.to_string()),
        }
    }

    /// More sound (48 kHz mono).
    pub async fn sound(&mut self, pcm: &[i16]) -> Result<(), String> {
        match &mut self.at {
            WriteAt::Helper(p) => p
                .call(
                    MediaOp::WriterSound(self.n),
                    pcm.iter().flat_map(|s| s.to_le_bytes()).collect(),
                )
                .await
                .map(|_| ()),
            WriteAt::Here(w) => w
                .as_mut()
                .ok_or("finished")?
                .sound(pcm)
                .map_err(|e| e.to_string()),
        }
    }

    /// The video: the file, and its size and length (ms).
    pub async fn finish(mut self) -> Result<(Vec<u8>, u32, u32, u32), String> {
        match &mut self.at {
            WriteAt::Helper(p) => {
                let p = Arc::clone(p);
                let head = match p.call(MediaOp::WriterFinish(self.n), Vec::new()).await? {
                    MediaOut::Raw(b) if b.len() == 16 => b,
                    _ => return Err("unexpected reply".into()),
                };
                let be =
                    |i: usize| u32::from_be_bytes([head[i], head[i + 1], head[i + 2], head[i + 3]]);
                let (len, w, h, ms) = (be(0) as usize, be(4), be(8), be(12));
                let mut out = Vec::with_capacity(len);
                while out.len() < len {
                    match p
                        .call(MediaOp::WriterRead(self.n, out.len() as u32), Vec::new())
                        .await?
                    {
                        MediaOut::Raw(b) if !b.is_empty() => out.extend_from_slice(&b),
                        _ => return Err("unexpected reply".into()),
                    }
                }
                Ok((out, w, h, ms))
            }
            WriteAt::Here(w) => {
                let c = w
                    .take()
                    .ok_or("finished")?
                    .finish()
                    .map_err(|e| e.to_string())?;
                Ok((c.bytes, c.width, c.height, c.duration_ms))
            }
        }
    }
}

impl Drop for VideoWrite {
    fn drop(&mut self) {
        if let WriteAt::Helper(p) = &self.at {
            let (p, n) = (Arc::clone(p), self.n);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = p.call(MediaOp::WriterDrop(n), Vec::new()).await;
                });
            }
        }
    }
}

/// A video playing, in a helper (or, in the demo only, here: other
/// people's AV1 is decoded in mediad).
pub struct VideoPlay {
    n: u32,
    at: PlayAt,
    /// Width, height, frames a second, length (ms).
    pub info: (u32, u32, u32, u32),
}

enum PlayAt {
    Helper(Arc<Proc>),
    #[cfg(feature = "demo")]
    Here(Box<enclave_media::movie::VideoPlayer>),
}

impl VideoPlay {
    /// The next `ms` of it: frames (`width × height` RGBA), the sound, and
    /// whether it ended.
    pub async fn piece(
        &mut self,
        ms: u16,
    ) -> Result<(u32, u32, Vec<Vec<u8>>, Vec<i16>, bool), String> {
        match &mut self.at {
            PlayAt::Helper(p) => {
                match p.call(MediaOp::PlayerPiece(self.n, ms), Vec::new()).await? {
                    MediaOut::Piece {
                        width,
                        height,
                        frames,
                        pcm,
                        done,
                    } => Ok((width, height, frames, pcm, done)),
                    _ => Err("unexpected reply".into()),
                }
            }
            #[cfg(feature = "demo")]
            PlayAt::Here(v) => {
                let p = v.piece(u32::from(ms)).map_err(|e| e.to_string())?;
                let (w, h) = p.frames.first().map_or((0, 0), |f| (f.width, f.height));
                Ok((
                    w,
                    h,
                    p.frames.into_iter().map(|f| f.pixels).collect(),
                    p.pcm,
                    p.done,
                ))
            }
        }
    }
}

impl Drop for VideoPlay {
    // Without `demo` a player is always in a helper.
    #[allow(irrefutable_let_patterns)]
    fn drop(&mut self) {
        if let PlayAt::Helper(p) = &self.at {
            let (p, n) = (Arc::clone(p), self.n);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = p.call(MediaOp::PlayerDrop(n), Vec::new()).await;
                });
            }
        }
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
    Here(Arc<std::sync::Mutex<HereVideo>>),
}

/// The demo's in-process video codecs: the encoder, the other person's
/// decoder, and a group call's decoders by participant.
#[cfg(feature = "demo")]
type HereVideo = (
    enclave_media::callvideo::VideoEncoder,
    enclave_media::callvideo::VideoDecoder,
    std::collections::HashMap<u32, enclave_media::callvideo::VideoDecoder>,
);

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

impl VideoCodec {
    /// Encode a shared screen (true; `enclave_media::callvideo::screen` at
    /// the call's tier) or the camera again.
    pub async fn set_screen(&self, tier: u8, on: bool) -> Result<(), String> {
        match &self.at {
            VideoAt::Helper(p) => p
                .call(MediaOp::VideoScreen(self.n, tier, on), Vec::new())
                .await
                .map(|_| ()),
            #[cfg(feature = "demo")]
            VideoAt::Here(c) => {
                use enclave_media::callvideo::VideoEncoder;
                let enc = if on {
                    VideoEncoder::screen(usize::from(tier))
                } else {
                    VideoEncoder::new(usize::from(tier))
                }
                .map_err(|e| e.to_string())?;
                c.lock().map_err(|_| "poisoned".to_string())?.0 = enc;
                Ok(())
            }
        }
    }

    /// Decode a temporal unit from one participant of a group call (its
    /// own decoder).
    pub async fn decode_from(&self, sender: u32, unit: Vec<u8>) -> Result<Option<Rgba>, String> {
        match &self.at {
            VideoAt::Helper(p) => match p
                .call(MediaOp::VideoDecodeFrom(self.n, sender), unit)
                .await?
            {
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
            VideoAt::Here(c) => {
                let mut c = c.lock().map_err(|_| "poisoned".to_string())?;
                let d = match c.2.entry(sender) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => e.insert(
                        enclave_media::callvideo::VideoDecoder::new().map_err(|e| e.to_string())?,
                    ),
                };
                d.decode(&unit).map_err(|e| e.to_string())
            }
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

impl CallCodec {
    /// The loss the other side reports hearing from us, in percent.
    pub async fn set_loss(&self, percent: u8) {
        match &self.at {
            CallAt::Helper(p) => {
                let _ = p.call(MediaOp::CallLoss(self.n, percent), Vec::new()).await;
            }
            CallAt::Here(a) => {
                if let Ok(mut a) = a.lock() {
                    a.set_loss(percent);
                }
            }
        }
    }

    /// A group call's next 20 ms: each other participant's frame decoded
    /// by its own decoder, mixed.
    pub async fn mix(&self, frames: &[(u32, CallDecode, Vec<u8>)]) -> Result<Vec<i16>, String> {
        match &self.at {
            CallAt::Helper(p) => {
                let mut b = vec![frames.len().min(255) as u8];
                for (sender, how, f) in frames.iter().take(255) {
                    b.extend_from_slice(&sender.to_be_bytes());
                    b.push(match how {
                        CallDecode::Packet => 0,
                        CallDecode::Recover => 1,
                        CallDecode::Lost => 2,
                    });
                    b.extend_from_slice(&(f.len() as u16).to_be_bytes());
                    b.extend_from_slice(f);
                }
                match p.call(MediaOp::CallMix(self.n), b).await? {
                    MediaOut::Raw(b) if b.len() == enclave_media::call::FRAME * 2 => Ok(b
                        .chunks_exact(2)
                        .map(|c| i16::from_le_bytes([c[0], c[1]]))
                        .collect()),
                    _ => Err("unexpected reply".into()),
                }
            }
            CallAt::Here(a) => {
                use enclave_media::call::Decode;
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
                a.lock()
                    .map_err(|_| "poisoned".to_string())?
                    .mix(&what)
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
                    std::collections::HashMap::new(),
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

    /// Start encoding a video `width × height` (as
    /// `enclave_media::movie::video_size` gives).
    pub async fn write_video(&self, width: u16, height: u16) -> Result<VideoWrite, String> {
        static NEXT: AtomicU32 = AtomicU32::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let Some(p) = self.procs.iter().find(|p| p.alive.load(Ordering::SeqCst)) else {
            let w = enclave_media::movie::VideoWriter::new(u32::from(width), u32::from(height))
                .map_err(|e| e.to_string())?;
            return Ok(VideoWrite {
                n,
                at: WriteAt::Here(Some(Box::new(w))),
            });
        };
        p.call(MediaOp::WriterOpen(n, width, height), Vec::new())
            .await?;
        Ok(VideoWrite {
            n,
            at: WriteAt::Helper(Arc::clone(p)),
        })
    }

    /// Get a video ready to play (frames at most `side` pixels). Without
    /// helpers, only the demo can.
    pub async fn play_video(&self, video: Vec<u8>, side: u16) -> Result<VideoPlay, String> {
        static NEXT: AtomicU32 = AtomicU32::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let Some(p) = self.procs.iter().find(|p| p.alive.load(Ordering::SeqCst)) else {
            #[cfg(feature = "demo")]
            {
                let v = enclave_media::movie::VideoPlayer::new(video, u32::from(side))
                    .map_err(|e| e.to_string())?;
                let info = v.info();
                return Ok(VideoPlay {
                    n,
                    at: PlayAt::Here(Box::new(v)),
                    info,
                });
            }
            #[cfg(not(feature = "demo"))]
            {
                let _ = (video, side);
                return Err("playing videos needs the media process".into());
            }
        };
        let mut play = VideoPlay {
            n,
            at: PlayAt::Helper(Arc::clone(p)),
            info: (0, 0, 0, 0),
        };
        for part in video.chunks(enclave_ipc::media::VIDEO_READ) {
            p.call(MediaOp::PlayerLoad(n), part.to_vec()).await?;
        }
        match p.call(MediaOp::PlayerStart(n, side), Vec::new()).await? {
            MediaOut::Raw(b) if b.len() == 16 => {
                let be = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
                play.info = (be(0), be(4), be(8), be(12));
                Ok(play)
            }
            _ => Err("unexpected reply".into()),
        }
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

    /// Ten seconds of a voice note from frame `start`, to play (empty past
    /// the end).
    pub async fn voice_piece(&self, note: Vec<u8>, start: u32) -> Result<Vec<i16>, String> {
        match self.call(MediaOp::VoicePiece(start), note).await? {
            MediaOut::Raw(b) if b.len() % 2 == 0 => Ok(b
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect()),
            _ => Err("unexpected reply".into()),
        }
    }

    /// A web page's preview, read in mediad (`url` is the page's
    /// address, for its picture's).
    pub async fn page_meta(
        &self,
        url: &str,
        page: &[u8],
    ) -> Result<enclave_media::web::PageMeta, String> {
        let url = &url.as_bytes()[..url.len().min(enclave_media::web::MAX_URL)];
        let mut b = Vec::with_capacity(2 + url.len() + page.len());
        b.extend_from_slice(&(url.len() as u16).to_be_bytes());
        b.extend_from_slice(url);
        b.extend_from_slice(&page[..page.len().min(enclave_media::web::MAX_PAGE)]);
        match self.call(MediaOp::PageMeta, b).await? {
            MediaOut::Raw(r) => {
                enclave_media::web::PageMeta::decode(&r).ok_or_else(|| "bad reply".into())
            }
            _ => Err("unexpected reply".into()),
        }
    }

    /// A GIF search's answer, read in mediad.
    pub async fn gif_hits(
        &self,
        answer: Vec<u8>,
    ) -> Result<Vec<enclave_media::web::GifHit>, String> {
        match self.call(MediaOp::GifHits, answer).await? {
            MediaOut::Raw(r) => {
                enclave_media::web::decode_hits(&r).ok_or_else(|| "bad reply".into())
            }
            _ => Err("unexpected reply".into()),
        }
    }

    /// A GIF's first frame, at most `side` pixels on the long side.
    pub async fn gif_poster(&self, gif: Vec<u8>, side: u16) -> Result<Rgba, String> {
        match self.call(MediaOp::GifPoster(side), gif).await? {
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

    /// A voice note as an Ogg Opus file, to save.
    pub async fn voice_ogg(&self, note: Vec<u8>) -> Result<Vec<u8>, String> {
        match self.call(MediaOp::VoiceOgg, note).await? {
            MediaOut::Raw(b) => Ok(b),
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
        MediaOp::VoicePiece(start) => enclave_media::voice::decode_voice_range(
            bytes,
            start,
            enclave_media::voice::CHUNK_FRAMES,
        )
        .map(|pcm| MediaOut::Raw(pcm.iter().flat_map(|s| s.to_le_bytes()).collect())),
        MediaOp::VoiceOgg => enclave_media::voice::voice_to_ogg(bytes).map(MediaOut::Raw),
        MediaOp::PageMeta => {
            let n = bytes
                .get(..2)
                .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
                .ok_or(enclave_media::MediaError::Damaged);
            n.and_then(|n| {
                let url = bytes
                    .get(2..2 + n)
                    .and_then(|u| std::str::from_utf8(u).ok())
                    .ok_or(enclave_media::MediaError::Damaged)?;
                enclave_media::web::page_meta(url, &bytes[2 + n..])
            })
            .map(|m| MediaOut::Raw(m.encode()))
        }
        MediaOp::GifHits => enclave_media::web::commons_gifs(bytes)
            .map(|h| MediaOut::Raw(enclave_media::web::encode_hits(&h))),
        MediaOp::GifPoster(side) => {
            enclave_media::web::gif_poster(bytes, u32::from(side)).map(|t| MediaOut::Rgba {
                width: t.width,
                height: t.height,
                pixels: t.pixels,
            })
        }
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
        | MediaOp::VideoClose(_)
        | MediaOp::CallMix(_)
        | MediaOp::CallLoss(..)
        | MediaOp::VideoDecodeFrom(..)
        | MediaOp::VideoScreen(..) => {
            return Err("calls go through Media::open_call and open_video".into());
        }
        // Videos keep state too (`Media::write_video`, `play_video`).
        MediaOp::WriterOpen(..)
        | MediaOp::WriterFrame(_)
        | MediaOp::WriterSound(_)
        | MediaOp::WriterFinish(_)
        | MediaOp::WriterRead(..)
        | MediaOp::WriterDrop(_)
        | MediaOp::PlayerLoad(_)
        | MediaOp::PlayerStart(..)
        | MediaOp::PlayerPiece(..)
        | MediaOp::PlayerDrop(_) => {
            return Err("videos go through Media::write_video and play_video".into());
        }
    }
    .map_err(|e| e.to_string())
}
