//! Videos in the window (`docs/15-client.md` §5.5): recording one from the
//! camera and microphone, reading one from a file with the platform's
//! decoder (`enclave_platform::video`), and playing one someone sent.
//!
//! What is recorded or read goes to the vault as frames (RGBA, 30 a
//! second) and sound (48 kHz mono); mediad encodes them as they come. A
//! file is read no faster than they are encoded ([`Out::RecordProgress`]
//! counts them), so a long one never piles up in memory. A video playing
//! comes back half a second at a time; the window shows its frames on a
//! timer, plays its sound, and asks for the next piece in time.
//!
//! [`Out::RecordProgress`]: enclave_ipc::Out::RecordProgress

use crate::AppWindow;
use enclave_ipc::{Cmd, VideoPiece};
use slint::{ComponentHandle, Image, Rgba8Pixel, SharedPixelBuffer};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Tx = tokio::sync::mpsc::UnboundedSender<Cmd>;
/// A camera frame: width, height, RGB.
type Frame = (u32, u32, Vec<u8>);

/// Longest side of a recording from the camera (it is encoded live).
const RECORD_SIDE: u32 = 480;
/// Frames sent ahead of the encoder at most while reading a file.
const AHEAD: u32 = 30;

/// Frames the vault has encoded of the video being made.
static ENCODED: AtomicU32 = AtomicU32::new(0);

/// The vault encoded this many frames of the video being made.
pub fn progress(frames: u32) {
    ENCODED.store(frames, Ordering::SeqCst);
}

/// `dw × dh` RGBA from a `sw × sh` picture of `channels` bytes a pixel
/// (3 or 4), each pixel the average of the source pixels it covers.
pub fn scale(sw: u32, sh: u32, src: &[u8], channels: usize, dw: u32, dh: u32) -> Vec<u8> {
    let (sw, sh, dw, dh) = (
        sw as usize,
        sh as usize,
        dw.max(1) as usize,
        dh.max(1) as usize,
    );
    let mut out = Vec::with_capacity(dw * dh * 4);
    if sw == 0 || sh == 0 || src.len() < sw * sh * channels {
        out.resize(dw * dh * 4, 0);
        return out;
    }
    for y in 0..dh {
        let (y0, y1) = (y * sh / dh, ((y + 1) * sh / dh).max(y * sh / dh + 1));
        for x in 0..dw {
            let (x0, x1) = (x * sw / dw, ((x + 1) * sw / dw).max(x * sw / dw + 1));
            let mut acc = [0u32; 3];
            let mut n = 0u32;
            for sy in y0..y1.min(sh) {
                for sx in x0..x1.min(sw) {
                    let p = &src[(sy * sw + sx) * channels..];
                    acc[0] += u32::from(p[0]);
                    acc[1] += u32::from(p[1]);
                    acc[2] += u32::from(p[2]);
                    n += 1;
                }
            }
            let n = n.max(1);
            out.extend_from_slice(&[
                (acc[0] / n) as u8,
                (acc[1] / n) as u8,
                (acc[2] / n) as u8,
                255,
            ]);
        }
    }
    out
}

/// The size to record at: the camera's shape, at most [`RECORD_SIDE`].
fn record_size(w: u32, h: u32) -> (u32, u32) {
    let (vw, vh) = enclave_media::movie::video_size(w, h);
    let k = (f64::from(RECORD_SIDE) / f64::from(vw.max(vh))).min(1.0);
    enclave_media::movie::video_size((f64::from(vw) * k) as u32, (f64::from(vh) * k) as u32)
}

fn image(w: u32, h: u32, rgba: &[u8]) -> Image {
    Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
        rgba, w, h,
    ))
}

fn clock(ms: u64) -> String {
    let s = ms / 1000;
    format!("{}:{:02}", s / 60, s % 60)
}

fn le(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().flat_map(|s| s.to_le_bytes()).collect()
}

/// The camera, as colour frames (width, height, RGB) to a callback, until
/// dropped.
struct Feed {
    #[cfg(desktop)]
    _scan: crate::camera::Scan,
}

impl Feed {
    fn start(report: impl Fn(u32, u32, &[u8]) + Send + 'static) -> Self {
        #[cfg(desktop)]
        {
            Self {
                _scan: crate::camera::start_video(move |w, h, rgb| report(w, h, &rgb)),
            }
        }
        #[cfg(not(desktop))]
        {
            enclave_platform::phone::start_call_camera(move |c| {
                if let enclave_platform::phone::Camera::Color(fw, fh, rot, i420) = c
                    && let Some((rw, rh, rgb)) = crate::camera::i420_rgb(fw, fh, rot, &i420)
                {
                    report(rw, rh, &rgb);
                }
            });
            Self {}
        }
    }
}

#[cfg(not(desktop))]
impl Drop for Feed {
    fn drop(&mut self) {
        enclave_platform::phone::stop_camera();
    }
}

/// A video being recorded from the camera and microphone.
pub struct Recording {
    stop: Arc<AtomicBool>,
    _feed: Feed,
    _mic: Option<crate::audio::Mic>,
    pacer: Option<std::thread::JoinHandle<()>>,
}

impl Recording {
    /// Start recording for `conversation`: a preview and the time go to
    /// the window.
    pub fn start(conversation: String, tx: Tx, ui: slint::Weak<AppWindow>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let latest: Arc<Mutex<Option<Frame>>> = Arc::default();
        let (l, w) = (Arc::clone(&latest), ui.clone());
        let shown = AtomicU32::new(0);
        let feed = Feed::start(move |fw, fh, rgb| {
            if let Ok(mut l) = l.lock() {
                *l = Some((fw, fh, rgb.to_vec()));
            }
            // A small mirrored preview, every other frame.
            if shown.fetch_add(1, Ordering::Relaxed).is_multiple_of(2) {
                let (pw, ph) = record_size(fw, fh);
                let (pw, ph) = (pw / 2, ph / 2);
                let px = crate::camera::fit(fw, fh, rgb, pw, ph, true);
                let _ =
                    w.upgrade_in_event_loop(move |ui| ui.set_record_preview(image(pw, ph, &px)));
            }
        });
        let (t, s) = (tx.clone(), Arc::clone(&started));
        let mic = crate::audio::Mic::start(move |pcm| {
            if s.load(Ordering::SeqCst) {
                let _ = t.send(Cmd::RecordSound(le(&pcm)));
            }
        })
        .ok();
        if mic.is_none() {
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_record_note(
                    crate::i18n::tr("No microphone: the video will be silent.").into(),
                );
            });
        }
        let (st, s) = (Arc::clone(&stop), Arc::clone(&started));
        let pacer = std::thread::Builder::new()
            .name("enclave-video-frames".into())
            .spawn(move || {
                let tick = Duration::from_nanos(
                    1_000_000_000 / u64::from(enclave_media::movie::VIDEO_FPS),
                );
                let mut next = Instant::now();
                let mut size = None;
                let mut frames = 0u32;
                while !st.load(Ordering::SeqCst) {
                    next += tick;
                    let now = Instant::now();
                    if next > now {
                        std::thread::sleep(next - now);
                    }
                    let Some((fw, fh, rgb)) = latest.lock().ok().and_then(|l| l.clone()) else {
                        next = Instant::now();
                        continue;
                    };
                    let (vw, vh) = *size.get_or_insert_with(|| {
                        let (vw, vh) = record_size(fw, fh);
                        let _ = tx.send(Cmd::RecordStart(
                            conversation.clone(),
                            "video".into(),
                            vw,
                            vh,
                        ));
                        s.store(true, Ordering::SeqCst);
                        (vw, vh)
                    });
                    let _ = tx.send(Cmd::RecordFrame(crate::camera::fit(
                        fw, fh, &rgb, vw, vh, false,
                    )));
                    frames += 1;
                    if frames.is_multiple_of(enclave_media::movie::VIDEO_FPS) {
                        let t = clock(
                            u64::from(frames) * 1000 / u64::from(enclave_media::movie::VIDEO_FPS),
                        );
                        let _ = ui.upgrade_in_event_loop(move |ui| ui.set_record_time(t.into()));
                    }
                    if frames >= enclave_media::movie::MAX_VIDEO_FRAMES {
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_record_note(
                                crate::i18n::tr("That's as long as a video can be.").into(),
                            );
                        });
                        break;
                    }
                }
            })
            .ok();
        Self {
            stop,
            _feed: feed,
            _mic: mic,
            pacer,
        }
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(p) = self.pacer.take() {
            let _ = p.join();
        }
    }

    /// Stop and send it with `caption`.
    pub fn finish(mut self, caption: String, tx: &Tx) {
        self.halt();
        let _ = tx.send(Cmd::RecordEnd(caption));
    }

    /// Stop and throw it away.
    pub fn cancel(mut self, tx: &Tx) {
        self.halt();
        let _ = tx.send(Cmd::RecordCancel);
    }
}

/// Read the video file at `path` with the platform's decoder and send it
/// to `conversation` with `caption`; progress and problems go to the
/// window's status line.
pub fn send_file(
    path: std::path::PathBuf,
    conversation: String,
    caption: String,
    tx: Tx,
    ui: slint::Weak<AppWindow>,
) {
    let say = move |ui: &slint::Weak<AppWindow>, text: String| {
        let _ = ui.upgrade_in_event_loop(move |ui| ui.set_status_line(text.into()));
    };
    let _ = std::thread::Builder::new()
        .name("enclave-video-file".into())
        .spawn(move || {
            use enclave_platform::video::{VideoError, VideoEvent, read_video};
            let name = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "video".into());
            ENCODED.store(0, Ordering::SeqCst);
            let (mut size, mut sent, mut total, mut full) = ((0, 0, 0, 0), 0u32, 0u64, false);
            say(&ui, crate::i18n::tr("Getting the video ready…"));
            let result = read_video(&path, &mut |e| match e {
                VideoEvent::Start {
                    width,
                    height,
                    duration_ms,
                } => {
                    let (vw, vh) = enclave_media::movie::video_size(width, height);
                    size = (width, height, vw, vh);
                    total = duration_ms.min(u64::from(enclave_media::movie::MAX_VIDEO_MS));
                    tx.send(Cmd::RecordStart(conversation.clone(), name.clone(), vw, vh))
                        .is_ok()
                }
                VideoEvent::Frame(rgba) => {
                    if sent >= enclave_media::movie::MAX_VIDEO_FRAMES {
                        full = true;
                        return false;
                    }
                    // No faster than mediad encodes.
                    while sent.saturating_sub(ENCODED.load(Ordering::SeqCst)) > AHEAD {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    let (w, h, vw, vh) = size;
                    let frame = if (w, h) == (vw, vh) {
                        rgba.to_vec()
                    } else {
                        scale(w, h, rgba, 4, vw, vh)
                    };
                    sent += 1;
                    if sent.is_multiple_of(15) && total > 0 {
                        let done =
                            u64::from(sent) * 1000 / u64::from(enclave_media::movie::VIDEO_FPS);
                        say(
                            &ui,
                            crate::i18n::tr("Getting the video ready… {}%")
                                .replace("{}", &(done * 100 / total).min(99).to_string()),
                        );
                    }
                    tx.send(Cmd::RecordFrame(frame)).is_ok()
                }
                VideoEvent::Sound(pcm) => tx.send(Cmd::RecordSound(le(pcm))).is_ok(),
            });
            match result {
                Ok(()) => {}
                Err(VideoError::Stopped) if full => {
                    say(
                        &ui,
                        crate::i18n::tr(
                            "The video was longer than 10 minutes, so only the start is sent.",
                        ),
                    );
                }
                Err(VideoError::NoDecoder) => {
                    let _ = tx.send(Cmd::RecordCancel);
                    return say(
                        &ui,
                        crate::i18n::tr(if cfg!(target_os = "linux") {
                            "This system has no video decoder. Install GStreamer to send videos."
                        } else {
                            "This system can't read videos."
                        }),
                    );
                }
                Err(_) => {
                    let _ = tx.send(Cmd::RecordCancel);
                    return say(
                        &ui,
                        crate::i18n::tr("Enclave couldn't read that video. Try another file."),
                    );
                }
            }
            if sent == 0 {
                let _ = tx.send(Cmd::RecordCancel);
                return say(
                    &ui,
                    crate::i18n::tr("Enclave couldn't read that video. Try another file."),
                );
            }
            say(&ui, String::new());
            let _ = tx.send(Cmd::RecordEnd(caption));
        });
}

/// The video playing in the player sheet.
struct Player {
    key: String,
    fps: u32,
    duration_ms: u32,
    frames: VecDeque<(u32, u32, Vec<u8>)>,
    sound: Option<crate::audio::Playback>,
    shown: u32,
    asked: bool,
    done: bool,
    timer: slint::Timer,
}

thread_local! {
    static PLAYER: std::cell::RefCell<Option<Player>> = const { std::cell::RefCell::new(None) };
}

/// A piece of the video playing: the first starts the player.
pub fn piece(ui: &AppWindow, p: VideoPiece, tx: &Tx) {
    let sizes = (p.width, p.height);
    let frames = p.frames.into_iter().map(|f| (sizes.0, sizes.1, f));
    let started = PLAYER.with(|cell| {
        let mut cell = cell.borrow_mut();
        if !p.first {
            let Some(pl) = cell.as_mut().filter(|pl| pl.key == p.key) else {
                return false;
            };
            pl.frames.extend(frames);
            if let Some(s) = &pl.sound {
                s.extend(&p.pcm);
            }
            pl.asked = false;
            pl.done = p.done;
            return false;
        }
        let sound = if p.pcm.is_empty() {
            None
        } else {
            crate::audio::Playback::start(p.pcm.clone(), || {}).ok()
        };
        *cell = Some(Player {
            key: p.key.clone(),
            fps: p.fps.clamp(1, 60),
            duration_ms: p.duration_ms,
            frames: frames.collect(),
            sound,
            shown: 0,
            asked: false,
            done: p.done,
            timer: slint::Timer::default(),
        });
        true
    });
    if !started {
        return;
    }
    ui.set_video_has_frame(false);
    ui.set_video_time("".into());
    ui.set_player_frames(slint::ModelRc::default());
    ui.set_sheet(crate::Sheet::Player);
    let (w, t) = (ui.as_weak(), tx.clone());
    PLAYER.with(|cell| {
        if let Some(pl) = cell.borrow().as_ref() {
            let every = Duration::from_millis(u64::from(1000 / pl.fps));
            pl.timer.start(slint::TimerMode::Repeated, every, move || {
                let Some(ui) = w.upgrade() else { return };
                PLAYER.with(|cell| {
                    let mut cell = cell.borrow_mut();
                    let Some(pl) = cell.as_mut() else { return };
                    if let Some((fw, fh, px)) = pl.frames.pop_front() {
                        ui.set_video_frame(image(fw, fh, &px));
                        ui.set_video_has_frame(true);
                        pl.shown += 1;
                        let at = u64::from(pl.shown) * 1000 / u64::from(pl.fps);
                        ui.set_video_time(
                            format!("{} / {}", clock(at), clock(u64::from(pl.duration_ms))).into(),
                        );
                    }
                    if !pl.done && !pl.asked && pl.frames.len() < (pl.fps / 2) as usize {
                        pl.asked = true;
                        let _ = t.send(Cmd::VideoMore(pl.key.clone()));
                    }
                    if pl.done && pl.frames.is_empty() {
                        pl.timer.stop();
                    }
                });
            });
        }
    });
}

/// Stop the video playing (the sheet closed).
pub fn stop(tx: &Tx) {
    let was = PLAYER.with(|cell| cell.borrow_mut().take().is_some());
    if was {
        let _ = tx.send(Cmd::StopVideo);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaled_by_area() {
        // 4 × 2 RGB, left half red, right half blue → 2 × 1.
        let src: Vec<u8> = (0..8)
            .flat_map(|i| if i % 4 < 2 { [200, 0, 0] } else { [0, 0, 100] })
            .collect();
        let out = scale(4, 2, &src, 3, 2, 1);
        assert_eq!(out, vec![200, 0, 0, 255, 0, 0, 100, 255]);
        assert_eq!(record_size(1280, 720), (480, 268));
        assert_eq!(record_size(320, 240), (320, 240));
    }
}
