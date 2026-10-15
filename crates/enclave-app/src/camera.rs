//! Scanning codes with the camera (`docs/03-identity.md` §7): invite
//! links, in-person and link codes, and friends' recovery shares.
//!
//! A thread reads the first camera (`nokhwa`: AVFoundation, Media
//! Foundation, V4L2), takes each frame's brightness (YUYV, NV12 and grey
//! frames directly, MJPEG decoded in Rust) for the QR reader (`rqrr`) and,
//! mirrored and made small, for the preview. The first code read ends it.
//! Frames never leave this process and are never stored.
//!
//! On phones the platform captures (`enclave_platform::phone`) and only
//! [`read_qr`] and [`preview`] are used from here.

#[cfg(desktop)]
use nokhwa::utils::{CameraIndex, FrameFormat, RequestedFormat, RequestedFormatType};
#[cfg(desktop)]
use std::sync::Arc;
#[cfg(desktop)]
use std::sync::atomic::{AtomicBool, Ordering};

/// Widest preview handed to the window.
const PREVIEW_WIDTH: u32 = 480;

#[cfg(desktop)]
/// A running scan; dropping it (or [`Scan::stop`]) turns the camera off.
pub struct Scan {
    stop: Arc<AtomicBool>,
}

#[cfg(desktop)]
impl Scan {
    /// Stop scanning.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(desktop)]
impl Drop for Scan {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(desktop)]
/// What the scan thread reports.
pub enum Event {
    /// A preview frame: width, height, grey pixels.
    Frame(u32, u32, Vec<u8>),
    /// A code was read.
    Code(String),
    /// The camera couldn't be used (no camera, no permission).
    Failed(String),
}

#[cfg(desktop)]
/// Start scanning; `report` is called from the scan thread.
pub fn start(report: impl Fn(Event) + Send + 'static) -> Scan {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let _ = std::thread::Builder::new()
        .name("enclave-camera".into())
        .spawn(move || {
            if let Err(why) = run(&flag, &report) {
                report(Event::Failed(why));
            }
        });
    Scan { stop }
}

#[cfg(desktop)]
fn run(stop: &AtomicBool, report: &impl Fn(Event)) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // The system asks the person the first time.
        let (tx, rx) = std::sync::mpsc::channel();
        nokhwa::nokhwa_initialize(move |ok| {
            let _ = tx.send(ok);
        });
        if !rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .unwrap_or(false)
        {
            return Err("Enclave may not use the camera. Allow it in System Settings → Privacy & Security → Camera.".into());
        }
    }
    let formats = [
        FrameFormat::YUYV,
        FrameFormat::NV12,
        FrameFormat::GRAY,
        FrameFormat::MJPEG,
        FrameFormat::RAWRGB,
    ];
    let mut camera = nokhwa::Camera::new(
        CameraIndex::Index(0),
        RequestedFormat::with_formats(RequestedFormatType::AbsoluteHighestFrameRate, &formats),
    )
    .map_err(|_| "No camera was found.".to_string())?;
    camera
        .open_stream()
        .map_err(|_| "The camera is busy or can't be opened.".to_string())?;
    while !stop.load(Ordering::SeqCst) {
        let Ok(frame) = camera.frame() else {
            continue;
        };
        let res = frame.resolution();
        let Some(grey) = brightness(
            frame.source_frame_format(),
            res.width(),
            res.height(),
            frame.buffer(),
        ) else {
            continue;
        };
        let (w, h) = (res.width(), res.height());
        if let Some(code) = read_qr(w, h, &grey) {
            report(Event::Code(code));
            break;
        }
        let (pw, ph, preview) = preview(w, h, &grey, true);
        report(Event::Frame(pw, ph, preview));
    }
    let _ = camera.stop_stream();
    Ok(())
}

#[cfg(desktop)]
/// One byte of brightness per pixel.
fn brightness(format: FrameFormat, w: u32, h: u32, data: &[u8]) -> Option<Vec<u8>> {
    let n = (w as usize).checked_mul(h as usize)?;
    match format {
        // Y0 U Y1 V: every other byte.
        FrameFormat::YUYV => {
            (data.len() >= 2 * n).then(|| data.iter().step_by(2).take(n).copied().collect())
        }
        // The Y plane comes first.
        FrameFormat::NV12 | FrameFormat::GRAY => data.get(..n).map(<[u8]>::to_vec),
        FrameFormat::MJPEG => image::load_from_memory_with_format(data, image::ImageFormat::Jpeg)
            .ok()
            .map(|i| i.to_luma8().into_raw())
            .filter(|g| g.len() == n),
        FrameFormat::RAWRGB | FrameFormat::RAWBGR => (data.len() >= 3 * n).then(|| {
            data.chunks_exact(3)
                .take(n)
                .map(|p| ((u16::from(p[0]) + 2 * u16::from(p[1]) + u16::from(p[2])) / 4) as u8)
                .collect()
        }),
    }
}

/// The first QR code in the frame, as text.
pub fn read_qr(w: u32, h: u32, grey: &[u8]) -> Option<String> {
    let (w, h) = (w as usize, h as usize);
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| grey[y * w + x]);
    img.detect_grids()
        .into_iter()
        .find_map(|g| g.decode().ok().map(|(_, text)| text))
}

/// A small grey preview; `mirror`ed for a camera facing the person (like
/// looking in a mirror, which makes holding a code up to it easier).
pub fn preview(w: u32, h: u32, grey: &[u8], mirror: bool) -> (u32, u32, Vec<u8>) {
    let scale = w.div_ceil(PREVIEW_WIDTH).max(1);
    let (pw, ph) = (w / scale, h / scale);
    let mut out = Vec::with_capacity((pw * ph) as usize);
    for y in 0..ph {
        for x in 0..pw {
            let sx = if mirror { w - 1 - x * scale } else { x * scale };
            out.push(grey[(y * scale * w + sx) as usize]);
        }
    }
    (pw, ph, out)
}

#[cfg(all(test, desktop))]
mod tests {
    use super::*;

    /// A code drawn with the same library the app shows codes with is read
    /// back from a grey frame, and from a YUYV one.
    #[test]
    fn reads_a_shown_code() {
        let text = "enclave:add#TESTCODE";
        let qr = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium).unwrap();
        let (size, scale, border) = (qr.size() as u32, 6u32, 4u32);
        let w = (size + 2 * border) * scale;
        let mut grey = vec![255u8; (w * w) as usize];
        for y in 0..w {
            for x in 0..w {
                let (mx, my) = (
                    (x / scale) as i32 - border as i32,
                    (y / scale) as i32 - border as i32,
                );
                if qr.get_module(mx, my) {
                    grey[(y * w + x) as usize] = 0;
                }
            }
        }
        assert_eq!(read_qr(w, w, &grey).as_deref(), Some(text));
        let yuyv: Vec<u8> = grey.iter().flat_map(|&g| [g, 128]).collect();
        let back = brightness(FrameFormat::YUYV, w, w, &yuyv).unwrap();
        assert_eq!(read_qr(w, w, &back).as_deref(), Some(text));
        let (pw, ph, p) = preview(w, w, &grey, true);
        assert_eq!(p.len(), (pw * ph) as usize);
        assert!(pw <= PREVIEW_WIDTH);
    }
}
