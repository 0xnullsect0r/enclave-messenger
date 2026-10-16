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
/// Start the camera for a video call: about 15 colour frames a second
/// (width, height, RGB) go to `report` until the handle is dropped.
pub fn start_video(report: impl Fn(u32, u32, Vec<u8>) + Send + 'static) -> Scan {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let _ = std::thread::Builder::new()
        .name("enclave-call-camera".into())
        .spawn(move || {
            if let Err(why) = video(&flag, &report) {
                eprintln!("enclave: call camera: {why}");
            }
        });
    Scan { stop }
}

#[cfg(desktop)]
fn video(stop: &AtomicBool, report: &impl Fn(u32, u32, Vec<u8>)) -> Result<(), String> {
    let formats = [
        FrameFormat::YUYV,
        FrameFormat::NV12,
        FrameFormat::MJPEG,
        FrameFormat::RAWRGB,
        FrameFormat::GRAY,
    ];
    let mut camera = nokhwa::Camera::new(
        CameraIndex::Index(0),
        RequestedFormat::with_formats(RequestedFormatType::AbsoluteHighestFrameRate, &formats),
    )
    .map_err(|_| "No camera was found.".to_string())?;
    camera
        .open_stream()
        .map_err(|_| "The camera is busy or can't be opened.".to_string())?;
    let mut last = std::time::Instant::now() - FRAME_GAP;
    while !stop.load(Ordering::SeqCst) {
        let Ok(frame) = camera.frame() else {
            continue;
        };
        if last.elapsed() < FRAME_GAP {
            continue;
        }
        last = std::time::Instant::now();
        let res = frame.resolution();
        if let Some(px) = rgb(
            frame.source_frame_format(),
            res.width(),
            res.height(),
            frame.buffer(),
        ) {
            report(res.width(), res.height(), px);
        }
    }
    let _ = camera.stop_stream();
    Ok(())
}

/// Least time between call frames (15 a second).
#[cfg(desktop)]
const FRAME_GAP: std::time::Duration = std::time::Duration::from_millis(66);

/// RGB from Y, U and V (BT.601, video range).
fn yuv_rgb(y: u8, u: u8, v: u8) -> [u8; 3] {
    let y = 1.164 * (f32::from(y) - 16.0);
    let (u, v) = (f32::from(u) - 128.0, f32::from(v) - 128.0);
    let c = |f: f32| f.round().clamp(0.0, 255.0) as u8;
    [
        c(y + 1.596 * v),
        c(y - 0.392 * u - 0.813 * v),
        c(y + 2.017 * u),
    ]
}

#[cfg(desktop)]
/// Three bytes of colour per pixel.
fn rgb(format: FrameFormat, w: u32, h: u32, data: &[u8]) -> Option<Vec<u8>> {
    let (wu, hu) = (w as usize, h as usize);
    let n = wu.checked_mul(hu)?;
    match format {
        FrameFormat::YUYV => {
            let quads = data.get(..2 * n)?;
            let mut out = Vec::with_capacity(3 * n);
            for q in quads.chunks_exact(4) {
                out.extend_from_slice(&yuv_rgb(q[0], q[1], q[3]));
                out.extend_from_slice(&yuv_rgb(q[2], q[1], q[3]));
            }
            Some(out)
        }
        FrameFormat::NV12 => {
            let (y, uv) = (data.get(..n)?, data.get(n..n + n / 2)?);
            let mut out = Vec::with_capacity(3 * n);
            for row in 0..hu {
                for col in 0..wu {
                    let c = (row / 2) * wu + (col / 2) * 2;
                    out.extend_from_slice(&yuv_rgb(y[row * wu + col], uv[c], uv[c + 1]));
                }
            }
            Some(out)
        }
        FrameFormat::GRAY => Some(data.get(..n)?.iter().flat_map(|&g| [g, g, g]).collect()),
        FrameFormat::MJPEG => image::load_from_memory_with_format(data, image::ImageFormat::Jpeg)
            .ok()
            .map(|i| i.to_rgb8().into_raw())
            .filter(|p| p.len() == 3 * n),
        FrameFormat::RAWRGB => data.get(..3 * n).map(<[u8]>::to_vec),
        FrameFormat::RAWBGR => Some(
            data.get(..3 * n)?
                .chunks_exact(3)
                .flat_map(|p| [p[2], p[1], p[0]])
                .collect(),
        ),
    }
}

/// RGB from a phone camera's I420 frame, turned upright (`rotation`
/// degrees clockwise): width, height, pixels.
pub fn i420_rgb(w: u32, h: u32, rotation: u16, i420: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let (wu, hu) = (w as usize, h as usize);
    let (cw, ch) = (wu.div_ceil(2), hu.div_ceil(2));
    if i420.len() < wu * hu + 2 * cw * ch {
        return None;
    }
    let (y, rest) = i420.split_at(wu * hu);
    let (u, v) = rest.split_at(cw * ch);
    let (ow, oh) = if rotation % 180 == 90 { (h, w) } else { (w, h) };
    let mut out = Vec::with_capacity(wu * hu * 3);
    for oy in 0..oh as usize {
        for ox in 0..ow as usize {
            // The source pixel that lands here.
            let (sx, sy) = match rotation {
                90 => (oy, hu - 1 - ox),
                180 => (wu - 1 - ox, hu - 1 - oy),
                270 => (wu - 1 - oy, ox),
                _ => (ox, oy),
            };
            let c = (sy / 2) * cw + sx / 2;
            out.extend_from_slice(&yuv_rgb(y[sy * wu + sx], u[c], v[c]));
        }
    }
    Some((ow, oh, out))
}

/// RGBA `out_w × out_h` from an RGB frame: centred, cropped to the same
/// shape, scaled (nearest pixel), and mirrored if asked (our own preview
/// reads like a mirror; what we send doesn't).
pub fn fit(w: u32, h: u32, rgb: &[u8], out_w: u32, out_h: u32, mirror: bool) -> Vec<u8> {
    let (w64, h64) = (u64::from(w), u64::from(h));
    let (ow, oh) = (u64::from(out_w), u64::from(out_h));
    // The largest centred crop of the output's shape.
    let (cw, ch) = if w64 * oh > h64 * ow {
        (h64 * ow / oh, h64)
    } else {
        (w64, w64 * oh / ow.max(1))
    };
    let (x0, y0) = ((w64 - cw) / 2, (h64 - ch) / 2);
    let mut out = Vec::with_capacity((ow * oh * 4) as usize);
    for oy in 0..oh {
        for ox in 0..ow {
            let fx = if mirror { ow - 1 - ox } else { ox };
            let sx = x0 + fx * cw / ow.max(1);
            let sy = y0 + oy * ch / oh.max(1);
            let i = ((sy * w64 + sx) * 3) as usize;
            match rgb.get(i..i + 3) {
                Some(p) => out.extend_from_slice(&[p[0], p[1], p[2], 255]),
                None => out.extend_from_slice(&[0, 0, 0, 255]),
            }
        }
    }
    out
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
    fn call_frames_are_cropped_scaled_and_turned() {
        // A 4×2 frame, left half red, right half blue, to 2×2: the
        // centre square (columns 1 and 2), one red and one blue column.
        let mut rgb = Vec::new();
        for _ in 0..2 {
            for x in 0..4 {
                rgb.extend_from_slice(if x < 2 { &[255, 0, 0] } else { &[0, 0, 255] });
            }
        }
        let out = fit(4, 2, &rgb, 2, 2, false);
        assert_eq!(&out[..4], &[255, 0, 0, 255]);
        assert_eq!(&out[4..8], &[0, 0, 255, 255]);
        let mirrored = fit(4, 2, &rgb, 2, 2, true);
        assert_eq!(&mirrored[..4], &[0, 0, 255, 255]);
        // An I420 frame 4×2 turned 90°: 2×4.
        let mut i420 = vec![16u8; 8];
        i420[3] = 235; // top-right pixel bright
        i420.extend_from_slice(&[128; 4]);
        let (w, h, px) = i420_rgb(4, 2, 90, &i420).unwrap_or_default();
        assert_eq!((w, h), (2, 4));
        // Top-right of the original ends at the bottom-right.
        assert!(px[(3 * 2 + 1) * 3] > 200, "{px:?}");
        assert!(i420_rgb(4, 2, 0, &i420[..5]).is_none());
    }

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
