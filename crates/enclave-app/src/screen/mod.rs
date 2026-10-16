//! Sharing the screen in a video call (`docs/11-calls.md` §8.3): the
//! screen's pictures, fitted into [`SCREEN_WIDTH`] × [`SCREEN_HEIGHT`]
//! (letterboxed, so nothing is cut off) and sent five a second in place of
//! the camera's.
//!
//! On the desktop the system shows what is shared and asks first where it
//! does (the desktop portal and PipeWire on Wayland, Windows Graphics
//! Capture, macOS's screen recording permission); on X11 the screen is
//! read directly. On phones, `enclave_platform::phone` asks for the
//! system's screen recording (Android's MediaProjection, iOS's broadcast
//! extension).

use enclave_ipc::{SCREEN_HEIGHT, SCREEN_WIDTH};

#[cfg(target_os = "linux")]
mod linux;

/// Frames a second sent while sharing (`enclave_media::callvideo::SCREEN`).
pub const FPS: u32 = 5;

/// Fit an RGBA picture into `out_w` × `out_h`, keeping its shape (black
/// bars where it doesn't fill), averaging the source pixels each output
/// pixel covers (so text shrinks legibly instead of breaking up).
pub fn contain(w: u32, h: u32, rgba: &[u8], out_w: u32, out_h: u32) -> Vec<u8> {
    let (w64, h64, ow, oh) = (
        u64::from(w),
        u64::from(h),
        u64::from(out_w),
        u64::from(out_h),
    );
    let mut out = vec![0u8; (ow * oh * 4) as usize];
    for px in out.chunks_exact_mut(4) {
        px[3] = 255;
    }
    if w64 == 0 || h64 == 0 || ow == 0 || oh == 0 || rgba.len() < (w64 * h64 * 4) as usize {
        return out;
    }
    // The scaled picture's size and place.
    let (sw, sh) = if w64 * oh > h64 * ow {
        (ow, (h64 * ow / w64).max(1))
    } else {
        ((w64 * oh / h64).max(1), oh)
    };
    let (x0, y0) = ((ow - sw) / 2, (oh - sh) / 2);
    for oy in 0..sh {
        let ya = oy * h64 / sh;
        let yb = ((oy + 1) * h64 / sh).max(ya + 1).min(h64);
        for ox in 0..sw {
            let xa = ox * w64 / sw;
            let xb = ((ox + 1) * w64 / sw).max(xa + 1).min(w64);
            // At most a 4 × 4 sample of the covered block: enough to keep
            // text readable, cheap enough for every frame.
            let (sx, sy) = (((xb - xa) / 4).max(1), ((yb - ya) / 4).max(1));
            let mut acc = [0u64; 3];
            let mut n = 0u64;
            let mut y = ya;
            while y < yb {
                let mut x = xa;
                while x < xb {
                    let i = ((y * w64 + x) * 4) as usize;
                    acc[0] += u64::from(rgba[i]);
                    acc[1] += u64::from(rgba[i + 1]);
                    acc[2] += u64::from(rgba[i + 2]);
                    n += 1;
                    x += sx;
                }
                y += sy;
            }
            let o = (((y0 + oy) * ow + x0 + ox) * 4) as usize;
            for c in 0..3 {
                out[o + c] = (acc[c] / n.max(1)) as u8;
            }
        }
    }
    out
}

/// A screen being shared: stops when dropped.
pub struct Share {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    recorder: xcap::VideoRecorder,
    #[cfg(target_os = "linux")]
    _capture: linux::Capture,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Share {
    /// Start sharing the main screen: `send` gets each fitted frame (RGBA
    /// at [`SCREEN_WIDTH`] × [`SCREEN_HEIGHT`]), at most [`FPS`] a second.
    /// On phones, `failed` hears if the system refused or stopped it later
    /// (on the desktop, refusals are this function's error).
    pub fn start(
        send: impl Fn(Vec<u8>) + Send + 'static,
        failed: impl FnOnce(String) + Send + 'static,
    ) -> Result<Self, String> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let gap = std::time::Duration::from_millis(u64::from(1000 / FPS));
        let fit =
            move |w: u32, h: u32, rgba: &[u8]| contain(w, h, rgba, SCREEN_WIDTH, SCREEN_HEIGHT);
        #[cfg(desktop)]
        drop(failed);
        #[cfg(target_os = "linux")]
        {
            let last = std::sync::Mutex::new(None::<std::time::Instant>);
            let s = std::sync::Arc::clone(&stop);
            let capture = linux::start(Box::new(move |w, h, rgba: Vec<u8>| {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(mut l) = last.lock() {
                    if l.is_some_and(|t| t.elapsed() < gap) {
                        return;
                    }
                    *l = Some(std::time::Instant::now());
                }
                send(fit(w, h, &rgba));
            }))?;
            Ok(Self {
                _capture: capture,
                stop,
            })
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            let monitors = xcap::Monitor::all().map_err(|e| e.to_string())?;
            let monitor = monitors
                .iter()
                .find(|m| m.is_primary().unwrap_or(false))
                .or(monitors.first())
                .ok_or("no screen to share")?;
            let (recorder, frames) = monitor.video_recorder().map_err(|e| e.to_string())?;
            recorder.start().map_err(|e| e.to_string())?;
            let s = std::sync::Arc::clone(&stop);
            std::thread::Builder::new()
                .name("screen-share".into())
                .spawn(move || {
                    let mut last: Option<std::time::Instant> = None;
                    while let Ok(f) = frames.recv() {
                        if s.load(Ordering::SeqCst) {
                            return;
                        }
                        // The newest frame each 200 ms; the rest are dropped.
                        if last.is_some_and(|t| t.elapsed() < gap) {
                            continue;
                        }
                        last = Some(std::time::Instant::now());
                        send(fit(f.width, f.height, &f.raw));
                    }
                })
                .map_err(|e| e.to_string())?;
            Ok(Self { recorder, stop })
        }
        #[cfg(not(desktop))]
        {
            let s = std::sync::Arc::clone(&stop);
            let last = std::sync::Mutex::new(None::<std::time::Instant>);
            enclave_platform::phone::start_screen_capture(
                move |w, h, rgba| {
                    if s.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(mut l) = last.lock() {
                        if l.is_some_and(|t| t.elapsed() < gap) {
                            return;
                        }
                        *l = Some(std::time::Instant::now());
                    }
                    send(fit(w, h, &rgba));
                },
                failed,
            );
            Ok(Self { stop })
        }
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let _ = self.recorder.stop();
        #[cfg(not(desktop))]
        enclave_platform::phone::stop_screen_capture();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wide_screen_is_letterboxed_not_cut() {
        // 4 × 1 white picture into 4 × 4: a white band across the middle.
        let white = vec![255u8; 4 * 4];
        let out = contain(4, 1, &white, 4, 4);
        assert_eq!(out.len(), 4 * 4 * 4);
        let row = |y: usize| &out[y * 16..(y + 1) * 16];
        assert!(row(0).chunks(4).all(|p| p == [0, 0, 0, 255]));
        assert!(
            row(1).chunks(4).all(|p| p == [255, 255, 255, 255])
                || row(2).chunks(4).all(|p| p == [255, 255, 255, 255])
        );
        assert!(row(3).chunks(4).all(|p| p == [0, 0, 0, 255]));
    }

    #[test]
    fn shrinking_averages() {
        // A 2 × 2 checkerboard of black and white into one pixel: grey.
        let px = [
            0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 255,
        ];
        let out = contain(2, 2, &px, 1, 1);
        assert!((120..=135).contains(&out[0]), "{}", out[0]);
        assert_eq!(out[3], 255);
    }
}
