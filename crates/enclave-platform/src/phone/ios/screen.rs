//! Sharing the screen on iOS (`docs/11-calls.md` §8.3): iOS records the
//! whole screen only in a broadcast upload extension
//! (`apps/ios/broadcast`), which the system's broadcast picker starts. The
//! app shows the picker; the extension leaves each picture (five a second,
//! 960 × 540) in a file in the app group's container, which this reads; a
//! `screen.stop` file there tells the extension to finish.

use super::{key_window, mtm};
use crate::phone::{ScreenFailed, ScreenFrames};
use objc2::msg_send;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject};
use objc2_foundation::{NSFileManager, NSString};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// RPSystemBroadcastPickerView, reached through the runtime.
#[link(name = "ReplayKit", kind = "framework")]
unsafe extern "C" {}

/// The app group the app and the extension share (as the notification
/// extension's, `keystore::shared::APP_GROUP`).
const APP_GROUP: &str = "group.com.aricummings.enclave";
/// The extension's bundle id (the picker offers only it).
const EXTENSION: &str = "com.aricummings.enclave.broadcast";
/// A picker's view tag, to take it away again.
const PICKER: isize = 0x0e5c;
/// How long to wait for the person to start the broadcast.
const START_LIMIT: Duration = Duration::from_secs(60);

/// Bumped on each start and stop: an older reader stops.
static RUN: AtomicU64 = AtomicU64::new(0);
/// The picker on the window while sharing.
static SHOWN: Mutex<bool> = Mutex::new(false);

fn container() -> Option<PathBuf> {
    let fm = NSFileManager::defaultManager();
    let url =
        fm.containerURLForSecurityApplicationGroupIdentifier(&NSString::from_str(APP_GROUP))?;
    Some(PathBuf::from(url.path()?.to_string()))
}

/// Put the system's broadcast picker on the window and press it: iOS asks
/// the person to start the broadcast.
fn show_picker() {
    let (Some(mtm), Some(cls)) = (mtm(), AnyClass::get(c"RPSystemBroadcastPickerView")) else {
        return;
    };
    let Some(window) = key_window(mtm) else {
        return;
    };
    // SAFETY: UIKit calls on the main thread (`mtm`) with the selectors and
    // argument types RPSystemBroadcastPickerView and UIView declare.
    unsafe {
        let picker: Retained<AnyObject> = msg_send![cls, new];
        let ext = NSString::from_str(EXTENSION);
        let _: () = msg_send![&*picker, setPreferredExtension: &*ext];
        let _: () = msg_send![&*picker, setShowsMicrophoneButton: false];
        let _: () = msg_send![&*picker, setTag: PICKER];
        let _: () = msg_send![&*window, addSubview: &*picker];
        let views: Retained<objc2_foundation::NSArray<AnyObject>> = msg_send![&*picker, subviews];
        let Some(button_class) = AnyClass::get(c"UIButton") else {
            return;
        };
        for v in views.iter() {
            let is_button: bool = msg_send![&*v, isKindOfClass: button_class];
            if is_button {
                // UIControlEventTouchUpInside.
                let _: () = msg_send![&*v, sendActionsForControlEvents: 1u64 << 6];
            }
        }
    }
    if let Ok(mut s) = SHOWN.lock() {
        *s = true;
    }
}

fn hide_picker() {
    let Some(mtm) = mtm() else { return };
    if let Some(window) = key_window(mtm)
        && let Some(v) = window.viewWithTag(PICKER)
    {
        v.removeFromSuperview();
    }
    if let Ok(mut s) = SHOWN.lock() {
        *s = false;
    }
}

pub(in crate::phone) fn start_screen_capture(mut frame: ScreenFrames, failed: ScreenFailed) {
    let Some(dir) = container() else {
        return failed("Screen sharing isn't set up in this build.".into());
    };
    let _ = std::fs::remove_file(dir.join("screen.stop"));
    let _ = std::fs::remove_file(dir.join("screen.frame"));
    let _ = std::fs::write(dir.join("screen.state"), b"");
    let run = RUN.fetch_add(1, Ordering::SeqCst) + 1;
    dispatch2::DispatchQueue::main().exec_async(show_picker);
    std::thread::spawn(move || {
        let started_at = Instant::now();
        let (mut started, mut last) = (false, 0u32);
        let mut failed = Some(failed);
        let mut fail = |why: &str| {
            if let Some(f) = failed.take() {
                f(why.into());
            }
        };
        while RUN.load(Ordering::SeqCst) == run {
            std::thread::sleep(Duration::from_millis(100));
            let state = std::fs::read(dir.join("screen.state")).unwrap_or_default();
            match state.as_slice() {
                b"on" => started = true,
                b"off" if started => {
                    // Stopped from the system's controls.
                    fail("");
                    break;
                }
                _ if !started && started_at.elapsed() > START_LIMIT => {
                    fail("Screen sharing didn't start.");
                    break;
                }
                _ => {}
            }
            let Ok(b) = std::fs::read(dir.join("screen.frame")) else {
                continue;
            };
            if b.len() < 16 || &b[..4] != b"ENSC" {
                continue;
            }
            let word = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
            let (seq, w, h) = (word(4), word(8), word(12));
            if seq == last || w == 0 || h == 0 || b.len() != 16 + (w as usize) * (h as usize) * 4 {
                continue;
            }
            last = seq;
            let rgba = b[16..]
                .chunks_exact(4)
                .flat_map(|p| [p[2], p[1], p[0], 255])
                .collect();
            frame(w, h, rgba);
        }
        dispatch2::DispatchQueue::main().exec_async(hide_picker);
    });
}

pub(in crate::phone) fn stop_screen_capture() {
    RUN.fetch_add(1, Ordering::SeqCst);
    if let Some(dir) = container() {
        let _ = std::fs::write(dir.join("screen.stop"), b"");
        let _ = std::fs::remove_file(dir.join("screen.frame"));
    }
    dispatch2::DispatchQueue::main().exec_async(hide_picker);
}
