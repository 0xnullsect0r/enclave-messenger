//! The app window's platform settings (`docs/14-storage.md` §5).

use raw_window_handle::HasWindowHandle;

/// Keep other programs from capturing `window` (screenshots, screen
/// recording and sharing): Windows `WDA_EXCLUDEFROMCAPTURE` (the window is
/// left out, or black), macOS `NSWindow.sharingType = .none` (best effort:
/// the system's own capture APIs honour it, not every tool). False where
/// there is no such control (Linux: X11 and Wayland let any program the
/// user runs capture the screen).
#[allow(unused_variables)]
pub fn exclude_from_capture(window: &impl HasWindowHandle, on: bool) -> bool {
    let Ok(handle) = window.window_handle() else {
        return false;
    };
    match handle.as_raw() {
        #[cfg(windows)]
        raw_window_handle::RawWindowHandle::Win32(h) => {
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
            };
            let affinity = if on { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE };
            // SAFETY: the handle is the live top-level window the caller
            // holds; SetWindowDisplayAffinity only reads it.
            unsafe { SetWindowDisplayAffinity(h.hwnd.get() as _, affinity) != 0 }
        }
        #[cfg(target_os = "macos")]
        raw_window_handle::RawWindowHandle::AppKit(h) => {
            use objc2::msg_send;
            use objc2::runtime::AnyObject;
            let view = h.ns_view.as_ptr().cast::<AnyObject>();
            // SAFETY: ns_view is the window's live NSView (raw-window-handle
            // guarantees it while the handle is borrowed); `window` returns
            // its NSWindow or nil, and setSharingType: takes an NSUInteger
            // (NSWindowSharingNone = 0, NSWindowSharingReadOnly = 1). Called
            // on the main thread, where the UI runs.
            unsafe {
                let ns_window: *mut AnyObject = msg_send![view, window];
                if ns_window.is_null() {
                    return false;
                }
                let sharing: usize = if on { 0 } else { 1 };
                let _: () = msg_send![ns_window, setSharingType: sharing];
            }
            true
        }
        _ => false,
    }
}

/// The window's native id where a platform API wants it (Windows: its
/// HWND, for Windows Hello's prompt); 0 elsewhere.
pub fn native_id(window: &impl HasWindowHandle) -> u64 {
    match window.window_handle().map(|h| h.as_raw()) {
        #[cfg(windows)]
        Ok(raw_window_handle::RawWindowHandle::Win32(h)) => h.hwnd.get() as u64,
        _ => 0,
    }
}

/// Whether [`exclude_from_capture`] does anything on this platform.
pub const CAN_EXCLUDE_FROM_CAPTURE: bool = cfg!(any(windows, target_os = "macos"));
