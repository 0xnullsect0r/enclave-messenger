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

/// The person asked the system for less motion (macOS "Reduce motion",
/// Windows "Show animations" off, GNOME's animations off, read through
/// the desktop portal): animations become instant (`docs/17-design.md`
/// §5).
pub fn reduce_motion() -> bool {
    #[cfg(target_os = "macos")]
    {
        use objc2::msg_send;
        use objc2::runtime::{AnyClass, AnyObject, Bool};
        let Some(class) = AnyClass::get(c"NSWorkspace") else {
            return false;
        };
        // SAFETY: NSWorkspace is an AppKit class (the app links AppKit);
        // sharedWorkspace returns the shared instance, and the property
        // read returns a BOOL.
        unsafe {
            let ws: *mut AnyObject = msg_send![class, sharedWorkspace];
            if ws.is_null() {
                return false;
            }
            let r: Bool = msg_send![ws, accessibilityDisplayShouldReduceMotion];
            r.as_bool()
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SPI_GETCLIENTAREAANIMATION, SystemParametersInfoW,
        };
        let mut on: i32 = 1;
        // SAFETY: SPI_GETCLIENTAREAANIMATION writes one BOOL to the pointer,
        // which points to `on` for the call.
        let ok = unsafe {
            SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&raw mut on).cast(), 0)
        };
        ok != 0 && on == 0
    }
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    {
        portal_animations().is_some_and(|on| !on)
    }
    #[cfg(not(any(unix, windows)))]
    false
}

/// GNOME's "enable-animations", through the desktop portal's settings.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
fn portal_animations() -> Option<bool> {
    let conn = zbus::blocking::Connection::session().ok()?;
    let proxy = zbus::blocking::Proxy::new(
        &conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Settings",
    )
    .ok()?;
    let reply = proxy
        .call_method(
            "ReadOne",
            &("org.gnome.desktop.interface", "enable-animations"),
        )
        .ok()?;
    let value: zbus::zvariant::OwnedValue = reply.body().deserialize().ok()?;
    bool::try_from(value).ok()
}

/// A haptic cue (`docs/17-design.md` §5).
#[derive(Clone, Copy, Debug)]
pub enum Haptic {
    /// A light tick: a message sent.
    Tick,
    /// The Seal closing: met in person.
    SealClosed,
}

/// Play a haptic cue where the computer has one (a Force Touch trackpad
/// on a Mac, which follows the system's setting); nothing elsewhere.
#[allow(unused_variables)]
pub fn haptic(h: Haptic) {
    #[cfg(target_os = "macos")]
    {
        use objc2::msg_send;
        use objc2::runtime::{AnyClass, AnyObject};
        let Some(class) = AnyClass::get(c"NSHapticFeedbackManager") else {
            return;
        };
        // NSHapticFeedbackPattern: Generic 0, Alignment 1, LevelChange 2;
        // NSHapticFeedbackPerformanceTime: Now 1.
        let pattern: isize = match h {
            Haptic::Tick => 0,
            Haptic::SealClosed => 2,
        };
        // SAFETY: an AppKit class; defaultPerformer returns the shared
        // performer, which takes two NSInteger/NSUInteger arguments.
        unsafe {
            let performer: *mut AnyObject = msg_send![class, defaultPerformer];
            if !performer.is_null() {
                let _: () =
                    msg_send![performer, performFeedbackPattern: pattern, performanceTime: 1usize];
            }
        }
    }
}
