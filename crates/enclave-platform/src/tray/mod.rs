//! A status-area icon for desktops (PC-48, `docs/09-transport.md` §6.3):
//! closing Enclave's window can leave it running in the Background profile,
//! with an icon to open the window again or quit.
//!
//! * Linux: a StatusNotifierItem with a `com.canonical.dbusmenu` menu, over
//!   the session bus (KDE, and GNOME with the AppIndicator extension that
//!   Ubuntu and Fedora ship; without a watcher there is no icon and
//!   [`show`] says so).
//! * Windows: a notification-area icon (`Shell_NotifyIconW`) on a hidden
//!   message window with its own thread.
//! * macOS: an `NSStatusItem` in the menu bar.
//!
//! One icon per process. The callback runs on whatever thread the system
//! delivers the click on; the app moves it to its own loop.

use std::sync::{Arc, Mutex, OnceLock};

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// What the person chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayEvent {
    /// Open the window again (a click on the icon, or "Open Enclave").
    Open,
    /// "Quit".
    Quit,
}

/// The icon's picture: RGBA, row by row.
#[derive(Clone, Debug)]
pub struct Icon {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// `width × height` RGBA pixels.
    pub rgba: Vec<u8>,
}

/// The labels the icon shows (translated by the app).
#[derive(Clone, Debug)]
pub struct Labels {
    /// The tooltip, and the icon's accessible name.
    pub tooltip: String,
    /// The menu item that opens the window.
    pub open: String,
    /// The menu item that quits.
    pub quit: String,
}

type Callback = Arc<dyn Fn(TrayEvent) + Send + Sync>;

fn callback() -> &'static Mutex<Option<Callback>> {
    static CB: OnceLock<Mutex<Option<Callback>>> = OnceLock::new();
    CB.get_or_init(|| Mutex::new(None))
}

/// Tell the app what was chosen.
fn fire(e: TrayEvent) {
    let cb = callback().lock().ok().and_then(|c| c.clone());
    if let Some(cb) = cb {
        cb(e);
    }
}

/// The icon while it is shown; dropping it removes it.
pub struct Tray {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    _inner: linux::Inner,
    #[cfg(windows)]
    _inner: windows::Inner,
    #[cfg(target_os = "macos")]
    _inner: macos::Inner,
}

impl Drop for Tray {
    fn drop(&mut self) {
        if let Ok(mut c) = callback().lock() {
            *c = None;
        }
    }
}

/// Show the icon. `None` when this desktop has no status area for it (or on
/// a platform without one); the app then quits when its window closes.
/// On macOS this must be called on the main thread.
pub fn show(
    icon: &Icon,
    labels: &Labels,
    on_event: impl Fn(TrayEvent) + Send + Sync + 'static,
) -> Option<Tray> {
    if let Ok(mut c) = callback().lock() {
        *c = Some(Arc::new(on_event));
    }
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    let tray = linux::show(icon, labels).map(|i| Tray { _inner: i });
    #[cfg(windows)]
    let tray = windows::show(icon, labels).map(|i| Tray { _inner: i });
    #[cfg(target_os = "macos")]
    let tray = macos::show(icon, labels).map(|i| Tray { _inner: i });
    #[cfg(not(any(unix, windows)))]
    let tray: Option<Tray> = {
        let _ = (icon, labels);
        None
    };
    #[cfg(any(target_os = "ios", target_os = "android"))]
    let tray: Option<Tray> = {
        let _ = (icon, labels);
        None
    };
    if tray.is_none()
        && let Ok(mut c) = callback().lock()
    {
        *c = None;
    }
    tray
}
