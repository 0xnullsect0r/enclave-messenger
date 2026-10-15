//! The phone's services for the app (feature `phone`): file pickers, the
//! camera for scanning codes, notifications, the clipboard, screen
//! security, and on Android the keystore. One API, with Android's
//! (`android`: JNI to `EnclaveActivity`, `apps/android`) and iOS's
//! (`ios`: UIKit through objc2) behind it.
//!
//! Answers come back on a thread of the platform's (Android's UI thread or
//! a worker, iOS's main thread); callers hop to their own event loop.

use std::path::PathBuf;

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(target_os = "android")]
use android as imp;
#[cfg(target_os = "ios")]
use ios as imp;

/// What a picker asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    /// One backup file.
    Backup,
    /// Pictures (several).
    Pictures,
    /// One file of any kind.
    File,
}

/// What the camera reports while scanning.
#[derive(Debug)]
pub enum Camera {
    /// A frame's brightness, `width` × `height`, row by row.
    Frame(u32, u32, Vec<u8>),
    /// The camera can't be used (the reason, for the person).
    Failed(String),
}

/// Set up what the app needs from the platform (Android: the native
/// methods; iOS: screen security and the keyboard rule). Once, at start.
pub fn init() {
    imp::init();
}

/// Ask the person for files; `done` gets copies the app may read (empty
/// when they chose none).
pub fn pick(kind: Pick, done: impl FnOnce(Vec<PathBuf>) + Send + 'static) {
    imp::pick(kind, Box::new(done));
}

/// Ask where to save `bytes` as `name`; `done` gets where it went (as the
/// platform names it), or why not (empty if the person cancelled).
pub fn save(
    name: &str,
    bytes: Vec<u8>,
    done: impl FnOnce(Result<String, String>) + Send + 'static,
) {
    imp::save(name, bytes, Box::new(done));
}

/// A notification, unless the app is in front.
pub fn notify(title: &str, body: &str) {
    imp::notify(title, body);
}

/// Copy `text`, marked sensitive and kept to this device, cleared after a
/// minute if it is still there. Whether it was copied.
pub fn copy(text: &str) -> bool {
    imp::copy(text)
}

/// Start the camera (the back one) for scanning; frames go to `report`
/// until [`stop_camera`].
pub fn start_camera(report: impl FnMut(Camera) + Send + 'static) {
    imp::start_camera(Box::new(report));
}

/// Turn the camera off.
pub fn stop_camera() {
    imp::stop_camera();
}

/// Screen security (Settings → Hide from screenshots, on until a profile
/// says otherwise): Android's `FLAG_SECURE`; on iOS, which can't block
/// screenshots, a blur over the app switcher's snapshot and over the
/// screen while it is recorded or mirrored.
pub fn set_screen_security(on: bool) {
    imp::set_screen_security(on);
}

/// Whether a camera frame needs mirroring to look right (the back camera
/// doesn't).
pub const MIRROR: bool = false;
