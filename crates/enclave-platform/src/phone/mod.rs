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

/// What the phone tells the app on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The app came to the front (true) or left it.
    Visible(bool),
    /// A push token for this app: platform (1 UnifiedPush endpoint, 2 APNs
    /// device token in hex, 3 FCM token) and the token; empty when the
    /// push service dropped the app.
    PushToken(u8, String),
    /// A push arrived: time to fetch.
    Wake,
}

type Listener = Box<dyn Fn(Event) + Send + Sync>;
static LISTENER: std::sync::RwLock<Option<Listener>> = std::sync::RwLock::new(None);

/// Where [`Event`]s go (one listener; a later call replaces it).
pub fn on_event(f: impl Fn(Event) + Send + Sync + 'static) {
    if let Ok(mut l) = LISTENER.write() {
        *l = Some(Box::new(f));
    }
}

/// Hand an event to the listener.
pub(crate) fn emit(e: Event) {
    if let Ok(l) = LISTENER.read()
        && let Some(f) = l.as_ref()
    {
        f(e);
    }
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

/// How messages reach this phone while the app is closed (its numbers are
/// the push platforms' in [`Event::PushToken`]).
pub mod delivery {
    /// Stay connected: Android keeps Enclave running in the background (a
    /// foreground service), which works with no push service at all.
    pub const CONNECTED: u8 = 0;
    /// A UnifiedPush distributor the person chose wakes Enclave.
    pub const UNIFIEDPUSH: u8 = 1;
    /// Apple's push service (iOS, always).
    pub const APPLE: u8 = 2;
    /// Google's push service (Android, the Play build).
    pub const FIREBASE: u8 = 3;
}

/// The way messages reach this phone with the app closed ([`delivery`]),
/// and the ways it offers (bit `1 << way` set for each).
pub fn delivery() -> (u8, u8) {
    imp::delivery()
}

/// Use `way` from now on ([`delivery`]). UnifiedPush first asks the person
/// to pick their distributor; [`on_delivery`] hears the outcome.
pub fn set_delivery(way: u8) {
    imp::set_delivery(way);
}

type DeliveryListener = Box<dyn Fn(u8) + Send + Sync>;
static DELIVERY: std::sync::RwLock<Option<DeliveryListener>> = std::sync::RwLock::new(None);

/// Where a change of [`delivery`] is reported (one listener).
pub fn on_delivery(f: impl Fn(u8) + Send + Sync + 'static) {
    if let Ok(mut l) = DELIVERY.write() {
        *l = Some(Box::new(f));
    }
}

#[cfg_attr(target_os = "ios", allow(dead_code))]
pub(crate) fn delivery_changed(way: u8) {
    if let Ok(l) = DELIVERY.read()
        && let Some(f) = l.as_ref()
    {
        f(way);
    }
}

/// The system's text size (1.0 = default): Android's font scale, iOS's
/// Dynamic Type size.
pub fn text_scale() -> f32 {
    imp::text_scale()
}

/// The person asked the system for less motion (Android: animations off
/// in the developer or accessibility settings; iOS: Reduce Motion).
pub fn reduce_motion() -> bool {
    imp::reduce_motion()
}

/// Whether a camera frame needs mirroring to look right (the back camera
/// doesn't).
pub const MIRROR: bool = false;
