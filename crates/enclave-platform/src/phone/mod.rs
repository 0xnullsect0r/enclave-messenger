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
    /// A colour frame for a call (the front camera): width, height, the
    /// clockwise turn (0, 90, 180, 270) that shows it upright, and I420
    /// planes (Y, then U and V at half size).
    Color(u32, u32, u16, Vec<u8>),
    /// The camera can't be used (the reason, for the person).
    Failed(String),
}

/// What the phone tells the app on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The app came to the front (true) or left it.
    Visible(bool),
    /// A push token for this app: platform (1 UnifiedPush endpoint, 2 APNs
    /// device token in hex, 3 FCM token, 4 PushKit VoIP token in hex) and
    /// the token; empty when the push service dropped the app.
    PushToken(u8, String),
    /// A push arrived: time to fetch.
    Wake,
    /// The system's call screen answered the ringing call.
    CallAnswered,
    /// The system's call screen hung up (or turned down) the call.
    CallEnded,
    /// The system's call screen turned the microphone off (true) or on.
    CallMuted(bool),
    /// A link opened with the app (a tapped `enclave:` link): for the Add
    /// screen.
    OpenLink(String),
    /// "Open with…" couldn't hand the file over (why).
    OpenFailed(String),
}

/// Where the phone is (latitude, longitude in degrees), or why not.
pub type Located = Box<dyn FnOnce(Result<(f64, f64), String>) + Send>;
static LOCATED: std::sync::Mutex<Option<Located>> = std::sync::Mutex::new(None);

/// Ask the phone where it is, once (the system asks the person the first
/// time); `done` gets the answer. Android reads its GPS only, never a
/// network location service.
pub fn locate(done: impl FnOnce(Result<(f64, f64), String>) + Send + 'static) {
    if let Ok(mut l) = LOCATED.lock() {
        *l = Some(Box::new(done));
    }
    imp::locate();
}

/// The answer to [`locate`].
pub(crate) fn located(r: Result<(f64, f64), String>) {
    let done = LOCATED.lock().ok().and_then(|mut l| l.take());
    if let Some(done) = done {
        done(r);
    }
}

/// Hand a place to a maps app the person picks. False when it can't be
/// done here.
pub fn open_map(lat: f64, lon: f64, label: &str) -> bool {
    imp::open_map(lat, lon, label)
}

/// "Open with…": hand a received file to an app the person picks. False
/// when it can't be done here.
pub fn open_with(name: &str, bytes: &[u8]) -> bool {
    imp::open_with(name, bytes)
}

/// A call is ringing: show the system's incoming-call screen (CallKit,
/// Android's ConnectionService), or name the caller on one already shown.
pub fn report_incoming_call(name: &str, video: bool) {
    imp::report_incoming(name, video);
}

/// We are calling someone: the system handles the call's audio and shows
/// it on the lock screen.
pub fn report_outgoing_call(name: &str, video: bool) {
    imp::report_outgoing(name, video);
}

/// The call connected.
pub fn report_call_connected() {
    imp::report_connected();
}

/// The call ended.
pub fn report_call_ended() {
    imp::report_ended();
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

/// Start the front camera for a video call; colour frames
/// ([`Camera::Color`], about 15 a second) go to `report` until
/// [`stop_camera`].
pub fn start_call_camera(report: impl FnMut(Camera) + Send + 'static) {
    imp::start_call_camera(Box::new(report));
}

/// A shared screen's pictures (width, height, RGBA), and why sharing
/// stopped or couldn't start (empty: stopped from the system's controls).
pub type ScreenFrames = Box<dyn FnMut(u32, u32, Vec<u8>) + Send>;
/// As above.
pub type ScreenFailed = Box<dyn FnOnce(String) + Send>;

/// Share the screen in a video call: the system asks first (Android's
/// MediaProjection; on iOS, the broadcast extension the system's picker
/// starts) and shows that the screen is recorded. Pictures, about five a
/// second, go to `frame` until [`stop_screen_capture`]; `failed` hears if
/// it was refused or stopped from the system's controls.
pub fn start_screen_capture(
    frame: impl FnMut(u32, u32, Vec<u8>) + Send + 'static,
    failed: impl FnOnce(String) + Send + 'static,
) {
    imp::start_screen_capture(Box::new(frame), Box::new(failed));
}

/// Stop sharing the screen.
pub fn stop_screen_capture() {
    imp::stop_screen_capture();
}

/// Turn the camera off.
pub fn stop_camera() {
    imp::stop_camera();
}

/// Ask for the microphone (a call is starting), if it hasn't been allowed
/// yet. The answer isn't reported: the call's audio keeps trying to open
/// the microphone for a while (`enclave-app`'s `audio`).
pub fn ask_microphone() {
    imp::ask_microphone();
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

/// Whether the system may stop Enclave in the background to save battery
/// (Android's battery optimisation, PC-22): staying connected with the
/// app closed then breaks off on some phones.
pub fn battery_restricted() -> bool {
    imp::battery_restricted()
}

/// Open the system's battery-optimisation setting, where Enclave can be
/// allowed to run.
pub fn open_battery_settings() {
    imp::open_battery_settings();
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
