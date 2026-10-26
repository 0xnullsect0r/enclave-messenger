//! Android: JNI to the app's activity, `EnclaveActivity`
//! (`apps/android/app/src/main/java`), which holds what only Java reaches.
//! Calls go to its public methods; answers come back through its native
//! methods, which [`init`] registers.

use super::Event;
use super::{Camera, Pick};
pub use crate::jvm::{attach_activity, attach_service};
use crate::jvm::{strings, with, with_any};
use jni::objects::{JByteArray, JClass, JObjectArray, JString, JValue};
use jni::sys::{jboolean, jint};
use jni::{JNIEnv, NativeMethod};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};

type Picked = Box<dyn FnOnce(Vec<PathBuf>) + Send>;
type Saved = Box<dyn FnOnce(Result<String, String>) + Send>;
type Frames = Box<dyn FnMut(Camera) + Send>;

static NEXT: AtomicI32 = AtomicI32::new(1);
static PICKS: Mutex<Option<HashMap<i32, Picked>>> = Mutex::new(None);
static SAVES: Mutex<Option<HashMap<i32, Saved>>> = Mutex::new(None);
static CAMERA: Mutex<Option<Frames>> = Mutex::new(None);
static SCREEN: Mutex<Option<(super::ScreenFrames, Option<super::ScreenFailed>)>> = Mutex::new(None);

extern "system" fn native_picked(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
    request: jint,
    paths: JObjectArray<'_>,
) {
    let paths = strings(&mut env, &paths)
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let done = PICKS
        .lock()
        .ok()
        .and_then(|mut m| m.as_mut()?.remove(&request));
    if let Some(done) = done {
        done(paths);
    }
}

extern "system" fn native_saved(
    mut env: JNIEnv<'_>,
    _: JClass<'_>,
    request: jint,
    ok: jboolean,
    place: JString<'_>,
) {
    let place: String = env.get_string(&place).map(Into::into).unwrap_or_default();
    let done = SAVES
        .lock()
        .ok()
        .and_then(|mut m| m.as_mut()?.remove(&request));
    if let Some(done) = done {
        done(if ok != 0 { Ok(place) } else { Err(place) });
    }
}

extern "system" fn native_frame(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    grey: JByteArray<'_>,
    width: jint,
    height: jint,
) {
    let Ok(bytes) = env.convert_byte_array(&grey) else {
        return;
    };
    let (Ok(w), Ok(h)) = (u32::try_from(width), u32::try_from(height)) else {
        return;
    };
    if let Ok(mut c) = CAMERA.lock()
        && let Some(report) = c.as_mut()
    {
        report(Camera::Frame(w, h, bytes));
    }
}

extern "system" fn native_color_frame(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    i420: JByteArray<'_>,
    width: jint,
    height: jint,
    rotation: jint,
) {
    let Ok(bytes) = env.convert_byte_array(&i420) else {
        return;
    };
    let (Ok(w), Ok(h), Ok(r)) = (
        u32::try_from(width),
        u32::try_from(height),
        u16::try_from(rotation.rem_euclid(360)),
    ) else {
        return;
    };
    if let Ok(mut c) = CAMERA.lock()
        && let Some(report) = c.as_mut()
    {
        report(Camera::Color(w, h, r, bytes));
    }
}

extern "system" fn native_scan_failed(mut env: JNIEnv<'_>, _: JClass<'_>, why: JString<'_>) {
    let why: String = env.get_string(&why).map(Into::into).unwrap_or_default();
    if let Ok(mut c) = CAMERA.lock()
        && let Some(report) = c.as_mut()
    {
        report(Camera::Failed(why));
    }
}

extern "system" fn native_screen_frame(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    rgba: JByteArray<'_>,
    width: jint,
    height: jint,
) {
    let Ok(bytes) = env.convert_byte_array(&rgba) else {
        return;
    };
    let (Ok(w), Ok(h)) = (u32::try_from(width), u32::try_from(height)) else {
        return;
    };
    if bytes.len() != (w as usize) * (h as usize) * 4 {
        return;
    }
    if let Ok(mut s) = SCREEN.lock()
        && let Some((frame, _)) = s.as_mut()
    {
        frame(w, h, bytes);
    }
}

extern "system" fn native_screen_failed(mut env: JNIEnv<'_>, _: JClass<'_>, why: JString<'_>) {
    let why: String = env.get_string(&why).map(Into::into).unwrap_or_default();
    let failed = SCREEN
        .lock()
        .ok()
        .and_then(|mut s| s.take())
        .and_then(|(_, f)| f);
    if let Some(f) = failed {
        f(why);
    }
}

pub(super) fn start_screen_capture(frame: super::ScreenFrames, failed: super::ScreenFailed) {
    if let Ok(mut s) = SCREEN.lock() {
        *s = Some((frame, Some(failed)));
    }
    let _ = with(|env, a| {
        env.call_method(a, "startScreenShare", "()V", &[])
            .map(|_| ())
    });
}

pub(super) fn stop_screen_capture() {
    if let Ok(mut s) = SCREEN.lock() {
        *s = None;
    }
    let _ = with(|env, a| {
        env.call_method(a, "stopScreenShare", "()V", &[])
            .map(|_| ())
    });
}

/// Nothing before the event loop on Android.
pub fn prepare() {}

/// Register the activity's native methods.
pub fn init() {
    let _ = with(|env, activity| {
        let class = env.get_object_class(activity)?;
        let methods = [
            NativeMethod {
                name: "nativePicked".into(),
                sig: "(I[Ljava/lang/String;)V".into(),
                fn_ptr: native_picked as *mut std::ffi::c_void,
            },
            NativeMethod {
                name: "nativeSaved".into(),
                sig: "(IZLjava/lang/String;)V".into(),
                fn_ptr: native_saved as *mut std::ffi::c_void,
            },
            NativeMethod {
                name: "nativeFrame".into(),
                sig: "([BII)V".into(),
                fn_ptr: native_frame as *mut std::ffi::c_void,
            },
            NativeMethod {
                name: "nativeColorFrame".into(),
                sig: "([BIII)V".into(),
                fn_ptr: native_color_frame as *mut std::ffi::c_void,
            },
            NativeMethod {
                name: "nativeScanFailed".into(),
                sig: "(Ljava/lang/String;)V".into(),
                fn_ptr: native_scan_failed as *mut std::ffi::c_void,
            },
            NativeMethod {
                name: "nativeScreenFrame".into(),
                sig: "([BII)V".into(),
                fn_ptr: native_screen_frame as *mut std::ffi::c_void,
            },
            NativeMethod {
                name: "nativeScreenFailed".into(),
                sig: "(Ljava/lang/String;)V".into(),
                fn_ptr: native_screen_failed as *mut std::ffi::c_void,
            },
        ];
        env.register_native_methods(&class, &methods)
    });
}

pub(super) fn pick(kind: Pick, done: Picked) {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut m) = PICKS.lock() {
        m.get_or_insert_with(HashMap::new).insert(id, done);
    }
    let (mime, several) = match kind {
        Pick::Backup | Pick::File => ("*/*", false),
        Pick::Pictures => ("image/*", true),
    };
    let sent = with(|env, a| {
        let mime = env.new_string(mime)?;
        env.call_method(
            a,
            "pick",
            "(ILjava/lang/String;Z)V",
            &[
                JValue::Int(id),
                JValue::Object(&mime),
                JValue::Bool(u8::from(several)),
            ],
        )
        .map(|_| ())
    });
    if sent.is_none()
        && let Some(done) = PICKS.lock().ok().and_then(|mut m| m.as_mut()?.remove(&id))
    {
        done(Vec::new());
    }
}

/// One GPS fix (the activity asks for the permission first); the answer
/// comes back as event 9 or 10, for [`super::located`].
pub(super) fn locate() {
    if with(|env, a| env.call_method(a, "locate", "()V", &[]).map(|_| ())).is_none() {
        super::located(Err("No location here.".into()));
    }
}

/// A `geo:` link in the system's chooser: the person picks the maps app.
pub(super) fn open_map(lat: f64, lon: f64, label: &str) -> bool {
    with(|env, a| {
        let label = env.new_string(label)?;
        env.call_method(
            a,
            "openMap",
            "(DDLjava/lang/String;)V",
            &[
                JValue::Double(lat),
                JValue::Double(lon),
                JValue::Object(&label),
            ],
        )
        .map(|_| ())
    })
    .is_some()
}

/// "Open with…": the activity writes the file where only its provider
/// serves it, and asks which app opens it.
pub(super) fn open_with(name: &str, bytes: &[u8]) -> bool {
    with(|env, a| {
        let name = env.new_string(name)?;
        let data = env.byte_array_from_slice(bytes)?;
        env.call_method(
            a,
            "openWith",
            "(Ljava/lang/String;[B)V",
            &[JValue::Object(&name), JValue::Object(&data)],
        )
        .map(|_| ())
    })
    .is_some()
}

pub(super) fn save(name: &str, bytes: Vec<u8>, done: Saved) {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut m) = SAVES.lock() {
        m.get_or_insert_with(HashMap::new).insert(id, done);
    }
    let sent = with(|env, a| {
        let name = env.new_string(name)?;
        let data = env.byte_array_from_slice(&bytes)?;
        env.call_method(
            a,
            "save",
            "(ILjava/lang/String;[B)V",
            &[
                JValue::Int(id),
                JValue::Object(&name),
                JValue::Object(&data),
            ],
        )
        .map(|_| ())
    });
    if sent.is_none()
        && let Some(done) = SAVES.lock().ok().and_then(|mut m| m.as_mut()?.remove(&id))
    {
        done(Err("the file can't be saved here".into()));
    }
}

pub(super) fn notify(title: &str, body: &str) {
    let _ = with_any(|env, a| {
        let t = env.new_string(title)?;
        let b = env.new_string(body)?;
        env.call_method(
            a,
            "notify",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            &[JValue::Object(&t), JValue::Object(&b)],
        )
        .map(|_| ())
    });
}

pub(super) fn copy(text: &str) -> bool {
    with(|env, a| {
        let t = env.new_string(text)?;
        env.call_method(a, "copy", "(Ljava/lang/String;)Z", &[JValue::Object(&t)])?
            .z()
    })
    .unwrap_or(false)
}

pub(super) fn start_camera(report: Frames) {
    if let Ok(mut c) = CAMERA.lock() {
        *c = Some(report);
    }
    let _ = with(|env, a| env.call_method(a, "startScan", "()V", &[]).map(|_| ()));
}

pub(super) fn ask_microphone() {
    let _ = with(|env, a| env.call_method(a, "askMicrophone", "()V", &[]).map(|_| ()));
}

pub(super) fn start_call_camera(report: Frames) {
    if let Ok(mut c) = CAMERA.lock() {
        *c = Some(report);
    }
    let _ = with(|env, a| {
        env.call_method(a, "startCallCamera", "()V", &[])
            .map(|_| ())
    });
}

pub(super) fn stop_camera() {
    let _ = with(|env, a| env.call_method(a, "stopScan", "()V", &[]).map(|_| ()));
    if let Ok(mut c) = CAMERA.lock() {
        *c = None;
    }
}

pub(super) fn set_screen_security(on: bool) {
    let _ = with(|env, a| {
        env.call_method(a, "setSecure", "(Z)V", &[JValue::Bool(u8::from(on))])
            .map(|_| ())
    });
}

pub(super) fn text_scale() -> f32 {
    with_any(|env, a| env.call_method(a, "fontScale", "()F", &[])?.f()).unwrap_or(1.0)
}

pub(super) fn reduce_motion() -> bool {
    with_any(|env, a| env.call_method(a, "reduceMotion", "()Z", &[])?.z()).unwrap_or(false)
}

pub(super) fn battery_restricted() -> bool {
    with(|env, a| env.call_method(a, "batteryRestricted", "()Z", &[])?.z()).unwrap_or(false)
}

pub(super) fn open_battery_settings() {
    let _ = with(|env, a| {
        env.call_method(a, "openBatterySettings", "()V", &[])
            .map(|_| ())
    });
}

pub(super) fn delivery() -> (u8, u8) {
    let way = with(|env, a| env.call_method(a, "delivery", "()I", &[])?.i()).unwrap_or(0);
    let ways = with(|env, a| env.call_method(a, "deliveryChoices", "()I", &[])?.i()).unwrap_or(1);
    (
        u8::try_from(way).unwrap_or(0),
        u8::try_from(ways).unwrap_or(1),
    )
}

pub(super) fn set_delivery(way: u8) {
    let _ = with(|env, a| {
        env.call_method(a, "setDelivery", "(I)V", &[JValue::Int(i32::from(way))])
            .map(|_| ())
    });
}

/// The call's state for the system's call handling (`Calls.java`, a
/// self-managed ConnectionService): 1 ringing, 2 calling out, 3
/// connected, 4 ended. On the activity, or the service with no window.
fn call_state(state: i32, name: &str, video: bool) {
    let _ = with_any(|env, a| {
        let n = env.new_string(name)?;
        env.call_method(
            a,
            "callState",
            "(ILjava/lang/String;Z)V",
            &[
                JValue::Int(state),
                JValue::Object(&n),
                JValue::Bool(u8::from(video)),
            ],
        )
        .map(|_| ())
    });
}

pub(super) fn report_incoming(name: &str, video: bool) {
    call_state(1, name, video);
}

pub(super) fn report_outgoing(name: &str, video: bool) {
    call_state(2, name, video);
}

pub(super) fn report_connected() {
    call_state(3, "", false);
}

pub(super) fn report_ended() {
    call_state(4, "", false);
}

/// An event from the Java side (`Native.event`): 1 in front ("1") or not,
/// 2 a push token ("platform:token"), 3 a wake, 4 the activity is gone
/// (its `System.identityHashCode`),
/// 5 the way messages arrive changed (its number), 6 the system's call
/// screen ("answer", "end", "mute:1", "mute:0"), 7 a link opened with the
/// app (its text), 8 "Open with…" failed (why), 9 a location ("lat,lon"),
/// 10 no location (why).
pub fn event(kind: i32, data: &str) {
    let e = match kind {
        4 => {
            // Which one: its identity hash (empty from an older app).
            crate::jvm::detach_activity(data.parse().ok());
            return;
        }
        5 => {
            super::delivery_changed(data.parse().unwrap_or(0));
            return;
        }
        1 => Event::Visible(data == "1"),
        2 => {
            let (p, t) = data.split_once(':').unwrap_or(("0", ""));
            Event::PushToken(p.parse().unwrap_or(0), t.to_string())
        }
        3 => Event::Wake,
        7 => Event::OpenLink(data.to_string()),
        8 => Event::OpenFailed(data.to_string()),
        9 => {
            super::located(
                match data.split_once(',').map(|(a, b)| (a.parse(), b.parse())) {
                    Some((Ok(lat), Ok(lon))) => Ok((lat, lon)),
                    _ => Err("The location couldn't be read.".into()),
                },
            );
            return;
        }
        10 => {
            super::located(Err(data.to_string()));
            return;
        }
        6 => match data {
            "answer" => Event::CallAnswered,
            "end" => Event::CallEnded,
            "mute:1" => Event::CallMuted(true),
            "mute:0" => Event::CallMuted(false),
            _ => return,
        },
        _ => return,
    };
    super::emit(e);
}

/// Android: start helper `name` in a process of the app's
/// (`HelperService`: netd in `:net`, mediad in the `isolatedProcess`
/// `:media`), connected by a socket handed over through Binder
/// (`EnclaveActivity.startHelper`, on the activity or the service). `None`
/// when that isn't possible (another helper, or no activity or service
/// yet): it then runs as a thread.
pub fn helper_process(name: &str, args: &[String]) -> Option<crate::process::InProcess> {
    use std::os::fd::{FromRawFd, OwnedFd};
    if !matches!(name, "enclave-netd" | "enclave-mediad") {
        return None;
    }
    let fd = with_any(|env, a| {
        let n = env.new_string(name)?;
        let arr = env.new_object_array(
            i32::try_from(args.len()).unwrap_or(0),
            "java/lang/String",
            jni::objects::JObject::null(),
        )?;
        for (i, s) in args.iter().enumerate() {
            let s = env.new_string(s)?;
            env.set_object_array_element(&arr, i32::try_from(i).unwrap_or(0), s)?;
        }
        env.call_method(
            a,
            "startHelper",
            "(Ljava/lang/String;[Ljava/lang/String;)I",
            &[JValue::Object(&n), JValue::Object(&arr)],
        )?
        .i()
    })?;
    if fd < 0 {
        eprintln!("enclave: {name} runs in the app's process (its own couldn't start)");
        return None;
    }
    // SAFETY: Java detached this descriptor (its end of the socket pair)
    // and handed it to us; nothing else owns or closes it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let other = fd.try_clone().ok()?;
    Some(crate::process::InProcess {
        stdin: fd.into(),
        stdout: other.into(),
    })
}

/// In a helper process: run helper `name` on the socket `fd` the app
/// handed over (`Native.helper`).
pub fn serve_helper(name: &str, args: Vec<String>, fd: i32) -> std::io::Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};
    if fd < 0 {
        return Err(std::io::Error::other("no connection"));
    }
    // SAFETY: Java detached the descriptor it received and gave it to us
    // alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let input = fd.try_clone()?;
    crate::process::serve(
        name,
        args,
        crate::process::Stdio {
            input: input.into(),
            output: fd.into(),
        },
    )
}
