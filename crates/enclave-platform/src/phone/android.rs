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

extern "system" fn native_scan_failed(mut env: JNIEnv<'_>, _: JClass<'_>, why: JString<'_>) {
    let why: String = env.get_string(&why).map(Into::into).unwrap_or_default();
    if let Ok(mut c) = CAMERA.lock()
        && let Some(report) = c.as_mut()
    {
        report(Camera::Failed(why));
    }
}

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
                name: "nativeScanFailed".into(),
                sig: "(Ljava/lang/String;)V".into(),
                fn_ptr: native_scan_failed as *mut std::ffi::c_void,
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

/// An event from the Java side (`Native.event`): 1 in front ("1") or not,
/// 2 a push token ("platform:token"), 3 a wake, 4 the activity is gone,
/// 5 the way messages arrive changed (its number).
pub fn event(kind: i32, data: &str) {
    let e = match kind {
        4 => {
            crate::jvm::detach_activity();
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
        _ => return,
    };
    super::emit(e);
}
