//! Android: the JavaVM, the app's activity and its background service, and
//! calls into them (`phone::android`, the keystore).
//!
//! The activity comes from the context android-activity sets up
//! ([`attach_activity`], from the app's `android_main`); the service hands
//! itself over when it starts the vault without a window
//! ([`attach_service`]). Window things (pickers, the camera) need the
//! activity; the keystore and notifications work with either.

use jni::objects::{GlobalRef, JObject, JObjectArray, JString};
use jni::{JNIEnv, JavaVM};
use std::sync::{Mutex, OnceLock};

static VM: OnceLock<JavaVM> = OnceLock::new();
static ACTIVITY: Mutex<Option<GlobalRef>> = Mutex::new(None);
static SERVICE: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// Take the activity from android-activity's context (call from
/// `android_main`, where it is set up; again for each new activity).
pub fn attach_activity() {
    let c = ndk_context::android_context();
    // SAFETY: android-activity sets the context to the process's JavaVM
    // and the activity before `android_main` runs; the VM lives as long as
    // the process.
    let Ok(vm) = (unsafe { JavaVM::from_raw(c.vm().cast()) }) else {
        return;
    };
    let vm = VM.get_or_init(|| vm);
    let Ok(env) = vm.attach_current_thread_permanently() else {
        return;
    };
    // SAFETY: as above: the context is a valid global reference to the
    // activity for as long as the activity lives.
    let obj = unsafe { JObject::from_raw(c.context().cast()) };
    if let (Ok(g), Ok(mut a)) = (env.new_global_ref(&obj), ACTIVITY.lock()) {
        *a = Some(g);
    }
}

/// The activity is gone (destroyed); window things wait for the next.
pub fn detach_activity() {
    if let Ok(mut a) = ACTIVITY.lock() {
        *a = None;
    }
}

/// Take the service that started the vault without a window (from its
/// native `start`, on its thread).
pub fn attach_service(env: &JNIEnv<'_>, service: &JObject<'_>) {
    if let Ok(vm) = env.get_java_vm() {
        let _ = VM.set(vm);
    }
    if let (Ok(g), Ok(mut s)) = (env.new_global_ref(service), SERVICE.lock()) {
        *s = Some(g);
    }
}

fn call<T>(
    target: &Option<GlobalRef>,
    f: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> jni::errors::Result<T>,
) -> Option<T> {
    let vm = VM.get()?;
    let obj = target.as_ref()?;
    let mut env = vm.attach_current_thread_permanently().ok()?;
    let out = f(&mut env, obj.as_obj());
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
        return None;
    }
    out.ok()
}

/// Run `f` with a JNI environment for this thread and the activity,
/// clearing any Java exception it leaves. `None` without an activity.
pub(crate) fn with<T>(
    f: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> jni::errors::Result<T>,
) -> Option<T> {
    let a = ACTIVITY.lock().ok()?.clone();
    call(&a, f)
}

/// As [`with`], on the activity if there is one, else the service (both
/// carry the keystore and notification methods).
pub(crate) fn with_any<T>(
    f: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> jni::errors::Result<T>,
) -> Option<T> {
    let a = ACTIVITY.lock().ok()?.clone();
    let target = match a {
        Some(a) => Some(a),
        None => SERVICE.lock().ok()?.clone(),
    };
    call(&target, f)
}

/// A Java `String[]` as strings.
pub(crate) fn strings(env: &mut JNIEnv<'_>, arr: &JObjectArray<'_>) -> Vec<String> {
    let n = env.get_array_length(arr).unwrap_or(0);
    (0..n)
        .filter_map(|k| {
            let o = env.get_object_array_element(arr, k).ok()?;
            let s: String = env.get_string(&JString::from(o)).ok()?.into();
            Some(s)
        })
        .collect()
}
