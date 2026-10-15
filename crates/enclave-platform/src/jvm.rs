//! Android: the JavaVM and the app's activity, from the context
//! android-activity sets up, and calls into it (`phone::android`, the
//! keystore).

use jni::objects::{GlobalRef, JObject, JObjectArray, JString};
use jni::{JNIEnv, JavaVM};
use std::sync::OnceLock;

/// The VM and the activity, from the context android-activity set up.
struct Ctx {
    vm: JavaVM,
    activity: GlobalRef,
}

static CTX: OnceLock<Option<Ctx>> = OnceLock::new();

fn ctx() -> Option<&'static Ctx> {
    CTX.get_or_init(|| {
        let c = ndk_context::android_context();
        // SAFETY: android-activity sets the context to the process's
        // JavaVM and the activity before the app's main runs, and both
        // live as long as the process.
        let vm = unsafe { JavaVM::from_raw(c.vm().cast()) }.ok()?;
        let activity = {
            let env = vm.attach_current_thread().ok()?;
            // SAFETY: as above: the context is a valid global reference
            // to the activity.
            let obj = unsafe { JObject::from_raw(c.context().cast()) };
            env.new_global_ref(&obj).ok()?
        };
        Some(Ctx { vm, activity })
    })
    .as_ref()
}

/// Run `f` with a JNI environment for this thread and the activity,
/// clearing any Java exception it leaves. `None` if there is no VM.
pub(crate) fn with<T>(
    f: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> jni::errors::Result<T>,
) -> Option<T> {
    let c = ctx()?;
    let mut env = c.vm.attach_current_thread_permanently().ok()?;
    let out = f(&mut env, c.activity.as_obj());
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
        return None;
    }
    out.ok()
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
