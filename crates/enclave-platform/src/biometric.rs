//! Touch ID, Face ID, Windows Hello and Android's fingerprint prompt, to
//! open the app lock (`docs/14-storage.md` §5). Never for root actions:
//! those take the PIN. On a phone it is the whole lock, with the phone's
//! own screen lock (passcode, PIN, pattern) as its fallback.
//!
//! The check runs in the vault, which decides what it unlocks: the window
//! only names itself (on Windows the prompt is attached to it) and can't
//! answer for the person.

/// What the platform calls it ("Touch ID", "Windows Hello"), where there
/// is one; `None` elsewhere (Linux has no common biometric API).
pub fn name() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        Some("Touch ID")
    } else if cfg!(windows) {
        Some("Windows Hello")
    } else if cfg!(target_os = "ios") {
        #[cfg(target_os = "ios")]
        return Some(apple::ios_name());
        #[allow(unreachable_code)]
        None
    } else if cfg!(target_os = "android") {
        Some("fingerprint")
    } else {
        None
    }
}

/// Whether the person can use it now (a sensor, enrolled).
pub fn available() -> bool {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    return apple::available();
    #[cfg(target_os = "android")]
    return android::available();
    #[cfg(windows)]
    return win::available();
    #[allow(unreachable_code)]
    false
}

/// Ask the person (blocking until they answer, up to a minute). `window`
/// is the window to attach the prompt to (Windows: its HWND), or 0.
#[allow(unused_variables)]
pub fn verify(window: u64, reason: &str) -> bool {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    return apple::verify(reason);
    #[cfg(target_os = "android")]
    return android::verify(reason);
    #[cfg(windows)]
    return win::verify(window, reason);
    #[allow(unreachable_code)]
    false
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::time::Duration;

    /// On a Mac Touch ID alone (the app PIN is the fallback); on a phone
    /// Face ID or Touch ID, then the phone's passcode.
    #[cfg(target_os = "macos")]
    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
    #[cfg(target_os = "ios")]
    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthentication;

    /// What this iPhone has.
    #[cfg(target_os = "ios")]
    pub fn ios_name() -> &'static str {
        use objc2_local_authentication::LABiometryType;
        // SAFETY: a fresh LAContext; biometryType is read after
        // canEvaluatePolicy, as Apple asks.
        let kind = unsafe {
            let c = LAContext::new();
            let _ = c.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics);
            c.biometryType()
        };
        if kind == LABiometryType::TouchID {
            "Touch ID"
        } else if kind == LABiometryType::FaceID {
            "Face ID"
        } else {
            "your passcode"
        }
    }

    pub fn available() -> bool {
        // SAFETY: a fresh LAContext, asked about a policy constant; no
        // pointers of ours cross.
        unsafe { LAContext::new().canEvaluatePolicy_error(POLICY).is_ok() }
    }

    pub fn verify(reason: &str) -> bool {
        let (tx, rx) = std::sync::mpsc::sync_channel::<bool>(1);
        let reply = block2::RcBlock::new(move |ok: Bool, _err: *mut NSError| {
            let _ = tx.try_send(ok.as_bool());
        });
        let context;
        // SAFETY: the context and the reason string live across the call
        // (the context until we have the answer); the block is reference
        // counted and LocalAuthentication keeps it until it replies, on a
        // queue of its own.
        unsafe {
            context = LAContext::new();
            context.evaluatePolicy_localizedReason_reply(
                POLICY,
                &NSString::from_str(reason),
                &reply,
            );
        }
        let ok = rx.recv_timeout(Duration::from_secs(60)).unwrap_or(false);
        drop(context);
        ok
    }
}

/// Android: the system's prompt (`BiometricPrompt`: a fingerprint or
/// face, else the screen lock), shown by the activity; its answer comes
/// back through `EnclaveActivity.nativeAuthenticated`.
#[cfg(target_os = "android")]
pub(crate) mod android {
    use jni::objects::{JClass, JValue};
    use jni::sys::jboolean;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Where the answer to the question being asked goes.
    static WAITING: Mutex<Option<std::sync::mpsc::SyncSender<bool>>> = Mutex::new(None);

    pub fn available() -> bool {
        crate::jvm::with(|env, a| env.call_method(a, "biometricAvailable", "()Z", &[])?.z())
            .unwrap_or(false)
    }

    pub fn verify(reason: &str) -> bool {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        if let Ok(mut w) = WAITING.lock() {
            *w = Some(tx);
        }
        let asked = crate::jvm::with(|env, a| {
            let r = env.new_string(reason)?;
            env.call_method(
                a,
                "authenticate",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&r)],
            )
            .map(|_| ())
        })
        .is_some();
        asked && rx.recv_timeout(Duration::from_secs(60)).unwrap_or(false)
    }

    /// Java's `nativeAuthenticated(ok)`: the person's answer.
    pub(crate) extern "system" fn native_authenticated(
        _env: jni::JNIEnv<'_>,
        _class: JClass<'_>,
        ok: jboolean,
    ) {
        if let Some(tx) = WAITING.lock().ok().and_then(|mut w| w.take()) {
            let _ = tx.try_send(ok != 0);
        }
    }
}

#[cfg(windows)]
mod win {
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::core::HSTRING;

    pub fn available() -> bool {
        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.join())
            .is_ok_and(|a| a == UserConsentVerifierAvailability::Available)
    }

    pub fn verify(window: u64, reason: &str) -> bool {
        let Ok(interop) =
            windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
        else {
            return false;
        };
        // SAFETY: the window handle is a value the caller names (its own
        // top-level window); Windows checks it, and the message is a live
        // HSTRING for the call.
        let op: windows::core::Result<
            windows_future::IAsyncOperation<UserConsentVerificationResult>,
        > = unsafe {
            interop.RequestVerificationForWindowAsync(
                HWND(window as usize as *mut core::ffi::c_void),
                &HSTRING::from(reason),
            )
        };
        op.and_then(|o| o.join())
            .is_ok_and(|r| r == UserConsentVerificationResult::Verified)
    }
}
