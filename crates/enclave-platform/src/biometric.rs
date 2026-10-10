//! Touch ID and Windows Hello, to open the app lock
//! (`docs/14-storage.md` §5). Never for root actions: those take the PIN.
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
    } else {
        None
    }
}

/// Whether the person can use it now (a sensor, enrolled).
pub fn available() -> bool {
    #[cfg(target_os = "macos")]
    return mac::available();
    #[cfg(windows)]
    return win::available();
    #[allow(unreachable_code)]
    false
}

/// Ask the person (blocking until they answer, up to a minute). `window`
/// is the window to attach the prompt to (Windows: its HWND), or 0.
#[allow(unused_variables)]
pub fn verify(window: u64, reason: &str) -> bool {
    #[cfg(target_os = "macos")]
    return mac::verify(reason);
    #[cfg(windows)]
    return win::verify(window, reason);
    #[allow(unreachable_code)]
    false
}

#[cfg(target_os = "macos")]
mod mac {
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::time::Duration;

    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

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
