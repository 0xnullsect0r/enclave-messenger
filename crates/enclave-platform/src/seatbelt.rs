//! macOS process sandboxing: Seatbelt profiles applied by each helper to
//! itself (`sandbox_init`, the mechanism the App Sandbox is built on, as
//! browsers use it for their helper processes). The App Sandbox proper
//! can't be used: helpers a sandboxed app starts must inherit its
//! sandbox and entitlements, so the window and every helper would share
//! one; separate profiles keep the vault off the network and mediad off
//! the files, as Landlock and seccomp do on Linux
//! (`enclave-sandbox::filesystem` writes the profiles).

use std::ffi::{CStr, CString, c_char, c_int};

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Confine this process with the Seatbelt profile `sbpl` (its source text).
/// It can't be undone; children inherit it.
pub fn confine(sbpl: &str) -> Result<(), String> {
    let profile = CString::new(sbpl).map_err(|_| "a NUL in the profile".to_string())?;
    let mut err: *mut c_char = std::ptr::null_mut();
    // SAFETY: `profile` is a NUL-terminated string that lives across the
    // call; flags 0 means it is profile source; `err` is written only on
    // failure, with a string we free once with sandbox_free_error.
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut err) };
    if rc == 0 {
        return Ok(());
    }
    let why = if err.is_null() {
        "refused".to_string()
    } else {
        // SAFETY: on failure `err` is a NUL-terminated string from the
        // sandbox library, valid until freed just below.
        let s = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: freed once, as the library asks.
        unsafe { sandbox_free_error(err) };
        s
    };
    Err(why)
}
