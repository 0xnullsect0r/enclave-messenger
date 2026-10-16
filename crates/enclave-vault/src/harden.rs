//! Vault hardening (`docs/15-client.md` §1.1a); the mechanisms are in
//! [`enclave_sandbox`], shared with netd.

pub use enclave_sandbox::{Profile, Report, process, syscalls};
use std::path::PathBuf;
use std::sync::OnceLock;

static FILESYSTEM: OnceLock<&'static str> = OnceLock::new();

/// Confine the vault's filesystem ([`enclave_sandbox::filesystem`]), and
/// remember how that went for Settings ([`filesystem_weak`]).
pub fn filesystem(read_write: &[PathBuf], read_only: &[PathBuf], deny_tcp: bool) -> &'static str {
    let r = enclave_sandbox::filesystem(read_write, read_only, deny_tcp);
    let _ = FILESYSTEM.set(r);
    r
}

/// Linux without (full) Landlock: the vault couldn't confine what files
/// it reaches, though seccomp still applies (PC-46). Settings says so.
pub fn filesystem_weak() -> bool {
    cfg!(target_os = "linux") && matches!(FILESYSTEM.get(), Some(&"partial" | &"unavailable"))
}

/// The paths the engine needs for `mode`: (read-write, read-only).
pub fn paths_for(mode: &crate::Mode) -> (Vec<PathBuf>, Vec<PathBuf>) {
    // Local time for message timestamps.
    let mut ro: Vec<PathBuf> = ["/etc/localtime", "/usr/share/zoneinfo"]
        .iter()
        .map(PathBuf::from)
        .collect();
    let mut rw = Vec::new();
    if let crate::Mode::Server {
        profile,
        kt_pins,
        foundation,
        server_list,
        ..
    } = mode
    {
        ro.extend(foundation.iter().cloned());
        ro.extend(server_list.iter().cloned());
        // The engine creates the profile directory if it's missing.
        let _ = std::fs::create_dir_all(profile);
        rw.push(profile.clone());
        // The secret portal's keyring, in a Flatpak (`crate::keystore`).
        rw.extend(crate::keystore::writable_paths());
        // macOS: the Keychain's own files and the security preferences,
        // which Security.framework may read in this process.
        #[cfg(target_os = "macos")]
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            ro.push(home.join("Library/Keychains"));
            ro.push(home.join("Library/Preferences"));
        }
        if let Some(k) = kt_pins {
            ro.push(k.clone());
        }
    }
    (rw, ro)
}
