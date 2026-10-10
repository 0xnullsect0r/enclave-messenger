//! Vault hardening (`docs/15-client.md` §1.1a); the mechanisms are in
//! [`enclave_sandbox`], shared with netd.

pub use enclave_sandbox::{Profile, Report, filesystem, process, syscalls};
use std::path::PathBuf;

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
        if let Some(k) = kt_pins {
            ro.push(k.clone());
        }
    }
    (rw, ro)
}
