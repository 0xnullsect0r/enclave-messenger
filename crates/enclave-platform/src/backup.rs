//! Keeping the profile out of OS backups (`docs/14-storage.md` §2.4).
//!
//! A profile is useless without this device's keystore, and copies of it
//! in backups outlive shredding and erasing, so its directory is marked:
//!
//! - **macOS**: the sticky Time Machine exclusion (the extended attribute
//!   `com.apple.metadata:com_apple_backup_excludeItem` set to
//!   `"com.apple.backupd"`, what `tmutil addexclusion` writes).
//! - **Everywhere**: a `CACHEDIR.TAG` (the Cache Directory Tagging
//!   Specification), which restic, borg, tar `--exclude-caches` and others
//!   skip.
//!
//! - **iOS**: the directory's `NSURLIsExcludedFromBackupKey` resource
//!   value (iCloud and computer backups skip it), with the `phone` feature
//!   the app turns on.
//!
//! Android sets its exclusion in the manifest (`allowBackup="false"`,
//! `fullBackupContent="false"` and `dataExtractionRules`). Windows has no
//! per-folder exclusion for File History; the profile lives under the
//! local (not roaming) AppData.

use std::path::Path;

const TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
# This file is a cache directory tag created by Enclave.\n\
# The profile here is useless without this device's keystore and is kept\n\
# out of backups; Enclave makes its own encrypted backups.\n";

/// Mark `dir` to be left out of backups. Returns whether every marker
/// available here was set.
pub fn exclude(dir: &Path) -> bool {
    let tag = dir.join("CACHEDIR.TAG");
    let tagged = tag.exists() || std::fs::write(&tag, TAG).is_ok();
    tagged && os_exclude(dir)
}

/// Whether `dir` carries the markers.
pub fn is_excluded(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("CACHEDIR.TAG"))
        .is_ok_and(|t| t.starts_with("Signature: 8a477f597d28d172789f06886806bc55"))
        && os_is_excluded(dir)
}

#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub const NAME: &[u8] = b"com.apple.metadata:com_apple_backup_excludeItem\0";
    /// The binary property list of the string "com.apple.backupd".
    pub const VALUE: &[u8] = b"bplist00_\x10\x11com.apple.backupd\x08\
\x00\x00\x00\x00\x00\x00\x01\x01\
\x00\x00\x00\x00\x00\x00\x00\x01\
\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x1c";

    pub fn path(dir: &Path) -> Option<CString> {
        CString::new(dir.as_os_str().as_bytes()).ok()
    }
}

#[cfg(target_os = "macos")]
fn os_exclude(dir: &Path) -> bool {
    let Some(p) = mac::path(dir) else {
        return false;
    };
    // SAFETY: both strings are NUL-terminated and the value buffer is
    // valid for its length; setxattr only reads them.
    unsafe {
        libc::setxattr(
            p.as_ptr(),
            mac::NAME.as_ptr().cast(),
            mac::VALUE.as_ptr().cast(),
            mac::VALUE.len(),
            0,
            0,
        ) == 0
    }
}

#[cfg(target_os = "macos")]
fn os_is_excluded(dir: &Path) -> bool {
    let Some(p) = mac::path(dir) else {
        return false;
    };
    let mut buf = [0u8; 64];
    // SAFETY: the buffer is valid for its length and the strings are
    // NUL-terminated.
    let n = unsafe {
        libc::getxattr(
            p.as_ptr(),
            mac::NAME.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            0,
        )
    };
    usize::try_from(n).is_ok_and(|n| buf.get(..n) == Some(mac::VALUE))
}

#[cfg(all(target_os = "ios", feature = "phone"))]
mod ios {
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2_foundation::{NSNumber, NSString, NSURL, NSURLIsExcludedFromBackupKey};
    use std::path::Path;

    fn url(dir: &Path) -> Option<Retained<NSURL>> {
        let p = dir.to_str()?;
        Some(NSURL::fileURLWithPath_isDirectory(
            &NSString::from_str(p),
            true,
        ))
    }

    pub fn exclude(dir: &Path) -> bool {
        let Some(url) = url(dir) else {
            return false;
        };
        let yes = NSNumber::new_bool(true);
        // SAFETY: a file URL, Foundation's constant key, and an NSNumber,
        // the type the key takes.
        unsafe {
            url.setResourceValue_forKey_error(Some(&yes), NSURLIsExcludedFromBackupKey)
                .is_ok()
        }
    }

    pub fn is_excluded(dir: &Path) -> bool {
        let Some(url) = url(dir) else {
            return false;
        };
        let mut value: Option<Retained<AnyObject>> = None;
        // SAFETY: as in `exclude`; the value comes back as an NSNumber.
        let read =
            unsafe { url.getResourceValue_forKey_error(&mut value, NSURLIsExcludedFromBackupKey) };
        read.is_ok()
            && value
                .and_then(|v| v.downcast::<NSNumber>().ok())
                .is_some_and(|n| n.as_bool())
    }
}

#[cfg(all(target_os = "ios", feature = "phone"))]
fn os_exclude(dir: &Path) -> bool {
    ios::exclude(dir)
}

#[cfg(all(target_os = "ios", feature = "phone"))]
fn os_is_excluded(dir: &Path) -> bool {
    ios::is_excluded(dir)
}

/// iOS without the app's `phone` feature can't mark the directory.
#[cfg(all(target_os = "ios", not(feature = "phone")))]
fn os_exclude(_dir: &Path) -> bool {
    false
}

#[cfg(all(target_os = "ios", not(feature = "phone")))]
fn os_is_excluded(_dir: &Path) -> bool {
    false
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn os_exclude(_dir: &Path) -> bool {
    true
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn os_is_excluded(_dir: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_dirs_are_marked() {
        let dir = std::env::temp_dir().join(format!("enclave-nobackup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        assert!(!is_excluded(&dir));
        assert!(exclude(&dir));
        assert!(is_excluded(&dir));
        assert!(exclude(&dir), "again: no harm");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
