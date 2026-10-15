//! Enclave's notification service extension on iOS (`docs/10-push.md`
//! §5.1, milestone I1).
//!
//! A push from the relay says only "New message" and carries the newest
//! envelope's capsule (`c`, 1,024 bytes). With previews on, the app keeps
//! a notification key table (each contact's and group's keys for today
//! and yesterday, and nothing else) in a Keychain item shared with the
//! extension (`enclave_platform::keystore::shared`); this opens the
//! capsule with it, so the notification shows who wrote and the start of
//! the message. No ratchet or identity key, no network, nothing written.
//! The Swift extension (`apps/ios/nse/NotificationService.swift`) calls
//! [`enclave_nse_open`].

use enclave_proto::notify::KeyTable;

/// The sender's name and the preview in `capsule`, opened with `table`;
/// `None` when no key in it opens the capsule.
pub fn open_with(table: &[u8], capsule: &[u8]) -> Option<(String, String)> {
    KeyTable::decode(table).ok()?.open(capsule)
}

/// The sender's name and the preview in `capsule`, opened with the table
/// the app shares.
#[cfg(target_os = "ios")]
pub fn open(capsule: &[u8]) -> Option<(String, String)> {
    use enclave_platform::keystore::shared;
    let table = shared::get(shared::NOTIFY_TABLE).ok()?;
    open_with(&table, capsule)
}

/// Elsewhere there is no shared table.
#[cfg(not(target_os = "ios"))]
pub fn open(_capsule: &[u8]) -> Option<(String, String)> {
    None
}

/// `name ‖ 0 ‖ preview`, as written for the extension.
fn joined(name: &str, preview: &str) -> Vec<u8> {
    [name.as_bytes(), &[0], preview.as_bytes()].concat()
}

/// Open the capsule at `capsule` (`len` bytes) and write `name ‖ 0 ‖
/// preview` (UTF-8) to `out` (room for `out_len` bytes). Returns the
/// length written, or -1 when it doesn't open or doesn't fit: the
/// notification then stays "New message".
///
/// # Safety
///
/// `capsule` must point to `len` readable bytes and `out` to `out_len`
/// writable ones (either may be null with a length of 0).
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn enclave_nse_open(
    capsule: *const u8,
    len: usize,
    out: *mut u8,
    out_len: usize,
) -> isize {
    if capsule.is_null() || out.is_null() {
        return -1;
    }
    // SAFETY: the caller gives `len` readable bytes at `capsule`, and
    // `out_len` writable bytes at `out`, which don't overlap them.
    let (capsule, out) = unsafe {
        (
            std::slice::from_raw_parts(capsule, len),
            std::slice::from_raw_parts_mut(out, out_len),
        )
    };
    let Some((name, preview)) = open(capsule) else {
        return -1;
    };
    let text = joined(&name, &preview);
    match out.get_mut(..text.len()) {
        Some(dst) => {
            dst.copy_from_slice(&text);
            isize::try_from(text.len()).unwrap_or(-1)
        }
        None => -1,
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use enclave_proto::notify::seal_capsule;

    #[test]
    fn opens_with_the_table_and_nothing_else() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = enclave_crypto::rng::HedgedRng::new()?;
        let key = [7; 32];
        let capsule = seal_capsule(&key, 20_000, "Ada", "See you at six", &mut rng)?;
        let table = KeyTable {
            day: 20_000,
            entries: vec![("Ada".into(), key, None)],
        };
        assert_eq!(
            open_with(&table.encode(), &capsule),
            Some(("Ada".into(), "See you at six".into()))
        );
        let other = KeyTable {
            day: 20_000,
            entries: vec![("Ben".into(), [9; 32], None)],
        };
        assert_eq!(open_with(&other.encode(), &capsule), None);
        assert_eq!(open_with(b"not a table", &capsule), None);
        assert_eq!(joined("Ada", "hi"), b"Ada\0hi");
        let mut out = [0u8; 64];
        // SAFETY: both buffers are live and as long as given.
        let n = unsafe {
            enclave_nse_open(capsule.as_ptr(), capsule.len(), out.as_mut_ptr(), out.len())
        };
        assert_eq!(n, -1, "no shared table off iOS");
        Ok(())
    }
}
