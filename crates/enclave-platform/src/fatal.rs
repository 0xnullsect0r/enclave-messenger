//! A record of a native crash (`docs/19-ops.md` §3): a segfault, bus
//! error, illegal instruction, arithmetic fault or abort on Unix, an
//! unhandled exception on Windows.
//!
//! The report is written before the crash, at [`arm`]: a header and the
//! path are prepared then, and the handler only adds the signal's name with
//! `open`, `write` and `close`, which are safe in a signal handler. Nothing
//! of the process's memory is read, so no key can end up in it. The handler
//! then puts the default action back and raises the signal again, so the
//! process ends as it would have (no core dump where the process turned
//! them off).
//!
//! A Rust panic is reported by its hook (`enclave-crash`), which calls
//! [`disarm`] first, so the abort that follows it doesn't write a second
//! report.

use std::ffi::OsString;
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

struct Prepared {
    #[cfg(unix)]
    path: std::ffi::CString,
    #[cfg(windows)]
    path: std::path::PathBuf,
    header: Vec<u8>,
}

static PREPARED: OnceLock<Prepared> = OnceLock::new();
static ARMED: AtomicBool = AtomicBool::new(false);

/// Prepare a report at `path` beginning `header`, and catch native
/// crashes. Call once, early, before any sandbox stops changing signal
/// handlers. Later calls do nothing.
pub fn arm(path: &Path, header: &str) {
    let prepared = Prepared {
        #[cfg(unix)]
        path: {
            use std::os::unix::ffi::OsStrExt;
            match std::ffi::CString::new(path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => return,
            }
        },
        #[cfg(windows)]
        path: path.to_path_buf(),
        header: header.as_bytes().to_vec(),
    };
    if PREPARED.set(prepared).is_err() {
        return;
    }
    ARMED.store(true, Ordering::SeqCst);
    install();
}

/// Don't write a report for what comes next (a panic's own report was
/// written).
pub fn disarm() {
    ARMED.store(false, Ordering::SeqCst);
}

/// The file name a report is written to: `native-<pid>-<seconds>.txt`.
pub fn file_name(pid: u32, at: u64) -> OsString {
    format!("native-{pid}-{at}.txt").into()
}

#[cfg(unix)]
const SIGNALS: [(libc::c_int, &[u8]); 5] = [
    (libc::SIGSEGV, b"SIGSEGV (invalid memory access)\n"),
    (libc::SIGBUS, b"SIGBUS (bus error)\n"),
    (libc::SIGILL, b"SIGILL (illegal instruction)\n"),
    (libc::SIGFPE, b"SIGFPE (arithmetic fault)\n"),
    (libc::SIGABRT, b"SIGABRT (aborted)\n"),
];

#[cfg(unix)]
fn install() {
    for (sig, _) in SIGNALS {
        // SAFETY: a zeroed sigaction is a valid starting value; we set the
        // handler, flags and an empty mask before passing it to sigaction,
        // which only reads it. The handler is an `extern "C"` function with
        // the signature SA_SIGINFO expects.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_RESETHAND | libc::SA_ONSTACK;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

#[cfg(unix)]
extern "C" fn handler(sig: libc::c_int, _info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    if ARMED.swap(false, Ordering::SeqCst)
        && let Some(p) = PREPARED.get()
    {
        let name: &[u8] = SIGNALS
            .iter()
            .find(|(s, _)| *s == sig)
            .map_or(b"signal\n", |(_, n)| n);
        // SAFETY: open, write and close are async-signal-safe; the path is
        // a NUL-terminated string and the buffers are valid for their
        // lengths, all prepared before the signal and never freed.
        unsafe {
            let fd = libc::open(
                p.path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            );
            if fd >= 0 {
                libc::write(fd, p.header.as_ptr().cast(), p.header.len());
                let label = b"kind: native crash\nsignal: ";
                libc::write(fd, label.as_ptr().cast(), label.len());
                libc::write(fd, name.as_ptr().cast(), name.len());
                libc::close(fd);
            }
        }
    }
    // SA_RESETHAND put the default action back: raise the signal again so
    // the process ends as it would have.
    // SAFETY: raise is async-signal-safe.
    unsafe {
        libc::raise(sig);
    }
}

#[cfg(windows)]
fn install() {
    use windows_sys::Win32::System::Diagnostics::Debug::SetUnhandledExceptionFilter;
    // SAFETY: the filter is an `extern "system"` function with the
    // signature SetUnhandledExceptionFilter expects; it lives for the
    // whole process.
    unsafe {
        SetUnhandledExceptionFilter(Some(filter));
    }
}

#[cfg(windows)]
unsafe extern "system" fn filter(
    info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    use std::io::Write;
    if ARMED.swap(false, Ordering::SeqCst)
        && let Some(p) = PREPARED.get()
    {
        // SAFETY: the system passes a valid EXCEPTION_POINTERS (or null,
        // checked) whose record pointer is valid for the call.
        let code = unsafe {
            info.as_ref()
                .and_then(|i| i.ExceptionRecord.as_ref())
                .map_or(0, |r| r.ExceptionCode as u32)
        };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p.path)
        {
            let _ = f.write_all(&p.header);
            let _ = write!(f, "kind: native crash\nexception: 0x{code:08X}\n");
        }
    }
    // EXCEPTION_CONTINUE_SEARCH: let Windows end the process as usual.
    0
}

#[cfg(not(any(unix, windows)))]
fn install() {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_native_crash_leaves_a_report() {
        // In a child process, so the test runner survives the crash.
        if let Some(dir) = std::env::var_os("ENCLAVE_FATAL_CHILD") {
            let path = Path::new(&dir).join("native.txt");
            arm(&path, "Enclave crash report\nprocess: test\n");
            // SAFETY: deliberately raising SIGSEGV to test the handler.
            unsafe {
                libc::raise(libc::SIGSEGV);
            }
            return;
        }
        let dir = std::env::temp_dir().join(format!("enclave-fatal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_default();
        let status = std::process::Command::new(std::env::current_exe().unwrap_or_default())
            .args([
                "--exact",
                "fatal::tests::a_native_crash_leaves_a_report",
                "--nocapture",
            ])
            .env("ENCLAVE_FATAL_CHILD", &dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        assert!(status.is_ok_and(|s| !s.success()), "the child should crash");
        let report = std::fs::read_to_string(dir.join("native.txt")).unwrap_or_default();
        assert!(
            report.starts_with("Enclave crash report\nprocess: test\n"),
            "{report}"
        );
        assert!(report.contains("signal: SIGSEGV"), "{report}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
