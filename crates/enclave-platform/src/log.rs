//! What Enclave's programs wrote to their error output, kept where a
//! person can copy it from the window: a phone has no terminal, and a
//! desktop app started from its menu has none either. The last lines are
//! kept in memory ([`keep`], [`recent`]), and [`tee_stderr`] (the desktop
//! vault, whose helpers write to the same error output) also writes them
//! to a file in the profile, which the window reads ([`read_file`]).
//! Nothing here goes anywhere by itself: the person copies it, or not.

use std::collections::VecDeque;
use std::sync::Mutex;

/// Lines kept in memory.
const KEEP: usize = 400;
/// The log file in a profile.
pub const FILE: &str = "log.txt";

static LINES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Keep `line` (the oldest go past [`KEEP`]).
pub fn keep(line: &str) {
    if let Ok(mut l) = LINES.lock() {
        if l.len() == KEEP {
            l.pop_front();
        }
        l.push_back(line.to_string());
    }
}

/// The lines kept, oldest first.
pub fn recent() -> String {
    LINES
        .lock()
        .map(|l| l.iter().map(|s| format!("{s}\n")).collect())
        .unwrap_or_default()
}

/// The log file in `profile`, its last [`KEEP`] lines (empty without one).
pub fn read_file(profile: &std::path::Path) -> String {
    let text = std::fs::read_to_string(profile.join(FILE)).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let from = lines.len().saturating_sub(KEEP);
    lines[from..].iter().map(|s| format!("{s}\n")).collect()
}

/// Send this process's error output (and its children's, which inherit
/// it) through a pipe: each line goes on to where it went before (a
/// terminal, the journal), into memory ([`keep`]), and to `profile`'s
/// [`FILE`]. Call before starting the helpers and before confining.
#[cfg(unix)]
pub fn tee_stderr(profile: &std::path::Path) {
    use std::io::{BufRead, Write};
    use std::os::fd::FromRawFd;
    /// A log file is started afresh once it is this long.
    const MAX_FILE: u64 = 512 * 1024;
    let path = profile.join(FILE);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_FILE) {
        let _ = std::fs::rename(&path, profile.join("log.1.txt"));
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let mut fds = [0i32; 2];
    // SAFETY: `pipe` fills the two descriptors of a new pipe.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return;
    }
    // SAFETY: a copy of descriptor 2 as it is now (where error output
    // went), ours from here on.
    let before = unsafe { libc::dup(2) };
    // SAFETY: points descriptor 2 at the pipe's write end; both are open
    // descriptors of this process.
    if before < 0 || unsafe { libc::dup2(fds[1], 2) } < 0 {
        return;
    }
    // SAFETY: the write end is now descriptor 2 as well; this copy goes.
    unsafe { libc::close(fds[1]) };
    // SAFETY: the read end and the old error output are this thread's
    // alone from here on.
    let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    // SAFETY: `before` is the copy of the old error output made above,
    // owned by nothing else.
    let mut out = unsafe { std::fs::File::from_raw_fd(before) };
    let _ = std::thread::Builder::new()
        .name("enclave-log".into())
        .spawn(move || {
            for line in std::io::BufReader::new(read).lines().map_while(Result::ok) {
                // Where it went before may be gone (a closed terminal):
                // that is no reason to stop keeping it.
                let _ = writeln!(out, "{line}");
                let _ = writeln!(file, "{line}");
                keep(&line);
            }
        });
}

/// Elsewhere error output stays as it is.
#[cfg(not(unix))]
pub fn tee_stderr(_profile: &std::path::Path) {}

#[cfg(test)]
mod tests {
    #[test]
    fn keeps_the_last_lines() {
        for i in 0..super::KEEP + 5 {
            super::keep(&format!("line {i}"));
        }
        let r = super::recent();
        assert!(r.starts_with("line 5\n"), "{}", &r[..20]);
        assert!(r.ends_with(&format!("line {}\n", super::KEEP + 4)));
    }
}
