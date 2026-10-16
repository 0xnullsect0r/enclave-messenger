//! Scrubbed local crash reports (`docs/19-ops.md` §3).
//!
//! When an Enclave process panics or crashes, it writes a short text file
//! into the profile's `crashes` folder: the version, which process, the
//! system, where it failed (source file and line), a scrubbed message and
//! the names of the functions on the stack. No memory is read or copied,
//! not even the stack's, so no key, message or contact can be in it; that
//! is why this is a text record rather than a minidump. Secret types
//! implement neither `Debug` nor `Display` (`docs/02-cryptography.md`
//! §10), and the message is scrubbed again here: quoted text, anything in
//! brackets, paths, long numbers and anything that looks like an
//! identifier or encoded bytes become "…".
//!
//! Nothing is sent. The app shows the reports the next time it starts;
//! the person can read them, save them to a file, send one to Enclave
//! Support as an ordinary end-to-end encrypted message, or delete them.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The folder in the profile directory that holds reports.
pub const DIR: &str = "crashes";
/// Reports kept; older ones are deleted when a process starts.
pub const KEEP: usize = 10;
/// The first line of every report.
pub const TITLE: &str = "Enclave crash report";
/// Longest scrubbed message kept, in characters.
const MAX_MESSAGE: usize = 300;
/// Most stack frames kept.
const MAX_FRAMES: usize = 40;

/// Write reports for this process (`process` is its short name, such as
/// "vault") into `dir`, which is created if needed. Call once, early, and
/// before any sandbox would stop the process from changing its signal
/// handlers or creating files there. Only the first call counts.
pub fn install(dir: &Path, process: &'static str) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| install_once(dir, process));
}

fn install_once(dir: &Path, process: &'static str) {
    if create_dir(dir).is_err() {
        return;
    }
    prune(dir, KEEP.saturating_sub(1));
    let pid = std::process::id();
    let started = now();
    let header = header(process);
    enclave_platform::fatal::arm(
        &dir.join(enclave_platform::fatal::file_name(pid, started)),
        &header,
    );
    let dir = dir.to_path_buf();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // This report replaces the native one the abort that follows
        // would write.
        enclave_platform::fatal::disarm();
        let report = panic_report(&header, info);
        let path = dir.join(format!("panic-{pid}-{}.txt", now()));
        let _ = write_new(&path, report.as_bytes());
        previous(info);
    }));
}

/// The lines every report starts with.
pub fn header(process: &str) -> String {
    format!(
        "{TITLE}\nversion: {}\nprocess: {process}\nsystem: {} {}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

fn panic_report(header: &str, info: &std::panic::PanicHookInfo<'_>) -> String {
    let message = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_default();
    let place = info
        .location()
        .map(|l| format!("{}:{}", short_path(l.file()), l.line()))
        .unwrap_or_else(|| "unknown".into());
    // Thread names are ours ("enclave-notify"); anything else is left out.
    let thread = std::thread::current()
        .name()
        .filter(|n| {
            n.len() <= 64
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_:".contains(c))
        })
        .unwrap_or("unnamed")
        .to_string();
    let mut out = format!(
        "{header}kind: panic\nthread: {thread}\nwhere: {place}\nmessage: {}\n",
        scrub(&message)
    );
    let frames = frames(&std::backtrace::Backtrace::force_capture().to_string());
    if !frames.is_empty() {
        out.push_str("frames:\n");
        for f in frames {
            out.push_str("  ");
            out.push_str(&f);
            out.push('\n');
        }
    }
    out
}

/// A source path without where it was built: from `crates/` for ours,
/// from the crate's folder for a dependency, else the file name.
pub fn short_path(file: &str) -> String {
    let file = file.replace('\\', "/");
    if let Some(i) = file.find("crates/") {
        return file[i..].to_string();
    }
    for marker in ["/registry/src/", "/git/checkouts/"] {
        if let Some(i) = file.find(marker) {
            let rest = &file[i + marker.len()..];
            // Skip the index or checkout folder.
            if let Some(j) = rest.find('/') {
                return rest[j + 1..].to_string();
            }
        }
    }
    if let Some(i) = file.find("/library/") {
        return format!("std{}", &file[i..]);
    }
    file.rsplit('/').next().unwrap_or_default().to_string()
}

/// The function names in a printed backtrace: no addresses, no paths, no
/// hashes, and not the panic machinery itself.
pub fn frames(backtrace: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in backtrace.lines() {
        let line = line.trim();
        let Some((index, name)) = line.split_once(": ") else {
            continue;
        };
        if index.is_empty() || !index.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let name = strip_hash(name.trim());
        let machinery = [
            "std::",
            "core::",
            "alloc::",
            "rust_begin_unwind",
            "__rust",
            "enclave_crash::install",
            "enclave_crash::panic_report",
            "<alloc::",
            "<core::",
            "<std::",
            "__libc",
            "_start",
            "clone",
            "start_thread",
            "<unknown>",
        ];
        if machinery.iter().any(|m| name.starts_with(m)) {
            continue;
        }
        // Names are code, but be strict anyway: only what a Rust path can
        // hold.
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " _:<>,&'()[]{}*#".contains(c) || c == '-')
        {
            continue;
        }
        out.push(name.to_string());
        if out.len() == MAX_FRAMES {
            break;
        }
    }
    out
}

fn strip_hash(name: &str) -> &str {
    match name.rsplit_once("::h") {
        Some((head, hash)) if hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            head
        }
        _ => name,
    }
}

/// A panic message with anything that could be data taken out: quoted
/// text, anything in brackets or braces, paths, addresses, numbers longer
/// than three digits, and any word with digits or longer than 24
/// characters (identifiers, hex, base64). What is left is the shape of the
/// message as a developer wrote it.
pub fn scrub(message: &str) -> String {
    let mut flat = String::new();
    let mut close: Vec<char> = Vec::new();
    for c in message.chars() {
        if let Some(&want) = close.last() {
            if c == want {
                close.pop();
                if close.is_empty() {
                    flat.push('…');
                    flat.push(c);
                }
            } else if let Some(other) = opener(c)
                && !matches!(want, '"' | '\'' | '`')
            {
                close.push(other);
            }
            continue;
        }
        if let Some(other) = opener(c) {
            // An apostrophe inside a word is not a quote.
            if c == '\'' && flat.chars().last().is_some_and(char::is_alphanumeric) {
                flat.push(c);
                continue;
            }
            flat.push(c);
            close.push(other);
            continue;
        }
        flat.push(c);
    }
    if !close.is_empty() {
        flat.push('…');
    }
    let mut out: Vec<String> = Vec::new();
    for word in flat.split_whitespace() {
        let core = word.trim_matches(|c: char| ",.;:!?".contains(c));
        let keep = core.is_empty()
            || core.contains('…')
            || (core.chars().count() <= 24
                && !core.contains(['/', '\\', '@', '='])
                && (core
                    .chars()
                    .all(|c| c.is_alphabetic() || "-_'()[]{}\"`<>".contains(c))
                    || (core.chars().all(|c| c.is_ascii_digit()) && core.len() <= 3)));
        let w = if keep { word.to_string() } else { "…".into() };
        if w == "…" && out.last().is_some_and(|l| l == "…") {
            continue;
        }
        out.push(w);
    }
    let joined = out.join(" ");
    if joined.chars().count() > MAX_MESSAGE {
        joined.chars().take(MAX_MESSAGE).chain(['…']).collect()
    } else {
        joined
    }
}

fn opener(c: char) -> Option<char> {
    match c {
        '"' => Some('"'),
        '\'' => Some('\''),
        '`' => Some('`'),
        '[' => Some(']'),
        '{' => Some('}'),
        '(' => Some(')'),
        _ => None,
    }
}

/// A report on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Its file.
    pub path: PathBuf,
    /// Unix time it was written (from the file name).
    pub at: u64,
    /// Its text.
    pub text: String,
}

impl Report {
    /// The process that crashed ("vault", "app", …).
    pub fn process(&self) -> &str {
        self.field("process").unwrap_or("unknown")
    }

    /// A `name: value` line's value.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.text
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(": "))
    }
}

/// The reports in `dir`, newest first. Files that aren't reports are
/// ignored.
pub fn reports(dir: &Path) -> Vec<Report> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        let Some(at) = time_of(&path) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !text.starts_with(TITLE) || text.len() > 64 * 1024 {
            continue;
        }
        out.push(Report { path, at, text });
    }
    out.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| b.path.cmp(&a.path)));
    out
}

/// The time in a report's file name (`panic-PID-SECS.txt`,
/// `native-PID-SECS.txt`).
fn time_of(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?.strip_suffix(".txt")?;
    let rest = name
        .strip_prefix("panic-")
        .or_else(|| name.strip_prefix("native-"))?;
    rest.split_once('-')?.1.parse().ok()
}

/// Delete a report.
pub fn remove(report: &Report) -> std::io::Result<()> {
    std::fs::remove_file(&report.path)
}

/// Delete every report in `dir`.
pub fn remove_all(dir: &Path) {
    for r in reports(dir) {
        let _ = remove(&r);
    }
}

/// Keep the newest `keep` reports.
fn prune(dir: &Path, keep: usize) {
    for r in reports(dir).into_iter().skip(keep) {
        let _ = remove(&r);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn create_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_scrubbed() {
        assert_eq!(
            scrub("called `Option::unwrap()` on a `None` value"),
            "called `…` on a `…` value"
        );
        assert_eq!(
            scrub("index out of bounds: the len is 3 but the index is 12345"),
            "index out of bounds: the len is 3 but the index is …"
        );
        assert_eq!(
            scrub("bad message \"meet me at 6\" from Alice"),
            "bad message \"…\" from Alice"
        );
        assert_eq!(scrub("key [12, 200, 7, 9] rejected"), "key […] rejected");
        assert_eq!(
            scrub("failed to open /home/robin/.local/share/enclave/profile.redb"),
            "failed to open …"
        );
        assert_eq!(
            scrub("token 3q2+7w== and deadbeefcafebabe12 refused"),
            "token … and … refused"
        );
        assert_eq!(scrub("it's broken (really)"), "it's broken (…)");
        assert_eq!(scrub("unclosed \"secret words here"), "unclosed \"…");
        assert!(scrub(&"word ".repeat(200)).chars().count() <= MAX_MESSAGE + 1);
    }

    #[test]
    fn paths_lose_where_they_were_built() {
        assert_eq!(
            short_path("/home/user/Enclave/crates/enclave-core/src/client.rs"),
            "crates/enclave-core/src/client.rs"
        );
        assert_eq!(
            short_path(
                "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/redb-4.3.0/src/db.rs"
            ),
            "redb-4.3.0/src/db.rs"
        );
        assert_eq!(short_path("C:\\build\\src\\main.rs"), "main.rs");
    }

    #[test]
    fn frames_are_names_only() {
        let bt = "   0: std::backtrace_rs::backtrace::libunwind::trace\n             at /rustc/abc/library/std/src/../../backtrace/src/backtrace/libunwind.rs:117:9\n   1: enclave_crash::panic_report\n   2: enclave_core::client::Client::sync::h0123456789abcdef\n             at /home/user/Enclave/crates/enclave-core/src/client.rs:10:5\n   3: <enclave_vault::Engine as core::ops::Drop>::drop\n   4: main\n   5: __libc_start_main\n";
        assert_eq!(
            frames(bt),
            vec![
                "enclave_core::client::Client::sync",
                "<enclave_vault::Engine as core::ops::Drop>::drop",
                "main"
            ]
        );
    }

    #[test]
    fn reports_are_listed_newest_first_and_pruned() {
        let dir = std::env::temp_dir().join(format!("enclave-crash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = create_dir(&dir);
        for (name, body) in [
            (
                "panic-1-100.txt",
                format!("{}process: vault\n", header("vault")),
            ),
            ("native-2-300.txt", header("netd")),
            ("panic-3-200.txt", header("app")),
            ("notes.txt", "not a report".into()),
            ("panic-4-400.txt", "not a report either".into()),
        ] {
            let _ = write_new(&dir.join(name), body.as_bytes());
        }
        let found = reports(&dir);
        assert_eq!(
            found.iter().map(|r| r.at).collect::<Vec<_>>(),
            vec![300, 200, 100]
        );
        assert_eq!(found[0].process(), "netd");
        assert_eq!(found[0].field("version"), Some(env!("CARGO_PKG_VERSION")));
        prune(&dir, 1);
        assert_eq!(reports(&dir).len(), 1);
        remove_all(&dir);
        assert!(reports(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_panic_leaves_a_scrubbed_report() {
        // In a child process: the hook is process-wide.
        if let Some(dir) = std::env::var_os("ENCLAVE_CRASH_CHILD") {
            install(Path::new(&dir), "test");
            let secret = String::from("hunter2 correct horse");
            let r: Result<(), String> = Err(secret);
            #[allow(clippy::unwrap_used, clippy::unnecessary_literal_unwrap)]
            r.unwrap();
            return;
        }
        let dir = std::env::temp_dir().join(format!("enclave-crash-child-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let status = std::process::Command::new(std::env::current_exe().unwrap_or_default())
            .args(["--exact", "tests::a_panic_leaves_a_scrubbed_report"])
            .env("ENCLAVE_CRASH_CHILD", &dir)
            .env("RUST_BACKTRACE", "0")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        assert!(status.is_ok_and(|s| !s.success()));
        let found = reports(&dir);
        assert_eq!(found.len(), 1, "{found:?}");
        let text = &found[0].text;
        assert_eq!(found[0].field("kind"), Some("panic"));
        assert_eq!(found[0].process(), "test");
        assert!(
            found[0]
                .field("where")
                .is_some_and(|w| w.starts_with("crates/enclave-crash/src/lib.rs:")),
            "{text}"
        );
        assert!(
            !text.contains("hunter2") && !text.contains("horse"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
