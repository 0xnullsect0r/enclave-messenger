//! Helper processes: consoles on Windows, and helpers run as threads where
//! an app is one process (Android, iOS; [`register`], [`start`]).
//!
//! The app is a GUI program (`windows_subsystem = "windows"`), so it opens
//! no console window. Its helpers (vault, netd, mediad, tord, nymd) are
//! console programs, usable from a terminal, but started from the app
//! with [`CREATE_NO_WINDOW`] so none of them flashes a window either.
//! Elsewhere both are no-ops.

/// `CREATE_NO_WINDOW`: the child gets no console window (its standard
/// handles are the pipes it was given).
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Start `cmd` without a console window (Windows).
#[allow(unused_variables)]
pub fn no_window(cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
}

/// When a GUI program was started from a terminal, write `eprintln!`
/// output there (Windows: attach to the parent's console, if it has one).
/// Call it first thing, before anything is printed.
pub fn attach_parent_console() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
        // SAFETY: AttachConsole takes a process id by value and touches no
        // memory of ours; it fails harmlessly when there is no parent
        // console or one is already attached.
        let _ = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
    }
}

/// A helper's standard input and output: pipes to the program that
/// started it.
pub struct Stdio {
    /// What the parent writes to it.
    pub input: std::fs::File,
    /// What it writes back.
    pub output: std::fs::File,
}

/// A helper's entry point, given its arguments (without the program name):
/// what its `main` runs. It reads and writes through [`stdio`].
pub type Entry = fn(Vec<String>) -> std::process::ExitCode;

thread_local! {
    static ASSIGNED: std::cell::RefCell<Option<Stdio>> = const { std::cell::RefCell::new(None) };
    static IN_PROCESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn registry() -> &'static std::sync::Mutex<std::collections::HashMap<&'static str, Entry>> {
    static R: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<&'static str, Entry>>,
    > = std::sync::OnceLock::new();
    R.get_or_init(Default::default)
}

/// Run the helper `name` (`enclave-netd`, …) as a thread of this process
/// instead of a program next to it: on Android and iOS, where an app is
/// one process (iOS starts no programs at all), the helpers are linked
/// into the app and register themselves here.
pub fn register(name: &'static str, entry: Entry) {
    if let Ok(mut r) = registry().lock() {
        r.insert(name, entry);
    }
}

/// Whether the helper `name` runs in this process ([`register`]).
pub fn registered(name: &str) -> bool {
    registry().lock().is_ok_and(|r| r.contains_key(name))
}

/// Whether this code runs as a helper thread ([`start`]) rather than in a
/// process of its own: process-wide steps (confining the process) are left
/// to the process.
pub fn in_process() -> bool {
    IN_PROCESS.with(std::cell::Cell::get)
}

/// This helper's standard input and output: the pipes [`start`] gave its
/// thread, or the process's own (each call takes a fresh handle).
pub fn stdio() -> std::io::Result<Stdio> {
    if let Some(s) = ASSIGNED.with(|a| a.borrow_mut().take()) {
        return Ok(s);
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let input = std::io::stdin().as_fd().try_clone_to_owned()?;
        let output = std::io::stdout().as_fd().try_clone_to_owned()?;
        Ok(Stdio {
            input: input.into(),
            output: output.into(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        let input = std::io::stdin().as_handle().try_clone_to_owned()?;
        let output = std::io::stdout().as_handle().try_clone_to_owned()?;
        Ok(Stdio {
            input: input.into(),
            output: output.into(),
        })
    }
}

/// A helper started as a thread: the parent's ends of its pipes.
pub struct InProcess {
    /// Write here: the helper reads it as its input.
    pub stdin: std::fs::File,
    /// Read here: what the helper writes.
    pub stdout: std::fs::File,
}

/// Start the registered helper `name` with `args` on a thread of its own,
/// connected by pipes as a child process would be (`None` when it isn't
/// registered: start the program instead). It ends when its input closes,
/// as the programs do.
pub fn start(name: &str, args: Vec<String>) -> std::io::Result<Option<InProcess>> {
    let entry = match registry().lock() {
        Ok(r) => match r.get(name) {
            Some(e) => *e,
            None => return Ok(None),
        },
        Err(_) => return Ok(None),
    };
    let (child_in, parent_in) = std::io::pipe()?;
    let (parent_out, child_out) = std::io::pipe()?;
    let assigned = Stdio {
        input: file_from_reader(child_in),
        output: file_from_writer(child_out),
    };
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            ASSIGNED.with(|a| *a.borrow_mut() = Some(assigned));
            IN_PROCESS.with(|f| f.set(true));
            let _ = entry(args);
            // The helper's pipe ends close with it (if it didn't take them).
            ASSIGNED.with(|a| a.borrow_mut().take());
        })?;
    Ok(Some(InProcess {
        stdin: file_from_writer(parent_in),
        stdout: file_from_reader(parent_out),
    }))
}

#[cfg(unix)]
fn file_from_reader(p: std::io::PipeReader) -> std::fs::File {
    std::os::fd::OwnedFd::from(p).into()
}
#[cfg(unix)]
fn file_from_writer(p: std::io::PipeWriter) -> std::fs::File {
    std::os::fd::OwnedFd::from(p).into()
}
#[cfg(windows)]
fn file_from_reader(p: std::io::PipeReader) -> std::fs::File {
    std::os::windows::io::OwnedHandle::from(p).into()
}
#[cfg(windows)]
fn file_from_writer(p: std::io::PipeWriter) -> std::fs::File {
    std::os::windows::io::OwnedHandle::from(p).into()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, Write};

    fn echo(args: Vec<String>) -> std::process::ExitCode {
        let Ok(io) = super::stdio() else {
            return std::process::ExitCode::FAILURE;
        };
        assert!(super::in_process());
        let mut out = io.output;
        let _ = writeln!(out, "args {}", args.join(" "));
        for line in std::io::BufReader::new(io.input).lines() {
            let Ok(l) = line else { break };
            let _ = writeln!(out, "echo {l}");
        }
        std::process::ExitCode::SUCCESS
    }

    #[test]
    fn a_registered_helper_runs_as_a_thread() {
        assert!(
            super::start("enclave-test-missing", vec![])
                .unwrap()
                .is_none()
        );
        super::register("enclave-test-echo", echo);
        assert!(super::registered("enclave-test-echo"));
        assert!(!super::in_process());
        let mut h = super::start("enclave-test-echo", vec!["a".into(), "b".into()])
            .unwrap()
            .unwrap();
        writeln!(h.stdin, "hello").unwrap();
        drop(h.stdin);
        let lines: Vec<String> = std::io::BufReader::new(h.stdout)
            .lines()
            .map(Result::unwrap)
            .collect();
        assert_eq!(lines, ["args a b", "echo hello"]);
    }
}
