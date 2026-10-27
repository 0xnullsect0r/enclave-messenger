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

/// Whether this code runs as a helper thread ([`start`], [`serve`]) rather
/// than as a program of its own: process-wide steps (confining the
/// process) are left to the process, or to the system's sandbox for the
/// app's helper processes (Android's `isolatedProcess`).
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

/// Where a helper can run in a process of its own though the app starts
/// no programs (Android: a service of the app's in another process,
/// `HelperService`): given the helper's name and arguments, the app's ends
/// of its connection, or `None` to run it as a thread instead.
pub type Remote = fn(&str, &[String]) -> Option<InProcess>;

static REMOTE: std::sync::OnceLock<Remote> = std::sync::OnceLock::new();

/// Start registered helpers through `f` first ([`Remote`]; once, at start).
pub fn set_remote(f: Remote) {
    let _ = REMOTE.set(f);
}

/// Start the registered helper `name` with `args`: in a process of the
/// app's where there is a way ([`set_remote`]), else on a thread of its
/// own, connected by pipes as a child process would be (`None` when it
/// isn't registered: start the program instead). It ends when its input
/// closes, as the programs do.
pub fn start(name: &str, args: Vec<String>) -> std::io::Result<Option<InProcess>> {
    let entry = match registry().lock() {
        Ok(r) => match r.get(name) {
            Some(e) => *e,
            None => return Ok(None),
        },
        Err(_) => return Ok(None),
    };
    if let Some(remote) = REMOTE.get()
        && let Some(p) = remote(name, &args)
    {
        return Ok(Some(p));
    }
    let (child_in, parent_in) = std::io::pipe()?;
    let (parent_out, child_out) = std::io::pipe()?;
    let assigned = Stdio {
        input: file_from_reader(child_in),
        output: file_from_writer(child_out),
    };
    run(name, entry, args, assigned)?;
    Ok(Some(InProcess {
        stdin: file_from_writer(parent_in),
        stdout: file_from_reader(parent_out),
    }))
}

/// Run the registered helper `name` with `args` on a thread of its own,
/// reading and writing `io`: in a helper process of the app's, on the
/// connection the app handed over ([`Remote`]).
pub fn serve(name: &str, args: Vec<String>, io: Stdio) -> std::io::Result<()> {
    let entry = registry()
        .lock()
        .ok()
        .and_then(|r| r.get(name).copied())
        .ok_or_else(|| std::io::Error::other(format!("no helper {name}")))?;
    run(name, entry, args, io)
}

fn run(name: &str, entry: Entry, args: Vec<String>, assigned: Stdio) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            ASSIGNED.with(|a| *a.borrow_mut() = Some(assigned));
            IN_PROCESS.with(|f| f.set(true));
            let _ = entry(args);
            // The helper's pipe ends close with it (if it didn't take them).
            ASSIGNED.with(|a| a.borrow_mut().take());
        })?;
    Ok(())
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

/// Enclave's programs, by file name: the ones a profile's files are ever
/// open in.
#[cfg(target_os = "linux")]
const OURS: [&str; 6] = [
    "enclave-vault",
    "enclave-netd",
    "enclave-tord",
    "enclave-nymd",
    "enclave-mediad",
    "lyrebird",
];

/// End what is left of an earlier Enclave on `profile`: one of our
/// programs (not this process) that still has a file in `profile` open.
/// Call it only where no window is running on `profile` (the window that
/// is starting found none to hand over to), so whatever holds it is left
/// over: a vault from an older version that didn't exit when its window
/// went, keeping the profile's database locked so no new one could open
/// it. Each gets SIGTERM, then SIGKILL after three seconds. Returns what
/// was ended (`"enclave-vault (pid 4242)"`), for the log.
#[cfg(target_os = "linux")]
pub fn end_leftovers(profile: &std::path::Path) -> Vec<String> {
    let Ok(profile) = std::fs::canonicalize(profile) else {
        return Vec::new();
    };
    let me = std::process::id();
    let mut found: Vec<(u32, String)> = Vec::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Some(name) = program(pid) else { continue };
        if !OURS.contains(&name.as_str()) {
            continue;
        }
        let holds = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .map(|fds| {
                fds.flatten()
                    .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|t| t.starts_with(&profile)))
            })
            .unwrap_or(false);
        if holds {
            found.push((pid, name));
        }
    }
    for (pid, _) in &found {
        signal(*pid, libc::SIGTERM);
    }
    let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while found.iter().any(|(pid, _)| alive(*pid)) && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    for (pid, _) in &found {
        if alive(*pid) {
            signal(*pid, libc::SIGKILL);
        }
    }
    found
        .into_iter()
        .map(|(pid, name)| format!("{name} (pid {pid})"))
        .collect()
}

/// The file name of the program process `pid` runs (an updated program's
/// old file reads "… (deleted)", which is dropped).
#[cfg(target_os = "linux")]
fn program(pid: u32) -> Option<String> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let name = exe.file_name()?.to_str()?;
    Some(name.trim_end_matches(" (deleted)").to_string())
}

#[cfg(target_os = "linux")]
fn alive(pid: u32) -> bool {
    // A zombie (ended, not yet reaped) holds nothing.
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit(')')
            .next()
            .is_some_and(|r| !r.trim_start().starts_with('Z'))
    })
}

#[cfg(target_os = "linux")]
fn signal(pid: u32, sig: libc::c_int) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: kill(2) on a process id; it touches no memory of ours.
        unsafe { libc::kill(pid, sig) };
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, Write};

    /// A program of ours left holding a file in the profile (here `tail`
    /// under the vault's name) is ended; one holding nothing there isn't.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_leftover_holding_the_profile_is_ended() {
        let dir = std::env::temp_dir().join(format!("enclave-leftover-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let profile = dir.join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(profile.join("profile.redb"), b"db").unwrap();
        let vault = dir.join("enclave-vault");
        std::fs::copy("/usr/bin/tail", &vault).unwrap();
        let other = dir.join("enclave-netd");
        std::fs::copy("/usr/bin/sleep", &other).unwrap();
        let mut holder = std::process::Command::new(&vault)
            .arg("-f")
            .arg(profile.join("profile.redb"))
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut idle = std::process::Command::new(&other)
            .arg("30")
            .spawn()
            .unwrap();
        // Until it has the file open.
        let fd_open = || {
            std::fs::read_dir(format!("/proc/{}/fd", holder.id()))
                .unwrap()
                .flatten()
                .any(|f| std::fs::read_link(f.path()).is_ok_and(|t| t.ends_with("profile.redb")))
        };
        for _ in 0..50 {
            if fd_open() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let ended = super::end_leftovers(&profile);
        assert_eq!(ended, vec![format!("enclave-vault (pid {})", holder.id())]);
        assert!(holder.wait().is_ok());
        assert!(idle.try_wait().unwrap().is_none(), "holds nothing there");
        let _ = idle.kill();
        let _ = idle.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

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
