//! Helper processes and consoles on Windows.
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
