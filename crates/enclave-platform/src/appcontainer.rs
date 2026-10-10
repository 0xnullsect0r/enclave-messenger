//! Windows: starting a helper inside an AppContainer with no capabilities
//! (PC-43): it can't reach the network, other processes, or files and
//! registry keys not granted to all app containers, and runs at low
//! integrity. mediad runs this way; its only channel is the two pipes it
//! is given.

use std::fs::File;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{FreeSid, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute,
};

/// A contained child: its stdin and stdout, and the process, ended when
/// this is dropped.
pub struct Contained {
    /// Writes reach the child's stdin.
    pub stdin: File,
    /// Reads come from the child's stdout.
    pub stdout: File,
    process: HANDLE,
}

// SAFETY: the process handle is an owned kernel handle, usable from any
// thread.
unsafe impl Send for Contained {}
// SAFETY: as above; nothing is mutated through a shared reference.
unsafe impl Sync for Contained {}

impl Drop for Contained {
    fn drop(&mut self) {
        // SAFETY: an owned process handle, ended and closed once.
        unsafe {
            TerminateProcess(self.process, 1);
            CloseHandle(self.process);
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// The container's SID, made on first use and found after.
fn container_sid(name: &str) -> std::io::Result<PSID> {
    let n = wide(name);
    let display = wide("Enclave helper");
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: the strings are NUL-terminated and live across the call; no
    // capabilities (null, 0); `sid` receives a SID we free with FreeSid.
    let hr = unsafe {
        CreateAppContainerProfile(
            n.as_ptr(),
            display.as_ptr(),
            display.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    if hr >= 0 {
        return Ok(sid);
    }
    // Already made (HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)): look it up.
    // SAFETY: as above; `sid` receives a SID we free with FreeSid.
    let hr = unsafe { DeriveAppContainerSidFromAppContainerName(n.as_ptr(), &mut sid) };
    if hr >= 0 {
        Ok(sid)
    } else {
        Err(std::io::Error::other(format!("app container: {hr:#x}")))
    }
}

/// A pipe whose `child` end is inheritable and whose other end isn't.
fn pipe(child_reads: bool) -> std::io::Result<(HANDLE, HANDLE)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: out-pointers to two handles and a live SECURITY_ATTRIBUTES.
    if unsafe { CreatePipe(&mut read, &mut write, &sa, 0) } == 0 {
        return Err(last_error());
    }
    let (child, ours) = if child_reads {
        (read, write)
    } else {
        (write, read)
    };
    // SAFETY: `ours` is a handle we just made; only its inherit flag changes.
    unsafe { SetHandleInformation(ours, HANDLE_FLAG_INHERIT, 0) };
    Ok((child, ours))
}

/// Start `exe` with `args` in the app container `name`, with no window,
/// its stdin and stdout piped to us and its stderr discarded.
pub fn spawn(exe: &Path, args: &[&str], name: &str) -> std::io::Result<Contained> {
    let sid = container_sid(name)?;
    let result = spawn_with(exe, args, sid);
    // SAFETY: the SID came from the calls above and is freed once.
    unsafe { FreeSid(sid) };
    result
}

fn spawn_with(exe: &Path, args: &[&str], sid: PSID) -> std::io::Result<Contained> {
    let (child_in, our_in) = pipe(true)?;
    let (child_out, our_out) = pipe(false)?;
    let close_all = || {
        // SAFETY: handles we made, each closed once on this failure path.
        unsafe {
            CloseHandle(child_in);
            CloseHandle(child_out);
            CloseHandle(our_in);
            CloseHandle(our_out);
        }
    };
    let mut caps = SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut inherit = [child_in, child_out];
    // Two attributes: the container, and the only handles it inherits.
    let mut size = 0usize;
    // SAFETY: the documented size query (null list), which fails with
    // ERROR_INSUFFICIENT_BUFFER and writes the size.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size) };
    let mut buf = vec![0u8; size];
    let list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    // SAFETY: `buf` is `size` bytes, as asked for, and outlives the list.
    if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) } == 0 {
        close_all();
        return Err(last_error());
    }
    // SAFETY: the attribute values point to `caps` and `inherit`, which
    // live until CreateProcessW returns; sizes are theirs.
    let ok = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&raw mut caps).cast(),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        ) != 0
            && UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherit.as_mut_ptr().cast(),
                std::mem::size_of_val(&inherit),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) != 0
    };
    if !ok {
        let e = last_error();
        // SAFETY: the list was initialised above.
        unsafe { DeleteProcThreadAttributeList(list) };
        close_all();
        return Err(e);
    }
    // SAFETY: an all-zero STARTUPINFOEXW is valid; the fields used are set
    // below.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = child_in;
    si.StartupInfo.hStdOutput = child_out;
    si.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    si.lpAttributeList = list;
    let exe_w = wide(&exe.to_string_lossy());
    let mut line = format!("\"{}\"", exe.to_string_lossy());
    for a in args {
        line.push_str(&format!(" \"{a}\""));
    }
    let mut line_w = wide(&line);
    // SAFETY: an all-zero PROCESS_INFORMATION is valid output space.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated program and (mutable, as required) command
    // line; inherited handles limited by the attribute list; `si` and `pi`
    // live across the call.
    let created = unsafe {
        CreateProcessW(
            exe_w.as_ptr(),
            line_w.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    let err = last_error();
    // SAFETY: done with the list and the child's pipe ends (it has its
    // own copies now, or failed to start).
    unsafe {
        DeleteProcThreadAttributeList(list);
        CloseHandle(child_in);
        CloseHandle(child_out);
    }
    if created == 0 {
        // SAFETY: our ends, closed once on failure.
        unsafe {
            CloseHandle(our_in);
            CloseHandle(our_out);
        }
        return Err(err);
    }
    // SAFETY: the thread handle isn't needed.
    unsafe { CloseHandle(pi.hThread) };
    Ok(Contained {
        // SAFETY: our pipe ends are owned handles, each given to one File.
        stdin: unsafe { File::from_raw_handle(our_in) },
        // SAFETY: as above.
        stdout: unsafe { File::from_raw_handle(our_out) },
        process: pi.hProcess,
    })
}
