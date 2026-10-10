//! Process hardening for the vault and netd (`docs/15-client.md` §1.1a).
//!
//! * No core dumps, and (Linux) not dumpable: other processes of the same
//!   user can't attach a debugger or read `/proc/<pid>/mem`, and a crash
//!   leaves no memory image with keys in it.
//! * `no_new_privs`: nothing the process runs can gain privileges.
//! * (Linux) a Landlock sandbox. The vault can only read and write its
//!   profile directory and read the few files the engine needs (pins, time
//!   zone data); with netd running it also may not open or accept any TCP
//!   connection, so the network is only reachable through netd. netd gets no
//!   filesystem access at all.
//! * (Linux) a seccomp allow-list ([`syscalls`]): the calls a process of
//!   that kind makes once it runs, and `EPERM` for every other (starting
//!   programs, debugging others, namespaces, kernel modules, `io_uring`,
//!   and anything new), with arguments checked where a call can do more
//!   (`socket` only for IPv4 and IPv6 in netd, `ioctl` and `prctl` only for
//!   harmless requests, `clone` never a new user namespace). Landlock can't
//!   stop UDP or raw sockets; this does.
//! * (macOS) a Seatbelt profile per process instead ([`filesystem`]).
//!
//! Every step is best effort: the processes keep working on kernels without
//! a feature, and report what they got.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::PathBuf;

/// What hardening took effect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Core dump size limit set to zero.
    pub no_core_dumps: bool,
    /// Marked not dumpable (Linux).
    pub not_dumpable: bool,
    /// `no_new_privs` set.
    pub no_new_privs: bool,
    /// Filesystem sandbox: "full", "partial", "unavailable" or "off".
    pub filesystem: &'static str,
    /// Where the network is: "netd" (a separate process; this one may not
    /// open TCP connections) or "in-process".
    pub network: &'static str,
    /// System-call filter: "filtered", "unavailable", "error" or "off".
    pub syscalls: &'static str,
    /// Where pictures are decoded: "mediad" (a separate confined process)
    /// or "in-process".
    pub media: &'static str,
}

/// Which system calls a process keeps: an allow-list, everything else
/// failing with `EPERM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The vault: files (Landlock limits which), no new sockets of any
    /// kind (its UI connection and netd's pipes exist before the filter).
    Vault,
    /// netd, tord and nymd: the vault's, plus new IPv4 and IPv6 sockets.
    Netd,
    /// mediad: no files and no sockets at all, only the pipes it holds.
    Media,
}

/// Harden the running process. Call first thing.
pub fn process() -> Report {
    #[allow(unused_mut)]
    let mut r = Report {
        filesystem: "off",
        network: "in-process",
        syscalls: "off",
        media: "in-process",
        ..Report::default()
    };
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        r.no_core_dumps = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .is_ok();
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        r.not_dumpable = set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok();
        r.no_new_privs = rustix::thread::set_no_new_privs(true).is_ok();
    }
    r
}

/// Cap the address space at `bytes` (Unix), so a picture that decodes to
/// more than it claimed fails an allocation instead of exhausting memory.
/// Returns whether the limit took effect.
pub fn memory_limit(bytes: u64) -> bool {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        setrlimit(
            Resource::As,
            Rlimit {
                current: Some(bytes),
                maximum: Some(bytes),
            },
        )
        .is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        false
    }
}

/// Install the seccomp filter for `profile` (Linux) on every thread of the
/// process, or with `this_thread_only` on the calling thread (tests). Call
/// after everything that needs the denied calls (spawning netd, connecting
/// to the UI). Returns "filtered", "unavailable" or "error".
pub fn syscalls(profile: Profile, this_thread_only: bool) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        match filter(profile) {
            Some(prog) => {
                let applied = if this_thread_only {
                    seccompiler::apply_filter(&prog)
                } else {
                    seccompiler::apply_filter_all_threads(&prog)
                };
                if applied.is_ok() { "filtered" } else { "error" }
            }
            None => "unavailable",
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, this_thread_only);
        "unavailable"
    }
}

/// System calls every confined process may make: memory, threads, time,
/// signals, polling, and reading and writing descriptors it already holds.
#[cfg(target_os = "linux")]
const BASE: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_preadv2,
    libc::SYS_pwritev2,
    libc::SYS_lseek,
    libc::SYS_close,
    libc::SYS_close_range,
    libc::SYS_dup,
    libc::SYS_dup3,
    libc::SYS_fcntl,
    libc::SYS_fstat,
    libc::SYS_futex,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_rseq,
    libc::SYS_set_tid_address,
    libc::SYS_clone3,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_tgkill,
    libc::SYS_tkill,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_getparam,
    libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max,
    libc::SYS_sched_get_priority_min,
    libc::SYS_getpriority,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_restart_syscall,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_rt_sigsuspend,
    libc::SYS_sigaltstack,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_msync,
    libc::SYS_brk,
    libc::SYS_mlock,
    libc::SYS_mlock2,
    libc::SYS_munlock,
    libc::SYS_membarrier,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_eventfd2,
    libc::SYS_pipe2,
    libc::SYS_ppoll,
    libc::SYS_pselect6,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_getrandom,
    libc::SYS_uname,
    libc::SYS_sysinfo,
    libc::SYS_prlimit64,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getresuid,
    libc::SYS_getresgid,
    libc::SYS_getgroups,
    // Children started before the filter: waited for, and ended.
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_kill,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_send_signal,
    // Sockets held from before the filter (the window's, netd's pipes).
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_recvmsg,
    libc::SYS_sendmsg,
    libc::SYS_recvmmsg,
    libc::SYS_sendmmsg,
    libc::SYS_shutdown,
    libc::SYS_getsockopt,
    libc::SYS_setsockopt,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
];

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BASE_X86: &[libc::c_long] = &[
    libc::SYS_arch_prctl,
    libc::SYS_poll,
    libc::SYS_select,
    libc::SYS_epoll_wait,
    libc::SYS_getrlimit,
    libc::SYS_time,
    libc::SYS_dup2,
    libc::SYS_pipe,
];

/// Files (within what Landlock allows): the vault's profile, tord's state.
#[cfg(target_os = "linux")]
const FILES: &[libc::c_long] = &[
    libc::SYS_openat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_getdents64,
    libc::SYS_mkdirat,
    libc::SYS_unlinkat,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_readlinkat,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_ftruncate,
    libc::SYS_fallocate,
    libc::SYS_flock,
    libc::SYS_getcwd,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_utimensat,
];

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const FILES_X86: &[libc::c_long] = &[
    libc::SYS_open,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_access,
    libc::SYS_mkdir,
    libc::SYS_rmdir,
    libc::SYS_unlink,
    libc::SYS_rename,
    libc::SYS_readlink,
];

/// New connections: netd, tord and nymd (`socket` itself only for IPv4 and
/// IPv6, below).
#[cfg(target_os = "linux")]
const NET: &[libc::c_long] = &[
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept4,
];

#[cfg(target_os = "linux")]
fn filter(profile: Profile) -> Option<seccompiler::BpfProgram> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond,
        SeccompFilter, SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;
    let arch: TargetArch = std::env::consts::ARCH.try_into().ok()?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut allow = |set: &[libc::c_long]| {
        for nr in set {
            rules.insert(*nr, Vec::new());
        }
    };
    allow(BASE);
    #[cfg(target_arch = "x86_64")]
    allow(BASE_X86);
    if profile != Profile::Media {
        allow(FILES);
        #[cfg(target_arch = "x86_64")]
        allow(FILES_X86);
    }
    if profile == Profile::Netd {
        allow(NET);
        #[cfg(target_arch = "x86_64")]
        allow(&[libc::SYS_accept]);
    }
    // Only these cases of the calls that can do more.
    let eq = |arg: u8, v: u64| Cond::new(arg, Len::Qword, Op::Eq, v);
    let one = |c: Result<Cond, seccompiler::BackendError>| -> Option<SeccompRule> {
        SeccompRule::new(vec![c.ok()?]).ok()
    };
    // Threads, never a new user namespace (clone3 passes its flags by
    // pointer, which seccomp can't read; unshare and setns aren't allowed).
    let newuser = libc::CLONE_NEWUSER as u64;
    rules.insert(
        libc::SYS_clone,
        vec![one(Cond::new(0, Len::Qword, Op::MaskedEq(newuser), 0))?],
    );
    // Terminal and non-blocking checks only (request constants are u64 on
    // glibc targets, other widths elsewhere).
    #[allow(clippy::unnecessary_cast)]
    rules.insert(
        libc::SYS_ioctl,
        [
            libc::TCGETS,
            libc::FIONBIO,
            libc::FIOCLEX,
            libc::FIONCLEX,
            libc::FIONREAD,
        ]
        .iter()
        .map(|r| one(eq(1, *r as u64)))
        .collect::<Option<Vec<_>>>()?,
    );
    // Thread names and reading state: not PR_SET_DUMPABLE, PR_SET_PTRACER
    // or anything else that would undo the hardening.
    rules.insert(
        libc::SYS_prctl,
        [
            libc::PR_SET_NAME as u64,
            libc::PR_GET_NAME as u64,
            libc::PR_GET_DUMPABLE as u64,
            libc::PR_CAPBSET_READ as u64,
            0x5356_4d41, // PR_SET_VMA (naming anonymous memory)
        ]
        .iter()
        .map(|o| one(eq(0, *o)))
        .collect::<Option<Vec<_>>>()?,
    );
    // A connected pair of Unix sockets inside the process (tokio's signal
    // handling makes one): it reaches nothing outside.
    rules.insert(
        libc::SYS_socketpair,
        vec![one(Cond::new(0, Len::Dword, Op::Eq, libc::AF_UNIX as u64))?],
    );
    if profile == Profile::Netd {
        // IPv4 and IPv6 only.
        rules.insert(
            libc::SYS_socket,
            [libc::AF_INET, libc::AF_INET6]
                .iter()
                .map(|af| one(Cond::new(0, Len::Dword, Op::Eq, *af as u64)))
                .collect::<Option<Vec<_>>>()?,
        );
    }
    // Everything else fails. `ENCLAVE_SECCOMP_LOG=1` logs instead, to find
    // a call a new library version makes.
    let refuse = if std::env::var_os("ENCLAVE_SECCOMP_LOG").is_some() {
        SeccompAction::Log
    } else {
        SeccompAction::Errno(libc::EPERM as u32)
    };
    let f = SeccompFilter::new(rules, refuse, SeccompAction::Allow, arch).ok()?;
    f.try_into().ok()
}

/// Restrict the filesystem to `read_write` and `read_only` paths, and with
/// `deny_tcp` forbid opening or accepting TCP connections (Linux). Returns
/// how much of the sandbox the kernel enforces.
pub fn filesystem(read_write: &[PathBuf], read_only: &[PathBuf], deny_tcp: bool) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetStatus, path_beneath_rules,
        };
        let abi = ABI::V5;
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| {
                if deny_tcp {
                    // Handled with no rules allowing any port: all denied.
                    r.handle_access(AccessNet::from_all(abi))
                } else {
                    Ok(r)
                }
            })
            .and_then(|r| r.create())
            .and_then(|r| r.add_rules(path_beneath_rules(read_only, AccessFs::from_read(abi))))
            .and_then(|r| r.add_rules(path_beneath_rules(read_write, AccessFs::from_all(abi))))
            .and_then(|r| r.restrict_self());
        match status.map(|s| s.ruleset) {
            Ok(RulesetStatus::FullyEnforced) => "full",
            Ok(RulesetStatus::PartiallyEnforced) => "partial",
            Ok(_) => "unavailable",
            Err(_) => "error",
        }
    }
    #[cfg(target_os = "macos")]
    {
        match enclave_platform::seatbelt::confine(&seatbelt_profile(
            read_write, read_only, deny_tcp,
        )) {
            Ok(()) => "full",
            Err(_) => "error",
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (read_write, read_only, deny_tcp);
        "unavailable"
    }
}

/// The macOS Seatbelt profile for [`filesystem`]: what Landlock and
/// seccomp do on Linux, as far as Seatbelt reaches. No programs are
/// started; nothing is written outside `read_write` (and the per-user
/// temporary folder, where system frameworks keep caches); nothing in the
/// home folder is read outside `read_write` and `read_only`; with
/// `deny_tcp`, no IP connection is made or accepted. System libraries and
/// services (the Keychain, through its daemon) stay reachable.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn seatbelt_profile(read_write: &[PathBuf], read_only: &[PathBuf], deny_tcp: bool) -> String {
    let quoted = |p: &PathBuf| {
        let p = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        let s = p
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!("(subpath \"{s}\")")
    };
    let rw: Vec<String> = read_write.iter().map(quoted).collect();
    let ro: Vec<String> = read_only.iter().map(quoted).collect();
    let mut sb =
        String::from("(version 1)\n(allow default)\n(deny process-exec*)\n(deny process-fork)\n");
    sb.push_str(&format!(
        "(deny file-write* (require-not (require-any (literal \"/dev/null\") (subpath \"/private/var/folders\") {})))\n",
        rw.join(" ")
    ));
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let mut keep = rw.clone();
        keep.extend(ro);
        sb.push_str(&format!(
            "(deny file-read* (require-all {} (require-not (require-any (literal \"/dev/null\") {}))))\n",
            quoted(&home),
            keep.join(" ")
        ));
    }
    if deny_tcp {
        sb.push_str("(deny network-outbound (remote ip))\n(deny network-inbound (local ip))\n(deny network-bind (local ip))\n");
    }
    sb
}

#[cfg(test)]
mod profile_tests {
    #![allow(clippy::unwrap_used)]

    /// The macOS profile keeps the profile directory writable, the rest of
    /// the home folder unreadable, and IP off when asked.
    #[test]
    fn seatbelt_profile_says_what_it_should() {
        let p = super::seatbelt_profile(
            &[std::path::PathBuf::from("/tmp/enclave \"q\"")],
            &[std::path::PathBuf::from("/etc/localtime")],
            true,
        );
        assert!(p.starts_with("(version 1)"));
        assert!(p.contains("(deny process-exec*)"));
        assert!(p.contains("(subpath \"/tmp/enclave \\\"q\\\"\")"), "{p}");
        assert!(p.contains("(deny network-outbound (remote ip))"));
        assert!(!super::seatbelt_profile(&[], &[], false).contains("network"));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    /// Landlock confines the calling thread (and threads it starts), so the
    /// sandbox can be tried on a thread of its own.
    #[test]
    fn sandbox_denies_tcp_and_files() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = std::env::temp_dir().join(format!("enclave-harden-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let allowed = dir.join("ok");
        let (status, tcp, outside, inside) = std::thread::spawn({
            let dir = dir.clone();
            move || {
                let status = super::filesystem(&[dir], &[], true);
                let tcp = std::net::TcpStream::connect(addr).is_ok();
                let outside =
                    std::fs::read("/etc/hostname").is_ok() || std::fs::read("/etc/passwd").is_ok();
                let inside = std::fs::write(&allowed, b"x").is_ok();
                (status, tcp, outside, inside)
            }
        })
        .join()
        .unwrap();
        // Before and after, this thread is unaffected.
        assert!(std::net::TcpStream::connect(addr).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
        match status {
            "full" => {
                assert!(!tcp, "TCP connect allowed in the sandbox");
                assert!(!outside, "read outside the sandbox allowed");
                assert!(inside, "profile not writable");
            }
            // Old kernels: nothing (or not everything) is enforced; the
            // vault reports it and keeps working.
            other => eprintln!("landlock: {other}"),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod seccomp_tests {
    #![allow(clippy::unwrap_used)]
    use super::{Profile, syscalls};

    fn in_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(f).join().unwrap()
    }

    #[test]
    fn vault_profile_denies_sockets_and_programs() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (status, tcp, udp, unix, exec, file) = in_thread(move || {
            let status = syscalls(Profile::Vault, true);
            (
                status,
                std::net::TcpStream::connect(addr).is_ok(),
                std::net::UdpSocket::bind("127.0.0.1:0").is_ok(),
                std::os::unix::net::UnixDatagram::unbound().is_ok(),
                std::process::Command::new("/bin/true").status().is_ok(),
                std::fs::read("/proc/self/status").is_ok(),
            )
        });
        assert_eq!(status, "filtered");
        assert!(!tcp && !udp && !unix, "sockets allowed");
        assert!(!exec, "exec allowed");
        assert!(file, "ordinary calls still work");
        // Other threads are unaffected.
        assert!(std::net::UdpSocket::bind("127.0.0.1:0").is_ok());
    }

    #[test]
    fn netd_profile_keeps_ip_sockets_only() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (status, tcp, unix, exec) = in_thread(move || {
            let status = syscalls(Profile::Netd, true);
            (
                status,
                std::net::TcpStream::connect(addr).is_ok(),
                std::os::unix::net::UnixDatagram::unbound().is_ok(),
                std::process::Command::new("/bin/true").status().is_ok(),
            )
        });
        assert_eq!(status, "filtered");
        assert!(tcp, "netd must reach servers");
        assert!(!unix && !exec);
    }

    /// mediad's profile: no files, no sockets, no programs, and no turning
    /// the hardening back (`PR_SET_DUMPABLE`); threads and pipes still work.
    #[test]
    fn media_profile_keeps_only_its_pipes() {
        let (status, file, tcp, exec, dumpable, thread, pipe) = in_thread(|| {
            let (r, mut w) = std::io::pipe().unwrap();
            let status = syscalls(Profile::Media, true);
            let file = std::fs::File::open("/etc/hostname").is_ok();
            let tcp = std::net::TcpStream::connect("127.0.0.1:9").is_ok();
            let exec = std::process::Command::new("/bin/true").status().is_ok();
            let dumpable =
                rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable)
                    .is_ok();
            let thread = std::thread::spawn(|| 2 + 2).join().is_ok()
                && std::os::unix::net::UnixStream::pair().is_ok();
            use std::io::{Read, Write};
            let pipe = w.write_all(b"x").is_ok() && {
                let mut b = [0u8; 1];
                let mut r = r;
                r.read_exact(&mut b).is_ok()
            };
            (status, file, tcp, exec, dumpable, thread, pipe)
        });
        assert_eq!(status, "filtered");
        assert!(!file && !tcp && !exec && !dumpable);
        assert!(thread && pipe);
    }
}
