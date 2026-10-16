//! Links opened while Enclave is already open (`docs/03-identity.md` §4.2).
//! The system starts a second copy of the app with the link as its
//! argument (Linux, Windows); that copy hands the link to the open window
//! through a socket only this user can reach, then quits, so one profile
//! never has two windows. macOS sends the link to the open app itself
//! (`enclave_platform::open_url`).
//!
//! Unix: `<profile>/open.sock` (the profile folder is the user's only).
//! Windows: the named pipe `\\.\pipe\enclave-open-<hash of the profile
//! path>`, local clients only. What arrives is only ever put in the Add
//! screen, which the person still confirms.

use std::path::Path;

/// Longest link taken.
const MAX_LINK: u64 = 8 * 1024;

/// Hand `link` to the window already open on `profile`. False when there
/// is none (this copy should open the window itself).
pub fn send(profile: &Path, link: &str) -> bool {
    imp::send(profile, link)
}

/// Pass links later copies hand over to `f`, for as long as the app runs.
pub fn listen(profile: &Path, f: impl Fn(String) + Send + 'static) {
    imp::listen(profile, Box::new(f));
}

type Sink = Box<dyn Fn(String) + Send>;

fn read_link(r: impl std::io::Read) -> Option<String> {
    use std::io::Read;
    let mut s = String::new();
    r.take(MAX_LINK).read_to_string(&mut s).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(unix)]
mod imp {
    use super::Sink;
    use std::io::Write;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    fn path(profile: &Path) -> PathBuf {
        profile.join("open.sock")
    }

    pub fn send(profile: &Path, link: &str) -> bool {
        match UnixStream::connect(path(profile)) {
            Ok(mut s) => s.write_all(link.as_bytes()).is_ok(),
            Err(_) => false,
        }
    }

    pub fn listen(profile: &Path, f: Sink) {
        let p = path(profile);
        // Nobody answers on it (we checked in `send`): left by a copy that
        // didn't quit cleanly.
        let _ = std::fs::remove_file(&p);
        let Ok(l) = UnixListener::bind(&p) else {
            return;
        };
        let _ = std::thread::Builder::new()
            .name("enclave-handoff".into())
            .spawn(move || {
                for s in l.incoming().flatten() {
                    if let Some(link) = super::read_link(s) {
                        f(link);
                    }
                }
            });
    }
}

#[cfg(windows)]
mod imp {
    use super::Sink;
    use std::hash::{Hash, Hasher};
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    fn name(profile: &Path) -> String {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        profile.hash(&mut h);
        format!(r"\\.\pipe\enclave-open-{:016x}", h.finish())
    }

    fn block_on<T>(f: impl std::future::Future<Output = T>) -> Option<T> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        Some(rt.block_on(f))
    }

    pub fn send(profile: &Path, link: &str) -> bool {
        let name = name(profile);
        block_on(async move {
            let Ok(mut c) = ClientOptions::new().open(&name) else {
                return false;
            };
            c.write_all(link.as_bytes()).await.is_ok() && c.shutdown().await.is_ok()
        })
        .unwrap_or(false)
    }

    pub fn listen(profile: &Path, f: Sink) {
        let name = name(profile);
        let _ = std::thread::Builder::new()
            .name("enclave-handoff".into())
            .spawn(move || {
                block_on(async move {
                    let mut first = true;
                    loop {
                        let Ok(server) = ServerOptions::new()
                            .first_pipe_instance(first)
                            .reject_remote_clients(true)
                            .create(&name)
                        else {
                            return;
                        };
                        first = false;
                        if server.connect().await.is_err() {
                            continue;
                        }
                        let mut buf = Vec::new();
                        let mut s = server;
                        if (&mut s)
                            .take(super::MAX_LINK)
                            .read_to_end(&mut buf)
                            .await
                            .is_ok()
                            && let Some(link) = super::read_link(buf.as_slice())
                        {
                            f(link);
                        }
                    }
                });
            });
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::Sink;
    use std::path::Path;

    pub fn send(_: &Path, _: &str) -> bool {
        false
    }

    pub fn listen(_: &Path, _: Sink) {}
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_second_copy_hands_its_link_over() {
        let dir = std::env::temp_dir().join(format!("enclave-handoff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!send(&dir, "enclave:add#AAAA"), "nobody open");
        let (tx, rx) = std::sync::mpsc::channel();
        listen(&dir, move |l| {
            let _ = tx.send(l);
        });
        assert!(send(&dir, " enclave:add#AAAA\n"));
        let got = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(got, "enclave:add#AAAA");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
