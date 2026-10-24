//! One tord at a time keeps Tor's state in a directory: two set up at
//! once, as netd and its spare did, lost arti's cache to each other ("cache
//! access problem: Error setting up the directory manager") and the app
//! never reached its server.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// A fresh state directory.
fn fresh() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("enclave-tord-claim-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d.join("tor")
}

struct Tord {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
}

fn start(state: &std::path::Path, standby: bool) -> Tord {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_enclave-tord"));
    cmd.arg("--state").arg(state).arg("--carrier");
    if standby {
        cmd.arg("--standby");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", "s".repeat(64)).unwrap();
    let out: ChildStdout = child.stdout.take().unwrap();
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for l in BufReader::new(out).lines() {
            let Ok(l) = l else { return };
            if tx.send(l).is_err() {
                return;
            }
        }
    });
    Tord {
        child,
        stdin: Some(stdin),
        lines,
    }
}

impl Tord {
    fn next(&self, within: Duration) -> Option<String> {
        self.lines.recv_timeout(within).ok()
    }

    /// Its netd goes away: its stdin closes, and it exits.
    fn stop(mut self) {
        drop(self.stdin.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        panic!("tord didn't exit when its stdin closed");
    }
}

impl Drop for Tord {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_second_tord_waits_for_the_first() {
    let state = fresh();
    let first = start(&state, false);
    std::thread::sleep(Duration::from_millis(500));
    let second = start(&state, false);
    assert_eq!(
        second.next(Duration::from_secs(10)).as_deref(),
        Some("waiting")
    );
    assert_eq!(second.next(Duration::from_secs(2)), None, "still waiting");
    // The first goes (while Tor is still coming up): the second has it.
    first.stop();
    assert_eq!(
        second.next(Duration::from_secs(10)).as_deref(),
        Some("claimed")
    );
    second.stop();
}

#[test]
fn a_standby_tord_lets_the_one_in_use_go_first() {
    // Started first, the spare's still waits for the one in use.
    let state = fresh();
    let spare = start(&state, true);
    assert_eq!(
        spare.next(Duration::from_secs(10)).as_deref(),
        Some("waiting")
    );
    std::thread::sleep(Duration::from_secs(1));
    let used = start(&state, false);
    assert_eq!(
        used.next(Duration::from_secs(3)),
        None,
        "no wait for the one in use"
    );
    assert_eq!(spare.next(Duration::from_secs(1)), None);
    used.stop();
    assert_eq!(
        spare.next(Duration::from_secs(10)).as_deref(),
        Some("claimed")
    );
    spare.stop();
}

#[test]
fn started_together_one_waits() {
    for _ in 0..3 {
        let state = fresh();
        let a = start(&state, false);
        let b = start(&state, false);
        let said: Vec<Option<String>> = [&a, &b]
            .iter()
            .map(|t| t.next(Duration::from_secs(5)))
            .collect();
        assert_eq!(
            said.iter()
                .filter(|l| l.as_deref() == Some("waiting"))
                .count(),
            1,
            "{said:?}"
        );
    }
}
