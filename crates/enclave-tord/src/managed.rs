//! Snowflake and WebTunnel bridges (`docs/09-transport.md` §7, censorship
//! mode), through lyrebird, the Tor Project's pluggable-transport program
//! (Go; a declared exception, shipped next to `enclave-tord` and started
//! only when bridges of these kinds are set).
//!
//! obfs4 runs in this process ([`crate::obfs4pt`]); these two have no Rust
//! implementation. `enclave-tord` starts lyrebird itself, before it
//! confines itself (it can't start programs afterwards), speaking the
//! pluggable-transport protocol (pt-spec §3.2–3.3): the transports asked
//! for go in the environment, lyrebird answers with a SOCKS5 port on
//! loopback for each, and arti dials bridges through those ports as
//! unmanaged transports. lyrebird exits when its stdin closes
//! (`TOR_PT_EXIT_ON_STDIN_CLOSE`), so it never outlives `enclave-tord`.

use std::io::{self, BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The transports lyrebird runs for us.
pub const PROTOCOLS: &[&str] = &["snowflake", "webtunnel"];

/// The program's name, next to `enclave-tord`.
pub const BINARY: &str = "lyrebird";

/// The Tor Project's built-in Snowflake bridges (`ci/tor/builtin-bridges.sh`,
/// from its Circumvention Settings API), one bridge line each.
pub const SNOWFLAKE: &str = include_str!("../bridges/snowflake.txt");

/// The built-in Snowflake bridge lines.
pub fn builtin_snowflake() -> Vec<String> {
    SNOWFLAKE
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Where lyrebird should be: next to this executable.
pub fn binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.with_file_name(format!("{BINARY}{}", std::env::consts::EXE_SUFFIX)))
}

/// The transports `bridges` (bridge lines) need from lyrebird, each once.
pub fn needed(bridges: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in bridges {
        if let Some(t) = l.split_whitespace().next()
            && PROTOCOLS.contains(&t)
            && !out.iter().any(|o| o == t)
        {
            out.push(t.to_string());
        }
    }
    out
}

/// A running lyrebird and the SOCKS5 address of each transport it runs.
pub struct Managed {
    child: Child,
    /// `(transport, address)`, one per transport asked for.
    pub methods: Vec<(String, SocketAddr)>,
}

impl Drop for Managed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What one line of the program's answer says (pt-spec §3.3).
#[derive(Debug, PartialEq, Eq)]
enum Line {
    Version,
    Method(String, SocketAddr),
    Failed(String),
    Done,
    Other,
}

fn parse(line: &str) -> Line {
    let mut w = line.split_whitespace();
    match w.next() {
        Some("VERSION") if w.next() == Some("1") => Line::Version,
        Some("VERSION-ERROR") => Line::Failed("no supported protocol version".into()),
        Some("ENV-ERROR") | Some("PROXY-ERROR") => Line::Failed(w.collect::<Vec<_>>().join(" ")),
        Some("CMETHOD-ERROR") => {
            let name = w.next().unwrap_or_default().to_string();
            Line::Failed(format!("{name}: {}", w.collect::<Vec<_>>().join(" ")))
        }
        Some("CMETHOD") => match (w.next(), w.next(), w.next().map(str::parse::<SocketAddr>)) {
            (Some(name), Some("socks5"), Some(Ok(addr))) if addr.ip().is_loopback() => {
                Line::Method(name.to_string(), addr)
            }
            _ => Line::Failed(format!("unusable method: {line}")),
        },
        Some("CMETHODS") if w.next() == Some("DONE") => Line::Done,
        _ => Line::Other,
    }
}

/// Start `bin` for `protocols`, keeping its state under `state`, and wait
/// up to `within` for every transport's address. `report` passes its log
/// through.
pub fn launch(
    bin: &Path,
    state: &Path,
    protocols: &[String],
    within: Duration,
    report: bool,
) -> io::Result<Managed> {
    let dir = state.join("pt");
    std::fs::create_dir_all(&dir)?;
    let mut cmd = Command::new(bin);
    enclave_platform::process::no_window(&mut cmd);
    cmd.env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_STATE_LOCATION", &dir)
        .env("TOR_PT_CLIENT_TRANSPORTS", protocols.join(","))
        .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if report {
            Stdio::inherit()
        } else {
            Stdio::null()
        });
    let mut child = cmd
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", bin.display())))?;
    let Some(out) = child.stdout.take() else {
        let _ = child.kill();
        return Err(io::Error::other("no stdout"));
    };
    // The answer comes on stdout; afterwards its log lines keep coming and
    // are read (and dropped) so the pipe never fills.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("enclave-tord-pt".into())
        .spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                if report {
                    eprintln!("enclave-tord: lyrebird: {line}");
                }
                let _ = tx.send(line);
            }
        })?;
    let mut managed = Managed {
        child,
        methods: Vec::new(),
    };
    let deadline = std::time::Instant::now() + within;
    let mut version = false;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let line = rx
            .recv_timeout(left)
            .map_err(|_| io::Error::other("lyrebird didn't start its transports in time"))?;
        match parse(&line) {
            Line::Version => version = true,
            Line::Method(name, addr) if protocols.contains(&name) => {
                managed.methods.push((name, addr));
            }
            Line::Method(..) | Line::Other => {}
            Line::Failed(why) => return Err(io::Error::other(format!("lyrebird: {why}"))),
            Line::Done => break,
        }
    }
    if !version {
        return Err(io::Error::other("lyrebird: no protocol version"));
    }
    if let Some(missing) = protocols
        .iter()
        .find(|p| !managed.methods.iter().any(|(n, _)| n == *p))
    {
        return Err(io::Error::other(format!("lyrebird has no {missing}")));
    }
    Ok(managed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_read() {
        assert_eq!(parse("VERSION 1"), Line::Version);
        assert_eq!(
            parse("CMETHOD snowflake socks5 127.0.0.1:4711"),
            Line::Method("snowflake".into(), "127.0.0.1:4711".parse().unwrap())
        );
        assert!(matches!(
            parse("CMETHOD snowflake socks5 192.0.2.1:4711"),
            Line::Failed(_)
        ));
        assert!(matches!(
            parse("CMETHOD snowflake socks4 127.0.0.1:1"),
            Line::Failed(_)
        ));
        assert!(matches!(
            parse("CMETHOD-ERROR webtunnel no"),
            Line::Failed(_)
        ));
        assert!(matches!(parse("ENV-ERROR no state"), Line::Failed(_)));
        assert_eq!(parse("CMETHODS DONE"), Line::Done);
        assert_eq!(parse("LOG SEVERITY=notice MESSAGE=\"hi\""), Line::Other);
        assert_eq!(parse("VERSION 2"), Line::Other);
    }

    #[test]
    fn transports_needed_once_each() {
        let lines: Vec<String> = [
            "obfs4 192.0.2.1:443 AAAA cert=x iat-mode=0",
            "snowflake 192.0.2.3:80 BBBB fingerprint=BBBB url=https://x/",
            "webtunnel [2001:db8::1]:443 CCCC url=https://x/y ver=0.0.1",
            "snowflake 192.0.2.4:80 DDDD fingerprint=DDDD url=https://x/",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(needed(&lines), ["snowflake", "webtunnel"]);
        assert!(needed(&lines[..1]).is_empty());
        assert!(!builtin_snowflake().is_empty());
        assert!(
            builtin_snowflake()
                .iter()
                .all(|l| l.starts_with("snowflake "))
        );
    }

    /// A stand-in program speaking the protocol, as lyrebird does.
    #[cfg(unix)]
    #[test]
    fn launches_a_transport_program() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("enclave-pt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fake-pt");
        std::fs::write(
            &bin,
            "#!/bin/sh\n\
             [ \"$TOR_PT_MANAGED_TRANSPORT_VER\" = 1 ] || { echo VERSION-ERROR; exit 1; }\n\
             [ \"$TOR_PT_EXIT_ON_STDIN_CLOSE\" = 1 ] || exit 1\n\
             echo VERSION 1\n\
             port=4711\n\
             for t in $(echo \"$TOR_PT_CLIENT_TRANSPORTS\" | tr , ' '); do\n\
               if [ \"$t\" = nope ]; then echo \"CMETHOD-ERROR $t unknown\"; else echo \"CMETHOD $t socks5 127.0.0.1:$port\"; fi\n\
               port=$((port+1))\n\
             done\n\
             echo CMETHODS DONE\n\
             cat > /dev/null\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let want = vec!["snowflake".to_string(), "webtunnel".to_string()];
        let m = launch(&bin, &dir, &want, Duration::from_secs(10), false).unwrap();
        assert_eq!(
            m.methods,
            [
                ("snowflake".to_string(), "127.0.0.1:4711".parse().unwrap()),
                ("webtunnel".to_string(), "127.0.0.1:4712".parse().unwrap()),
            ]
        );
        assert!(dir.join("pt").is_dir(), "its state directory");
        drop(m);
        let bad = launch(
            &bin,
            &dir,
            &["nope".to_string()],
            Duration::from_secs(10),
            false,
        );
        assert!(bad.is_err());
        assert!(
            launch(
                &dir.join("missing"),
                &dir,
                &want,
                Duration::from_secs(1),
                false
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
