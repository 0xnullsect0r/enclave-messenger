//! Starting `enclave-tord` and pointing a mixnet client at it.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// A running `enclave-tord`. Its stdin stays open while this lives: when it
/// is dropped (or the parent dies), tord sees its stdin close and exits.
pub struct Running {
    /// Its loopback SOCKS5 port.
    pub port: u16,
    secret: String,
    /// Requests to onion services and HTTPS fetches through it (started
    /// with `carrier`); it holds tord's stdin and stdout.
    pub carrier: Option<std::sync::Arc<crate::carrier::Client>>,
    _stdin: Option<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>,
    /// The process (none when tord runs as a thread of this one).
    _child: Option<tokio::process::Child>,
}

impl Running {
    /// What `enclave-nymd` needs in its environment to reach its gateway
    /// (`ENCLAVE_TOR_SOCKS`, `ENCLAVE_TOR_SECRET`) and nym-api (reqwest's
    /// proxy variables, resolved at the Tor exit) only through Tor.
    pub fn nymd_env(&self) -> Vec<(&'static str, String)> {
        let proxy = format!(
            "socks5h://{}:{}@127.0.0.1:{}",
            crate::USER,
            self.secret,
            self.port
        );
        let mut env = vec![
            ("ENCLAVE_TOR_SOCKS", format!("127.0.0.1:{}", self.port)),
            ("ENCLAVE_TOR_SECRET", self.secret.clone()),
        ];
        for v in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            env.push((v, proxy.clone()));
        }
        env
    }

    /// Variables to remove from `enclave-nymd`'s environment (an exception
    /// list would let a request bypass Tor).
    pub const NYMD_ENV_REMOVE: [&'static str; 2] = ["NO_PROXY", "no_proxy"];
}

/// What [`start`] fails with when Tor didn't come up in time: the network
/// may be blocking Tor (bridges may help).
pub const BLOCKED: &str = "enclave-tord: Tor didn't come up; the network may be blocking it";

/// Start `bin` keeping Tor's state under `state`, give it `secret` (at
/// least 32 characters, from the caller's own randomness), and wait up to
/// `within` for Tor to be up. `direct` (a `dev-direct` build) dials without
/// Tor; `report` logs each connection's destination; `extra` are more
/// arguments (`--bridge LINE`, `--builtin-bridges`, `--snowflake`). With
/// `carrier`, tord also carries requests to onion services and HTTPS
/// fetches ([`Running::carrier`]). [`spawn`] and [`Starting::ready`] in one.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    bin: &std::path::Path,
    state: &std::path::Path,
    secret: String,
    direct: bool,
    report: bool,
    carrier: bool,
    extra: &[String],
    within: std::time::Duration,
) -> Result<Running, String> {
    spawn(bin, state, secret, direct, report, carrier, extra)
        .await?
        .ready(within)
        .await
}

/// A started `enclave-tord` that hasn't said yet whether Tor is up. A
/// caller that confines itself starts tord first (no new process after
/// that) and waits for it afterwards, in the background, so that nothing
/// else waits on Tor's bootstrap.
pub struct Starting {
    secret: String,
    carrier: bool,
    stdin: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    reader: tokio::io::BufReader<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    child: Option<tokio::process::Child>,
}

/// Start `bin` and hand it `secret`, as [`start`] does, without waiting for
/// Tor.
pub async fn spawn(
    bin: &std::path::Path,
    state: &std::path::Path,
    secret: String,
    direct: bool,
    report: bool,
    carrier: bool,
    extra: &[String],
) -> Result<Starting, String> {
    let mut args: Vec<String> = vec!["--state".into(), state.display().to_string()];
    args.extend(extra.iter().cloned());
    if carrier {
        args.push("--carrier".into());
    }
    if direct {
        args.push("--direct".into());
    }
    if report {
        args.push("--report".into());
    }
    type Pipes = (
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Option<tokio::process::Child>,
    );
    // A thread of this process where the helpers are linked in (Android,
    // iOS), the program next to this one elsewhere.
    let in_process = enclave_platform::process::start("enclave-tord", args.clone())
        .map_err(|e| format!("enclave-tord: {e}"))?;
    let (mut stdin, stdout, child): Pipes = match in_process {
        Some(p) => (
            Box::new(tokio::fs::File::from_std(p.stdin)),
            Box::new(tokio::fs::File::from_std(p.stdout)),
            None,
        ),
        None => {
            let mut cmd = tokio::process::Command::new(bin);
            enclave_platform::process::no_window(cmd.as_std_mut());
            cmd.args(&args);
            let mut child = cmd
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| format!("{}: {e}", bin.display()))?;
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                return Err("no pipes to enclave-tord".into());
            };
            (Box::new(stdin), Box::new(stdout), Some(child))
        }
    };
    stdin
        .write_all(format!("{secret}\n").as_bytes())
        .await
        .map_err(|e| format!("enclave-tord: {e}"))?;
    stdin
        .flush()
        .await
        .map_err(|e| format!("enclave-tord: {e}"))?;
    Ok(Starting {
        secret,
        carrier,
        stdin,
        reader: tokio::io::BufReader::new(stdout),
        child,
    })
}

impl Starting {
    /// Wait up to `within` for Tor to be up: the running tord, or
    /// [`BLOCKED`], or why it didn't start.
    pub async fn ready(self, within: std::time::Duration) -> Result<Running, String> {
        let Starting {
            secret,
            carrier,
            stdin,
            mut reader,
            child,
        } = self;
        let mut line = String::new();
        tokio::time::timeout(within, reader.read_line(&mut line))
            .await
            .map_err(|_| BLOCKED.to_string())?
            .map_err(|e| format!("enclave-tord: {e}"))?;
        if line.trim() == "blocked" {
            return Err(BLOCKED.into());
        }
        let port = line
            .trim()
            .strip_prefix("ready ")
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| "enclave-tord: Tor didn't start".to_string())?;
        let (carrier, stdin) = if carrier {
            (
                Some(std::sync::Arc::new(crate::carrier::Client::new(
                    reader, stdin,
                ))),
                None,
            )
        } else {
            (None, Some(stdin))
        };
        Ok(Running {
            port,
            secret,
            carrier,
            _stdin: stdin,
            _child: child,
        })
    }
}

#[cfg(all(test, feature = "dev-direct"))]
mod tests {
    /// Where the helpers share the app's process (Android, iOS), tord runs
    /// as a thread and answers on its pipes as the program does.
    #[tokio::test]
    async fn starts_as_a_thread() {
        enclave_platform::process::register("enclave-tord", crate::daemon::main_with);
        let state =
            std::env::temp_dir().join(format!("enclave-tord-thread-{}", std::process::id()));
        let running = super::start(
            std::path::Path::new("enclave-tord"),
            &state,
            "a".repeat(64),
            true,
            false,
            false,
            &[],
            std::time::Duration::from_secs(20),
        )
        .await
        .unwrap();
        assert_ne!(running.port, 0);
        // Its SOCKS port answers.
        tokio::net::TcpStream::connect(("127.0.0.1", running.port))
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(state);
    }
}
