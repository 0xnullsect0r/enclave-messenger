//! Starting `enclave-tord` and pointing a mixnet client at it.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// A running `enclave-tord`. Its stdin stays open while this lives: when it
/// is dropped (or the parent dies), tord sees its stdin close and exits.
pub struct Running {
    /// Its loopback SOCKS5 port.
    pub port: u16,
    secret: String,
    _stdin: tokio::process::ChildStdin,
    _child: tokio::process::Child,
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

/// Start `bin` keeping Tor's state under `state`, give it `secret` (at
/// least 32 characters, from the caller's own randomness), and wait up to
/// `within` for Tor to be up. `direct` (a `dev-direct` build) dials without
/// Tor; `report` logs each connection's destination.
pub async fn start(
    bin: &std::path::Path,
    state: &std::path::Path,
    secret: String,
    direct: bool,
    report: bool,
    within: std::time::Duration,
) -> Result<Running, String> {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.arg("--state").arg(state);
    if direct {
        cmd.arg("--direct");
    }
    if report {
        cmd.arg("--report");
    }
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err("no pipes to enclave-tord".into());
    };
    stdin
        .write_all(format!("{secret}\n").as_bytes())
        .await
        .map_err(|e| format!("enclave-tord: {e}"))?;
    let mut line = String::new();
    tokio::time::timeout(
        within,
        tokio::io::BufReader::new(stdout).read_line(&mut line),
    )
    .await
    .map_err(|_| "enclave-tord: Tor didn't start in time".to_string())?
    .map_err(|e| format!("enclave-tord: {e}"))?;
    let port = line
        .trim()
        .strip_prefix("ready ")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| "enclave-tord: Tor didn't start".to_string())?;
    Ok(Running {
        port,
        secret,
        _stdin: stdin,
        _child: child,
    })
}
