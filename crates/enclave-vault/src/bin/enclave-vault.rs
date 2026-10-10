//! `enclave-vault --connect SOCKET|PIPE [--server SERVER_ID=ROUTE --profile DIR
//! [--kt-pins FILE] [--nym-env] | --demo] [--report]`, a route being
//! `nym:ADDRESS` or (development) `HOST:PORT`
//!
//! Started by the Enclave UI, never by hand. Hardens itself (no core dumps,
//! not dumpable, `no_new_privs`), reads the connection token (hex) from
//! stdin, connects to the UI's socket (a named pipe on Windows), proves
//! itself with the token, starts
//! `enclave-netd` for the network (server mode), confines itself to its
//! profile directory with no TCP at all (Landlock) and runs the engine until
//! the UI disconnects. `--report` prints what hardening took effect.

use std::io::BufRead;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut report = enclave_vault::harden::process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = args.iter().any(|a| a == "--report");
    let Some(socket) = args
        .iter()
        .position(|a| a == "--connect")
        .and_then(|i| args.get(i + 1))
        .cloned()
    else {
        eprintln!("enclave-vault is started by the Enclave app");
        return ExitCode::from(2);
    };
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return ExitCode::from(2);
    }
    let Some(token) = enclave_ipc::frame::token_from_hex(&line) else {
        return ExitCode::from(2);
    };
    let mode = match enclave_vault::Mode::from_args(&args) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("enclave-vault: {e}");
            return ExitCode::from(2);
        }
    };
    // McEliece key generation needs a deep stack.
    let worker = std::thread::Builder::new()
        .name("enclave-vault".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let ok = run(&socket, mode, token, &mut report);
            if verbose {
                eprintln!("enclave-vault: {report:?}");
            }
            ok
        });
    match worker.map(|h| h.join()) {
        Ok(Ok(true)) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

fn run(
    socket: &str,
    mode: enclave_vault::Mode,
    token: [u8; 32],
    report: &mut enclave_vault::harden::Report,
) -> bool {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    rt.block_on(async {
        match connect(socket).await {
            Ok(s) => connected(s, mode, token, report).await,
            Err(e) => {
                eprintln!("enclave-vault: can't reach the app: {e}");
                false
            }
        }
    })
}

/// The UI's Unix socket (in its private 0700 directory).
#[cfg(unix)]
async fn connect(socket: &str) -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(socket).await
}

/// The UI's named pipe (`\\.\pipe\enclave-…`, local clients only).
#[cfg(windows)]
async fn connect(
    socket: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(socket)
}

/// Connected to the UI: start the helpers, confine ourselves, serve.
async fn connected<S>(
    s: S,
    mode: enclave_vault::Mode,
    token: [u8; 32],
    report: &mut enclave_vault::harden::Report,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    // The network lives in netd and pictures in mediad; start them while
    // we still may, and reach the platform keystore (the Secret Service's
    // bus) while we can open a socket.
    if matches!(mode, enclave_vault::Mode::Server { .. }) {
        enclave_vault::keystore::prepare();
    }
    let net = start_netd(&mode);
    if net.is_some() {
        report.network = "netd";
    }
    let media = enclave_vault::media::mediad_binary()
        .and_then(|b| enclave_vault::media::Media::spawn(&b, enclave_vault::media::SPARES).ok());
    if media.is_some() {
        report.media = "mediad";
    }
    // From here on only the profile is reachable, and (with netd) no TCP
    // connection can be opened (Linux; elsewhere this reports
    // "unavailable").
    let (rw, ro) = enclave_vault::harden::paths_for(&mode);
    report.filesystem = enclave_vault::harden::filesystem(&rw, &ro, net.is_some());
    // And no new sockets (or IP sockets only, when the network stayed in
    // this process), no programs, no debugging.
    let profile = match (&mode, net.is_some()) {
        (enclave_vault::Mode::Server { .. }, false) => enclave_vault::harden::Profile::Netd,
        _ => enclave_vault::harden::Profile::Vault,
    };
    report.syscalls = enclave_vault::harden::syscalls(profile, false);
    let helpers = enclave_vault::Helpers { net, media };
    enclave_vault::serve_with(mode, helpers, s, &token)
        .await
        .is_ok()
}

fn start_netd(
    mode: &enclave_vault::Mode,
) -> Option<std::sync::Arc<dyn enclave_net::transport::Transport>> {
    let enclave_vault::Mode::Server {
        profile,
        home,
        others,
        nym_env,
        ..
    } = mode
    else {
        return None;
    };
    let bin = enclave_vault::netd::netd_binary()?;
    let servers: Vec<_> = home
        .iter()
        .chain(others)
        .map(|(id, r)| (*id, r.to_string()))
        .collect();
    let mut extra: Vec<String> = if *nym_env {
        vec!["--nym-env".into()]
    } else {
        Vec::new()
    };
    // Tor in front of the mixnet whenever this build ships enclave-tord
    // (`docs/09-transport.md` §1): netd starts it, keeping Tor's state in
    // the profile.
    let tord = bin.with_file_name(format!("enclave-tord{}", std::env::consts::EXE_SUFFIX));
    if tord.exists() {
        extra.push("--tor".into());
        extra.push(profile.join("tor").to_string_lossy().into_owned());
        // Bridges the user set (censorship mode).
        extra.extend(enclave_vault::netd::bridge_args(profile));
    }
    // With a server list the servers are reached over the mixnet, their
    // routes given once the list is read: the mixnet client starts anyway.
    let listed = mode.has_server_list();
    if listed {
        extra.push("--mixnet".into());
    }
    // The mixnet client waits for its zk-nym tickets, which the vault
    // gives it once it can read its wallet (`docs/09-transport.md` §7).
    if listed
        || home
            .iter()
            .chain(others)
            .any(|(_, r)| matches!(r, enclave_net::transport::Route::Nym(_)))
    {
        extra.push("--await-tickets".into());
    }
    match enclave_vault::netd::PipeTransport::spawn(&bin, &servers, &extra) {
        Ok(t) => Some(std::sync::Arc::new(t)),
        Err(e) => {
            eprintln!("enclave-vault: netd didn't start ({e}); using the network directly");
            None
        }
    }
}
