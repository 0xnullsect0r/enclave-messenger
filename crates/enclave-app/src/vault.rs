//! Start the vault process and talk to it (`docs/15-client.md` §1).
//!
//! The UI creates a private directory (mode 0700), listens on a Unix socket
//! inside it, and starts `enclave-vault` from next to its own executable with
//! a fresh 32-byte token on the child's stdin. The first connection must
//! present that token and (where the kernel reports it) be the child's pid;
//! the socket is then unlinked, so nothing else can connect.
//!
//! On Windows the UI instead creates a named pipe `\\.\pipe\enclave-<random>`
//! as its first and only instance, refusing remote clients, before it
//! starts the vault; the vault connects and presents the token the same
//! way. (The kernel's client process id is not checked there yet: that
//! needs the Win32 API, which this crate's no-`unsafe` rule keeps out.)
//!
//! Commands and outputs cross as [`enclave_ipc`] frames. If the vault
//! exits, the UI shows that instead of pretending to work.

use enclave_ipc::{Cmd, Out, Snapshot};
use enclave_vault::Mode;
use tokio::sync::mpsc;

/// Channels to the engine: commands in, outputs out.
pub type Channels = (mpsc::UnboundedSender<Cmd>, mpsc::UnboundedReceiver<Out>);

/// Where the vault binary should be: next to this executable.
pub fn vault_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.with_file_name(format!("enclave-vault{}", std::env::consts::EXE_SUFFIX));
    p.exists().then_some(p)
}

/// On a phone the vault runs on a thread and outlives the window
/// ([`phone::attach`]); returns its channels (never a separate process).
#[cfg(not(desktop))]
pub fn start(mode: Mode, _single_process: bool) -> (Channels, bool) {
    (phone::attach(mode), false)
}

/// Start the engine: as a separate process when possible, otherwise on a
/// thread. Returns the channels and whether the vault is a separate process.
#[cfg(desktop)]
pub fn start(mode: Mode, single_process: bool) -> (Channels, bool) {
    if !single_process && let Some(bin) = vault_binary() {
        match spawn_process(&bin, &mode) {
            Ok(ch) => return (ch, true),
            Err(e) => eprintln!("enclave: vault process unavailable ({e}); running in-process"),
        }
    }
    (enclave_vault::spawn(mode), false)
}

/// Start the vault binary at `bin` as a separate process.
#[cfg(unix)]
pub fn spawn_process(bin: &std::path::Path, mode: &Mode) -> std::io::Result<Channels> {
    use enclave_ipc::frame;
    use std::io::Write;
    use std::os::unix::fs::DirBuilderExt;

    let mut rng = enclave_crypto::rng::HedgedRng::new().map_err(std::io::Error::other)?;
    let token: [u8; frame::TOKEN_LEN] = rng
        .array("app/vault-token")
        .map_err(std::io::Error::other)?;
    let nonce: [u8; 8] = rng.array("app/vault-dir").map_err(std::io::Error::other)?;
    let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("enclave-{name}"));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let sock = dir.join("vault.sock");

    let std_listener = std::os::unix::net::UnixListener::bind(&sock)?;
    std_listener.set_nonblocking(true)?;
    let mut child = std::process::Command::new(bin)
        .arg("--connect")
        .arg(&sock)
        .args(mode.to_args())
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{}", frame::token_hex(&token))?;
    }
    let child_pid = child.id();

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Out>();
    std::thread::Builder::new()
        .name("enclave-vault-link".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                let result: enclave_ipc::Result<()> = async {
                    let listener = tokio::net::UnixListener::from_std(std_listener)?;
                    let accepted =
                        tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept())
                            .await
                            .map_err(|_| std::io::Error::other("vault did not connect"))?;
                    // One connection only: nothing else can reach us now.
                    drop(listener);
                    let _ = std::fs::remove_file(&sock);
                    let _ = std::fs::remove_dir(&dir);
                    let (stream, _) = accepted?;
                    // The kernel's word on who connected: it must be our child
                    // (where the platform reports it), as well as know the token.
                    if let Some(pid) = stream.peer_cred()?.pid()
                        && u32::try_from(pid).ok() != Some(child_pid)
                    {
                        return Err(enclave_ipc::IpcError::Unauthenticated);
                    }
                    relay(stream, &token, &mut cmd_rx, &out_tx).await
                }
                .await;
                let _ = std::fs::remove_file(&sock);
                let _ = std::fs::remove_dir(&dir);
                let _ = child.kill();
                let _ = child.wait();
                if let Err(e) = result {
                    let _ = out_tx.send(Out::Snapshot(Box::new(Snapshot {
                        status: format!("Enclave's vault stopped ({e}). Restart Enclave."),
                        ..Default::default()
                    })));
                }
            });
        })?;
    Ok((cmd_tx, out_rx))
}

/// Check the vault's token, then carry commands to it and outputs back
/// until either side goes away.
async fn relay<S>(
    stream: S,
    token: &[u8; enclave_ipc::frame::TOKEN_LEN],
    cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>,
    out_tx: &mpsc::UnboundedSender<Out>,
) -> enclave_ipc::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    use enclave_ipc::frame;
    let (mut rd, mut wr) = tokio::io::split(stream);
    frame::check_token(&mut rd, token).await?;
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return Ok(()) };
                frame::write_frame(&mut wr, &cmd.encode()).await?;
            }
            body = frame::read_frame(&mut rd) => {
                let out = Out::decode(&body?)?;
                if out_tx.send(out).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

/// Start the vault binary at `bin` as a separate process (Windows: over a
/// named pipe).
#[cfg(windows)]
pub fn spawn_process(bin: &std::path::Path, mode: &Mode) -> std::io::Result<Channels> {
    use enclave_ipc::frame;
    use std::io::Write;
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut rng = enclave_crypto::rng::HedgedRng::new().map_err(std::io::Error::other)?;
    let token: [u8; frame::TOKEN_LEN] = rng
        .array("app/vault-token")
        .map_err(std::io::Error::other)?;
    let nonce: [u8; 16] = rng.array("app/vault-dir").map_err(std::io::Error::other)?;
    let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let pipe = format!(r"\\.\pipe\enclave-{hex}");
    let bin = bin.to_path_buf();
    let args = mode.to_args();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Out>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::io::Result<()>>();
    std::thread::Builder::new()
        .name("enclave-vault-link".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            rt.block_on(async move {
                // The pipe exists, as its only instance, before the vault
                // starts; nothing remote can open it.
                let server = match ServerOptions::new()
                    .first_pipe_instance(true)
                    .reject_remote_clients(true)
                    .max_instances(1)
                    .create(&pipe)
                {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let mut cmd = std::process::Command::new(&bin);
                enclave_platform::process::no_window(&mut cmd);
                let mut child = match cmd
                    .arg("--connect")
                    .arg(&pipe)
                    .args(&args)
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = writeln!(stdin, "{}", frame::token_hex(&token));
                }
                let _ = ready_tx.send(Ok(()));
                let result: enclave_ipc::Result<()> = async {
                    tokio::time::timeout(std::time::Duration::from_secs(30), server.connect())
                        .await
                        .map_err(|_| std::io::Error::other("vault did not connect"))??;
                    relay(server, &token, &mut cmd_rx, &out_tx).await
                }
                .await;
                let _ = child.kill();
                let _ = child.wait();
                if let Err(e) = result {
                    let _ = out_tx.send(Out::Snapshot(Box::new(Snapshot {
                        status: format!("Enclave's vault stopped ({e}). Restart Enclave."),
                        ..Default::default()
                    })));
                }
            });
        })?;
    ready_rx
        .recv()
        .map_err(|_| std::io::Error::other("the vault launcher stopped"))??;
    Ok((cmd_tx, out_rx))
}

/// Start the vault binary at `bin` as a separate process.
#[cfg(not(any(unix, windows)))]
pub fn spawn_process(_: &std::path::Path, _: &Mode) -> std::io::Result<Channels> {
    Err(std::io::Error::other("not supported on this platform yet"))
}

/// On a phone the vault runs as long as the process, not the window: the
/// system can destroy and remake the activity, and with the app in the
/// background (Android's foreground service keeping it alive) messages
/// still arrive and are announced. One vault per process; each window
/// attaches to it, and while none is, what it would have shown as a
/// notification goes to the phone's notifications.
#[cfg(not(desktop))]
pub mod phone {
    use super::{Channels, Cmd, Out};
    use enclave_vault::Mode;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::sync::mpsc;

    struct Shared {
        tx: mpsc::UnboundedSender<Cmd>,
        window: Arc<Mutex<Option<mpsc::UnboundedSender<Out>>>>,
    }

    static ENGINE: OnceLock<Shared> = OnceLock::new();

    /// The process's vault, started with `mode` if there is none yet;
    /// whether it was started now.
    fn engine(mode: Mode) -> (&'static Shared, bool) {
        let mut fresh = false;
        let shared = ENGINE.get_or_init(|| {
            fresh = true;
            let (tx, mut out_rx) = enclave_vault::spawn(mode);
            let window: Arc<Mutex<Option<mpsc::UnboundedSender<Out>>>> = Arc::new(Mutex::new(None));
            let to = Arc::clone(&window);
            let _ = std::thread::Builder::new()
                .name("enclave-outputs".into())
                .spawn(move || {
                    while let Some(out) = out_rx.blocking_recv() {
                        let Ok(mut w) = to.lock() else {
                            return;
                        };
                        let out = match w.as_ref() {
                            Some(win) => match win.send(out) {
                                Ok(()) => continue,
                                Err(e) => {
                                    // The window is gone.
                                    *w = None;
                                    e.0
                                }
                            },
                            None => out,
                        };
                        if let Out::Notify(n) = out {
                            let n = crate::i18n::notice(n);
                            enclave_platform::phone::notify(&n.title, &n.body);
                        }
                    }
                });
            // What the phone says on its own becomes commands.
            let events = tx.clone();
            enclave_platform::phone::on_event(move |e| {
                use enclave_platform::phone::Event;
                let _ = events.send(match e {
                    Event::Visible(v) => Cmd::Visible(v),
                    Event::PushToken(p, t) => Cmd::PushToken(p, t),
                    Event::Wake => Cmd::Wake,
                });
            });
            Shared { tx, window }
        });
        (shared, fresh)
    }

    /// The process's vault (started with `mode` the first time), with a
    /// fresh output channel for this window.
    pub fn attach(mode: Mode) -> Channels {
        let (shared, fresh) = engine(mode);
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        if let Ok(mut w) = shared.window.lock() {
            *w = Some(out_tx);
        }
        if !fresh {
            let _ = shared.tx.send(Cmd::Reattach);
        }
        (shared.tx.clone(), out_rx)
    }

    /// Start the process's vault with no window (Android's background
    /// service), if it isn't running.
    pub fn run(mode: Mode) {
        let _ = engine(mode);
    }

    /// A command to the running vault (a push token, a wake), if there is
    /// one.
    pub fn send(cmd: Cmd) -> bool {
        ENGINE.get().is_some_and(|s| s.tx.send(cmd).is_ok())
    }
}
