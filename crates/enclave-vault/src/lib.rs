//! The Enclave vault (`docs/15-client.md` §1, process split).
//!
//! The vault runs the client engine: it owns `enclave_core::Client` and with
//! it every long-term key, the sealed store and the network. The UI talks to
//! it only through [`enclave_ipc`] commands and display snapshots.
//!
//! On desktop the vault is its own process (`enclave-vault`), started by the
//! UI with a one-time token on its stdin and connected back over a Unix socket
//! in a private directory. Where that isn't possible (Windows for now, mobile
//! platforms, tests) the same engine runs on a thread ([`engine::spawn`]).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The foundation key and server list built into this build, if any.
pub mod built {
    include!(concat!(env!("OUT_DIR"), "/federation.rs"));
}
pub mod calls;
pub mod engine;
pub mod harden;
pub mod helpers;
pub mod keystore;
pub mod labels;
pub mod lock;
pub mod media;
pub mod netd;

pub use engine::{Helpers, Mode, default_profile, spawn, spawn_with_web};

/// The vault's exit code asking the window to start it again: its
/// network helpers all stopped, and a confined vault can start no programs
/// to replace them.
pub const RESTART: i32 = 75;

/// How long a vault of its own process keeps going once its window is gone
/// (to finish what it was doing) before it exits.
pub const EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

static STANDALONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// This process is the vault and nothing else (the `enclave-vault`
/// program): it may end itself to be started again ([`RESTART`]).
pub fn set_standalone() {
    STANDALONE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Whether [`set_standalone`] was called.
pub fn standalone() -> bool {
    STANDALONE.load(std::sync::atomic::Ordering::SeqCst)
}

use enclave_ipc::frame::{self, TOKEN_LEN};
use enclave_ipc::{Cmd, Out};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// Serve one UI connection: present the token, then run the engine on the
/// commands that arrive until the UI goes away. A command that does not
/// decode ends the connection (the UI is trusted to be well-formed; anything
/// else is not our UI).
pub async fn serve<S>(mode: Mode, stream: S, token: &[u8; TOKEN_LEN]) -> enclave_ipc::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    serve_with(mode, Helpers::default(), stream, token).await
}

/// [`serve`], with the network and pictures handled by helper processes
/// (see [`netd`] and [`media`]).
pub async fn serve_with<S>(
    mode: Mode,
    helpers: Helpers,
    stream: S,
    token: &[u8; TOKEN_LEN],
) -> enclave_ipc::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    frame::present_token(&mut wr, token).await?;
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Out>();
    let (gone_tx, gone_rx) = tokio::sync::oneshot::channel::<()>();
    let reader = tokio::spawn(async move {
        while let Ok(body) = frame::read_frame(&mut rd).await {
            let Ok(cmd) = Cmd::decode(&body) else { break };
            if cmd_tx.send(cmd).is_err() {
                break;
            }
        }
        let _ = gone_tx.send(());
        // The last resort, if even stopping the engine (below) hangs: a
        // vault of its own process exits, so the profile's database is
        // free for the next copy of Enclave.
        if standalone() {
            std::thread::spawn(|| {
                std::thread::sleep(EXIT_GRACE * 3);
                eprintln!("enclave-vault: the window is gone and the vault didn't stop; exiting");
                std::process::exit(0);
            });
        }
    });
    let writer = tokio::spawn(async move {
        while let Some(out) = out_rx.recv().await {
            if frame::write_frame(&mut wr, &out.encode()).await.is_err() {
                break;
            }
        }
    });
    // The window gone (it quit), the engine stops at its next turn, which
    // a step over Tor can delay: it gets EXIT_GRACE, then it is stopped
    // where it is (dropped: the profile closes, a write in progress is
    // rolled back). The next copy of Enclave waits for the profile meanwhile
    // ("Opening…"); before, it gave up and offered setup over it.
    let mut engine = Box::pin(engine::run_with(mode, helpers, cmd_rx, out_tx));
    tokio::select! {
        () = &mut engine => {}
        () = async {
            let _ = gone_rx.await;
            tokio::time::sleep(EXIT_GRACE).await;
        } => {
            eprintln!("enclave-vault: the window is gone; stopping");
        }
    }
    drop(engine);
    reader.abort();
    let _ = writer.await;
    Ok(())
}
