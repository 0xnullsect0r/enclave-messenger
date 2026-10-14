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
pub mod engine;
pub mod harden;
pub mod helpers;
pub mod keystore;
pub mod lock;
pub mod media;
pub mod netd;

pub use engine::{Helpers, Mode, default_profile, spawn};

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
    let reader = tokio::spawn(async move {
        while let Ok(body) = frame::read_frame(&mut rd).await {
            let Ok(cmd) = Cmd::decode(&body) else { break };
            if cmd_tx.send(cmd).is_err() {
                break;
            }
        }
    });
    let writer = tokio::spawn(async move {
        while let Some(out) = out_rx.recv().await {
            if frame::write_frame(&mut wr, &out.encode()).await.is_err() {
                break;
            }
        }
    });
    engine::run_with(mode, helpers, cmd_rx, out_tx).await;
    reader.abort();
    let _ = writer.await;
    Ok(())
}
