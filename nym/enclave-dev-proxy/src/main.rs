//! A stand-in for `nym-credential-proxy` for tests and the local mixnet
//! (`ci/federation`): the two calls `enclave-credgate` makes, answered by
//! signers this process makes at start (three, threshold two), so the
//! gate and the device run the same code as against Nym's.
//!
//! ```text
//! enclave-dev-proxy [--listen ADDR] [--token-file FILE]
//!
//! GET  /api/v1/ticketbook/partial-verification-keys   the signers' keys
//! POST /api/v1/ticketbook/obtain?…                    TicketbookRequest → wallet shares
//! ```
//!
//! With `--token-file` it wants that bearer token, like the real proxy.
//! Its books carry no coin-index or expiration-date signatures, so a
//! gateway that checks tickets wouldn't take them; the local mixnet's
//! don't check. Never part of a release.

use nym_compact_ecash::{KeyPairAuth, VerificationKeyAuth};
use nym_credential_proxy_requests::api::v1::ticketbook::models::{
    MasterVerificationKeyResponse, PartialVerificationKey, PartialVerificationKeysResponse,
    TicketbookRequest, TicketbookWalletSharesResponse, WalletShare,
};
use nym_credentials_interface::Base58;
use nym_ecash_time::EcashTime;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const EPOCH: u64 = 1;
const MAX_REQUEST: usize = 256 * 1024;

struct Signers {
    keys: Vec<KeyPairAuth>,
    master: VerificationKeyAuth,
    bearer: Option<String>,
}

impl Signers {
    fn new(bearer: Option<String>) -> Result<Self, String> {
        let keys = nym_compact_ecash::ttp_keygen(2, 3).map_err(|e| e.to_string())?;
        let vks: Vec<_> = keys.iter().map(|k| k.verification_key()).collect();
        let master = nym_compact_ecash::aggregate_verification_keys(&vks, Some(&[1, 2, 3]))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            keys,
            master,
            bearer,
        })
    }

    fn partial_keys(&self) -> Vec<u8> {
        let r = PartialVerificationKeysResponse {
            epoch_id: EPOCH,
            keys: self
                .keys
                .iter()
                .enumerate()
                .map(|(i, k)| PartialVerificationKey {
                    node_index: i as u64 + 1,
                    bs58_encoded_key: k.verification_key().to_bs58(),
                })
                .collect(),
        };
        serde_json::to_vec(&r).unwrap_or_default()
    }

    fn obtain(&self, body: &[u8]) -> Result<Vec<u8>, String> {
        let req: TicketbookRequest = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        let mut shares = Vec::new();
        for (i, k) in self.keys.iter().enumerate() {
            let blinded = nym_compact_ecash::issue(
                k.secret_key(),
                req.ecash_pubkey,
                &req.withdrawal_request.0,
                req.expiration_date.ecash_unix_timestamp(),
                req.ticketbook_type.encode(),
            )
            .map_err(|e| e.to_string())?;
            shares.push(WalletShare {
                node_index: i as u64 + 1,
                bs58_encoded_share: blinded.to_bs58(),
            });
        }
        let r = TicketbookWalletSharesResponse {
            epoch_id: EPOCH,
            shares,
            master_verification_key: Some(MasterVerificationKeyResponse {
                epoch_id: EPOCH,
                bs58_encoded_key: self.master.to_bs58(),
            }),
            aggregated_coin_index_signatures: None,
            aggregated_expiration_date_signatures: None,
        };
        serde_json::to_vec(&r).map_err(|e| e.to_string())
    }
}

/// One request per connection: the head, then `Content-Length` bytes.
async fn serve(mut s: TcpStream, signers: Arc<Signers>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_REQUEST {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let first = lines.next().unwrap_or_default().to_string();
    let mut len = 0usize;
    let mut auth = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().unwrap_or(0),
                "authorization" => auth = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    if len > MAX_REQUEST {
        return Ok(());
    }
    while buf.len() < head_end + len {
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = &buf[head_end..head_end + len];
    let mut parts = first.split(' ');
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = path.split('?').next().unwrap_or("");
    let allowed = match &signers.bearer {
        Some(t) => auth.as_deref() == Some(format!("Bearer {t}").as_str()),
        None => true,
    };
    let (status, answer) = if !allowed {
        ("401 Unauthorized", Vec::new())
    } else {
        match (method, path) {
            ("GET", "/api/v1/ticketbook/partial-verification-keys") => {
                ("200 OK", signers.partial_keys())
            }
            ("POST", "/api/v1/ticketbook/obtain") => match signers.obtain(body) {
                Ok(b) => ("200 OK", b),
                Err(e) => ("400 Bad Request", e.into_bytes()),
            },
            ("GET", "/healthz") => ("200 OK", Vec::new()),
            _ => ("404 Not Found", Vec::new()),
        }
    };
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        answer.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(&answer).await?;
    s.shutdown().await
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

async fn run(args: Vec<String>) -> Result<(), String> {
    let listen: SocketAddr = flag(&args, "--listen")
        .unwrap_or_else(|| "127.0.0.1:7449".into())
        .parse()
        .map_err(|_| "--listen ADDR:PORT".to_string())?;
    let bearer = match flag(&args, "--token-file") {
        Some(f) => Some(
            std::fs::read_to_string(&f)
                .map_err(|e| format!("{f}: {e}"))?
                .trim()
                .to_string(),
        ),
        None => None,
    };
    let signers = Arc::new(Signers::new(bearer)?);
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("{listen}: {e}"))?;
    eprintln!("enclave-dev-proxy: serving on {listen}");
    loop {
        tokio::select! {
            a = listener.accept() => {
                let (s, _) = a.map_err(|e| e.to_string())?;
                let signers = Arc::clone(&signers);
                tokio::spawn(async move {
                    let _ = serve(s, signers).await;
                });
            }
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-dev-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}
