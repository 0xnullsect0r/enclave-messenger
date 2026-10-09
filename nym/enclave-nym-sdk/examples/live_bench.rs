//! Measure the mixnet path a device uses (`docs/spikes/m4-network.md`, N4):
//! an ingress-role client and a device client connect, the device sends
//! polls with reply blocks and the ingress answers each with a full unit (a
//! server's answer), then the device sends units one way in a bulk window.
//! Writes one JSON object: connect times, round-trip latencies, bulk
//! throughput, peak memory, and zk-nym tickets spent.
//!
//! ```text
//! cargo run --release -p enclave-nym-sdk --example live_bench -- [--mainnet] [--out FILE]
//!     [--rounds N] [--bulk-units N]
//! ```
//!
//! The network is mainnet with `--mainnet`; otherwise a local mixnet
//! (`ENCLAVE_NYM_TOPOLOGY`, `ENCLAVE_NYM_API`) or the network the `NYM_*`
//! variables describe (the sandbox: `envs/sandbox.env` from Nym's
//! repository). On a network whose gateways check tickets, both clients buy
//! them from the Nyx account whose mnemonic is in `ENCLAVE_NYM_MNEMONIC`
//! (as an operator's ingress does; a device's own tickets come through the
//! credential gate, which needs a funded proxy). With `ENCLAVE_TOR_SOCKS`
//! and `ENCLAVE_TOR_SECRET` (enclave-tord), gateways are dialled through
//! Tor, as on a device. Exits non-zero if a client can't connect or if
//! more than one round trip in ten gets no answer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_nym::frame::{REPLY_LEN, Reply, Request};
use enclave_nym::{MixnetDriver, Pacing};
use enclave_nym_sdk::funding::Funding;
use enclave_nym_sdk::{Network, NymDriver, Options, Role};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Peak resident memory of this process, in KiB (Linux).
fn peak_rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// What one ticketbook costs on `network` (the ecash contract's default
/// deposit), as `(amount, denom)`; nothing on a local mixnet.
async fn deposit(network: &Network) -> Option<(String, String)> {
    use nym_validator_client::nyxd::contract_traits::EcashQueryClient;
    let details = match network {
        Network::Mainnet => nym_sdk::NymNetworkDetails::new_mainnet(),
        Network::Env => nym_sdk::NymNetworkDetails::new_from_env(),
        Network::Local { .. } => return None,
    };
    let url = details.endpoints.first()?.nyxd_url.to_string();
    let client =
        nym_validator_client::nyxd::NyxdClient::connect_with_network_details(url.as_str(), details)
            .ok()?;
    let coin = client.get_default_deposit_amount().await.ok()?;
    Some((coin.amount.to_string(), coin.denom))
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[i]
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rounds: usize = flag(&args, "--rounds").map_or(20, |n| n.parse().expect("--rounds N"));
    let bulk_units: usize =
        flag(&args, "--bulk-units").map_or(40, |n| n.parse().expect("--bulk-units N"));
    let network = if args.iter().any(|a| a == "--mainnet") {
        Network::Mainnet
    } else {
        Network::from_env(true)
    };
    let tor = if let (Ok(proxy), Ok(secret)) = (
        std::env::var("ENCLAVE_TOR_SOCKS"),
        std::env::var("ENCLAVE_TOR_SECRET"),
    ) {
        enclave_nym_sdk::dial_gateways_through(
            proxy.parse().expect("ENCLAVE_TOR_SOCKS is HOST:PORT"),
            secret,
        );
        true
    } else {
        false
    };
    let funding = std::env::var("ENCLAVE_NYM_MNEMONIC")
        .ok()
        .filter(|m| !m.trim().is_empty())
        .map(|m| Funding {
            mnemonic: zeroize::Zeroizing::new(m.trim().to_string()),
            keep: 5,
        });
    let funded = funding.is_some();
    let dir = std::env::temp_dir().join(format!("enclave-bench-{}", std::process::id()));

    let t = Instant::now();
    let ingress = match NymDriver::connect(Options {
        role: Role::Ingress { dir: dir.clone() },
        gateway: None,
        network: network.clone(),
        tickets: Vec::new(),
        funding: funding.clone(),
    })
    .await
    {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("live_bench: the ingress didn't connect: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let ingress_connect = t.elapsed();
    let t = Instant::now();
    let device = match NymDriver::connect(Options {
        role: Role::Client,
        gateway: None,
        network: network.clone(),
        tickets: Vec::new(),
        funding,
    })
    .await
    {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("live_bench: the device didn't connect: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let device_connect = t.elapsed();
    let spent_at_start = nym_gateway_client::client::tickets_spent();
    eprintln!(
        "live_bench: connected (ingress {ingress_connect:?}, device {device_connect:?}) on {network:?}"
    );

    // The ingress answers every poll with a unit, as a server does.
    let answering = {
        let ingress = Arc::clone(&ingress);
        tokio::spawn(async move {
            let mut oneway = 0usize;
            while let Some(m) = ingress.recv().await {
                let Ok(req) = Request::decode(&m.data) else {
                    continue;
                };
                match m.reply {
                    Some(tag) => {
                        let reply = Reply {
                            id: req.id,
                            data: Some(vec![7; enclave_wire::UNIT_LEN]),
                        };
                        let _ = ingress.reply(tag, reply.encode().unwrap()).await;
                    }
                    None => oneway += 1,
                }
                if oneway == usize::MAX {
                    break;
                }
            }
        })
    };

    // Round trips: a poll with its reply blocks, answered with a unit.
    let to = ingress.address();
    let mut rtts = Vec::new();
    let mut lost = 0usize;
    for n in 0..rounds {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(n as u64).to_be_bytes());
        let req = Request::for_sealed(id, vec![1; enclave_wire::POLL_LEN]).unwrap();
        let t = Instant::now();
        device.send(&to, req.encode(), REPLY_LEN).await.unwrap();
        let answered = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let m = device.recv().await?;
                if Reply::decode(&m.data).is_ok_and(|r| r.id == id) {
                    return Some(());
                }
            }
        })
        .await;
        match answered {
            Ok(Some(())) => rtts.push(t.elapsed().as_secs_f64() * 1000.0),
            _ => lost += 1,
        }
    }
    rtts.sort_by(f64::total_cmp);

    // Bulk: units one way, paced at the bulk rate (40 packets/s), until
    // the far gateway has acknowledged every packet.
    device.set_pacing(Pacing {
        tick: Duration::from_secs(3),
        bulk: true,
        loop_cover: Duration::from_secs(10),
        probe: Duration::from_secs(30),
    });
    let t = Instant::now();
    for n in 0..bulk_units {
        let mut id = [0xb0; 16];
        id[8..].copy_from_slice(&(n as u64).to_be_bytes());
        let unit = Request::oneway(id, vec![2; enclave_wire::UNIT_LEN]).unwrap();
        device.send(&to, unit.encode(), 0).await.unwrap();
    }
    let flushed = device.flush(Duration::from_secs(600)).await;
    let bulk = t.elapsed();
    let kib_per_s = (bulk_units * enclave_wire::UNIT_LEN) as f64 / 1024.0 / bulk.as_secs_f64();

    let tickets_left_device = device.top_up().await.and_then(Result::ok);
    let tickets_left_ingress = ingress.top_up().await.and_then(Result::ok);
    let spent = nym_gateway_client::client::tickets_spent();
    answering.abort();
    let price = deposit(&network).await;
    let report = serde_json::json!({
        "network": format!("{network:?}"),
        "tor": tor,
        "funded": funded,
        "connect_ms": {
            "ingress": ingress_connect.as_millis(),
            "device": device_connect.as_millis(),
        },
        "round_trips": {
            "sent": rounds,
            "lost": lost,
            "p50_ms": percentile(&rtts, 0.5),
            "p95_ms": percentile(&rtts, 0.95),
            "max_ms": rtts.last().copied().unwrap_or(f64::NAN),
        },
        "bulk": {
            "units": bulk_units,
            "flushed": flushed,
            "seconds": bulk.as_secs_f64(),
            "payload_kib_per_s": kib_per_s,
        },
        "peak_rss_kib_both_clients": peak_rss_kib(),
        "tickets": {
            "spent_while_connected": spent.saturating_sub(spent_at_start),
            "spent_total": spent,
            "left_device": tickets_left_device,
            "left_ingress": tickets_left_ingress,
            "book_deposit": price.as_ref().map(|(a, _)| a.clone()),
            "book_deposit_denom": price.map(|(_, d)| d),
        },
    });
    let text = serde_json::to_string_pretty(&report).unwrap();
    println!("{text}");
    if let Some(out) = flag(&args, "--out") {
        std::fs::write(out, &text).unwrap();
    }
    let _ = std::fs::remove_dir_all(dir);
    if lost * 10 > rounds || !flushed {
        eprintln!("live_bench: {lost} of {rounds} round trips lost, flushed {flushed}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
