//! On a local mixnet with two gateways (`ci/nym-localnet/run-local.sh`): a
//! device client sends what the shaper sends every Foreground tick, a poll
//! with the reply blocks for its answer and a unit one way, paced as the
//! shaper sets it, to an ingress on the other gateway (so the device is
//! the only client of its own). A packet capture of the gateways'
//! WebSocket ports during the run, given to `ci/federation/pcap-check.py`
//! with the marks this writes (first half and second half), measures the
//! wire: packets per tick each way, their size and their spacing. The
//! ingress answers each poll with a full reply unit, as a server does. It
//! also prints
//! the paced queue, which must keep emptying. The CI step
//! (`ci/federation/gen.sh shape`) runs the real shaped client instead.
//!
//! ```text
//! ENCLAVE_NYM_TOPOLOGY=network.json ENCLAVE_NYM_API=http://127.0.0.1:8000/ \
//!   cargo run -p enclave-nym-sdk --example localnet_ticks -- SECONDS MARKS
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_nym::frame::{REPLY_LEN, Reply, Request};
use enclave_nym::{MixnetDriver, Pacing};
use enclave_nym_sdk::{Network, NymDriver, Options, Role};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seconds: u64 = args.first().map_or(120, |s| s.parse().expect("SECONDS"));
    let marks = args.get(1).cloned().unwrap_or_else(|| "marks".into());
    let network = Network::from_env(true);
    assert!(
        matches!(network, Network::Local { .. }),
        "set ENCLAVE_NYM_TOPOLOGY"
    );
    let dir = std::env::temp_dir().join(format!("enclave-ticks-{}", std::process::id()));
    let ingress = Arc::new(
        NymDriver::connect(Options {
            role: Role::Ingress { dir: dir.clone() },
            gateway: None,
            network: network.clone(),
            tickets: Vec::new(),
        })
        .await
        .expect("ingress connects"),
    );
    let device = Arc::new(
        NymDriver::connect(Options {
            role: Role::Client,
            gateway: None,
            network,
            tickets: Vec::new(),
        })
        .await
        .expect("device connects"),
    );
    if device.gateway() == ingress.gateway() {
        device.switch_gateway().await.expect("to the other gateway");
    }
    assert_ne!(device.gateway(), ingress.gateway());
    // Foreground's pacing. Loop cover at 1 per 10 s on its own: there is
    // no NymTransport here to send self-loop probes.
    device.set_pacing(Pacing {
        tick: Duration::from_secs(3),
        bulk: false,
        loop_cover: Duration::from_secs(10),
        probe: Duration::from_secs(30),
    });
    println!(
        "device {} on gateway {:?}",
        device.address(),
        device.gateway()
    );
    println!("ingress on gateway {:?}", ingress.gateway());
    let reader = Arc::clone(&device);
    tokio::spawn(async move { while reader.recv().await.is_some() {} });
    // The ingress answers every poll with a full reply unit, as a server
    // does, over the reply blocks that came with it.
    let server = Arc::clone(&ingress);
    tokio::spawn(async move {
        while let Some(m) = server.recv().await {
            if let (Some(surbs), Ok(req)) = (m.reply, Request::decode(&m.data)) {
                let reply = Reply {
                    id: req.id,
                    data: Some(vec![3; enclave_wire::UNIT_LEN]),
                };
                let _ = server.reply(surbs, reply.encode().unwrap()).await;
            }
        }
    });

    let to = ingress.address();
    // Ten seconds to settle, then the measured run.
    tokio::time::sleep(Duration::from_secs(10)).await;
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    let start = unix_ms();
    let end = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let mut n = 0u64;
    while tokio::time::Instant::now() < end {
        tick.tick().await;
        let id = |k: u64| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&k.to_be_bytes());
            id
        };
        let poll = Request::for_sealed(id(2 * n), vec![1; enclave_wire::POLL_LEN]).unwrap();
        device.send(&to, poll.encode(), REPLY_LEN).await.unwrap();
        let unit = Request::oneway(id(2 * n + 1), vec![2; enclave_wire::UNIT_LEN]).unwrap();
        device.send(&to, unit.encode(), 0).await.unwrap();
        n += 1;
        if n.is_multiple_of(5) {
            use nym_client_core::enclave as e;
            println!(
                "tick {n}: fragments {} out {} queued {} outstanding {}",
                e::fragments_sent(),
                e::packets_out(),
                e::queued(),
                e::outstanding()
            );
        }
    }
    let stop = unix_ms();
    let mid = start + (stop - start) / 2;
    std::fs::write(&marks, format!("{start} {mid} {mid} {stop}\n")).unwrap();
    println!("{n} ticks; marks in {marks}");
    assert!(device.flush(Duration::from_secs(60)).await);
    let _ = std::fs::remove_dir_all(dir);
}
