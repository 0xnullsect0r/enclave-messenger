//! On a local mixnet (`ci/nym-localnet`): an ingress-role client and a
//! device client connect, the device sends requests with reply blocks for a
//! full reply, and the ingress answers each over them.
//!
//! ```text
//! ENCLAVE_NYM_TOPOLOGY=network.json ENCLAVE_NYM_API=http://127.0.0.1:8000/ \
//!   cargo run -p enclave-nym-sdk --example localnet_roundtrip
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_nym::MixnetDriver;
use enclave_nym::frame::{REPLY_LEN, Reply, Request};
use enclave_nym_sdk::{Network, NymDriver, Options, Role};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    // RUST_LOG for nym-sdk's own logs (warnings by default).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let network = Network::from_env(true);
    assert!(
        matches!(network, Network::Local { .. }),
        "set ENCLAVE_NYM_TOPOLOGY"
    );
    let dir = std::env::temp_dir().join(format!("enclave-localnet-{}", std::process::id()));
    let t = Instant::now();
    let ingress = NymDriver::connect(Options {
        role: Role::Ingress { dir: dir.clone() },
        gateway: None,
        network: network.clone(),
    })
    .await
    .expect("ingress connects");
    let device = NymDriver::connect(Options {
        role: Role::Client,
        gateway: None,
        network,
    })
    .await
    .expect("device connects");
    println!(
        "connected in {:?}: ingress {}",
        t.elapsed(),
        ingress.address()
    );

    let to = ingress.address();
    for n in 0..3u8 {
        let t = Instant::now();
        let req = Request::for_sealed([n; 16], vec![n; enclave_wire::POLL_LEN]).unwrap();
        device.send(&to, req.encode(), REPLY_LEN).await.unwrap();
        let m = tokio::time::timeout(Duration::from_secs(60), ingress.recv())
            .await
            .expect("request arrives")
            .unwrap();
        let got = Request::decode(&m.data).unwrap();
        assert_eq!(got, req);
        let reply = Reply {
            id: got.id,
            data: Some(vec![n ^ 0xff; enclave_wire::UNIT_LEN]),
        };
        ingress
            .reply(m.reply.expect("reply blocks came"), reply.encode().unwrap())
            .await
            .unwrap();
        let r = tokio::time::timeout(Duration::from_secs(60), device.recv())
            .await
            .expect("reply arrives")
            .unwrap();
        let r = Reply::decode(&r.data).unwrap();
        assert_eq!(r, reply);
        println!("round trip {n}: {:?}", t.elapsed());
    }

    // One way, then flushed: by the time the flush returns, the far gateway
    // has acknowledged every packet (what a client does before exiting).
    let t = Instant::now();
    let req = Request::oneway([9; 16], vec![9; enclave_wire::UNIT_LEN]).unwrap();
    device.send(&to, req.encode(), 0).await.unwrap();
    assert!(
        device.flush(Duration::from_secs(60)).await,
        "flushed in time"
    );
    assert_eq!(nym_client_core::enclave::outstanding(), 0);
    println!("one-way send flushed in {:?}", t.elapsed());
    let m = tokio::time::timeout(Duration::from_secs(60), ingress.recv())
        .await
        .expect("one-way request arrives")
        .unwrap();
    assert_eq!(Request::decode(&m.data).unwrap(), req);

    // How many Sphinx packets a poll (with its reply blocks) and a one-way
    // unit take: what pacing spreads across a tick.
    let sent = nym_client_core::enclave::fragments_sent;
    let before = sent();
    let poll = Request::for_sealed([7; 16], vec![7; enclave_wire::POLL_LEN]).unwrap();
    device.send(&to, poll.encode(), REPLY_LEN).await.unwrap();
    assert!(device.flush(Duration::from_secs(60)).await);
    let poll_packets = sent() - before;
    let before = sent();
    let unit = Request::oneway([8; 16], vec![8; enclave_wire::UNIT_LEN]).unwrap();
    device.send(&to, unit.encode(), 0).await.unwrap();
    assert!(device.flush(Duration::from_secs(60)).await);
    let unit_packets = sent() - before;
    println!("packets: poll {poll_packets}, one-way unit {unit_packets}");
    assert_eq!(
        (poll_packets, unit_packets),
        (
            u64::from(enclave_nym_sdk::POLL_PACKETS),
            u64::from(enclave_nym_sdk::UNIT_PACKETS)
        ),
        "the pacing constants match the mixnet"
    );

    // Paced: with a 100 ms gap, a unit's 11 packets take at least 1 s.
    let pacing = enclave_nym::Pacing {
        tick: Duration::from_millis(1_600),
        bulk: false,
        loop_cover: Duration::from_secs(10),
    };
    device.set_pacing(pacing);
    let t = Instant::now();
    let unit = Request::oneway([10; 16], vec![10; enclave_wire::UNIT_LEN]).unwrap();
    device.send(&to, unit.encode(), 0).await.unwrap();
    assert!(device.flush(Duration::from_secs(60)).await);
    let paced = t.elapsed();
    println!("paced one-way unit flushed in {paced:?}");
    assert!(paced >= Duration::from_millis(1_000), "{paced:?}");
    let _ = std::fs::remove_dir_all(dir);
    println!("ok");
}
