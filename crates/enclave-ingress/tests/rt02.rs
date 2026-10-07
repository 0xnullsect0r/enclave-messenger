//! RT-02 (`docs/redteam-matrix.md`): a gateway that drops or delays a
//! device's traffic (an n-1 attack, or just a bad gateway) makes the device
//! move to another one, at most once per 10 minutes
//! (`enclave_net::monitor`, `docs/09-transport.md` §6.3).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_net::monitor::COOLDOWN;
use enclave_net::transport::{NymTransport, Transport};
use enclave_nym::MixnetDriver;
use enclave_nym::fake::{FakeClient, FakeMixnet, Faults};
use enclave_nym::frame::{Kind, Reply, Request};
use enclave_wire::{POLL_LEN, UNIT_LEN};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const SERVER: [u8; 16] = [9; 16];

/// A network with two gateways for the device and one for the ingress,
/// and an ingress that answers every request at once.
fn network(seed: u64) -> (FakeMixnet, Arc<FakeClient>, NymTransport) {
    let net = FakeMixnet::new(Faults::default(), seed);
    for g in ["gw-a", "gw-b", "gw-ingress"] {
        net.set_gateway(g, Faults::default());
    }
    let ingress = net.client_at("ingress", "gw-ingress");
    tokio::spawn(async move {
        while let Some(m) = ingress.recv().await {
            let (Ok(req), Some(tag)) = (Request::decode(&m.data), m.reply) else {
                continue;
            };
            if req.kind == Kind::Oneway {
                continue;
            }
            let reply = Reply {
                id: req.id,
                data: Some(vec![0; UNIT_LEN]),
            };
            let _ = ingress.reply(tag, reply.encode().unwrap()).await;
        }
    });
    let phone = Arc::new(net.client_at("phone", "gw-a"));
    let t = NymTransport::new(
        phone.clone(),
        HashMap::from([(SERVER, "ingress".to_string())]),
        Duration::from_secs(5),
    );
    (net, phone, t)
}

/// `n` polls one after another; how many came back.
async fn exchanges(t: &NymTransport, n: usize) -> usize {
    let mut ok = 0;
    for _ in 0..n {
        if t.exchange(&SERVER, vec![1; POLL_LEN]).await.is_ok() {
            ok += 1;
        }
    }
    ok
}

#[tokio::test(start_paused = true)]
async fn rt02_gateway_switch_on_loss_over_10pct() {
    let (net, phone, t) = network(3);
    net.set_gateway(
        "gw-a",
        Faults {
            loss: 0.2,
            ..Faults::default()
        },
    );
    exchanges(&t, 120).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(t.switches(), 1);
    assert_eq!(phone.gateway().as_deref(), Some("gw-b"));

    // The new gateway goes bad too: no second switch within 10 minutes,
    // then one.
    net.set_gateway(
        "gw-b",
        Faults {
            loss: 0.3,
            ..Faults::default()
        },
    );
    let started = tokio::time::Instant::now();
    while started.elapsed() < COOLDOWN - Duration::from_secs(60) {
        exchanges(&t, 10).await;
    }
    assert_eq!(t.switches(), 1, "at most one switch per 10 minutes");
    while t.switches() < 2 && started.elapsed() < COOLDOWN * 2 {
        exchanges(&t, 10).await;
    }
    assert_eq!(t.switches(), 2);
    assert_ne!(
        phone.gateway().as_deref(),
        Some("gw-b"),
        "moved off the bad one"
    );
}

#[tokio::test(start_paused = true)]
async fn rt02_gateway_switch_on_latency_over_5x_median() {
    let (net, phone, t) = network(5);
    net.set_gateway(
        "gw-a",
        Faults {
            loss: 0.0,
            max_delay: Duration::from_millis(100),
        },
    );
    assert_eq!(exchanges(&t, 60).await, 60);
    assert_eq!(t.switches(), 0, "a steady path");
    // Slower by far more than 5×, still within the request timeout.
    net.set_gateway(
        "gw-a",
        Faults {
            loss: 0.0,
            max_delay: Duration::from_millis(1_600),
        },
    );
    exchanges(&t, 20).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(t.switches(), 1);
    assert_eq!(phone.gateway().as_deref(), Some("gw-b"));
}

/// A little loss is normal and never moves the device.
#[tokio::test(start_paused = true)]
async fn rt02_no_switch_on_ordinary_loss() {
    let (net, phone, t) = network(11);
    net.set_gateway(
        "gw-a",
        Faults {
            loss: 0.01,
            max_delay: Duration::from_millis(100),
        },
    );
    exchanges(&t, 150).await;
    assert_eq!(t.switches(), 0);
    assert_eq!(phone.gateway().as_deref(), Some("gw-a"));
}
