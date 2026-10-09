//! The server at scale (`docs/12-servers.md` §7): fill a server with
//! `--accounts` accounts (an inbox and a request inbox each, 16 write tokens
//! and one stored message), then measure the requests a running server
//! handles all day against that state. Prints a Markdown table.
//!
//! ```text
//! cargo run --release -p enclave-server --example scale -- [--accounts 100000] [--samples 20000] [--dir DIR] [--postgres URL]
//! ```
//!
//! Clients' sealing is done before the clock starts; what is timed is the
//! server's side: opening the request (X448 + ML-KEM-1024), the replay
//! check, the operation and its transaction, and sealing the reply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{self, FLAG_CREATE, FLAG_REQUEST_INBOX};
use enclave_rpc::{seal_poll, seal_request};
use enclave_server::db::Db;
use enclave_server::keys::ServerKeys;
use enclave_server::{Config, Server};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::time::Instant;

const DAY: u32 = 20_700;
const NOW: u64 = DAY as u64 * 86_400 + 600;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn rss_mib() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())
        })
        .map_or(0.0, |kb| kb / 1024.0)
}

fn dir_mib(p: &std::path::Path) -> f64 {
    std::fs::read_dir(p)
        .map(|d| {
            d.filter_map(Result::ok)
                .filter_map(|e| e.metadata().ok())
                .filter(std::fs::Metadata::is_file)
                .map(|m| m.len())
                .sum::<u64>()
        })
        .unwrap_or(0) as f64
        / (1024.0 * 1024.0)
}

fn mailbox(i: u64, kind: u8) -> [u8; 32] {
    let mut m = [kind; 32];
    m[..8].copy_from_slice(&i.to_be_bytes());
    m
}

fn owner(i: u64) -> [u8; 32] {
    let mut m = [0xaa; 32];
    m[..8].copy_from_slice(&i.to_be_bytes());
    m
}

fn token(i: u64, n: u8) -> [u8; 32] {
    let mut m = [n; 32];
    m[..8].copy_from_slice(&i.to_be_bytes());
    m
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let accounts: u64 = flag(&args, "--accounts").map_or(100_000, |v| v.parse().unwrap());
    let samples: usize = flag(&args, "--samples").map_or(20_000, |v| v.parse().unwrap());
    let dir = flag(&args, "--dir").map_or_else(
        || std::env::temp_dir().join(format!("enclave-scale-{}", std::process::id())),
        std::path::PathBuf::from,
    );
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let keys = ServerKeys::init(&dir.join("keys"), DAY).unwrap();
    let db = match flag(&args, "--postgres") {
        Some(url) => Db::connect(&url).unwrap(),
        None => Db::open(&dir.join("server.redb")).unwrap(),
    };
    let backend = db.backend();
    let cfg = Config {
        id: keys.id(),
        effort_inbox: 0,
        ..Config::default()
    };
    let mut s = Server::open(cfg, db, keys.chain.keys()).unwrap();
    let key = s.public_key().unwrap();
    let mut rng = HedgedRng::new().unwrap();
    let envelope = vec![0x5a; ENVELOPE_LEN];

    // Fill it, in batches sealed ahead of handling.
    let start = Instant::now();
    let mut handled = 0u64;
    let batch = 1_000u64;
    for first in (0..accounts).step_by(batch as usize) {
        let mut reqs = Vec::new();
        for i in first..(first + batch).min(accounts) {
            for (mb, flags) in [
                (mailbox(i, 1), FLAG_CREATE),
                (mailbox(i, 2), FLAG_CREATE | FLAG_REQUEST_INBOX),
            ] {
                let h = RequestHeader {
                    op: Op::RegisterTokens,
                    flags,
                    mailbox: mb,
                    token: owner(i),
                };
                reqs.push(
                    seal_request(&key, &h, &api::frame(&[], &mut rng).unwrap(), &mut rng).unwrap(),
                );
            }
            let hashes: Vec<u8> = (1..=16u8)
                .flat_map(|n| enclave_tokens::token_hash(&token(i, n), &mailbox(i, 1)))
                .collect();
            let reg = RequestHeader {
                op: Op::RegisterTokens,
                flags: 0,
                mailbox: mailbox(i, 1),
                token: owner(i),
            };
            reqs.push(
                seal_request(
                    &key,
                    &reg,
                    &api::frame(&hashes, &mut rng).unwrap(),
                    &mut rng,
                )
                .unwrap(),
            );
            let w = RequestHeader {
                op: Op::Write,
                flags: 0,
                mailbox: mailbox(i, 1),
                token: token(i, 1),
            };
            reqs.push(seal_request(&key, &w, &envelope, &mut rng).unwrap());
        }
        for (bytes, _) in reqs {
            s.handle(&bytes, NOW);
            handled += 1;
        }
    }
    let fill = start.elapsed();
    let filled_mib = dir_mib(&dir);

    // The day's mix, timed per kind: polls (Background and Foreground
    // devices poll their inbox every tick), writes, cover.
    let mut rows = Vec::new();
    let pick = |n: usize| (n as u64 * 7_919) % accounts;
    for kind in ["poll", "write", "cover", "replay"] {
        let mut reqs = Vec::with_capacity(samples);
        for n in 0..samples {
            let i = pick(n);
            let bytes = match kind {
                "poll" => {
                    let mut cred = [0u8; 32];
                    cred[..24].copy_from_slice(&api::read_credential(&owner(i)));
                    let h = RequestHeader {
                        op: Op::Poll,
                        flags: 0,
                        mailbox: mailbox(i, 1),
                        token: cred,
                    };
                    seal_poll(&key, &h, &mut rng).unwrap().0
                }
                "write" => {
                    let h = RequestHeader {
                        op: Op::Write,
                        flags: 0,
                        mailbox: mailbox(i, 1),
                        token: token(i, 2 + (n as u64 / accounts) as u8 % 15),
                    };
                    seal_request(&key, &h, &envelope, &mut rng).unwrap().0
                }
                _ => {
                    let h = RequestHeader {
                        op: Op::Cover,
                        flags: 0,
                        mailbox: [0; 32],
                        token: [0; 32],
                    };
                    seal_request(&key, &h, &envelope, &mut rng).unwrap().0
                }
            };
            reqs.push(bytes);
        }
        if kind == "replay" {
            // The same cover requests again: refused by the replay cache.
            for r in &reqs {
                s.handle(r, NOW);
            }
        }
        let t = Instant::now();
        for r in &reqs {
            s.handle(r, NOW);
        }
        let per = t.elapsed().as_secs_f64() / samples as f64;
        rows.push((kind, per));
    }
    let stats = s.stats();

    println!("## Scale run: {accounts} accounts on {backend}\n");
    println!("| Quantity | Measured |");
    println!("|---|---|");
    println!(
        "| Fill: {handled} requests | {:.1} s ({:.0} requests/s) |",
        fill.as_secs_f64(),
        handled as f64 / fill.as_secs_f64()
    );
    println!(
        "| State on disk after the fill | {filled_mib:.0} MiB ({:.1} KiB per account) |",
        filled_mib * 1024.0 / accounts as f64
    );
    for (kind, per) in &rows {
        println!(
            "| {kind} | {:.3} ms per request, {:.0} per second per core |",
            per * 1000.0,
            1.0 / per
        );
    }
    // §7's load: every device's tick is one poll and one unit, and nearly
    // every unit is cover; say 5% carry a message.
    let per = |k: &str| rows.iter().find(|(n, _)| *n == k).map_or(0.0, |(_, p)| *p);
    let mix = 0.5 * per("poll") + 0.45 * per("cover") + 0.05 * per("write");
    println!(
        "| Cores for §7's 7,375 requests/s (50% polls, 45% cover, 5% writes) | {:.1} |",
        7_375.0 * mix
    );
    println!("| Resident memory | {:.0} MiB |", rss_mib());
    println!("| Replays refused | {} |", stats.replays);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}
