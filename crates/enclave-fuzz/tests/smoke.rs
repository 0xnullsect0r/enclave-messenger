//! Seeded mutation smoke test over every fuzz target. A failure prints the
//! target, seed and iteration; `enclave_fuzz::run` reproduces it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_fuzz::{TARGETS, Xorshift, mutate};

/// Valid encodings to mutate, so mutations reach past the first length check.
fn samples() -> Vec<Vec<u8>> {
    let mut rng = HedgedRng::new().unwrap();
    let mut out = vec![Vec::new(), vec![0; 72], vec![0xff; 200]];
    // Small pictures for the media target.
    let mut png_bytes = Vec::new();
    {
        let mut e = png::Encoder::new(&mut png_bytes, 6, 4);
        e.set_color(png::ColorType::Rgba);
        let mut w = e.write_header().unwrap();
        w.write_image_data(&[90; 6 * 4 * 4]).unwrap();
    }
    out.push(png_bytes);
    let mut jpeg = Vec::new();
    jpeg_encoder::Encoder::new(&mut jpeg, 80)
        .encode(&[120; 8 * 8 * 3], 8, 8, jpeg_encoder::ColorType::Rgb)
        .unwrap();
    out.push(jpeg);
    // Content, cards, attachments.
    use enclave_core::content::Content;
    out.push(
        Content::Text {
            tokens: vec![[1; 32]; 3],
            text: "hello".into(),
            id: [2; 16],
            expires: 60,
            reply: Some([4; 16]),
            forwarded: true,
            link: None,
        }
        .encode()
        .unwrap(),
    );
    out.push(Content::Read(vec![[3; 16]; 4]).encode().unwrap());
    out.push(
        Content::GroupCards {
            group_id: [4; 32],
            cards: vec![vec![5; 50]; 3],
        }
        .encode()
        .unwrap(),
    );
    let card = enclave_core::ContactCard {
        root: [6; 64],
        server: [7; 16],
        request_inbox: [8; 32],
        vault_locator: [9; 32],
        vault_key: [10; 32],
        name: "Sam".into(),
        server_domain: "a.example".into(),
        invite: Some(enclave_core::Invite {
            secret: [11; 32],
            uses: 2,
        }),
    };
    out.push(card.encode());
    out.push(card.to_link().into_bytes());
    let (att, _) =
        enclave_core::files::seal_file(b"file", "a.txt", "text/plain", [1; 16], &mut rng).unwrap();
    out.push(att.encode());
    // Group state and group persistence.
    let mut g = enclave_proto::group::Group::create("g", [1; 64], [2; 16], 0, &mut rng).unwrap();
    out.push(g.state.encode());
    g.rotate(&[], None, 0, &mut rng).unwrap();
    out.push(g.export().to_vec());
    out.push(g.seal(b"hi", 0, &mut rng).unwrap());
    // Wire and RPC.
    let h = enclave_wire::RequestHeader {
        op: enclave_wire::Op::Poll,
        flags: 0,
        mailbox: [1; 32],
        token: [2; 32],
    };
    out.push(h.encode().to_vec());
    let req = enclave_rpc::api::DirRequest {
        kind: enclave_rpc::api::DirKind::Manifest,
        action: enclave_rpc::api::DirAction::Get,
        key: [3; 32],
        index: 0,
        total: 1,
        proof: [0; 32],
        data: vec![1, 2, 3],
    };
    out.push(req.encode());
    out.push(enclave_rpc::api::frame(&req.encode(), &mut rng).unwrap());
    // Key transparency: a real signed head, claim and pin file.
    {
        let (svc, policy) = enclave_kt::KtService::start_dev([5; 16], "fuzz.test").unwrap();
        svc.publish("sam", vec![1; 80], 1_790_000_000).unwrap();
        out.push(svc.lookup("sam", 1_790_000_000).unwrap());
        out.push(policy.encode());
        out.push(svc.info().encode());
        out.push(
            enclave_kt::UsernameClaim {
                name: "sam".into(),
                value: vec![2; 100],
                device: [3; 16],
                time: 1,
                signature: vec![4; 60],
            }
            .encode(),
        );
    }
    // UI ↔ vault messages.
    out.push(enclave_ipc::Cmd::Send("ab".into(), "hello".into()).encode());
    out.push(
        enclave_ipc::Out::Snapshot(Box::new(enclave_ipc::Snapshot {
            my_name: "Robin".into(),
            contacts: vec![enclave_ipc::Row::default(); 3],
            messages: vec![enclave_ipc::Msg::default(); 2],
            ..Default::default()
        }))
        .encode(),
    );
    // Calls.
    let p = enclave_calls::signal::offer(
        enclave_calls::signal::Media::Audio,
        enclave_calls::signal::Route::Relay,
        vec![1; 10],
        0,
        &mut rng,
    )
    .unwrap();
    out.push(p.offer().encode());
    let mut tx = enclave_calls::sframe::Sender::new(0, &[7; 32]);
    out.push(tx.protect(0, b"", &[0; 111]).unwrap());
    out
}

#[test]
fn every_target_survives_mutated_and_random_input() {
    let samples = samples();
    let iterations: usize = std::env::var("ENCLAVE_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500);
    for (name, f) in TARGETS {
        // The server and relay targets do KEM work per input; fewer rounds.
        let n = if matches!(*name, "server" | "relay") {
            iterations / 10
        } else {
            iterations
        };
        let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15 ^ name.len() as u64);
        for i in 0..n {
            let base = &samples[rng.below(samples.len())];
            let input = if rng.below(8) == 0 {
                (0..rng.below(20_000))
                    .map(|_| rng.next_u64() as u8)
                    .collect()
            } else {
                mutate(base, &mut rng)
            };
            let r = std::panic::catch_unwind(|| f(&input));
            assert!(
                r.is_ok(),
                "target {name} panicked at iteration {i} (input {} bytes)",
                input.len()
            );
        }
    }
}

/// Inputs the nightly fuzzer found, kept so they stay fixed.
#[test]
fn found_by_the_nightly_fuzzer() {
    // calls: an SFrame header whose counter makes the epoch arithmetic
    // overflow.
    enclave_fuzz::run(
        "calls",
        &[
            244, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 8,
        ],
    );
    // media: a one-byte AV1 unit (rav1d's empty picture leaked).
    enclave_fuzz::run("media", &[0, 0, 0, 1, 0]);
    // media: an 8-byte AV1 unit the nightly fuzzer killed the decoder with.
    enclave_fuzz::run("media", &[0, 0, 0, 8, 40, 4, 0, 0, 0, 0, 0, 0, 0, 65]);
    // media: a picture whose frame header was refused reached rav1d's
    // error path, which read the header it didn't have.
    enclave_fuzz::run(
        "media",
        &[
            0, 0, 0, 22, 137, 39, 34, 206, 0, 137, 80, 78, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0,
            255, 0, 0, 0, 22, 52, 0, 0, 0, 0, 137, 80, 178, 250, 0, 0, 0, 1, 0, 0, 0, 0, 0, 253,
            10, 26, 38,
        ],
    );
    // media: a motion vector whose residual takes it past i16 (dav1d
    // wraps it, as C's int16_t store does; rav1d overflowed).
    enclave_fuzz::run(
        "media",
        &[
            0, 0, 0, 10, 137, 60, 240, 228, 248, 1, 1, 249, 0, 0, 0, 0, 0, 26, 53, 0, 255, 255, 8,
            1, 252, 37, 35, 255, 0, 0, 10, 137, 60, 240, 228, 248, 1, 1, 249, 0, 0, 10, 137, 60, 0,
            0, 0, 0, 26, 53, 0, 255, 255, 8, 1, 252, 0, 35, 255, 32, 0, 0, 1, 0, 0, 0, 223, 47, 11,
            0, 0, 0, 250, 0, 0, 7, 251, 251, 251, 251, 251, 251, 251, 251, 255, 0, 0, 0, 10, 32, 0,
            0, 1, 0, 0, 0, 47, 11, 0, 0, 0, 250, 0, 0, 7, 251, 251, 251, 251, 251, 251, 251, 251,
            255, 0, 0, 0, 10, 137,
        ],
    );
}
