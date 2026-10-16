//! Release updates through the home server (`docs/19-ops.md` §1.3, §4):
//! the bundle a server relays is checked against the built-in root; a
//! release's minimum version stops an older app from sending, and from
//! receiving 30 days later.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, CoreError, Options, RECEIVE_GRACE};
use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use enclave_update::sigsum::Policy;
use enclave_update::*;
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];
const DAY: u64 = 86_400;

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

struct Keys {
    m: Vec<MaintainerKey>,
}

impl Keys {
    fn new() -> Self {
        let mut rng = HedgedRng::new().unwrap();
        Self {
            m: (0..3)
                .map(|_| MaintainerKey::generate(&mut rng).unwrap())
                .collect(),
        }
    }

    /// Maintainers 0 and 1 hold root and targets (2 of 2); key 2 is the
    /// online key.
    fn root(&self, now: u64) -> Vec<u8> {
        let rk = |keys: Vec<u8>, threshold| RoleKeys { keys, threshold };
        let r = Root {
            version: 1,
            expires: now + 365 * DAY,
            keys: self.m.iter().map(MaintainerKey::public).collect(),
            roles: [
                rk(vec![0, 1], 2),
                rk(vec![0, 1], 2),
                rk(vec![2], 1),
                rk(vec![2], 1),
            ],
            sigsum: Policy {
                log: [1; 32],
                submitters: vec![[2; 32]],
                witnesses: vec![[5; 32]],
                quorum: 1,
            },
        };
        let mut rng = HedgedRng::new().unwrap();
        let mut s = Signed::root(&r);
        for i in [0u8, 1] {
            s.sign(i, &self.m[usize::from(i)], &mut rng).unwrap();
        }
        s.encode()
    }

    /// A bundle for `release` at `version`, its targets signed by `by`.
    fn bundle(&self, version: u32, release: &str, minimum: &str, by: &[u8], now: u64) -> Vec<u8> {
        use sha2::Digest as _;
        let mut rng = HedgedRng::new().unwrap();
        let t = Targets {
            version,
            expires: now + 90 * DAY,
            release: release.into(),
            minimum: minimum.into(),
            targets: vec![Target::of("enclave.tar.gz", release.as_bytes())],
        };
        let mut ts = Signed::targets(&t);
        for &i in by {
            ts.sign(i, &self.m[usize::from(i)], &mut rng).unwrap();
        }
        let targets = ts.encode();
        let mut ss = Signed::snapshot(&Snapshot {
            version,
            expires: now + 90 * DAY,
            targets_version: version,
            targets_hash: sha2::Sha256::digest(&targets).into(),
        });
        ss.sign(2, &self.m[2], &mut rng).unwrap();
        let snapshot = ss.encode();
        let mut tms = Signed::timestamp(&Timestamp {
            version,
            expires: now + 7 * DAY,
            snapshot_version: version,
            snapshot_hash: sha2::Sha256::digest(&snapshot).into(),
        });
        tms.sign(2, &self.m[2], &mut rng).unwrap();
        Bundle {
            roots: Vec::new(),
            timestamp: tms.encode(),
            snapshot,
            targets,
            proofs: Vec::new(),
        }
        .encode()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn updates_come_from_the_home_server_and_a_minimum_stops_sending() {
    let net = LocalTransport::new();
    net.add_server(enclave_server::Config {
        id: S1,
        effort_request: 4,
        effort_claim: 1,
        blob_tokens_per_day: 64,
        effort_username: 1,
        ..Default::default()
    })
    .unwrap();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut ben, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ben")
        .await
        .unwrap();
    ada.add_contact(&ben.card(), "hi").await.unwrap();
    ben.sync().await.unwrap();
    ben.accept(&ada.root()).await.unwrap();
    ada.sync().await.unwrap();
    let keys = Keys::new();
    let now = enclave_net::transport::Transport::now(&net);
    let root = keys.root(now);

    // Nothing relayed yet.
    assert_eq!(ada.check_updates(&root, "0.1.0").await.unwrap(), None);

    // A newer release.
    let b1 = keys.bundle(1, "v0.2.0", "", &[0, 1], now);
    net.with_server(&S1, |s| s.set_update_bundle(b1.clone()))
        .unwrap();
    let st = ada.check_updates(&root, "0.1.0").await.unwrap().unwrap();
    assert_eq!(st.release, "v0.2.0");
    assert!(st.newer && !st.required);
    assert_eq!(st.targets.len(), 1);
    assert!(ada.update_bundle(&root).unwrap().is_some());

    // A release only one maintainer signed is refused and changes nothing.
    let forged = keys.bundle(2, "v9.0.0", "9.0.0", &[0], now);
    net.with_server(&S1, |s| s.set_update_bundle(forged))
        .unwrap();
    assert!(matches!(
        ada.check_updates(&root, "0.1.0").await,
        Err(CoreError::Update(_))
    ));
    assert_eq!(ada.update_required_since().unwrap(), None);

    // A critical fix: 0.3.0 at least. Ada stops sending at once.
    let b2 = keys.bundle(2, "v0.3.0", "0.3.0", &[0, 1], now);
    net.with_server(&S1, |s| s.set_update_bundle(b2)).unwrap();
    let st = ada.check_updates(&root, "0.1.0").await.unwrap().unwrap();
    assert!(st.required);
    let b = ben.root();
    assert!(matches!(
        ada.send_text(&b, "still here?").await,
        Err(CoreError::UpdateRequired)
    ));
    // She still receives, for 30 days.
    ben.send_text(&ada.root(), "hello").await.unwrap();
    ada.sync().await.unwrap();
    assert!(!ada.receiving_stopped().unwrap());
    net.advance(RECEIVE_GRACE);
    assert!(ada.receiving_stopped().unwrap());

    // Updated: the same release no longer holds her back.
    let st = ada.check_updates(&root, "0.3.0").await;
    // The timestamp expired while time moved on: the server must relay a
    // fresh one, as the online key signs weekly.
    assert!(matches!(st, Err(CoreError::Update(_))));
    let now = enclave_net::transport::Transport::now(&net);
    let b3 = keys.bundle(3, "v0.3.0", "0.3.0", &[0, 1], now);
    net.with_server(&S1, |s| s.set_update_bundle(b3)).unwrap();
    let st = ada.check_updates(&root, "0.3.0").await.unwrap().unwrap();
    assert!(!st.required && !st.newer);
    assert!(!ada.receiving_stopped().unwrap());
    assert_eq!(ada.update_required_since().unwrap(), None);
}
