//! Red-team matrix rows for the app's engine (`docs/redteam-matrix.md`),
//! in demo mode.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::{Cmd, Out, Snapshot};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

async fn snapshot(rx: &mut UnboundedReceiver<Out>, want: impl Fn(&Snapshot) -> bool) -> Snapshot {
    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if let Out::Snapshot(s) = rx.recv().await.expect("engine running")
                && want(&s)
            {
                return *s;
            }
        }
    })
    .await
    .expect("in time")
}

/// RT-09: a device-link code scanned with the general scanner (or pasted
/// into Add) is refused with the warning of `03-identity.md` §4.2, and
/// adds no one, whatever the case of its scheme.
#[tokio::test(flavor = "multi_thread")]
async fn rt09_link_qr_refused_by_general_scanner() {
    const WARNING: &str = "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one.";
    let (tx, mut rx) = enclave_vault::spawn(enclave_vault::Mode::Demo);
    tx.send(Cmd::Create("Robin".into(), String::new())).unwrap();
    let s = snapshot(&mut rx, |s| !s.requests.is_empty()).await;
    let contacts = s.contacts.len();
    let code = enclave_core::LinkCode {
        server: [1; 16],
        mailbox: [2; 32],
        owner: [3; 32],
        x448: [4; 56],
        secret: [5; 32],
        commit: [6; 32],
    }
    .to_link();
    assert!(code.starts_with("enclave:link#"));
    let shouting = code.replacen("enclave:link#", "ENCLAVE:LINK#", 1);
    for scanned in [code.clone(), shouting, format!(" {code}\n")] {
        tx.send(Cmd::Add(scanned.clone(), "hello".into())).unwrap();
        // The engine clears the field's error and works on it, then
        // answers.
        snapshot(&mut rx, |s| s.busy && s.add_error.is_empty()).await;
        let s = snapshot(&mut rx, |s| !s.busy).await;
        assert_eq!(s.add_error, WARNING, "{scanned:?}");
        assert_eq!(s.contacts.len(), contacts, "nobody added");
    }
}
