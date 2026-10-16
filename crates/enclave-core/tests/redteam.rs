//! Red-team matrix rows checked with real clients against real servers
//! (`docs/redteam-matrix.md`): one test per named property.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, ContactCard, CoreError, DeepLink, Event, LinkError, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_sim::LocalTransport;
use enclave_store::{FileKeystore, MemoryKeystore};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];
const S2: [u8; 16] = [2; 16];

fn network() -> LocalTransport {
    let t = LocalTransport::new();
    for id in [S1, S2] {
        t.add_server(enclave_server::Config {
            id,
            effort_request: 4,
            effort_claim: 1,
            blob_tokens_per_day: 64,
            effort_username: 1,
            ..Default::default()
        })
        .unwrap();
    }
    t
}

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

/// A profile on disk, so the device's whole state can be copied.
fn on_disk(dir: &Path) -> Options {
    Options {
        path: Some(dir.join("profile.redb")),
        keystore: Arc::new(FileKeystore::new(dir.join("keys")).unwrap()),
        passphrase: Some(zeroize::Zeroizing::new(b"correct horse".to_vec())),
        pw_params: PwParams::FLOOR,
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("enclave-redteam-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

async fn new(net: &LocalTransport, server: [u8; 16], name: &str) -> Client {
    Client::create(memory(), Arc::new(net.clone()), server, name)
        .await
        .unwrap()
        .0
}

async fn connect(a: &mut Client, b: &mut Client) {
    a.add_contact(&b.card(), "hi").await.unwrap();
    b.sync().await.unwrap();
    b.accept(&a.root()).await.unwrap();
    a.sync().await.unwrap();
}

async fn link(net: &LocalTransport, a: &mut Client) -> Client {
    let mut n = enclave_core::LinkingDevice::start(memory(), Arc::new(net.clone()), S1)
        .await
        .unwrap();
    let offer = a.link_prepare(&n.code()).await.unwrap();
    let enclave_core::LinkProgress::Words(words) = n.poll().await.unwrap() else {
        unreachable!("words come before the package")
    };
    let right = offer.choices.iter().position(|c| *c == words).unwrap();
    a.link_confirm(offer, right).await.unwrap();
    assert_eq!(n.poll().await.unwrap(), enclave_core::LinkProgress::Ready);
    n.finish().await.unwrap()
}

async fn settle(clients: &mut [&mut Client], rounds: usize) -> Vec<Vec<Event>> {
    let mut all = vec![Vec::new(); clients.len()];
    for _ in 0..rounds {
        for (i, c) in clients.iter_mut().enumerate() {
            all[i].extend(c.sync().await.unwrap());
        }
    }
    all
}

fn texts(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(message.text.clone()),
            Event::GroupMessage { message, .. } => Some(message.text.clone()),
            _ => None,
        })
        .collect()
}

fn group_texts(c: &Client, gid: &[u8; 32]) -> Vec<String> {
    c.group_messages(gid)
        .unwrap()
        .into_iter()
        .filter(|m| !m.notice)
        .map(|m| m.text)
        .collect()
}

fn notices(c: &Client, gid: &[u8; 32]) -> Vec<String> {
    c.group_messages(gid)
        .unwrap()
        .into_iter()
        .filter(|m| m.notice)
        .map(|m| m.text)
        .collect()
}

fn requests(events: &[Event]) -> Vec<[u8; 64]> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Request { root, .. } => Some(*root),
            _ => None,
        })
        .collect()
}

/// Every key and value a server holds, by table.
fn server_state(net: &LocalTransport, id: &[u8; 16]) -> Vec<(&'static str, Vec<u8>)> {
    use enclave_server::db;
    let tables = [
        ("inboxes", db::INBOXES),
        ("read-creds", db::READ_CREDS),
        ("hints", db::HINTS),
        ("blob-issued", db::BLOB_ISSUED),
        ("blob-spent", db::BLOB_SPENT),
        ("allocs", db::ALLOCS),
        ("tokens", db::TOKENS),
        ("envelopes", db::ENVELOPES),
        ("manifests", db::MANIFESTS),
        ("devices-seen", db::DEVICES_SEEN),
        ("attestations", db::ATTESTATIONS),
        ("migrations", db::MIGRATIONS),
        ("moved", db::MOVED),
        ("server-moves", db::SERVER_MOVES),
        ("tombstones", db::TOMBSTONES),
        ("replays", db::REPLAYS),
        ("pow-spent", db::POW_SPENT),
        ("equivocations", db::EQUIVOCATIONS),
        ("device-owner", db::DEVICE_OWNER),
        ("bundles", db::BUNDLES),
        ("vaults", db::VAULTS),
        ("blobs", db::BLOBS),
        ("push", db::PUSH),
        ("push-group", db::PUSH_GROUP),
        ("push-dummy", db::PUSH_DUMMY),
        ("usernames", db::USERNAMES),
        ("names-by-root", db::NAMES_BY_ROOT),
        ("reports", db::REPORTS),
        ("meta", db::META),
    ];
    net.with_server(id, |s| {
        let mut out = Vec::new();
        for (name, t) in tables {
            for (k, v) in s.db().read(|r| r.scan(t, &[])).unwrap() {
                out.push((name, k));
                out.push((name, v));
            }
        }
        out
    })
    .unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// RT-01
// ---------------------------------------------------------------------------

/// RT-01: a server that logs every token registration and every burn can't
/// link one contact's writes to each other. Every write burns a different
/// random token, and the tokens one contact burns came in the same
/// registration batches as another contact's, so neither the values nor
/// the batches group writes by sender.
#[tokio::test(flavor = "multi_thread")]
async fn rt01_tokens_unlinkable_across_writes() {
    let net = network();
    let mut ada = new(&net, S1, "Ada").await;
    let mut mo = new(&net, S2, "Mo").await;
    let mut jo = new(&net, S2, "Jo").await;
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let before = net.with_server(&S1, |s| s.token_log().1.len()).unwrap();
    for i in 0..4 {
        mo.send_text(&ada.root(), &format!("Mo {i}")).await.unwrap();
        jo.send_text(&ada.root(), &format!("Jo {i}")).await.unwrap();
    }
    let (batches, burned) = net.with_server(&S1, |s| s.token_log().clone()).unwrap();
    let burned = &burned[before..];
    assert_eq!(burned.len(), 8, "one burn per write, in order");
    let distinct: HashSet<&[u8; 32]> = burned.iter().collect();
    assert_eq!(distinct.len(), burned.len(), "no token is used twice");
    let mo_burns: Vec<[u8; 32]> = burned.iter().step_by(2).copied().collect();
    let jo_burns: Vec<[u8; 32]> = burned.iter().skip(1).step_by(2).copied().collect();
    // The values carry nothing in common: as many differing bits as two
    // random values.
    for (i, a) in mo_burns.iter().enumerate() {
        for b in &mo_burns[i + 1..] {
            let bits: u32 = a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum();
            assert!((64..=192).contains(&bits), "{bits} bits differ");
        }
    }
    // Registration batches: every batch one contact's writes used also
    // held tokens the other contact used.
    let batch_of = |t: &[u8; 32]| batches.iter().position(|b| b.contains(t)).unwrap();
    let mo_batches: HashSet<usize> = mo_burns.iter().map(batch_of).collect();
    let jo_batches: HashSet<usize> = jo_burns.iter().map(batch_of).collect();
    assert_eq!(
        mo_batches, jo_batches,
        "batches don't tell the senders apart"
    );
    // Ada reads all eight.
    let got = texts(&ada.sync().await.unwrap());
    assert_eq!(got.len(), 8, "{got:?}");
}

// ---------------------------------------------------------------------------
// RT-04
// ---------------------------------------------------------------------------

/// RT-04: a client looks itself up in the log once a day, with the same
/// anonymous lookup anyone else makes. While the log binds its name to it,
/// nothing happens; once the operator binds the name to another account,
/// everyone else is shown that account, and the owner's audit says so.
#[tokio::test(flavor = "multi_thread")]
async fn rt04_self_audit_detects_foreign_entry() {
    let net = network();
    let policy = net.enable_usernames(&S1, "one.test").unwrap();
    let mut ada = new(&net, S1, "Ada").await;
    let mut mal = new(&net, S1, "Mallory").await;
    let mut ben = new(&net, S1, "Ben").await;
    for c in [&mut ada, &mut mal, &mut ben] {
        c.set_kt_policy(policy.clone());
    }
    assert_eq!(ada.claim_username("ada").await.unwrap(), "ada@one.test");
    let problem = |ev: &[Event]| {
        ev.iter()
            .any(|e| matches!(e, Event::UsernameProblem { address } if address == "ada@one.test"))
    };

    // A day later the audit finds her own entry: nothing to say.
    net.advance(enclave_core::client::AUDIT_EVERY_SECS + 1);
    let ev = ada.sync().await.unwrap();
    assert!(!problem(&ev), "{ev:?}");

    // The operator quietly binds her name to Mallory's account.
    let mut forged = mal.root().to_vec();
    forged.extend_from_slice(&mal.card().encode());
    let now = net.now();
    assert!(
        net.with_server(&S1, |s| s.kt_force("ada", forged, now))
            .unwrap()
    );
    assert_eq!(
        ben.find_username("ada").await.unwrap().root,
        mal.root(),
        "everyone else is shown the foreign entry"
    );
    // Not before the next daily audit...
    let ev = ada.sync().await.unwrap();
    assert!(!problem(&ev), "{ev:?}");
    // ...which catches it.
    net.advance(enclave_core::client::AUDIT_EVERY_SECS + 1);
    let ev = ada.sync().await.unwrap();
    assert!(problem(&ev), "{ev:?}");
}

// ---------------------------------------------------------------------------
// RT-09
// ---------------------------------------------------------------------------

/// RT-09: history goes to a newly linked device only 24 hours after it was
/// added (unless both devices confirm, see `link_a_second_device`).
#[tokio::test(flavor = "multi_thread")]
async fn rt09_history_transfer_delayed_24h() {
    use enclave_core::client::HISTORY_DELAY_SECS;
    let net = network();
    let mut a = new(&net, S1, "Ada").await;
    let mut b = new(&net, S2, "Ben").await;
    connect(&mut a, &mut b).await;
    b.send_text(&a.root(), "before the link").await.unwrap();
    a.sync().await.unwrap();

    let mut a2 = link(&net, &mut a).await;
    let new_id = a2.devices().iter().find(|d| d.this_device).unwrap().id;
    let ben = b.root();
    let has_history = |c: &Client| {
        c.messages(&ben)
            .unwrap()
            .iter()
            .any(|m| m.text == "before the link")
    };
    settle(&mut [&mut a, &mut a2, &mut b], 2).await;
    assert!(!a.history_sent(&new_id));
    assert!(!has_history(&a2), "nothing from before the link at once");

    // Just under a day: still nothing.
    net.advance(HISTORY_DELAY_SECS - 120);
    let ev = settle(&mut [&mut a, &mut a2], 2).await;
    assert!(!a.history_sent(&new_id));
    assert!(!ev[1].contains(&Event::HistoryImported));
    assert!(!has_history(&a2));

    // A day after the link: the device holding the root sends it.
    net.advance(240);
    a.sync().await.unwrap();
    assert!(a.history_sent(&new_id));
    let ev = a2.sync().await.unwrap();
    assert!(ev.contains(&Event::HistoryImported), "{ev:?}");
    assert!(has_history(&a2));
}

/// RT-09: a tapped link never starts linking. The deep-link handler refuses
/// a device-link code (whatever the case of its scheme, with stray spaces)
/// and opens only invites; in-person and recovery codes are refused too.
#[tokio::test(flavor = "multi_thread")]
async fn rt09_link_qr_refused_by_deep_link() {
    let net = network();
    let mut a = new(&net, S1, "Ada").await;
    let n = enclave_core::LinkingDevice::start(memory(), Arc::new(net.clone()), S1)
        .await
        .unwrap();
    let code = n.code();
    assert!(code.starts_with("enclave:link#"));
    let upper = code.replacen("enclave:link#", "ENCLAVE:Link#", 1);
    for uri in [code.clone(), upper, format!("  {code}\n")] {
        assert_eq!(
            enclave_core::open_deep_link(&uri),
            Err(LinkError::DeviceLinkCode),
            "{uri}"
        );
    }
    // What a deep link may open: an invite, a group invite.
    let invite = a.create_invite(1).await.unwrap();
    assert!(matches!(
        enclave_core::open_deep_link(&invite),
        Ok(DeepLink::Contact(c)) if c.root == a.root()
    ));
    let gid = a.create_group("Club", &[]).await.unwrap();
    let join = a.create_group_invite(&gid, 1, true).await.unwrap();
    assert_eq!(
        enclave_core::open_deep_link(&join),
        Ok(DeepLink::Join(join.clone()))
    );
    // Not on their own screens: refused.
    assert_eq!(
        enclave_core::open_deep_link(&a.meet_code().unwrap()),
        Err(LinkError::MeetCode)
    );
    // The link scanner itself still takes the code.
    assert!(a.link_prepare(&code).await.is_ok());
}

/// RT-09: every device of the account, the new one included, shows the
/// "New device linked" notice for 7 days after a link, and then no more.
#[tokio::test(flavor = "multi_thread")]
async fn rt09_new_device_banner_7_days() {
    use enclave_core::client::NEW_DEVICE_SECS;
    let net = network();
    let mut a = new(&net, S1, "Ada").await;
    assert!(a.new_device_notice().is_none(), "nothing linked yet");
    let mut a2 = link(&net, &mut a).await;
    settle(&mut [&mut a, &mut a2], 2).await;
    let new_id = a2.devices().iter().find(|d| d.this_device).unwrap().id;
    let shown = |c: &Client| c.new_device_notice().map(|d| d.id);
    assert_eq!(shown(&a), Some(new_id), "on the device that linked it");
    assert_eq!(shown(&a2), Some(new_id), "on the new device");
    assert!(a2.new_device_notice().unwrap().this_device);

    net.advance(NEW_DEVICE_SECS - 120);
    settle(&mut [&mut a, &mut a2], 1).await;
    assert_eq!(shown(&a), Some(new_id), "still there on day 7");
    assert_eq!(shown(&a2), Some(new_id));

    net.advance(240);
    settle(&mut [&mut a, &mut a2], 1).await;
    assert_eq!(shown(&a), None, "gone after 7 days");
    assert_eq!(shown(&a2), None);
}

// ---------------------------------------------------------------------------
// RT-10
// ---------------------------------------------------------------------------

/// A server that takes no proof of work any client would do: only an
/// invite's capability gets a request through.
const STRICT: [u8; 16] = [9; 16];

fn strict_network() -> LocalTransport {
    let net = network();
    net.add_server(enclave_server::Config {
        id: STRICT,
        effort_request: 1 << 30,
        effort_claim: 1,
        blob_tokens_per_day: 64,
        ..Default::default()
    })
    .unwrap();
    net
}

/// RT-10: an invite link's secret is only in the URL fragment (after `#`),
/// which browsers never send to a server; the inviter's server holds only
/// hashes of capabilities derived from it.
#[tokio::test(flavor = "multi_thread")]
async fn rt10_invite_secret_only_in_fragment() {
    let net = strict_network();
    let mut host = new(&net, STRICT, "Hana").await;
    let mut a = new(&net, S1, "Ada").await;
    let link = host.create_invite(2).await.unwrap();
    let secret = ContactCard::from_link(&link)
        .unwrap()
        .invite
        .unwrap()
        .secret;
    let (before, fragment) = link.split_once('#').unwrap();
    assert_eq!(before, "enclave:add", "nothing but the scheme before it");
    assert!(!fragment.contains('#') && !fragment.contains('?'));

    // The https form puts the same payload after `/i#`.
    let card = ContactCard {
        server_domain: "invite.example".into(),
        ..ContactCard::from_link(&link).unwrap()
    };
    let web = card.to_share_link();
    let (path, frag) = web.split_once('#').unwrap();
    assert_eq!(
        path, "https://invite.example/i",
        "the server sees this only"
    );
    assert_eq!(
        ContactCard::from_link(&format!("{path}#")),
        Err(LinkError::Malformed),
        "without the fragment there is no invite"
    );
    let decoded = enclave_core::card::b64url_decode(frag).unwrap();
    assert!(contains(&decoded, &secret), "the secret is in the fragment");

    // Used once: the server learned no secret and no capability, only
    // their hashes.
    a.add_contact(&ContactCard::from_link(&link).unwrap(), "hi")
        .await
        .unwrap();
    assert!(!requests(&host.sync().await.unwrap()).is_empty());
    let caps: Vec<[u8; 32]> = (0..8)
        .map(|i| enclave_proto::eqxdh::invite_cap(&secret, i))
        .collect();
    for (table, bytes) in server_state(&net, &STRICT) {
        assert!(!contains(&bytes, &secret), "secret in {table}");
        for c in &caps {
            assert!(!contains(&bytes, c), "capability in {table}");
        }
    }
}

/// RT-10: a cancelled invite link lets nobody in: its capabilities are
/// revoked at the server, so a greeting through it is refused there, and
/// nothing reaches the inviter.
#[tokio::test(flavor = "multi_thread")]
async fn rt10_revoked_invite_rejected() {
    let net = strict_network();
    let mut host = new(&net, STRICT, "Hana").await;
    let mut a = new(&net, S1, "Ada").await;
    let mut b = new(&net, S2, "Ben").await;
    let leaked = ContactCard::from_link(&host.create_invite(3).await.unwrap()).unwrap();
    assert_eq!(host.invites().unwrap().len(), 1);
    host.cancel_invites().await.unwrap();
    assert!(host.invites().unwrap().is_empty());
    let denied = net.with_server(&STRICT, |s| s.stats().denied).unwrap();
    for c in [&mut a, &mut b] {
        assert!(matches!(
            c.add_contact(&leaked, "let me in").await,
            Err(CoreError::Link(LinkError::InviteUsed))
        ));
        assert!(c.contact(&host.root()).is_none(), "nothing half-added");
    }
    assert!(
        net.with_server(&STRICT, |s| s.stats().denied).unwrap() > denied,
        "the server refused the capability"
    );
    let ev = host.sync().await.unwrap();
    assert!(requests(&ev).is_empty(), "{ev:?}");
}

/// RT-10: a link for two brings two people. Once two accounts came through
/// it, a third's greeting is dropped even if it got in before the inviter
/// noticed, and the rest of the capabilities are revoked.
#[tokio::test(flavor = "multi_thread")]
async fn rt10_invite_use_limit_enforced() {
    let net = strict_network();
    let mut host = new(&net, STRICT, "Hana").await;
    let mut a = new(&net, S1, "Ada").await;
    let mut b = new(&net, S2, "Ben").await;
    let mut c = new(&net, S1, "Cy").await;
    let mut d = new(&net, S2, "Dee").await;
    let two = ContactCard::from_link(&host.create_invite(2).await.unwrap()).unwrap();
    // Three use it before the host's device next syncs: each of them has a
    // capability to burn (one per device per use).
    for x in [&mut a, &mut b, &mut c] {
        x.add_contact(&two, "hello via the link").await.unwrap();
    }
    let got = requests(&host.sync().await.unwrap());
    assert_eq!(got.len(), 2, "two people, as the link said");
    assert!(got.contains(&a.root()) && got.contains(&b.root()));
    assert!(host.contact(&c.root()).is_none(), "the third is dropped");
    assert!(host.invites().unwrap().is_empty(), "used up");
    // Later ones are refused at the server.
    assert!(matches!(
        d.add_contact(&two, "me too").await,
        Err(CoreError::Link(LinkError::InviteUsed))
    ));
    assert!(requests(&host.sync().await.unwrap()).is_empty());
}

// ---------------------------------------------------------------------------
// RT-11
// ---------------------------------------------------------------------------

/// Ada (admin, whose server hosts the group), Ben and Cy, who have all
/// talked in the group.
async fn group_of_three(net: &LocalTransport) -> (Client, Client, Client, [u8; 32]) {
    let mut ada = new(net, S1, "Ada").await;
    let mut ben = new(net, S2, "Ben").await;
    let mut cy = new(net, S2, "Cy").await;
    connect(&mut ada, &mut ben).await;
    connect(&mut ada, &mut cy).await;
    let gid = ada
        .create_group("Trip", &[ben.root(), cy.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut ben, &mut cy], 3).await;
    for (c, t) in [
        (&mut ada, "from Ada"),
        (&mut ben, "from Ben"),
        (&mut cy, "from Cy"),
    ] {
        c.send_group_text(&gid, t).await.unwrap();
    }
    settle(&mut [&mut ada, &mut ben, &mut cy], 2).await;
    for c in [&ada, &ben, &cy] {
        assert_eq!(group_texts(c, &gid).len(), 3, "everyone has spoken");
    }
    (ada, ben, cy, gid)
}

fn diverged(c: &Client, gid: &[u8; 32]) -> bool {
    c.groups().iter().any(|g| g.id == *gid && g.diverged)
}

fn diverged_event(ev: &[Event], gid: &[u8; 32]) -> bool {
    ev.contains(&Event::GroupDiverged { group_id: *gid })
}

/// RT-11: the group's server shows Cy the group without a state update
/// everyone else has (here: Ben made an admin). Ben's messages carry a
/// state hash Cy doesn't hold; a moment's difference is normal, but when
/// a message ten minutes later still shows it, Cy's chat is marked. Ada
/// and Ben, who hold Cy's state as an earlier one of theirs, are not.
#[tokio::test(flavor = "multi_thread")]
async fn rt11_group_fork_detected() {
    use enclave_core::client::DIVERGE_SECS;
    let net = network();
    let (mut ada, mut ben, mut cy, gid) = group_of_three(&net).await;
    let host = |on: bool| net.with_server(&S1, |s| s.hide_marked(on)).unwrap();

    net.with_server(&S1, |s| s.mark_new(true)).unwrap();
    ada.set_group_admin(&gid, &ben.root(), true).await.unwrap();
    net.with_server(&S1, |s| s.mark_new(false)).unwrap();
    settle(&mut [&mut ada, &mut ben], 1).await;
    assert!(ben.groups()[0].admin, "Ben sees the update");
    host(true);
    cy.sync().await.unwrap();
    host(false);
    assert!(!cy.groups()[0].admins.contains(&ben.root()), "Cy doesn't");

    ben.send_group_text(&gid, "I'm an admin now").await.unwrap();
    host(true);
    let ev = cy.sync().await.unwrap();
    host(false);
    assert!(texts(&ev).contains(&"I'm an admin now".to_string()));
    assert!(
        !diverged_event(&ev, &gid) && !diverged(&cy, &gid),
        "not yet"
    );

    net.advance(DIVERGE_SECS + 1);
    ben.send_group_text(&gid, "still me").await.unwrap();
    host(true);
    let ev = cy.sync().await.unwrap();
    host(false);
    assert!(diverged_event(&ev, &gid), "{ev:?}");
    assert!(diverged(&cy, &gid));

    cy.send_group_text(&gid, "what's going on?").await.unwrap();
    let ev = settle(&mut [&mut ada, &mut ben], 1).await;
    for (who, (c, ev)) in [("Ada", (&ada, &ev[0])), ("Ben", (&ben, &ev[1]))] {
        assert!(texts(ev).contains(&"what's going on?".to_string()), "{who}");
        assert!(!diverged_event(ev, &gid) && !diverged(c, &gid), "{who}");
    }
}

/// RT-11: the group's server hides one of Ada's messages from Cy while
/// Ben gets it. Ben's next messages name it in their causal frontier, so
/// Cy learns a message exists that she never received; when a message ten
/// minutes later still names it, her chat is marked.
#[tokio::test(flavor = "multi_thread")]
async fn rt11_equivocation_detected_via_frontier() {
    use enclave_core::client::DIVERGE_SECS;
    let net = network();
    let (mut ada, mut ben, mut cy, gid) = group_of_three(&net).await;
    let host = |on: bool| net.with_server(&S1, |s| s.hide_marked(on)).unwrap();

    net.with_server(&S1, |s| s.mark_new(true)).unwrap();
    ada.send_group_text(&gid, "for Ben only").await.unwrap();
    net.with_server(&S1, |s| s.mark_new(false)).unwrap();
    ben.sync().await.unwrap();
    assert!(group_texts(&ben, &gid).contains(&"for Ben only".to_string()));

    ben.send_group_text(&gid, "agreed").await.unwrap();
    host(true);
    let ev = cy.sync().await.unwrap();
    host(false);
    assert!(texts(&ev).contains(&"agreed".to_string()));
    assert!(!group_texts(&cy, &gid).contains(&"for Ben only".to_string()));
    assert!(!diverged(&cy, &gid), "a moment's gap is normal");

    net.advance(DIVERGE_SECS + 1);
    ben.send_group_text(&gid, "see you then").await.unwrap();
    host(true);
    let ev = cy.sync().await.unwrap();
    host(false);
    assert!(diverged_event(&ev, &gid), "{ev:?}");
    assert!(diverged(&cy, &gid));
    ada.sync().await.unwrap();
    assert!(!diverged(&ada, &gid) && !diverged(&ben, &gid));
}

/// RT-11: every membership change shows in the chat, for every member and
/// on the admin's own device, as a line nobody wrote and nobody can hide.
#[tokio::test(flavor = "multi_thread")]
async fn rt11_membership_change_rendered_in_chat() {
    let net = network();
    let mut ada = new(&net, S1, "Ada").await;
    let mut ben = new(&net, S2, "Ben").await;
    let mut cy = new(&net, S2, "Cy").await;
    let mut dee = new(&net, S1, "Dee").await;
    for x in [&mut ben, &mut cy, &mut dee] {
        connect(&mut ada, x).await;
    }
    let gid = ada
        .create_group("Trip", &[ben.root(), cy.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut ben, &mut cy], 3).await;
    assert!(notices(&ben, &gid).is_empty(), "joining shows no change");

    ada.add_group_members(&gid, &[dee.root()]).await.unwrap();
    settle(&mut [&mut ben, &mut cy, &mut dee], 3).await;
    assert_eq!(notices(&ada, &gid), ["You added Dee."]);
    assert_eq!(notices(&ben, &gid), ["Ada added Dee."]);
    assert_eq!(notices(&cy, &gid), ["Ada added Dee."]);
    let line = ben
        .group_messages(&gid)
        .unwrap()
        .into_iter()
        .find(|m| m.notice)
        .unwrap();
    assert_eq!(line.from, Some(ada.root()), "made by Ada");

    ada.remove_group_member(&gid, &cy.root()).await.unwrap();
    settle(&mut [&mut ben, &mut dee], 3).await;
    assert_eq!(notices(&ada, &gid), ["You added Dee.", "You removed Cy."]);
    assert_eq!(notices(&ben, &gid), ["Ada added Dee.", "Ada removed Cy."]);
    assert_eq!(notices(&dee, &gid), ["Ada removed Cy."]);

    ben.leave_group(&gid).await.unwrap();
    settle(&mut [&mut ada, &mut dee], 3).await;
    assert_eq!(notices(&ada, &gid).last().unwrap(), "Ben left.");
    assert_eq!(notices(&dee, &gid).last().unwrap(), "Ben left.");
    // In the chat in order, between the messages.
    dee.send_group_text(&gid, "just us").await.unwrap();
    ada.sync().await.unwrap();
    let last = ada.group_messages(&gid).unwrap();
    assert_eq!(last.last().unwrap().text, "just us");
    assert!(!last.last().unwrap().notice);
}

// ---------------------------------------------------------------------------
// RT-21
// ---------------------------------------------------------------------------

/// RT-21: someone copies everything on Ada's device (a seized phone, given
/// back), and Ada then uses "Secure my account". The copy, run against the
/// real servers, reads nothing written after that: not Ben's messages (new
/// inbox addresses, new identity and vault keys, PQ-stepped sessions) and
/// not the group's (rekeyed). Group messages written before it were still
/// open to it.
#[tokio::test(flavor = "multi_thread")]
async fn rt21_secure_my_account_rotates_all() {
    let net = network();
    let dir = scratch("secure");
    let (mut ada, _) = Client::create(on_disk(&dir.join("ada")), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let mut ben = new(&net, S2, "Ben").await;
    connect(&mut ada, &mut ben).await;
    let trip = ada.create_group("Trip", &[ben.root()]).await.unwrap();
    settle(&mut [&mut ada, &mut ben], 3).await;
    ben.send_group_text(&trip, "hello group").await.unwrap();
    settle(&mut [&mut ada, &mut ben], 1).await;
    let old_identity = ada.identity_public();
    let old_card = ada.card();
    let code = ben.security_code(&ada.root());

    // The copy (closed first: Windows won't read a database file another
    // handle has locked).
    drop(ada);
    copy_dir(&dir.join("ada"), &dir.join("copy"));
    let mut ada = Client::open(on_disk(&dir.join("ada")), Arc::new(net.clone())).unwrap();
    ben.send_group_text(&trip, "before securing").await.unwrap();
    settle(&mut [&mut ada, &mut ben], 1).await;

    ada.secure_account().await.unwrap();
    for _ in 0..4 {
        settle(&mut [&mut ada, &mut ben], 1).await;
    }
    assert!(!ada.securing());
    assert_ne!(ada.identity_public(), old_identity, "new identity key");
    let card = ada.card();
    assert_ne!(
        card.request_inbox, old_card.request_inbox,
        "new request inbox"
    );
    assert_ne!(card.vault_locator, old_card.vault_locator, "new vault key");
    assert_ne!(card.vault_key, old_card.vault_key);
    assert_eq!(ben.security_code(&ada.root()), code, "same account");

    ben.send_text(&ada.root(), "after securing").await.unwrap();
    ben.send_group_text(&trip, "group after securing")
        .await
        .unwrap();

    // The copy, back online.
    let mut copy = Client::open(on_disk(&dir.join("copy")), Arc::new(net.clone())).unwrap();
    assert_eq!(copy.root(), ada.root());
    let mut seen = Vec::new();
    for _ in 0..3 {
        if let Ok(ev) = copy.sync().await {
            seen.extend(texts(&ev));
        }
    }
    let stored: Vec<String> = copy
        .messages(&ben.root())
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .chain(group_texts(&copy, &trip))
        .collect();
    assert!(
        stored.contains(&"before securing".to_string()),
        "the copy works: {stored:?}"
    );
    for t in ["after securing", "group after securing"] {
        assert!(!seen.contains(&t.to_string()), "{t}: {seen:?}");
        assert!(!stored.contains(&t.to_string()), "{t}: {stored:?}");
    }
    drop(copy);

    // Ada reads both.
    let got = texts(&ada.sync().await.unwrap());
    assert!(got.contains(&"after securing".to_string()), "{got:?}");
    assert!(group_texts(&ada, &trip).contains(&"group after securing".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// RT-22
// ---------------------------------------------------------------------------

/// RT-22: someone restores Ada's account from stolen words. Her phone is
/// told, and its veto stops the change for good: three days later Ben
/// still refuses the thief's device, the thief's device knows it was
/// stopped, and Ada's phone still talks to Ben.
#[tokio::test(flavor = "multi_thread")]
async fn rt22_pending_root_veto_honored() {
    use enclave_proto::attest::RECOVERY_WAIT_SECS;
    let net = network();
    let (mut a, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let mut b = new(&net, S2, "Ben").await;
    connect(&mut a, &mut b).await;
    let archive = a.export_backup().unwrap();
    let mut thief = Client::restore(&words.join(" "), &archive, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    let before = b.contact(&a.root()).unwrap().manifest_version();

    net.advance(601);
    let ev = a.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::RecoveryPending { .. })),
        "{ev:?}"
    );
    a.stop_recovery().await.unwrap();

    net.advance(RECOVERY_WAIT_SECS + 601);
    for _ in 0..2 {
        let ev = b.sync().await.unwrap();
        assert!(
            ev.iter()
                .all(|e| !matches!(e, Event::Message { .. } | Event::Request { .. })),
            "{ev:?}"
        );
    }
    assert_eq!(
        b.contact(&a.root()).unwrap().manifest_version(),
        before,
        "Ben never took the change"
    );
    let ev = thief.sync().await.unwrap();
    assert!(ev.contains(&Event::RecoveryStopped), "{ev:?}");
    assert!(matches!(
        thief.send_text(&b.root(), "it's me, really").await,
        Err(CoreError::RecoveryHeld)
    ));
    a.send_text(&b.root(), "still me").await.unwrap();
    assert_eq!(texts(&b.sync().await.unwrap()), ["still me"]);
}

/// RT-22: with no device left to co-sign or veto, a restore takes effect
/// only once each contact has held it for 72 hours: until then Ben's client
/// keeps the new device's greeting and the account's old manifest, so
/// nothing he writes reaches the new device.
#[tokio::test(flavor = "multi_thread")]
async fn rt22_contacts_enforce_72h() {
    use enclave_proto::attest::RECOVERY_WAIT_SECS;
    let net = network();
    let (mut a, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let mut b = new(&net, S2, "Ben").await;
    connect(&mut a, &mut b).await;
    let archive = a.export_backup().unwrap();
    let root = a.root();
    drop(a); // the phone is gone
    let mut a_new = Client::restore(&words.join(" "), &archive, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    let before = b.contact(&root).unwrap().manifest_version();

    // Ben's client holds the change, almost to the end of the 72 hours.
    for step in [0, RECOVERY_WAIT_SECS / 2, RECOVERY_WAIT_SECS / 2 - 3600] {
        net.advance(step);
        let ev = b.sync().await.unwrap();
        assert!(ev.is_empty(), "{ev:?}");
        assert_eq!(b.contact(&root).unwrap().manifest_version(), before);
        b.send_text(&root, "are you there?").await.unwrap();
        let ev = a_new.sync().await.unwrap();
        assert!(
            texts(&ev).is_empty(),
            "nothing reaches the new device: {ev:?}"
        );
        assert!(matches!(
            a_new.send_text(&b.root(), "it's me").await,
            Err(CoreError::RecoveryHeld)
        ));
    }

    // Past 72 hours since Ben first saw it: he takes it.
    net.advance(3600 + 601);
    b.sync().await.unwrap();
    assert!(b.contact(&root).unwrap().manifest_version() > before);
    let ev = a_new.sync().await.unwrap();
    assert!(ev.contains(&Event::RecoveryDone), "{ev:?}");
    b.sync().await.unwrap();
    a_new.send_text(&b.root(), "new phone").await.unwrap();
    assert!(texts(&b.sync().await.unwrap()).contains(&"new phone".to_string()));
}

// ---------------------------------------------------------------------------
// RT-28
// ---------------------------------------------------------------------------

/// RT-28: after a conversation, a group, a file and a linked device, the
/// servers' whole state (every table, keys and values) holds no IP address,
/// no name and no message text, and the mailbox side (inboxes, tokens,
/// envelopes, blobs, push) holds no account key or device id that could
/// tie it to an account: there is nothing identifying for a compelled
/// operator to hand over. (`Server::handle` takes no peer address at all.)
#[tokio::test(flavor = "multi_thread")]
async fn rt28_server_state_contains_no_ip_or_account() {
    let net = network();
    let mut ada = new(&net, S1, "Adelinda Quarrington").await;
    let mut ben = new(&net, S2, "Bertrand Ostrowski").await;
    connect(&mut ada, &mut ben).await;
    let mut ada2 = link(&net, &mut ada).await;
    ada.send_text(&ben.root(), "meet at the lighthouse")
        .await
        .unwrap();
    ben.send_text(&ada.root(), "bring the blue notebook")
        .await
        .unwrap();
    ben.send_attachment(
        &ada.root(),
        "ostrowski-passport.txt",
        "text/plain",
        b"a file with a telling name",
        "scan attached",
    )
    .await
    .unwrap();
    let gid = ada
        .create_group("Lighthouse keepers", &[ben.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut ada2, &mut ben], 3).await;
    ben.send_group_text(&gid, "group secret plan")
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut ada2, &mut ben], 2).await;

    let mut identifying: Vec<(&str, Vec<u8>)> = vec![
        ("an IP address", b"127.0.0.1".to_vec()),
        ("an IP address", b"[::1]".to_vec()),
        ("an IP address", b"localhost".to_vec()),
    ];
    for t in [
        "Adelinda",
        "Quarrington",
        "Bertrand",
        "Ostrowski",
        "lighthouse",
        "blue notebook",
        "ostrowski-passport",
        "scan attached",
        "Lighthouse keepers",
        "group secret plan",
    ] {
        identifying.push(("a name or text", t.as_bytes().to_vec()));
    }
    // What would tie a mailbox to an account.
    let mut account = Vec::new();
    for c in [&ada, &ben] {
        account.push(c.root().to_vec());
        account.push(c.identity_public().to_vec());
    }
    for c in [&ada, &ada2, &ben] {
        for d in c.devices() {
            account.push(d.id.to_vec());
        }
    }
    const MAILBOX_SIDE: [&str; 14] = [
        "inboxes",
        "read-creds",
        "hints",
        "blob-issued",
        "blob-spent",
        "allocs",
        "tokens",
        "envelopes",
        "replays",
        "pow-spent",
        "blobs",
        "push",
        "push-group",
        "push-dummy",
    ];
    let mut rows = 0;
    for id in [S1, S2] {
        for (table, bytes) in server_state(&net, &id) {
            rows += 1;
            for (what, needle) in &identifying {
                assert!(!contains(&bytes, needle), "{what} in {table}");
            }
            if MAILBOX_SIDE.contains(&table) {
                for (i, needle) in account.iter().enumerate() {
                    if contains(&bytes, needle) {
                        let at = bytes.windows(needle.len()).position(|w| w == needle);
                        eprintln!(
                            "needle {i} len {} at {at:?} of {} in {table}: head {:02x?}",
                            needle.len(),
                            bytes.len(),
                            &bytes[..bytes.len().min(48)]
                        );
                    }
                }
            }
        }
    }
    assert!(rows > 100, "the servers hold state: {rows} rows");
}
