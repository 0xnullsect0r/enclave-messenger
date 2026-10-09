//! Two real clients, two real servers, one process.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, ContactCard, ContactState, CoreError, Event, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_sim::LocalTransport;
use enclave_store::{FileKeystore, MemoryKeystore};
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
            effort_blob: 1,
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

#[tokio::test(flavor = "multi_thread")]
async fn request_accept_chat_refill_and_reopen() {
    let net = network();
    let dir = std::env::temp_dir().join(format!("enclave-core-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bob_opts = || Options {
        path: Some(dir.join("bob.redb")),
        keystore: Arc::new(FileKeystore::new(dir.join("keys")).unwrap()),
        passphrase: Some(zeroize::Zeroizing::new(b"hunter2 hunter2".to_vec())),
        pw_params: PwParams::FLOOR,
    };

    let (mut alice, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Alice")
        .await
        .unwrap();
    assert_eq!(words.len(), 24);
    assert_eq!(alice.recovery_words().unwrap(), words);
    let (mut bob, _) = Client::create(bob_opts(), Arc::new(net.clone()), S2, "Bob")
        .await
        .unwrap();

    // Alice scans Bob's code.
    let card = ContactCard::from_link(&bob.card().to_link()).unwrap();
    assert!(matches!(
        alice.add_contact(&alice.card(), "me").await,
        Err(CoreError::Link(enclave_core::LinkError::OwnCode))
    ));
    alice
        .add_contact(&card, "Hi Bob, it's Alice")
        .await
        .unwrap();
    assert_eq!(
        alice.contact(&bob.root()).unwrap().state,
        ContactState::Pending
    );
    assert!(matches!(
        alice.send_text(&bob.root(), "again?").await,
        Err(CoreError::NotAccepted)
    ));

    // Bob sees a message request, and cannot reply before accepting.
    let ev = bob.sync().await.unwrap();
    assert_eq!(
        ev,
        vec![Event::Request {
            root: alice.root(),
            name: "Alice".into(),
            text: "Hi Bob, it's Alice".into()
        }]
    );
    assert!(matches!(
        bob.send_text(&alice.root(), "hey").await,
        Err(CoreError::NotAccepted)
    ));
    assert!(
        bob.sync().await.unwrap().is_empty(),
        "the request is not processed twice"
    );
    bob.accept(&alice.root()).await.unwrap();

    let ev = alice.sync().await.unwrap();
    assert_eq!(ev, vec![Event::Accepted { root: bob.root() }]);
    assert_eq!(alice.contact(&bob.root()).unwrap().name, "Bob");
    assert_eq!(
        alice.security_code(&bob.root()),
        bob.security_code(&alice.root())
    );

    // Conversation.
    bob.send_text(&alice.root(), "Hi Alice").await.unwrap();
    let ev = alice.sync().await.unwrap();
    assert!(matches!(&ev[..], [Event::Message { message, .. }] if message.text == "Hi Alice"));
    alice.send_text(&bob.root(), "How are you?").await.unwrap();
    bob.sync().await.unwrap();
    bob.send_text(&alice.root(), "Well, thanks").await.unwrap();
    alice.sync().await.unwrap();
    assert!(
        alice.fully_protected(&bob.root()),
        "PQ-authenticated, three KEMs"
    );
    assert!(bob.fully_protected(&alice.root()));

    // A monologue longer than the hello tokens: Bob refills during sync.
    for i in 0..14 {
        alice
            .send_text(&bob.root(), &format!("monologue {i}"))
            .await
            .unwrap();
    }
    // Fourteen messages (and Alice's delivery receipt for Bob's last one,
    // which rode on the first of them).
    let messages = |ev: &[Event]| {
        ev.iter()
            .filter(|e| matches!(e, Event::Message { .. }))
            .count()
    };
    let ev = bob.sync().await.unwrap();
    assert_eq!(messages(&ev), 14, "{ev:?}");
    alice.sync().await.unwrap();
    for i in 0..10 {
        alice
            .send_text(&bob.root(), &format!("still talking {i}"))
            .await
            .unwrap();
    }

    // Bob's app restarts: everything comes back from the sealed store.
    let alice_root = alice.root();
    drop(bob);
    let wrong = Options {
        passphrase: Some(zeroize::Zeroizing::new(b"wrong".to_vec())),
        ..bob_opts()
    };
    assert!(Client::open(wrong, Arc::new(net.clone())).is_err());
    let mut bob = Client::open(bob_opts(), Arc::new(net.clone())).unwrap();
    let ev = bob.sync().await.unwrap();
    assert_eq!(messages(&ev), 10, "{ev:?}");
    let history = bob.messages(&alice_root).unwrap();
    assert_eq!(history.len(), 1 + 1 + 1 + 1 + 14 + 10);
    assert!(history.windows(2).all(|w| w[0].seq < w[1].seq));
    assert_eq!(bob.contact(&alice_root).unwrap().unread, 1 + 14 + 10 + 1);
    bob.send_text(&alice_root, "back after a restart")
        .await
        .unwrap();
    // (with Bob's delivery receipts riding on it)
    let ev = alice.sync().await.unwrap();
    assert_eq!(messages(&ev), 1, "{ev:?}");
    assert!(ev.iter().any(
        |e| matches!(e, Event::Message { message, .. } if message.text == "back after a restart")
    ));

    // Verification and removal.
    bob.set_verified(&alice_root, true).unwrap();
    assert!(bob.contact(&alice_root).unwrap().verified);
    bob.remove_contact(&alice_root).unwrap();
    assert!(bob.contacts().is_empty());
    assert!(bob.messages(&alice_root).unwrap().is_empty());
    bob.erase().unwrap();
    assert!(
        Client::open(bob_opts(), Arc::new(net)).is_err(),
        "crypto-erased"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_adds_become_one_conversation() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "A")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S1, "B")
        .await
        .unwrap();
    a.add_contact(&b.card(), "hi from a").await.unwrap();
    b.add_contact(&a.card(), "hi from b").await.unwrap();
    let ea = a.sync().await.unwrap();
    let eb = b.sync().await.unwrap();
    assert!(ea.contains(&Event::Accepted { root: b.root() }));
    assert!(eb.contains(&Event::Accepted { root: a.root() }));
    a.send_text(&b.root(), "so, both of us").await.unwrap();
    let eb = b.sync().await.unwrap();
    assert!(
        eb.iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "so, both of us")
        )
    );
}

async fn connect(a: &mut Client, b: &mut Client) {
    a.add_contact(&b.card(), "hi").await.unwrap();
    b.sync().await.unwrap();
    b.accept(&a.root()).await.unwrap();
    a.sync().await.unwrap();
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

fn group_texts(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::GroupMessage { message, .. } => Some(message.text.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn group_of_three_where_two_are_strangers() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    let (mut c, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Cy")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    connect(&mut a, &mut c).await;

    let gid = a.create_group("Trip", &[b.root(), c.root()]).await.unwrap();
    let ev = settle(&mut [&mut b, &mut c], 1).await;
    assert!(ev[0].contains(&Event::GroupJoined {
        group_id: gid,
        name: "Trip".into()
    }));
    assert!(ev[1].contains(&Event::GroupJoined {
        group_id: gid,
        name: "Trip".into()
    }));
    // B and C introduce themselves through the group; no message requests.
    let ev = settle(&mut [&mut a, &mut b, &mut c], 3).await;
    assert!(
        ev.iter()
            .flatten()
            .all(|e| !matches!(e, Event::Request { .. }))
    );
    assert!(
        b.contacts().iter().all(|x| x.root != c.root()),
        "group-only contacts stay out of the list"
    );
    assert_eq!(b.groups()[0].members.len(), 2);

    a.send_group_text(&gid, "Train at 9?").await.unwrap();
    b.send_group_text(&gid, "Works for me").await.unwrap();
    c.send_group_text(&gid, "Same").await.unwrap();
    let ev = settle(&mut [&mut a, &mut b, &mut c], 3).await;
    let mut got_a = group_texts(&ev[0]);
    let mut got_b = group_texts(&ev[1]);
    let mut got_c = group_texts(&ev[2]);
    got_a.sort();
    got_b.sort();
    got_c.sort();
    assert_eq!(got_a, vec!["Same", "Works for me"]);
    assert_eq!(got_b, vec!["Same", "Train at 9?"]);
    assert_eq!(got_c, vec!["Train at 9?", "Works for me"]);
    let hist = b.group_messages(&gid).unwrap();
    assert_eq!(hist.len(), 3);
    assert!(
        hist.iter()
            .any(|m| m.from == Some(c.root()) && m.from_name == "Cy")
    );

    // The server holds only fixed-size units.
    net.with_server(&S1, |s| {
        assert!(
            s.stored_lengths()
                .iter()
                .all(|l| *l == enclave_wire::ENVELOPE_LEN)
        )
    });

    // A removes C. B keeps talking with A; C hears nothing more.
    a.remove_group_member(&gid, &c.root()).await.unwrap();
    let ev = settle(&mut [&mut b, &mut c], 2).await;
    assert!(ev[0].contains(&Event::GroupChanged { group_id: gid }));
    assert_eq!(b.groups()[0].members.len(), 1);
    b.send_group_text(&gid, "Just us").await.unwrap();
    let ev = settle(&mut [&mut a, &mut b, &mut c], 2).await;
    assert_eq!(group_texts(&ev[0]), vec!["Just us"]);
    assert!(
        group_texts(&ev[2]).is_empty(),
        "removed member reads nothing"
    );

    // A adds Dee, whom B has never met. Dee reads nothing from before she
    // joined, and after that everyone talks.
    let (mut d, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Dee")
        .await
        .unwrap();
    connect(&mut a, &mut d).await;
    a.add_group_members(&gid, &[d.root()]).await.unwrap();
    let ev = settle(&mut [&mut b, &mut d], 3).await;
    assert!(
        ev[0].contains(&Event::GroupChanged { group_id: gid }),
        "{:?}",
        ev[0]
    );
    assert!(
        ev[1]
            .iter()
            .any(|e| matches!(e, Event::GroupJoined { group_id, .. } if *group_id == gid)),
        "{:?}",
        ev[1]
    );
    assert!(
        d.group_messages(&gid).unwrap().is_empty(),
        "no history before joining"
    );
    assert_eq!(b.groups()[0].members.len(), 2);
    settle(&mut [&mut a, &mut b, &mut d], 2).await;
    b.send_group_text(&gid, "Welcome, Dee").await.unwrap();
    let ev = settle(&mut [&mut a, &mut b, &mut d], 3).await;
    assert_eq!(group_texts(&ev[2]), vec!["Welcome, Dee"]);
    d.send_group_text(&gid, "Thanks!").await.unwrap();
    let ev = settle(&mut [&mut a, &mut b, &mut d, &mut c], 3).await;
    assert_eq!(group_texts(&ev[0]), vec!["Thanks!"]);
    assert_eq!(group_texts(&ev[1]), vec!["Thanks!"]);
    assert!(
        group_texts(&ev[3]).is_empty(),
        "the removed member still reads nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn attachments_reactions_edits_deletes_receipts_and_timers() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    let (ra, rb) = (a.root(), b.root());

    // A 300 KB file travels as a padded 1 MiB bucket and verifies.
    let photo: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let sent = a
        .send_attachment(&rb, "beach.jpg", "image/jpeg", &photo, "Look!")
        .await
        .unwrap();
    let ev = b.sync().await.unwrap();
    let got = ev
        .iter()
        .find_map(|e| match e {
            Event::Message { message, .. } if message.attachment.is_some() => Some(message.clone()),
            _ => None,
        })
        .expect("attachment message");
    assert_eq!(got.text, "Look!");
    assert_eq!(got.attachment.as_ref().unwrap().name, "beach.jpg");
    assert_eq!(b.fetch_attachment(&ra, got.seq).await.unwrap(), photo);
    assert_eq!(
        a.fetch_attachment(&rb, sent.seq).await.unwrap(),
        photo,
        "sender keeps a local copy"
    );
    let chunk_sizes = net
        .with_server(&S1, |s| s.stored_lengths().clone())
        .unwrap();
    assert!(chunk_sizes.iter().all(|l| *l == enclave_wire::ENVELOPE_LEN));

    // Reaction, edit, delete for everyone, read receipt.
    let m = a.send_text(&rb, "See you at 10").await.unwrap();
    b.sync().await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.text == "See you at 10")
        .unwrap();
    // Local search finds it (case-insensitive, all words) and the photo by
    // its file name.
    let hits = b.search("see 10", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].place, enclave_core::Place::Contact(ra));
    assert_eq!(hits[0].seq, theirs.seq);
    assert_eq!(b.search("BEACH", 10).unwrap().len(), 1);
    assert!(b.search("see nothing", 10).unwrap().is_empty());
    assert!(b.search("s", 10).unwrap().is_empty());
    b.react(&ra, theirs.seq, "👍").await.unwrap();
    b.mark_read(&ra).await.unwrap();
    let ev = a.sync().await.unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::MessageChanged { .. })));
    let mine = a
        .messages(&rb)
        .unwrap()
        .into_iter()
        .find(|x| x.seq == m.seq)
        .unwrap();
    assert_eq!(
        mine.reactions,
        vec![enclave_core::Reaction {
            from_us: false,
            emoji: "👍".into()
        }]
    );
    assert!(mine.read, "read receipt arrived");
    a.edit_message(&rb, m.seq, "See you at 11").await.unwrap();
    b.sync().await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.seq == theirs.seq)
        .unwrap();
    assert_eq!(
        (theirs.text.as_str(), theirs.edited),
        ("See you at 11", true)
    );
    // Ben cannot edit or delete Ada's message.
    assert!(b.edit_message(&ra, theirs.seq, "no").await.is_err());
    assert!(b.delete_for_everyone(&ra, theirs.seq).await.is_err());
    a.delete_for_everyone(&rb, m.seq).await.unwrap();
    b.sync().await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.seq == theirs.seq)
        .unwrap();
    assert!(theirs.deleted && theirs.text.is_empty());

    // Disappearing messages: timer set by Ada applies to both sides.
    a.set_timer(&rb, 60).await.unwrap();
    let ev = b.sync().await.unwrap();
    assert!(ev.contains(&Event::TimerChanged { root: ra, secs: 60 }));
    let gone = a.send_text(&rb, "this disappears").await.unwrap();
    assert_eq!(gone.expires_secs, 60);
    assert!(gone.expires_at.is_some());
    b.sync().await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.text == "this disappears")
        .unwrap();
    assert_eq!(theirs.expires_at, None, "their clock starts when read");
    b.mark_read(&ra).await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.seq == theirs.seq)
        .unwrap();
    assert!(theirs.expires_at.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn link_a_second_device() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    b.send_text(&a.root(), "before the link").await.unwrap();
    a.sync().await.unwrap();

    // The new device shows a code; the general scanner refuses it.
    let mut n = enclave_core::LinkingDevice::start(memory(), Arc::new(net.clone()), S1)
        .await
        .unwrap();
    let code = n.code();
    assert_eq!(
        ContactCard::from_link(&code).unwrap_err(),
        enclave_core::LinkError::DeviceLinkCode
    );
    assert_eq!(n.poll().await.unwrap(), enclave_core::LinkProgress::Waiting);

    // A wrong pick links nothing.
    let offer = a.link_prepare(&code).await.unwrap();
    let enclave_core::LinkProgress::Words(words) = n.poll().await.unwrap() else {
        panic!("words")
    };
    let right = offer
        .choices
        .iter()
        .position(|c| *c == words)
        .expect("one choice matches");
    let wrong = (right + 1) % 4;
    assert!(a.link_confirm(offer, wrong).await.is_err());
    assert_eq!(a.devices().len(), 1);

    // Start again and pick the right words.
    let mut n = enclave_core::LinkingDevice::start(memory(), Arc::new(net.clone()), S1)
        .await
        .unwrap();
    let offer = a.link_prepare(&n.code()).await.unwrap();
    let enclave_core::LinkProgress::Words(words) = n.poll().await.unwrap() else {
        panic!("words")
    };
    let right = offer.choices.iter().position(|c| *c == words).unwrap();
    a.link_confirm(offer, right).await.unwrap();
    assert_eq!(n.poll().await.unwrap(), enclave_core::LinkProgress::Ready);
    let mut a2 = n.finish().await.unwrap();
    assert_eq!(a2.root(), a.root());
    assert!(!a2.can_link(), "linked devices hold no root");
    assert_eq!(a.devices().len(), 2);
    assert_eq!(a2.contacts().len(), 1);

    // Ben and Ada's first device learn the new device without any request.
    let ev = b.sync().await.unwrap();
    assert!(ev.iter().all(|e| !matches!(e, Event::Request { .. })));
    let ev = a.sync().await.unwrap();
    assert!(ev.contains(&Event::DevicesChanged));

    // History waits 24 h unless both devices confirm: the new one asks,
    // then the first one sends.
    let new_id = a2.devices().iter().find(|d| d.this_device).unwrap().id;
    assert!(a2.messages(&b.root()).unwrap().is_empty());
    assert!(!a.history_sent(&new_id));
    assert!(
        a2.send_history_now(&new_id).await.is_err(),
        "only the root sends"
    );
    assert!(
        a.send_history_now(&new_id).await.is_err(),
        "not before the new device asks"
    );
    a2.ask_history_now().await.unwrap();
    a.sync().await.unwrap();
    assert!(a.history_asked(&new_id));
    a.send_history_now(&new_id).await.unwrap();
    assert!(a.history_sent(&new_id));
    let ev = a2.sync().await.unwrap();
    assert!(ev.contains(&Event::HistoryImported), "{ev:?}");
    let texts: Vec<String> = a2
        .messages(&b.root())
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    let on_first: Vec<String> = a
        .messages(&b.root())
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert_eq!(texts, on_first);
    assert!(texts.contains(&"before the link".to_string()));
    // Sending again adds nothing twice.
    a.send_history_now(&new_id).await.unwrap();
    assert!(!a2.sync().await.unwrap().contains(&Event::HistoryImported));
    assert_eq!(a2.messages(&b.root()).unwrap().len(), texts.len());

    // Ben's next message reaches both of Ada's devices.
    b.send_text(&a.root(), "to both of you").await.unwrap();
    for dev in [&mut a, &mut a2] {
        let ev = dev.sync().await.unwrap();
        assert!(ev.iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "to both of you")
        ));
    }
    // What one device sends shows up on the other as sent.
    a2.send_text(&b.root(), "from the new device")
        .await
        .unwrap();
    let ev = b.sync().await.unwrap();
    assert!(ev.iter().any(
        |e| matches!(e, Event::Message { message, .. } if message.text == "from the new device")
    ));
    let ev = a.sync().await.unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Message { message, .. } if message.outgoing && message.text == "from the new device")));
    a.send_text(&b.root(), "and from the first").await.unwrap();
    let ev = a2.sync().await.unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Message { message, .. } if message.outgoing && message.text == "and from the first")));

    // Notes to self reach the other device, and so does deleting one;
    // nothing reaches Ben.
    assert!(a.send_note("  ").await.is_err(), "empty note");
    let note = a.send_note("Buy stamps").await.unwrap();
    let ev = a2.sync().await.unwrap();
    assert!(ev.contains(&Event::NotesChanged), "{ev:?}");
    assert_eq!(a2.notes().unwrap()[0].text, "Buy stamps");
    b.sync().await.unwrap();
    assert!(
        b.messages(&a.root())
            .unwrap()
            .iter()
            .all(|m| m.text != "Buy stamps")
    );
    let seq = a2.notes().unwrap()[0].seq;
    a2.delete_note(seq).await.unwrap();
    a.sync().await.unwrap();
    let on_first = a.notes().unwrap();
    assert!(on_first[0].deleted && on_first[0].id == note.id);

    // Ada removes the new device. Only the primary can; Ben and the removed
    // device find out, and nothing new reaches it.
    let a2_id = a.devices().iter().find(|d| !d.this_device).unwrap().id;
    let a1_id = a.devices().iter().find(|d| d.this_device).unwrap().id;
    assert!(a2.remove_device(&a1_id).await.is_err());
    assert!(a.remove_device(&a1_id).await.is_err(), "not this device");
    a.remove_device(&a2_id).await.unwrap();
    assert_eq!(a.devices().len(), 1);
    b.sync().await.unwrap();
    let ev = a2.sync().await.unwrap();
    assert!(ev.contains(&Event::RemovedFromAccount), "{ev:?}");
    b.send_text(&a.root(), "after the removal").await.unwrap();
    let ev = a.sync().await.unwrap();
    assert!(ev.iter().any(
        |e| matches!(e, Event::Message { message, .. } if message.text == "after the removal")
    ));
    let ev = a2.sync().await.unwrap();
    assert!(
        ev.iter().all(|e| !matches!(e, Event::Message { .. })),
        "{ev:?}"
    );
    // Messages the removed device sends are no longer accepted.
    let _ = a2.send_text(&b.root(), "still here?").await;
    let ev = b.sync().await.unwrap();
    assert!(
        ev.iter().all(|e| !matches!(e, Event::Message { .. })),
        "{ev:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_from_backup_on_a_new_device() {
    let net = network();
    let (mut a, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    b.send_text(&a.root(), "remember this").await.unwrap();
    a.sync().await.unwrap();
    a.send_text(&b.root(), "I will").await.unwrap();
    b.sync().await.unwrap();
    let archive = a.export_backup().unwrap();
    let root = a.root();
    drop(a); // the phone is lost

    // A wrong phrase fails; the right one restores contacts and history.
    let wrong = RecoverySecretWords::other();
    assert!(
        Client::restore(&wrong, &archive, memory(), Arc::new(net.clone()))
            .await
            .is_err()
    );
    let mut a = Client::restore(&words.join(" "), &archive, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    assert_eq!(a.root(), root);
    assert_eq!(
        a.devices().len(),
        1,
        "the lost device is gone from the manifest"
    );
    let history: Vec<String> = a
        .messages(&b.root())
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert!(
        history.contains(&"remember this".to_string()) && history.contains(&"I will".to_string())
    );

    // No device co-signed the restore, so Ben's client holds the new device's
    // greeting for 72 hours (someone else might hold the words).
    let ev = b.sync().await.unwrap();
    assert!(ev.is_empty(), "{ev:?}");
    net.advance(enclave_proto::attest::RECOVERY_WAIT_SECS + 1);
    // Then it accepts the new device silently and sends it fresh tokens.
    let ev = b.sync().await.unwrap();
    assert!(ev.iter().all(|e| !matches!(e, Event::Request { .. })));
    a.sync().await.unwrap();
    for i in 0..20 {
        a.send_text(&b.root(), &format!("after restore {i}"))
            .await
            .unwrap();
    }
    let ev = b.sync().await.unwrap();
    assert_eq!(
        ev.iter()
            .filter(|e| matches!(e, Event::Message { .. }))
            .count(),
        20
    );
    b.send_text(&a.root(), "welcome back").await.unwrap();
    let ev = a.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Message { message, .. } if message.text == "welcome back"))
    );
}

struct RecoverySecretWords;
impl RecoverySecretWords {
    fn other() -> String {
        let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
        enclave_proto::recovery::RecoverySecret::generate(&mut rng)
            .unwrap()
            .to_words()
            .unwrap()
            .join(" ")
    }
}

/// Usernames across two servers: claim, find, add, message; taken and
/// confusable names; renaming releases the old name but keeps it reserved;
/// a lookup that fails verification is never reported as "not found".
#[tokio::test(flavor = "multi_thread")]
async fn usernames_through_key_transparency() {
    use enclave_core::UsernameError;
    let net = network();
    let mut policy = net.enable_usernames(&S1, "one.test").unwrap();
    policy.merge(net.enable_usernames(&S2, "two.test").unwrap());

    let (mut alice, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Alice")
        .await
        .unwrap();
    let (mut bob, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Bob")
        .await
        .unwrap();
    let (mut carol, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Carol")
        .await
        .unwrap();
    assert!(matches!(
        alice.claim_username("alice").await,
        Err(CoreError::Username(UsernameError::Unavailable))
    ));
    for c in [&mut alice, &mut bob, &mut carol] {
        c.set_kt_policy(policy.clone());
    }

    assert_eq!(
        alice.claim_username("Alice").await.unwrap(),
        "alice@one.test"
    );
    assert_eq!(alice.username().as_deref(), Some("alice@one.test"));
    assert_eq!(bob.claim_username("bob").await.unwrap(), "bob@two.test");
    for (name, err) in [
        ("alice", UsernameError::Taken),
        ("a1ice", UsernameError::Taken),
        ("admin", UsernameError::NotAllowed),
        ("x", UsernameError::NotAllowed),
    ] {
        match carol.claim_username(name).await {
            Err(CoreError::Username(e)) => assert_eq!(e, err, "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }

    // Bob finds Alice on the other server and messages her.
    let card = bob.find_username("@alice@one.test").await.unwrap();
    assert_eq!(card.root, alice.root());
    assert_eq!(card.name, "Alice");
    bob.add_contact(&card, "Hi Alice, found you by name")
        .await
        .unwrap();
    let ev = alice.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { root, .. } if *root == bob.root())),
        "{ev:?}"
    );
    // Home-server lookups need no domain.
    assert_eq!(
        carol.find_username("alice").await.unwrap().root,
        alice.root()
    );
    assert!(matches!(
        bob.find_username("nobody@one.test").await,
        Err(CoreError::Username(UsernameError::NotFound))
    ));
    assert!(matches!(
        bob.find_username("alice@elsewhere.test").await,
        Err(CoreError::Username(UsernameError::Unavailable))
    ));

    // Renaming: the old name stops resolving but stays Alice's.
    assert_eq!(
        alice.claim_username("alice_w").await.unwrap(),
        "alice_w@one.test"
    );
    assert!(matches!(
        bob.find_username("alice@one.test").await,
        Err(CoreError::Username(UsernameError::NotFound))
    ));
    assert_eq!(
        bob.find_username("alice_w@one.test").await.unwrap().root,
        alice.root()
    );
    assert!(matches!(
        carol.claim_username("alice").await,
        Err(CoreError::Username(UsernameError::Taken))
    ));

    // Self-audit: Alice checks her own name once a day. It still leads to
    // her, so nothing happens; then the operator quietly rebinds it to Bob's
    // card and her next check says so.
    net.advance(enclave_core::client::AUDIT_EVERY_SECS + 1);
    let ev = alice.sync().await.unwrap();
    assert!(
        ev.iter()
            .all(|e| !matches!(e, Event::UsernameProblem { .. })),
        "{ev:?}"
    );
    let mut forged = bob.root().to_vec();
    forged.extend_from_slice(&bob.card().encode());
    let now = net.now();
    assert!(
        net.with_server(&S1, |s| s.kt_force("alice_w", forged, now))
            .unwrap()
    );
    net.advance(enclave_core::client::AUDIT_EVERY_SECS + 1);
    let ev = alice.sync().await.unwrap();
    assert!(
        ev.contains(&Event::UsernameProblem {
            address: "alice_w@one.test".into()
        }),
        "{ev:?}"
    );

    // A client pinning different witnesses refuses the server's answer.
    let mut strict = policy.clone();
    strict.witnesses.witnesses.truncate(2);
    carol.set_kt_policy(strict);
    assert!(matches!(
        carol.find_username("bob@two.test").await,
        Err(CoreError::Username(UsernameError::Unverified))
    ));
}

/// Someone restores Ada's account from her words while her devices still
/// exist: her devices are told, contacts hold the change, and a veto from any
/// of her devices stops it for good. A restore her device approves is
/// accepted at once.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_without_a_device_waits_and_can_be_vetoed() {
    use enclave_proto::attest::RECOVERY_WAIT_SECS;
    let net = network();
    let (mut a, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    let archive = a.export_backup().unwrap();

    // Someone with the words and a backup restores the account elsewhere.
    let mut thief = Client::restore(&words.join(" "), &archive, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    assert!(b.sync().await.unwrap().is_empty(), "held, not accepted");

    // Ada's phone notices within ten minutes and she stops it.
    net.advance(601);
    let ev = a.sync().await.unwrap();
    let Some(Event::RecoveryPending { until }) = ev
        .iter()
        .find(|e| matches!(e, Event::RecoveryPending { .. }))
        .cloned()
    else {
        panic!("no alert: {ev:?}")
    };
    assert!(until > net.now());
    assert!(a.recovery_alert().is_some());
    a.stop_recovery().await.unwrap();
    assert!(a.recovery_alert().is_none());

    // Three days later Ben still refuses the thief's device, and Ada's phone
    // still talks to Ben.
    net.advance(RECOVERY_WAIT_SECS + 601);
    let ev = b.sync().await.unwrap();
    assert!(
        ev.iter()
            .all(|e| !matches!(e, Event::Message { .. } | Event::Request { .. })),
        "{ev:?}"
    );
    let _ = thief.send_text(&b.root(), "it's me, really").await;
    a.send_text(&b.root(), "ignore any new device of mine")
        .await
        .unwrap();
    let texts: Vec<String> = b
        .sync()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(message.text),
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["ignore any new device of mine"]);
    drop(thief);

    // Later Ada really does restore onto a new phone, and approves it from
    // her old one: Ben accepts it without waiting.
    let archive = a.export_backup().unwrap();
    let mut a_new = Client::restore(&words.join(" "), &archive, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    net.advance(601);
    let ev = a.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::RecoveryPending { .. })),
        "{ev:?}"
    );
    a.approve_recovery().await.unwrap();
    net.advance(601);
    let ev = b.sync().await.unwrap();
    assert!(
        ev.iter().all(|e| !matches!(e, Event::Request { .. })),
        "{ev:?}"
    );
    a_new.sync().await.unwrap();
    a_new
        .send_text(&b.root(), "new phone, same me")
        .await
        .unwrap();
    let ev = b.sync().await.unwrap();
    assert!(
        ev.iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "new phone, same me")
        ),
        "{ev:?}"
    );
    // The approving phone learns it was replaced.
    net.advance(601);
    let ev = a.sync().await.unwrap();
    assert!(ev.contains(&Event::RemovedFromAccount), "{ev:?}");
}

/// Meeting in person: both phones show the same Seal words, contacts end up
/// in sessions keyed with the optical secret and checked in person, and two
/// strangers who meet become contacts without a request.
#[tokio::test(flavor = "multi_thread")]
async fn meeting_in_person() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    let (mut c, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Cy")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;

    // Ada and Ben scan each other.
    let code_a = a.meet_code().unwrap();
    let code_b = b.meet_code().unwrap();
    assert_eq!(
        ContactCard::from_link(&code_a).unwrap_err(),
        enclave_core::LinkError::MeetCode
    );
    assert!(matches!(
        a.meet_scan(&code_a),
        Err(CoreError::Link(enclave_core::LinkError::OwnCode))
    ));
    let on_a = a.meet_scan(&code_b).unwrap();
    let on_b = b.meet_scan(&code_a).unwrap();
    assert_eq!(on_a.words, on_b.words);
    assert_eq!((on_a.root, on_a.name.as_str()), (b.root(), "Ben"));
    // A bystander's scan of Ada's code shows different words.
    c.meet_code().unwrap();
    assert_ne!(c.meet_scan(&code_a).unwrap().words, on_a.words);
    c.meet_cancel();

    a.meet_confirm().await.unwrap();
    b.meet_confirm().await.unwrap();
    for _ in 0..2 {
        a.sync().await.unwrap();
        b.sync().await.unwrap();
    }
    assert!(a.met_in_person(&b.root()) && b.met_in_person(&a.root()));
    assert!(a.contact(&b.root()).unwrap().verified && b.contact(&a.root()).unwrap().verified);
    a.send_text(&b.root(), "after we met").await.unwrap();
    assert!(
        b.sync()
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(e, Event::Message { message, .. } if message.text == "after we met"))
    );
    b.send_text(&a.root(), "same here").await.unwrap();
    assert!(
        a.sync()
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(e, Event::Message { message, .. } if message.text == "same here"))
    );

    // Ada and Cy have never talked: meeting makes them contacts, no request.
    let code_a = a.meet_code().unwrap();
    let code_c = c.meet_code().unwrap();
    assert_eq!(
        a.meet_scan(&code_c).unwrap().words,
        c.meet_scan(&code_a).unwrap().words
    );
    a.meet_confirm().await.unwrap();
    c.meet_confirm().await.unwrap();
    let mut events = Vec::new();
    for _ in 0..2 {
        events.extend(a.sync().await.unwrap());
        events.extend(c.sync().await.unwrap());
    }
    assert!(
        events.iter().all(|e| !matches!(e, Event::Request { .. })),
        "{events:?}"
    );
    for (me, them) in [(&a, c.root()), (&c, a.root())] {
        let ct = me.contact(&them).unwrap();
        assert_eq!(ct.state, ContactState::Accepted);
        assert!(ct.verified && me.met_in_person(&them));
    }
    c.send_text(&a.root(), "nice to meet you").await.unwrap();
    assert!(a.sync().await.unwrap().iter().any(
        |e| matches!(e, Event::Message { message, .. } if message.text == "nice to meet you")
    ));
}

/// Invite links (03 §7.3, §9.2): the link's capabilities stand in for the
/// proof of work (here a server demands more than any client will do), the
/// session carries the link's one-way PSK, a used link lets nobody else
/// in, and cancelled or lapsed links stop working.
#[tokio::test(flavor = "multi_thread")]
async fn invite_links() {
    const STRICT: [u8; 16] = [9; 16];
    let net = network();
    net.add_server(enclave_server::Config {
        id: STRICT,
        effort_request: 1 << 30,
        effort_claim: 1,
        effort_blob: 1,
        ..Default::default()
    })
    .unwrap();
    let (mut host, _) = Client::create(memory(), Arc::new(net.clone()), STRICT, "Hana")
        .await
        .unwrap();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();

    let link = host.create_invite(1).await.unwrap();
    let card = ContactCard::from_link(&link).unwrap();
    assert_eq!(card.invite.as_ref().map(|i| i.uses), Some(1));
    assert_eq!(host.invites().unwrap().len(), 1);
    a.add_contact(&card, "hello via link").await.unwrap();
    let ev = host.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { text, .. } if text == "hello via link")),
        "{ev:?}"
    );
    // An invite is not a check in person.
    assert!(!host.contact(&a.root()).unwrap().verified);
    assert!(host.invites().unwrap().is_empty(), "used up");
    host.accept(&a.root()).await.unwrap();
    a.sync().await.unwrap();
    a.send_text(&host.root(), "we're talking").await.unwrap();
    assert!(
        host.sync().await.unwrap().iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "we're talking")
        )
    );

    // The same link again: its capability is spent.
    assert!(matches!(
        b.add_contact(&card, "me too").await,
        Err(CoreError::Link(enclave_core::LinkError::InviteUsed))
    ));
    assert!(b.contact(&host.root()).is_none(), "nothing half-added");

    // A cancelled link, and a lapsed one.
    let cancelled = ContactCard::from_link(&host.create_invite(2).await.unwrap()).unwrap();
    host.cancel_invites().await.unwrap();
    assert!(host.invites().unwrap().is_empty());
    assert!(matches!(
        b.add_contact(&cancelled, "").await,
        Err(CoreError::Link(enclave_core::LinkError::InviteUsed))
    ));
    let lapsed = ContactCard::from_link(&host.create_invite(1).await.unwrap()).unwrap();
    net.advance(8 * 86_400);
    host.sync().await.unwrap();
    b.sync().await.unwrap();
    let r = b.add_contact(&lapsed, "").await;
    assert!(
        matches!(r, Err(CoreError::Link(enclave_core::LinkError::InviteUsed))),
        "{r:?}"
    );

    // A link for two brings two.
    let two = ContactCard::from_link(&host.create_invite(2).await.unwrap()).unwrap();
    b.add_contact(&two, "Ben here").await.unwrap();
    let ev = host.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { root, .. } if *root == b.root()))
    );
    assert_eq!(host.invites().unwrap()[0].used, 1);
}

/// RT-04: a server whose witnesses collude shows Ben a forked log in which
/// Cy's name leads to Mallory. Each view verifies on its own. When Ada, who
/// saw the real log, messages Ben, the head digests they gossip disagree;
/// they exchange signed heads, and both end up holding proof that the
/// server signed two versions of the same epoch.
#[tokio::test(flavor = "multi_thread")]
async fn rt04_split_view_detected_by_gossip() {
    let net = network();
    let (real, fork, policy) = enclave_kt::KtService::start_dev_twins(S1, "one.test").unwrap();
    net.with_server(&S1, |s| {
        s.enable_kt(real);
        s.enable_kt_fork(fork);
    })
    .unwrap();
    // Ben's home is another server, which takes proofs about S1's log.
    let s1_key = policy.by_server(&S1).unwrap().head_key.clone();
    net.with_server(&S2, |s| s.pin_log(S1, s1_key)).unwrap();
    let mut clients = Vec::new();
    for (name, home) in [("Ada", S1), ("Ben", S2), ("Cy", S1), ("Mallory", S1)] {
        let (mut c, _) = Client::create(memory(), Arc::new(net.clone()), home, name)
            .await
            .unwrap();
        c.set_kt_policy(policy.clone());
        clients.push(c);
    }
    let [mut ada, mut ben, mut cy, mallory] = <[Client; 4]>::try_from(clients).ok().unwrap();
    cy.claim_username("cyrus").await.unwrap();
    // The fork binds the same name, at the same epoch, to Mallory.
    let forged = [&mallory.root()[..], &mallory.card().encode()].concat();
    let now = net.now();
    assert!(
        net.with_server(&S1, |s| s.kt_fork_force("cyrus", forged, now))
            .unwrap()
    );

    connect(&mut ada, &mut ben).await;
    assert_eq!(
        ada.find_username("cyrus@one.test").await.unwrap().root,
        cy.root()
    );
    net.with_server(&S1, |s| s.kt_serve_fork(true)).unwrap();
    // Ben's view verifies: he alone can't tell.
    assert_eq!(
        ben.find_username("cyrus@one.test").await.unwrap().root,
        mallory.root()
    );
    net.with_server(&S1, |s| s.kt_serve_fork(false)).unwrap();
    assert!(ada.kt_alert().is_none() && ben.kt_alert().is_none());

    ada.send_text(&ben.root(), "hi Ben").await.unwrap();
    let mut events = Vec::new();
    for _ in 0..4 {
        events.extend(ben.sync().await.unwrap());
        events.extend(ada.sync().await.unwrap());
    }
    let split = |e: &Event| matches!(e, Event::KtSplitView { server, .. } if *server == S1);
    assert!(
        events.iter().filter(|e| split(e)).count() >= 2,
        "{events:?}"
    );
    let a = ada.kt_alert().expect("Ada holds the proof");
    let b = ben.kt_alert().expect("Ben holds the proof");
    assert_eq!(a, b);
    assert_eq!(a.server, S1);
    // Ben published the proof to his home server, which checked it and
    // queued it for the witnesses; anyone can fetch it there.
    let held = net.with_server(&S2, |s| s.take_equivocations()).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!((held[0].server(), held[0].epoch()), (S1, a.epoch));
    assert!(
        held[0].colluders().len() >= 2,
        "the colluding witnesses signed both"
    );

    // Honest views raise nothing: Cy and Ada agree.
    connect(&mut cy, &mut ada).await;
    cy.find_username("cyrus@one.test").await.unwrap();
    cy.send_text(&ada.root(), "hello").await.unwrap();
    ada.sync().await.unwrap();
    cy.sync().await.unwrap();
    assert!(cy.kt_alert().is_none());
}

/// Group invite links (07 §9): a join waits for an admin by default, the
/// newcomer reads nothing from before, only admins make links, and a link
/// without approval lets people straight in.
#[tokio::test(flavor = "multi_thread")]
async fn group_invite_links() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [
        ("Ada", S1),
        ("Mo", S2),
        ("Jo", S1),
        ("Kit", S2),
        ("Nia", S1),
    ] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo, mut kit, mut nia] = <[Client; 5]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    let gid = ada.create_group("Book club", &[mo.root()]).await.unwrap();
    settle(&mut [&mut ada, &mut mo], 2).await;
    ada.send_group_text(&gid, "before Jo").await.unwrap();
    settle(&mut [&mut ada, &mut mo], 2).await;

    // Only admins make links.
    assert!(mo.create_group_invite(&gid, 1, true).await.is_err());
    let link = ada.create_group_invite(&gid, 1, true).await.unwrap();
    assert!(link.starts_with("enclave:join#"));
    assert_eq!(jo.join_group(&link).await.unwrap(), "Book club");
    assert_eq!(jo.joining().len(), 1);

    let ev = ada.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::JoinRequest { root, group, .. } if *root == jo.root() && *group == gid)),
        "{ev:?}"
    );
    assert_eq!(ada.join_request(&jo.root()), Some(gid));
    ada.approve_join(&jo.root()).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;
    assert!(jo.groups().iter().any(|g| g.id == gid));
    assert!(jo.joining().is_empty());
    assert!(ada.join_request(&jo.root()).is_none());
    // Nothing from before Jo joined.
    assert!(
        jo.group_messages(&gid)
            .unwrap()
            .iter()
            .all(|m| m.text != "before Jo")
    );
    jo.send_group_text(&gid, "hi all").await.unwrap();
    let ev = settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    assert!(
        group_texts(&ev[1]).contains(&"hi all".to_string()),
        "{:?}",
        ev[1]
    );

    // Without approval: straight in.
    let open = ada.create_group_invite(&gid, 1, false).await.unwrap();
    kit.join_group(&open).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo, &mut kit], 3).await;
    assert!(kit.groups().iter().any(|g| g.id == gid));

    // A declined request goes away.
    let link = ada.create_group_invite(&gid, 1, true).await.unwrap();
    nia.join_group(&link).await.unwrap();
    ada.sync().await.unwrap();
    assert_eq!(ada.join_request(&nia.root()), Some(gid));
    ada.decline_join(&nia.root()).unwrap();
    assert!(ada.contact(&nia.root()).is_none());
    assert!(ada.join_request(&nia.root()).is_none());
}

/// Polls (07 §7.5): votes reach everyone, a later vote replaces an earlier
/// one, only the creator closes, and a close that missed a vote shows as a
/// tally that doesn't match.
#[tokio::test(flavor = "multi_thread")]
async fn polls_in_groups() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let gid = ada
        .create_group("Trip", &[mo.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;

    let opts = [
        "Friday".to_string(),
        "Saturday".into(),
        "  ".into(),
        "Sunday".into(),
    ];
    assert!(
        ada.create_poll(&gid, "When?", &opts[..1]).await.is_err(),
        "one option"
    );
    let id = ada.create_poll(&gid, "When?", &opts).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    for c in [&ada, &mo, &jo] {
        let p = c.poll(&gid, &id).expect("poll arrived");
        assert_eq!(p.question, "When?");
        assert_eq!(p.options.len(), 3, "blank option dropped");
        let msgs = c.group_messages(&gid).unwrap();
        assert!(msgs.iter().any(|m| m.poll == Some(id)));
    }

    mo.vote(&gid, &id, 0).await.unwrap();
    mo.vote(&gid, &id, 1).await.unwrap(); // changed their mind
    jo.vote(&gid, &id, 1).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    let p = ada.poll(&gid, &id).unwrap();
    assert_eq!(
        p.options.iter().map(|o| o.1).collect::<Vec<_>>(),
        vec![0, 2, 0]
    );
    assert_eq!(mo.poll(&gid, &id).unwrap().mine, Some(1));
    assert!(p.ours && !mo.poll(&gid, &id).unwrap().ours);
    assert!(
        mo.close_poll(&gid, &id).await.is_err(),
        "only the creator closes"
    );
    assert!(ada.vote(&gid, &id, 9).await.is_err(), "no such option");

    // Jo votes again, but Ada closes before it reaches her.
    jo.vote(&gid, &id, 2).await.unwrap();
    ada.close_poll(&gid, &id).await.unwrap();
    settle(&mut [&mut mo, &mut jo, &mut ada], 2).await;
    let a = ada.poll(&gid, &id).unwrap();
    assert!(a.closed && a.tally_agrees == Some(true));
    let m = mo.poll(&gid, &id).unwrap();
    assert!(m.closed);
    assert_eq!(m.tally_agrees, Some(false), "Mo counted Jo's last vote");
    assert!(jo.vote(&gid, &id, 0).await.is_err(), "closed");
}

/// Pinned messages: in a 1:1 conversation either person pins for both;
/// in a group any member pins for all. At most three stay pinned, newest
/// first, and a deleted message drops out.
#[tokio::test(flavor = "multi_thread")]
async fn pinned_messages() {
    use enclave_core::Place;
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;

    // 1:1.
    let mut seqs = Vec::new();
    for t in ["one", "two", "three", "four"] {
        seqs.push(ada.send_text(&mo.root(), t).await.unwrap().seq);
    }
    mo.sync().await.unwrap();
    let theirs: Vec<u64> = mo
        .messages(&ada.root())
        .unwrap()
        .iter()
        .filter(|m| ["one", "two", "three", "four"].contains(&m.text.as_str()))
        .map(|m| m.seq)
        .collect();
    assert_eq!(theirs.len(), 4);
    for &s in &theirs {
        mo.pin_message(&ada.root(), s, true).await.unwrap();
    }
    let ev = ada.sync().await.unwrap();
    let here = Place::Contact(mo.root());
    assert!(ev.contains(&enclave_core::Event::PinsChanged { place: here }));
    assert_eq!(
        ada.pinned(&here),
        vec![seqs[3], seqs[2], seqs[1]],
        "newest first, three at most"
    );
    ada.pin_message(&mo.root(), seqs[2], false).await.unwrap();
    ada.delete_for_everyone(&mo.root(), seqs[3]).await.unwrap();
    mo.sync().await.unwrap();
    assert_eq!(ada.pinned(&here), vec![seqs[1]]);
    assert_eq!(mo.pinned(&Place::Contact(ada.root())), vec![theirs[1]]);

    // Group.
    let gid = ada
        .create_group("Trip", &[mo.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;
    let sent = jo
        .send_group_text(&gid, "Meet at the station")
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    let at_mo = mo
        .group_messages(&gid)
        .unwrap()
        .into_iter()
        .find(|m| m.text == "Meet at the station")
        .unwrap();
    assert_eq!(at_mo.id, sent.id, "same id for every member");
    mo.pin_group_message(&gid, at_mo.seq, true).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    assert_eq!(jo.pinned(&Place::Group(gid)), vec![sent.seq]);
    assert_eq!(mo.pinned(&Place::Group(gid)), vec![at_mo.seq]);
    assert_eq!(ada.pinned(&Place::Group(gid)).len(), 1);
    jo.pin_group_message(&gid, sent.seq, false).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    for c in [&mut ada, &mut mo, &mut jo] {
        assert!(c.pinned(&Place::Group(gid)).is_empty());
    }
}

/// Group reactions, edits and deletes travel by message id; edits and
/// deletes apply only to the author's own messages.
#[tokio::test(flavor = "multi_thread")]
async fn group_reactions_edits_deletes() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let gid = ada
        .create_group("Trip", &[mo.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;
    let find = |c: &Client, text: &str| {
        c.group_messages(&gid)
            .unwrap()
            .into_iter()
            .find(|m| m.text.starts_with(text))
            .unwrap()
    };

    let sent = mo.send_group_text(&gid, "Train at 9").await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    let at_ada = find(&ada, "Train at 9");
    ada.react_group(&gid, at_ada.seq, "👍").await.unwrap();
    let at_jo = find(&jo, "Train at 9");
    jo.react_group(&gid, at_jo.seq, "❤").await.unwrap();
    jo.react_group(&gid, at_jo.seq, "😂").await.unwrap(); // replaces Jo's
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    let m = find(&mo, "Train at 9");
    let mut emoji: Vec<_> = m.reactions.iter().map(|r| r.emoji.as_str()).collect();
    emoji.sort_unstable();
    assert_eq!(emoji, vec!["👍", "😂"], "one reaction per member");

    assert!(
        ada.edit_group_message(&gid, at_ada.seq, "Train at 8")
            .await
            .is_err(),
        "only the author edits"
    );
    mo.edit_group_message(&gid, sent.seq, "Train at 10")
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    for c in [&ada, &jo] {
        let m = find(c, "Train at 1");
        assert!(m.edited && m.text == "Train at 10");
    }

    ada.pin_group_message(&gid, at_ada.seq, true).await.unwrap();
    assert!(
        ada.delete_group_message(&gid, at_ada.seq).await.is_err(),
        "not ours"
    );
    mo.delete_group_message(&gid, sent.seq).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    for c in [&ada, &mo, &jo] {
        let m = c
            .group_messages(&gid)
            .unwrap()
            .into_iter()
            .find(|m| m.id == sent.id)
            .unwrap();
        assert!(m.deleted && m.text.is_empty() && m.reactions.is_empty());
        assert!(
            c.pinned(&enclave_core::Place::Group(gid)).is_empty(),
            "unpinned"
        );
    }
}

/// Locations: coordinates and a label, nothing looked up; with a timer
/// they disappear with the message.
#[tokio::test(flavor = "multi_thread")]
async fn share_a_location() {
    use enclave_core::Location;
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut mo, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Mo")
        .await
        .unwrap();
    connect(&mut ada, &mut mo).await;
    let here = Location::from_degrees(52.520008, 13.404954, "Meet here").unwrap();
    ada.share_location(&mo.root(), &here).await.unwrap();
    mo.sync().await.unwrap();
    let got = mo
        .messages(&ada.root())
        .unwrap()
        .into_iter()
        .find_map(|m| m.location)
        .expect("location arrived");
    assert_eq!(got, here);
    assert_eq!(got.coordinates(), "52.520008, 13.404954");

    // With a one-minute timer, it's gone a minute after Mo reads it.
    ada.set_timer(&mo.root(), 60).await.unwrap();
    mo.sync().await.unwrap();
    let there = Location::from_degrees(48.8584, 2.2945, "").unwrap();
    ada.share_location(&mo.root(), &there).await.unwrap();
    mo.sync().await.unwrap();
    mo.mark_read(&ada.root()).await.unwrap();
    assert!(
        mo.messages(&ada.root())
            .unwrap()
            .iter()
            .any(|m| m.location.as_ref() == Some(&there))
    );
    net.advance(61);
    mo.sync().await.unwrap();
    assert!(
        mo.messages(&ada.root())
            .unwrap()
            .iter()
            .all(|m| m.location.as_ref() != Some(&there))
    );
}

/// Sharing a contact: Ada shares Jo's card with Mo, who adds Jo from it.
/// The card carries no invite secret, and Jo sees an ordinary request.
#[tokio::test(flavor = "multi_thread")]
async fn share_a_contact() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    assert!(
        ada.share_contact(&mo.root(), &mo.root()).await.is_err(),
        "not to themselves"
    );
    let m = ada.share_contact(&mo.root(), &jo.root()).await.unwrap();
    assert!(ada.shared_contacts(&mo.root()).contains_key(&m.id));
    let ev = mo.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Message { message, .. } if message.id == m.id))
    );
    let shared = mo.shared_contacts(&ada.root());
    let card = shared.get(&m.id).expect("card kept");
    assert_eq!(card.root, jo.root());
    assert_eq!(card.name, "Jo");
    assert!(card.invite.is_none());

    mo.add_contact(card, "Ada said to say hi").await.unwrap();
    let ev = jo.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { root, .. } if *root == mo.root())),
        "{ev:?}"
    );
}

/// Reports go to the reported person's server, with the quotes the
/// reporter chose and nothing about the reporter; the operator can close
/// the reported request inbox.
#[tokio::test(flavor = "multi_thread")]
async fn report_to_the_operator() {
    use enclave_rpc::api::ReportReason;
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut mo, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Mo")
        .await
        .unwrap();
    connect(&mut ada, &mut mo).await;
    for t in ["one", "two", "three"] {
        mo.send_text(&ada.root(), t).await.unwrap();
    }
    ada.sync().await.unwrap();
    ada.report(&mo.root(), ReportReason::Spam, 2).await.unwrap();
    let mo_inbox = mo.card().request_inbox;
    let reports = net.with_server(&S2, |s| s.take_reports()).unwrap();
    assert_eq!(reports.len(), 1, "to Mo's server");
    assert_eq!(reports[0].request_inbox, mo_inbox);
    assert_eq!(reports[0].body.reason, ReportReason::Spam);
    assert_eq!(
        reports[0].body.quotes,
        vec!["two", "three"],
        "the latest two"
    );
    assert_eq!(
        net.with_server(&S1, |s| s.reports().len()).unwrap(),
        0,
        "not to Ada's own server"
    );
    ada.report(&mo.root(), ReportReason::Other, 0)
        .await
        .unwrap();
    let r = net.with_server(&S2, |s| s.take_reports()).unwrap();
    assert!(r[0].body.quotes.is_empty(), "quotes are optional");

    // Ada makes message requests to her cost more for a month: a
    // stranger's request still arrives (their device climbs the effort
    // ladder), and a month later the server's own effort is back.
    assert_eq!(ada.raise_request_effort().await.unwrap(), 256);
    assert_eq!(ada.raise_request_effort().await.unwrap(), 1024);
    let (mut kit, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Kit")
        .await
        .unwrap();
    kit.add_contact(&ada.card(), "hello from a stranger")
        .await
        .unwrap();
    let ev = ada.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { root, .. } if *root == kit.root())),
        "{ev:?}"
    );
    net.advance(enclave_core::client::RAISED_EFFORT_SECS + 1);
    ada.sync().await.unwrap();
    assert_eq!(ada.request_effort().unwrap().0, 0);

    assert!(
        net.with_server(&S2, |s| s.disable_request_inbox(&mo_inbox))
            .unwrap()
    );
    assert!(
        ada.report(&mo.root(), ReportReason::Spam, 0).await.is_err(),
        "inbox closed"
    );
}

/// Token registration doesn't group writes by sender (09 §3.2): the tokens
/// two different contacts burn came in the same registration batch, so a
/// server that logs batches and burns can't tell them apart by batch.
#[tokio::test(flavor = "multi_thread")]
async fn token_batches_mix_contacts() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S2)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let burned_before = net.with_server(&S1, |s| s.token_log().1.len()).unwrap();
    mo.send_text(&ada.root(), "from Mo").await.unwrap();
    jo.send_text(&ada.root(), "from Jo").await.unwrap();
    let (batches, burned) = net.with_server(&S1, |s| s.token_log().clone()).unwrap();
    let (mo_tok, jo_tok) = (burned[burned_before], burned[burned_before + 1]);
    let batch_of = |t: &[u8; 32]| batches.iter().position(|b| b.contains(t)).unwrap();
    assert_eq!(
        batch_of(&mo_tok),
        batch_of(&jo_tok),
        "both contacts' tokens came from one shared batch"
    );
}

/// Blocking: the blocked contact's tokens are revoked at our server, so
/// their writes fail; nothing from them shows. Unblocking sends fresh
/// tokens and the conversation works again.
#[tokio::test(flavor = "multi_thread")]
async fn block_and_unblock() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut mo, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Mo")
        .await
        .unwrap();
    connect(&mut ada, &mut mo).await;
    let count = |c: &Client, root: &[u8; 64]| c.messages(root).unwrap().len();

    ada.block(&mo.root()).await.unwrap();
    assert!(ada.is_blocked(&mo.root()));
    assert_eq!(ada.blocked(), vec![mo.root()]);
    assert!(
        ada.send_text(&mo.root(), "hi").await.is_err(),
        "we can't write either"
    );
    let before = count(&ada, &mo.root());
    assert!(
        mo.send_text(&ada.root(), "are you there?").await.is_err(),
        "their tokens were revoked at Ada's server"
    );
    let ev = ada.sync().await.unwrap();
    assert!(ev.is_empty(), "nothing from them: {ev:?}");
    assert_eq!(count(&ada, &mo.root()), before);

    ada.unblock(&mo.root()).await.unwrap();
    assert!(!ada.is_blocked(&mo.root()));
    mo.sync().await.unwrap(); // fresh tokens
    mo.send_text(&ada.root(), "hello again").await.unwrap();
    ada.sync().await.unwrap();
    assert!(
        ada.messages(&mo.root())
            .unwrap()
            .iter()
            .any(|m| m.text == "hello again")
    );
}

/// The pre-rekey PQ step (07 §5.2): a rotation into a new epoch pings
/// members whose pairwise PQ state hasn't moved since the last epoch
/// change; once they have answered, the device rotates again.
#[tokio::test(flavor = "multi_thread")]
async fn pre_rekey_pq_step() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let gid = ada
        .create_group("Trip", &[mo.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;
    ada.send_group_text(&gid, "hello").await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    assert_eq!(ada.group_pre_step(&gid).unwrap(), (0, 0));

    // Removing Jo starts a new epoch. Pairs that stepped since the last
    // epoch change (welcomes and cards did) need no ping.
    ada.remove_group_member(&gid, &jo.root()).await.unwrap();
    assert_eq!(ada.group_pre_step(&gid).unwrap(), (0, 0));
    settle(&mut [&mut mo, &mut ada], 2).await;

    // A day later Ada's chain is due. Nothing has crossed between Ada and Mo
    // since the epoch began, so Ada pings Mo before rotating.
    net.advance(25 * 3600);
    ada.send_group_text(&gid, "a day later").await.unwrap();
    let (pending, healed) = ada.group_pre_step(&gid).unwrap();
    assert!(
        pending >= 1,
        "Mo's pair hadn't stepped since the epoch began"
    );
    assert_eq!(healed, 0);
    settle(&mut [&mut mo, &mut ada], 3).await;
    assert_eq!(
        ada.group_pre_step(&gid).unwrap(),
        (0, 1),
        "Mo answered; Ada rotated again under the new keys"
    );
    // The group still works after the extra rotation.
    ada.send_group_text(&gid, "still here").await.unwrap();
    settle(&mut [&mut ada, &mut mo], 2).await;
    assert!(
        mo.group_messages(&gid)
            .unwrap()
            .iter()
            .any(|m| m.text == "still here")
    );
}

/// Stickers: Ada makes a pack and sends a sticker to Mo and to a group;
/// Mo and Jo decode the same picture from the pack and can add it.
#[tokio::test(flavor = "multi_thread")]
async fn sticker_packs() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let pics = vec![vec![1u8; 3000], vec![2u8; 5000], vec![3u8; 700]];
    let pack = ada
        .create_sticker_pack(" Cats ", pics.clone())
        .await
        .unwrap();
    assert_eq!((pack.title.as_str(), pack.count), ("Cats", 3));
    assert_eq!(ada.sticker_packs(), vec![pack.clone()]);
    assert!(
        ada.send_sticker(&mo.root(), &pack.key, 3).await.is_err(),
        "no fourth"
    );

    let sent = ada.send_sticker(&mo.root(), &pack.key, 1).await.unwrap();
    mo.sync().await.unwrap();
    let got = mo
        .messages(&ada.root())
        .unwrap()
        .into_iter()
        .find(|m| m.id == sent.id)
        .expect("arrived");
    assert_eq!(got.sticker, Some(1));
    let att = got.attachment.clone().unwrap();
    assert!(!mo.has_sticker_pack(&att));
    assert_eq!(mo.sticker_picture(&att, 1).await.unwrap(), pics[1]);
    let added = mo.add_sticker_pack(&att).await.unwrap();
    assert_eq!(added.title, "Cats");
    assert!(mo.has_sticker_pack(&att));

    let gid = ada
        .create_group("Trip", &[mo.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;
    let gs = mo.send_group_sticker(&gid, &added.key, 2).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    let at_jo = jo
        .group_messages(&gid)
        .unwrap()
        .into_iter()
        .find(|m| m.id == gs.id)
        .expect("arrived");
    assert_eq!(at_jo.sticker, Some(2));
    assert_eq!(
        jo.sticker_picture(at_jo.attachment.as_ref().unwrap(), 2)
            .await
            .unwrap(),
        pics[2]
    );
}

/// Files in groups: sealed chunks on the sender's server, a reference in
/// the group message; every member downloads and verifies the same bytes.
#[tokio::test(flavor = "multi_thread")]
async fn files_in_groups() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let gid = ada
        .create_group("Trip", &[mo.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;
    let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let sent = mo
        .send_group_file(&gid, "route.gpx", "application/gpx+xml", &data, "The route")
        .await
        .unwrap();
    assert_eq!(
        mo.fetch_group_attachment(&gid, sent.seq).await.unwrap(),
        data
    );
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    for c in [&mut ada, &mut jo] {
        let m = c
            .group_messages(&gid)
            .unwrap()
            .into_iter()
            .find(|m| m.id == sent.id)
            .expect("arrived");
        assert_eq!(m.text, "The route");
        assert_eq!(m.attachment.as_ref().unwrap().name, "route.gpx");
        assert_eq!(c.fetch_group_attachment(&gid, m.seq).await.unwrap(), data);
    }
    mo.delete_group_message(&gid, sent.seq).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    let m = jo
        .group_messages(&gid)
        .unwrap()
        .into_iter()
        .find(|m| m.id == sent.id)
        .unwrap();
    assert!(m.deleted && m.attachment.is_none());
    assert!(jo.fetch_group_attachment(&gid, m.seq).await.is_err());
}

/// Shaped syncing in rounds (09 §9.4): even rounds read the inboxes, odd
/// rounds one group at a time; a client that only ever syncs in rounds
/// still gets everything.
#[tokio::test(flavor = "multi_thread")]
async fn sync_in_rounds() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let g1 = ada
        .create_group("One", &[mo.root(), jo.root()])
        .await
        .unwrap();
    let g2 = ada.create_group("Two", &[mo.root()]).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;

    mo.send_text(&ada.root(), "direct").await.unwrap();
    mo.send_group_text(&g1, "in one").await.unwrap();
    mo.send_group_text(&g2, "in two").await.unwrap();
    // An odd round reads one group only; the inbox waits for an even one.
    let ev = ada.sync_round(1).await.unwrap();
    assert!(ev.iter().all(|e| !matches!(e, Event::Message { .. })));
    let mut all = ev;
    for r in 2..6 {
        all.extend(ada.sync_round(r).await.unwrap());
    }
    assert!(
        all.iter()
            .any(|e| matches!(e, Event::Message { message, .. } if message.text == "direct"))
    );
    let texts = group_texts(&all);
    assert!(
        texts.contains(&"in one".to_string()) && texts.contains(&"in two".to_string()),
        "{texts:?}"
    );

    // In Background groups get one round in four: rounds 0–2 read the
    // inbox only, round 3 a group.
    mo.send_group_text(&g1, "later").await.unwrap();
    for r in 0..3 {
        let ev = ada.sync_round_every(r, 4).await.unwrap();
        assert!(group_texts(&ev).is_empty(), "round {r}: {ev:?}");
    }
    let mut later = Vec::new();
    for r in 3..12 {
        later.extend(ada.sync_round_every(r, 4).await.unwrap());
    }
    assert!(group_texts(&later).contains(&"later".to_string()));
}

/// Counts the polls (2,048-byte requests) and bulk windows a client asks
/// its transport for.
#[derive(Clone)]
struct Counting {
    inner: LocalTransport,
    polls: Arc<std::sync::atomic::AtomicUsize>,
    bulk: Arc<std::sync::atomic::AtomicUsize>,
}

impl Counting {
    fn new(inner: LocalTransport) -> Self {
        Self {
            inner,
            polls: Arc::default(),
            bulk: Arc::default(),
        }
    }
    fn take(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering::SeqCst;
        (self.polls.swap(0, SeqCst), self.bulk.swap(0, SeqCst))
    }
}

#[async_trait::async_trait]
impl enclave_net::transport::Transport for Counting {
    async fn exchange(
        &self,
        server: &enclave_net::transport::ServerId,
        request: Vec<u8>,
    ) -> enclave_net::Result<Vec<u8>> {
        // POLL_LEN (enclave-wire).
        if request.len() == 2_048 {
            self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.exchange(server, request).await
    }
    fn set_bulk(&self, on: bool) {
        if on {
            self.bulk.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    async fn server_key(
        &self,
        server: &enclave_net::transport::ServerId,
    ) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.inner.server_key(server).await
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
}

/// A shaped client reads a group within its poll slots (09 §6.7): a
/// group round is today's message and rekey mailboxes (yesterday's too,
/// early in the day), never a bulk window; and a rekey and the message
/// after it arrive through rounds alone.
#[tokio::test(flavor = "multi_thread")]
async fn group_round_reads_in_slots() {
    let net = network();
    let counted = Counting::new(net.clone());
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut mo, _) = Client::create(memory(), Arc::new(counted.clone()), S2, "Mo")
        .await
        .unwrap();
    let (mut jo, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Jo")
        .await
        .unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    let gid = ada.create_group("G", &[mo.root()]).await.unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;

    // Round 3 with period 2 is a group round, and not an upkeep round.
    counted.take();
    mo.sync_round_every(3, 2).await.unwrap();
    let (polls, bulk) = counted.take();
    assert_eq!(bulk, 0, "a group round opened a bulk window");
    // One epoch: today's message mailbox and 3 rekey buckets (twice that
    // in the first 2 h of the day).
    assert!((4..=8).contains(&polls), "{polls} polls in a group round");

    // A rekey (Jo joins) and a message in the new epoch reach Mo through
    // rounds alone.
    ada.add_group_members(&gid, &[jo.root()]).await.unwrap();
    ada.send_group_text(&gid, "after the rekey").await.unwrap();
    let mut seen = Vec::new();
    for r in 4..20 {
        seen.extend(mo.sync_round_every(r, 2).await.unwrap());
        if group_texts(&seen).contains(&"after the rekey".to_string()) {
            return;
        }
    }
    panic!("the message after the rekey never arrived: {seen:?}");
}

/// Archive, pin to the top and mute: local to this device. A new message
/// brings an archived conversation back unless it is muted; at most four
/// conversations are pinned.
#[tokio::test(flavor = "multi_thread")]
async fn conversation_prefs() {
    use enclave_core::{ConvPrefs, MAX_PINNED_CONVERSATIONS, Place};
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut mo, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Mo")
        .await
        .unwrap();
    connect(&mut ada, &mut mo).await;
    let here = Place::Contact(mo.root());
    let archived = ConvPrefs {
        archived: true,
        ..Default::default()
    };
    ada.set_conv_prefs(&here, archived).unwrap();
    assert!(ada.conv_prefs(&here).archived);
    mo.send_text(&ada.root(), "still there?").await.unwrap();
    ada.sync().await.unwrap();
    assert!(
        !ada.conv_prefs(&here).archived,
        "a new message brings it back"
    );

    let quiet = ConvPrefs {
        archived: true,
        muted: true,
        ..Default::default()
    };
    ada.set_conv_prefs(&here, quiet).unwrap();
    mo.send_text(&ada.root(), "hello?").await.unwrap();
    ada.sync().await.unwrap();
    assert_eq!(ada.conv_prefs(&here), quiet, "muted stays archived");
    assert_eq!(
        mo.conv_prefs(&Place::Contact(ada.root())),
        ConvPrefs::default(),
        "the other side never learns"
    );

    let pin = ConvPrefs {
        pinned: true,
        ..Default::default()
    };
    for i in 0..MAX_PINNED_CONVERSATIONS as u8 {
        ada.set_conv_prefs(&Place::Group([i; 32]), pin).unwrap();
    }
    assert!(ada.set_conv_prefs(&here, pin).is_err(), "four at most");
    ada.set_conv_prefs(&Place::Group([0; 32]), ConvPrefs::default())
        .unwrap();
    ada.set_conv_prefs(&here, pin).unwrap();
    ada.set_conv_prefs(&here, pin).unwrap(); // unchanged: still allowed
}

/// Push (10-push.md): a message to Bob's inbox makes his server schedule
/// one wake per window for his sealed token, released in the next window;
/// the relay opens it to Bob's UnifiedPush endpoint. The server never sees
/// the endpoint, and unregistering stops the wakes.
#[tokio::test(flavor = "multi_thread")]
async fn push_wakes() {
    use enclave_push_relay::{Platform, Relay, RelaySecret};
    let net = network();
    let (mut alice, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Alice")
        .await
        .unwrap();
    let (mut bob, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Bob")
        .await
        .unwrap();
    connect(&mut alice, &mut bob).await;
    let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
    let key = RelaySecret::generate(1, &mut rng).unwrap();
    let public = key.public().clone();
    let mut relay = Relay::new(vec![key]);
    let endpoint = b"http://up.example/bob-phone";
    bob.register_push(&public, Platform::UnifiedPush, endpoint)
        .await
        .unwrap();
    let due = |net: &LocalTransport| {
        let now = net.now();
        net.with_server(&S2, |s| s.due_wakes(now)).unwrap()
    };
    assert!(due(&net).is_empty());

    alice.send_text(&bob.root(), "one").await.unwrap();
    alice.send_text(&bob.root(), "two").await.unwrap();
    assert!(due(&net).is_empty(), "not before the next window");
    net.advance(enclave_server::PUSH_WINDOW_SECS + enclave_server::PUSH_JITTER_SECS + 1);
    let wakes = due(&net);
    assert_eq!(wakes.len(), 1, "one wake for two messages in a window");
    assert!(
        !wakes[0].windows(endpoint.len()).any(|w| w == endpoint),
        "sealed"
    );
    let d = relay.wake(&wakes[0], net.now()).unwrap();
    assert_eq!(
        (d.platform, d.token.as_slice()),
        (Platform::UnifiedPush, &endpoint[..])
    );
    assert!(due(&net).is_empty(), "sent once");

    bob.unregister_push().await.unwrap();
    alice.send_text(&bob.root(), "three").await.unwrap();
    net.advance(3 * enclave_server::PUSH_WINDOW_SECS);
    assert!(due(&net).is_empty());
}

/// Social recovery (03 §8.3): Ada splits her recovery among three
/// contacts, two of whom can rebuild it. After she loses everything, two
/// shares give back her recovery words, and with her backup she restores.
#[tokio::test(flavor = "multi_thread")]
async fn social_recovery() {
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Ben", S2), ("Cy", S1), ("Dee", S2)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap(),
        );
    }
    let words = cs[0].1.join(" ");
    let [mut ada, mut ben, mut cy, mut dee] =
        <[Client; 4]>::try_from(cs.into_iter().map(|c| c.0).collect::<Vec<_>>())
            .ok()
            .unwrap();
    for other in [&mut ben, &mut cy, &mut dee] {
        connect(&mut ada, other).await;
    }
    let holders = [ben.root(), cy.root(), dee.root()];
    assert!(
        ada.give_recovery_shares(&holders, 4).await.is_err(),
        "threshold over count"
    );
    ada.give_recovery_shares(&holders, 2).await.unwrap();
    assert_eq!(ada.recovery_holders(), Some((2, holders.to_vec())));
    for h in [&mut ben, &mut cy, &mut dee] {
        let ev = h.sync().await.unwrap();
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::RecoveryShareReceived { .. }))
        );
        assert!(h.holds_recovery_share(&ada.root()));
    }
    assert!(!ben.holds_recovery_share(&cy.root()));
    let archive = ada.export_backup().unwrap();
    let root = ada.root();
    drop(ada);

    // In person, Ben and Dee each show Ada their share.
    let b = ben.recovery_share_for(&root).unwrap();
    let d = dee.recovery_share_for(&root).unwrap();
    assert!(
        enclave_core::words_from_shares(&[b.as_str()]).is_err(),
        "one isn't enough"
    );
    let rebuilt = enclave_core::words_from_shares(&[b.as_str(), d.as_str()]).unwrap();
    assert_eq!(rebuilt, words);
    let restored = Client::restore(&rebuilt, &archive, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    assert_eq!(restored.root(), root);
}

/// A transport that loses every droppable request, as a busy tick would.
#[derive(Clone)]
struct NoFreeSlots(LocalTransport);

#[async_trait::async_trait]
impl enclave_net::transport::Transport for NoFreeSlots {
    async fn exchange(
        &self,
        server: &enclave_net::transport::ServerId,
        request: Vec<u8>,
    ) -> enclave_net::Result<Vec<u8>> {
        self.0.exchange(server, request).await
    }
    async fn exchange_droppable(
        &self,
        _: &enclave_net::transport::ServerId,
        _: Vec<u8>,
    ) -> enclave_net::Result<Vec<u8>> {
        Err(enclave_net::NetError::Dropped)
    }
    async fn server_key(
        &self,
        server: &enclave_net::transport::ServerId,
    ) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.0.server_key(server).await
    }
    fn now(&self) -> u64 {
        self.0.now()
    }
}

/// Typing indicators (16-features): off by default and both ways; sent as
/// droppable requests, and a dropped one costs nothing but a token.
#[tokio::test(flavor = "multi_thread")]
async fn typing_indicators() {
    let net = network();
    let (mut ada, _) = Client::create(memory(), Arc::new(NoFreeSlots(net.clone())), S1, "Ada")
        .await
        .unwrap();
    let (mut mo, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Mo")
        .await
        .unwrap();
    connect(&mut ada, &mut mo).await;
    async fn sent(s: Option<enclave_core::Sending>) -> Result<(), CoreError> {
        s.expect("typing indicators are on").await
    }
    let typing = |ev: &[Event]| {
        ev.iter()
            .filter_map(|e| match e {
                Event::Typing { on, .. } => Some(*on),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    assert!(!mo.typing_enabled(), "off by default");
    assert!(mo.send_typing(&ada.root(), true).await.unwrap().is_none());

    mo.set_typing_enabled(true).unwrap();
    sent(mo.send_typing(&ada.root(), true).await.unwrap())
        .await
        .unwrap();
    assert!(
        typing(&ada.sync().await.unwrap()).is_empty(),
        "Ada has them off, so she doesn't see Mo's"
    );
    ada.set_typing_enabled(true).unwrap();
    sent(mo.send_typing(&ada.root(), true).await.unwrap())
        .await
        .unwrap();
    sent(mo.send_typing(&ada.root(), false).await.unwrap())
        .await
        .unwrap();
    assert_eq!(typing(&ada.sync().await.unwrap()), vec![true, false]);

    // Ada's transport never has a free slot: hers are all dropped, and the
    // conversation carries on as if they had never been written.
    for _ in 0..3 {
        let r = sent(ada.send_typing(&mo.root(), true).await.unwrap()).await;
        assert!(matches!(r, Err(CoreError::Net(_))), "dropped: {r:?}");
    }
    ada.send_text(&mo.root(), "still here").await.unwrap();
    let ev = mo.sync().await.unwrap();
    assert!(typing(&ev).is_empty());
    assert!(
        mo.messages(&ada.root())
            .unwrap()
            .iter()
            .any(|m| m.text == "still here")
    );
    mo.send_text(&ada.root(), "good").await.unwrap();
    ada.sync().await.unwrap();
    assert!(
        ada.messages(&mo.root())
            .unwrap()
            .iter()
            .any(|m| m.text == "good"),
        "replies still decrypt after the dropped units"
    );

    // Blocked contacts get none.
    mo.block(&ada.root()).await.unwrap();
    assert!(mo.send_typing(&ada.root(), true).await.unwrap().is_none());
}

/// Changing the recovery words (03 §8.2): a new root, signed by both; the
/// contacts rename the old root everywhere, the group takes Ada's own root
/// update without an admin, history, settings and shares carry over, and
/// the old root's codes stop working.
#[tokio::test(flavor = "multi_thread")]
async fn change_recovery_words() {
    use enclave_core::{ConvPrefs, Place};
    let net = network();
    let mut cs = Vec::new();
    for (name, server) in [("Ada", S1), ("Mo", S2), ("Jo", S1)] {
        cs.push(
            Client::create(memory(), Arc::new(net.clone()), server, name)
                .await
                .unwrap()
                .0,
        );
    }
    let [mut ada, mut mo, mut jo] = <[Client; 3]>::try_from(cs).ok().unwrap();
    connect(&mut ada, &mut mo).await;
    connect(&mut ada, &mut jo).await;
    connect(&mut mo, &mut jo).await;
    // Mo's group: Ada is a member, not an admin.
    let gid = mo
        .create_group("Trip", &[ada.root(), jo.root()])
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 3).await;
    ada.send_group_text(&gid, "before").await.unwrap();
    ada.send_text(&mo.root(), "kept").await.unwrap();
    ada.set_timer(&mo.root(), 3600).await.unwrap();
    ada.send_text(&mo.root(), "fading").await.unwrap();
    ada.give_recovery_shares(&[mo.root(), jo.root()], 2)
        .await
        .unwrap();
    settle(&mut [&mut ada, &mut mo, &mut jo], 2).await;
    let old = ada.root();
    mo.set_verified(&old, true).unwrap();
    let muted = ConvPrefs {
        muted: true,
        ..Default::default()
    };
    mo.set_conv_prefs(&Place::Contact(old), muted).unwrap();
    let kept = mo
        .messages(&old)
        .unwrap()
        .into_iter()
        .find(|m| m.text == "kept")
        .unwrap();
    mo.pin_message(&old, kept.seq, true).await.unwrap();
    let old_card = ada.card();

    let words = ada.change_recovery_words().await.unwrap();
    let new = ada.root();
    assert_ne!(new, old);
    assert_eq!(ada.recovery_words().unwrap(), words);
    assert!(
        !ada.migration_pending(),
        "directory, file, shares: all done"
    );
    assert!(
        ada.change_recovery_words().await.is_ok(),
        "and it can be done again"
    );
    let words = ada.recovery_words().unwrap();
    let (old2, new) = (new, ada.root());

    let evs = settle(&mut [&mut mo, &mut jo, &mut ada], 4).await;
    let moved: Vec<_> = evs[0]
        .iter()
        .filter_map(|e| match e {
            Event::ContactMoved {
                old,
                root,
                cross_signed,
            } => Some((*old, *root, *cross_signed)),
            _ => None,
        })
        .collect();
    assert_eq!(moved, vec![(old, old2, true), (old2, new, true)]);

    // Mo knows Ada only by the new root now, unchecked, with everything kept.
    let roots: Vec<_> = mo.contacts().iter().map(|c| c.root).collect();
    assert!(roots.contains(&new) && !roots.contains(&old) && !roots.contains(&old2));
    let c = mo.contacts().into_iter().find(|c| c.root == new).unwrap();
    assert!(!c.verified, "the security code changed");
    assert!(mo.moved(&new).unwrap().cross_signed);
    let texts: Vec<String> = mo
        .messages(&new)
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert!(texts.contains(&"kept".to_string()));
    assert!(
        texts.contains(&"fading".to_string()),
        "disappearing messages are sealed again: {texts:?}"
    );
    assert!(mo.conv_prefs(&Place::Contact(new)).muted);
    assert_eq!(mo.pinned(&Place::Contact(new)).len(), 1);
    mo.set_verified(&new, true).unwrap();
    assert!(mo.moved(&new).is_none(), "checking again clears the notice");

    // The conversation carries on both ways.
    mo.send_text(&new, "still you?").await.unwrap();
    ada.sync().await.unwrap();
    assert!(
        ada.messages(&mo.root())
            .unwrap()
            .iter()
            .any(|m| m.text == "still you?")
    );
    ada.send_text(&mo.root(), "still me").await.unwrap();
    mo.sync().await.unwrap();
    assert!(
        mo.messages(&new)
            .unwrap()
            .iter()
            .any(|m| m.text == "still me")
    );

    // The group took Ada's own update; her old message is hers under the
    // new root, and new ones arrive, including after a rekey.
    for c in [&mo, &jo] {
        let g = c.groups().into_iter().find(|g| g.id == gid).unwrap();
        let members: Vec<_> = g.members.iter().map(|(r, _)| *r).collect();
        assert!(members.contains(&new), "{members:?}");
        assert!(!members.contains(&old));
        let before = c
            .group_messages(&gid)
            .unwrap()
            .into_iter()
            .find(|m| m.text == "before")
            .unwrap();
        assert_eq!(before.from, Some(new));
    }
    net.advance(86_400 + 1);
    ada.send_group_text(&gid, "after").await.unwrap();
    let evs = settle(&mut [&mut mo, &mut jo], 2).await;
    for e in &evs {
        assert!(group_texts(e).contains(&"after".to_string()), "{e:?}");
    }

    // Friends hold shares of the new words.
    let a = mo.recovery_share_for(&new).unwrap();
    let b = jo.recovery_share_for(&new).unwrap();
    let rebuilt = enclave_core::words_from_shares(&[a.as_str(), b.as_str()]).unwrap();
    assert_eq!(rebuilt, words.join(" "));

    // The old root's code leads nowhere.
    let (mut dee, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Dee")
        .await
        .unwrap();
    assert!(dee.add_contact(&old_card, "hi").await.is_err());
}

/// Link a second device to `a` (on server `home`).
#[allow(clippy::panic)]
async fn link_device(a: &mut Client, net: &LocalTransport, home: [u8; 16]) -> Client {
    let mut n = enclave_core::LinkingDevice::start(memory(), Arc::new(net.clone()), home)
        .await
        .unwrap();
    let offer = a.link_prepare(&n.code()).await.unwrap();
    let enclave_core::LinkProgress::Words(words) = n.poll().await.unwrap() else {
        panic!("words")
    };
    let right = offer.choices.iter().position(|c| *c == words).unwrap();
    a.link_confirm(offer, right).await.unwrap();
    assert_eq!(n.poll().await.unwrap(), enclave_core::LinkProgress::Ready);
    n.finish().await.unwrap()
}

fn texts(c: &Client, root: &[u8; 64]) -> Vec<String> {
    c.messages(root)
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect()
}

/// `docs/12-servers.md` §4.4: Ada moves from S1 to S3. Her other device
/// follows; Ben (a contact) is told in his session and writes to S3 with
/// fresh tokens; a message already on its way to S1 still arrives; Cy,
/// holding her card from before the move, and Dee, holding an invite link
/// from before it, reach her on S3 through the record she left on S1; a
/// backup from before the move is refused; the old server keeps no say.
#[tokio::test(flavor = "multi_thread")]
async fn move_to_another_server() {
    const S3: [u8; 16] = [3; 16];
    let net = network();
    net.add_server(enclave_server::Config {
        id: S3,
        effort_request: 4,
        effort_claim: 1,
        effort_blob: 1,
        effort_username: 1,
        ..Default::default()
    })
    .unwrap();
    let (mut a, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    let (mut cy, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Cyrus")
        .await
        .unwrap();
    let (mut dee, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Dee")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    let mut a2 = link_device(&mut a, &net, S1).await;
    settle(&mut [&mut a, &mut a2, &mut b], 2).await;
    let old_card = a.card();
    let old_link = a.create_invite(1).await.unwrap();
    let old_backup = a.export_backup().unwrap();

    // Only the device with the recovery words can move the account.
    assert!(matches!(
        a2.move_home(S3).await,
        Err(CoreError::NotAccepted)
    ));
    a.move_home(S3).await.unwrap();
    assert!(!a.move_pending(), "nothing left to do");
    assert_eq!(a.card().server, S3);
    assert_ne!(a.card().request_inbox, old_card.request_inbox);

    // Ada's other device switches when it reads her note on S1.
    a2.sync().await.unwrap();
    assert_eq!(a2.card().server, S3);
    assert_eq!(a2.card().request_inbox, a.card().request_inbox);

    // Ben wrote before reading her notice: it went to S1, and arrives.
    b.send_text(&a.root(), "on its way to S1").await.unwrap();
    a.sync().await.unwrap();
    assert!(texts(&a, &b.root()).contains(&"on its way to S1".to_string()));

    // Ben reads the notice: from now on he writes to S3.
    b.sync().await.unwrap();
    let ada = b
        .contacts()
        .into_iter()
        .find(|c| c.root == a.root())
        .unwrap();
    assert_eq!(
        (ada.server, ada.request_inbox),
        (S3, a.card().request_inbox)
    );
    b.send_text(&a.root(), "to S3").await.unwrap();
    settle(&mut [&mut a, &mut a2], 1).await;
    assert!(texts(&a, &b.root()).contains(&"to S3".to_string()));
    assert!(texts(&a2, &b.root()).contains(&"to S3".to_string()));
    a.send_text(&b.root(), "welcome to S3").await.unwrap();
    b.sync().await.unwrap();
    assert!(texts(&b, &a.root()).contains(&"welcome to S3".to_string()));

    // Cy has the card from before the move.
    cy.add_contact(&old_card, "found you").await.unwrap();
    let ev = a.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { text, .. } if text == "found you")),
        "{ev:?}"
    );
    let cy_view = cy
        .contacts()
        .into_iter()
        .find(|c| c.root == a.root())
        .unwrap();
    assert_eq!(cy_view.server, S3);
    a.accept(&cy.root()).await.unwrap();
    cy.sync().await.unwrap();
    cy.send_text(&a.root(), "it works").await.unwrap();
    a.sync().await.unwrap();
    assert!(texts(&a, &cy.root()).contains(&"it works".to_string()));
    // Her second device published its prekeys on S3: Cy reached it too.
    a2.sync().await.unwrap();
    assert!(texts(&a2, &cy.root()).contains(&"it works".to_string()));

    // Dee has an invite link from before the move.
    let card = ContactCard::from_link(&old_link).unwrap();
    assert_eq!(card.server, S1);
    dee.add_contact(&card, "via the old link").await.unwrap();
    let ev = a.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { text, .. } if text == "via the old link")),
        "{ev:?}"
    );

    // A backup from before the move names the inboxes she left.
    assert!(matches!(
        Client::restore(
            &words.join(" "),
            &old_backup,
            memory(),
            Arc::new(net.clone())
        )
        .await,
        Err(CoreError::BackupBeforeMove)
    ));
    let fresh = a.export_backup().unwrap();
    let restored = Client::restore(&words.join(" "), &fresh, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    assert_eq!(restored.card().server, S3);
}

/// `docs/12-servers.md` §3.5: a name the operator withdraws, and the name
/// of an account its owner deleted, become tombstones in the log. Lookups
/// say so, nobody can claim them again, and the deleted account's manifest
/// is gone.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawn_usernames() {
    use enclave_core::UsernameError;
    let net = network();
    let policy = net.enable_usernames(&S1, "one.test").unwrap();
    let mut people = Vec::new();
    for name in ["Ada", "Ben", "Cyrus"] {
        let (mut c, _) = Client::create(memory(), Arc::new(net.clone()), S1, name)
            .await
            .unwrap();
        c.set_kt_policy(policy.clone());
        people.push(c);
    }
    let [ada, ben, cy] = people.as_mut_slice() else {
        unreachable!()
    };
    ada.claim_username("ada").await.unwrap();
    ben.claim_username("benjamin").await.unwrap();

    // The operator withdraws "ada" (once; again changes nothing).
    let now = net.now();
    assert!(
        net.with_server(&S1, |s| s.withdraw_username("ADA", now))
            .unwrap()
            .unwrap()
    );
    assert!(
        !net.with_server(&S1, |s| s.withdraw_username("ada", now))
            .unwrap()
            .unwrap()
    );
    let found = cy.find_username("ada").await;
    assert!(
        matches!(found, Err(CoreError::Username(UsernameError::Withdrawn))),
        "{found:?}"
    );
    for (who, name) in [(&mut *cy, "ada"), (&mut *ada, "ada")] {
        let r = who.claim_username(name).await;
        assert!(
            matches!(r, Err(CoreError::Username(UsernameError::Taken))),
            "{r:?}"
        );
    }

    // Ben deletes his account.
    let ben_card = ben.card();
    ben.publish_tombstone().await.unwrap();
    let found = cy.find_username("benjamin").await;
    assert!(
        matches!(found, Err(CoreError::Username(UsernameError::Withdrawn))),
        "{found:?}"
    );
    let r = cy.claim_username("benjamin").await;
    assert!(
        matches!(r, Err(CoreError::Username(UsernameError::Taken))),
        "{r:?}"
    );
    // His account can't be reached any more, or brought back.
    assert!(cy.add_contact(&ben_card, "hello?").await.is_err());
    assert!(ben.claim_username("benjamin2").await.is_err());
}
