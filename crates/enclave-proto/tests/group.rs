//! Groups: rekey broadcast, MAC vectors, removal, and a 100 × 5 rotation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::kem::{MlKemSecret, X448Secret};
use enclave_crypto::rng::HedgedRng;
use enclave_proto::ProtoError;
use enclave_proto::group::{FLAG_STATE_UPDATE, Group, GroupState, RekeyOutcome, RekeyTarget};
use enclave_proto::ratchet::{InitialDh, Role, Session, SessionInit};
use zeroize::Zeroizing;

const NOW: u64 = 1_790_000_000;

/// A pairwise session pair without the (slow) full handshake.
fn pair(rng: &mut HedgedRng) -> (Session, Session) {
    let sk: [u8; 64] = rng.array("test").unwrap();
    let (spk, spk_pub) = X448Secret::generate(rng).unwrap();
    let (auth_sk, auth_pk) = MlKemSecret::generate(rng).unwrap();
    let (b_sk, b_pk) = MlKemSecret::generate(rng).unwrap();
    let a = Session::new(
        SessionInit {
            sk: Zeroizing::new(sk),
            role: Role::Initiator,
            initial_dh: InitialDh::Initiator(spk_pub),
            my_pq: (0, auth_sk, auth_pk.clone()),
            peer_pq: None,
            three_kem: true,
            braid_to: None,
        },
        rng,
    )
    .unwrap();
    let b = Session::new(
        SessionInit {
            sk: Zeroizing::new(sk),
            role: Role::Responder,
            initial_dh: InitialDh::Responder(spk),
            my_pq: (1, b_sk, b_pk),
            peer_pq: Some((0, auth_pk)),
            three_kem: true,
            braid_to: None,
        },
        rng,
    )
    .unwrap();
    (a, b)
}

fn apply_any(g: &mut Group, units: &[Vec<u8>], session: &Session) -> RekeyOutcome {
    for u in units {
        if let RekeyOutcome::Installed { new_epoch } = g.apply_rekey(u, session).unwrap() {
            return RekeyOutcome::Installed { new_epoch };
        }
    }
    RekeyOutcome::NotForUs
}

#[test]
fn three_members_rekey_chat_remove() {
    let mut rng = HedgedRng::new().unwrap();
    let (ra, rb, rc) = ([1u8; 64], [2u8; 64], [3u8; 64]);
    // Pairwise sessions: s_xy is x's session with y.
    let (s_ab, s_ba) = pair(&mut rng);
    let (s_ac, s_ca) = pair(&mut rng);
    let (s_bc, s_cb) = pair(&mut rng);

    // A creates the group and adds B and C.
    let mut a = Group::create("Book club", ra, [9; 16], NOW, &mut rng).unwrap();
    let st = a
        .state
        .child(|s| {
            s.add(rb, false, NOW).unwrap();
            s.add(rc, false, NOW).unwrap();
        })
        .unwrap();
    assert!(a.state.accepts(&st, 0));
    a.apply_state(st).unwrap();
    assert!(a.needs_rotation(NOW));
    a.rotate(&[], None, NOW, &mut rng).unwrap();
    let mut b = Group::join(&a.welcome(1).unwrap(), &rb, 0).unwrap();
    let mut c = Group::join(&a.welcome(2).unwrap(), &rc, 0).unwrap();
    assert_eq!(b.state, a.state);

    // B and C rotate; everyone installs their chains from the 3-unit broadcast.
    let units = b
        .rotate(
            &[
                RekeyTarget {
                    member: 0,
                    device: 0,
                    device_id: [0xa0; 16],
                    session: &s_ba,
                },
                RekeyTarget {
                    member: 2,
                    device: 0,
                    device_id: [0xc0; 16],
                    session: &s_bc,
                },
            ],
            None,
            NOW,
            &mut rng,
        )
        .unwrap();
    assert_eq!(units.len(), 3);
    assert!(units.iter().all(|u| u.len() == enclave_wire::ENVELOPE_LEN));
    assert_eq!(a.rekey_sender(&units[0]).unwrap().0.member, 1);
    assert_eq!(
        apply_any(&mut a, &units, &s_ab),
        RekeyOutcome::Installed { new_epoch: None }
    );
    assert_eq!(
        apply_any(&mut c, &units, &s_cb),
        RekeyOutcome::Installed { new_epoch: None }
    );
    let units = c
        .rotate(
            &[
                RekeyTarget {
                    member: 0,
                    device: 0,
                    device_id: [0xa0; 16],
                    session: &s_ca,
                },
                RekeyTarget {
                    member: 1,
                    device: 0,
                    device_id: [0xb0; 16],
                    session: &s_cb,
                },
            ],
            None,
            NOW,
            &mut rng,
        )
        .unwrap();
    assert!(matches!(
        apply_any(&mut a, &units, &s_ac),
        RekeyOutcome::Installed { .. }
    ));
    assert!(matches!(
        apply_any(&mut b, &units, &s_bc),
        RekeyOutcome::Installed { .. }
    ));

    // Messages in every direction.
    let m = a.seal(b"hello from A", 0, &mut rng).unwrap();
    assert_eq!(b.open(&m).unwrap().content, b"hello from A");
    let got = c.open(&m).unwrap();
    assert_eq!((got.member, got.own_account), (0, false));
    assert!(
        matches!(c.open(&m), Err(ProtoError::Missing | ProtoError::Counter)),
        "replay rejected"
    );
    let m2 = b.seal(b"hi A and C", 0, &mut rng).unwrap();
    assert_eq!(a.open(&m2).unwrap().content, b"hi A and C");
    let got = c.open(&m2).unwrap();
    assert_eq!(got.state_hash, c.state.hash(), "same state");
    assert!(c.missing(&got).is_empty(), "C has seen everything B has");

    // Tampering with the body or with C's MAC entry fails before decryption.
    let m3 = a.seal(b"third", 0, &mut rng).unwrap();
    let mut bad = m3.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(matches!(b.open(&bad), Err(ProtoError::Crypto)));
    let mut bad = m3.clone();
    bad[enclave_wire::group::MACS + 16] ^= 1; // entry for member 2 (C) from sender 0
    assert!(matches!(c.open(&bad), Err(ProtoError::Crypto)));
    assert_eq!(b.open(&m3).unwrap().content, b"third");
    assert_eq!(c.open(&m3).unwrap().content, b"third");

    // A removes C: new epoch, rekey only to B, then a state update message.
    let (e1, es1) = a.new_epoch(&mut rng).unwrap();
    let st = a
        .state
        .child(|s| {
            s.remove(2);
            s.epoch = e1;
        })
        .unwrap();
    let prev = a.state.clone();
    a.apply_state(st.clone()).unwrap();
    let units = a
        .rotate(
            &[RekeyTarget {
                member: 1,
                device: 0,
                device_id: [0xb0; 16],
                session: &s_ab,
            }],
            Some((e1, es1)),
            NOW,
            &mut rng,
        )
        .unwrap();
    let update = a.seal(&st.encode(), FLAG_STATE_UPDATE, &mut rng).unwrap();

    assert_eq!(
        apply_any(&mut b, &units, &s_ba),
        RekeyOutcome::Installed {
            new_epoch: Some(e1)
        }
    );
    assert_eq!(
        apply_any(&mut c, &units, &s_ca),
        RekeyOutcome::NotForUs,
        "removed member gets nothing"
    );
    let got = b.open(&update).unwrap();
    assert_eq!(got.flags & FLAG_STATE_UPDATE, FLAG_STATE_UPDATE);
    let next = GroupState::decode(&got.content).unwrap();
    assert!(prev.accepts(&next, got.member));
    b.apply_state(next).unwrap();
    assert!(
        matches!(c.open(&update), Err(ProtoError::Missing)),
        "C cannot read the new epoch"
    );

    // B must rotate in the new epoch before sending; C can read none of it.
    assert!(b.needs_rotation(NOW));
    assert!(b.seal(b"too early", 0, &mut rng).is_err());
    let units = b
        .rotate(
            &[RekeyTarget {
                member: 0,
                device: 0,
                device_id: [0xa0; 16],
                session: &s_ba,
            }],
            None,
            NOW,
            &mut rng,
        )
        .unwrap();
    assert!(matches!(
        apply_any(&mut a, &units, &s_ab),
        RekeyOutcome::Installed { new_epoch: None }
    ));
    let m = b.seal(b"just us now", 0, &mut rng).unwrap();
    assert_eq!(a.open(&m).unwrap().content, b"just us now");
    assert!(c.open(&m).is_err());
    assert_ne!(
        a.mailbox(1).unwrap(),
        c.mailbox(1).unwrap(),
        "new mailbox address"
    );
}

#[test]
fn hundred_members_five_devices_rotation_is_three_units() {
    let mut rng = HedgedRng::new().unwrap();
    let roots: Vec<[u8; 64]> = (0..100u8).map(|i| [i.wrapping_add(1); 64]).collect();
    let mut admin = Group::create("Big", roots[0], [9; 16], NOW, &mut rng).unwrap();
    let st = admin
        .state
        .child(|s| {
            for r in &roots[1..] {
                s.add(*r, false, NOW).unwrap();
            }
        })
        .unwrap();
    admin.apply_state(st).unwrap();
    admin.rotate(&[], None, NOW, &mut rng).unwrap();
    assert!(
        admin
            .state
            .clone()
            .child(|s| {
                assert!(
                    s.add([0xff; 64], false, NOW).is_err(),
                    "101st member refused"
                );
            })
            .is_ok()
    );

    // Every device except the sender itself: 100 × 5 − 1 = 499 targets.
    let mut sessions = Vec::new();
    let mut members = Vec::new();
    for m in 0..100u8 {
        for d in 0..5u8 {
            if (m, d) == (0, 0) {
                continue;
            }
            let (ours, theirs) = pair(&mut rng);
            let g = Group::join(&admin.welcome(m).unwrap(), &roots[m as usize], d).unwrap();
            sessions.push(ours);
            members.push((
                m,
                d,
                [m ^ 0x5a, d, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
                g,
                theirs,
            ));
        }
    }
    let targets: Vec<RekeyTarget<'_>> = members
        .iter()
        .zip(&sessions)
        .map(|((m, d, id, _, _), s)| RekeyTarget {
            member: *m,
            device: *d,
            device_id: *id,
            session: s,
        })
        .collect();
    let units = admin.rotate(&targets, None, NOW, &mut rng).unwrap();
    assert_eq!(units.len(), 3, "a rotation costs exactly three units");
    let msg = admin.seal(b"to everyone", 0, &mut rng).unwrap();
    let mut own = 0;
    for (m, _, id, g, theirs) in members.iter_mut() {
        // Each device reads its own bucket first.
        let (b, _) = g.my_rekey_mailbox(0, id, 1).unwrap();
        let order = [b as usize, (b as usize + 1) % 3, (b as usize + 2) % 3];
        let installed = order.iter().any(|&i| {
            matches!(
                g.apply_rekey(&units[i], theirs).unwrap(),
                RekeyOutcome::Installed { .. }
            )
        });
        assert!(installed, "member {m} found its entry");
        let got = g.open(&msg).unwrap();
        assert_eq!(got.content, b"to everyone");
        own += usize::from(got.own_account);
    }
    assert_eq!(own, 4, "our other four devices see it as our own");
}

/// A device handed the group by another device of its account reads what
/// that device sends from then on (as our own), and starts a chain of its
/// own before sending.
#[test]
fn hand_over_to_another_device() {
    let mut rng = HedgedRng::new().unwrap();
    let mut first = Group::create("Ours", [1; 64], [9; 16], NOW, &mut rng).unwrap();
    first.rotate(&[], None, NOW, &mut rng).unwrap();
    let earlier = first.seal(b"before", 0, &mut rng).unwrap();
    let mut second = Group::import(&first.hand_over(1).unwrap()).unwrap();
    assert_eq!((second.me, second.my_device), (0, 1));
    let msg = first.seal(b"after", 0, &mut rng).unwrap();
    let got = second.open(&msg).unwrap();
    assert_eq!(got.content, b"after");
    assert!(got.own_account, "from our own account");
    assert!(
        second.open(&earlier).is_err(),
        "nothing from before the hand-over"
    );
    // Its own chain comes from its own rotation.
    assert!(second.seal(b"mine", 0, &mut rng).is_err());
    second.rotate(&[], None, NOW, &mut rng).unwrap();
    assert!(second.seal(b"mine", 0, &mut rng).is_ok());
}
