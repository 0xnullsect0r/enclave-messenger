//! Red-team matrix rows played in the simulator (`docs/redteam-matrix.md`):
//! real protocol code, real servers, the network as a function call.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::kem::{MlKemSecret, X448Secret};
use enclave_crypto::rng::HedgedRng;
use enclave_proto::envelope;
use enclave_proto::group::{FLAG_STATE_UPDATE, Group, GroupState, RekeyOutcome, RekeyTarget};
use enclave_proto::ratchet::{InitialDh, Role, Session, SessionInit};
use enclave_rpc::api::{self, FLAG_FOUND, Status};
use enclave_sim::{Network, SimUser};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader, UNIT_LEN};
use zeroize::Zeroizing;

const NOW: u64 = enclave_sim::T0;

/// Every envelope in `mailbox` after `cursor`, as its owner (or whoever
/// copied its owner secret) reads them.
fn read_all(
    net: &mut Network,
    server: &[u8; 16],
    mailbox: [u8; 32],
    owner: &[u8; 32],
    mut cursor: u64,
    rng: &mut HedgedRng,
) -> (Vec<Vec<u8>>, u64) {
    let cred = api::read_credential(owner);
    let mut out = Vec::new();
    loop {
        let mut token = [0u8; 32];
        token[..24].copy_from_slice(&cred);
        token[24..].copy_from_slice(&cursor.to_be_bytes());
        let h = RequestHeader {
            op: Op::Poll,
            flags: 0,
            mailbox,
            token,
        };
        let (s, flags, rh, env) = net.call(server, h, &[], rng);
        assert_eq!(s, Status::Ok);
        if flags & FLAG_FOUND == 0 {
            return (out, cursor);
        }
        cursor = u64::from_be_bytes(rh.token[24..].try_into().unwrap());
        out.push(env);
    }
}

// ---------------------------------------------------------------------------
// RT-03
// ---------------------------------------------------------------------------

/// RT-03: a unit tagged on the way (one bit flipped anywhere) fails the
/// seal check at the server and is dropped. Its reply is random bytes of
/// the same length as every real reply, accepted or refused, and changes
/// nothing on the server: a tagging hop downstream sees nothing it could
/// tell apart.
#[test]
fn rt03_rejected_request_gets_no_distinct_reply() {
    let mut rng = HedgedRng::new().unwrap();
    let mut net = Network::new();
    let s = [1u8; 16];
    net.add_server(s, 1);
    let bob = SimUser::create(&mut net, s, 1, &mut rng);
    let key = net.key(&s);
    let env = vec![5u8; ENVELOPE_LEN];
    // A write the server refuses (no such token): its reply is a sealed
    // `Denied`, the size of every reply.
    let write = RequestHeader {
        op: Op::Write,
        flags: 0,
        mailbox: bob.inbox,
        token: [3; 32],
    };
    let (bytes, ex) = enclave_rpc::seal_request(&key, &write, &env, &mut rng).unwrap();
    assert_eq!(bytes.len(), UNIT_LEN);
    let refused = net.servers.get_mut(&s).unwrap().handle(&bytes, NOW);
    assert_eq!(refused.len(), UNIT_LEN);
    let (rh, _) = ex.open_reply(&refused).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Denied);

    let before = net.servers[&s].stats();
    let mut replies = Vec::new();
    for at in [0, 1, 17, 100, 1_000, 4_096, 8_000, 12_000, UNIT_LEN - 100] {
        // A fresh sealing each time (a replay is refused anyway).
        let (mut bytes, ex) = enclave_rpc::seal_request(&key, &write, &env, &mut rng).unwrap();
        bytes[at] ^= 0x10;
        let reply = net.servers.get_mut(&s).unwrap().handle(&bytes, NOW);
        assert_eq!(reply.len(), refused.len(), "byte {at}: same size");
        assert!(ex.open_reply(&reply).is_err(), "byte {at}: not a reply");
        replies.push(reply);
    }
    // Random each time: no fixed bytes that would mark a dropped unit.
    for (i, a) in replies.iter().enumerate() {
        for b in &replies[i + 1..] {
            let same = a.iter().zip(b).filter(|(x, y)| x == y).count();
            assert!(same < UNIT_LEN / 64, "{same} equal bytes");
        }
    }
    let after = net.servers[&s].stats();
    assert_eq!(after.stored, before.stored, "nothing stored");
    assert_eq!(
        after.denied, before.denied,
        "not even processed as a request"
    );
    assert_eq!(after.tokens_burned, before.tokens_burned);
    assert_eq!(after.requests, before.requests + replies.len() as u64);
}

// ---------------------------------------------------------------------------
// RT-21
// ---------------------------------------------------------------------------

/// RT-21: an attacker copies all of Bob's device state (sessions, inbox
/// credentials, vault key) and leaves. It reads what Alice sends next. Once
/// Bob has written to Alice and she has answered (one round trip), the
/// copy opens nothing more: the session healed with randomness the copy
/// never saw.
#[test]
fn rt21_pcs_after_one_round_trip() {
    let mut rng = HedgedRng::new().unwrap();
    let mut net = Network::new();
    let (sa, sb) = ([1u8; 16], [2u8; 16]);
    net.add_server(sa, 1);
    net.add_server(sb, 1);
    let mut alice = SimUser::create(&mut net, sa, 1, &mut rng);
    let mut bob = SimUser::create(&mut net, sb, 1, &mut rng);
    let (a_root, b_root) = (alice.account.root_public.0, bob.account.root_public.0);
    alice.add_contact(&mut net, &bob.card(), b"hi bob", &mut rng);
    bob.contacts.insert(a_root, alice.manifest.clone());
    assert_eq!(bob.process_requests(&mut net, 0, &mut rng).len(), 1);
    let tokens = bob.issue_tokens(&mut net, a_root, 32, &mut rng);
    let hello = enclave_sim::encode_hello(&bob.server, &bob.inbox, &tokens, b"hello alice");
    assert_eq!(bob.send(&mut net, 0, a_root, &hello, &mut rng), Status::Ok);
    let got = alice.receive(&mut net, 0, &mut rng);
    alice.accept_hello(b_root, &got[0]);
    // A while of normal conversation.
    for i in 0..3 {
        let m = format!("a{i}");
        assert_eq!(
            alice.send(&mut net, 0, b_root, m.as_bytes(), &mut rng),
            Status::Ok
        );
        assert_eq!(bob.receive(&mut net, 0, &mut rng), [m.into_bytes()]);
        let r = format!("b{i}");
        assert_eq!(
            bob.send(&mut net, 0, a_root, r.as_bytes(), &mut rng),
            Status::Ok
        );
        assert_eq!(alice.receive(&mut net, 0, &mut rng), [r.into_bytes()]);
    }

    // The copy.
    let mut copy = Copy {
        sessions: bob.devices[0].sessions.values().cloned().collect(),
        cursor: bob.devices[0].cursor,
        owner: bob.inbox_owner,
        inbox: bob.inbox,
        server: sb,
    };

    // Before healing: the copy reads Alice's next message.
    assert_eq!(
        alice.send(&mut net, 0, b_root, b"exposed", &mut rng),
        Status::Ok
    );
    assert_eq!(
        copy.reads(&mut net, &bob.account.vault, &mut rng),
        [b"exposed".to_vec()]
    );
    assert_eq!(bob.receive(&mut net, 0, &mut rng), [b"exposed".to_vec()]);

    // One round trip: Bob writes, Alice answers.
    assert_eq!(bob.send(&mut net, 0, a_root, b"ping", &mut rng), Status::Ok);
    assert_eq!(alice.receive(&mut net, 0, &mut rng), [b"ping".to_vec()]);
    assert_eq!(
        alice.send(&mut net, 0, b_root, b"pong", &mut rng),
        Status::Ok
    );
    // The copy can't follow, even reading everything Bob gets.
    assert!(
        copy.reads(&mut net, &bob.account.vault, &mut rng)
            .is_empty(),
        "healed"
    );
    assert_eq!(bob.receive(&mut net, 0, &mut rng), [b"pong".to_vec()]);
    for i in 0..3 {
        let m = format!("later {i}");
        assert_eq!(
            alice.send(&mut net, 0, b_root, m.as_bytes(), &mut rng),
            Status::Ok
        );
        assert!(
            copy.reads(&mut net, &bob.account.vault, &mut rng)
                .is_empty()
        );
        assert_eq!(bob.receive(&mut net, 0, &mut rng), [m.into_bytes()]);
    }
}

/// A copy of a device's state: its sessions and inbox credentials.
struct Copy {
    sessions: Vec<Session>,
    cursor: u64,
    owner: [u8; 32],
    inbox: [u8; 32],
    server: [u8; 16],
}

impl Copy {
    /// Read everything new in the inbox and open what it can.
    fn reads(
        &mut self,
        net: &mut Network,
        vault: &enclave_crypto::kem::McElieceSecret,
        rng: &mut HedgedRng,
    ) -> Vec<Vec<u8>> {
        let (envs, c) = read_all(net, &self.server, self.inbox, &self.owner, self.cursor, rng);
        self.cursor = c;
        envs.iter()
            .filter_map(|env| {
                let mut s: Vec<&mut Session> = self.sessions.iter_mut().collect();
                envelope::open_direct(&mut s, env, Some(vault), rng)
                    .ok()
                    .map(|o| o.content)
            })
            .collect()
    }
}

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

fn target(member: u8, id: u8, session: &Session) -> RekeyTarget<'_> {
    RekeyTarget {
        member,
        device: 0,
        device_id: [id; 16],
        session,
    }
}

fn apply_any(g: &mut Group, units: &[Vec<u8>], session: &Session) -> Option<RekeyOutcome> {
    for u in units {
        match g.apply_rekey(u, session) {
            Ok(RekeyOutcome::Installed { new_epoch }) => {
                return Some(RekeyOutcome::Installed { new_epoch });
            }
            Ok(RekeyOutcome::NotForUs) => {}
            Err(_) => return None,
        }
    }
    Some(RekeyOutcome::NotForUs)
}

/// One pairwise message `from` → `to`; the attacker's copies of `to`'s
/// session try it too (it sees every unit).
fn direct(from: &mut Session, to: &mut Session, stolen: Option<&mut Session>, rng: &mut HedgedRng) {
    let carry = from.wants_pq_slot().then_some(0);
    let env = envelope::seal_direct(&mut [from], b"pq step", carry, rng).unwrap();
    if let Some(s) = stolen {
        let _ = envelope::open_direct(&mut [s], &env, None, rng);
    }
    assert_eq!(
        envelope::open_direct(&mut [to], &env, None, rng)
            .unwrap()
            .content,
        b"pq step"
    );
}

/// RT-21: an attacker copies Cy's group state and her pairwise sessions,
/// and reads the group. Each of Cy's pairs then takes a PQ round trip (the
/// pre-rekey step), and the next epoch change makes every member rotate:
/// the copy, which saw every unit, can't unwrap the new chains or read a
/// word of what follows. Cy can.
#[test]
fn rt21_group_pcs_after_rekey() {
    let mut rng = HedgedRng::new().unwrap();
    let (ra, rb, rc) = ([1u8; 64], [2u8; 64], [3u8; 64]);
    let (mut s_ab, mut s_ba) = pair(&mut rng);
    let (mut s_ac, mut s_ca) = pair(&mut rng);
    let (mut s_bc, mut s_cb) = pair(&mut rng);
    // Warm the pairs up, as a conversation would.
    for _ in 0..2 {
        direct(&mut s_ab, &mut s_ba, None, &mut rng);
        direct(&mut s_ba, &mut s_ab, None, &mut rng);
        direct(&mut s_ac, &mut s_ca, None, &mut rng);
        direct(&mut s_ca, &mut s_ac, None, &mut rng);
        direct(&mut s_bc, &mut s_cb, None, &mut rng);
        direct(&mut s_cb, &mut s_bc, None, &mut rng);
    }

    let mut a = Group::create("Trip", ra, [9; 16], NOW, &mut rng).unwrap();
    let st = a
        .state
        .child(|s| {
            s.add(rb, false, NOW).unwrap();
            s.add(rc, false, NOW).unwrap();
        })
        .unwrap();
    a.apply_state(st).unwrap();
    a.rotate(&[], None, NOW, &mut rng).unwrap();
    let mut b = Group::join(&a.welcome(1).unwrap(), &rb, 0).unwrap();
    let mut c = Group::join(&a.welcome(2).unwrap(), &rc, 0).unwrap();
    let units = b
        .rotate(
            &[target(0, 0xa0, &s_ba), target(2, 0xc0, &s_bc)],
            None,
            NOW,
            &mut rng,
        )
        .unwrap();
    apply_any(&mut a, &units, &s_ab).unwrap();
    apply_any(&mut c, &units, &s_cb).unwrap();
    let units = c
        .rotate(
            &[target(0, 0xa0, &s_ca), target(1, 0xb0, &s_cb)],
            None,
            NOW,
            &mut rng,
        )
        .unwrap();
    apply_any(&mut a, &units, &s_ac).unwrap();
    apply_any(&mut b, &units, &s_bc).unwrap();

    // The copy.
    let mut x = Group::import(&c.export()).unwrap();
    let (mut x_ca, mut x_cb) = (s_ca.clone(), s_cb.clone());

    let m = a.seal(b"exposed", 0, &mut rng).unwrap();
    assert_eq!(x.open(&m).unwrap().content, b"exposed", "the copy reads");
    assert_eq!(c.open(&m).unwrap().content, b"exposed");
    assert_eq!(b.open(&m).unwrap().content, b"exposed");

    // The pre-rekey PQ step: a round trip on each of Cy's pairs.
    direct(&mut s_ac, &mut s_ca, Some(&mut x_ca), &mut rng);
    direct(&mut s_ca, &mut s_ac, None, &mut rng);
    direct(&mut s_ac, &mut s_ca, Some(&mut x_ca), &mut rng);
    direct(&mut s_bc, &mut s_cb, Some(&mut x_cb), &mut rng);
    direct(&mut s_cb, &mut s_bc, None, &mut rng);
    direct(&mut s_bc, &mut s_cb, Some(&mut x_cb), &mut rng);

    // The next rekey: Ada starts a new epoch, Ben rotates into it.
    let (e1, es1) = a.new_epoch(&mut rng).unwrap();
    let prev = a.state.clone();
    let st = a.state.child(|s| s.epoch = e1).unwrap();
    a.apply_state(st.clone()).unwrap();
    let units = a
        .rotate(
            &[target(1, 0xb0, &s_ab), target(2, 0xc0, &s_ac)],
            Some((e1, es1)),
            NOW,
            &mut rng,
        )
        .unwrap();
    let update = a.seal(&st.encode(), FLAG_STATE_UPDATE, &mut rng).unwrap();
    for (g, s) in [(&mut b, &s_ba), (&mut c, &s_ca)] {
        assert!(matches!(
            apply_any(g, &units, s),
            Some(RekeyOutcome::Installed { new_epoch: Some(e) }) if e == e1
        ));
        let next = GroupState::decode(&g.open(&update).unwrap().content).unwrap();
        assert!(prev.accepts(&next, 0));
        g.apply_state(next).unwrap();
    }
    assert!(
        !matches!(
            apply_any(&mut x, &units, &x_ca),
            Some(RekeyOutcome::Installed { .. })
        ),
        "the copy can't unwrap Ada's new chain"
    );
    assert!(x.open(&update).is_err());
    let units = b
        .rotate(
            &[target(0, 0xa0, &s_ba), target(2, 0xc0, &s_bc)],
            None,
            NOW,
            &mut rng,
        )
        .unwrap();
    apply_any(&mut a, &units, &s_ab).unwrap();
    apply_any(&mut c, &units, &s_cb).unwrap();
    assert!(
        !matches!(
            apply_any(&mut x, &units, &x_cb),
            Some(RekeyOutcome::Installed { .. })
        ),
        "nor Ben's"
    );

    for (sender, text) in [(&mut a, &b"from Ada"[..]), (&mut b, &b"from Ben"[..])] {
        let m = sender.seal(text, 0, &mut rng).unwrap();
        assert_eq!(c.open(&m).unwrap().content, text, "Cy reads it");
        assert!(x.open(&m).is_err(), "the copy doesn't");
    }
}

// ---------------------------------------------------------------------------
// RT-25
// ---------------------------------------------------------------------------

/// RT-25: a request inbox holds at most 100 pending requests (the
/// server's default `request_quota`). A flood beyond that pushes out the
/// oldest, so the inbox never grows and the newest requests (a friend's
/// among them) are still there.
#[test]
fn rt25_request_inbox_caps_at_100() {
    assert_eq!(enclave_server::Config::default().request_quota, 100);
    let mut rng = HedgedRng::new().unwrap();
    let mut net = Network::new();
    let s = [1u8; 16];
    net.add_server(s, 1);
    let bob = SimUser::create(&mut net, s, 1, &mut rng);
    let inbox = bob.card().request_inbox;
    for i in 0..130u32 {
        let mut env = vec![0u8; ENVELOPE_LEN];
        env[..4].copy_from_slice(&i.to_be_bytes());
        let ctx = api::pow_context_request(
            &inbox,
            net.now / 86_400,
            &enclave_crypto::hash::sha3_512(&env),
        );
        let proof = enclave_tokens::solve(&ctx, 1, &mut rng).unwrap();
        let h = RequestHeader {
            op: Op::WriteRequest,
            flags: 0,
            mailbox: inbox,
            token: proof.0,
        };
        assert_eq!(net.call(&s, h, &env, &mut rng).0, Status::Ok, "request {i}");
    }
    let (held, _) = read_all(&mut net, &s, inbox, &bob.request_owner, 0, &mut rng);
    assert_eq!(held.len(), 100, "capped at 100");
    let order: Vec<u32> = held
        .iter()
        .map(|e| u32::from_be_bytes(e[..4].try_into().unwrap()))
        .collect();
    assert_eq!(
        order,
        (30..130).collect::<Vec<_>>(),
        "the oldest went first"
    );
}
