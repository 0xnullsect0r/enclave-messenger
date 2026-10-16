//! The datagrams a relay and its clients exchange (`docs/11-calls.md`
//! §3), as the client builds them; `enclave-relay` answers them.
//!
//! ```text
//! T_DESC   ‖ part ‖ zeros to DESC_REQUEST          → T_DESC ‖ part ‖ count ‖ ≤ DESC_PART bytes
//! T_TICKET ‖ id (8) ‖ index ‖ count ‖ ≤ TICKET_PART → T_TICKET ‖ id ‖ sealed ticket reply
//! T_REFLECT ‖ nonce (8) ‖ zeros to REFLECT_REQUEST → T_REFLECT ‖ nonce ‖ len ‖ "IP:PORT" seen
//! WireGuard (types 1–4)                             payloads: P_JOIN, P_MEDIA, P_KEEPALIVE
//! ```

use std::net::SocketAddr;

/// Datagram type: relay link (from a peer relay's address only).
pub const T_RELAY: u8 = 0x02;
/// Datagram type: a ticket request part, or a ticket reply. (A WireGuard
/// datagram starts with its type, 1 to 4, then three zero bytes.)
pub const T_TICKET: u8 = 0x10;
/// Datagram type: a request for one part of the signed descriptor, or
/// that part.
pub const T_DESC: u8 = 0x11;
/// Datagram type: what address did this come from? (Direct mode's
/// candidates, `docs/11-calls.md` §4: the relay is the only STUN server.)
pub const T_REFLECT: u8 = 0x12;
/// A reflect request is padded to this many bytes, more than any answer.
pub const REFLECT_REQUEST: usize = 64;
/// A descriptor request is padded to this many bytes, so the relay never
/// answers with more than it was sent (no amplification).
pub const DESC_REQUEST: usize = 1100;
/// Bytes of the descriptor in one reply datagram.
pub const DESC_PART: usize = 1024;
/// Most parts a descriptor is sent in.
pub const MAX_DESC_PARTS: usize = 32;
/// Bytes of a ticket request in one datagram.
pub const TICKET_PART: usize = 1024;
/// Proof-of-work effort a relay asks for a ticket, by default.
pub const TICKET_EFFORT: u32 = 16;
/// Link payload: join a rendezvous.
pub const P_JOIN: u8 = 0x10;
/// Link payload: a media packet.
pub const P_MEDIA: u8 = 0x11;
/// Link payload: keepalive.
pub const P_KEEPALIVE: u8 = 0x12;
/// Link payload: join a group call's rendezvous (as [`P_JOIN`]); the
/// relay then sends this session its downlink in [`P_BUNDLE`]s.
pub const P_JOIN_GROUP: u8 = 0x13;
/// Link payload (relay → client, group calls): packets bundled into one
/// fixed-size payload, `P_BUNDLE ‖ count ‖ (u16 len ‖ packet)… ‖ zeros`.
pub const P_BUNDLE: u8 = 0x14;
/// Bytes of a bundle payload: room for one video packet with its framing.
pub const BUNDLE_LEN: usize = 1300;
/// Microseconds between a group session's bundles: about 2.5 Mbit/s
/// downlink, whatever the call carries (`docs/11-calls.md` §8).
pub const BUNDLE_INTERVAL_US: u64 = 4_000;

/// Relay helper: as many queued packets as fit, bundled and padded to
/// [`BUNDLE_LEN`], from the first queue before the next (audio before
/// video: past the downlink budget, pictures wait, voices don't).
pub fn bundle(queues: &mut [&mut std::collections::VecDeque<Vec<u8>>]) -> Vec<u8> {
    let mut v = vec![P_BUNDLE, 0];
    for queue in queues.iter_mut() {
        while let Some(p) = queue.front() {
            if v.len() + 2 + p.len() > BUNDLE_LEN || v[1] == u8::MAX {
                break;
            }
            let Some(p) = queue.pop_front() else { break };
            v.extend_from_slice(&(p.len() as u16).to_be_bytes());
            v.extend_from_slice(&p);
            v[1] += 1;
        }
    }
    v.resize(BUNDLE_LEN, 0);
    v
}

/// Client helper: the packets in a bundle.
pub fn unbundle(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let [P_BUNDLE, count, rest @ ..] = b else {
        return out;
    };
    let mut at = 0;
    for _ in 0..*count {
        let Some(len) = rest.get(at..at + 2) else {
            break;
        };
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        let Some(p) = rest.get(at + 2..at + 2 + len) else {
            break;
        };
        out.push(p);
        at += 2 + len;
    }
    out
}

/// Encode a join payload: rendezvous id and the peer relay's address.
pub fn join_payload(rendezvous: &[u8; 16], peer: SocketAddr) -> Vec<u8> {
    let mut v = vec![P_JOIN];
    v.extend_from_slice(rendezvous);
    let s = peer.to_string();
    v.push(s.len() as u8);
    v.extend_from_slice(s.as_bytes());
    v
}

/// Relay helper: a join payload's rendezvous id and peer relay.
pub fn decode_join(b: &[u8]) -> Result<([u8; 16], SocketAddr), crate::CallError> {
    let rv: [u8; 16] = b
        .get(..16)
        .ok_or(crate::CallError::Malformed)?
        .try_into()
        .map_err(|_| crate::CallError::Malformed)?;
    let n = usize::from(*b.get(16).ok_or(crate::CallError::Malformed)?);
    let s = std::str::from_utf8(b.get(17..17 + n).ok_or(crate::CallError::Malformed)?)
        .map_err(|_| crate::CallError::Malformed)?;
    Ok((rv, s.parse().map_err(|_| crate::CallError::Malformed)?))
}

/// Client helper: the request for part `part` of a relay's descriptor.
pub fn descriptor_request(part: u8) -> Vec<u8> {
    let mut v = vec![0u8; DESC_REQUEST];
    v[0] = T_DESC;
    v[1] = part;
    v
}

/// Client helper: a descriptor reply's part number, part count and bytes.
pub fn descriptor_part(dg: &[u8]) -> Option<(usize, usize, &[u8])> {
    match dg {
        [T_DESC, part, count, rest @ ..]
            if part < count && usize::from(*count) <= MAX_DESC_PARTS && rest.len() <= DESC_PART =>
        {
            Some((usize::from(*part), usize::from(*count), rest))
        }
        _ => None,
    }
}

/// Client helper: a ticket request as the datagrams that carry it.
pub fn ticket_datagrams(id: [u8; 8], request: &[u8]) -> Vec<Vec<u8>> {
    let parts: Vec<&[u8]> = request.chunks(TICKET_PART).collect();
    let count = parts.len() as u8;
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| [&[T_TICKET][..], &id, &[i as u8, count], p].concat())
        .collect()
}

/// Client helper: a ticket reply datagram's request id and reply.
pub fn ticket_reply(dg: &[u8]) -> Option<([u8; 8], &[u8])> {
    match dg {
        [T_TICKET, rest @ ..] if rest.len() > 8 => Some((rest[..8].try_into().ok()?, &rest[8..])),
        _ => None,
    }
}

/// Client helper: a request for the address a relay sees us at.
pub fn reflect_request(nonce: [u8; 8]) -> Vec<u8> {
    let mut v = vec![0u8; REFLECT_REQUEST];
    v[0] = T_REFLECT;
    v[1..9].copy_from_slice(&nonce);
    v
}

/// Relay helper: the answer to a reflect request from `from`.
pub fn reflect_reply(dg: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    if dg.len() < REFLECT_REQUEST || dg.first() != Some(&T_REFLECT) {
        return None;
    }
    let seen = from.to_string();
    let mut v = vec![T_REFLECT];
    v.extend_from_slice(&dg[1..9]);
    v.push(seen.len() as u8);
    v.extend_from_slice(seen.as_bytes());
    Some(v)
}

/// Client helper: a reflect answer's nonce and the address it names.
pub fn reflected(dg: &[u8]) -> Option<([u8; 8], SocketAddr)> {
    match dg {
        [T_REFLECT, rest @ ..] if rest.len() > 9 => {
            let nonce: [u8; 8] = rest[..8].try_into().ok()?;
            let n = usize::from(rest[8]);
            let s = std::str::from_utf8(rest.get(9..9 + n)?).ok()?;
            Some((nonce, s.parse().ok()?))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn bundles_have_one_size_and_carry_what_fits() {
        use std::collections::VecDeque;
        let mut audio: VecDeque<Vec<u8>> = [vec![1u8; 160], vec![3u8; 160]].into_iter().collect();
        let mut video: VecDeque<Vec<u8>> = [vec![2u8; 1200]].into_iter().collect();
        let a = bundle(&mut [&mut audio, &mut video]);
        assert_eq!(a.len(), BUNDLE_LEN);
        assert_eq!(
            unbundle(&a),
            vec![&[1u8; 160][..], &[3u8; 160][..]],
            "voices first"
        );
        let b = bundle(&mut [&mut audio, &mut video]);
        assert_eq!(unbundle(&b), vec![&[2u8; 1200][..]]);
        let empty = bundle(&mut [&mut audio, &mut video]);
        assert_eq!(empty.len(), BUNDLE_LEN);
        assert!(unbundle(&empty).is_empty());
        assert!(unbundle(&[P_BUNDLE, 9, 0, 200]).is_empty());
    }

    #[test]
    fn reflect_answers_with_the_address_and_never_more_than_it_was_sent() {
        let from: SocketAddr = "[2001:db8::1234:5678:9abc:def0]:65535".parse().unwrap();
        let req = reflect_request([7; 8]);
        let reply = reflect_reply(&req, from).unwrap();
        assert!(reply.len() <= req.len());
        assert_eq!(reflected(&reply), Some(([7; 8], from)));
        assert!(reflect_reply(&req[..10], from).is_none());
        assert!(reflected(&req).is_none());
    }
}
