//! The datagrams a relay and its clients exchange (`docs/11-calls.md`
//! §3), as the client builds them; `enclave-relay` answers them.
//!
//! ```text
//! T_DESC   ‖ part ‖ zeros to DESC_REQUEST          → T_DESC ‖ part ‖ count ‖ ≤ DESC_PART bytes
//! T_TICKET ‖ id (8) ‖ index ‖ count ‖ ≤ TICKET_PART → T_TICKET ‖ id ‖ sealed ticket reply
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
