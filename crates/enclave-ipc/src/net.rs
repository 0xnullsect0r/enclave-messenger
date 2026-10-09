//! Messages between the vault and `netd` (`docs/15-client.md` §1.1a).
//!
//! `netd` holds no keys: it only carries sealed requests to servers and
//! their sealed replies back, and fetches servers' public request keys. The
//! vault numbers requests so several can be in flight.

use crate::codec::{MAX_BYTES, Reader, Writer};
use crate::{IpcError, Result};

/// Most ticketbooks one `Connect` carries.
pub const MAX_TICKETBOOKS: usize = 64;

/// Vault → netd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetRequest {
    /// Send a sealed request to a server and return its sealed reply.
    Exchange {
        /// Request number.
        id: u32,
        /// Server.
        server: [u8; 16],
        /// Sealed request.
        bytes: Vec<u8>,
    },
    /// Fetch a server's current request key (`key_id ‖ x448 ‖ mlkem`).
    ServerKey {
        /// Request number.
        id: u32,
        /// Server.
        server: [u8; 16],
    },
    /// Send a sealed unit that needs no answer
    /// (`Transport::exchange_oneway`). The reply is empty when it went one
    /// way (over the mixnet), else the server's reply.
    Oneway {
        /// Request number.
        id: u32,
        /// Server.
        server: [u8; 16],
        /// Sealed unit.
        bytes: Vec<u8>,
    },
    /// Reach a server by this route from now on (`HOST:PORT` or
    /// `nym:ADDRESS`, as in netd's `--server`). No reply.
    SetRoute {
        /// Server.
        server: [u8; 16],
        /// Route.
        route: String,
    },
    /// Pace the mixnet client from now on (`enclave_nym::Pacing::encode`,
    /// `docs/09-transport.md` §6.3). No reply.
    SetPacing {
        /// The encoded pacing.
        pacing: Vec<u8>,
    },
    /// Use only the private route (Maximum privacy,
    /// `Transport::require_private`): no TCP route, and nothing without
    /// Tor. No reply.
    RequirePrivate {
        /// On or off.
        on: bool,
    },
    /// HTTP through the mixnet client's Tor (the credential gate,
    /// `docs/09-transport.md` §7). The reply is `u16 status ‖ body`.
    Fetch {
        /// Request number.
        id: u32,
        /// `GET` or `POST`.
        method: String,
        /// The URL.
        url: String,
        /// The body.
        body: Vec<u8>,
    },
    /// Buy one zk-nym ticketbook from the credential gate at `gate` with
    /// one Privacy Pass token. The reply is the ticketbook, to keep.
    BuyTickets {
        /// Request number.
        id: u32,
        /// The gate's base URL.
        gate: String,
        /// The token.
        token: Vec<u8>,
    },
    /// Connect the mixnet client, spending these ticketbooks (netd started
    /// with `--await-tickets`). The reply is empty, or why it couldn't.
    Connect {
        /// Request number.
        id: u32,
        /// Ticketbooks, as `BuyTickets` returned them.
        tickets: Vec<Vec<u8>>,
    },
}

/// netd → vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetReply {
    /// The request it answers.
    pub id: u32,
    /// Reply bytes, or why there are none.
    pub result: core::result::Result<Vec<u8>, String>,
}

impl NetRequest {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            NetRequest::Exchange { id, server, bytes } => {
                w.u8(1).u32(*id).bytes(server).bytes(bytes);
            }
            NetRequest::ServerKey { id, server } => {
                w.u8(2).u32(*id).bytes(server);
            }
            NetRequest::SetRoute { server, route } => {
                w.u8(3).bytes(server).str(route);
            }
            NetRequest::Oneway { id, server, bytes } => {
                w.u8(4).u32(*id).bytes(server).bytes(bytes);
            }
            NetRequest::SetPacing { pacing } => {
                w.u8(5).bytes(pacing);
            }
            NetRequest::RequirePrivate { on } => {
                w.u8(6).u8(u8::from(*on));
            }
            NetRequest::Fetch {
                id,
                method,
                url,
                body,
            } => {
                w.u8(7).u32(*id).str(method).str(url).bytes(body);
            }
            NetRequest::BuyTickets { id, gate, token } => {
                w.u8(8).u32(*id).str(gate).bytes(token);
            }
            NetRequest::Connect { id, tickets } => {
                w.u8(9).u32(*id).u32(tickets.len() as u32);
                for t in tickets {
                    w.bytes(t);
                }
            }
        }
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let server = |r: &mut Reader<'_>| -> Result<[u8; 16]> {
            r.bytes()?.try_into().map_err(|_| IpcError::Malformed)
        };
        let v = match r.u8()? {
            1 => NetRequest::Exchange {
                id: r.u32()?,
                server: server(&mut r)?,
                bytes: r.bytes()?,
            },
            2 => NetRequest::ServerKey {
                id: r.u32()?,
                server: server(&mut r)?,
            },
            3 => NetRequest::SetRoute {
                server: server(&mut r)?,
                route: r.str()?,
            },
            4 => NetRequest::Oneway {
                id: r.u32()?,
                server: server(&mut r)?,
                bytes: r.bytes()?,
            },
            5 => NetRequest::SetPacing { pacing: r.bytes()? },
            6 => NetRequest::RequirePrivate {
                on: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(IpcError::Malformed),
                },
            },
            7 => NetRequest::Fetch {
                id: r.u32()?,
                method: r.str()?,
                url: r.str()?,
                body: r.bytes()?,
            },
            8 => NetRequest::BuyTickets {
                id: r.u32()?,
                gate: r.str()?,
                token: r.bytes()?,
            },
            9 => {
                let id = r.u32()?;
                let n = r.u32()? as usize;
                if n > MAX_TICKETBOOKS {
                    return Err(IpcError::Malformed);
                }
                let mut tickets = Vec::with_capacity(n);
                for _ in 0..n {
                    tickets.push(r.bytes()?);
                }
                NetRequest::Connect { id, tickets }
            }
            _ => return Err(IpcError::Malformed),
        };
        r.end()?;
        Ok(v)
    }
}

impl NetReply {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.id);
        match &self.result {
            Ok(b) => {
                w.u8(0).bytes(&b[..b.len().min(MAX_BYTES)]);
            }
            Err(e) => {
                w.u8(1).str(e);
            }
        }
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let id = r.u32()?;
        let result = match r.u8()? {
            0 => Ok(r.bytes()?),
            1 => Err(r.str()?),
            _ => return Err(IpcError::Malformed),
        };
        r.end()?;
        Ok(Self { id, result })
    }
}
