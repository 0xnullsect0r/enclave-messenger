//! Blob uploads paid with Privacy Pass tokens (`docs/09-transport.md` §9).
//!
//! A server lets its own accounts upload: the request inbox proves the
//! account, and buys up to `BLOB_ISSUE_MAX` blind tokens at a time, at most
//! the server's `blob_tokens_per_day` a day (`BlobAlloc` issue). Spending a
//! token (`BlobAlloc` redeem, with a random mailbox and token) buys an
//! allocation of `ALLOC_CHUNKS` chunk uploads for a day, and each
//! `BlobPut` carries the allocation's secret. Tokens are unlinkable to
//! their issue, so the server can't tell which account an upload is from,
//! only that it paid.
//!
//! The issuer key is the one the server's KT-checked descriptor lists for
//! the month when we hold the descriptor; otherwise the first key the
//! server names for a month is pinned (`NS_BLOB` `pin`), and a different
//! one for the same month later is refused, so the server can't give each
//! account its own key to tell redemptions apart (RT-17).

use super::Client;
use crate::{CoreError, Result};
use enclave_net::transport::ServerId;
use enclave_proto::codec::{Reader, Writer};
use enclave_rpc::api::{
    self, BLOB_ISSUE_MAX, BlobAlloc, BlobAllocReply, PP_REQUEST_LEN, PP_TOKEN_LEN, Status,
};
use enclave_tokens::privpass::{IssuerPublic, Pending, blob_challenge};

const NS_BLOB: &str = "blob-quota";

fn key(kind: &[u8], server: &ServerId, epoch: Option<u32>) -> Vec<u8> {
    let mut k = [kind, server].concat();
    if let Some(e) = epoch {
        k.extend_from_slice(&e.to_be_bytes());
    }
    k
}

/// An allocation: `alloc ‖ u32 uploads left ‖ u64 expires`.
struct Alloc {
    secret: [u8; 32],
    left: u32,
    expires: u64,
}

impl Client {
    /// Upload a blob chunk to `host`, under an allocation.
    pub(crate) async fn put_chunk(
        &mut self,
        host: &ServerId,
        id: [u8; 32],
        chunk: &[u8],
        now: u64,
    ) -> Result<()> {
        // A second try with a fresh allocation if the server lost ours.
        for _ in 0..2 {
            let mut a = self.allocation(host, now).await?;
            match self
                .rpc
                .blob_put(host, id, chunk, a.secret, now, &mut self.rng)
                .await
            {
                Ok(()) => {
                    a.left = a.left.saturating_sub(1);
                    return self.save_alloc(host, &a);
                }
                Err(CoreError::Server(Status::Quota)) => {
                    self.store.delete(NS_BLOB, &key(b"alloc", host, None))?;
                }
                Err(e) => return Err(e),
            }
        }
        Err(CoreError::Server(Status::Quota))
    }

    /// An allocation with uploads left, buying one with a token if needed.
    async fn allocation(&mut self, host: &ServerId, now: u64) -> Result<Alloc> {
        if let Some(b) = self.store.get(NS_BLOB, &key(b"alloc", host, None))? {
            let mut r = Reader::new(&b);
            let a = Alloc {
                secret: r.array()?,
                left: r.u32()?,
                expires: r.u64()?,
            };
            if a.left > 0 && a.expires > now + 60 {
                return Ok(a);
            }
        }
        let token = self.blob_token(host, now).await?;
        let mailbox = self.rng.array("core/blob-redeem")?;
        let random = self.rng.array("core/blob-redeem")?;
        let reply = self
            .rpc
            .blob_alloc(
                host,
                mailbox,
                random,
                &BlobAlloc::Redeem(token),
                now,
                &mut self.rng,
            )
            .await?;
        let BlobAllocReply::Allocated { alloc, chunks } = reply else {
            return Err(CoreError::Server(Status::Malformed));
        };
        let a = Alloc {
            secret: alloc,
            left: chunks.min(api::ALLOC_CHUNKS),
            expires: now + api::ALLOC_SECS,
        };
        self.save_alloc(host, &a)?;
        Ok(a)
    }

    fn save_alloc(&mut self, host: &ServerId, a: &Alloc) -> Result<()> {
        let mut w = Writer::new();
        w.fixed(&a.secret).u32(a.left).u64(a.expires);
        self.store.put(
            NS_BLOB,
            &key(b"alloc", host, None),
            &w.finish(),
            &mut self.rng,
        )?;
        Ok(())
    }

    /// One unspent token for `host`, issuing more when none are left.
    async fn blob_token(&mut self, host: &ServerId, now: u64) -> Result<[u8; PP_TOKEN_LEN]> {
        let k = key(b"tokens", host, None);
        let mut tokens: Vec<[u8; PP_TOKEN_LEN]> = match self.store.get(NS_BLOB, &k)? {
            Some(b) => b
                .chunks_exact(PP_TOKEN_LEN)
                .filter_map(|c| c.try_into().ok())
                .collect(),
            None => Vec::new(),
        };
        if tokens.is_empty() {
            tokens = self.issue_blob_tokens(host, now).await?;
        }
        let t = tokens.pop().ok_or(CoreError::Server(Status::Quota))?;
        // Spent before it is used: a token sent twice is refused anyway.
        self.store
            .put(NS_BLOB, &k, &tokens.concat(), &mut self.rng)?;
        Ok(t)
    }

    /// Ask our home server for a batch of blind tokens.
    async fn issue_blob_tokens(
        &mut self,
        host: &ServerId,
        now: u64,
    ) -> Result<Vec<[u8; PP_TOKEN_LEN]>> {
        if *host != self.profile.server {
            // Only a server we have an inbox on issues to us.
            return Err(CoreError::NotAccepted);
        }
        let (epoch, public) = self.blob_issuer(host, now).await?;
        let digest = blob_challenge(host)
            .digest()
            .map_err(|_| CoreError::Server(Status::Malformed))?;
        let mut pending = Vec::with_capacity(BLOB_ISSUE_MAX);
        let mut reqs = Vec::with_capacity(BLOB_ISSUE_MAX);
        for _ in 0..BLOB_ISSUE_MAX {
            let (req, p) = Pending::begin(IssuerPublic(public), digest, &mut self.rng)
                .map_err(|_| CoreError::Server(Status::Malformed))?;
            let req: [u8; PP_REQUEST_LEN] = req
                .try_into()
                .map_err(|_| CoreError::Server(Status::Malformed))?;
            reqs.push(req);
            pending.push(p);
        }
        let (inbox, owner) = (self.profile.request_inbox, self.profile.request_owner);
        let reply = self
            .rpc
            .blob_alloc(
                host,
                inbox,
                owner,
                &BlobAlloc::Issue(reqs),
                now,
                &mut self.rng,
            )
            .await?;
        let BlobAllocReply::Issued {
            epoch: got_epoch,
            public: got,
            responses,
        } = reply
        else {
            return Err(CoreError::Server(Status::Malformed));
        };
        // The proofs check against the key we expect, so a server that
        // answered with another key fails here.
        if got_epoch != epoch || got != public || responses.len() != pending.len() {
            return Err(CoreError::Server(Status::Malformed));
        }
        pending
            .into_iter()
            .zip(responses)
            .map(|(p, r)| {
                p.finish(&r)
                    .map_err(|_| CoreError::Server(Status::Malformed))
                    .and_then(|t| {
                        t.encode()
                            .try_into()
                            .map_err(|_| CoreError::Server(Status::Malformed))
                    })
            })
            .collect()
    }

    /// This month's issuer key of `host`: from its checked descriptor, or
    /// pinned on first sight.
    async fn blob_issuer(&mut self, host: &ServerId, now: u64) -> Result<(u32, [u8; 49])> {
        let epoch = api::issuer_epoch(now);
        let listed = self
            .server_descriptor(host)?
            .and_then(|d| d.blob_issuer(epoch));
        let pin_key = key(b"pin", host, Some(epoch));
        let pinned: Option<[u8; 49]> = self
            .store
            .get(NS_BLOB, &pin_key)?
            .and_then(|b| b.as_slice().try_into().ok());
        if let Some(k) = listed {
            if pinned.is_some_and(|p| p != k) {
                return Err(CoreError::Server(Status::Malformed));
            }
            self.store.put(NS_BLOB, &pin_key, &k, &mut self.rng)?;
            return Ok((epoch, k));
        }
        if let Some(p) = pinned {
            return Ok((epoch, p));
        }
        let mailbox = self.rng.array("core/blob-redeem")?;
        let random = self.rng.array("core/blob-redeem")?;
        let reply = self
            .rpc
            .blob_alloc(host, mailbox, random, &BlobAlloc::Key, now, &mut self.rng)
            .await?;
        let BlobAllocReply::Issued {
            epoch: got_epoch,
            public,
            ..
        } = reply
        else {
            return Err(CoreError::Server(Status::Malformed));
        };
        if got_epoch != epoch {
            return Err(CoreError::Server(Status::Malformed));
        }
        self.store.put(NS_BLOB, &pin_key, &public, &mut self.rng)?;
        Ok((epoch, public))
    }
}

/// Decoy chunks kept to fetch alongside real ones.
const DECOY_POOL: usize = 256;
/// A decoy is a chunk seen within this long (blobs live 30 days).
const DECOY_SECS: u64 = 25 * 86_400;
const NS_DECOYS: &str = "blob-decoys";

/// When a file that arrived at `at` may be fetched without the person
/// asking (previews, voice notes): 5 to 60 s later, by its message id, so
/// a server can't match the fetches to the upload by timing (RT-17). A
/// fetch the person asks for goes at once.
pub fn fetch_due(id: &[u8; 16], at: u64, now: u64) -> bool {
    let delay = 5 + u64::from(u16::from_be_bytes([id[14], id[15]])) % 56;
    now >= at.saturating_add(delay)
}

impl Client {
    /// Remember a few chunks of `att` (they exist on its host) as decoys
    /// for later fetches.
    pub(crate) fn note_decoys(
        &mut self,
        host: &ServerId,
        ids: &[[u8; 32]],
        now: u64,
    ) -> Result<()> {
        for id in ids.iter().take(4) {
            self.store.put(
                NS_DECOYS,
                &[&host[..], id].concat(),
                &now.to_be_bytes(),
                &mut self.rng,
            )?;
        }
        // Oldest out, past the cap or the blobs' lifetime.
        let mut kept = self.store.scan(NS_DECOYS)?;
        kept.sort_by_key(|(_, v)| v.as_slice().try_into().map_or(0, u64::from_be_bytes));
        let over = kept.len().saturating_sub(DECOY_POOL);
        for (i, (k, v)) in kept.iter().enumerate() {
            let at = v.as_slice().try_into().map_or(0, u64::from_be_bytes);
            if i < over || at + DECOY_SECS < now {
                self.store.delete(NS_DECOYS, k)?;
            }
        }
        Ok(())
    }

    /// 1 to 3 chunks of other files on `host` to fetch too (none if we
    /// know of none yet).
    pub(crate) fn pick_decoys(
        &mut self,
        host: &ServerId,
        not: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>> {
        let known: Vec<[u8; 32]> = self
            .store
            .scan(NS_DECOYS)?
            .into_iter()
            .filter_map(|(k, _)| {
                let (h, id) = k.split_at_checked(16)?;
                (h == host.as_slice()).then(|| id.try_into().ok())?
            })
            .filter(|id| !not.contains(id))
            .collect();
        if known.is_empty() {
            return Ok(Vec::new());
        }
        let n: [u8; 1] = self.rng.array("core/decoy")?;
        let want = (1 + usize::from(n[0]) % 3).min(known.len());
        let mut out: Vec<[u8; 32]> = Vec::with_capacity(want);
        while out.len() < want {
            let r: [u8; 4] = self.rng.array("core/decoy")?;
            let pick = known[u32::from_be_bytes(r) as usize % known.len()];
            if !out.contains(&pick) {
                out.push(pick);
            }
        }
        Ok(out)
    }

    /// Fetch every chunk of `att`, with decoy fetches at random places
    /// among them (RT-17).
    pub(crate) async fn fetch_chunks(
        &mut self,
        att: &crate::files::Attachment,
        now: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let ids: Vec<[u8; 32]> = (0..att.chunks).map(|i| att.chunk_id(i)).collect();
        let decoys = self.pick_decoys(&att.host, &ids)?;
        let mut at: Vec<usize> = Vec::with_capacity(decoys.len());
        for _ in &decoys {
            let r: [u8; 4] = self.rng.array("core/decoy")?;
            at.push(u32::from_be_bytes(r) as usize % (ids.len() + 1));
        }
        let mut parts = Vec::with_capacity(ids.len());
        for (i, id) in ids.iter().enumerate() {
            for (d, _) in decoys.iter().zip(&at).filter(|(_, p)| **p == i) {
                // What comes back is thrown away; a failed decoy is no error.
                let _ = self.rpc.blob_get(&att.host, *d, now, &mut self.rng).await;
            }
            let chunk = self
                .rpc
                .blob_get(&att.host, *id, now, &mut self.rng)
                .await?;
            parts.push(crate::files::open_chunk(att, i as u32, &chunk)?);
        }
        for (d, _) in decoys.iter().zip(&at).filter(|(_, p)| **p == ids.len()) {
            let _ = self.rpc.blob_get(&att.host, *d, now, &mut self.rng).await;
        }
        let pick: [u8; 1] = self.rng.array("core/decoy")?;
        let start = usize::from(pick[0]) % ids.len().max(1);
        let noted: Vec<[u8; 32]> = ids.iter().cycle().skip(start).take(4).copied().collect();
        self.note_decoys(&att.host, &noted, now)?;
        Ok(parts)
    }
}
