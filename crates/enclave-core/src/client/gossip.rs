//! Key-transparency gossip (`docs/12-servers.md` §3.8, RT-04).
//!
//! A server whose witnesses collude could show different people different
//! versions of its log, each properly signed. Contacts compare notes:
//!
//! 1. Every head this client verifies (username lookups, the daily
//!    self-audit) is kept.
//! 2. Direct messages carry, in space the envelope pads anyway, up to three
//!    `(server, epoch, digest)` items for the newest heads we hold.
//! 3. A received item for an epoch we also hold with a **different digest**
//!    means one of us was shown a fork. We send our signed head, as a sealed
//!    file (it is ~19 KB with its cosignatures), to that contact. An item we
//!    can't compare yet is remembered and checked when we verify that epoch.
//! 4. A received head that verifies under our pinned server key and witness
//!    quorum and differs from ours at the same epoch **proves** the server
//!    equivocated: we keep both heads, raise [`crate::Event::KtSplitView`],
//!    and send ours back so they hold the proof too.
//! 5. We publish the proof (`enclave_kt::Equivocation`) to a server other
//!    than the one that equivocated (our home server, or another the list
//!    names) as `DirKind::Equivocation`. That server checks it and hands it
//!    to the witnesses, which never cosign that log again.

use super::Client;
use crate::content::Content;
use crate::files::{self, Attachment};
use crate::{CoreError, Result};
use enclave_kt::SignedHead;
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};

const NS_KT_HEADS: &str = "kt-heads";
const NS_KT_HEARD: &str = "kt-heard";
const NS_KT_SENT: &str = "kt-sent";
const NS_KT_ALERT: &str = "kt-alert";
/// Alerts whose proof a server took (`server ‖ epoch` → empty).
const NS_KT_PUBLISHED: &str = "kt-published";
/// Items per message.
pub const MAX_ITEMS: usize = 3;
/// Bytes one item takes: server, epoch, digest.
pub const ITEM_LEN: usize = 16 + 8 + 32;
/// Heads kept per client (oldest dropped).
const KEEP_HEADS: usize = 64;
/// First byte of a payload that carries gossip. Content kinds are small
/// numbers, so a bare content never starts with it.
const WRAPPED: u8 = 0xFE;

/// One gossiped head digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GossipItem {
    /// The log's server.
    pub server: [u8; 16],
    /// Epoch.
    pub epoch: u64,
    /// `TreeHead::gossip_digest`.
    pub digest: [u8; 32],
}

/// A proven split view: the server signed two different heads for one epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KtAlert {
    /// The log's server.
    pub server: [u8; 16],
    /// The epoch it equivocated on.
    pub epoch: u64,
}

/// Bytes gossip adds to a payload.
pub(crate) fn overhead(n: usize) -> usize {
    if n == 0 { 0 } else { 1 + 4 + 1 + n * ITEM_LEN }
}

/// `WRAPPED ‖ u32 len ‖ content ‖ u8 n ‖ items`.
pub(crate) fn wrap(content: &[u8], items: &[GossipItem]) -> Result<Vec<u8>> {
    if items.is_empty() {
        return Ok(content.to_vec());
    }
    let mut w = Writer::new();
    w.u8(WRAPPED)
        .bytes(content)
        .u8(items.len().min(MAX_ITEMS) as u8);
    for i in items.iter().take(MAX_ITEMS) {
        w.fixed(&i.server).u64(i.epoch).fixed(&i.digest);
    }
    Ok(w.finish())
}

/// Split a payload into its content and gossip.
pub(crate) fn unwrap(b: &[u8]) -> Result<(Vec<u8>, Vec<GossipItem>)> {
    if b.first() != Some(&WRAPPED) {
        return Ok((b.to_vec(), Vec::new()));
    }
    let mut r = Reader::new(&b[1..]);
    let content = r.bytes(b.len())?.to_vec();
    let n = usize::from(r.u8()?);
    if n > MAX_ITEMS {
        return Err(ProtoError::Decode.into());
    }
    let items = (0..n)
        .map(|_| {
            Ok(GossipItem {
                server: r.array()?,
                epoch: r.u64()?,
                digest: r.array()?,
            })
        })
        .collect::<std::result::Result<Vec<_>, ProtoError>>()?;
    r.end()?;
    Ok((content, items))
}

fn head_key(server: &[u8; 16], epoch: u64) -> Vec<u8> {
    [&server[..], &epoch.to_be_bytes()].concat()
}

fn peer_key(server: &[u8; 16], epoch: u64, peer: &[u8; 64]) -> Vec<u8> {
    [&head_key(server, epoch)[..], &peer[..]].concat()
}

impl Client {
    /// Keep a head we verified, and check it against digests contacts sent
    /// before we had it.
    pub(crate) fn record_head(&mut self, sh: &SignedHead) -> Result<()> {
        let (server, epoch) = (sh.head.server, sh.head.epoch);
        let key = head_key(&server, epoch);
        if self.store.get(NS_KT_HEADS, &key)?.is_none() {
            self.store
                .put(NS_KT_HEADS, &key, &sh.encode(), &mut self.rng)?;
            let mut all = self.store.scan(NS_KT_HEADS)?;
            if all.len() > KEEP_HEADS {
                all.sort_by(|a, b| a.0[16..].cmp(&b.0[16..]));
                for (k, _) in all.iter().take(all.len() - KEEP_HEADS) {
                    self.store.delete(NS_KT_HEADS, k)?;
                }
            }
        }
        let ours = sh.head.gossip_digest();
        for (k, v) in self.store.scan(NS_KT_HEARD)? {
            if k.len() == 16 + 8 + 64 && k[..24] == key[..] {
                let peer: [u8; 64] = k[24..].try_into().map_err(|_| CoreError::NotFound)?;
                if v[..] != ours[..] {
                    self.pending_kt_proofs.push((peer, server, epoch));
                }
                self.store.delete(NS_KT_HEARD, &k)?;
            }
        }
        Ok(())
    }

    fn held_head(&self, server: &[u8; 16], epoch: u64) -> Result<Option<SignedHead>> {
        Ok(
            match self.store.get(NS_KT_HEADS, &head_key(server, epoch))? {
                Some(b) => Some(SignedHead::decode(&b).map_err(|_| ProtoError::Decode)?),
                None => None,
            },
        )
    }

    /// Items for the newest heads we hold.
    pub(crate) fn gossip_items(&self) -> Vec<GossipItem> {
        let Ok(all) = self.store.scan(NS_KT_HEADS) else {
            return Vec::new();
        };
        let mut heads: Vec<SignedHead> = all
            .into_iter()
            .filter_map(|(_, v)| SignedHead::decode(&v).ok())
            .collect();
        heads.sort_by_key(|h| std::cmp::Reverse(h.head.epoch));
        heads
            .iter()
            .take(MAX_ITEMS)
            .map(|h| GossipItem {
                server: h.head.server,
                epoch: h.head.epoch,
                digest: h.head.gossip_digest(),
            })
            .collect()
    }

    /// Gossip from `peer`: compare, or remember for later.
    pub(crate) fn on_gossip(&mut self, peer: &[u8; 64], items: &[GossipItem]) -> Result<()> {
        for i in items {
            match self.held_head(&i.server, i.epoch)? {
                Some(ours) if ours.head.gossip_digest() != i.digest => {
                    self.pending_kt_proofs.push((*peer, i.server, i.epoch));
                }
                Some(_) => {}
                None => {
                    self.store.put(
                        NS_KT_HEARD,
                        &peer_key(&i.server, i.epoch, peer),
                        &i.digest,
                        &mut self.rng,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// A contact's signed head arrived (`Content::KtHead`).
    pub(crate) fn on_kt_head(&mut self, peer: &[u8; 64], b: &[u8]) {
        if let Ok(att) = Attachment::decode(b)
            && att.size <= 64 * 1024
        {
            self.pending_kt_heads.push((*peer, att));
        }
    }

    /// Send queued proofs and check received heads (from `sync`).
    pub(crate) async fn process_kt(&mut self, now: u64) -> Result<Vec<crate::Event>> {
        let mut events = Vec::new();
        for (peer, server, epoch) in std::mem::take(&mut self.pending_kt_proofs) {
            self.send_head(&peer, &server, epoch, now).await?;
        }
        for (peer, att) in std::mem::take(&mut self.pending_kt_heads) {
            let mut parts = Vec::with_capacity(att.chunks as usize);
            for i in 0..att.chunks {
                let chunk = self
                    .rpc
                    .blob_get(&att.host, att.chunk_id(i), now, &mut self.rng)
                    .await?;
                parts.push(files::open_chunk(&att, i, &chunk)?);
            }
            let Ok(sh) = SignedHead::decode(&files::finish(&att, &parts)?) else {
                continue;
            };
            if !self.verifies(&sh) {
                continue;
            }
            let (server, epoch) = (sh.head.server, sh.head.epoch);
            match self.held_head(&server, epoch)? {
                Some(ours) if ours.head.root != sh.head.root => {
                    // Two heads for one epoch, both signed and witnessed.
                    let proof = [
                        &(ours.encode().len() as u32).to_be_bytes()[..],
                        &ours.encode(),
                        &sh.encode(),
                    ]
                    .concat();
                    let key = head_key(&server, epoch);
                    if self.store.get(NS_KT_ALERT, &key)?.is_none() {
                        self.store.put(NS_KT_ALERT, &key, &proof, &mut self.rng)?;
                        events.push(crate::Event::KtSplitView { server, epoch });
                    }
                    self.send_head(&peer, &server, epoch, now).await?;
                }
                Some(_) => {}
                // A valid head we didn't have: keep it like our own.
                None => self.record_head(&sh)?,
            }
        }
        self.publish_equivocations(now).await?;
        Ok(events)
    }

    /// Publish each proof we hold to a server other than the one that
    /// equivocated, until one takes it. A network failure leaves it for the
    /// next sync.
    async fn publish_equivocations(&mut self, now: u64) -> Result<()> {
        for (k, proof) in self.store.scan(NS_KT_ALERT)? {
            if self.store.get(NS_KT_PUBLISHED, &k)?.is_some() {
                continue;
            }
            let Some(e) = equivocation(&proof) else {
                continue;
            };
            let culprit = e.server();
            let to = if self.profile.server != culprit {
                Some(self.profile.server)
            } else {
                self.server_list()
                    .and_then(|l| l.servers.iter().map(|s| s.id()).find(|id| *id != culprit))
            };
            let Some(to) = to else {
                continue;
            };
            let mut key = [0u8; 32];
            key[..16].copy_from_slice(&culprit);
            match self
                .rpc
                .dir_put(
                    &to,
                    enclave_rpc::api::DirKind::Equivocation,
                    key,
                    [0; 32],
                    &e.encode(),
                    now,
                    &mut self.rng,
                )
                .await
            {
                Ok(()) => {}
                // It can't take it (a server that doesn't know the log):
                // nobody else will either, so stop trying.
                Err(CoreError::Server(_)) => {}
                Err(e) => return Err(e),
            }
            self.store.put(NS_KT_PUBLISHED, &k, &[], &mut self.rng)?;
        }
        Ok(())
    }

    /// Whether `sh` is signed by a log we pin and cosigned by our witness
    /// quorum. Only the signatures matter here, not how recent it is.
    fn verifies(&self, sh: &SignedHead) -> bool {
        let Some(policy) = &self.kt else {
            return false;
        };
        let Some(info) = policy.by_server(&sh.head.server) else {
            return false;
        };
        policy
            .witnesses
            .check(sh, &info.head_key, &info.operator, sh.head.time)
            .is_ok()
    }

    /// Send our head for `(server, epoch)` to `peer`, once.
    async fn send_head(
        &mut self,
        peer: &[u8; 64],
        server: &[u8; 16],
        epoch: u64,
        now: u64,
    ) -> Result<()> {
        let sent = peer_key(server, epoch, peer);
        if self.store.get(NS_KT_SENT, &sent)?.is_some() {
            return Ok(());
        }
        let Some(ours) = self.held_head(server, epoch)? else {
            return Ok(());
        };
        let host = self.profile.server;
        let (att, chunks) = files::seal_file(
            &ours.encode(),
            "kt-head",
            "application/x-enclave-kt-head",
            host,
            &mut self.rng,
        )?;
        for (id, chunk) in &chunks {
            self.put_chunk(&host, *id, chunk, now).await?;
        }
        self.send_content(peer, &Content::KtHead(att.encode()), now)
            .await?;
        self.store.put(NS_KT_SENT, &sent, &[1], &mut self.rng)?;
        Ok(())
    }

    /// The domain of the log at `server`, if we pin it.
    pub fn kt_domain(&self, server: &[u8; 16]) -> Option<String> {
        Some(self.kt.as_ref()?.by_server(server)?.domain.clone())
    }

    /// A proven split view of a log we pin, if any.
    pub fn kt_alert(&self) -> Option<KtAlert> {
        let all = self.store.scan(NS_KT_ALERT).ok()?;
        let (k, _) = all.into_iter().next()?;
        Some(KtAlert {
            server: k.get(..16)?.try_into().ok()?,
            epoch: u64::from_be_bytes(k.get(16..24)?.try_into().ok()?),
        })
    }
}

/// The two heads of a stored alert (`u32 len ‖ ours ‖ theirs`).
fn equivocation(proof: &[u8]) -> Option<enclave_kt::Equivocation> {
    let n = u32::from_be_bytes(proof.get(..4)?.try_into().ok()?) as usize;
    let a = SignedHead::decode(proof.get(4..4 + n)?).ok()?;
    let b = SignedHead::decode(proof.get(4 + n..)?).ok()?;
    Some(enclave_kt::Equivocation { a, b })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn wrap_round_trips_and_leaves_plain_content_alone() {
        let items = [GossipItem {
            server: [1; 16],
            epoch: 9,
            digest: [2; 32],
        }; 3];
        let w = wrap(b"\x02hello", &items).unwrap();
        assert_eq!(w.len(), 6 + overhead(3));
        assert_eq!(unwrap(&w).unwrap(), (b"\x02hello".to_vec(), items.to_vec()));
        assert_eq!(
            unwrap(b"\x02plain").unwrap(),
            (b"\x02plain".to_vec(), vec![])
        );
        assert_eq!(wrap(b"\x02x", &[]).unwrap(), b"\x02x");
        let mut bad = w.clone();
        bad[5 + 6] = 4; // item count over the limit
        assert!(unwrap(&bad).is_err());
        assert!(unwrap(&w[..w.len() - 1]).is_err());
    }
}
