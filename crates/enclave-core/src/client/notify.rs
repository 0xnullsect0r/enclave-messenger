//! Notification previews (`docs/10-push.md` §4).
//!
//! With previews on, we give each contact the root of a notification key
//! chain (`Content::NotifyKey`): they fill the 1,024-byte capsule of every
//! envelope they send us with their name and a preview, sealed under the
//! day's key, and our iOS notification extension opens it from a small key
//! table ([`Client::notify_table`]) without the app's database. With
//! previews off, capsules stay random and we tell contacts so. Either way
//! every envelope carries a capsule, so nobody can tell which.

use super::Client;
use crate::content::Content;
use crate::{CoreError, Result};
use enclave_proto::notify::{CAPSULE_LEN, Chain, KeyTable, seal_capsule};

/// Contact root → the chain we gave them (it opens their capsules).
const NS_MINE: &str = "notify-mine";
/// Contact root → `u8 previews ‖ chain`: the chain they gave us.
const NS_THEIRS: &str = "notify-theirs";
/// Setting: previews on.
const KEY_PREVIEWS: &str = "previews";

fn today(now: u64) -> u32 {
    u32::try_from(now / 86_400).unwrap_or(u32::MAX)
}

/// What a capsule shows for `content`, or `None` for content nobody is
/// notified of.
fn preview_of(content: &Content) -> Option<String> {
    Some(match content {
        Content::Text { text, .. } => text.clone(),
        Content::Attachment { caption, .. } if !caption.is_empty() => caption.clone(),
        Content::Attachment { .. } => "Sent a file".into(),
        Content::Sticker { .. } => "Sent a sticker".into(),
        Content::Location { .. } => "Shared a location".into(),
        c if c.is_personal() => "New message".into(),
        _ => return None,
    })
}

impl Client {
    /// Whether contacts fill our notification capsules with previews.
    pub fn previews(&self) -> bool {
        matches!(self.setting(KEY_PREVIEWS), Ok(Some(v)) if v == [1])
    }

    /// Turn previews on (every contact gets a fresh chain) or off (every
    /// contact is told, and our chains are forgotten).
    pub async fn set_previews(&mut self, on: bool) -> Result<()> {
        self.set_setting(KEY_PREVIEWS, &[u8::from(on)])?;
        let now = self.now();
        let roots = self.notify_contacts();
        for root in roots {
            let r = if on {
                self.give_notify_key(&root, now).await
            } else {
                self.store.delete(NS_MINE, &root)?;
                let off = Content::NotifyKey {
                    key: [0; 32],
                    day: today(now),
                    previews: false,
                };
                self.send_content(&root, &off, now).await
            };
            if let Err(e @ CoreError::Net(_)) = r {
                return Err(e);
            }
        }
        Ok(())
    }

    fn notify_contacts(&self) -> Vec<[u8; 64]> {
        self.contacts
            .values()
            .filter(|c| c.state == super::ContactState::Accepted)
            .map(|c| c.root)
            .filter(|r| !self.is_blocked(r) && !self.is_closed(r))
            .collect()
    }

    async fn give_notify_key(&mut self, root: &[u8; 64], now: u64) -> Result<()> {
        let chain = Chain {
            day: today(now),
            key: self.rng.array("core/notify-key")?,
        };
        self.store
            .put(NS_MINE, root, &chain.encode(), &mut self.rng)?;
        let c = Content::NotifyKey {
            key: chain.key,
            day: chain.day,
            previews: true,
        };
        self.send_content(root, &c, now).await
    }

    /// From `sync`: with previews on, a chain for every contact who has
    /// none yet (a new contact); and our chains stepped to yesterday, so
    /// older keys are gone.
    pub(crate) async fn notify_upkeep(&mut self, now: u64) -> Result<()> {
        let d = today(now).saturating_sub(1);
        for (k, v) in self.store.scan(NS_MINE)? {
            if let Some(mut c) = Chain::decode(&v)
                && c.day < d
            {
                if c.advance(d) {
                    self.store.put(NS_MINE, &k, &c.encode(), &mut self.rng)?;
                } else {
                    self.store.delete(NS_MINE, &k)?;
                }
            }
        }
        if !self.previews() {
            return Ok(());
        }
        for root in self.notify_contacts() {
            if self.store.get(NS_MINE, &root)?.is_some() {
                continue;
            }
            match self.give_notify_key(&root, now).await {
                Err(e @ CoreError::Net(_)) => return Err(e),
                // No tokens or no session yet: next time.
                Err(_) => {
                    self.store.delete(NS_MINE, &root)?;
                }
                Ok(()) => {}
            }
        }
        Ok(())
    }

    /// "Secure my account": forget the chains we gave; the next upkeep
    /// gives every contact a fresh one (previews on).
    pub(crate) fn forget_notify_keys(&mut self) -> Result<()> {
        for (k, _) in self.store.scan(NS_MINE)? {
            self.store.delete(NS_MINE, &k)?;
        }
        Ok(())
    }

    /// `root` gave us their chain (or said previews are off).
    pub(crate) fn on_notify_key(
        &mut self,
        root: &[u8; 64],
        key: [u8; 32],
        day: u32,
        previews: bool,
    ) -> Result<()> {
        if !previews {
            self.store.delete(NS_THEIRS, root)?;
            return Ok(());
        }
        let v = [&[1u8][..], &Chain { day, key }.encode()].concat();
        self.store.put(NS_THEIRS, root, &v, &mut self.rng)?;
        Ok(())
    }

    /// The capsule for `content` to `root`: our name and a preview under
    /// today's key of the chain they gave us, if they want previews.
    pub(crate) fn capsule_for(
        &mut self,
        root: &[u8; 64],
        content: &Content,
        now: u64,
    ) -> Result<Option<[u8; CAPSULE_LEN]>> {
        let Some(preview) = preview_of(content) else {
            return Ok(None);
        };
        let Some(v) = self.store.get(NS_THEIRS, root)? else {
            return Ok(None);
        };
        let Some(mut chain) = v.get(1..).and_then(Chain::decode) else {
            return Ok(None);
        };
        if !chain.advance(today(now)) {
            return Ok(None);
        }
        let v = [&[1u8][..], &chain.encode()].concat();
        self.store.put(NS_THEIRS, root, &v, &mut self.rng)?;
        let name = self.profile.name.clone();
        Ok(Some(seal_capsule(
            &chain.key,
            chain.day,
            &name,
            &preview,
            &mut self.rng,
        )?))
    }

    /// The key table for the notification extension: each contact we gave a
    /// chain, with today's and yesterday's keys.
    pub fn notify_table(&self, now: u64) -> KeyTable {
        let d = today(now);
        let entries = self
            .store
            .scan(NS_MINE)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v)| {
                let root: [u8; 64] = k.as_slice().try_into().ok()?;
                let chain = Chain::decode(&v)?;
                let label = self.contacts.get(&root).map(|c| c.name.clone())?;
                Some((label, chain.key_for(d)?, chain.key_for(d.wrapping_sub(1))))
            })
            .collect();
        KeyTable { day: d, entries }
    }
}
