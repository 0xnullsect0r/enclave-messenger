//! Encrypted backups and restore (`docs/14-storage.md` §4).
//!
//! A backup is sealed under a key derived from the recovery secret. It holds
//! the profile, the shared account keys, contacts, message history and
//! settings, and never ratchet, prekey, shred-keyring or group-chain state:
//! restoring creates a new device that opens fresh sessions, so an old
//! backup can never cause key reuse. Disappearing messages are not restored
//! (their keys are not in the backup) and neither are groups.

use super::{Client, Options};
use crate::persist::{self, NS_CONTACTS, NS_ISSUERS, NS_PROFILE, NS_SECRETS, Profile};
use crate::rpc::Rpc;
use crate::{CoreError, Result};
use enclave_crypto::sig::RootPublic;
use enclave_net::transport::Transport;
use enclave_proto::bundle::PrekeyStore;
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::{DeviceEntry, MAX_VALIDITY_SECS, Role, SignedManifest};
use enclave_proto::recovery::RecoverySecret;
use enclave_rpc::api::{DirAction, DirKind, device_key, manifest_key};
use enclave_store::{Store, backup};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use zeroize::Zeroizing;

const NS_SETTINGS: &str = "settings";

impl Client {
    /// Export an encrypted backup (primary device only: it needs the
    /// recovery secret).
    pub fn export_backup(&mut self) -> Result<Vec<u8>> {
        let rs = self
            .store
            .get(NS_SECRETS, b"recovery")?
            .ok_or(CoreError::NotAccepted)?;
        let rs: [u8; 32] = rs.as_slice().try_into().map_err(|_| CoreError::NotFound)?;
        // Only the shared account keys from "secrets", never device or prekey
        // state; the export below skips excluded namespaces as well.
        let tmp_ns = "backup-secrets";
        self.store.put(
            tmp_ns,
            b"account",
            &self.account.export_shared(),
            &mut self.rng,
        )?;
        let mut namespaces: Vec<String> = vec![
            NS_PROFILE.into(),
            NS_CONTACTS.into(),
            NS_ISSUERS.into(),
            NS_SETTINGS.into(),
            tmp_ns.into(),
        ];
        for root in self.contacts.keys() {
            namespaces.push(persist::msg_ns(root));
            namespaces.push(format!("mid/{}", &persist::msg_ns(root)[2..]));
        }
        let refs: Vec<&str> = namespaces.iter().map(String::as_str).collect();
        let archive = backup::export(&self.store, &refs, &rs, &mut self.rng)?;
        self.store.delete(tmp_ns, b"account")?;
        Ok(archive)
    }

    /// Restore onto a new device from the recovery words and a backup. The
    /// new device becomes the primary: the root (re-derived from the words)
    /// signs a manifest that lists only it, and every contact is contacted
    /// again from it.
    pub async fn restore(
        words: &str,
        archive: &[u8],
        opts: Options,
        transport: Arc<dyn Transport>,
    ) -> Result<Self> {
        let now = transport.now();
        let mut rng = enclave_store::device_rng(opts.keystore.as_ref())?;
        let rs = RecoverySecret::from_words(words)?;
        let pw = opts
            .passphrase
            .as_ref()
            .map(|p| (p.as_slice(), opts.pw_params));
        let store = Store::create(
            opts.path.as_deref(),
            Arc::clone(&opts.keystore),
            pw,
            &mut rng,
        )?;
        backup::import(&store, archive, rs.as_bytes(), &mut rng)?;
        let shared = Zeroizing::new(
            store
                .get("backup-secrets", b"account")?
                .ok_or(CoreError::NotFound)?,
        );
        store.delete("backup-secrets", b"account")?;
        let account = AccountKeys::import_shared(&shared, Some(&rs))?;
        // The manifest the account's devices held when the backup was made:
        // their verdicts on this restore are the ones contacts count.
        let held = store.get(NS_PROFILE, b"manifest")?.unwrap_or_default();
        let mut profile = Profile::decode(
            &store
                .get(NS_PROFILE, b"profile")?
                .ok_or(CoreError::NotFound)?,
        )?;
        for (_, cursor) in profile.weeks.iter_mut() {
            *cursor = 0;
        }
        profile.request_cursor = 0;

        let mut rpc = Rpc::new(Arc::clone(&transport));
        let root = account.root_public.0;
        // A backup from before a move names inboxes the account left (and
        // not the new ones' secrets): refuse it rather than read the old
        // home forever.
        match rpc
            .dir_get(
                &profile.server,
                DirKind::Moved,
                DirAction::Get,
                manifest_key(&root),
                [0; 32],
                now,
                &mut rng,
            )
            .await
        {
            Ok(b) => {
                let m = enclave_proto::server_move::ServerMove::decode(&b)?;
                if m.verify().is_ok() && m.root.0 == root && m.from == profile.server {
                    return Err(CoreError::BackupBeforeMove);
                }
            }
            Err(CoreError::Server(_)) => {}
            Err(e) => return Err(e),
        }

        // The previous manifest (for the chain), then ours with a new device.
        let prev_bytes = rpc
            .dir_get(
                &profile.server,
                DirKind::Manifest,
                DirAction::Get,
                manifest_key(&root),
                [0; 32],
                now,
                &mut rng,
            )
            .await?;
        let prev = SignedManifest::from_bytes(&prev_bytes)?;
        let prev_m = prev.verify(&RootPublic(root), now)?;
        let device = DeviceKeys::generate(&mut rng)?;
        let mut manifest = prev_m.clone();
        manifest.version += 1;
        manifest.prev_hash = prev.hash();
        manifest.issued_at = now;
        manifest.expires_at = now + MAX_VALIDITY_SECS;
        manifest.devices = vec![DeviceEntry::for_device(&device, Role::Primary, now)];
        let signed = manifest.sign(&account, &mut rng)?;
        rpc.dir_put(
            &profile.server,
            DirKind::Manifest,
            manifest_key(&root),
            [0; 32],
            &signed.to_bytes(),
            now,
            &mut rng,
        )
        .await?;
        let mut prekeys = PrekeyStore::default();
        let publication = prekeys.publish(&device, now, &mut rng)?;
        rpc.dir_put(
            &profile.server,
            DirKind::Bundle,
            device_key(&device.id),
            [0; 32],
            &publication.encode(),
            now,
            &mut rng,
        )
        .await?;

        store.put(NS_SECRETS, b"recovery", rs.as_bytes(), &mut rng)?;
        store.put(NS_SECRETS, b"account", &account.export_shared(), &mut rng)?;
        store.put(NS_SECRETS, b"device", &device.export(), &mut rng)?;
        store.put(NS_SECRETS, b"prekeys", &prekeys.export(), &mut rng)?;
        store.put(NS_PROFILE, b"profile", &profile.encode(), &mut rng)?;
        store.put(NS_PROFILE, b"manifest", &manifest.encode()?, &mut rng)?;
        store.put(NS_PROFILE, b"signed-manifest", &signed.to_bytes(), &mut rng)?;
        // No device of the account co-signed this: contacts hold it for 72
        // hours and the old devices may stop it (`guard.rs`).
        let len = u32::try_from(held.len()).map_err(|_| CoreError::NotFound)?;
        let rec = [
            &now.to_be_bytes()[..],
            &len.to_be_bytes(),
            &held,
            &prev_bytes,
        ]
        .concat();
        store.put(NS_PROFILE, super::guard::RECOVERING, &rec, &mut rng)?;

        let mut contacts = BTreeMap::new();
        for (_, v) in store.scan(NS_CONTACTS)? {
            let c = persist::decode_contact(&v)?;
            contacts.insert(c.root, c);
        }
        let mut client = Client {
            store,
            rng,
            rpc,
            account,
            device,
            prekeys,
            manifest,
            profile,
            sessions: HashMap::new(),
            contacts,
            token_pool: Vec::new(),
            groups: BTreeMap::new(),
            kt: None,
            extra_pins: None,
            foundation: None,
            servers: None,
            stale_manifests: BTreeMap::new(),
            pending_history: Vec::new(),
            pending_kt_proofs: Vec::new(),
            pending_kt_heads: Vec::new(),
            recovery_alert: None,
            meet: None,
            pending_bond: None,
            pending_receipts: BTreeMap::new(),
            maximum: false,
            inbox_rounds: 0,
            fallback_week: false,
            pq_carried: std::collections::HashMap::new(),
            late_unit: false,
            metered: false,
            root_unlocked: 0,
            unit_signature: None,
            group_unit_signed: None,
            group_polls: std::collections::HashMap::new(),
            #[cfg(test)]
            two_kem_for_tests: false,
        };
        // Never reuse a token pool: its tokens may have been handed out
        // after the backup was taken. (Pools are not backed up; this is
        // belt and braces.)
        client.clear_pool()?;
        let roots: Vec<[u8; 64]> = client.contacts.keys().copied().collect();
        for root in roots {
            let Some(card) = client.contacts.get(&root).and_then(|c| c.card.clone()) else {
                continue;
            };
            // They may have moved to another server since the backup.
            let card = client.follow_moves(&card).await.unwrap_or(card);
            let Ok((peer_manifest, vault)) = client.fetch_peer(&card, now).await else {
                continue;
            };
            if let Some(c) = client.contacts.get_mut(&root) {
                c.manifest = peer_manifest.clone();
            }
            let hello = client.hello_for(&root, now).await?;
            client
                .initiate_to(&card, &peer_manifest, Some(&vault), &hello, None, now, None)
                .await?;
        }
        Ok(client)
    }
}
