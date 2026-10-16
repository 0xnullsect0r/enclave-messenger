//! Usernames (`@name@domain`) backed by each server's key-transparency log.
//!
//! Claiming binds the name to `root ‖ contact card` with a device signature
//! the server checks against the account's root-signed manifest. Finding
//! someone checks the lookup proof against a head signed by the pinned log
//! key and cosigned by a quorum of pinned witnesses, then checks that the
//! card names the same root and server. A name only ever leads to a card; the
//! usual contact request and security-code check follow as for a QR code.

use super::Client;
use crate::card::ContactCard;
use crate::rpc::EFFORT_LADDER;
use crate::{CoreError, Result, UsernameError};
use enclave_kt::username::normalize;
use enclave_kt::wire::{CTX_CLAIM, ROOT_LEN};
use enclave_kt::{KtError, KtPolicy, NameAnswer, UsernameClaim, verify_absence, verify_lookup};
use enclave_rpc::api::{self, DirAction, DirKind, Status};

const SETTING: &str = "username";
const AUDITED: &str = "username-audit";
/// The time of our last claim: the server takes a name's claims only in
/// increasing time, so two claims in one second must not share a time.
const CLAIMED: &str = "username-claimed";
/// How often a client checks its own username in the log.
pub const AUDIT_EVERY_SECS: u64 = 24 * 3600;

/// Split `@name@domain`, `name@domain` or `name`.
pub(crate) fn parse_address(address: &str) -> (String, Option<String>) {
    let a = address.trim().trim_start_matches('@');
    match a.split_once('@') {
        Some((n, d)) => (n.to_string(), Some(d.trim().to_string())),
        None => (a.to_string(), None),
    }
}

impl Client {
    /// Pin key-transparency logs and witnesses beyond the server list's
    /// (development servers). Not stored: the app supplies them at every
    /// start. Merged with the pins of the list held.
    pub fn set_kt_policy(&mut self, policy: KtPolicy) {
        self.extra_pins = Some(policy);
        self.apply_pins();
    }

    /// This account's username as `name@domain`, if it has one.
    pub fn username(&self) -> Option<String> {
        let name = String::from_utf8(self.setting(SETTING).ok()??).ok()?;
        let domain = self
            .kt
            .as_ref()
            .and_then(|p| p.by_server(&self.profile.server))
            .map(|i| i.domain.clone())?;
        Some(format!("{name}@{domain}"))
    }

    /// Claim `name` on the home server. Replaces any earlier name (which stays
    /// reserved for this account). Returns the full address.
    pub async fn claim_username(&mut self, name: &str) -> Result<String> {
        let info = self
            .kt
            .as_ref()
            .and_then(|p| p.by_server(&self.profile.server))
            .cloned()
            .ok_or(UsernameError::Unavailable)?;
        let name = normalize(name).map_err(|_| UsernameError::NotAllowed)?;
        let key = api::name_key(&name).ok_or(UsernameError::NotAllowed)?;
        let last = self
            .setting(CLAIMED)?
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        let now = self.now().max(last + 1);
        let mut value = self.account.root_public.0.to_vec();
        value.extend_from_slice(&self.card().encode());
        let msg = UsernameClaim::message(&self.profile.server, &name, &value, now);
        let signature = self.device.signing.sign(CTX_CLAIM, &msg, &mut self.rng)?;
        let claim = UsernameClaim {
            name: name.clone(),
            value,
            device: self.device.id,
            time: now,
            signature,
        }
        .encode();
        let ctx = api::pow_context_username(&key, now / 86_400);
        let server = self.profile.server;
        let mut result = Err(CoreError::Server(Status::Pow));
        for effort in EFFORT_LADDER {
            let proof = enclave_tokens::solve(&ctx, effort, &mut self.rng)?;
            result = self
                .rpc
                .dir_put(
                    &server,
                    DirKind::Username,
                    key,
                    proof.0,
                    &claim,
                    now,
                    &mut self.rng,
                )
                .await;
            if !matches!(result, Err(CoreError::Server(Status::Pow))) {
                break;
            }
        }
        match result {
            Ok(()) => {}
            Err(CoreError::Server(Status::Denied)) => return Err(UsernameError::Taken.into()),
            Err(CoreError::Server(Status::NotFound)) => {
                return Err(UsernameError::Unavailable.into());
            }
            Err(CoreError::Server(Status::Invalid)) => {
                return Err(UsernameError::NotAllowed.into());
            }
            Err(e) => return Err(e),
        }
        self.set_setting(SETTING, name.as_bytes())?;
        self.set_setting(CLAIMED, &now.to_be_bytes())?;
        Ok(format!("{name}@{}", info.domain))
    }

    /// Look ourselves up once a day, the way anyone else would. If the log
    /// (as its witnesses sign it) binds our name to another account or to
    /// nothing, or its answer doesn't verify, the operator or someone with
    /// its keys changed it: raise [`crate::Event::UsernameProblem`].
    pub(crate) async fn audit_username(&mut self, now: u64) -> Result<Vec<crate::Event>> {
        let Some(address) = self.username() else {
            return Ok(Vec::new());
        };
        let last = self
            .setting(AUDITED)?
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        if last + AUDIT_EVERY_SECS > now {
            return Ok(Vec::new());
        }
        let problem = match self.find_username(&address).await {
            Ok(card) => {
                card.root != self.account.root_public.0 || card.server != self.profile.server
            }
            Err(CoreError::Username(
                UsernameError::NotFound | UsernameError::Unverified | UsernameError::Withdrawn,
            )) => true,
            // Try again at the next sync.
            Err(_) => return Ok(Vec::new()),
        };
        self.set_setting(AUDITED, &now.to_be_bytes())?;
        Ok(if problem {
            vec![crate::Event::UsernameProblem { address }]
        } else {
            Vec::new()
        })
    }

    /// Find the contact card behind `@name@domain` (or `name` on the home
    /// server), verified against the pinned log and witness quorum.
    pub async fn find_username(&mut self, address: &str) -> Result<ContactCard> {
        let policy = self.kt.clone().ok_or(UsernameError::Unavailable)?;
        let (name, domain) = parse_address(address);
        let info = match &domain {
            Some(d) => policy.by_domain(d),
            None => policy.by_server(&self.profile.server),
        }
        .cloned()
        .ok_or(UsernameError::Unavailable)?;
        let name = normalize(&name).map_err(|_| UsernameError::NotAllowed)?;
        let key = api::name_key(&name).ok_or(UsernameError::NotAllowed)?;
        let now = self.now();
        let bytes = match self
            .rpc
            .dir_get(
                &info.server,
                DirKind::Username,
                DirAction::Get,
                key,
                [0; 32],
                now,
                &mut self.rng,
            )
            .await
        {
            // "Nobody has it" without a proof could be the server hiding
            // someone: never shown as not found.
            Err(CoreError::Server(Status::NotFound)) => {
                return Err(UsernameError::Unverified.into());
            }
            other => other?,
        };
        let reply = match NameAnswer::decode(&bytes).map_err(|_| UsernameError::Unverified)? {
            NameAnswer::Found(r) => r,
            NameAnswer::Absent { head, proof } => {
                let trusted = verify_absence(
                    &policy.witnesses,
                    &info.head_key,
                    &info.operator,
                    &info.vrf_public,
                    &head,
                    &name,
                    &proof,
                    now,
                )
                .map_err(|_| UsernameError::Unverified)?;
                self.record_head(&head)?;
                self.observe_trusted_time(trusted, now)?;
                return Err(UsernameError::NotFound.into());
            }
        };
        let (value, _, trusted) = verify_lookup(
            &policy.witnesses,
            &info.head_key,
            &info.operator,
            &info.vrf_public,
            &reply.head,
            &name,
            reply.proof,
            now,
        )
        .map_err(|e| match e {
            KtError::Username => UsernameError::NotAllowed,
            _ => UsernameError::Unverified,
        })?;
        // Kept for gossip with contacts (RT-04).
        self.record_head(&reply.head)?;
        self.observe_trusted_time(trusted, now)?;
        // A bare root is a released name.
        if enclave_kt::username::as_tombstone(&value).is_some() {
            return Err(UsernameError::Withdrawn.into());
        }
        if value.len() <= ROOT_LEN {
            return Err(UsernameError::NotFound.into());
        }
        let card =
            ContactCard::decode(&value[ROOT_LEN..]).map_err(|_| UsernameError::Unverified)?;
        if card.root[..] != value[..ROOT_LEN] || card.server != info.server {
            return Err(UsernameError::Unverified.into());
        }
        Ok(card)
    }
}

impl Client {
    /// The server half of deleting the account (`docs/03-identity.md`
    /// §8.5): the root signs a tombstone and the home server withdraws the
    /// account's username for good, drops its manifest and prekeys, and
    /// takes no new manifest for it. Only on the device that holds the
    /// recovery words.
    pub async fn publish_tombstone(&mut self) -> Result<()> {
        let now = self.now();
        self.load_root()?;
        let root = self.account.root.as_ref().ok_or(CoreError::NotAccepted)?;
        let t = enclave_proto::tombstone::Tombstone::sign(root, now, &mut self.rng)?;
        let server = self.profile.server;
        self.rpc
            .dir_put(
                &server,
                DirKind::Tombstone,
                api::manifest_key(&self.account.root_public.0),
                [0; 32],
                &t.encode(),
                now,
                &mut self.rng,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::parse_address;

    #[test]
    fn addresses() {
        assert_eq!(
            parse_address(" @sam@enclave.example "),
            ("sam".into(), Some("enclave.example".into()))
        );
        assert_eq!(
            parse_address("sam@enclave.example"),
            ("sam".into(), Some("enclave.example".into()))
        );
        assert_eq!(parse_address("sam"), ("sam".into(), None));
    }
}
