//! Linked devices (`docs/03-identity.md` §4, RT-09).
//!
//! 1. The new device creates its keys and a rendezvous mailbox on a server,
//!    writes its ML-KEM key and device keys there, and shows an
//!    `enclave:link#` code: the mailbox, an X448 key, a link secret, and a
//!    hash committing to what it wrote. The general scanner refuses these
//!    codes (`ContactCard::from_link`); only the device screen accepts them.
//! 2. The primary reads the mailbox, checks the commitment, and runs an
//!    X448 + ML-KEM-1024 exchange keyed also by the link secret. Both
//!    devices derive three words from the result; the primary shows four
//!    choices and the person picks the one the new device shows.
//! 3. On the right choice the primary signs a new manifest with the device,
//!    publishes it, and hands over the account (profile, shared keys,
//!    contacts, a share of their write tokens) as a sealed blob.
//! 4. The new device publishes its prekeys and opens sessions with every
//!    contact and with the primary. Contacts accept it because it is in
//!    the root-signed manifest; nothing is shown to them as a request.

use super::{Client, Contact, ContactState, Options};
use crate::card::{ContactCard, LINK_PREFIX, LinkError, b64url_decode, b64url_encode};
use crate::content::{Content, Token};
use crate::files::{self, Attachment};
use crate::persist::{NS_PROFILE, NS_SECRETS, Profile};
use crate::rpc::Rpc;
use crate::{CoreError, Result};
use enclave_crypto::hash::sha3_512;
use enclave_crypto::kem::{
    MLKEM_CT_LEN, MLKEM_PK_LEN, MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448_LEN,
    X448Public, X448Secret, combine,
};
use enclave_crypto::kmac::kmac256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_crypto::sig::{COMPOSITE_PK_LEN, CompositePublic, RootPublic};
use enclave_net::transport::{ServerId, Transport};
use enclave_proto::ProtoError;
use enclave_proto::bundle::PrekeyStore;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::{
    DeviceEntry, MAX_DEVICES, MAX_VALIDITY_SECS, Manifest, MlKemPublicBytes, Role, SignedManifest,
};
use enclave_rpc::api::{self, DirAction, DirKind, FLAG_GROUP, device_key, manifest_key};
use enclave_store::Store;
use enclave_wire::{Op, RequestHeader};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use zeroize::Zeroizing;

const L_TRANSCRIPT: &str = "enclave/v1/proto/link-transcript";
const L_PHRASE: &str = "enclave/v1/proto/link-phrase";
const L_KEYS: &str = "enclave/v1/proto/link-keys";
const AD_LINK: &str = "enclave/v1/wire/ad-link";

const U_OFFER: u8 = 1;
const U_ANSWER: u8 = 2;
const U_PACKAGE: u8 = 3;

/// What a link code carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkCode {
    /// Server holding the rendezvous mailbox.
    pub server: [u8; 16],
    /// Rendezvous mailbox.
    pub mailbox: [u8; 32],
    /// Its owner secret.
    pub owner: [u8; 32],
    /// New device's X448 share.
    pub x448: [u8; 56],
    /// Link secret (mixed in as a PSK).
    pub secret: [u8; 32],
    /// SHA3-512 (first 32 bytes) of the offer written to the mailbox.
    pub commit: [u8; 32],
}

impl LinkCode {
    /// Binary form.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.server)
            .fixed(&self.mailbox)
            .fixed(&self.owner)
            .fixed(&self.x448)
            .fixed(&self.secret)
            .fixed(&self.commit);
        w.finish()
    }

    /// `enclave:link#…`.
    pub fn to_link(&self) -> String {
        format!("{LINK_PREFIX}{}", b64url_encode(&self.encode()))
    }

    /// Parse a scanned link code.
    pub fn from_link(s: &str) -> std::result::Result<Self, LinkError> {
        let body = s
            .trim()
            .strip_prefix(LINK_PREFIX)
            .ok_or(LinkError::NotEnclave)?;
        let b = b64url_decode(body).ok_or(LinkError::Malformed)?;
        let mut r = Reader::new(&b);
        let m = |_| LinkError::Malformed;
        if r.u8().map_err(m)? != 1 {
            return Err(LinkError::Malformed);
        }
        let c = Self {
            server: r.array().map_err(m)?,
            mailbox: r.array().map_err(m)?,
            owner: r.array().map_err(m)?,
            x448: r.array().map_err(m)?,
            secret: r.array().map_err(m)?,
            commit: r.array().map_err(m)?,
        };
        r.end().map_err(m)?;
        Ok(c)
    }
}

fn encode_entry(e: &DeviceEntry) -> Vec<u8> {
    let mut w = Writer::new();
    w.fixed(&e.id)
        .fixed(&e.signing.to_bytes())
        .fixed(&e.auth.0[..]);
    w.finish()
}

fn decode_entry(r: &mut Reader<'_>, now: u64) -> enclave_proto::Result<DeviceEntry> {
    let id = r.array()?;
    let signing = CompositePublic::from_slice(r.fixed(COMPOSITE_PK_LEN)?)?;
    let auth: [u8; MLKEM_PK_LEN] = r.array()?;
    MlKemPublic::from_slice(&auth)?;
    Ok(DeviceEntry {
        id,
        role: Role::Linked,
        added_at: now,
        capabilities: 1,
        signing,
        auth: MlKemPublicBytes(Box::new(auth)),
    })
}

fn link_key(
    dh: &[u8],
    ss: &[u8],
    x_new: &[u8],
    ek: &[u8],
    x_primary: &[u8],
    ct: &[u8],
    code: &LinkCode,
) -> Zeroizing<[u8; 64]> {
    let transcript = [L_TRANSCRIPT.as_bytes(), &code.commit, &code.mailbox].concat();
    combine(
        Suite::TwoKem,
        &[dh, ss],
        &[x_new, ek, x_primary, ct, &transcript],
        Some(&code.secret),
    )
}

/// Three words both screens show.
fn words(key: &[u8; 64]) -> [String; 3] {
    let h: [u8; 8] = kmac256(key, b"", L_PHRASE);
    let v = u64::from_be_bytes(h);
    let list = bip39_words();
    [0u32, 11, 22].map(|s| list[((v >> (53 - s)) & 0x7ff) as usize].to_string())
}

fn bip39_words() -> &'static [&'static str; 2048] {
    enclave_proto::recovery::english_words()
}

fn package_key(key: &[u8; 64]) -> SealKey {
    seal::derive_key(key, b"package", L_KEYS)
}

async fn write(
    rpc: &mut Rpc,
    code: &LinkCode,
    payload: &[u8],
    now: u64,
    rng: &mut HedgedRng,
) -> Result<()> {
    let env = api::frame(payload, rng)?;
    let h = RequestHeader {
        op: Op::Write,
        flags: FLAG_GROUP,
        mailbox: code.mailbox,
        token: code.owner,
    };
    rpc.call_ok(&code.server, h, &env, now, rng).await?;
    Ok(())
}

async fn read(
    rpc: &mut Rpc,
    code: &LinkCode,
    cursor: &mut u64,
    now: u64,
    rng: &mut HedgedRng,
) -> Result<Vec<Vec<u8>>> {
    let items = match rpc
        .poll(
            &code.server,
            code.mailbox,
            api::read_credential(&code.owner),
            *cursor,
            now,
            rng,
        )
        .await
    {
        Ok(v) => v,
        Err(CoreError::Server(enclave_rpc::api::Status::Denied)) => Vec::new(),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for polled in items {
        *cursor = polled.cursor;
        if let Ok(p) = api::unframe(&polled.envelope) {
            out.push(p.to_vec());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// New device
// ---------------------------------------------------------------------------

/// Progress of a new device waiting to be linked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkProgress {
    /// Waiting for the primary to scan the code.
    Waiting,
    /// Show these words; the person picks them on the primary.
    Words([String; 3]),
    /// The account arrived; call [`LinkingDevice::finish`].
    Ready,
}

/// A device that is being linked to an existing account.
pub struct LinkingDevice {
    opts: Options,
    transport: Arc<dyn Transport>,
    rpc: Rpc,
    rng: HedgedRng,
    device: DeviceKeys,
    x: X448Secret,
    k: MlKemSecret,
    code: LinkCode,
    cursor: u64,
    key: Option<Zeroizing<[u8; 64]>>,
    package: Option<Attachment>,
}

impl LinkingDevice {
    /// Start: create keys and the rendezvous mailbox on `server`.
    pub async fn start(
        opts: Options,
        transport: Arc<dyn Transport>,
        server: ServerId,
    ) -> Result<Self> {
        let mut rng = HedgedRng::new()?;
        let now = transport.now();
        let device = DeviceKeys::generate(&mut rng)?;
        let (x, xp) = X448Secret::generate(&mut rng)?;
        let (k, kp) = MlKemSecret::generate(&mut rng)?;
        let entry = DeviceEntry::for_device(&device, Role::Linked, now);
        let offer = [&[U_OFFER][..], &kp.0[..], &encode_entry(&entry)].concat();
        let mut commit = [0u8; 32];
        commit.copy_from_slice(&sha3_512(&offer)[..32]);
        let code = LinkCode {
            server,
            mailbox: rng.array("link/mailbox")?,
            owner: rng.array("link/owner")?,
            x448: xp.0,
            secret: rng.array("link/secret")?,
            commit,
        };
        let mut rpc = Rpc::new(Arc::clone(&transport));
        write(&mut rpc, &code, &offer, now, &mut rng).await?;
        Ok(Self {
            opts,
            transport,
            rpc,
            rng,
            device,
            x,
            k,
            code,
            cursor: 0,
            key: None,
            package: None,
        })
    }

    /// The code to show (as a QR code).
    pub fn code(&self) -> String {
        self.code.to_link()
    }

    /// Check the mailbox.
    pub async fn poll(&mut self) -> Result<LinkProgress> {
        let now = self.rpc.now();
        for p in read(
            &mut self.rpc,
            &self.code,
            &mut self.cursor,
            now,
            &mut self.rng,
        )
        .await?
        {
            match p.first() {
                Some(&U_ANSWER) if self.key.is_none() => {
                    let mut r = Reader::new(&p[1..]);
                    let xp = X448Public(r.array::<X448_LEN>()?);
                    let ct = MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN)?)?;
                    let dh = self.x.diffie_hellman(&xp)?;
                    let ss = self.k.decapsulate(&ct);
                    let ek = public_of(&self.k)?;
                    self.key = Some(link_key(
                        &dh[..],
                        &ss[..],
                        &self.code.x448,
                        &ek,
                        &xp.0,
                        &ct.0[..],
                        &self.code,
                    ));
                }
                Some(&U_PACKAGE) => {
                    let key = self.key.as_ref().ok_or(ProtoError::Decode)?;
                    let att = seal::open(&package_key(key), AD_LINK.as_bytes(), &p[1..])?;
                    self.package = Some(Attachment::decode(&att)?);
                }
                _ => {}
            }
        }
        Ok(match (&self.key, &self.package) {
            (_, Some(_)) => LinkProgress::Ready,
            (Some(k), None) => LinkProgress::Words(words(k)),
            _ => LinkProgress::Waiting,
        })
    }

    /// Install the account and connect to every contact.
    pub async fn finish(mut self) -> Result<Client> {
        let now = self.rpc.now();
        let att = self.package.clone().ok_or(CoreError::NotFound)?;
        let mut parts = Vec::with_capacity(att.chunks as usize);
        for i in 0..att.chunks {
            let chunk = self
                .rpc
                .blob_get(&att.host, att.chunk_id(i), now, &mut self.rng)
                .await?;
            parts.push(files::open_chunk(&att, i, &chunk)?);
        }
        let pkg = Zeroizing::new(files::finish(&att, &parts)?);
        let mut r = Reader::new(&pkg);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode.into());
        }
        let mut profile = Profile::decode(r.bytes(4096)?)?;
        for (_, cursor) in profile.weeks.iter_mut() {
            *cursor = 0;
        }
        profile.request_cursor = 0;
        let account = AccountKeys::import_shared(r.bytes(4 << 20)?, None)?;
        let signed = SignedManifest::from_bytes(r.bytes(1 << 20)?)?;
        let manifest = signed.verify(&account.root_public, now)?;
        if manifest.device(&self.device.id).is_none() {
            return Err(ProtoError::BadSignature.into());
        }
        let mut contacts = Vec::new();
        for _ in 0..r.u16()? {
            let card = ContactCard::decode(r.bytes(crate::content::MAX_CARD)?)
                .map_err(|_| ProtoError::Decode)?;
            let name = String::from_utf8(r.bytes(256)?.to_vec()).map_err(|_| ProtoError::Decode)?;
            let (verified, timer) = (r.u8()? == 1, r.u32()?);
            let inbox = r.array::<32>()?;
            let server = r.array::<16>()?;
            let n = r.u16()? as usize;
            let tokens: Vec<Token> = (0..n.min(64))
                .map(|_| r.array())
                .collect::<enclave_proto::Result<_>>()?;
            contacts.push((card, name, verified, timer, inbox, server, tokens));
        }
        r.end()?;

        // Local profile.
        let pw = self
            .opts
            .passphrase
            .as_ref()
            .map(|p| (p.as_slice(), self.opts.pw_params));
        let store = Store::create(
            self.opts.path.as_deref(),
            Arc::clone(&self.opts.keystore),
            pw,
            &mut self.rng,
        )?;
        let mut prekeys = PrekeyStore::default();
        let publication = prekeys.publish(&self.device, now, &mut self.rng)?;
        store.put(
            NS_SECRETS,
            b"account",
            &account.export_shared(),
            &mut self.rng,
        )?;
        store.put(NS_SECRETS, b"device", &self.device.export(), &mut self.rng)?;
        store.put(NS_SECRETS, b"prekeys", &prekeys.export(), &mut self.rng)?;
        store.put(NS_PROFILE, b"profile", &profile.encode(), &mut self.rng)?;
        store.put(NS_PROFILE, b"manifest", &manifest.encode()?, &mut self.rng)?;
        store.put(
            NS_PROFILE,
            b"signed-manifest",
            &signed.to_bytes(),
            &mut self.rng,
        )?;
        self.rpc
            .dir_put(
                &profile.server,
                DirKind::Bundle,
                device_key(&self.device.id),
                [0; 32],
                &publication.encode(),
                now,
                &mut self.rng,
            )
            .await?;

        let mut client = Client {
            store,
            rng: self.rng,
            rpc: Rpc::new(self.transport),
            account,
            device: self.device,
            prekeys,
            manifest,
            profile,
            sessions: HashMap::new(),
            contacts: BTreeMap::new(),
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
            group_polls: std::collections::HashMap::new(),
            #[cfg(test)]
            two_kem_for_tests: false,
        };
        let own = client.card();
        for (card, name, verified, timer, inbox, server, tokens) in contacts {
            let Ok((peer_manifest, vault)) = client.fetch_peer(&card, now).await else {
                continue;
            };
            let c = Contact {
                root: card.root,
                name,
                state: ContactState::Accepted,
                verified,
                server,
                request_inbox: card.request_inbox,
                inbox: Some(inbox),
                tokens,
                manifest: peer_manifest.clone(),
                next_seq: 0,
                received_since_refill: 0,
                unread: 0,
                added_at: now,
                card: Some(card.clone()),
                group_only: false,
                timer,
            };
            client.contacts.insert(card.root, c.clone());
            client.save_contact(&c)?;
            let hello = client.hello_for(&card.root, now).await?;
            client
                .initiate_to(&card, &peer_manifest, &vault, &hello, None, now, None)
                .await?;
        }
        // Our other devices, for self-copies.
        let own_manifest = client.manifest.clone();
        let own_vault = client.account.vault_public.clone();
        let hello = Content::Tokens(Vec::new()).encode()?;
        let me = client.device.id;
        client
            .initiate_to(&own, &own_manifest, &own_vault, &hello, Some(me), now, None)
            .await?;
        Ok(client)
    }
}

fn public_of(k: &MlKemSecret) -> Result<Vec<u8>> {
    k.as_bytes()
        .get(1536..1536 + MLKEM_PK_LEN)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| ProtoError::Decode.into())
}

// ---------------------------------------------------------------------------
// Primary
// ---------------------------------------------------------------------------

/// A scanned link code, waiting for the person to pick the matching words.
pub struct LinkOffer {
    code: LinkCode,
    entry: DeviceEntry,
    key: Zeroizing<[u8; 64]>,
    /// Four choices; exactly one matches the new device's screen.
    pub choices: [[String; 3]; 4],
    correct: usize,
}

/// A device of this account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Device id.
    pub id: [u8; 16],
    /// Primary (holds the root).
    pub primary: bool,
    /// When it was added.
    pub added_at: u64,
    /// This device.
    pub this_device: bool,
}

impl Client {
    /// Devices of this account.
    pub fn devices(&self) -> Vec<DeviceInfo> {
        self.manifest
            .devices
            .iter()
            .map(|d| DeviceInfo {
                id: d.id,
                primary: d.role == Role::Primary,
                added_at: d.added_at,
                this_device: d.id == self.device.id,
            })
            .collect()
    }

    /// Whether this device can add devices (holds the root).
    pub fn can_link(&self) -> bool {
        self.account.root.is_some()
    }

    /// Scan a link code (Settings → Your devices only).
    pub async fn link_prepare(&mut self, link: &str) -> Result<LinkOffer> {
        if !self.can_link() {
            return Err(CoreError::NotAccepted);
        }
        if self.manifest.devices.len() >= MAX_DEVICES {
            return Err(CoreError::TooLong);
        }
        let code = LinkCode::from_link(link)?;
        let now = self.now();
        let mut cursor = 0;
        let offer = read(&mut self.rpc, &code, &mut cursor, now, &mut self.rng)
            .await?
            .into_iter()
            .find(|p| p.first() == Some(&U_OFFER))
            .ok_or(CoreError::NotFound)?;
        if sha3_512(&offer)[..32] != code.commit {
            return Err(LinkError::Malformed.into());
        }
        let mut r = Reader::new(&offer[1..]);
        let ek = MlKemPublic::from_slice(r.fixed(MLKEM_PK_LEN)?)?;
        let entry = decode_entry(&mut r, now)?;
        r.end()?;
        let (x, xp) = X448Secret::generate(&mut self.rng)?;
        let dh = x.diffie_hellman(&X448Public(code.x448))?;
        let (ct, ss) = ek.encapsulate(&mut self.rng)?;
        let key = link_key(
            &dh[..],
            &ss[..],
            &code.x448,
            &ek.0[..],
            &xp.0,
            &ct.0[..],
            &code,
        );
        write(
            &mut self.rpc,
            &code,
            &[&[U_ANSWER][..], &xp.0, &ct.0[..]].concat(),
            now,
            &mut self.rng,
        )
        .await?;

        let right = words(&key);
        let correct = (self.rng.array::<1>("link/choice")?[0] % 4) as usize;
        let mut choices: [[String; 3]; 4] = Default::default();
        for (i, c) in choices.iter_mut().enumerate() {
            *c = if i == correct {
                right.clone()
            } else {
                let mut decoy = [0u8; 64];
                self.rng.fill("link/decoy", &mut decoy)?;
                words(&decoy)
            };
        }
        Ok(LinkOffer {
            code,
            entry,
            key,
            choices,
            correct,
        })
    }

    /// The person picked `choice`. Only the right words link the device.
    pub async fn link_confirm(&mut self, offer: LinkOffer, choice: usize) -> Result<()> {
        if choice != offer.correct {
            return Err(CoreError::Crypto);
        }
        let now = self.now();
        // New manifest with the device.
        let entry = offer.entry.clone();
        let signed = self
            .publish_manifest(|m| m.devices.push(entry), now)
            .await?;

        // The account, as a sealed blob.
        let mut w = Writer::new();
        w.u8(1)
            .bytes(&self.profile.encode())
            .bytes(&self.account.export_shared())
            .bytes(&signed.to_bytes());
        let roots: Vec<[u8; 64]> = self
            .contacts
            .values()
            .filter(|c| c.state == ContactState::Accepted && c.card.is_some() && c.inbox.is_some())
            .map(|c| c.root)
            .collect();
        w.u16(roots.len() as u16);
        for root in &roots {
            let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
            // The new device takes half of the tokens (single use, so each
            // device needs its own).
            let give = c.tokens.len() / 2;
            let tokens: Vec<Token> = c.tokens.drain(..give).collect();
            let card = c.card.clone().ok_or(CoreError::NotFound)?;
            w.bytes(&card.encode())
                .bytes(c.name.as_bytes())
                .u8(u8::from(c.verified))
                .u32(c.timer);
            w.fixed(&c.inbox.unwrap_or_default())
                .fixed(&c.server)
                .u16(tokens.len() as u16);
            for t in &tokens {
                w.fixed(t);
            }
            let c = c.clone();
            self.save_contact(&c)?;
        }
        let pkg = Zeroizing::new(w.finish());
        let host = self.profile.server;
        let (att, chunks) = files::seal_file(
            &pkg,
            "link",
            "application/x-enclave-link",
            host,
            &mut self.rng,
        )?;
        for (id, chunk) in &chunks {
            self.rpc
                .blob_put(&host, *id, chunk, now, &mut self.rng)
                .await?;
        }
        let sealed = seal::seal(
            &package_key(&offer.key),
            AD_LINK.as_bytes(),
            &att.encode(),
            &mut self.rng,
        )?;
        write(
            &mut self.rpc,
            &offer.code,
            &[&[U_PACKAGE][..], &sealed].concat(),
            now,
            &mut self.rng,
        )
        .await?;
        Ok(())
    }

    /// Sign and publish the next manifest version with `change` applied, and
    /// make it ours. Needs the root (primary device).
    pub(crate) async fn publish_manifest(
        &mut self,
        change: impl FnOnce(&mut Manifest),
        now: u64,
    ) -> Result<SignedManifest> {
        let prev = self.current_signed_manifest(now).await?;
        let mut m = self.manifest.clone();
        m.version += 1;
        m.prev_hash = prev.hash();
        m.issued_at = now;
        m.expires_at = now + MAX_VALIDITY_SECS;
        change(&mut m);
        let signed = m.sign(&self.account, &mut self.rng)?;
        // Co-signed by this device (listed in the current manifest), so
        // contacts take it at once rather than after the 72-hour guard.
        self.cosign_own(&signed, m.version, now).await?;
        let root = self.account.root_public.0;
        self.rpc
            .dir_put(
                &self.profile.server,
                DirKind::Manifest,
                manifest_key(&root),
                [0; 32],
                &signed.to_bytes(),
                now,
                &mut self.rng,
            )
            .await?;
        self.set_manifest(m, &signed)?;
        Ok(signed)
    }

    /// Adopt a verified manifest of our own account.
    pub(crate) fn set_manifest(&mut self, m: Manifest, signed: &SignedManifest) -> Result<()> {
        self.manifest = m;
        self.store.put(
            NS_PROFILE,
            b"manifest",
            &self.manifest.encode()?,
            &mut self.rng,
        )?;
        self.store.put(
            NS_PROFILE,
            b"signed-manifest",
            &signed.to_bytes(),
            &mut self.rng,
        )?;
        Ok(())
    }

    pub(crate) async fn current_signed_manifest(&mut self, now: u64) -> Result<SignedManifest> {
        if let Some(b) = self.store.get(NS_PROFILE, b"signed-manifest")? {
            return Ok(SignedManifest::from_bytes(&b)?);
        }
        let root = self.account.root_public.0;
        let b = self
            .rpc
            .dir_get(
                &self.profile.server,
                DirKind::Manifest,
                DirAction::Get,
                manifest_key(&root),
                [0; 32],
                now,
                &mut self.rng,
            )
            .await?;
        let sm = SignedManifest::from_bytes(&b)?;
        sm.verify(&RootPublic(root), now)?;
        Ok(sm)
    }

    /// A Hello for an existing contact (sent by a newly linked device).
    pub(crate) async fn hello_for(&mut self, root: &[u8; 64], now: u64) -> Result<Vec<u8>> {
        let tokens = self.issue_tokens(root, super::HELLO_TOKENS, now).await?;
        Ok(Content::Hello {
            server: self.profile.server,
            inbox: self.profile.addr_seed(),
            tokens,
            name: self.profile.name.clone(),
            text: String::new(),
            card: self.card().encode(),
            group: None,
            id: self.rng.array("core/msg-id")?,
        }
        .encode()?)
    }

    /// Send a copy of `content` (sent to `to`) to our other devices.
    pub(crate) async fn send_self_copy(
        &mut self,
        to: &[u8; 64],
        content: &Content,
        now: u64,
    ) -> Result<()> {
        let copy = Content::SelfCopy {
            to: *to,
            content: content.encode()?,
        }
        .encode()?;
        self.send_own(&copy, now).await
    }

    /// Send encoded content to every other device of ours we have a session
    /// with (one envelope, one slot per device).
    ///
    /// With no other device to send to (none, none active, or no session
    /// yet), a cover envelope goes instead: every message costs the same
    /// two writes whatever the number of devices (`06-multidevice.md` §4).
    pub(crate) async fn send_own(&mut self, copy: &[u8], now: u64) -> Result<()> {
        // Too large for one envelope: continuation units (`parts.rs`).
        let id = self.rng.array("core/part-id")?;
        let room = super::parts::PART_LEN;
        match super::parts::split(copy, room, id) {
            Some(parts) => {
                for p in parts {
                    self.send_own_unit(&p.encode()?, now).await?;
                }
                Ok(())
            }
            None => self.send_own_unit(copy, now).await,
        }
    }

    async fn send_own_unit(&mut self, copy: &[u8], now: u64) -> Result<()> {
        let own = self.account.root_public.0;
        let inactive: Vec<[u8; 16]> = self
            .own_devices()
            .into_iter()
            .filter(|d| d.inactive)
            .map(|d| d.id)
            .collect();
        let token = self
            .issue_tokens(&own, 1, now)
            .await?
            .pop()
            .ok_or(CoreError::OutOfTokens)?;
        let env = {
            let mut keys = Vec::new();
            let mut refs = Vec::new();
            for (k, s) in self.sessions.iter_mut() {
                if k.0 == own
                    && s.can_send()
                    && !inactive.contains(&k.1)
                    && refs.len() < MAX_DEVICES
                {
                    keys.push(*k);
                    refs.push(s);
                }
            }
            if refs.is_empty() {
                drop(refs);
                enclave_proto::envelope::cover_direct(&mut self.rng)?
            } else {
                let carrier = super::pq_carrier(&mut self.pq_carried, &keys, &refs);
                let env =
                    enclave_proto::envelope::seal_direct(&mut refs, copy, carrier, &mut self.rng)?;
                drop(refs);
                for k in keys {
                    if let Some(s) = self.sessions.get(&k) {
                        let s = s.clone();
                        self.save_session(&k.0, &k.1, &s)?;
                    }
                }
                env
            }
        };
        let h = RequestHeader {
            op: Op::Write,
            flags: 0,
            mailbox: self
                .profile
                .addr(enclave_rpc::api::week_of(self.inbox_now(now))),
            token,
        };
        let server = self.profile.server;
        self.rpc.write(&server, h, &env, now, &mut self.rng).await
    }
}
