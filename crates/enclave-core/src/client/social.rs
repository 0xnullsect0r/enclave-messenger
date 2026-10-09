//! Social recovery (`docs/03-identity.md` §8.3).
//!
//! The 256-bit recovery secret is split with SLIP-0039 (`enclave-slip39`)
//! into one share per chosen contact, any `threshold` of which rebuild it.
//! Each share travels to its holder over the pairwise session
//! (`Content::RecoveryShare`) and is kept in the holder's sealed store.
//!
//! When someone loses every device, they meet each holder in person; the
//! holder's app shows the share (words, or a QR code) only on request, and
//! the new device combines `threshold` shares back into the recovery words
//! ([`words_from_shares`]). From there it is an ordinary restore, so the
//! 72-hour guard (§8.1) still protects the account: a restore no device
//! co-signed waits, and any remaining device can stop it.
//!
//! The holder's app never shows the share as words: the recovering
//! person's new device shows a request code ([`ShareRequest`], fresh X448
//! and ML-KEM-1024 keys), the holder confirms they are with them and scans
//! it, and the share comes back sealed to those keys as another code
//! ([`Client::release_recovery_share`]); both screens show the same three
//! words, so the holder knows they scanned the right screen.
//!
//! Giving shares again makes a new split. Old shares still rebuild the same
//! secret (it doesn't change), so taking a holder's share away changes the
//! recovery words themselves ([`Client::remove_recovery_holder`]).

use super::Client;
use crate::card::{LinkError, b64url_decode, b64url_encode};
use crate::content::Content;
use crate::{CoreError, Result};
use enclave_crypto::kem::{
    MLKEM_CT_LEN, MLKEM_PK_LEN, MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448_LEN,
    X448Public, X448Secret, combine,
};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::recovery::RecoverySecret;
use zeroize::Zeroizing;

pub(crate) const NS_HELD_SHARES: &str = "held-shares";
const GIVEN: &str = "recovery-shares-given";
/// Most holders.
pub const MAX_HOLDERS: usize = 16;

/// The recovery words rebuilt from `threshold` SLIP-0039 shares.
pub fn words_from_shares(shares: &[&str]) -> Result<String> {
    let secret = enclave_slip39::combine(shares, b"").map_err(|_| CoreError::Crypto)?;
    let arr: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Crypto)?;
    Ok(RecoverySecret::from_bytes(arr).to_words()?.join(" "))
}

impl Client {
    /// Split the recovery secret among `holders` (accepted contacts), any
    /// `threshold` of whom can help rebuild it, and send each their share.
    pub async fn give_recovery_shares(
        &mut self,
        holders: &[[u8; 64]],
        threshold: u8,
    ) -> Result<()> {
        let n = holders.len();
        if !(2..=MAX_HOLDERS).contains(&n) || threshold < 2 || usize::from(threshold) > n {
            return Err(CoreError::TooLong);
        }
        for h in holders {
            let c = self.contact(h).ok_or(CoreError::NotFound)?;
            if c.state != super::ContactState::Accepted {
                return Err(CoreError::NotAccepted);
            }
        }
        let secret = Zeroizing::new(
            self.store
                .get(super::NS_SECRETS, b"recovery")?
                .ok_or(CoreError::NotFound)?,
        );
        let rng = &mut self.rng;
        let mut fill = |b: &mut [u8]| {
            if rng.fill("core/slip39", b).is_err() {
                b.fill(0);
            }
        };
        let shares =
            enclave_slip39::generate(1, &[(threshold, n as u8)], &secret, b"", true, 1, &mut fill)
                .map_err(|_| CoreError::Crypto)?;
        let now = self.now();
        for (h, share) in holders.iter().zip(shares.into_iter().flatten()) {
            self.send_content(h, &Content::RecoveryShare(share), now)
                .await?;
        }
        let mut record = vec![threshold];
        for h in holders {
            record.extend_from_slice(h);
        }
        self.set_setting(GIVEN, &record)?;
        Ok(())
    }

    /// Who holds a share of our recovery, and how many are needed.
    pub fn recovery_holders(&self) -> Option<(u8, Vec<[u8; 64]>)> {
        let r = self.setting(GIVEN).ok()??;
        let (&t, rest) = r.split_first()?;
        Some((
            t,
            rest.chunks_exact(64)
                .filter_map(|c| c.try_into().ok())
                .collect(),
        ))
    }

    /// A share `from` gave us to keep (an empty one: forget theirs, they
    /// changed their words without us).
    pub(crate) fn keep_recovery_share(&mut self, from: &[u8; 64], share: &str) -> Result<()> {
        if share.is_empty() {
            self.store.delete(NS_HELD_SHARES, from)?;
            return Ok(());
        }
        self.store
            .put(NS_HELD_SHARES, from, share.as_bytes(), &mut self.rng)?;
        Ok(())
    }

    /// Whether we hold part of `root`'s recovery.
    pub fn holds_recovery_share(&self, root: &[u8; 64]) -> bool {
        matches!(self.store.get(NS_HELD_SHARES, root), Ok(Some(_)))
    }

    /// The share we hold for `root`, to show them in person.
    pub fn recovery_share_for(&self, root: &[u8; 64]) -> Option<Zeroizing<String>> {
        let b = self.store.get(NS_HELD_SHARES, root).ok()??;
        Some(Zeroizing::new(String::from_utf8(b).ok()?))
    }
}

/// Prefix of a recovering person's request for a share, shown on their new
/// device for each holder to scan in person.
pub const RELEASE_PREFIX: &str = "enclave:release#";
/// Prefix of a holder's answer: the share, sealed to the request.
pub const SHARE_PREFIX: &str = "enclave:share#";

/// Three words from a request code, shown on both screens so the holder
/// knows they scanned the right one.
fn check_words(request: &[u8]) -> [String; 3] {
    let d: [u8; 32] = enclave_crypto::kmac::kmac256(
        &enclave_crypto::hash::sha3_512(request),
        b"",
        "enclave/v1/proto/share-words",
    );
    let words = enclave_proto::recovery::Language::English.word_list();
    let pick = |i: usize| words[usize::from(u16::from_be_bytes([d[2 * i], d[2 * i + 1]])) % 2048];
    [pick(0).into(), pick(1).into(), pick(2).into()]
}

/// The key a share is sealed under: X448 and ML-KEM-1024 to the request's
/// keys, combined (`EnclaveCombine`, two KEMs) over both codes' public parts.
fn release_key(dh: &[u8], ss: &[u8], request: &[u8], eph: &[u8], ct: &[u8]) -> SealKey {
    let k = combine(Suite::TwoKem, &[dh, ss], &[request, eph, ct], None);
    SealKey::from_bytes(enclave_crypto::kmac::kmac256(
        &k[..],
        b"",
        "enclave/v1/proto/share-release",
    ))
}

/// On the recovering person's new device, before there is an account: a
/// request each holder of a share scans in person (`03-identity.md` §8.3).
/// Its keys live only in memory.
pub struct ShareRequest {
    x448: X448Secret,
    mlkem: MlKemSecret,
    /// `1 ‖ X448 public ‖ ML-KEM-1024 public`.
    payload: Vec<u8>,
}

impl ShareRequest {
    /// A fresh request.
    pub fn new() -> Result<Self> {
        let mut rng = HedgedRng::new()?;
        let (x448, xp) = X448Secret::generate(&mut rng)?;
        let (mlkem, mp) = MlKemSecret::generate(&mut rng)?;
        let mut w = Writer::new();
        w.u8(1).fixed(&xp.0).fixed(&mp.0[..]);
        Ok(Self {
            x448,
            mlkem,
            payload: w.finish(),
        })
    }

    /// The code to show (as a QR code).
    pub fn code(&self) -> String {
        format!("{RELEASE_PREFIX}{}", b64url_encode(&self.payload))
    }

    /// The words the holder's screen should show too.
    pub fn words(&self) -> [String; 3] {
        check_words(&self.payload)
    }

    /// Open a holder's answer: their share's words.
    pub fn open(&self, answer: &str) -> Result<Zeroizing<String>> {
        let body = answer
            .trim()
            .strip_prefix(SHARE_PREFIX)
            .ok_or(LinkError::NotEnclave)?;
        let b = b64url_decode(body).ok_or(LinkError::Malformed)?;
        let mut r = Reader::new(&b);
        if r.u8()? != 1 {
            return Err(LinkError::Malformed.into());
        }
        let eph: [u8; X448_LEN] = r.array()?;
        let ct = MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN)?)?;
        let sealed = r.bytes(1024)?;
        r.end()?;
        let dh = self.x448.diffie_hellman(&X448Public(eph))?;
        let ss = self.mlkem.decapsulate(&ct);
        let key = release_key(&dh[..], &ss[..], &self.payload, &eph, &ct.0[..]);
        let pt = Zeroizing::new(seal::open(&key, &self.payload, sealed)?);
        Ok(Zeroizing::new(
            String::from_utf8(pt.to_vec()).map_err(|_| CoreError::Crypto)?,
        ))
    }
}

/// What a holder shows after scanning a request.
pub struct ShareRelease {
    /// The words the recovering person's screen shows: compare them.
    pub words: [String; 3],
    /// The sealed share, for the recovering person to scan.
    pub code: String,
}

impl Client {
    /// We hold a share for `root`, who is in front of us: seal it to the
    /// request code on their new device. Only after the person confirmed
    /// they are with them (`03-identity.md` §8.3); the share never shows
    /// as words.
    pub fn release_recovery_share(
        &mut self,
        root: &[u8; 64],
        request: &str,
    ) -> Result<ShareRelease> {
        let share = self.recovery_share_for(root).ok_or(CoreError::NotFound)?;
        let body = request
            .trim()
            .strip_prefix(RELEASE_PREFIX)
            .ok_or(LinkError::NotEnclave)?;
        let payload = b64url_decode(body).ok_or(LinkError::Malformed)?;
        let mut r = Reader::new(&payload);
        if r.u8()? != 1 {
            return Err(LinkError::Malformed.into());
        }
        let xp: [u8; X448_LEN] = r.array()?;
        let mp = MlKemPublic::from_slice(r.fixed(MLKEM_PK_LEN)?)?;
        r.end()?;
        let (eph, eph_pub) = X448Secret::generate(&mut self.rng)?;
        let dh = eph.diffie_hellman(&X448Public(xp))?;
        let (ct, ss) = mp.encapsulate(&mut self.rng)?;
        let key = release_key(&dh[..], &ss[..], &payload, &eph_pub.0, &ct.0[..]);
        let sealed = seal::seal(&key, &payload, share.as_bytes(), &mut self.rng)?;
        let mut w = Writer::new();
        w.u8(1).fixed(&eph_pub.0).fixed(&ct.0[..]).bytes(&sealed);
        Ok(ShareRelease {
            words: check_words(&payload),
            code: format!("{SHARE_PREFIX}{}", b64url_encode(&w.finish())),
        })
    }

    /// Take `root`'s share away (see [`Client::reshare_recovery`]):
    /// returns the new recovery words.
    pub async fn remove_recovery_holder(&mut self, root: &[u8; 64]) -> Result<Vec<String>> {
        let (threshold, holders) = self.recovery_holders().ok_or(CoreError::NotFound)?;
        if !holders.contains(root) {
            return Err(CoreError::NotAccepted);
        }
        let left: Vec<[u8; 64]> = holders.into_iter().filter(|h| h != root).collect();
        let t = threshold.min(left.len() as u8).max(2);
        self.reshare_recovery(&left, t)
            .await?
            .ok_or(CoreError::NotAccepted)
    }

    /// Choose again who holds a share. If everyone holding one now is
    /// kept, it is a new split ([`Client::give_recovery_shares`]; their old
    /// shares still rebuild the same words, which is fine). If someone is
    /// dropped, their share must stop working, and old shares always
    /// rebuild the words they were made from: so the recovery words
    /// change (03 §8.2), the new holders get shares of the new ones, and
    /// those dropped are told to forget theirs. Returns the new words in
    /// that case. Fewer than two holders: no social recovery any more.
    pub async fn reshare_recovery(
        &mut self,
        holders: &[[u8; 64]],
        threshold: u8,
    ) -> Result<Option<Vec<String>>> {
        let current = self.recovery_holders().map(|(_, h)| h).unwrap_or_default();
        let dropped: Vec<[u8; 64]> = current
            .iter()
            .filter(|h| !holders.contains(h))
            .copied()
            .collect();
        if dropped.is_empty() {
            self.give_recovery_shares(holders, threshold).await?;
            return Ok(None);
        }
        if !self.holds_recovery_words() || self.migration_pending() {
            return Err(CoreError::NotAccepted);
        }
        let n = holders.len();
        if n >= 2 {
            if threshold < 2 || usize::from(threshold) > n || n > MAX_HOLDERS {
                return Err(CoreError::TooLong);
            }
            for h in holders {
                let c = self.contact(h).ok_or(CoreError::NotFound)?;
                if c.state != super::ContactState::Accepted {
                    return Err(CoreError::NotAccepted);
                }
            }
            let mut record = vec![threshold];
            for h in holders {
                record.extend_from_slice(h);
            }
            self.set_setting(GIVEN, &record)?;
        } else {
            self.store
                .delete(crate::persist::NS_SETTINGS, GIVEN.as_bytes())?;
        }
        let now = self.now();
        // Best effort: a dropped share is worthless once the words change.
        for h in &dropped {
            let _ = self
                .send_content(h, &Content::RecoveryShare(String::new()), now)
                .await;
        }
        // The migration gives the new holders their shares as it goes.
        self.change_recovery_words().await.map(Some)
    }
}
