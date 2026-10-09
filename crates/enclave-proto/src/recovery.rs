//! Recovery words: the 256-bit recovery secret as 24 BIP-39 words.
//!
//! The recovery secret deterministically derives the SLH-DSA account root
//! (`enclave_crypto::sig::RootSigningKey::from_recovery_secret`) and the backup
//! key. Whoever holds the words can take over the account after the 72-hour
//! pending window, so the UI treats them like a house key.

use crate::error::{ProtoError, Result};
pub use bip39::Language;
use enclave_crypto::rng::HedgedRng;
use enclave_platform::mem::Secret;
use zeroize::Zeroizing;

/// A 256-bit recovery secret, in locked memory and zeroized on drop.
pub struct RecoverySecret(Secret<32>);

impl RecoverySecret {
    /// Generate a fresh secret.
    pub fn generate(rng: &mut HedgedRng) -> Result<Self> {
        Ok(Self(Secret::new(rng.array("recovery/secret")?)))
    }

    /// Wrap existing bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Secret::new(b))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 24 English words.
    pub fn to_words(&self) -> Result<Vec<String>> {
        self.to_words_in(Language::English)
    }

    /// The 24 words in `language` (any of BIP-39's ten lists). The words
    /// stand for the same secret in every language, so the account is the
    /// same whichever list it was written down in.
    pub fn to_words_in(&self, language: Language) -> Result<Vec<String>> {
        let m = bip39::Mnemonic::from_entropy_in(language, &self.0[..])
            .map_err(|_| ProtoError::Recovery)?;
        Ok(m.words().map(str::to_owned).collect())
    }

    /// Parse 24 words in any BIP-39 language, found from the words (case,
    /// extra whitespace and Unicode form are ignored).
    pub fn from_words(phrase: &str) -> Result<Self> {
        let normalized = phrase
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" ");
        let m = bip39::Mnemonic::parse(normalized.as_str()).map_err(|_| ProtoError::Recovery)?;
        let entropy = Zeroizing::new(m.to_entropy());
        let arr: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| ProtoError::Recovery)?;
        Ok(Self::from_bytes(arr))
    }
}

/// Every BIP-39 language, with its code: `en`, `es`, `fr`, `it`, `pt`, `cs`,
/// `ja`, `ko`, `zh-Hans`, `zh-Hant`.
pub fn languages() -> [(&'static str, Language); 10] {
    [
        ("en", Language::English),
        ("es", Language::Spanish),
        ("fr", Language::French),
        ("it", Language::Italian),
        ("pt", Language::Portuguese),
        ("cs", Language::Czech),
        ("ja", Language::Japanese),
        ("ko", Language::Korean),
        ("zh-Hans", Language::SimplifiedChinese),
        ("zh-Hant", Language::TraditionalChinese),
    ]
}

/// The language with code `code` (see [`languages`]).
pub fn language(code: &str) -> Option<Language> {
    languages()
        .into_iter()
        .find(|(c, _)| *c == code)
        .map(|(_, l)| l)
}

/// The spoken form of the security code (`02b-key-schedule.md` §4.1,
/// `03-identity.md` §6.2): five BIP-39 words from each side's fingerprint
/// (the 55 bits after the 30 bytes the digits use), the lower fingerprint
/// first, so both people read the same 10 words (110 bits) in the same
/// list.
pub fn security_words(root_a: &[u8], root_b: &[u8], language: Language) -> Vec<String> {
    let fa = enclave_crypto::hash::root_fingerprint(root_a);
    let fb = enclave_crypto::hash::root_fingerprint(root_b);
    let (lo, hi) = if fa.digest <= fb.digest {
        (fa, fb)
    } else {
        (fb, fa)
    };
    let list = language.word_list();
    [lo.digest, hi.digest]
        .iter()
        .flat_map(|d| {
            let mut b = [0u8; 8];
            b[1..].copy_from_slice(&d[30..37]);
            let v = u64::from_be_bytes(b);
            (0..5).map(move |i| ((v >> (45 - 11 * i)) & 0x7ff) as usize)
        })
        .map(|i| list[i].to_string())
        .collect()
}

/// The BIP-39 English word list (for short check phrases elsewhere).
pub fn english_words() -> &'static [&'static str; 2048] {
    bip39::Language::English.word_list()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_roundtrip() {
        let mut rng = HedgedRng::new().unwrap();
        let s = RecoverySecret::generate(&mut rng).unwrap();
        let words = s.to_words().unwrap();
        assert_eq!(words.len(), 24);
        let back = RecoverySecret::from_words(&words.join("  ").to_uppercase()).unwrap();
        assert_eq!(back.as_bytes(), s.as_bytes());
    }

    #[test]
    fn checksum_catches_typos() {
        let s = RecoverySecret::from_bytes([7; 32]);
        let mut words = s.to_words().unwrap();
        words.swap(0, 1);
        // A swap changes the checksum with overwhelming probability.
        assert!(RecoverySecret::from_words(&words.join(" ")).is_err() || words[0] == words[1]);
        assert!(RecoverySecret::from_words("abandon abandon").is_err());
    }

    /// Every language's words stand for the same secret, and are told
    /// apart without being told which language they are in.
    #[test]
    fn every_language() {
        let s = RecoverySecret::from_bytes([0x5a; 32]);
        for (code, lang) in languages() {
            assert_eq!(language(code), Some(lang));
            let words = s.to_words_in(lang).unwrap();
            assert_eq!(words.len(), 24, "{code}");
            let back = RecoverySecret::from_words(&words.join(" ")).unwrap();
            assert_eq!(back.as_bytes(), s.as_bytes(), "{code}");
        }
        assert_eq!(language("xx"), None);
    }

    #[test]
    fn spoken_security_code() {
        let (a, b) = ([1u8; 64], [2u8; 64]);
        let w = security_words(&a, &b, Language::English);
        assert_eq!(w.len(), 10);
        assert_eq!(
            w,
            security_words(&b, &a, Language::English),
            "the same both sides"
        );
        assert_ne!(w, security_words(&a, &[3u8; 64], Language::English));
        let fr = security_words(&a, &b, Language::French);
        let en_idx: Vec<usize> = w
            .iter()
            .map(|x| english_words().iter().position(|y| y == x).unwrap())
            .collect();
        let fr_idx: Vec<usize> = fr
            .iter()
            .map(|x| {
                Language::French
                    .word_list()
                    .iter()
                    .position(|y| y == x)
                    .unwrap()
            })
            .collect();
        assert_eq!(en_idx, fr_idx, "the same words in another list");
    }
}
