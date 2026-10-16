//! Domain-separation labels. Every KMAC256 call in Enclave uses exactly one of
//! these strings as its customization string `S`. The authoritative list is
//! `docs/label-registry.md`; a CI test checks that the two agree and that no
//! label is used twice.

/// EnclaveSeal hedged nonce derivation.
pub const SEAL_NONCE: &str = "enclave/v1/seal/nonce";
/// EnclaveSeal subkey derivation (XChaCha20 key, AES-256 key, MAC key, IVs).
pub const SEAL_KEYS: &str = "enclave/v1/seal/keys";
/// EnclaveSeal authentication tag.
pub const SEAL_TAG: &str = "enclave/v1/seal/tag";
/// EnclaveCombine (3-KEM) extraction step.
pub const KEM_EXTRACT: &str = "enclave/v1/kem/extract";
/// EnclaveCombine (3-KEM) combination step.
pub const KEM_COMBINE: &str = "enclave/v1/kem/combine";
/// EnclaveCombine (2-KEM, pre-braid) extraction step.
pub const KEM2_EXTRACT: &str = "enclave/v1/kem2/extract";
/// EnclaveCombine (2-KEM, pre-braid) combination step.
pub const KEM2_COMBINE: &str = "enclave/v1/kem2/combine";
/// EnclaveCombine (4-KEM, with HQC-256; feature `hqc`) extraction step.
pub const KEM4_EXTRACT: &str = "enclave/v1/kem4/extract";
/// EnclaveCombine (4-KEM, with HQC-256; feature `hqc`) combination step.
pub const KEM4_COMBINE: &str = "enclave/v1/kem4/combine";
/// Hedged random number generation.
pub const RNG_HEDGE: &str = "enclave/v1/rng/hedge";
/// Deterministic SLH-DSA root key generation from the recovery secret.
pub const ROOT_KEYGEN: &str = "enclave/v1/root/keygen";
/// Composite (Ed448 + ML-DSA-87) signature domain separation.
pub const SIG_COMPOSITE: &str = "enclave/v1/sig/composite";
/// Per-record storage key derivation.
pub const STORE_RECORD: &str = "enclave/v1/store/record";
/// Backup archive key derivation.
pub const BACKUP_KEY: &str = "enclave/v1/backup/key";
/// Root fingerprint (security code) derivation.
pub const FP_ROOT: &str = "enclave/v1/fp/root";

/// All labels defined by this crate, for uniqueness checks.
pub const ALL: &[&str] = &[
    SEAL_NONCE,
    SEAL_KEYS,
    SEAL_TAG,
    KEM_EXTRACT,
    KEM_COMBINE,
    KEM2_EXTRACT,
    KEM2_COMBINE,
    KEM4_EXTRACT,
    KEM4_COMBINE,
    RNG_HEDGE,
    ROOT_KEYGEN,
    SIG_COMPOSITE,
    STORE_RECORD,
    BACKUP_KEY,
    FP_ROOT,
];

#[cfg(test)]
mod tests {
    use super::ALL;
    use std::collections::HashSet;

    #[test]
    fn labels_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for l in ALL {
            assert!(seen.insert(*l), "duplicate label {l}");
            assert!(l.starts_with("enclave/v1/"), "bad prefix {l}");
            assert!(l.is_ascii());
        }
    }
}
