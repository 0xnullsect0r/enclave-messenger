//! Secret hygiene (`docs/02-cryptography.md` §12): secret types can't be
//! printed, their bytes live in locked memory, and crypto runs with
//! data-independent timing where the CPU has it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::kem::{McElieceSecret, MlKemSecret, X448Public, X448Secret};
use enclave_crypto::rng::{HedgedRng, XofRng};
use enclave_crypto::seal::{self, SealKey};
use enclave_crypto::sig::{CompositeSigningKey, MlDsa44SigningKey, RootSigningKey};
use enclave_platform::{dit, mem};

/// Whether `$t` implements `Debug`, decided at compile time: the inherent
/// constant exists only when it does, and the trait's covers the rest.
macro_rules! implements_debug {
    ($t:ty) => {{
        #[allow(dead_code)]
        trait Fallback {
            const DEBUG: bool = false;
        }
        impl<T: ?Sized> Fallback for T {}
        struct Probe<T: ?Sized>(core::marker::PhantomData<T>);
        #[allow(dead_code)]
        impl<T: ?Sized + core::fmt::Debug> Probe<T> {
            const DEBUG: bool = true;
        }
        <Probe<$t>>::DEBUG
    }};
}

#[test]
fn secret_types_have_no_debug() {
    // The probe works: public types print.
    assert!(implements_debug!(X448Public));
    assert!(implements_debug!(u8));
    assert!(!implements_debug!(SealKey));
    assert!(!implements_debug!(X448Secret));
    assert!(!implements_debug!(MlKemSecret));
    assert!(!implements_debug!(McElieceSecret));
    assert!(!implements_debug!(CompositeSigningKey));
    assert!(!implements_debug!(MlDsa44SigningKey));
    assert!(!implements_debug!(RootSigningKey));
    assert!(!implements_debug!(HedgedRng));
    assert!(!implements_debug!(XofRng));
    assert!(!implements_debug!(mem::SecretBytes));
    assert!(!implements_debug!(mem::Secret<32>));
}

#[test]
fn long_term_keys_are_in_locked_memory() {
    let mut rng = HedgedRng::new().unwrap();
    let before = mem::stats();
    let keys = (
        CompositeSigningKey::generate(&mut rng).unwrap(),
        MlKemSecret::generate(&mut rng).unwrap(),
        RootSigningKey::from_recovery_secret(&[4; 32]),
    );
    let after = mem::stats();
    assert!(
        after.locked_bytes > before.locked_bytes || after.lock_failures > before.lock_failures,
        "{before:?} {after:?}"
    );
    drop(keys);
}

/// RT-15: crypto runs under a DIT guard, which sets the bit on CPUs that
/// have it (Apple silicon, recent Arm cores) and restores it after.
#[test]
fn rt15_dit_bit_set_during_crypto() {
    let mut rng = HedgedRng::new().unwrap();
    let key = SealKey::generate(&mut rng).unwrap();
    let n = dit::guards_entered();
    let sealed = seal::seal(&key, b"ad", b"pt", &mut rng).unwrap();
    assert!(dit::guards_entered() > n, "sealing takes a guard");
    let n = dit::guards_entered();
    assert_eq!(seal::open(&key, b"ad", &sealed).unwrap(), b"pt");
    let (sk, pk) = X448Secret::generate(&mut rng).unwrap();
    sk.diffie_hellman(&pk).unwrap();
    assert!(dit::guards_entered() >= n + 3, "open, public key and DH");
    let was = dit::is_set();
    {
        let _g = dit::Guard::new();
        assert_eq!(dit::is_set(), dit::supported());
    }
    assert_eq!(dit::is_set(), was);
}
