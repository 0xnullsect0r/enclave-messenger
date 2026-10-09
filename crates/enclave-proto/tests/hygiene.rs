//! Protocol secrets can't be printed (`docs/02-cryptography.md` §12).

use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::recovery::RecoverySecret;

/// Whether `$t` implements `Debug`, decided at compile time.
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
    assert!(implements_debug!(enclave_proto::identity::DeviceId));
    assert!(!implements_debug!(RecoverySecret));
    assert!(!implements_debug!(AccountKeys));
    assert!(!implements_debug!(DeviceKeys));
    assert!(!implements_debug!(enclave_proto::group::Group));
    assert!(!implements_debug!(enclave_proto::ratchet::Session));
}
