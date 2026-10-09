//! Argon2id (RFC 9106) for the optional app passphrase and the root PIN wrap.
//!
//! Full-entropy secrets (recovery secret, device keys) never go through
//! Argon2id; it exists only to stretch human-chosen secrets.

use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PwParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Iterations (t).
    pub iterations: u32,
    /// Parallelism (p).
    pub parallelism: u32,
}

impl PwParams {
    /// Desktop default: 1 GiB, t = 4, p = 4.
    pub const DESKTOP_DEFAULT: Self = Self {
        memory_kib: 1024 * 1024,
        iterations: 4,
        parallelism: 4,
    };
    /// Desktop maximum the settings UI offers: 4 GiB.
    pub const DESKTOP_MAX: Self = Self {
        memory_kib: 4 * 1024 * 1024,
        iterations: 4,
        parallelism: 4,
    };
    /// Mobile default: 256 MiB, t = 4, p = 2.
    pub const MOBILE_DEFAULT: Self = Self {
        memory_kib: 256 * 1024,
        iterations: 4,
        parallelism: 2,
    };
    /// Floor below which Enclave refuses to go (64 MiB, t = 3).
    pub const FLOOR: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    fn check(&self) -> Result<()> {
        if self.memory_kib < Self::FLOOR.memory_kib
            || self.iterations < Self::FLOOR.iterations
            || self.parallelism == 0
            || self.memory_kib > Self::DESKTOP_MAX.memory_kib
        {
            return Err(Error::Params);
        }
        Ok(())
    }
}

/// Derive a 32-byte key from `password` and a 32-byte `salt`.
pub fn derive(password: &[u8], salt: &[u8; 32], params: PwParams) -> Result<Zeroizing<[u8; 32]>> {
    params.check()?;
    derive_unchecked(password, salt, params)
}

fn derive_unchecked(
    password: &[u8],
    salt: &[u8; 32],
    params: PwParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let _dit = enclave_platform::dit::Guard::new();
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| Error::Params)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(password, salt, &mut out[..])
        .map_err(|_| Error::Params)?;
    Ok(out)
}

/// Pick the largest memory setting from `candidates_kib` (ascending) whose
/// derivation takes at most `target` on this device, never below the floor.
/// The device RAM ceiling (for example 1 GiB only with 6 GB of RAM or more) is
/// applied by the caller, which knows the platform.
pub fn calibrate(
    candidates_kib: &[u32],
    iterations: u32,
    parallelism: u32,
    target: std::time::Duration,
) -> PwParams {
    let mut best = PwParams::FLOOR;
    for &m in candidates_kib {
        let p = PwParams {
            memory_kib: m,
            iterations,
            parallelism,
        };
        if p.check().is_err() {
            continue;
        }
        let start = std::time::Instant::now();
        if derive_unchecked(b"calibration", &[0u8; 32], p).is_err() {
            break;
        }
        if start.elapsed() > target {
            break;
        }
        best = p;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_is_enforced() {
        let weak = PwParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert_eq!(derive(b"pw", &[0; 32], weak).unwrap_err(), Error::Params);
    }

    #[test]
    fn derivation_is_deterministic_and_salted() {
        let p = PwParams::FLOOR;
        let a = derive(b"correct horse", &[1; 32], p).unwrap();
        let b = derive(b"correct horse", &[1; 32], p).unwrap();
        let c = derive(b"correct horse", &[2; 32], p).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn rfc9106_argon2id_vector() {
        // RFC 9106 §5.3: m=32 KiB, t=3, p=4, secret = 0x03*8, AD = 0x04*12.
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(argon2::AssociatedData::new(&[4u8; 12]).unwrap())
            .build()
            .unwrap();
        let a =
            argon2::Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params)
                .unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
            .unwrap();
        assert_eq!(
            out,
            hex_literal::hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }
}
