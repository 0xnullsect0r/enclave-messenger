//! Data-independent timing (`docs/02-cryptography.md` §12).
//!
//! On AArch64 CPUs with FEAT_DIT, setting PSTATE.DIT makes the timing of
//! data-processing instructions independent of their operands (Apple and
//! Arm recommend it around cryptography). [`Guard`] sets it for as long as
//! it lives on the current thread and restores what was there before. The
//! state is per thread and the kernel saves it across context switches, so
//! a guard is `!Send`: it must be dropped where it was made.
//!
//! Elsewhere the guard does nothing: x86's equivalent (DOITM) is set by the
//! kernel, not by programs.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

static ENTERED: AtomicU64 = AtomicU64::new(0);

/// Whether this CPU has FEAT_DIT.
pub fn supported() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("dit")
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Whether DIT is set on this thread now.
pub fn is_set() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        supported() && arm::read() & arm::DIT != 0
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// How many guards have been made in this process (for tests that a code
/// path runs under one).
pub fn guards_entered() -> u64 {
    ENTERED.load(Ordering::Relaxed)
}

/// DIT on, for as long as this lives.
#[must_use = "DIT is cleared again when the guard is dropped"]
pub struct Guard {
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    restore: bool,
    _thread: PhantomData<*const ()>,
}

impl Guard {
    /// Set DIT on this thread (where the CPU has it).
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        ENTERED.fetch_add(1, Ordering::Relaxed);
        #[cfg(target_arch = "aarch64")]
        {
            if supported() {
                let v = arm::read();
                if v & arm::DIT == 0 {
                    arm::write(v | arm::DIT);
                    return Self {
                        restore: true,
                        _thread: PhantomData,
                    };
                }
            }
        }
        Self {
            restore: false,
            _thread: PhantomData,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(target_arch = "aarch64")]
        if self.restore {
            arm::write(arm::read() & !arm::DIT);
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    /// PSTATE.DIT as seen through the DIT system register.
    pub const DIT: u64 = 1 << 24;

    /// Read the DIT register (`S3_3_C4_C2_5`). Only called when the CPU
    /// has FEAT_DIT.
    pub fn read() -> u64 {
        let v: u64;
        // SAFETY: the DIT register is readable at EL0 on CPUs with
        // FEAT_DIT, which every caller checks first; the instruction
        // touches no memory and no flags.
        unsafe {
            core::arch::asm!("mrs {0}, s3_3_c4_c2_5", out(reg) v, options(nomem, nostack, preserves_flags));
        }
        v
    }

    /// Write the DIT register. Only called when the CPU has FEAT_DIT.
    pub fn write(v: u64) {
        // SAFETY: as for `read`; writing DIT changes only instruction
        // timing, never results, and touches no memory and no flags.
        unsafe {
            core::arch::asm!("msr s3_3_c4_c2_5, {0}", in(reg) v, options(nomem, nostack, preserves_flags));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_sets_and_restores() {
        let before = is_set();
        let n = guards_entered();
        {
            let _g = Guard::new();
            assert_eq!(is_set(), supported(), "on wherever the CPU has it");
            {
                let _inner = Guard::new();
                assert_eq!(is_set(), supported());
            }
            assert_eq!(is_set(), supported(), "an inner guard leaves it on");
        }
        assert_eq!(is_set(), before, "restored");
        assert!(guards_entered() >= n + 2);
    }
}
