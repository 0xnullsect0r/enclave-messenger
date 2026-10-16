//! Secret poisoning under Valgrind ("ctgrind", `docs/02-cryptography.md`
//! §12, RT-15): mark a secret's bytes *undefined* to Memcheck, run the
//! code, and Memcheck reports every branch or memory address that depends
//! on them, which is exactly what constant-time code must not have.
//!
//! These are Valgrind's client requests (the magic instruction sequences
//! of `valgrind.h`): outside Valgrind they do nothing and return the
//! default, so a test can check [`on_valgrind`] first. Only for tests
//! (feature `ctgrind`); `cargo xtask ctgrind` runs them under Memcheck.

/// `VG_USERREQ_TOOL_BASE('M', 'C')`, Memcheck's first request.
const MEMCHECK: usize = ((b'M' as usize) << 24) | ((b'C' as usize) << 16);
const MAKE_MEM_UNDEFINED: usize = MEMCHECK + 1;
const MAKE_MEM_DEFINED: usize = MEMCHECK + 2;
const RUNNING_ON_VALGRIND: usize = 0x1001;
const COUNT_ERRORS: usize = 0x1201;

/// One client request: `args` is the request code and up to five
/// arguments; outside Valgrind the answer is `default`.
#[cfg(target_arch = "x86_64")]
fn request(default: usize, args: [usize; 6]) -> usize {
    let result;
    // SAFETY: the special sequence of `valgrind.h` for amd64. The four
    // rotations of RDI add up to 128 bits (RDI is unchanged) and
    // `xchg rbx, rbx` changes nothing, so natively this only moves
    // `default` to the result; under Valgrind the core reads the six words
    // at RAX (alive for the call) and writes its answer to RDX.
    unsafe {
        std::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            inout("rdx") default => result,
            in("rax") args.as_ptr(),
            inout("rdi") 0usize => _,
            options(nostack),
        );
    }
    result
}

#[cfg(target_arch = "aarch64")]
fn request(default: usize, args: [usize; 6]) -> usize {
    let result;
    // SAFETY: the special sequence of `valgrind.h` for arm64. The four
    // rotations of X12 add up to 128 bits and `orr x10, x10, x10` changes
    // nothing, so natively this only moves `default` to the result; under
    // Valgrind the core reads the six words at X4 and answers in X3.
    unsafe {
        std::arch::asm!(
            "ror x12, x12, #3",
            "ror x12, x12, #13",
            "ror x12, x12, #51",
            "ror x12, x12, #61",
            "orr x10, x10, x10",
            inout("x3") default => result,
            in("x4") args.as_ptr(),
            inout("x12") 0usize => _,
            options(nostack),
        );
    }
    result
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn request(default: usize, _args: [usize; 6]) -> usize {
    default
}

/// Whether this process runs under Valgrind.
pub fn on_valgrind() -> bool {
    request(0, [RUNNING_ON_VALGRIND, 0, 0, 0, 0, 0]) > 0
}

/// Errors Valgrind has reported so far (0 outside Valgrind).
pub fn errors() -> usize {
    request(0, [COUNT_ERRORS, 0, 0, 0, 0, 0])
}

/// Mark `secret` as undefined: from here on Memcheck reports any branch
/// or address computed from it.
pub fn poison(secret: &[u8]) {
    request(
        0,
        [
            MAKE_MEM_UNDEFINED,
            secret.as_ptr() as usize,
            secret.len(),
            0,
            0,
            0,
        ],
    );
}

/// Mark `value` as defined again (a result the caller may now look at).
pub fn unpoison(value: &[u8]) {
    request(
        0,
        [
            MAKE_MEM_DEFINED,
            value.as_ptr() as usize,
            value.len(),
            0,
            0,
            0,
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_do_nothing_outside_valgrind() {
        if on_valgrind() {
            return;
        }
        let s = [7u8; 32];
        poison(&s);
        unpoison(&s);
        assert_eq!(errors(), 0);
        assert_eq!(s, [7u8; 32]);
    }
}
