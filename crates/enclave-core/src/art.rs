//! Key-derived contact art (`docs/17-design.md` §6.7, RT-26).
//!
//! A 5 × 5 grid, mirrored left to right, and one of 8 tints, all from
//! `art_seed = KMAC256(root_hash, "", 256, "enclave/v1/proto/contact-art")`.
//! Someone who makes an account to look like a contact (the same name, a
//! confusable username) gets other art, because their root differs. It is
//! never the only identifier: the security code is.

use enclave_crypto::kmac::kmac256;
use enclave_proto::otr::root_hash;

const L_ART: &str = "enclave/v1/proto/contact-art";

/// A contact's art.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContactArt {
    /// Filled cells, bit `5 × row + column` (row 0 at the top, column 0 on
    /// the left); always symmetric left to right, never empty.
    pub cells: u32,
    /// Which of the 8 art tints (`17-design.md` §6.7).
    pub tint: u8,
}

/// The art for root key `root`.
pub fn contact_art(root: &[u8; 64]) -> ContactArt {
    let seed: [u8; 32] = kmac256(&root_hash(root), b"", L_ART);
    // 15 bits: columns 0, 1, 2 of each row; 3 and 4 mirror 1 and 0.
    let bits = u32::from(u16::from_be_bytes([seed[0], seed[1]])) & 0x7fff;
    let bits = if bits == 0 { 0x7fff } else { bits };
    let mut cells = 0u32;
    for row in 0..5 {
        for col in 0..3 {
            if bits & (1 << (3 * row + col)) != 0 {
                cells |= 1 << (5 * row + col);
                cells |= 1 << (5 * row + (4 - col));
            }
        }
    }
    ContactArt {
        cells,
        tint: seed[2] % 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Art follows the root: one changed bit of the key gives other art,
    /// and it is mirrored and never blank (RT-26).
    #[test]
    fn rt26_contact_art_depends_on_root() {
        let a = [7u8; 64];
        let mut b = a;
        b[63] ^= 1;
        assert_eq!(contact_art(&a), contact_art(&a));
        assert_ne!(contact_art(&a), contact_art(&b));
        let mut seen = std::collections::HashSet::new();
        for i in 0..200u8 {
            let mut r = [0u8; 64];
            r[0] = i;
            let art = contact_art(&r);
            assert_ne!(art.cells, 0);
            assert!(art.tint < 8);
            for row in 0..5 {
                for col in 0..5 {
                    let on = |c: u32| art.cells & (1 << (5 * row + c)) != 0;
                    assert_eq!(on(col), on(4 - col), "mirrored");
                }
            }
            seen.insert((art.cells, art.tint));
        }
        assert!(seen.len() > 190, "{} distinct of 200", seen.len());
    }
}
