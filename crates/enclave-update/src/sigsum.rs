//! Sigsum inclusion proofs (`docs/19-ops.md` §1.2): that a release file's
//! hash is in a Sigsum log whose tree head enough witnesses cosigned.
//!
//! The proof is the text `sigsum-submit` writes (proof version 2, as
//! `sigsum-go` reads it), checked as `sigsum-verify` does:
//!
//! ```text
//! version=2
//! log=<hex SHA-256(log key)>
//! leaf=<hex SHA-256(submit key)> <hex signature>
//!
//! size=<n>
//! root_hash=<hex>
//! signature=<hex log signature>
//! cosignature=<hex SHA-256(witness key)> <time> <hex signature>   (any number)
//!
//! leaf_index=<i>                                                  (when n > 1)
//! node_hash=<hex>                                                 (the path)
//! ```
//!
//! - The logged message is `m` = SHA-256 of the file; the leaf's checksum
//!   is SHA-256(m), signed by a submit key as `"sigsum.org/v1/tree-leaf" ‖
//!   0 ‖ checksum`; the leaf is `checksum ‖ signature ‖ SHA-256(submit
//!   key)` and hashes as `SHA-256(0 ‖ leaf)`.
//! - The tree head is the checkpoint `origin "\n" size "\n" base64(root)
//!   "\n"` with origin `"sigsum.org/v1/tree/" hex(SHA-256(log key))`,
//!   signed by the log; a witness cosigns `"cosignature/v1\ntime " time
//!   "\n" checkpoint`.
//! - The inclusion path is RFC 9162's (interior nodes `SHA-256(1 ‖ l ‖ r)`).
//!
//! Checked against vectors made with sigsum-go (`ci/sigsum`).

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Why a proof doesn't hold.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigsumError {
    /// The text isn't a proof this reads.
    #[error("malformed Sigsum proof: {0}")]
    Malformed(&'static str),
    /// Not a log, submitter or witness the policy names.
    #[error("unknown Sigsum {0}")]
    Unknown(&'static str),
    /// A signature didn't verify.
    #[error("bad Sigsum {0} signature")]
    Signature(&'static str),
    /// Fewer witnesses than the quorum cosigned the tree head.
    #[error("only {0} witness cosignatures, need {1}")]
    Quorum(usize, usize),
    /// The path doesn't lead to the tree head's root.
    #[error("the leaf isn't in the tree")]
    Inclusion,
}

/// What a proof must satisfy: the log, who may submit, and how many of
/// which witnesses must cosign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The log's Ed25519 key.
    pub log: [u8; 32],
    /// Keys allowed to submit releases (the release workflow's).
    pub submitters: Vec<[u8; 32]>,
    /// Witness keys.
    pub witnesses: Vec<[u8; 32]>,
    /// How many distinct witnesses must cosign.
    pub quorum: usize,
}

/// A parsed proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// SHA-256 of the log key.
    pub log_key_hash: [u8; 32],
    /// SHA-256 of the submit key.
    pub submit_key_hash: [u8; 32],
    /// The leaf's signature.
    pub leaf_signature: [u8; 64],
    /// Tree size.
    pub size: u64,
    /// Tree root.
    pub root: [u8; 32],
    /// The log's signature on the tree head.
    pub signature: [u8; 64],
    /// `(witness key hash, time, signature)`.
    pub cosignatures: Vec<([u8; 32], u64, [u8; 64])>,
    /// Our leaf's index.
    pub leaf_index: u64,
    /// The inclusion path.
    pub path: Vec<[u8; 32]>,
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn unhex<const N: usize>(s: &str) -> Result<[u8; N], SigsumError> {
    let bad = SigsumError::Malformed("hex");
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(bad);
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| SigsumError::Malformed("hex"))?;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decimal(s: &str) -> Result<u64, SigsumError> {
    // As sigsum-go: digits only, no sign, no leading zeros.
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(SigsumError::Malformed("number"));
    }
    s.parse().map_err(|_| SigsumError::Malformed("number"))
}

/// The longest path a proof may have (sigsum-go's limit).
const MAX_PATH: usize = 63;

impl Proof {
    /// Read a proof (version 2).
    pub fn parse(text: &str) -> Result<Self, SigsumError> {
        let mut lines = text.split('\n');
        let mut next = |key: &'static str| -> Result<&str, SigsumError> {
            let line = lines.next().ok_or(SigsumError::Malformed(key))?;
            line.strip_prefix(key)
                .and_then(|r| r.strip_prefix('='))
                .ok_or(SigsumError::Malformed(key))
        };
        if next("version")? != "2" {
            return Err(SigsumError::Malformed("version"));
        }
        let log_key_hash = unhex(next("log")?)?;
        let (kh, sig) = next("leaf")?
            .split_once(' ')
            .ok_or(SigsumError::Malformed("leaf"))?;
        let (submit_key_hash, leaf_signature) = (unhex(kh)?, unhex(sig)?);
        let rest: Vec<&str> = lines.collect();
        let mut it = rest.into_iter();
        if it.next() != Some("") {
            return Err(SigsumError::Malformed("blank line"));
        }
        let mut field = |key: &'static str| -> Result<String, SigsumError> {
            it.next()
                .and_then(|l| l.strip_prefix(key))
                .and_then(|r| r.strip_prefix('='))
                .map(str::to_string)
                .ok_or(SigsumError::Malformed(key))
        };
        let size = decimal(&field("size")?)?;
        let root = unhex(&field("root_hash")?)?;
        let signature = unhex(&field("signature")?)?;
        let mut cosignatures = Vec::new();
        let mut line = it.next();
        while let Some(l) = line.and_then(|l| l.strip_prefix("cosignature=")) {
            let mut v = l.split(' ');
            let (Some(k), Some(t), Some(s), None) = (v.next(), v.next(), v.next(), v.next()) else {
                return Err(SigsumError::Malformed("cosignature"));
            };
            let k = unhex(k)?;
            if cosignatures.iter().any(|(c, _, _)| *c == k) {
                return Err(SigsumError::Malformed("duplicate cosignature"));
            }
            cosignatures.push((k, decimal(t)?, unhex(s)?));
            line = it.next();
        }
        if size == 0 {
            return Err(SigsumError::Malformed("empty tree"));
        }
        let (mut leaf_index, mut path) = (0, Vec::new());
        if size > 1 {
            if line != Some("") {
                return Err(SigsumError::Malformed("inclusion proof"));
            }
            let l = it.next().ok_or(SigsumError::Malformed("leaf_index"))?;
            leaf_index = decimal(
                l.strip_prefix("leaf_index=")
                    .ok_or(SigsumError::Malformed("leaf_index"))?,
            )?;
            line = it.next();
            while let Some(h) = line.and_then(|l| l.strip_prefix("node_hash=")) {
                if path.len() >= MAX_PATH {
                    return Err(SigsumError::Malformed("path too long"));
                }
                path.push(unhex(h)?);
                line = it.next();
            }
            if path.is_empty() {
                return Err(SigsumError::Malformed("empty path"));
            }
        }
        // Nothing may follow but the file's last newline.
        if !(line.is_none() || (line == Some("") && it.next().is_none())) {
            return Err(SigsumError::Malformed("trailing data"));
        }
        Ok(Proof {
            log_key_hash,
            submit_key_hash,
            leaf_signature,
            size,
            root,
            signature,
            cosignatures,
            leaf_index,
            path,
        })
    }

    /// Check that `message` (SHA-256 of the file) is logged under `policy`.
    pub fn verify(&self, message: &[u8; 32], policy: &Policy) -> Result<(), SigsumError> {
        // The log.
        if sha256(&[&policy.log]) != self.log_key_hash {
            return Err(SigsumError::Unknown("log"));
        }
        let log = VerifyingKey::from_bytes(&policy.log).map_err(|_| SigsumError::Unknown("log"))?;
        let origin = format!("sigsum.org/v1/tree/{}", hex(&self.log_key_hash));
        let checkpoint = format!("{origin}\n{}\n{}\n", self.size, base64(&self.root));
        log.verify_strict(
            checkpoint.as_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| SigsumError::Signature("log"))?;
        // Witnesses: each counted once, unknown ones ignored (as sigsum-go).
        let mut good = 0;
        for w in &policy.witnesses {
            let kh = sha256(&[w]);
            let Some((_, time, sig)) = self.cosignatures.iter().find(|(k, _, _)| *k == kh) else {
                continue;
            };
            let Ok(key) = VerifyingKey::from_bytes(w) else {
                continue;
            };
            let msg = format!("cosignature/v1\ntime {time}\n{checkpoint}");
            if key
                .verify_strict(msg.as_bytes(), &Signature::from_bytes(sig))
                .is_ok()
            {
                good += 1;
            }
        }
        if good < policy.quorum {
            return Err(SigsumError::Quorum(good, policy.quorum));
        }
        // The leaf, from an allowed submitter.
        let submitter = policy
            .submitters
            .iter()
            .find(|k| sha256(&[*k]) == self.submit_key_hash)
            .ok_or(SigsumError::Unknown("submitter"))?;
        let submitter =
            VerifyingKey::from_bytes(submitter).map_err(|_| SigsumError::Unknown("submitter"))?;
        let checksum = sha256(&[message]);
        let signed = [b"sigsum.org/v1/tree-leaf".as_slice(), &[0], &checksum].concat();
        submitter
            .verify_strict(&signed, &Signature::from_bytes(&self.leaf_signature))
            .map_err(|_| SigsumError::Signature("leaf"))?;
        let leaf = sha256(&[&[0], &checksum, &self.leaf_signature, &self.submit_key_hash]);
        if verify_inclusion(leaf, self.leaf_index, self.size, &self.root, &self.path) {
            Ok(())
        } else {
            Err(SigsumError::Inclusion)
        }
    }
}

/// RFC 9162 §2.1.3.2 inclusion check.
fn verify_inclusion(
    leaf: [u8; 32],
    index: u64,
    size: u64,
    root: &[u8; 32],
    path: &[[u8; 32]],
) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = leaf;
    for p in path {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = sha256(&[&[1], p, &r]);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = sha256(&[&[1], &r, p]);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let v = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(A[((v >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
