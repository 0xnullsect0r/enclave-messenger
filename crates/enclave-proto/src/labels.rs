//! Protocol-layer KMAC labels (see `docs/label-registry.md`).

/// Root-signature context for account manifests.
pub const CTX_MANIFEST: &str = "enclave/v1/ctx/manifest";
/// Composite-signature context for signed prekeys.
pub const CTX_SIGNED_PREKEY: &str = "enclave/v1/ctx/signed-prekey";
/// Composite-signature context for one-time prekey batches.
pub const CTX_OPK_BATCH: &str = "enclave/v1/ctx/opk-batch";
/// Composite-signature context for last-resort PQ prekeys.
pub const CTX_LAST_RESORT: &str = "enclave/v1/ctx/last-resort";
/// Composite-signature context for On-the-record message signatures.
pub const CTX_SIGNED_MESSAGE: &str = "enclave/v1/ctx/signed-msg";
/// Composite-signature context for On-the-record group messages.
pub const GRP_SIGNED_MSG: &str = "enclave/v1/proto/grp-signed-msg";
/// Composite-signature context for an admin's state update in a group on
/// the record.
pub const GRP_ADMIN_SIG: &str = "enclave/v1/proto/grp-admin-sig";
/// Composite-signature context for a poll creator's tally in a group on the
/// record.
pub const POLL_TALLY: &str = "enclave/v1/proto/poll-tally";
/// `root_hash` of a root public key.
pub const ROOT_HASH: &str = "enclave/v1/proto/root-hash";
/// A 1:1 conversation's id.
pub const CONV_ID: &str = "enclave/v1/proto/conv-id";
/// Composite-signature context for the initiator's transcript signature.
pub const CTX_EQXDH_TRANSCRIPT: &str = "enclave/v1/ctx/eqxdh-transcript";
/// Composite-signature context for a device approving a manifest change.
pub const CTX_MANIFEST_COSIGN: &str = "enclave/v1/ctx/manifest-cosign";
/// Composite-signature context for a device vetoing a manifest change.
pub const CTX_MANIFEST_VETO: &str = "enclave/v1/ctx/manifest-veto";
/// Root-signature context for a change of recovery words (old and new root).
pub const CTX_MIGRATION: &str = "enclave/v1/ctx/migration";
/// Root-signature context for moving an account to another server.
pub const CTX_SERVER_MOVE: &str = "enclave/v1/proto/moved";
/// Root-signature context for deleting an account (its username tombstone).
pub const CTX_TOMBSTONE: &str = "enclave/v1/proto/tombstone";

/// EQXDH stage-1 key that seals the initiator's identity.
pub const EQXDH_IDENTITY: &str = "enclave/v1/eqxdh/identity";
/// Initial ratchet root key.
pub const RATCHET_INIT_RK: &str = "enclave/v1/ratchet/init-rk";
/// Initial header keys.
pub const RATCHET_INIT_HK: &str = "enclave/v1/ratchet/init-hk";
/// Initial PQ roots.
pub const RATCHET_INIT_PQ: &str = "enclave/v1/ratchet/init-pq";
/// Root-key step (DH ratchet).
pub const RATCHET_RK: &str = "enclave/v1/ratchet/rk";
/// Chain-key step.
pub const RATCHET_CK: &str = "enclave/v1/ratchet/ck";
/// Lookup tag.
pub const RATCHET_TAG: &str = "enclave/v1/ratchet/tag";
/// Final message key (DR ‖ PQ).
pub const RATCHET_MSG: &str = "enclave/v1/ratchet/msg";
/// Body-key wrap.
pub const RATCHET_WRAP: &str = "enclave/v1/ratchet/wrap";
/// PQ slot sealing key.
pub const RATCHET_PQ_SLOT: &str = "enclave/v1/ratchet/pq-slot";
/// PQ root step.
pub const PQ_STEP: &str = "enclave/v1/pq/step";
/// PQ epoch key from (out root, in root).
pub const PQ_KEY: &str = "enclave/v1/pq/key";
/// Merkle leaf and node hashing for one-time prekey batches.
pub const MERKLE: &str = "enclave/v1/prekey/merkle";
/// In-person bond PSK.
pub const BOND: &str = "enclave/v1/bond/psk";
/// Seal words shown after an in-person scan.
pub const BOND_SEAL_WORDS: &str = "enclave/v1/bond/seal-words";
/// Hash of a closed poll's tally (`docs/07-groups.md` §7.5).
pub const POLL_TALLY_HASH: &str = "enclave/v1/proto/poll-tally-hash";
/// One-way PSK from an invite link's secret.
pub const INVITE_PSK: &str = "enclave/v1/invite/psk";
/// Request-inbox capabilities from an invite link's secret.
pub const INVITE_CAP: &str = "enclave/v1/invite/cap";

/// All labels in this crate, for uniqueness checks.
pub const ALL: &[&str] = &[
    CTX_MANIFEST,
    CTX_SERVER_MOVE,
    CTX_TOMBSTONE,
    CTX_SIGNED_PREKEY,
    CTX_OPK_BATCH,
    CTX_LAST_RESORT,
    CTX_SIGNED_MESSAGE,
    CTX_EQXDH_TRANSCRIPT,
    EQXDH_IDENTITY,
    RATCHET_INIT_RK,
    RATCHET_INIT_HK,
    RATCHET_INIT_PQ,
    RATCHET_RK,
    RATCHET_CK,
    RATCHET_TAG,
    RATCHET_MSG,
    RATCHET_WRAP,
    RATCHET_PQ_SLOT,
    PQ_STEP,
    PQ_KEY,
    MERKLE,
    BOND,
    BOND_SEAL_WORDS,
    INVITE_PSK,
    INVITE_CAP,
    POLL_TALLY_HASH,
];

/// Group: exporter key from a pairwise session.
pub const GRP_EXPORT: &str = "enclave/v1/proto/grp-export";
/// Group: sender chain step.
pub const GRP_CHAIN: &str = "enclave/v1/proto/grp-chain";
/// Group: MAC-vector entry.
pub const GRP_MAC: &str = "enclave/v1/proto/grp-mac";
/// Group: MAC-vector entry of an admin state update.
pub const GRP_ADMIN_MAC: &str = "enclave/v1/proto/grp-admin-mac";
/// Group: routing-header keystream.
pub const GRP_HEADER: &str = "enclave/v1/proto/grp-header";
/// Group: bucket key.
pub const GRP_BUCKET: &str = "enclave/v1/proto/grp-bucket";
/// Group: bucket index of a device.
pub const GRP_BUCKET_INDEX: &str = "enclave/v1/proto/grp-bucket-index";
/// Group: rekey entry pad.
pub const GRP_REKEY_PAD: &str = "enclave/v1/proto/grp-rekey-pad";
/// Group: rekey entry check value.
pub const GRP_REKEY_CHECK: &str = "enclave/v1/proto/grp-rekey-check";
/// Group: state hash chain.
pub const GRP_STATE: &str = "enclave/v1/proto/grp-state";
/// Group: message identifier.
pub const GRP_MSG_ID: &str = "enclave/v1/proto/grp-msg-id";
/// Group: mailbox address for a day.
pub const NET_GRP_MAILBOX: &str = "enclave/v1/net/grp-mailbox";
/// Group: rekey bucket mailbox for a day.
pub const NET_GRP_REKEY_MAILBOX: &str = "enclave/v1/net/grp-rekey-mailbox";
/// Group: write key.
pub const NET_GRP_WRITE_KEY: &str = "enclave/v1/net/grp-write-key";
/// Group: write token for a mailbox address.
pub const NET_GRP_WRITE_TOKEN: &str = "enclave/v1/net/grp-write-token";

#[cfg(test)]
mod tests {
    #[test]
    fn unique_and_disjoint_from_crypto() {
        let mut all: Vec<&str> = super::ALL.to_vec();
        all.extend_from_slice(enclave_crypto::labels::ALL);
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n);
    }
}
