#!/bin/sh
# hax extraction (docs/20-assurance.md §2, "Code extraction"): the parts of
# enclave-crypto Enclave wrote itself on fiat-crypto's verified field
# arithmetic, the Ed448 signer and the X448 ladder, translated to F* by
# hax. The extraction checks that the code stays inside the Rust subset
# hax models (no unsupported constructs crept in); the F* lands in
# crates/enclave-crypto/proofs/fstar/extraction, uploaded by CI job `hax`.
#
# hax pins its own nightly compiler (older than the workspace's
# rust-version), hence --ignore-rust-version.
set -eu
cd "$(dirname "$0")/../../crates/enclave-crypto"
hax=${HAX:-cargo hax}
$hax -C --ignore-rust-version \; into \
    -i '-** +enclave_crypto::ed448_sign::** +enclave_crypto::x448_ladder::**' \
    fstar
ls proofs/fstar/extraction
