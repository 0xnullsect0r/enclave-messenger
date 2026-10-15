Enclave's programs for Linux, macOS and Windows, and the service images
and compose stack for operators.

**Check what you downloaded.** `SHA256SUMS` and `SHA3-512SUMS` list every
file; each has a Sigstore bundle (`*.sigstore.json`) made by this
repository's release workflow:

```
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/0xnullsect0r/enclave-messenger/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify FILE --repo 0xnullsect0r/enclave-messenger
```

Images: `cosign verify ghcr.io/0xnullsect0r/enclave-server:VERSION` with the
same identity. Operators: `docker compose -f oci://ghcr.io/0xnullsect0r/enclave-stack:VERSION up -d`
(see the operator kit).

**Windows** installers are not signed yet: Windows warns before running them.
