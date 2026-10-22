# Record of processing activities (GDPR Art. 30) — template

| Field | Entry |
|---|---|
| Controller | [Operator name, address, contact] |
| Data protection officer | [If appointed: contact] |
| Purposes | (1) Delivering end-to-end encrypted messages and files between accounts; (2) publishing a verifiable directory of usernames; (3) handling abuse reports |
| Categories of data subjects | People with accounts on [domain]; people named in reports |
| Categories of personal data | Usernames chosen by users; text quoted in abuse reports. Message content is end-to-end encrypted and not accessible to us |
| Recipients | None. The username log is public by design (any client can look a name up) |
| Transfers to third countries | [None / describe hosting location] |
| Retention | Encrypted envelopes and files: [30] days. Usernames: append-only log, tombstoned on deletion. Reports: deleted once handled, at most [90] days. Backups: [7] daily snapshots |
| Security measures | End-to-end encryption; requests sealed to daily keys from a forward-secure chain; no IP logging (Tor, and the Nym mixnet when enabled); TLS 1.3 with post-quantum key exchange on the public front; containers without shell, as an unprivileged user, read-only filesystem; encrypted off-host key backups; reproducible builds |
