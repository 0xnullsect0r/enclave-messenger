# GDPR note (template)

*An analysis for operators in the EU/EEA and the UK. It is not legal
advice; have it reviewed for your situation.*

## Does the server process personal data?

The server holds:

| Data | Linkable to a person? | Retention |
|---|---|---|
| Encrypted envelopes and files | Not by the server: no key, no identity | At most `policy.ttl_days` (default 30) |
| Inbox addresses, token hashes | Pseudonymous random values | While in use; envelopes 30 days |
| Account manifests (public keys, device list) | Pseudonymous; public by design | While the account is on the server |
| Usernames in the key-transparency log | **Yes, if a user chooses a name that identifies them** | Permanent (append-only log); a deleted account leaves a tombstone |
| Sealed push tokens | Not by the server | Until replaced or the inbox is idle |
| Reports users send | **Yes: quoted messages may contain personal data** | At most 1,000 kept; delete them once handled |
| IP addresses | Not received (Tor, and the Nym mixnet when enabled); not logged | — |
| Backups | The same as above | `[backup] keep` snapshots (default 7) |

So the personal data you process is mainly **usernames** and the
**content of reports**.

## Legal basis

- Usernames: performance of a contract (Art. 6(1)(b)): the user asks for a
  name so others can find them.
- Reports: legitimate interest (Art. 6(1)(f)) in keeping the service free
  of abuse, balanced by keeping only what is needed for as long as needed.

## Data-subject rights

- **Access:** you can tell a user what username their account key holds in
  your log; you can't find an account any other way.
- **Erasure:** the key-transparency log is append-only, so a name can't be
  removed, only tombstoned (released). Explain this in your privacy notice:
  it is what lets users detect a server that lies about names.
- **Portability:** users move their account themselves (`move to another
  server` in the app).

## Records

Keep the Art. 30 record in `data-processing-record.md`.
