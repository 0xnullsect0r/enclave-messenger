# Law-enforcement guide

*For operators, and for the authorities who contact them. Replace the
[brackets].*

## Contact

Requests go to **[legal contact address]**. We answer in [language(s)].
Emergency requests (imminent risk to life): **[emergency address]**,
answered within [hours]. We may ask for confirmation through official
channels before acting.

## What we can and cannot provide

An Enclave server stores encrypted mail for anonymous inbox addresses. It
has no account records.

| Data | Can we provide it? | Notes |
|---|---|---|
| Account identity | No | The server has no accounts |
| Phone number, email | No | Never collected |
| IP addresses | No | Requests arrive through Tor (and the Nym mixnet when enabled); not logged |
| Message content | No | End-to-end encrypted; keys exist only on users' devices |
| Contacts, group membership | No | Not visible to the server |
| Inbox activity, for an inbox address you name | From the date of the order only | Counts of writes and polls in 60-second buckets, if we are ordered to start recording them. Pseudonymous: we can't say whose inbox it is or who writes to it |
| Stored ciphertext | Yes | Opaque 14,336-byte objects, useless without device keys; kept at most [30] days |
| Username → account key | Yes | Public in the key-transparency log anyway |
| Push tokens | No | The server holds only sealed tokens; the push relay holds platform tokens but not which inbox they serve |

We cannot add a device to an account, read future messages, or alter the
username log without other operators' witnesses detecting it; no court
order changes what the software can do.

## Which binary we run

Our releases are built reproducibly. Anyone can rebuild the published
source and get the same binaries (`cargo xtask repro`, `ops/docker/Dockerfile`),
and our transparency report lists the image digest of every release we ran.
That is how we show a court which software we run.

## Preservation

On a valid preservation request we keep, for the period it names, the
stored ciphertext for the inbox addresses it names (normally deleted
after [30] days).

## Notification

Unless the law prohibits it, we tell the holder of an affected inbox
address through the app's server notices that a request concerned it.
