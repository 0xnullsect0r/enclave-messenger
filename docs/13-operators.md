# Operators: Moderation and Operator Kit

Status: Draft (M0) · Normative

Source: PLAN.md §12.4, §18 (operator program), RT-25, RT-28. Operator kit files live in `ops/operator-kit/`. This document fixes what operators can and cannot do, and what the kit must contain.

## 1. What operators can do (operators cannot see content)

| Action | Mechanism | Visible to users |
|---|---|---|
| Rate-limit | Server quotas, PoW effort, Privacy Pass issuance limits | Indirectly (slower sends, higher PoW) |
| Delete a reported blob | Delete by chunk ID from a report | The blob fails to download ("This file is no longer available.") |
| Disable a reported inbox or mailbox address | Mark the address disabled; writes get `DENIED` | Senders see "Couldn't deliver to Sam." after retries |
| Tombstone a username that breaks policy | KT tombstone entry: `[kt] withdrawn = ["name"]` in `server.toml`, applied at start (`12-servers.md` §3.5) | Visible in KT to anyone who looks the name up ("that name was withdrawn"); nobody can claim it again |
| Refuse registrations | Stop accepting `INBOX_REGISTER` or `KT_WRITE` | New users choose another server |

Operators MUST NOT be able to:

- read message content, capsules, or attachment content;
- learn who writes to an inbox, or link an inbox to a username, IP address, or device;
- add devices to an account, change a manifest, or forge a KT entry that witnesses will cosign;
- push a client update (updates are signed by maintainers, `19-ops.md`).

The software provides no admin interface that would suggest otherwise.

## 2. User reports

- A report is created by the user in the app: "Report" on a message or conversation. The user chooses what to include. Reports **voluntarily include the reported plaintext** and, for attachments, the blob pointer.
- Reports are sent through Enclave (end-to-end encrypted, over the mixnet) to the operator's report address published in the server descriptor.
- **Off-the-record chats:** a report is an unverifiable claim. The report UI says so: "Because this chat is off the record, the operator can't confirm who wrote these messages."
- **On-the-record chats:** the report includes the messages' composite signatures, which the operator checks against the sender's manifest, so the operator can verify authorship.
- Spam reports on message requests additionally feed local blocking and, if the reporter agrees, raise the request-inbox PoW effort for that sender's capability.

**As implemented** (`enclave-core/src/client/reports.rs`, `enclave-server`, `enclave-rpc::api::ReportBody`).

- **Where reports go.** The operator's report address is its server: a report is `Op::Report` (11) to the **reported person's home server**, sealed to the request key in that server's descriptor like every request, so only its operator reads it. It costs the request-inbox proof of work of the descriptor's policy, spent once. There is no second address to publish or keep in step.
- **What it says.** The header's mailbox is the reported account's request inbox (from their contact card), the one handle an operator can act on. The body is `u8 version 1 ‖ u8 reason (1 spam, 2 harassment or threats, 3 other) ‖ u8 on_record ‖ u8 n ‖ n × (u16 length ‖ UTF-8)`: up to 10 quoted messages of at most 1,024 B each, chosen by the reporter (their latest, as they see them), or none. On the record it goes on: `‖ reported root (64) ‖ u8 m ‖ m × (u16 length ‖ signed content ‖ device id (16) ‖ u64 counter ‖ recipient root hash (32) ‖ signature (4,741))`, the signatures of up to 2 of the quoted messages (the latest that verified when they arrived and weren't edited since, content at most 2,048 B); to fit one frame the oldest text quotes are left out first. Nothing in it names the reporter, except that a signed quote carries the root hash of the account it was sent to, which checking the signature needs. The server keeps at most 1,000 reports.
- **The app** offers **Report** on a message request and in the conversation sheet, with a reason, whether to quote, whether to block too, and, for spam, **"Make message requests cost more"**: for 30 days the reporter's server asks everyone writing to their request inbox for a proof of work of 256, then 1,024, … up to 16,384 on later reports (`Client::raise_request_effort`; `RegisterTokens` with `FLAG_EFFORT` and a `u32` payload, owner only, request inboxes only, at most `MAX_INBOX_EFFORT`). Senders' devices climb their effort ladder and still get through; someone sending many pays for each. After 30 days the client sets it back to the server's own (`relax_request_effort`). Tests `report_to_the_operator`, `an_owner_raises_what_requests_cost`.
- **The operator's console.** `enclave-server run` listens on `data_dir/admin.sock` (mode 0600, inside the server's container only) for one text command per connection (`enclave_server::admin`), and `enclave-admin reports` is its client: `docker compose exec server enclave-admin reports` lists waiting reports (id, day, reason, number of quotes, on or off the record, the request inbox), `reports show N` prints one with its quotes, `reports dismiss N` forgets it, `reports close-request-inbox HEX` closes the account's request inbox (no new requests, no replies to theirs). `enclave-admin console withdraw-username NAME` tombstones a name for breaking the policy, and `console stats` prints the aggregate counters. Tests `reports_through_the_console` (server), `reports_through_a_server_console` (the binary against a console socket).
- **Off or on the record.** From a conversation off the record `on_record` is 0, and both the app and the console say the operator can't confirm who wrote the quotes. From one on the record, `reports show N` checks each signed quote (`Server::verify_quotes`): the reported account's manifest held by this server must list the reported request inbox and the signing device, and the signature must verify over the conversation id (from the two root hashes), device, recipient, counter and content. It prints "verified, device …" with the text the device signed (the Protobuf text or caption, `api::quoted_text`), or why not. A device since removed from the account no longer verifies. Text quotes without a signature stay unverified claims. Tests `rt07_mode_switch_requires_authenticated_event` (core, end to end) and `signed_report_codec` (rpc).

## 3. Law-enforcement guide (content requirements)

The kit's guide MUST list, per data type, what an operator **can** and **cannot** provide.

| Data | Can provide | Notes |
|---|---|---|
| Account identity | No | The server has no accounts |
| Phone number, email | No | Never collected |
| IP addresses | No | Requests arrive through Nym and Tor; not logged |
| Message content | No | End-to-end encrypted; keys are only on devices |
| Contacts, group membership | No | Not visible to the server |
| Inbox activity (for a known inbox address) | Counts and 60 s timing buckets of writes and polls, from the moment logging is ordered | RT-28 residual: pseudonymous activity from that point on |
| Stored ciphertext | Yes, as opaque 14,336 B objects | Useless without device keys |
| Username → root hash mapping | Yes | Public in KT anyway |
| Push tokens | No | The server holds only sealed tokens; the push relay holds platform tokens but not inboxes |

The guide explains the reproducible-build process so that an operator can show a court which binary it runs.

## 4. Operator kit contents

| File | Content |
|---|---|
| `terms-of-service.md` | Template terms, including the no-content-access statement |
| `acceptable-use.md` | Template AUP: spam, abuse, illegal content; enforcement actions limited to §1 |
| `transparency-report.md` | Template: requests received, by type and jurisdiction; actions taken (§1 table); requests refused |
| `law-enforcement-guide.md` | §3, with contact procedure and emergency-request policy |
| `gdpr-note.md` | Analysis of what personal data (if any) the server processes, legal basis, retention (30/90 days), data-subject rights handling |
| `data-processing-record.md` | GDPR Art. 30 record template for operators |
| `deployment.md` | Docker and Nix deployment, KT backup, key rotation, descriptor publishing |
| `operator-family.md` | How to declare an operator family and why honesty matters for call-relay separation |

## 5. Operator program

- Vetting, a code of practice, and jurisdiction diversity are run by the foundation (PLAN §18).
- Launch target (M11): at least 5 operators across at least 3 jurisdictions, and at least 5 witnesses.
- Operators publish an annual transparency report. There is no warrant canary.
- Operators MUST run reproducible builds of the published server release and MUST back up the KT database.

## Open questions

1. Whether operators should be able to raise the request-inbox PoW effort for a specific capability after spam reports (§2), since capability IDs could become a weak linking handle.
2. The report address format and whether reports should also be deliverable to the foundation when the operator does not respond.
