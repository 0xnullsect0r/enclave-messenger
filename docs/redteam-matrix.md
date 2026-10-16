# Red-Team Matrix

Status: Draft (M0) · Normative

Source: PLAN.md §1.4 and §21. Every row maps to at least one specification section and at least one named test. Tests live in `tests/` or in `enclave-sim` scenarios, and each test name below MUST exist in CI by the milestone listed. A row whose test is missing or failing blocks the milestone's exit gate. Adversary capability tags (A-GPO, A-NET, and so on) are defined in `01-threat-model.md` §2.

Test naming: `rtNN_<short_description>`. When a row needs several tests they share the prefix. "Sim" means an `enclave-sim` adversary scenario; "Shape" means `cargo xtask shape`; "Unit" means a crate unit or integration test; "E2E" means the end-to-end harness; "Manual" means a scripted manual check recorded in the release checklist.

## 1. Matrix

### RT-01 Long-term intersection attack
- **Adversary:** A-GPO, A-INF.
- **Attack:** Correlate when you are online with writes to an inbox, over weeks or months.
- **Fix:** Always-on Background profile on Android and desktop. Fixed send slots on the tick schedule. Unlinkable single-use write tokens. Push wakes quantized into 60 s windows. Maximum privacy mode.
- **Residual:** iOS app-open times remain visible. A pair who talk often can be narrowed down over months.
- **Spec:** `09-transport.md` §3, §6; `10-push.md` §3.
- **Tests:** `rt01_background_profile_constant_when_idle` (Shape, M4); `rt01_send_slots_independent_of_real_traffic` (Shape, M4); `rt01_tokens_unlinkable_across_writes` (Sim, M3).
- **Milestone:** M3, M4.

### RT-02 n-1 attack or flooding by a malicious gateway or mix
- **Adversary:** A-INF, A-NET.
- **Attack:** Hold back or flood all traffic except the target's to isolate one message.
- **Fix:** Nym loop cover (1 per 10 s in Foreground and Maximum, 1 per tick in Background). Enclave self-loop probes. If loss exceeds 10% or latency exceeds 5× the rolling median, the client switches gateway and records a local event.
- **Residual:** A single message can be targeted this way.
- **Spec:** `09-transport.md` §6.4.
- **Tests:** `rt02_gateway_switch_on_loss_over_10pct` (Sim, M4); `rt02_gateway_switch_on_latency_over_5x_median` (Sim, M4).
- **Milestone:** M4.

### RT-03 Active tagging of Sphinx packets
- **Adversary:** A-INF, A-NET.
- **Attack:** Modify packet bits at one hop and watch for the malformed result downstream.
- **Fix:** A tagged unit fails the EnclaveSeal tag check at the server and is dropped with no distinguishable response. Tor hides the client IP from the gateway.
- **Residual:** A colluding gateway and server can learn "this Tor circuit talks to server S".
- **Spec:** `02-cryptography.md` §4.4; `09-transport.md` §2.
- **Tests:** `rt03_bitflip_in_any_unit_byte_rejected` (Unit, M1); `rt03_rejected_request_gets_no_distinct_reply` (Sim, M3).
- **Milestone:** M1, M3.

### RT-04 Key-transparency split view
- **Adversary:** A-INF.
- **Attack:** Show different users different keys for the same username.
- **Fix:** Tree heads are valid only with ≥3 independent witness cosignatures (≥2 during beta, at least one from another operator). Head digests are gossiped in message padding. Clients audit their own entries anonymously. Security codes remain available.
- **Residual:** A colluding witness quorum against a target who has checked no contacts.
- **Spec:** `12-servers.md` §3; `08-envelope.md` §5.6.
- **Tests:** `rt04_split_view_detected_by_gossip` (Sim, M3); `rt04_head_rejected_below_witness_quorum` (Unit, M3); `rt04_self_audit_detects_foreign_entry` (Sim, M3).
- **Milestone:** M3.

### RT-05 Malicious prekey server
- **Adversary:** A-INF.
- **Attack:** Withhold or replay prekeys.
- **Fix:** Signed prekeys expire after 14 days. Responders keep a replay cache of initial-message hashes for the signed prekey's lifetime plus 7 days. The bundle epoch is committed in the manifest.
- **Residual:** If the one-time prekey is withheld, forward secrecy for the first message rests only on the signed prekey.
- **Spec:** `04-eqxdh.md` §2, §10.
- **Tests:** `rt05_replayed_initial_message_rejected` (Sim, M2); `rt05_expired_spk_rejected` (Unit, M2); `rt05_bundle_epoch_mismatch_rejected` (Unit, M2).
- **Milestone:** M2.

### RT-06 Draining one-time prekeys
- **Adversary:** A-INF, A-SOC.
- **Attack:** Claim all one-time prekeys to force weaker first messages.
- **Fix:** proof-of-work to claim one. A last-resort PQ prekey rotates every 7 days.
- **Residual:** An attacker can force use of the last-resort key.
- **Spec:** `04-eqxdh.md` §2.3; `02-cryptography.md` §10.
- **Tests:** `rt06_opk_claim_requires_pow` (Unit, M3); `rt06_last_resort_used_when_drained` (Sim, M3).
- **Milestone:** M3.

### RT-07 Downgrade
- **Adversary:** A-NET, A-INF.
- **Attack:** Strip the PQ or McEliece parts, or switch modes.
- **Fix:** No negotiation in v1. Suite ID, `H512(McE_pk)`, and mode are bound into the manifest, the transcript, and associated data. Mode changes are in-band authenticated events shown in the UI. The fallback transport requires user consent.
- **Residual:** An attacker can delay the McEliece braid; the session still has X448 + ML-KEM-1024.
- **Spec:** `02-cryptography.md` §5; `04-eqxdh.md` §7, §11; `05-ratchet.md` §9.
- **Tests:** `rt07_stripped_mceliece_rejected` (Unit, M1 for the combiner, Sim M2 for the protocol); `rt07_psk_flag_downgrade_rejected` (Unit, M1); `rt07_kem2_kem3_label_confusion_rejected` (Unit, M1); `rt07_mode_switch_requires_authenticated_event` (Unit, M2).
- **Milestone:** M1, M2.

### RT-08 State rollback from a snapshot or backup
- **Adversary:** A-DEV.
- **Attack:** Restore an old copy of device state to force nonce or key reuse.
- **Fix:** Hedged nonces and hedged RNG. Backups exclude ratchet state. The database is excluded from OS backups.
- **Residual:** Old messages could be accepted again, but confidentiality is never lost. Device-slot headers use a detached nonce and can leak the XOR of two slot headers under rollback (`05-ratchet.md` §6.4).
- **Spec:** `02-cryptography.md` §4, §6; `14-storage.md` §4.
- **Tests:** `rt08_rollback_no_keystream_reuse` (Unit, M1); `rt08_backup_contains_no_ratchet_state` (Unit, M5); `rt08_db_excluded_from_os_backup` (Manual, M5).
- **Milestone:** M1, M5.

### RT-09 Device-link phishing
- **Adversary:** A-SOC.
- **Attack:** Trick a user into scanning an attacker's link QR code.
- **Fix:** Linking starts only from Settings → Your devices. The link QR uses a distinct URI type that the general scanner and deep links refuse. Pick-1-of-4 phrase check. History transfer waits 24 h. A banner on every device for 7 days. Inactive linked devices expire after 30 days.
- **Residual:** A user who is socially engineered through every step.
- **Spec:** `03-identity.md` §4.
- **Tests:** `rt09_link_qr_refused_by_general_scanner` (Unit, M5); `rt09_link_qr_refused_by_deep_link` (Unit, M5); `rt09_history_transfer_delayed_24h` (Sim, M5); `rt09_new_device_banner_7_days` (Unit, M6).
- **Milestone:** M5, M6.

### RT-10 Invite links leaking
- **Adversary:** A-SOC, A-INF.
- **Attack:** A leaked invite link is used by strangers.
- **Fix:** The secret lives in the URL fragment. Links are limited-use, expire, and can be revoked. Requests land in quarantine (Message requests).
- **Residual:** Spam requests until the link is revoked.
- **Spec:** `03-identity.md` §9; `09-transport.md` §4.
- **Tests:** `rt10_invite_secret_only_in_fragment` (Unit, M5); `rt10_revoked_invite_rejected` (Sim, M5); `rt10_invite_use_limit_enforced` (Sim, M5).
- **Milestone:** M5.

### RT-11 Malicious admin forking group state
- **Adversary:** A-SOC (insider).
- **Attack:** Show different members different group states.
- **Fix:** Group state is a hash chain. Every message carries the state hash and a causal frontier. Membership changes are always shown in the chat.
- **Residual:** Admins can legitimately add people, and everyone sees it.
- **Spec:** `07-groups.md` §7.
- **Tests:** `rt11_group_fork_detected` (Sim, M7); `rt11_equivocation_detected_via_frontier` (Sim, M7); `rt11_membership_change_rendered_in_chat` (Unit, M7).
- **Milestone:** M7.

### RT-12 Fingerprinting the cover-traffic implementation
- **Adversary:** A-GPO.
- **Attack:** Distinguish Enclave users or individual clients by traffic shape.
- **Fix:** Three global profiles. Packet-paced traffic. Nym default delays. Profile changes only at foreground/background transitions.
- **Residual:** "Is an Enclave user" and "screen is on" remain visible.
- **Spec:** `09-transport.md` §6.
- **Tests:** `rt12_profiles_identical_across_clients` (Shape, M4); `rt12_profile_change_only_on_visibility_transition` (Unit, M4).
- **Milestone:** M4.

### RT-13 Targeted malicious update
- **Adversary:** A-SUP, A-LEG.
- **Attack:** Serve one user a backdoored build.
- **Fix:** Reproducible builds. TUF with 2-of-3 SLH-DSA + Ed448 maintainer signatures. Sigsum log. Update manifests fetched over the mixnet.
- **Residual:** App stores can serve a targeted binary. Detectable, not preventable.
- **Spec:** `19-ops.md` §1.
- **Tests:** `rt13_update_rejected_without_2_of_3` (Unit, M10); `rt13_update_rejected_without_sigsum_inclusion` (Unit, M10); `rt13_reproducible_build_diff_empty` (CI, M10).
- **Milestone:** M10.

### RT-14 Crate supply chain
- **Adversary:** A-SUP.
- **Attack:** A malicious or compromised dependency.
- **Fix:** `cargo vet`, `cargo deny`, vendoring, a build.rs and proc-macro allowlist, hermetic Nix builds, and the process split.
- **Residual:** iOS runs as a single process.
- **Spec:** `19-ops.md` §2; `15-client.md` §1.
- **Tests:** `rt14_netd_has_no_key_material` (Unit, M5); `rt14_build_rs_allowlist_enforced` (CI, M0); `rt14_cargo_vet_complete_for_crypto_and_parsers` (CI, M1).
- **Milestone:** M0, M1, M5.

### RT-15 Side channels in the crypto
- **Adversary:** A-DEV (co-resident), A-NET (remote timing).
- **Attack:** Timing or cache side channels.
- **Fix:** `subtle` for comparisons. dudect and ctgrind/secret-poisoning tests. ARM DIT bit. Hardware AES or bitsliced (fixslice) fallback. `mlock`. Core dumps disabled.
- **Residual:** Physical, power, and EM side channels.
- **Spec:** `02-cryptography.md` §12.
- **Tests:** `rt15_dudect_mac_compare` (CI, M1); `rt15_ctgrind_mlkem_decap` (CI, M1); `rt15_ctgrind_mceliece_decap` (CI, M1); `rt15_dit_bit_set_during_crypto` (Unit, M1). Also under ctgrind: the X448 ladder, sealing, MAC compare, token verification and Ed448 signing.
- **Milestone:** M1.

### RT-16 iOS push timing
- **Adversary:** A-LEG (Apple), A-GPO.
- **Attack:** Use APNs wake timing to infer activity.
- **Fix:** 60 s windows. 0 to 30 s jitter. Dummy wakes only with Apple's filtering entitlement. Fixed-size capsule. A "Notifications off" option.
- **Residual:** Apple learns which windows had at least one message.
- **Spec:** `10-push.md` §3, §5.
- **Tests:** `rt16_one_wake_per_window` (Sim, M4); `rt16_capsule_always_1024_bytes` (Unit, M2).
- **Milestone:** M2, M4.

### RT-17 Correlating blob uploads and fetches
- **Adversary:** A-INF.
- **Attack:** Match an upload to its fetchers by size and ID.
- **Fix:** Size buckets. Random blob IDs. Delayed fetches with 1 to 3 decoy fetches. McEliece keys fetched as encrypted blobs.
- **Residual:** Approximate fan-out count.
- **Spec:** `08-envelope.md` §9; `09-transport.md` §9.
- **Tests:** `rt17_attachment_padded_to_bucket` (Unit, M1); `rt17_fetch_includes_decoys` (Sim, M4); `rt17_blob_ids_not_content_derived` (Unit, M1).
- **Milestone:** M1, M4.

### RT-18 Colluding call relays plus a global observer
- **Adversary:** A-INF, A-GPO.
- **Attack:** Link both call legs by timing.
- **Fix:** Each side picks a relay from a different operator family. PQ PSK obtained anonymously. Maximum mode keeps a constant audio-shaped tunnel open.
- **Residual:** Call start and stop times without Maximum mode.
- **Spec:** `11-calls.md` §3, §7.
- **Tests:** `rt18_relays_from_distinct_operator_families` (Unit, M8); `rt18_max_mode_tunnel_constant` (Shape, M8).
- **Milestone:** M8.

### RT-19 Traffic analysis of CBR media
- **Adversary:** A-GPO, A-INF.
- **Attack:** Infer speech or activity from packet sizes and rates.
- **Fix:** Opus CBR, DTX off. RFC 6464 audio-level extension forbidden. Fixed packet size and rate. Padding while muted or with the camera off. Quality can only step down.
- **Residual:** Audio-only vs. video tier is visible.
- **Spec:** `11-calls.md` §6.
- **Tests:** `rt19_call_packets_constant_size_and_rate` (Shape, M8); `rt19_rfc6464_extension_rejected` (Unit, M8); `rt19_mute_keeps_rate` (Shape, M8).
- **Milestone:** M8.

### RT-20 Deanonymizing push tokens
- **Adversary:** A-INF, A-LEG.
- **Attack:** Link a device's mailboxes or server through its push token.
- **Fix:** Tokens are sealed to the relay and re-randomized on each registration. The relay is reached over Nym. The Android default avoids FCM.
- **Residual:** On iOS, activity windows can be tied to a device.
- **Spec:** `10-push.md` §2.
- **Tests:** `rt20_sealed_token_differs_per_registration` (Unit, M4); `rt20_server_never_sees_plain_token` (Sim, M4).
- **Milestone:** M4.

### RT-21 Temporary device compromise
- **Adversary:** A-DEV.
- **Attack:** Copy all device state, then leave.
- **Fix:** 1:1 heals in one round trip. Groups heal on the next rekey. "Secure my account" rotates everything. Root operations are gated by a PIN.
- **Residual:** Message history already on the device is exposed.
- **Spec:** `05-ratchet.md` §8; `07-groups.md` §8; `03-identity.md` §5.
- **Tests:** `rt21_pcs_after_one_round_trip` (Sim, M2); `rt21_group_pcs_after_rekey` (Sim, M7); `rt21_secure_my_account_rotates_all` (E2E, M5).
- **Milestone:** M2, M5, M7.

### RT-22 Theft of the recovery words
- **Adversary:** A-SOC, A-DEV.
- **Attack:** Use stolen words to take over the account.
- **Fix:** Root actions without a co-signature from an existing device wait 72 h and can be vetoed by any device. Contacts' clients enforce the delay.
- **Residual:** Recovery is slow if every device is lost.
- **Spec:** `03-identity.md` §8.1.
- **Tests:** `rt22_pending_root_veto_honored` (Sim, M5); `rt22_contacts_enforce_72h` (Sim, M5).
- **Milestone:** M5.

### RT-23 Clock manipulation
- **Adversary:** A-NET, A-DEV.
- **Attack:** Shift the device clock to accept expired keys or break timers.
- **Fix:** Trusted time is the median of witness timestamps. Skew warnings. Disappearing timers run on local monotonic time after receipt.
- **Residual:** A device that is offline and has had its clock tampered with.
- **Spec:** `12-servers.md` §3.5.
- **Tests:** `rt23_clock_skew_warning_shown` (Sim, M5); `rt23_disappearing_timer_uses_monotonic` (Unit, M6).
- **Milestone:** M5, M6.

### RT-24 Server replays or delays messages
- **Adversary:** A-INF.
- **Attack:** Deliver a message twice, or hold it back.
- **Fix:** Counters, skipped-key cache, and single-use tokens. "Delivered late" indicator. Gap notice after 60 s.
- **Residual:** A server can still drop messages. Probes detect it.
- **Spec:** `05-ratchet.md` §10, §11; `09-transport.md` §3.
- **Tests:** `rt24_replayed_message_rejected` (Sim, M2); `rt24_gap_notice_after_60s` (Sim, M2); `rt24_token_reuse_rejected` (Unit, M3).
- **Milestone:** M2, M3.

### RT-25 Spam and Sybil accounts with no identity
- **Adversary:** A-SOC.
- **Attack:** Mass requests from free accounts.
- **Fix:** Invite capability or proof of work. Text-only requests. Quotas. Local blocking.
- **Residual:** Well-funded PoW spam can still reach the requests folder.
- **Spec:** `09-transport.md` §4; `13-operators.md` §1.
- **Tests:** `rt25_request_requires_pow_or_capability` (Unit, M3); `rt25_request_inbox_caps_at_100` (Unit, M3); `rt25_request_media_stripped` (Unit, M6).
- **Milestone:** M3, M6.

### RT-26 Lookalike usernames and first-contact MITM
- **Adversary:** A-SOC, A-INF.
- **Attack:** Register a confusable name, or substitute keys at first contact.
- **Fix:** UTS #39 confusable-skeleton uniqueness. Key-derived contact art. In-person QR scan.
- **Residual:** Trust on first use until the contact is checked.
- **Spec:** `12-servers.md` §3.3; `03-identity.md` §6, §7.
- **Tests:** `rt26_confusable_username_rejected` (Unit, M3); `rt26_contact_art_depends_on_root` (Unit, M6).
- **Milestone:** M3, M6.

### RT-27 Quantum computer used on recorded transport metadata
- **Adversary:** A-QC, A-GPO.
- **Attack:** Break recorded Sphinx and Tor layers after 2035.
- **Fix:** Sealed requests (X448 + ML-KEM-1024) to a daily server key that is deleted after use.
- **Residual:** Recorded traffic reveals routing, but not mailbox IDs or content.
- **Spec:** `09-transport.md` §2.
- **Tests:** `rt27_request_fields_only_inside_pq_seal` (Unit, M1); `rt27_server_request_key_deleted_after_rotation` (Unit, M3).
- **Milestone:** M1, M3.

### RT-28 Operators legally compelled to log
- **Adversary:** A-LEG.
- **Attack:** Force an operator to start logging.
- **Fix:** Nothing identifying to log. Reproducible server builds.
- **Residual:** Pseudonymous inbox activity from that point on.
- **Spec:** `12-servers.md` §1; `13-operators.md` §3.
- **Tests:** `rt28_server_state_contains_no_ip_or_account` (Sim, M3); `rt28_server_build_reproducible` (CI, M10).
- **Milestone:** M3, M10.

## 2. Summary table

| ID | Attack | Fix (short) | Residual (short) | Spec | Primary test |
|---|---|---|---|---|---|
| RT-01 | Long-term intersection | Background profile, fixed slots, tokens, push windows, Maximum | iOS open times; frequent pairs over months | 09 §3 §6, 10 §3 | `rt01_background_profile_constant_when_idle` |
| RT-02 | n-1 / flooding | Loop cover, self-probes, gateway switch | One message targetable | 09 §6.4 | `rt02_gateway_switch_on_loss_over_10pct` |
| RT-03 | Sphinx tagging | Seal check drops; Tor | Circuit-to-server link | 02 §4.4, 09 §2 | `rt03_bitflip_in_any_unit_byte_rejected` |
| RT-04 | KT split view | ≥3 witnesses, gossip, self-audit | Colluding quorum | 12 §3 | `rt04_split_view_detected_by_gossip` |
| RT-05 | Prekey withhold/replay | 14-day SPK, replay cache, bundle epoch | First-message FS on SPK only | 04 §2 §10 | `rt05_replayed_initial_message_rejected` |
| RT-06 | OPK drain | Proof of work; last-resort PQ prekey | Forced last-resort | 04 §2.3 | `rt06_opk_claim_requires_pow` |
| RT-07 | Downgrade | No negotiation; binding | Braid delayed | 02 §5, 04 §7 | `rt07_stripped_mceliece_rejected` |
| RT-08 | Rollback | Hedged nonces; no ratchet in backups | Replays; slot-header XOR | 02 §4 §6 | `rt08_rollback_no_keystream_reuse` |
| RT-09 | Link phishing | Settings-only, URI type, 1-of-4, 24 h, banner | Fully deceived user | 03 §4 | `rt09_link_qr_refused_by_general_scanner` |
| RT-10 | Invite leak | Fragment, limits, revocation, quarantine | Spam until revoked | 03 §9 | `rt10_revoked_invite_rejected` |
| RT-11 | Admin fork | Hash chain, frontier, visible changes | Legit adds visible | 07 §7 | `rt11_group_fork_detected` |
| RT-12 | Cover fingerprinting | 3 global profiles | User/screen-on visible | 09 §6 | `rt12_profiles_identical_across_clients` |
| RT-13 | Targeted update | Repro, TUF 2-of-3, Sigsum, mixnet fetch | Store binaries | 19 §1 | `rt13_update_rejected_without_2_of_3` |
| RT-14 | Crate supply chain | vet, deny, vendoring, split | iOS single process | 19 §2, 15 §1 | `rt14_netd_has_no_key_material` |
| RT-15 | Crypto side channels | subtle, dudect, ctgrind, DIT | Physical channels | 02 §12 | `rt15_dudect_mac_compare` |
| RT-16 | iOS push timing | Windows, jitter, fixed capsule | Windows with messages | 10 §3 §5 | `rt16_one_wake_per_window` |
| RT-17 | Blob correlation | Buckets, random IDs, decoys | Fan-out count | 08 §9, 09 §9 | `rt17_attachment_padded_to_bucket` |
| RT-18 | Relay collusion | Distinct families, anon PSK, Max tunnel | Call times | 11 §3 §7 | `rt18_relays_from_distinct_operator_families` |
| RT-19 | CBR media analysis | CBR, no DTX, no RFC 6464, padding | Audio vs video tier | 11 §6 | `rt19_call_packets_constant_size_and_rate` |
| RT-20 | Push-token deanon | Sealed, re-randomized, via Nym | iOS windows per device | 10 §2 | `rt20_sealed_token_differs_per_registration` |
| RT-21 | Temporary compromise | 1-RT heal, rekey, Secure my account | Stored history | 05 §8, 07 §8 | `rt21_pcs_after_one_round_trip` |
| RT-22 | Stolen recovery words | 72 h pending + veto | Slow recovery | 03 §8.1 | `rt22_pending_root_veto_honored` |
| RT-23 | Clock manipulation | Witness median time | Offline tampered device | 12 §3.5 | `rt23_clock_skew_warning_shown` |
| RT-24 | Replay/delay | Counters, tokens, gap notice | Drops | 05 §10 §11 | `rt24_replayed_message_rejected` |
| RT-25 | Spam/Sybil | Capability or PoW, text-only, quotas | Funded PoW spam | 09 §4 | `rt25_request_requires_pow_or_capability` |
| RT-26 | Lookalikes/MITM | UTS #39, contact art, in-person | TOFU | 12 §3.3, 03 §6 | `rt26_confusable_username_rejected` |
| RT-27 | CRQC on metadata | Sealed requests | Routing visible | 09 §2 | `rt27_request_fields_only_inside_pq_seal` |
| RT-28 | Compelled logging | Nothing to log; repro builds | Pseudonymous activity | 12 §1 | `rt28_server_state_contains_no_ip_or_account` |

## 3. Cross-cutting tests from PLAN §21

These tests are not tied to a single row but back several:

| Test | Backs |
|---|---|
| `inv_every_wire_unit_16384` | RT-12, RT-17, D1 |
| `inv_every_stored_object_14336` | RT-17, D1 |
| `inv_poll_object_2048_single_mailbox` | RT-01, D7 |
| `inv_server_sees_no_device_count` | RT-01, D5 |
| `inv_server_never_sees_initiator_identity` | RT-01, `04-eqxdh.md` §4 |
| `inv_no_repeated_tokens_at_server` | RT-01, RT-24 |
| `inv_label_registry_unique` | all crypto rows |
| `inv_no_secret_type_implements_debug` | RT-15 |

## Open questions

1. **Resolved:** RT-01 keeps no numeric threshold. Such a number depends on how many people use Enclave and how they behave, which `enclave-sim` can't model and Enclave doesn't measure (no telemetry). Acceptance is the mechanisms' tests (`rt01_tokens_unlinkable_across_writes` in `enclave-core`; `tick_timing_is_independent_of_real_traffic` and `real_and_cover_requests_are_the_same_size_and_look_random` in `enclave-net/tests/shape.rs`; the CI wire capture check) and the disclosed residual. The row's two planned Shape test names don't exist under those names yet. The candidate metric can be added later as a simulation; it would not gate a release.
2. **Resolved:** if Apple refuses the entitlement (G6), Enclave ships with jitter only and the larger residual, disclosed: Apple learns every window with a message. That is the current behaviour: the vault asks for dummy wakes only with Google's push (`engine.rs`, `Cmd::PushToken`), and turning dummy wakes on for APNs waits for the grant. People who need more use Maximum privacy, which has no push.
