# Voice and Video Calls

Status: Partly implemented (M8) · Normative

Source: PLAN.md §11 (D8, D9). Crates: `enclave-calls`, `enclave-relay`, `enclave-media`. Derivations: `02b-key-schedule.md` §12.

## 1. Overview

- Signalling travels as ordinary Lockstep messages over the mixnet. Calls take 3 to 10 s to start ringing.
- Every call does a fresh X448 + ML-KEM-1024 exchange. **Call keys are independent of chat keys.**
- Media is end-to-end encrypted with **SFrame (RFC 9605)** using a private-use EnclaveSeal suite.
- Transport is **WireGuard** in both modes. There is no DTLS-SRTP, no SCTP, and no RingRTC (D9).
- The mode is chosen per call: **Relay** (default, "Private route") or **Direct** (opt-in, shows the IP warning).

## 2. Signalling and call keys

```
Offer (caller → callee, in a ratchet message):
    call_id = HedgedRng.fill("call-id", 16)
    (x_sk, x_pk) = X448.KeyGen(…); (ek, dk) = ML-KEM-1024.KeyGen(…)
    offer = { call_id, x_pk, ek, media: audio | video tier, mode request, caller relay info (§3.2) }

Answer (callee → caller, in a ratchet message):
    (y_sk, y_pk) = X448.KeyGen(…); (ct, ss_m) = ML-KEM-1024.Encaps(ek)
    answer = { call_id, y_pk, ct, callee relay info }

Both:
    ss_call = Combine2(suite, [X448(…)], [ss_m], none, 0x00,
                       pks = [x_pk, ek], cts = [y_pk, ct],
                       transcript = E("enclave/v1/calls/transcript") ‖ call_id ‖ conv_id)
    call_secret = KMAC256(ss_call, "", 512, "enclave/v1/calls/secret")
```

- Offers expire after 60 s. A second answer for the same `call_id` is ignored.
- Other signalling (hang-up, mute state for UI only, tier step-down, rekey) is carried in ratchet messages or, once media flows, in SFrame-protected control frames.
- On iOS, an incoming offer arrives by PushKit VoIP push and MUST be reported to CallKit (`15b-platform-constraints.md`).

## 3. Relay mode (default)

### 3.1 Topology

```
caller ──WireGuard (ticket PSK)──▶ relay R1 ══X448 + ML-KEM link══ relay R2 ◀──WireGuard (ticket PSK)── callee
```

- No ICE is used, so no host candidates leak. No single relay sees both IP addresses. Each relay sees its own caller's IP, stream timing, and the peer relay's IP.
- Client↔relay WireGuard runs in userspace via **GotaTun**, so no VPN permission is needed.
- Relay↔relay links are keyed by the relays' static X448 exchange and a fresh ML-KEM-1024 exchange every 120 s, built into the relay (RFC 0007, in place of WireGuard with upstream Rosenpass; `12-servers.md` §5). Phones never take part in it (D8).

### 3.2 Choosing relays

- Each relay descriptor declares an **operator family** (`12-servers.md` §5).
- The caller picks a relay whose family differs from the caller's home server family and the callee's home server family. The offer carries the caller relay's ID.
- The callee picks a relay whose family differs from the callee's home server family and the caller relay's family.
- Choice among eligible relays is uniformly random, weighted by declared capacity.

### 3.3 Relay tickets

```
TicketRequest (client → relay ticket service, over the mixnet, as an ISSUE-class request):
    fresh WireGuard X25519 key pair (wg_sk, wg_pk) for this call
    (eph, ct) = X448 + ML-KEM-1024 encapsulation to the relay's daily ticket key
    ss_ticket = Combine2(… transcript = E("enclave/v1/calls/ticket-transcript") ‖ relay_id ‖ u32(key_epoch))
    ticket_secret = KMAC256(ss_ticket, "", 256, "enclave/v1/calls/ticket-secret")
    k_ticket_seal = KMAC256(ss_ticket, "", 256, "enclave/v1/calls/ticket-seal")
    body = Seal(k_ticket_seal, E("enclave/v1/calls/ad-ticket") ‖ relay_id ‖ u32(key_epoch),
                { privacy_pass_token, wg_pk, requested_duration })
Relay:
    verifies the Privacy Pass token (single use), installs peer wg_pk with PSK schedule,
    replies with { relay wg_pk, endpoint, t0, expiry }
PSK schedule:
    wg_psk_i = KMAC256(ticket_secret, u32(i), 256, "enclave/v1/calls/wg-psk"),  i = ⌊(t − t0) / 120 s⌋
```

- WireGuard keys are fresh per call. The PSK changes every 2 minutes; both ends switch at the period boundary and WireGuard's own 120 s rekey picks it up.
- Tickets are obtained **anonymously** over the mixnet and paid with Privacy Pass, so the relay cannot link a ticket to an account. Clients MAY pre-fetch one ticket per relay family to cut setup time.

### 3.4 As implemented

`crates/enclave-calls` and `crates/enclave-relay` implement signalling (`message::CallMessage`, carried as `Content::Call` in ratchet messages; `Client::send_call`, `Event::Call`, a line in the conversation per call), SFrame, shaping, tickets, the WireGuard client link and two-relay forwarding.

- **Client↔relay link: WireGuard** (`enclave_calls::wg`, boringtun's Noise_IKpsk2 without a network device). The client's key pair is fresh per call, the relay's static (`calls/relay-wg` from its link key); the pre-shared key is the ticket's `wg_psk_i` for the current 120 s period, counted on the relay's clock. At each period the client starts a new tunnel; the old one carries traffic until the new handshake completes. Payloads ride behind a fixed 20-byte IPv4 header, so a stream's datagrams keep one size. Tests: `payloads_cross_a_wireguard_link_and_periods_rekey`, `two_relays_carry_a_call_without_seeing_both_ends`, `udp_loopback_call`.
- **Tickets** are paid with proof of work bound to the request, not Privacy Pass (RFC 0006: a privately verifiable token can't be redeemed by a relay of another operator family, and the family rule makes that always the case). They are asked for over UDP in two datagrams (`T_TICKET`). Test `tickets_cost_their_proof_of_work`.
- **Choosing relays** by operator family (`enclave_calls::route`): test `rt18_relays_from_distinct_operator_families`.
- **Relay↔relay link.** Sealed with EnclaveSeal under per-direction keys from the two relays' static X448 exchange and, each 120 s epoch, three ML-KEM-1024 shared secrets (RFC 0007; not WireGuard with Rosenpass): the relay with the lower id sends an ephemeral key and a ciphertext to the other's static ML-KEM key, the answer one ciphertext to that ephemeral key and one to the initiator's static key; each side sends under an epoch's keys only once it has received something sealed under them. Relays peer with every relay in the foundation's signed server list, with the static ML-KEM key from each one's signed descriptor. Tests `relay_links_turn_post_quantum_each_epoch`, `audio_goes_both_ways_through_two_relays`.
- **Rendezvous.** Both legs of a call join with `rendezvous = KMAC256(call_secret, "", 128, "enclave/v1/calls/rendezvous")`; the join names the peer relay's address. Relays forward media only between a joined session and the named peer relay.
- **netd** opens UDP sockets for calls (`NetRequest::UdpOpen`, `UdpSend`, `UdpClose`; datagrams come back as `SOCKET_EVENT` replies). The vault sees a socket as two channels (`Transport::open_udp`, `Datagrams`); netd's seccomp profile allows the IPv4 and IPv6 UDP sockets this needs (test `netd_profile_keeps_ip_sockets_only`).
- **Relay descriptors.** The server list names each relay's identity, address and family; its descriptor (`RelayDescriptor` v2: link key, WireGuard key, today's and tomorrow's ticket keys, ticket effort) changes daily, so the client fetches it from the relay in parts (`T_DESC`; a request is padded to 1,100 bytes and answered with at most 1,027, so a relay never amplifies) and checks its signature, identity and address against the list (`enclave_vault::calls::fetch_descriptor`). Relays re-sign it when their ticket keys turn over at midnight.
- **A leg** (`enclave_vault::calls::open_leg`): descriptor, ticket (the proof of work runs off the engine's thread), WireGuard link. The engine (`engine/calling.rs`) picks the caller's relay when calling and the callee's when answering, by the RT-18 rule, sends the relay's id in the offer or answer, and starts the media once it has the keys, its leg and the other relay's address.
- **Media** (`enclave_vault::calls::run`): every 20 ms one 160-byte SFrame packet goes up (an Opus frame with a 32-bit sequence number, or padding while muted or before the microphone has sound) and one frame is played from a jitter buffer (60 ms deep; a lost frame is recovered from the next one's in-band FEC, else concealed, then silence; more than 300 ms behind skips ahead). The join is repeated each second until the other side is heard; 30 s without connecting or 20 s of silence ends the call. Test `audio_goes_both_ways_through_two_relays` runs two relays and both legs on this machine.
- **Audio** (`enclave_media::call`, in mediad: `MediaOp::CallOpen`/`CallEncode`/`CallDecode`/`CallClose`, one helper per call): Opus CBR 32 kbit/s, 20 ms, FEC on, DTX off; the microphone goes through `sonora` (AEC3 echo cancellation against what was just played, noise suppression, AGC2) before encoding. The window captures and plays with `cpal` (`enclave-app`'s `audio`, converting the device's rate and channels) and moves 20 ms frames to and from the vault (`Cmd::CallMic`, `Out::CallAudio`); a phone asks for the microphone when a call starts. Tests `frames_are_constant_size_and_decode`, `lost_frames_are_concealed_or_recovered`, `echo_is_cancelled`, `calls_keep_their_codec_state`.
- **Video** (`enclave_media::callvideo`, in mediad: `MediaOp::VideoOpen`/`VideoEncode`/`VideoDecode`/`VideoClose`, on another helper than the call's audio): AV1 by rav1e at speed 10 in low-latency mode without lookahead, decoded by rav1d. Tier 0 (320×240, 15 frames/s, 240 kbit/s) to start; a key frame every 3 s and whenever the other side asks (`K` on the video stream after a frame failed to decode), each carrying the sequence header so decoding can start there. The video stream is its own shaper: fixed 1,200-byte packets at the tier's rate, padding when the camera is off; frames that would queue more than half a second are dropped and the next is a key frame. The window crops and scales camera frames to the tier's size (desktop: `nokhwa`; phones: the front camera through `enclave_platform::phone::start_call_camera`) and shows the other person's picture full-window with its own mirrored in a corner. Tests `frames_round_trip_at_the_tier_rate`, `video_goes_through_two_relays`, `call_frames_are_cropped_scaled_and_turned`.
- **Screens**: calling, ringing (with a notification), connecting, the call (time, the two check words, mute, hang up), and how it ended, over the whole window; a call and video-call button in a 1:1 conversation. Each call leaves a line ("Call, 3:02", "Missed call", "Declined call", "No answer").

- **In the app**: the call screen can shrink to a tile over the app (picture in picture: the other person's picture, or who and for how long, with hang up); tapping it brings the call back. A call that rings or ends always takes the whole window.
- **The system's call screens** (`enclave_platform::phone::report_*_call`, driven from the vault's snapshots in `enclave-app`'s `vault::phone`, so they work with no window open): on iOS, CallKit and PushKit (`phone/ios/calls.rs`): a call's offer is sent with `FLAG_CALL`, so the home server wakes the callee at once through the push relay as an APNs VoIP push (`apns-push-type: voip`, topic `<bundle>.voip`, 60 s expiry), which is reported to CallKit before anything else (PC-02) as "Enclave" and named once the offer is in; a push whose offer never comes stops ringing after 30 s. The PushKit token is registered as its own push token (platform 4, `FLAG_PUSH_CALL`). On Android, a self-managed `ConnectionService` (`apps/android/.../Calls.java`): the system gives the call its audio mode and holds other calling apps, a ringing call is a full-screen call notification (CallStyle, the ringtone), and the background service keeps the microphone (`phoneCall` and `microphone` foreground types) while a call is on. Both keep calls out of the phone's call history; with notification previews off the system's screens say "Enclave", not the caller. Answer, decline, hang up and mute there come back as commands; an answer given before the offer arrived is applied when it does. The window's own ringing notice is not shown on phones.

Not implemented yet: group calls, call links, screen share and the Maximum-privacy tunnel (C-f).

## 4. Direct mode (opt-in per call)

- The pre-call sheet offers "Direct (clearer, but Sam can see your internet address)". Checked contacts get one confirmation; unchecked contacts get a second, stronger warning: "You haven't checked Sam's security code. Direct calls show your internet address to whoever is on the other end."
- ICE comes from the webrtc-rs sans-IO `rtc` crates (str0m is evaluated in M8). STUN goes only through Enclave relays. Host candidates use mDNS names.
- The tunnel is WireGuard with `direct_psk = KMAC256(call_secret, "", 256, "enclave/v1/calls/direct-psk")`. There is no DTLS-SRTP.

### 4.1 As implemented

- **Asking and agreeing.** The pre-call sheet offers the private route and "Call directly"; for a contact whose security code wasn't checked, the second, stronger warning follows before a direct call goes out. A direct call's offer carries `route = direct`. The callee's ringing screen says the caller asked for a direct call and what answering directly shows; "Answer privately" keeps the relays, "Answer directly" (`Cmd::AnswerCallDirect`) agrees. The system's call screens (CallKit, Android's) answer privately.
- **Who shows their address first.** Nothing about either address leaves before both people agreed: the callee, having answered directly, sends its candidates (`enclave_calls::direct::Candidates`: a fresh WireGuard key for this call and up to 8 addresses, in a `CallMessage::Candidates` ratchet message); the caller sends its own only once the callee's have arrived. A callee who answered privately sends none, and the caller's go nowhere.
- **Candidates.** Each side opens one socket that talks to any address (netd `UdpOpen` with no remote; datagrams carry their address both ways, `enclave_net::transport::addressed`). It asks its own relay what address the datagram came from (`T_REFLECT`, padded to 64 bytes so the answer is never larger: the relays are the only STUN servers, and each relay already sees its own client's address), and adds its address on the local network. Not ICE: WireGuard's handshake is the connectivity check. Host addresses are sent as they are, not as mDNS names: they go end to end, only to the person the user agreed to show their address to.
- **The link.** WireGuard (`enclave_calls::wg::DirectLink`) between the two fresh keys, under `direct_psk`; the keys came in authenticated ratchet messages, so no one in between can take a side's place. The caller sends handshake initiations to every address the callee named once a second; the callee sends a byte to every address the caller named, opening its NAT for them. The first address a handshake completes from is the other side's. Once up, both send a keepalive each second.
- **Fallback.** Both legs to the relays are opened as for any call and carry the media until the direct link is up; the media then goes directly, and back through the relays if the direct link is quiet for 3 s. The window says which ("Direct: you and Sam can see each other's internet address."). Test `audio_goes_directly_once_both_agree` (two relays, both legs, the reflection, the candidates and the switch; the relays forwarded the first moments only), `direct_links_handshake_and_carry_payloads`, `candidates_round_trip_and_refuse_garbage`, `reflect_answers_with_the_address_and_never_more_than_it_was_sent`, netd's `udp_sockets_carry_datagrams_both_ways`.

## 5. Media end-to-end encryption: SFrame with EnclaveSeal

### 5.1 Suite

| Property | Value |
|---|---|
| SFrame cipher suite ID | 0xF0E1 (private use range of RFC 9605) |
| Name | `ENCLAVE_SEAL_V1_KMAC256` |
| `Nk` (key) | 32 |
| `Nn` (nonce) | 32 |
| `Nt` (tag) | 32 |
| AEAD | EnclaveSeal-v1 detached-nonce form (`02-cryptography.md` §4.5) |

Overhead: a 256-bit tag per frame. On 20 ms Opus that is 32 B × 50 frames/s × 8 = 12.8 kbps, which is accepted.

### 5.2 Key schedule

```
base_{p,0}   = KMAC256(call_secret, T(participant_id, u32(join_gen)), 256, "enclave/v1/calls/sframe-base")
base_{p,i+1} = KMAC256(base_{p,i}, u32(i + 1), 256, "enclave/v1/calls/sframe-ratchet")      # every 5 s
KID          = u64( participant_index << 32 | i )
(sframe_key, sframe_salt) = split32( KMAC256(base_{p,i}, u64(KID), 512, "enclave/v1/calls/sframe-key") )
nonce(CTR)   = sframe_salt ⊕ (0^24 ‖ u64(CTR))
ct ‖ tag     = SealDN(sframe_key, nonce(CTR), E("enclave/v1/calls/ad-sframe") ‖ sframe_header ‖ metadata, frame)
```

- Per-sender base keys ratchet every 5 s; the previous base key is deleted after a 1 s grace.
- In group calls, a sender's `base_{p,0}` is a fresh random value (not derived from `call_secret`) sent to each participant over pairwise ratchet messages.
- **A participant leaving** triggers a rekey: every remaining sender generates a fresh random base key, increments `join_gen`, and distributes it pairwise to the remaining participants.
- **Joiners** receive each sender's current `base_{p,i}` (ratcheted forward), so they cannot decrypt earlier frames.

### 5.3 Nonce uniqueness

`CTR` starts at 0 for each KID and increments per frame. Call state is never persisted, so a rollback of stored state cannot repeat `(sframe_key, nonce)`. If the call process restarts, the participant rejoins with a new `join_gen`. This is the second permitted SealDN call site.

## 6. Traffic shaping (RT-19)

| Stream | Rule |
|---|---|
| Audio | Opus CBR 32 kbps, 20 ms frames, DTX off, in-band FEC on. Every SFrame packet is exactly 160 B (17 B header, 111 B plaintext, 32 B tag) at exactly 50 packets/s. |
| Video | Tiers 300, 800, 1,500 kbps, chosen at call start. Fixed 1,200 B packets at a fixed rate: 31.25, 83.33, or 156.25 packets/s. |
| Step-down | Quality can only step down, at most once per 30 s. It never steps up during a call. |
| Mute / camera off | Padding frames keep exactly the same size and rate. |
| Header extensions | Allowlist only. The RFC 6464 audio-level extension MUST NOT be sent and MUST be stripped if received. |

The observable residual is the tier (audio-only vs. each video tier).

## 7. Maximum privacy calls

In Maximum privacy mode, while the app is in the foreground, the client keeps a constant 32 kbps audio-shaped WireGuard tunnel (160 B × 50 packets/s) open to its chosen relay, using a ticket as in §3.3. Calls ride inside it, which hides call start and stop from a global observer. On iOS, calls ring only while the app is open.

As implemented (`enclave_vault::calls::Standby`, the engine's `standby_upkeep`): with Maximum privacy on, the app in front and no call, the vault opens a leg to a relay of another family than its home server's and sends what a call's audio sends: a padded payload of the audio packet's size every 20 ms, and a control payload each second. Every call's once-a-second control payload (its join, then keepalives) is padded to the same 64 bytes, so the change is invisible from outside. A call whose relay choice the standby's relay satisfies (RT-18: a family neither home server's, nor, when answering, the caller's relay's) takes the leg over; the media then sends at the same rate on it. A call that can't (the other side's home server is in the standby relay's family) opens its own leg as usual, and the standby keeps padding meanwhile. When the app leaves the front or Maximum is turned off, the tunnel closes; a ticket that runs out (4 h) is replaced. A video call's picture is its own stream, so starting one with the camera on shows. Test `a_standby_tunnel_carries_the_call_that_takes_it`.

## 8. Group calls

- An SFU in the host's relay forwards only SFrame frames and simulcast layers, in fixed-rate slots. It never holds media keys.
- Audio is forwarded to all participants at CBR. There is no dominant-speaker detection.
- Each receiver has a fixed 2.5 Mbps downlink budget; the SFU fills unused budget with padding.
- **Limits:** 32 video tiles or 64 audio participants.
- **Call links:** `https://<invite-host>/call#<payload>` with a capability `call_link_cap = KMAC256(call_link_secret, "", 256, "enclave/v1/calls/link-cap")` and an optional lobby.
- Raise hand, reactions, picture-in-picture. Screen share on desktop in M8, on mobile after 1.0.

## 9. Call check

An optional 2-word code, as in ZRTP: the first two 11-bit groups of `KMAC256(call_secret, "", 256, "enclave/v1/calls/check-words")`, shown as BIP-39 words in the user's language. Both people read them aloud.

## 10. Media engine

| Function | Implementation | Isolation |
|---|---|---|
| Opus decode | Pure-Rust `opus-decoder` once it passes RFC 8251 vectors and fuzzing | mediad sandbox |
| Opus encode | `opus-rs` (pure Rust), only on the user's own microphone | mediad sandbox |
| Opus via Symphonia | Never (Symphonia cannot decode Opus) | — |
| Echo cancellation | Pure-Rust `sonora` (WebRTC AEC3, noise suppression, AGC2) on every platform; its echo test is `echo_is_cancelled` | mediad sandbox |
| Video encode | AV1 via rav1e at speed 10, or an OS hardware AV1 encoder | mediad sandbox / OS |
| Video decode | rav1d, in software, in the sandbox. Incoming video never touches hardware decoders. | mediad sandbox |
| M8 gate | 360p at 30 fps on the reference low-end phone; if it fails, OS hardware H.264 encode as a declared exception | — |
| Capture | `cpal` for audio; CameraX via `jni`, AVFoundation via `objc2`, `nokhwa` on desktop | platform shims |

## 11. Errors

| Condition | Behavior | User-facing |
|---|---|---|
| No eligible relay family | Retry with relaxed capacity weighting; never relax family distinctness | "Couldn't find a private route right now. Try again, or use Direct." |
| Ticket payment fails | Acquire a new Privacy Pass token and retry once | same |
| Offer expired | Show missed call | "Missed call" |
| RFC 6464 extension received | Strip and log | none |
| Decrypt failure bursts | Request rekey via signalling | "Reconnecting…" |

## Open questions

1. The SFrame suite ID 0xF0E1 is a private-use value chosen here; RFC 9605 private-use allocation rules should be confirmed.
2. Audio packets are padded to 160 B (§6); PLAN fixes the rate and CBR but not the exact size. 160 B fits a 20 ms, 32 kbps Opus frame (80 B), the SFrame header, the 32 B tag, and RTP headers.
3. Whether the Maximum-mode tunnel (§7) should run on Android in the background, where the always-on profile already runs. PLAN says "while the app is in the foreground"; this spec follows PLAN.
