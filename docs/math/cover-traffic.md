# Cover-Traffic Data Rates and Latency

Status: Draft (M0, reconciled with the M4 scheduler code) · Normative

Source: PLAN.md §9.4, §9.5, honest limit 5, Appendix A; `crates/enclave-net/src/schedule.rs`. This document derives the data rates and latencies quoted in `09-transport.md` §6 and in the UI from first principles. Every figure here is an estimate until M4 measures `k`, `u`, SURB size, and overheads; M4 must land within ±20%.

## 1. Tick model as implemented

`enclave_net::schedule::Scheduler` produces one tick at a time:

| Profile | Tick delay | Poll target |
|---|---|---|
| Foreground | fixed 3 s | account inbox on even ticks; other mailboxes on odd ticks by smooth weighted round robin; inbox on every tick if there are no other mailboxes |
| Background | exponential, mean 120 s (Poisson process) | account inbox on 3 of every 4 ticks; other mailboxes on every 4th (`Scheduler::other_mailbox_period`, `Client::sync_round_every`); inbox on every tick if there are no other mailboxes |
| Maximum | fixed 3 s | same as Foreground |

Each tick sends one 16,384 B unit (real or cover) and one 2,048 B poll. Bulk bursts are allowed in Foreground and Background and disabled in Maximum.

**Replies.** The server answers a request with a 16,384 B reply unit unless the request is one way. PLAN §9.4 counts **one** unit down per tick: writes and cover units get no reply. Over the optional mixnet they go without reply SURBs; on a stream to an onion service (the default route since RFC 0010) the carrier sets the one-way bit in the request's length (`enclave_wire::STREAM_ONEWAY`) and the server answers an empty frame, 4 bytes (`09-transport.md` §1, §6.1). Only the development transports (`TcpTransport`, `TorTransport`) still bring back a full reply for every request; §2.1 gives those figures.

§2 to §6 model the optional mixnet (Sphinx packets). The onion route is modelled in §10.1.

## 2. Assumptions

| Symbol | Meaning | Value | Status |
|---|---|---|---|
| `S` | Sphinx packet size on the wire (Nym) | 2,413 B | V (Nym docs) |
| `P` | Sphinx payload size | 2,048 B | V (Nym docs) |
| `u` | Usable Enclave bytes per Sphinx packet after Nym's message framing | unknown, `u < P` | U, measured in M1.5/M4 |
| `U` | Wire unit size | 16,384 B | fixed (D1) |
| `k` | Sphinx packets per wire unit, `k = ⌈U / u⌉` | 11 (measured, §10) | V |
| `p` | Sphinx packets per poll object (2,048 B plus its reply SURBs) | 5 (measured, §10; PLAN said 1 or 2) | V |
| `T_fg` | Foreground and Maximum tick | 3 s | fixed (`Profile::mean_tick`) |
| `T_bg` | Background tick mean (Poisson) | 120 s | fixed |
| `λ_loop` | Nym loop-cover rate | 1 per 10 s (Foreground, Maximum); 1 per tick (Background), Nym loop cover and Enclave's self-loop probes together | implemented (`09-transport.md` §6.3) |
| `o` | Tor + TLS + TCP/IP + WSS overhead factor on client bytes | ≈1.10 | estimated (§2.2) |

Relationship between `u` and `k` (`k = ⌈16,384 / u⌉`):

| `k` | Range of `u` (B) |
|---|---|
| 8 | 2,048 (only if Nym framing were zero) |
| 9 | 1,821 to 2,047 |
| 10 | 1,639 to 1,820 |
| 11 | 1,490 to 1,638 |

### 2.1 Bytes per tick

PLAN's model (1 unit up, 1 poll up, 1 reply down):

```
packets per tick  = k (unit up) + p (poll up) + k (poll reply down) = 2k + p
```

With a reply for the write or cover unit too (before one-way writes; what the development TCP and Tor transports still do):

```
packets per tick  = k + p + k + k (write reply down) = 3k + p
```

| `k` | `p` | PLAN model: packets | Sphinx bytes/tick | Implemented: packets | Sphinx bytes/tick |
|---|---|---|---|---|---|
| 9 | 1 | 19 | 45,847 | 28 | 67,564 |
| 9 | 2 | 20 | 48,260 | 29 | 69,977 |
| 10 | 1 | 21 | 50,673 | 31 | 74,803 |
| 10 | 2 | 22 | 53,086 | 32 | 77,216 |
| 11 | 1 | 23 | 55,499 | 34 | 82,042 |
| 11 | 2 | 24 | 57,912 | 35 | 84,455 |

With a reply for every request, the rates in §3 to §5 grow by a factor of `(3k + p) / (2k + p)` ≈ 1.46 to 1.47 before loop cover: Foreground ≈91–104 MB/h, Background ≈57–65 MB/day, Maximum ≈2.2–2.5 GB/day (with loop cover and `o` = 1.10, `k` = 9 to 10). That is outside PLAN's ±20% band, so writes and cover now go one way over the mixnet (`09-transport.md` §6.1), which restores PLAN's `2k + p`; delivery comes from receipts instead.

Loop cover: each loop packet goes up and comes back down, so it costs 2 × 2,413 = 4,826 B.

### 2.2 Overhead factor `o`

- Tor carries data in 514 B cells with 498 B of relay payload. One 2,413 B Sphinx packet needs ⌈2,413 / 498⌉ = 5 cells = 2,570 B, a factor of 2,570 / 2,413 = **1.065**.
- TLS records, TCP/IP headers (about 52 B per 1,448 B segment), and WSS framing add about **3 to 4%**.
- Combined: 1.065 × 1.035 ≈ **1.10**. M4 measures it.

## 3. Foreground (tick 3 s, PLAN model)

```
ticks per hour = 3,600 / 3 = 1,200
loop per hour  = 3,600 / 10 = 360 → 360 × 4,826 = 1,737,360 B ≈ 1.74 MB
data per hour  = o × (1,200 × bytes/tick + 1.74 MB)
```

| `k`, `p` | Sphinx only | + loop | × 1.10 |
|---|---|---|---|
| 9, 1 | 55.0 MB | 56.8 MB | 62.4 MB/h |
| 9, 2 | 57.9 MB | 59.7 MB | 65.6 MB/h |
| 10, 1 | 60.8 MB | 62.5 MB | 68.8 MB/h |
| 10, 2 | 63.7 MB | 65.4 MB | 72.0 MB/h |
| 11, 2 | 69.5 MB | 71.2 MB | 78.4 MB/h |

PLAN's **≈60–70 MB/h** matches `k` = 9 to 10 with overhead. At `k` = 11, `p` = 2 the figure is ≈78 MB/h: above PLAN's range, but inside the ±20% M4 tolerance (70 × 1.2 = 84 MB/h).

## 4. Background (Poisson, mean 120 s, PLAN model)

```
ticks per day = 86,400 / 120 = 720
loop per day  = 720 × 4,826 = 3,474,720 B ≈ 3.47 MB     (1 per tick)
data per day  = o × (720 × bytes/tick + 3.47 MB)
```

| `k`, `p` | Sphinx only | + loop (1 per tick) | × 1.10 |
|---|---|---|---|
| 9, 1 | 33.0 MB | 36.5 MB | 40.1 MB/day |
| 9, 2 | 34.7 MB | 38.2 MB | 42.0 MB/day |
| 10, 1 | 36.5 MB | 40.0 MB | 44.0 MB/day |
| 10, 2 | 38.2 MB | 41.7 MB | 45.9 MB/day |

PLAN's **≈35–40 MB/day** matches the Sphinx-only figures for `k` = 9 to 10 and is about 10 to 15% low once Tor overhead is included, which is inside the ±20% M4 band.

**Why loop cover is 1 per tick in Background.** At PLAN's 1 per 10 s, loop cover alone would be 8,640 × 4,826 B = 41.7 MB/day, more than the whole Background budget (`00-overview.md` §9, I-10).

## 5. Maximum privacy (tick 3 s always, PLAN model)

```
ticks per day = 86,400 / 3 = 28,800
loop per day  = 8,640 × 4,826 = 41.7 MB
```

| `k`, `p` | Sphinx only | + loop | × 1.10 |
|---|---|---|---|
| 9, 1 | 1.320 GB | 1.362 GB | 1.50 GB/day |
| 9, 2 | 1.390 GB | 1.432 GB | 1.57 GB/day |
| 10, 1 | 1.459 GB | 1.501 GB | 1.65 GB/day |
| 10, 2 | 1.529 GB | 1.571 GB | 1.73 GB/day |

PLAN's **≈1.5–1.7 GB/day** matches the model. Measured over the optional mixnet (§10.2), Maximum runs Foreground's tick around the clock: ≈80 MB/h with Tor, ≈1.9 GB/day. The UI states the onion route's figures (§10.1): "about 45 MB an hour" and "about 30 MB a day in the background" for Standard, and "about 1.1 GB a day" for Maximum.

## 6. Bulk mode and media

Bulk (`Scheduler::bulk`, Foreground and Background only) sends queued requests in a burst. At PLAN's cap of 40 Sphinx packets per second (the Nym client's packet gap in bulk, `09-transport.md` §6.4), each chunk is one wire unit of `k` packets (`k` = 11 measured for a one-way unit):

```
time for a blob = n_B × k / 40 s
```

| Object | Chunks `n_B` | `k` = 9 | `k` = 10 | `k` = 11 |
|---|---|---|---|---|
| Photo, 1 MiB bucket | 74 | 16.7 s | 18.5 s | 20.4 s |
| Photo, 4 MiB bucket | 295 | 66.4 s | 73.8 s | 81.1 s |
| Vault-key object (98 directory chunks in the reference client) | 98 | 22.1 s | 24.5 s | 27.0 s |
| Contact add, 5 devices (`math/envelope-budget.md` §9) | 112 | 25.2 s | 28.0 s | 30.8 s |

PLAN's "Photo ~16 s" matches the 1 MiB bucket at `k` = 9. Bulk payload throughput: 40 × `u` ≤ 40 × 2,048 = 81,920 B/s ≈ **82 KB/s**, which is why the M4 "≥200 KB/s" gate measures nym-sdk raw throughput (`00-overview.md` §9, I-12).

**Maximum mode.** `bulk` returns nothing, so each chunk takes the up slot of one 3 s tick:

| Bucket | Chunks | Time |
|---|---|---|
| 1 MiB | 74 | 222 s ≈ 3.7 min |
| 4 MiB | 295 | 885 s ≈ 14.8 min |

PLAN's "a 1 MiB photo takes about 15 minutes" corresponds to the 4 MiB bucket (a photo just over 1 MiB); a photo that fits the 1 MiB bucket takes about 3.7 minutes (`00-overview.md` §9, I-11).

## 7. Latency

### 7.1 Model

Median one-way text latency, sender in Foreground:

```
L = W_send + D_write + W_poll + D_poll_reply
W_send        wait for the sender's next up slot: uniform on [0, 3 s] → median 1.5 s
D_write       Tor (≈0.2–0.4 s) + Nym (3 mix hops at Nym's default mean delay plus link latency,
              ≈0.5–0.8 s) + exit gateway to server ≈ 1.0–1.5 s
W_poll        wait until the recipient's next inbox poll reaches the server:
              inbox polled every tick (no other mailboxes) → median T/2;
              inbox polled on even ticks (other mailboxes present) → median T in Foreground
D_poll_reply  the poll's reply over SURBs ≈ 1.0–1.5 s
```

### 7.2 Results

| Case (recipient's scheduler) | `W_send` | `D_write` | `W_poll` | `D_poll_reply` | Median `L` |
|---|---|---|---|---|---|
| Foreground or Maximum, inbox only | 1.5 | 1.0–1.5 | 1.5 | 1.0–1.5 | **5.0–6.0 s** |
| Foreground or Maximum, other mailboxes present | 1.5 | 1.0–1.5 | 3.0 | 1.0–1.5 | **6.5–7.5 s** |
| Background, inbox only (no push) | 1.5 | 1.0–1.5 | 83.8 (§7.3) | 1.0–1.5 | **≈88 s** |
| Background, other mailboxes present (no push) | 1.5 | 1.0–1.5 | 107.7 (§7.3) | 1.0–1.5 | **≈112 s** |

PLAN's "≈5–6 s" holds when the inbox is polled every tick. With other mailboxes in the rotation the median rises by about 1.5 s (`00-overview.md` §9, I-9).

### 7.3 Background poll wait (simulated)

Background ticks are a Poisson process with mean 120 s, so the wait from a message's arrival to the next inbox poll is not uniform. A simulation of 200,000 arrivals over 3 × 10⁷ s of ticks gives:

| Inbox polled on | Median wait | P(wait ≤ 115 s) | Median `L` (sender in Foreground) | Status |
|---|---|---|---|---|
| Every tick | 83.8 s | 61.5% | ≈88 s | implemented when the inbox is the only mailbox |
| 3 of every 4 ticks | 107.7 s | 52.3% | ≈112 s | implemented in Background when other mailboxes are present |
| Every other tick | 136.2 s | 43.6% | ≈140 s | Foreground and Maximum pattern; not used in Background |

PLAN's "≤2 min" in Background holds for the median only if the inbox is polled on at least 3 of every 4 Background ticks, so that is what Background does (test `background_polls_the_inbox_three_ticks_in_four`). The pattern keeps exactly one poll per tick, so the traffic shape is unchanged; groups are read on every 4th tick instead of every other one.

## 8. Server-side scale

See `12-servers.md` §7: 100k accounts with 5% of 150,000 devices in Foreground give ≈483 Mbit/s of reply egress under PLAN's one-reply-per-tick model (twice that if every write also gets a reply unit), and ≈7,375 sealed requests per second (≈2.2 cores at 0.3 ms each).

## 9. What M4 must measure

1. `u` and therefore `k` on each platform's nym-sdk build.
2. SURB size and therefore `p`.
3. The overhead factor `o` on real Tor circuits.
4. Nym per-hop delay distribution at default settings, and link latencies.
5. Battery cost per profile.

If any measured data rate falls outside ±20% of §3 to §5, the tick length is adjusted **globally** (never per user; D10) through an RFC.

## 10. Data on the wire

### 10.1 Over the onion route (model, RFC 0010)

The default route: each tick's unit and poll go as frames on the carrier's two long-lived Tor streams to the server's onion service (`09-transport.md` §1). A frame is `u32 len ‖ bytes`. The unit is one way (the length's top bit set), so the server answers it with an empty frame; the poll gets its full reply. There is no loop cover and no self-loop probe on this route.

```
up per tick     = (4 + 16,384) unit + (4 + 2,048) poll     = 16,388 + 2,052 = 18,440 B
down per tick   = (4 + 16,384) poll reply + 4 unit ack      = 16,388 + 4     = 16,392 B
per tick                                                                    = 34,832 B

Foreground      = 1,200 ticks × 34,832 B = 41.8 MB/h of payload
                  × o ≈ 1.10             ≈ 46 MB/h on the wire
Background      = 720 ticks × 34,832 B × 1.10 ≈ 28 MB/day
Maximum         = 24 h × 46 MB/h              ≈ 1.1 GB/day
```

`o` here is Tor's cells (498 data bytes in 514), TLS and TCP/IP on the device's link to its guard, taken as ≈1.10 like §2.2 until it is measured on live Tor. To the Tor network that is about 13 kB/s per device in Foreground, the same whether or not anything real is sent. These are the figures `09-transport.md` §6.3 and the UI give. CI's `federation-e2e-onion` checks the shape on the carrier's streams (two requests a tick, within ±20%; `ci/federation/pcap-check.py --stream`); its capture is on loopback, so it measures the payload without Tor's cells.

### 10.2 Measured on a local mixnet (Foreground, 2026-10-08)

With the optional mixnet:

`nym/enclave-nym-sdk/examples/localnet_ticks.rs` on `ci/nym-localnet/run-local.sh` (nym-node 1.21.5, three mix nodes, two gateways): a device sends a Foreground tick's poll (with its reply blocks) and one-way unit every 3 s, paced as the shaper sets it, to an ingress on the other gateway that answers every poll with a full reply unit. A capture of the device's link to its gateway, read by `ci/federation/pcap-check.py`, over 120 s:

| Quantity | Measured | Model |
|---|---|---|
| Sphinx packets up per unit `k` | 11 | 9 to 11 |
| Sphinx packets up per poll `p` (2,048 B plus 12 reply blocks) | 5 | 1 or 2 |
| Packets up per tick, with loop cover and probes | 16.25 to 16.30 | `k + p` + 0.3 = 16.3 |
| Frame size on the gateway connection | 2,452 B (2,413 B Sphinx + 39 B framing and encryption) | 2,413 B |
| Spacing of packets up | 150 ms (`09-transport.md` §6.3) | even across the tick |
| Paced queue | empty every tick | — |
| Data up, WebSocket payloads | 48 MB/h | 1,200 × 16.3 × 2,413 B = 47.2 MB/h |
| Data down, WebSocket payloads (acks and the reply's 11 packets, delivered unwrapped) | 25 MB/h | — |
| Total, WebSocket payloads | **73 MB/h** | — |

With TCP/IP headers (≈3.5%) and Tor's cells (≈6.5%, §2.2) on top, Foreground comes to ≈80 MB/h: above PLAN's 60–70 MB/h, inside its ±20% band (≤ 84 MB/h), so the tick stays at 3 s (§9). The extra comes from `p`: a poll carries the 12 reply blocks its 16 KB answer needs (open question 1). Down is smaller than up because the gateway delivers a packet's payload, not the whole Sphinx packet. The same tick, pacing and loop cover make Maximum's figures equal Foreground's; Background's (one tick per 120 s on average) scale by 3/120. CI repeats this on every run with the real client (`09-transport.md` §6.7): Ada's shaped Foreground client, through `enclave-tord` and `enclave-nymd`, in a group, syncing on the vault's clock, 90 s idle and 90 s busy. First green run (37847951558, commit eca9fc0): **16.23 packets up a tick idle (−0.4% of the model) and 16.57 busy (+1.6%)**, 150 ms apart, busy within 2.1% of idle up and 9.3% down, the largest 15 s window 87 packets against a median of 81; **72.7 MB/h idle and 76.0 MB/h busy** at the WebSocket level. The run before it (81b23b5) measured 29.5 packets a tick and 173 MB/h, because group reads then skipped the clock in a bulk window; reading them in poll slots fixed it (`09-transport.md` §6.7).

## 11. What the mixnet costs a user (zk-nym tickets)

This applies only with the optional mixnet (RFC 0010). With the default route, Tor onion services, running Enclave costs nothing recurring: Tor is free and volunteer-run, call-relay tickets are paid with proof of work (RFC 0006), blob tokens are issued by each user's own server, and APNs and FCM cost nothing with the developer accounts already held.

Nym's gateways take a device's traffic against zk-nym tickets (`09-transport.md` §7). The units, from nym-network-defaults 1.21.5: a mixnet-entry ticket is 200 MB of traffic through one gateway (`MIXNET_ENTRY_TICKET_SIZE`), a ticketbook holds 50 tickets (`TICKETBOOK_SIZE`, 10 GB) and is valid for 7 days (`TICKETBOOK_VALIDITY_DAYS`). The wallet lets a book go after 6 days (`BOOK_LIFETIME`).

A device spends tickets three ways:

```
by traffic      bytes / 200 MB
by connection   one ticket each time it connects to a gateway: every start of the
                mixnet client (a fresh identity) and every gateway switch (RT-02)
by expiry       whatever is left in a book after 6 days is lost
```

A day of 4 h in Foreground and 20 h in Background, with the measured Foreground rate over the mixnet (§10.2, ≈80 MB/h with Tor) and Background at 3/120 of it (≈2 MB/h):

```
traffic per day   = 4 × 80 + 20 × 2  = 360 MB  → 1.8 tickets
starts per day    ≈ 3 (app launches after the OS stopped it; a phone, more)
tickets per week  ≈ 7 × (1.8 + 3) ≈ 34   < 50 in a book
books per month   = 30 / 6 = 5          (expiry decides, not traffic)
```

So a typical device buys **one book every 6 days, 5 a month**, and pays for a book's worth of capacity it doesn't use. A heavy user (all day in Foreground: 24 × 80 MB = 1.9 GB, ≈10 tickets a day) needs about 1.4 books a week, ≈7 a month. With `P` the price the foundation's credential proxy pays for one book:

```
cost per user per month ≈ 5 × P      (typical)    ≈ 7 × P   (all-day Foreground)
target ≤ $1                       →   P ≤ $0.20             P ≤ $0.14
```

The work a device does for its tokens (Equi-X, 4 tokens a proof) and the gate's own costs are small next to that. `P` isn't fixed by the protocol: it is the deposit the proxy makes per ticketbook on the Nyx chain, priced in NYM, so it moves with the token. The nightly sandbox job (`live.yml`, N4) records the deposit nym-api asks and checks `5 × P ≤ $1` at the day's price, when a funded account is configured; only whoever funds the optional mixnet needs that check, so External Gate G7 is no longer needed (RFC 0010). Ways to lower the cost if it fails: fewer starts (keep the mixnet client running in Background, which costs tickets by traffic only), books that last longer if Nym adds a validity option, or a smaller book type.

## Open questions

1. **Resolved:** the Nym SURB size is measured (§10): a poll with the 12 reply blocks its answer needs is 5 packets, not PLAN's 1 to 2. Foreground still lands inside the ±20% band.
2. **Resolved:** yes, on every platform. The same Nym client code (`enclave-nym-sdk`, run by nymd) sends loop cover at the same profile rates everywhere (`09-transport.md` §6.3), so it counts toward the downlink in the same way. The CI wire check counts it too: its model is 16 packets a tick plus 0.1 a second addressed to the device itself (`ci/federation/pcap-check.py`). iOS has no background profile, so it sends none in the background.
3. **Resolved:** writes and cover units now go one way over the mixnet, with no reply blocks, and delivery is confirmed by receipts only (`09-transport.md` §6.1, Open question 5). Tests `writes_go_one_way`, `deferred_answers_come_back_through_status_polls` (`enclave-ingress`) and `receipts_resends_and_not_delivered_yet` (`enclave-core`). §1's note on reply units describes the TCP and Tor development transports.
4. **Resolved:** the Background median latency with other mailboxes present was ≈140 s; Background now polls the inbox on 3 of every 4 ticks (≈112 s, §7.3).
5. **Resolved:** over the onion route a write or cover unit no longer brings back a full 16 KiB reply, which would have doubled the data down: the stream's one-way bit gets an empty acknowledgement instead (§1, §10.1; RFC 0010).
