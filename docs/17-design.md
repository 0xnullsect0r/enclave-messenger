# Design System: "Paper & Seal"

Status: Draft (M0) · Normative

Source: PLAN.md §15. Tokens: `design/tokens.toml` (source of truth), generated into `tokens.slint` by `enclave-design`. Copy glossary: `design/copy-glossary.md`. Accessibility: `18-a11y-i18n.md`.

## 1. Point of view

Enclave feels like private correspondence done well: warm paper, deep pine ink, and one saffron seal that appears only when something has really been confirmed.

Three rules follow from this and override any local design choice:

1. **Saffron means "confirmed by you".** It is never used for decoration, branding, warnings, or calls to action.
2. **"Private" is the default and is never labelled.** Only exceptions are shown.
3. **Security events are inline and persistent.** They are never toasts, never red-only, never hidden behind icons.

## 2. Typefaces and type scale

### 2.1 Faces

Two families, both SIL OFL 1.1, bundled unmodified with `OFL.txt` in `LICENSES/`.

| Face | Weights | Job |
|---|---|---|
| **Atkinson Hyperlegible Next** | 400, 600 only (and their italics, used only for `_italic_` text people write) | Everything people read: messages, UI, headings. Built for low-vision legibility. |
| **Atkinson Hyperlegible Mono** | 400 | Only things people must **compare or copy exactly**: security codes, recovery words, link and invite codes. Its 0/O and 1/l/I glyphs are clearly different. |

Content fonts (not design choices): Noto Color Emoji for emoji; Noto Sans, bundled per shipped locale, for scripts Atkinson does not cover.

### 2.2 Scale (sp on Android, pt on Apple, logical px on desktop)

| Token | Size | Weight | Use |
|---|---|---|---|
| `type.caption` | 13 | 400 | Timestamps, footnotes, bubble metadata |
| `type.secondary` | 15 | 400 | Secondary lines, list subtitles |
| `type.body` | **17** | 400 | **Body text and messages** |
| `type.title` | 20 | 600 | Section titles, dialog titles |
| `type.screen_title` | 24 | 600 | Screen titles |
| `type.onboarding` | 32 | 600 | Onboarding only |
| `type.mono_code` | 22 | 400 (Mono) | Security codes, recovery words, link codes; tracking 0.04 em |

- Line height: 1.4 for all text.
- OS text scaling is honored up to **200%** with **no truncation of message text**. Layouts reflow; bubbles grow; lists wrap.
- Numbers in security codes are grouped in fives with a thin space; screen readers read one group at a time.

## 3. Palette

One dominant color (Pine), one accent (Saffron), and neutrals. Contrast ratios follow WCAG 2.x and are checked in CI by `cargo xtask tokens-check`. Every ratio below was computed with the WCAG relative-luminance formula.

### 3.1 Tokens

| Token | Light | Dark | Role |
|---|---|---|---|
| `background` | Paper `#F6F3EC` | Night `#111412` | App background |
| `surface` | `#FFFFFF` | `#1A1E1B` | Sheets, dialogs |
| `bubble_in` | `#ECE7DC` | `#242A26` | Incoming bubble |
| `bubble_out` | `#DCEBE6` | `#2A6B58` | Outgoing bubble |
| `text` | Ink `#1C1F1D` | Chalk `#EEEAE1` | Primary text |
| `text_muted` | `#585E59` | `#A7ADA6` | Secondary text; input borders |
| `pine` (dominant) | `#1D5646` | `#7CC4A8` | Primary buttons, links, focus (light) |
| `saffron` (accent) | `#F2B230`, **fill only** | `#F5BE45` | **Fixed meaning: "confirmed by you"** |
| `danger` | Brick `#A8321E` | Ember `#F08A73` | Danger only; always with an icon and text |
| `hairline` | `#CFC8BA` | `#3A423D` | Decorative dividers only |

Derived tokens (also in `design/tokens.toml`):

| Token | Light | Dark | Why |
|---|---|---|---|
| `on_pine` | Paper `#F6F3EC` | Night `#111412` | Text on Pine buttons |
| `on_saffron` | Ink `#1C1F1D` | Night `#111412` | Text or stroke on a Saffron fill |
| `focus_ring` | Pine `#1D5646` | Saffron `#F5BE45` | 2 px focus ring (`18-a11y-i18n.md`) |
| `on_bubble_out` | Ink `#1C1F1D` | Chalk `#EEEAE1` | All text on outgoing bubbles |
| `meta_on_bubble_out` | `#585E59` | Chalk `#EEEAE1` | Timestamps and status on outgoing bubbles (§3.3) |
| `link_on_bubble_out` | Pine `#1D5646` | Chalk `#EEEAE1`, underlined | Links on outgoing bubbles (§3.3) |
| `seal_stroke` | Pine `#1D5646` | Night `#111412` | Stroke around the Seal glyph |

### 3.2 Contrast ratios

| Pair | Light | Dark | Requirement | Pass |
|---|---|---|---|---|
| `text` on `background` | 15.00 | 15.44 | 4.5 | yes |
| `text` on `surface` | 16.63 | 14.04 | 4.5 | yes |
| `text` on `bubble_in` | 13.48 | 12.20 | 4.5 | yes |
| `on_bubble_out` on `bubble_out` (Ink / Chalk) | 13.51 | 5.23 | 4.5 | yes |
| `text_muted` on `background` | 6.00 | 8.10 | 4.5 | yes |
| `text_muted` on `bubble_in` | 5.39 | 6.39 | 4.5 | yes |
| `text_muted` on `surface` | 6.64 | 7.36 | 4.5 | yes |
| `text_muted` on `bubble_out` | 5.40 | **2.74** | 4.5 | **no in dark**: use `meta_on_bubble_out` (Chalk, 5.23) |
| `on_pine` on `pine` (Paper on Pine; Night on Pine-light) | 7.67 | 9.11 | 4.5 | yes |
| `pine` on `background` (links, Pine-light on Night) | 7.67 | 9.11 | 4.5 | yes |
| `pine` on `surface` | 8.50 | 8.28 | 4.5 | yes |
| `pine` on `bubble_in` | 6.89 | 7.19 | 4.5 | yes |
| `pine` on `bubble_out` | 6.91 | **3.09** | 4.5 | **no in dark**: use `link_on_bubble_out` (Chalk, underlined) |
| Ink on `saffron` | 8.86 | 9.76 | 4.5 | yes |
| Pine on `saffron` (light Seal stroke) | 4.53 | — | 3.0 (graphic) | yes |
| `saffron` on `background` | **1.69** | 10.89 | 3.0 (graphic) | **no in light**: the Seal always has a Pine or Ink stroke |
| `saffron` on `surface` | **1.88** | 9.90 | 3.0 | same rule |
| `danger` on `background` | 6.04 | 7.58 | 4.5 | yes |
| `danger` on `surface` | 6.69 | 6.90 | 4.5 | yes |
| `focus_ring` on `background` | 7.67 | 10.89 | 3.0 | yes |
| `focus_ring` on `bubble_out` | 6.91 | 3.69 | 3.0 | yes |
| `text_muted` as input border on `background` | 6.00 | 8.10 | 3.0 | yes |
| `hairline` on `background` | 1.50 | 1.79 | none (decorative) | decorative only |

The PLAN §15.2 figures (15.0 / 15.44, 13.51, 5.23, 6.0, 5.39, 7.67, 9.11, 8.86, 1.69, 6.04 / 7.58) all reproduce exactly. The two failures in bold are pairs PLAN did not list; the derived tokens above resolve them without changing the palette.

### 3.3 Usage rules

- **Proportions:** about 85% neutrals, 12% Pine, under 3% Saffron.
- **No gradients**, anywhere.
- **Color is never the only way state is shown.** Every state has a shape and words (§6.5).
- In **light mode**, Saffron is a **fill only** and always carries a Pine or Ink stroke of at least 1.5 px so the glyph reaches 3:1.
- In **dark mode**, all text and links on the outgoing bubble use Chalk; links are underlined.
- `danger` is used only for destructive actions and genuine errors, always paired with an icon and text. A changed security code is **not** danger (§6.4).
- `hairline` is never used for input borders or any information-bearing line.

## 4. Spacing, grid, shape, elevation

| Token group | Values |
|---|---|
| Spacing (4-pt base) | 4, 8, 12, 16, 24, 32, 48, 64 |
| Grid, phone | 4 columns, 16 margin, 8 gutter |
| Grid, tablet | 8 columns, 24 margin, 16 gutter |
| Grid, desktop | 320 conversation list; fluid conversation with 680 max text width; 360 details pane |
| Touch targets | At least 48 × 48 dp |
| Radii | 8 controls; 12 bubbles (4 on the tail corner); 20 sheets |
| Elevation | Two levels only: `flat` (0) and `raised` (sheets and menus) |

## 5. Motion, haptics, icons

- **Motion:** 150 to 200 ms, ease-out. **Reduce-motion** turns every animation into a cross-fade (and the Seal close into an instant state change).
- **Haptics:** a light tick on send; a distinct pattern when the Seal closes. Haptics follow the OS setting.
- **As implemented on the desktop:** the app reads the system's reduce-motion setting at start (macOS "Reduce motion", Windows "Show animations", GNOME's animations through the desktop portal) into `Tokens.reduce-motion`, which every animation follows; haptics play on a Mac's Force Touch trackpad (`NSHapticFeedbackManager`: generic on send, level change when the Seal closes) and nowhere else on the desktop.
- **Icons:** a custom 24 px set with a 1.75 px stroke, derived from Lucide (ISC). **No locks, shields, or keyholes.**
- **App icon:** a Pine square with a paper-colored Seal (a circle with a folded notch). **As drawn** (`design/icon/`, rendered by `cargo xtask icons`): the back of a Pine letter, its lighter flap folded down to a paper-colored Seal with an inner ring; a full-bleed variant for masks and stores, and a one-color glyph (flap and Seal) for themed and symbolic icons.
- **Spinners:** never longer than 2 s without text. Progress bars show real progress only.

## 6. Signature moments

### 6.1 Onboarding: no phone number, under 60 s

1. "Talk privately. No phone number. No email." **[Get started]**
2. "What should people call you?" (name, optional photo) with the line "Only people you talk to can see this." While the user types, keys are generated and the proof-of-work runs behind a single line: "Setting up your private address…"
3. A server is picked automatically: "Your messages wait here, locked, until your devices collect them. **Change**"
4. The home screen shows three equal actions: **Show my code**, **Scan a code**, **Share an invite link**. Usernames come later, with one honest line: "A username is public, like an email address."
5. **Recovery words** are deferred until after the first conversation or 24 hours.
   - They appear as a persistent card: 24 numbered words in Mono, a check of 3 words, "Save as file" on desktop, and screenshot blocking on Android.
   - The words must be saved before linking a device or claiming a username.
   - Completing this earns the Saffron seal on Settings → Account.

### 6.2 Meeting in person is verification

- Two people scan each other's codes. The **Seal closes**: two halves meet in 240 ms (instant under reduce-motion) with a haptic pulse.
- Three matching Seal words appear on both phones.
- "You and Sam are checked in person. If anything changes, we'll tell you before you send anything."
- The contact header gains a small Saffron seal and the date.

### 6.3 Checking remotely

- Title: "Check it's really Sam."
- Twelve groups of 5 digits in Mono, or 10 words to read aloud on a call.
- Screen readers read one group at a time.
- The user taps **They match**.

### 6.4 Security code changed

An in-conversation card with a Saffron left rule and **no red**:

> Sam's security code changed. This usually means a new phone or a reinstall. Check again before sharing anything private.

Buttons: **Check now** and **Later**. The first send after a change needs a tap-through. If "Only send to checked contacts" is on, sending is blocked.

### 6.5 Security state without jargon

- "Private" is the default and is never labelled; only exceptions show.
- Contact state has three shapes plus words: a filled Seal for "Checked in person", an outline for "Not checked yet", and a notched Seal for "Code changed".
- The mode chip reads **"Off the record"**: "Nobody can prove to others who wrote these messages." Or **"On the record"**: "Your messages carry your signature. Anyone who gets a copy can prove you wrote them."
- Delivery shapes: hollow dot "Sending privately…", half dot "On its way" (sent one way), full dot "Delivered" (the recipient's receipt came), ring "Read", and a hollow dot in the warning color "Not delivered yet" (no receipt after every re-send, `09-transport.md` §6.1). The first time only: "Private delivery takes a few seconds. That pause is part of what hides who you talk to."
- The pre-call sheet offers **"Private route (hides where you are)"** or **"Direct (clearer, but Sam can see your internet address)"**.
- Settings → Privacy: "Standard" or "Maximum (hides even when you're using Enclave; uses about 2 GB a day)". On iPhone it adds: "iPhone pauses apps in the background, so Maximum only works while Enclave is open."
- "Extra protection: finishing…" (the McEliece braid) and "Backup route" appear only on the contact-info and settings screens.

### 6.6 Wrong-place link code

"This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one."

### 6.7 Contact art

Contact art is key-derived (`art_seed`, `02b-key-schedule.md` §4.3) so that a lookalike account looks different (RT-26).

- A 5 × 5 grid, mirrored left to right, on a circle clipped to the avatar size. Each cell is filled or empty from the seed's bits; the fill color is one of 8 Pine and neutral tints chosen from the seed. Saffron is never used.
- Art is shown only when the contact has no photo, and next to the name in the security-code screen.
- It is decorative for screen readers (the name is the label) and never the only identifier.
- **As implemented** (`enclave-core/src/art.rs`, `controls.slint` `Avatar`): every 1:1 contact's avatar is its art (there are no profile photos yet, F4), cells in one of 8 Pine and neutral tints on the surface color, in the conversation list, the header, the members sheet and, larger, on the security-code sheet. Groups and Note to self keep initials. Test `rt26_contact_art_depends_on_root`.

## 7. Copy voice

- A calm, exact friend who has done this before.
- Second person, sentence case, one idea per sentence.
- Say what happened, what it means, and what to do.
- Use concrete numbers ("about 80 MB an hour"). Never fear, never brag, never blame.
- Aim for a grade 6 to 8 reading level.
- **Keys and algorithms appear only in an "Advanced details" sheet.**
- Example error: "Couldn't send yet. Your phone is offline. We'll send it when you're back."
- Glossary and banned words: `design/copy-glossary.md`.

## 8. Banned

**Visuals:**

- purple-to-blue gradients, or any gradients;
- glassmorphism or frosted blur;
- emoji used as UI decoration;
- identical icon-card grids;
- padlocks, shields, keyholes, vault doors, hooded hackers, binary rain, terminal green, or skeuomorphic wax seals with shadows;
- confetti, stock photos of people, 3D blobs;
- more than two elevation levels;
- red or green as the only signal;
- toasts for security events (they must be inline and persistent);
- spinners over 2 s without text;
- fake progress.

**Copy:** "unlock", "seamless", "elevate", "empower", "supercharge", "military-grade", "bank-level", "unbreakable", "bulletproof", "hacker-proof", "100% secure", "anonymous" as a promise, "Oops", and exclamation marks in system copy.

**Behaviour:** dark patterns in privacy or data settings (pre-checked data sharing, confirm-shaming, hidden "off" options, nagging to disable Maximum privacy).

## 9. Token pipeline

- `design/tokens.toml` is the single source. `enclave-design` generates `tokens.slint` (Slint globals) at build time.
- `cargo xtask tokens-check` computes every pair in §3.2 from the TOML and fails if any "yes" pair drops below its requirement, or if a new text/background token pair is added without a row.
- CI also runs a copy lint over all `@tr()` source strings for the banned-copy list.

## Open questions

1. **Resolved:** derived tokens, and PLAN's palette stays (`bubble_out` `#2A6B58` in dark). `design/tokens.toml` sets `meta_on_bubble_out` and `link_on_bubble_out` to Chalk in dark (links underlined), and the app's build fails if any declared pair drops below its requirement (`Tokens::check`, `crates/enclave-app/build.rs`).
2. **Resolved:** the ban covers every `@tr()` string, because those are Enclave's own; the OS's wording appears only in the OS's own dialogs, which aren't in our source, so the lint needs no exception list. Where Enclave must refer to that step it says "open", for example "Open your phone to continue". No copy lint is in CI yet, and two strings in `crates/enclave-app/ui/app.slint` still say "Unlock" (the passphrase button and "Unlock with {}"); both must change when the lint lands.
3. **Resolved:** art stays a hint, never a check (§6.7; the security code is the check). Distinctness is tested: one changed bit of the root gives other art, and 200 roots give more than 190 distinct arts (`rt26_contact_art_depends_on_root`). Only 15 bits choose the pattern and 3 the tint, so someone can grind a root to match a contact's art; that is why it is never the only identifier. The pattern carries the difference for people with color-vision deficiencies; checking that with users is part of the WCAG audit and usability sessions (G9).
