# Copy Glossary and Banned Words

Status: Draft (M0) · Normative

Source: PLAN.md §15.4 to §15.6. Design system: `docs/17-design.md`. Every user-facing string in Enclave follows this file. CI lints all `@tr()` source strings against §3.

## 1. Voice

- A calm, exact friend who has done this before.
- Second person, sentence case, one idea per sentence.
- Say what happened, what it means, and what to do.
- Use concrete numbers ("about 45 MB an hour"). Never fear, never brag, never blame.
- Grade 6 to 8 reading level.
- Keys and algorithm names appear only in the "Advanced details" sheet.
- No exclamation marks in system copy.

## 2. Glossary

| Use | Not | Meaning / notes |
|---|---|---|
| security code | safety number, fingerprint, key hash | The 60 digits or 10 words that confirm a contact's account |
| recovery words | seed phrase, mnemonic, backup phrase, private key | The 24 words that recover an account |
| checked | verified, trusted, authenticated | A contact whose security code the user confirmed |
| checked in person | verified in person | Confirmed by a mutual scan |
| not checked yet | unverified, untrusted | Default contact state |
| code changed | key changed, identity changed | The contact's security code changed |
| private route | relay, TURN, proxy | The default call mode, which hides where you are |
| direct | P2P, peer-to-peer | The opt-in call mode that shows your internet address |
| off the record | deniable, OTR | Nobody can prove to others who wrote the messages |
| on the record | signed, non-repudiable | Messages carry your signature |
| linked devices | sessions, clients, instances | Your other phones and computers |
| message request | pending chat, unknown sender | A first message from someone not in your contacts |
| Maximum privacy | paranoid mode, stealth mode | The constant cover-traffic setting |
| backup route | fallback transport, onion fallback | The onion route for a server on the optional Nym mixnet, used only with consent (RFC 0010) |
| extra protection | McEliece, third KEM, braid | Shown as "Extra protection: finishing…" |
| Seal (UI) | lock, badge | The Saffron glyph that means "confirmed by you" |
| Seal words | SAS, short authentication string | Three words shown after an in-person scan |
| private address | inbox, mailbox | Where your messages wait (onboarding only) |
| username | handle, ID | "A username is public, like an email address." |
| invite link | share link | A link that lets someone send you a first message |

## 3. Banned words and patterns

| Banned | Why | Say instead |
|---|---|---|
| unlock (in Enclave's own strings) | Implies a padlock metaphor | "open", "continue" |
| seamless | Marketing | say what happens |
| elevate, empower, supercharge | Marketing | say what happens |
| military-grade, bank-level | Unverifiable claim | say nothing, or name the property plainly |
| unbreakable, bulletproof, hacker-proof | False promise | "Only you and Sam can read these messages." |
| 100% secure | False promise | — |
| anonymous (as a promise) | Overclaim; using Enclave is visible | "hides who you talk to" |
| Oops | Trivializes errors | say what happened |
| `!` in system copy | Alarm or hype | full stop |
| safety number, fingerprint | Glossary conflict | security code |

Behavior copy is also banned: confirm-shaming ("No thanks, I don't care about privacy"), pre-checked data sharing, and nagging to turn off Maximum privacy.

## 4. Reference strings

| Context | String |
|---|---|
| Welcome | Talk privately. No phone number. No email. |
| Name prompt | What should people call you? |
| Name note | Only people you talk to can see this. |
| Setup progress | Setting up your private address… |
| Server | Your messages wait here, locked, until your devices collect them. |
| Username note | A username is public, like an email address. |
| In-person done | You and Sam are checked in person. If anything changes, we'll tell you before you send anything. |
| Remote check title | Check it's really Sam. |
| Code changed card | Sam's security code changed. This usually means a new phone or a reinstall. Check again before sharing anything private. |
| Off the record chip | Nobody can prove to others who wrote these messages. |
| On the record chip | Your messages carry your signature. Anyone who gets a copy can prove you wrote them. |
| Delivery, first time | Private delivery takes a few seconds. That pause is part of what hides who you talk to. |
| Call route | Private route (hides where you are) / Direct (clearer, but Sam can see your internet address) |
| Maximum | Maximum (hides even when you're using Enclave; uses about 1.1 GB a day) |
| Maximum on iPhone | iPhone pauses apps in the background, so Maximum only works while Enclave is open. |
| Wrong-place link code | This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one. |
| New device banner | New device linked: *{device}*, {date} {time}. Not you? Remove it |
| Offline error | Couldn't send yet. Your phone is offline. We'll send it when you're back. |
| Gap notice | A message from Sam may not have arrived. |
| Server gone | Sam's server is unreachable. We'll keep trying. |
| Group mismatch | Some people in this group may be seeing different messages. |
| Backup route | Backup route: slower to hide who you talk to |
| Lost everything | If you lose your recovery words and all your devices, you'll need to start a new account. |
| Emergency PIN caveat | A copy of your phone made before you used the emergency PIN isn't affected. |
| Off-the-record report | Because this chat is off the record, the operator can't confirm who wrote these messages. |

Strings in `{braces}` are placeholders. "Sam" stands for the contact's display name.
