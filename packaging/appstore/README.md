# App Store listing

What to enter in App Store Connect for Enclave (bundle ID
`com.aricummings.enclave`). The screenshots in this folder are rendered by
`enclave-shots` at 3x (`ENCLAVE_SHOT_SCALE=3`; iPad from the wide layout at
2x) and framed by `make.py` at the sizes in Apple's screenshot
specifications; every limit below is App Store Connect's.

| Folder | App Store Connect field |
| --- | --- |
| `iphone-6.3/` (1206 x 2622) | iPhone with Dynamic Island, medium display (6.3"): **required** |
| `iphone-6.9/` (1320 x 2868) | iPhone with Dynamic Island, large display (6.9"): optional |
| `ipad-13/` (2752 x 2064, landscape) | iPad 13" Display: required, as the app runs on iPad |

Upload each folder in file order to its own display size; a file sent to
another size is refused for its dimensions. Apple scales them down for the
smaller displays.
The app icon comes from the build.

## App Information

- **Name** (30 max): `Enclave: Private Messenger`
- **Subtitle** (30 max): `Private messages over Tor`
- **Category:** Primary **Social Networking**, secondary **Utilities**.
- **Content rights:** "No, it does not contain, show, or access
  third-party content". (GIF search shows images from Wikimedia Commons
  only when a user searches; if Apple asks, answer Yes and say so.)
- **Age rating:** answer **None** to every content question (violence,
  sexual content, profanity, drugs, gambling, horror, medical);
  **Unrestricted web access: No**; **Messaging and chat / user-generated
  content: Yes**; **Advertising: No**; **Parental controls: No**. Apple
  computes the rating from the answers.

## Pricing and Availability

- **Price:** Free.
- **Availability:** every country except **France** (Enclave carries its
  own encryption, and France asks for a declaration before distribution;
  see App Encryption Documentation in `docs/release-checklist.md`).

## App Privacy

- **Privacy policy URL:**
  `https://github.com/0xnullsect0r/enclave-messenger/blob/main/PRIVACY.md`
- **Do you or your third-party partners collect data from this app?** Yes.
- Data types (each: used for **App Functionality** only, **not used for
  tracking**):

| Data type | Linked to the user | Why |
| --- | --- | --- |
| Identifiers → **User ID** | Yes | The optional username, published so people can find the user |
| Identifiers → **Device ID** | Yes | The push token, only when the user turns on notifications through Apple |

Not collected: name, email, phone number, contacts, location, messages,
photos, audio, files and everything else. Messages, media and shared
locations are end-to-end encrypted, so neither the developer nor a server
operator can read them; Apple counts data as collected only when it can be
accessed. Crash reports and reported messages are sent only when the user
chooses to, from a clearly named button, which Apple's optional disclosure
rules leave out.

## Version (0.1.0)

**Promotional text** (170 max, can change without a new build):

```
No phone number, no email, no tracking. Messages, calls and files are end-to-end encrypted with post-quantum keys and travel over Tor, so servers can't see who you are.
```

**Description** (4,000 max):

```
Enclave is a messenger that hides not only what you say, but who you talk to and when.

No phone number. No email.
Your account is a set of keys made on your phone. Add people by scanning their code, sharing a link, or by an optional username.

Hides who you talk to
Enclave reaches its servers through Tor onion services, so no server sees your IP address. Every message is the same size and the app sends cover traffic, so even the network can't tell when you're talking.

Post-quantum encryption from the first message
Everything is end-to-end encrypted with keys that resist future quantum computers: messages, photos, files, voice notes, locations, stickers and calls.

Check it's really them
Compare a security code or a few words in person or on a call. Meet in person and Enclave remembers you checked.

Servers you don't have to trust
Servers are run by independent operators. They can't read messages, see your contacts or swap your keys without being caught: every key change is published in a public log that other operators watch.

Everything you expect
- 1:1 and group chats, with replies, reactions, mentions and polls
- Photos, videos, files up to 100 MB, voice notes and stickers
- Voice and video calls, group calls and screen sharing
- Disappearing messages and view-once media
- Stories that only the people you choose can see
- Several devices on one account
- App lock, an emergency PIN, and encrypted backups

Free, with no ads and no tracking.

Open source
Every line of Enclave is public: github.com/0xnullsect0r/enclave-messenger
```

**Keywords** (100 max; words already in the name and subtitle count
without repeating them):

```
encrypted,secure,chat,e2ee,post-quantum,anonymous,video calls,groups,privacy,no phone number,onion
```

**Support URL:** `https://github.com/0xnullsect0r/enclave-messenger/issues`

**Marketing URL:** `https://github.com/0xnullsect0r/enclave-messenger`

**Copyright:** `2026 ` and the developer's legal name, as on the Apple
developer account.

**What's New** (from the second version on):

```
First beta of Enclave.
```

## App Review Information

- **Sign-in required:** No (there is no login; the account is created on
  the device).
- **Contact:** the developer's name, phone number and email.
- **Notes** (4,000 max):

```
Enclave has no login. Tap "Get started", choose a name, and the account is created on the device. The first connection goes through the Tor network and can take up to a minute.

To try messaging you need two accounts: install Enclave on a second device (an iPhone and an iPad work), create an account on each, then open "My code" on one and tap "Add someone" on the other to scan it (or copy an invite link from "My code" and paste it on the other device). Accept the message request, and messages, voice notes, photos and calls then work between them.

Encryption: the app uses standard algorithms (ML-KEM, X25519, AES, ChaCha20, Ed25519, SHA-3) for end-to-end encryption of the users' own messages.

User-generated content (guideline 1.2): in any conversation, long-press a message or open the conversation menu to Report it (the reported message goes to the server's operator) or Block the person; blocked people can no longer message you. Contact for abuse reports: see the Support URL.

Background modes: remote-notification (message wakes), voip (incoming calls through CallKit), audio (calls continue with the screen locked).
```
