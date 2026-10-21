# Google Play listing

What to enter in the Play Console for Enclave (package
`com.aricummings.enclave`). The graphics in this folder are rendered from `design/icon/`, the app's
fonts and `docs/screenshots/*-phone-light.png`.

| File | Play Console field |
| --- | --- |
| `icon-512.png` | App icon (512 x 512) |
| `feature-graphic.png` | Feature graphic (1024 x 500) |
| `phone-1-…png` to `phone-6-…png` | Phone screenshots, in that order |

## Store listing

**App name** (30 max): `Enclave: Private Messenger`

**Short description** (80 max):

```
Private messages, groups and calls. No phone number, no email, no tracking.
```

**Full description** (4,000 max):

```
Enclave is a messenger that hides not only what you say, but who you talk to and when.

No phone number. No email.
Your account is a set of keys made on your phone. Add people by scanning their code, sharing a link, or by an optional username.

Hides who you talk to
Messages travel through Tor and the Nym mixnet, so no server sees your IP address. Every message is the same size and the app sends cover traffic, so even the network can't tell when you're talking.

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

Open source
Every line of Enclave is public: github.com/0xnullsect0r/enclave-messenger
```

## Categorisation and contact details

- App or game: **App**. Category: **Communication**.
- Tags: Messaging, Communication (choose the closest offered).
- Email: your choice (shown publicly).
- Website: `https://github.com/0xnullsect0r/enclave-messenger`

## App content

**Privacy policy:** `https://github.com/0xnullsect0r/enclave-messenger/blob/main/PRIVACY.md`

**App access (sign-in details):** "All functionality is available without
special access". There is no login: the account is created on the
device. Reviewers can use the app as is, provided a listed server is
running.

**Ads:** No, the app doesn't contain ads.

**Content rating** (IARC questionnaire):
- Category: **All other app types** / "Utility, productivity, communication or other".
- Violence, fear, sexuality, language, controlled substances, gambling: **No** to every question.
- Does the app allow users to interact or exchange content? **Yes**.
- Does the app share the user's current location with other users? **Yes** (only when the user chooses to share it).
- Does the app allow users to purchase digital goods? **No**.
- Is the app a web browser or search engine? **No**.

**Target audience:** **18 and over** only. Does the app appeal to
children? **No**. (This keeps it out of the Families programme, which
doesn't allow anonymous messaging with strangers.)

**News app:** No.

**Data safety:**
- Does your app collect or share any of the required user data types? **Yes** (two optional items below; messages and media are end-to-end encrypted and don't count as collected).
- Is all of the user data collected by your app encrypted in transit? **Yes**.
- Which of the following methods of account creation does your app support? **The app lets users create an account** with "Username and other authentication" / "Other".
- Delete account URL: `https://github.com/0xnullsect0r/enclave-messenger/blob/main/PRIVACY.md#deleting-your-account`
- Do you provide a way for users to request that some or all of their data is deleted, without requiring them to delete their account? **No** (deleting the account removes everything; uninstalling removes everything on the device).
- Data types:

| Data type | Collected | Shared | Optional | Ephemeral | Purpose |
| --- | --- | --- | --- | --- | --- |
| Personal info → **User IDs** (the optional username) | Yes | No | Yes | No | App functionality |
| Device or other IDs (the push token, only when Apple or Google push is on) | Yes | No | Yes | No | App functionality |

Everything else (name, email, phone, location, messages, photos, audio,
files, contacts, app activity, crash logs, diagnostics): **not collected**.
Messages, media and shared locations are end-to-end encrypted, and crash
reports go end-to-end encrypted only when the user chooses to send one.

**Government apps:** No. **Financial features:** "My app doesn't provide
any financial features". **Health:** "My app doesn't have any health
features".

## Declarations Play asks for after the first upload

- **Foreground service types** (`specialUse`, `phoneCall`, `microphone`,
  `mediaProjection`):
  - specialUse: "Keeps the encrypted connection to the user's messaging
    server open while the user has chosen to stay connected instead of
    using a push service, so messages arrive. Shown as an ongoing
    notification the user can turn off."
  - phoneCall and microphone: "Voice and video calls the user starts or
    answers."
  - mediaProjection: "Screen sharing in a call, started by the user."
  - Play may ask for a short screen recording of each: record the
    notification, a call, and a screen share.
- **Full-screen intent** (`USE_FULL_SCREEN_INTENT`): "Calling: shows the
  incoming-call screen when someone calls."
- **Advertising ID:** the app does not use it.

## Testing before production

A personal developer account has to run a closed test with at least 12
testers for 14 days in a row before it can publish to production. Upload
the release's `Enclave-VERSION.aab` to a closed testing track, add the
testers' Google accounts or a Google Group, and send them the opt-in link.
