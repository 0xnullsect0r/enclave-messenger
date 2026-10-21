# Enclave privacy policy

Last updated: 21 October 2026

Enclave is a messenger built so that the people who make it and run its
servers learn as little about you as possible. This policy covers the
Enclave apps (Android, iOS, macOS, Windows, Linux) published from
github.com/0xnullsect0r/enclave-messenger, and the servers we run. Servers
run by other operators follow this design too, but each operator is
responsible for its own server.

## What we never get

- **Your messages, photos, files, voice notes, calls, locations and
  stickers.** They are end-to-end encrypted on your device. Servers store
  and pass on only ciphertext they cannot read.
- **Your contacts and groups.** Your contact list, who is in your groups and
  who you talk to stay on your devices.
- **Your phone number or email.** Enclave doesn't ask for either. Your
  account is a set of keys made on your device.
- **Your IP address.** The app reaches servers through Tor and the Nym
  mixnet, so a server sees traffic from the network, not from you. Every
  message is the same size, and the app sends cover traffic, so a server
  can't tell when you are talking.
- **Analytics, advertising or tracking.** The app has none.

## What a server holds, and for how long

| Data | Why | How long |
| --- | --- | --- |
| Your public keys (account and device keys, one-time keys) | So contacts can start encrypted conversations with you | Until you delete your account |
| Encrypted messages waiting for your other devices or contacts | Delivery | Until fetched, at most 30 days |
| Encrypted attachments, not linked to your account | Delivery | At most 30 days |
| Inbox addresses and one-time delivery tokens, which change every week and aren't linked to who you are | Delivery | Until they expire |
| Your username, only if you choose one | So people can find you | Until you delete your account. It is published in a public key-transparency log, as usernames must be to stop a server swapping keys; deleting your account leaves only a deletion mark. |
| A sealed push registration, only if you turn on notifications through Apple or Google | Waking your phone | Until you turn it off or delete your account |
| A message you report, only if you report it | Handling abuse | Until the server's operator handles it |

## Apple and Google push

If you allow notifications through Apple (iOS) or Google (Android, Play
build, only when you choose it), Apple or Google sees that your device was
woken, but not by whom or with what. The wake carries no message content.
You can use Enclave without them: Android offers UnifiedPush or staying
connected.

## Features that reach other services

- **GIF search** (off until you use it) searches Wikimedia Commons through
  Tor. Wikimedia sees the search, not who you are.
- **Link previews** (off by default) are fetched by the sender's device
  through Tor and sent inside the encrypted message.
- **Location sharing** reads your location only when you choose to share
  it, and sends it end-to-end encrypted to that conversation.
- **Voice transcription** downloads a speech model once, through Tor, and
  then runs on your device. Your audio never leaves it.

## Permissions

Camera (scanning codes, photos, video calls), microphone (voice notes and
calls), location (only when you share it), notifications, and running in
the background to receive messages. Each is used only for that purpose,
and the camera and microphone only while you are using them.

## Crash reports

When a part of the app crashes, a report is kept on your device. Nothing
is sent unless you choose to send it, and then it goes end-to-end
encrypted to Enclave Support, with personal data removed.

## Deleting your account

In the app: **Settings → Delete my account**, on the device that holds
your recovery words. It deletes your public keys, username, inboxes and
push registration from the server, tells your contacts the account is
closed, records the deletion in the key-transparency log, and erases the
device. Attachments you sent expire on their own within 30 days.
**Settings → Erase this device** erases one device only. Uninstalling
the app removes everything stored on that device.

## Children

Enclave is not directed at children under 13 (or the minimum age in your
country).

## Changes

Changes to this policy are made in this file in the public repository,
where its history is visible.

## Contact

Questions about privacy: open an issue at
https://github.com/0xnullsect0r/enclave-messenger/issues, or use the
contact email on the app's store listing. To report a security problem
privately, see SECURITY.md.
