#!/usr/bin/env bash
# The screen recordings Google Play asks for with the foreground-service
# declarations (README.md, "Declarations Play asks for after the first
# upload"), made on two Android emulators on this computer: phone A records,
# phone B is the other end of the calls.
#
#   packaging/play/record-videos.sh [VERSION]    # default: the newest release
#
# It installs what it needs (the Android command-line tools, the emulator,
# an Android 14 image) under ~/Android/Sdk, starts both phones, installs the
# release's APK on them, and then walks through each video: it says what to
# tap, records phone A while you do it, and saves the video in
# ~/enclave-play-videos/. Upload those to YouTube as Unlisted and paste the
# links into Play Console.
#
# Needs: Linux with KVM (/dev/kvm), Java 17 or newer, curl, unzip, about
# 6 GB of disk and 8 GB of RAM. Both phones create accounts on the server in
# the app's built-in list, over Tor.
set -euo pipefail

REPO=0xnullsect0r/enclave-messenger
SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}
IMAGE="system-images;android-34;google_apis;x86_64"
OUT=$HOME/enclave-play-videos
A=emulator-5554
B=emulator-5556

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
step() { printf '   - %s\n' "$@"; }
wait_enter() { read -r -p "   Press Enter $1 " _ </dev/tty; }
die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- checks
[ -r /dev/kvm ] && [ -w /dev/kvm ] || die "No access to /dev/kvm. Enable virtualization in the BIOS, then: sudo usermod -aG kvm \$USER (and log in again)."
command -v java >/dev/null || die "Java is missing. Arch: sudo pacman -S jdk17-openjdk   Debian/Ubuntu: sudo apt install openjdk-17-jdk-headless"
for t in curl unzip sha256sum; do command -v $t >/dev/null || die "$t is missing"; done
jv=$(java -version 2>&1 | awk -F'"' '/version/ {split($2, v, "."); print (v[1] == "1" ? v[2] : v[1])}')
[ "${jv:-0}" -ge 17 ] || die "Java $jv is too old; the Android tools need 17 or newer."

# ---------------------------------------------------------------- the SDK
export ANDROID_HOME=$SDK ANDROID_SDK_ROOT=$SDK
mkdir -p "$SDK"
SDKM=$SDK/cmdline-tools/latest/bin/sdkmanager
if [ ! -x "$SDKM" ]; then
  say "Downloading the Android command-line tools into $SDK"
  tmp=$(mktemp -d)
  curl -fL --progress-bar -o "$tmp/tools.zip" \
    https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
  unzip -q "$tmp/tools.zip" -d "$tmp"
  mkdir -p "$SDK/cmdline-tools"
  rm -rf "$SDK/cmdline-tools/latest"
  mv "$tmp/cmdline-tools" "$SDK/cmdline-tools/latest"
  rm -rf "$tmp"
fi
say "Installing the emulator, platform tools and the Android 14 image (once; about 2 GB)"
yes | "$SDKM" --licenses >/dev/null 2>&1 || true
"$SDKM" --install emulator platform-tools "$IMAGE" >/dev/null
ADB=$SDK/platform-tools/adb
EMU=$SDK/emulator/emulator
AVDM=$SDK/cmdline-tools/latest/bin/avdmanager

for n in enclave-a enclave-b; do
  if ! "$EMU" -list-avds | grep -qx "$n"; then
    echo no | "$AVDM" create avd -n "$n" -k "$IMAGE" -d pixel_7 >/dev/null
    # A camera for the video call (the emulator's moving test scene).
    printf 'hw.camera.back=virtualscene\nhw.camera.front=emulated\nhw.ramSize=3072\n' \
      >> "$HOME/.android/avd/$n.avd/config.ini"
  fi
done

# ---------------------------------------------------------------- the APK
if [ -n "${1:-}" ]; then
  V=${1#v}
else
  V=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=1" \
    | grep -m1 '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
fi
[ -n "$V" ] || die "Couldn't find the newest release."
mkdir -p "$OUT/apk"
APK=$OUT/apk/Enclave-$V-android-x86_64.apk
if [ ! -s "$APK" ]; then
  say "Downloading Enclave $V for the emulator"
  base=https://github.com/$REPO/releases/download/v$V
  curl -fL --progress-bar -o "$APK" "$base/Enclave-$V-android-x86_64.apk"
  curl -fsSL -o "$OUT/apk/SHA256SUMS-$V" "$base/SHA256SUMS"
  want=$(awk -v f="Enclave-$V-android-x86_64.apk" '$2 == f {print $1}' "$OUT/apk/SHA256SUMS-$V")
  have=$(sha256sum "$APK" | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$have" ] || { rm -f "$APK"; die "The APK's checksum doesn't match the release's SHA256SUMS."; }
  echo "   checksum OK"
fi

# ---------------------------------------------------------------- the phones
boot() {  # avd port
  if ! "$ADB" devices | grep -q "emulator-$2"; then
    "$EMU" -avd "$1" -port "$2" -no-boot-anim -no-snapshot-save -gpu auto \
      >"$OUT/$1.log" 2>&1 &
  fi
}
say "Starting phone A (records) and phone B (the other end of the calls)"
"$ADB" start-server >/dev/null
boot enclave-a 5554
boot enclave-b 5556
for d in $A $B; do
  "$ADB" -s $d wait-for-device
  until [ "$("$ADB" -s $d shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 2; done
  "$ADB" -s $d shell settings put global window_animation_scale 1 >/dev/null
  "$ADB" -s $d install -r -g "$APK" >/dev/null
  echo "   $d ready, Enclave $V installed"
done
# Phone A's name in the recordings.
"$ADB" -s $A shell settings put global device_name "Phone A" >/dev/null 2>&1 || true

record() {  # file
  "$ADB" -s $A shell rm -f /sdcard/rec.mp4
  "$ADB" -s $A shell screenrecord --time-limit 180 --bit-rate 6000000 /sdcard/rec.mp4 &
  REC=$!
  sleep 1
  echo "   Recording phone A (3 minutes at most)."
}
stop() {  # file
  "$ADB" -s $A shell pkill -INT screenrecord >/dev/null 2>&1 || true
  wait "$REC" 2>/dev/null || true
  sleep 2
  "$ADB" -s $A pull /sdcard/rec.mp4 "$OUT/$1" >/dev/null
  echo "   Saved $OUT/$1"
}

# ---------------------------------------------------------------- set-up
say "Set up both phones (not recorded)"
step "On each phone: open Enclave, tap Get started, give a name (Phone A / Phone B) and wait until the chat list shows (Tor takes up to a minute the first time)."
step "On phone B: tap My code, then Copy invite link. (The emulators share the clipboard with this computer.)"
step "On phone A: tap Add, paste the link, send the request. On phone B: open the request and Accept it."
step "Send one message each way so the conversation is open on both."
wait_enter "when both phones show the conversation with each other."

# ---------------------------------------------------------------- 1. calls
say "Video 1 of 3: a call (Phone call and Microphone)"
step "When recording starts: on phone B, open the conversation and tap the call (phone) button."
step "On phone A: the call rings. Answer it."
step "On phone A: press the Home button (circle at the bottom). The call goes on: show the ongoing call notification by pulling the status bar down."
step "Wait a few seconds, then hang up from the notification or by going back into Enclave."
wait_enter "to start recording."
record
wait_enter "when the call has ended, to stop recording."
stop 1-call-phonecall-microphone.mp4

# ---------------------------------------------------------------- 2. screen share
say "Video 2 of 3: sharing the screen in a video call (Media projection)"
step "When recording starts: on phone A, open the conversation and tap Video call. On phone B, answer."
step "On phone A: tap Share screen, and in Android's prompt choose to share and tap Start."
step "Press Home on phone A: the call keeps sharing (Android shows that it is). Open any app for a second."
step "Go back into Enclave, tap Stop sharing, then hang up."
wait_enter "to start recording."
record
wait_enter "when you've hung up, to stop recording."
stop 2-screenshare-mediaprojection.mp4

# ---------------------------------------------------------------- 3. stay connected
say "Video 3 of 3: staying connected (Special use)"
step "When recording starts: on phone A, open Settings in Enclave, then Notifications, and choose Stay connected."
step "Press Home. Pull the status bar down: the ongoing \"Enclave — Connected, so messages arrive\" notification is there."
step "Push the shade back up. On phone B, send phone A a message: it arrives on phone A as a notification while Enclave is in the background."
wait_enter "to start recording."
record
wait_enter "when the message has arrived on phone A, to stop recording."
stop 3-stayconnected-specialuse.mp4

say "Done. The videos are in $OUT:"
ls -1 "$OUT"/*.mp4
cat <<EOF

Upload each to YouTube as Unlisted, then in Play Console (App content →
Foreground service permissions):
  Media projection  → 2-screenshare-mediaprojection.mp4
  Microphone        → 1-call-phonecall-microphone.mp4
  Phone call        → 1-call-phonecall-microphone.mp4
  Special use       → 3-stayconnected-specialuse.mp4

Stop the emulators with:  $ADB -s $A emu kill; $ADB -s $B emu kill
EOF
