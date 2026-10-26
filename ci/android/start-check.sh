#!/usr/bin/env bash
# An APK on a running emulator (release.yml `install-android`,
# android-apk-check.yml): it installs, starts, is still running after
# 20 s with Tor started in its process, and shows its first screen to the
# accessibility tree; then it is uninstalled.
#
#   ci/android/start-check.sh APK
set -euo pipefail
apk=$1
# -g: grant the runtime permissions (the notification prompt would cover
# the window).
adb install -r -g "$apk"
adb shell am start -W -n com.aricummings.enclave/.EnclaveActivity
sleep 20
# What the app and the system said while it started (a crash, and the
# service bringing the process back, would show here).
adb logcat -d -b crash -v brief | tail -80
adb logcat -d -v brief -s enclave AndroidRuntime DEBUG libc ActivityTaskManager WindowManager NativeActivity threaded_app | grep -v 'Slow operation' | tail -150 || true
adb shell dumpsys activity activities | grep -iE 'aricummings|ResumedActivity' | head -20 || true
adb shell dumpsys window | grep -iE 'mCurrentFocus|mFocusedApp' | head -5 || true
adb shell pidof com.aricummings.enclave
# Tor started in the app's process (0.1.1's stopped at a lock std doesn't
# implement on Android, so no account could be set up).
if adb logcat -d -v brief -s enclave | grep -E "enclave-tord: |Tor didn.t start"; then
  exit 1
fi
# uiautomator reads the accessibility tree TalkBack reads (PC-28): the
# first dump turns accessibility on and the app sends its tree, so the
# second has the welcome screen's controls in it.
adb shell uiautomator dump /sdcard/ui.xml > /dev/null
sleep 3
adb shell uiautomator dump /sdcard/ui.xml
adb shell cat /sdcard/ui.xml > ui.xml
grep -q com.aricummings.enclave ui.xml || { cat ui.xml; exit 1; }
grep -q 'Get started' ui.xml || { cat ui.xml; exit 1; }
adb uninstall com.aricummings.enclave
adb logcat -c
