#!/usr/bin/env bash
# Select the Xcode an App Store build is made with (release.yml `ios`,
# ios-store-check.yml): the newest Xcode_X.Y.app on the runner. GitHub's
# images name a release candidate Xcode_X.Y_Release_Candidate.app and
# link Xcode_X.Y.app to it, which App Store Connect takes as the newest
# (Apple's releases page lists the RC), so a release candidate is picked
# through its link and a beta never is.
set -euo pipefail
ls -d /Applications/Xcode*.app
want=$(ls -d /Applications/Xcode_*.app | sed -n 's|^/Applications/Xcode_\([0-9][0-9.]*\)\.app$|\1|p' | sort -V | tail -n 1)
[ -n "$want" ] || { echo "no released Xcode on this runner"; exit 1; }
sudo xcode-select -s "/Applications/Xcode_${want}.app"
# Read whole: grep -q closing the pipe early makes xcodebuild abort
# (SIGPIPE), which pipefail counts as a failure.
v=$(xcodebuild -version)
echo "$v"
echo "iOS SDK $(xcrun --sdk iphoneos --show-sdk-version) ($(xcrun --sdk iphoneos --show-sdk-build-version))"
# Xcode_27.2.0.app and Xcode_27.2.app are the same release.
grep -Eq "^Xcode ${want%.0}(\.0)?\$" <<<"$v" || { echo "not Xcode $want"; exit 1; }
