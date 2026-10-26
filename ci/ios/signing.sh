#!/usr/bin/env bash
# The distribution certificate in a keychain of the job's own, the
# provisioning profiles and the App Store Connect key (release.yml `ios`,
# ios-store-check.yml), from the secrets in P12, P12_PASSWORD, PROFILE,
# NSE_PROFILE, BROADCAST_PROFILE and ASC_P8. What apps/ios/bundle.sh reads
# goes to $GITHUB_ENV.
set -euo pipefail
kc="$RUNNER_TEMP/ios.keychain-db"
kcpw=$(head -c 24 /dev/urandom | base64)
security create-keychain -p "$kcpw" "$kc"
security set-keychain-settings -lut 21600 "$kc"
security unlock-keychain -p "$kcpw" "$kc"
echo "$P12" | base64 --decode > "$RUNNER_TEMP/dist.p12"
security import "$RUNNER_TEMP/dist.p12" -P "$P12_PASSWORD" -A -t cert -f pkcs12 -k "$kc"
rm "$RUNNER_TEMP/dist.p12"
security set-key-partition-list -S apple-tool:,apple: -s -k "$kcpw" "$kc" > /dev/null
security list-keychains -d user -s "$kc" $(security list-keychains -d user | tr -d '"')
id=$(security find-identity -v -p codesigning "$kc" | awk '/Apple Distribution/{print $2; exit}')
test -n "$id"
echo "IOS_SIGN_IDENTITY=$id" >> "$GITHUB_ENV"
# Without the app's profile the .ipa is signed ad hoc (for sideloading)
# and not sent to TestFlight; the release still publishes.
if [ -n "$PROFILE" ]; then
  echo "$PROFILE" | base64 --decode > "$RUNNER_TEMP/enclave.mobileprovision"
  echo "IOS_PROFILE=$RUNNER_TEMP/enclave.mobileprovision" >> "$GITHUB_ENV"
else
  echo "::warning::IOS_PROVISIONING_PROFILE_BASE64 is empty: the .ipa is signed ad hoc and not uploaded to TestFlight"
fi
if [ -n "$NSE_PROFILE" ]; then
  echo "$NSE_PROFILE" | base64 --decode > "$RUNNER_TEMP/nse.mobileprovision"
  echo "IOS_NSE_PROFILE=$RUNNER_TEMP/nse.mobileprovision" >> "$GITHUB_ENV"
fi
if [ -n "$BROADCAST_PROFILE" ]; then
  echo "$BROADCAST_PROFILE" | base64 --decode > "$RUNNER_TEMP/broadcast.mobileprovision"
  echo "IOS_BROADCAST_PROFILE=$RUNNER_TEMP/broadcast.mobileprovision" >> "$GITHUB_ENV"
fi
echo "$ASC_P8" | base64 --decode > "$RUNNER_TEMP/asc.p8"
echo "ASC_KEY_PATH=$RUNNER_TEMP/asc.p8" >> "$GITHUB_ENV"
