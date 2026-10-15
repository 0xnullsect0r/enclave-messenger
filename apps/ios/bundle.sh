#!/usr/bin/env bash
# Build Enclave for iOS (release.yml `ios`, on macOS): the program
# (nym/enclave-mobile, bin enclave-ios) in Enclave.app with its icon, signed,
# and packed as an .ipa in OUT.
#
#   apps/ios/bundle.sh OUT [--simulator]
#
# Signing: IOS_SIGN_IDENTITY (an "Apple Distribution" certificate in the
# keychain) and IOS_PROFILE (its App Store provisioning profile) sign for
# the App Store and TestFlight, and IOS_NSE_PROFILE (the profile for
# com.aricummings.enclave.nse) adds the notification service extension,
# which shows who wrote with previews on; signed without it, the app ships
# without the extension ("New message" only). Without them the app is
# signed ad hoc, with the extension,
# which a sideloading tool (AltStore, SideStore) re-signs with its user's
# Apple ID, and which the simulator runs. With ASC_KEY_ID, ASC_ISSUER_ID and
# ASC_KEY_PATH (an App Store Connect API key) a signed .ipa is uploaded to
# TestFlight.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
SIM=${2:-}
if [ "$SIM" = --simulator ]; then
  TARGET=aarch64-apple-ios-sim SDK=iphonesimulator PLATFORM=iPhoneSimulator
else
  TARGET=aarch64-apple-ios SDK=iphoneos PLATFORM=iPhoneOS
fi
V=${ENCLAVE_VERSION:-$(cd "$ROOT" && cargo xtask version)}
BUILD=$(cd "$ROOT" && cargo xtask version --android-code "$V")
export IPHONEOS_DEPLOYMENT_TARGET=16.0
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
export SOURCE_DATE_EPOCH=$epoch
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$ROOT=/src"
(cd "$ROOT/nym" && cargo build --release --locked --target "$TARGET" -p enclave-mobile --bin enclave-ios)
(cd "$ROOT" && cargo build --release --locked --target "$TARGET" -p enclave-nse)

work=$ROOT/nym/target/$TARGET/release/ios
app=$work/Enclave.app
rm -rf "$work" && mkdir -p "$app"
cp "$ROOT/nym/target/$TARGET/release/enclave-ios" "$app/Enclave"
sed -e "s/@VERSION@/${V%%-*}/" -e "s/@BUILD@/$BUILD/" "$ROOT/apps/ios/Info.plist" > "$app/Info.plist"
printf 'APPL????' > "$app/PkgInfo"

# The icon: an asset catalog compiled by actool, which also says what to
# add to Info.plist.
mkdir -p "$work/Assets.xcassets"
cp -R "$ROOT/packaging/icons/ios/AppIcon.appiconset" "$work/Assets.xcassets/"
printf '{ "info" : { "author" : "xcode", "version" : 1 } }\n' > "$work/Assets.xcassets/Contents.json"
xcrun actool "$work/Assets.xcassets" --compile "$app" --platform "$SDK" \
  --minimum-deployment-target 16.0 --app-icon AppIcon --target-device iphone --target-device ipad \
  --output-partial-info-plist "$work/icon.plist" > /dev/null
/usr/libexec/PlistBuddy -c "Merge $work/icon.plist" "$app/Info.plist"

# What Xcode records about the build (App Store processing checks them).
built() {
  local info=$1
  plist() { /usr/libexec/PlistBuddy -c "Add :$1 $2 $3" "$info"; }
  plist CFBundleSupportedPlatforms array ""
  /usr/libexec/PlistBuddy -c "Add :CFBundleSupportedPlatforms:0 string $PLATFORM" "$info"
  plist DTPlatformName string "$SDK"
  plist DTPlatformVersion string "$(xcrun --sdk "$SDK" --show-sdk-version)"
  plist DTSDKName string "$SDK$(xcrun --sdk "$SDK" --show-sdk-version)"
  plist DTSDKBuild string "$(xcrun --sdk "$SDK" --show-sdk-build-version)"
  plist DTXcode string "$(xcodebuild -version | awk '/Xcode/{gsub(/\./,""); printf "%04d", $2}')"
  plist DTXcodeBuild string "$(xcodebuild -version | awk '/Build version/{print $3}')"
  plist DTCompiler string com.apple.compilers.llvm.clang.1_0
  plist BuildMachineOSBuild string "$(sw_vers -buildVersion)"
}
built "$app/Info.plist"

# The notification service extension (docs/10-push.md §5.1): the Swift
# class calling crates/enclave-nse, as an .appex in PlugIns.
nse=$app/PlugIns/EnclaveNSE.appex
swift_target=arm64-apple-ios16.0
[ "$SIM" = --simulator ] && swift_target=arm64-apple-ios16.0-simulator
mkdir -p "$nse"
xcrun --sdk "$SDK" swiftc -target "$swift_target" -O -parse-as-library -application-extension \
  -module-name EnclaveNSE "$ROOT/apps/ios/nse/NotificationService.swift" \
  -L "$ROOT/target/$TARGET/release" -lenclave_nse \
  -framework Foundation -framework Security -framework UserNotifications -framework CoreFoundation \
  -Xlinker -e -Xlinker _NSExtensionMain -o "$nse/EnclaveNSE"
sed -e "s/@VERSION@/${V%%-*}/" -e "s/@BUILD@/$BUILD/" "$ROOT/apps/ios/nse/Info.plist" > "$nse/Info.plist"
built "$nse/Info.plist"

# The entitlements a profile grants, to sign with.
entitlements() {
  security cms -D -i "$1" > "$work/$2.plist"
  /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' "$work/$2.plist" > "$work/$2-entitlements.plist"
  echo "$work/$2-entitlements.plist"
}

if [ -n "${IOS_SIGN_IDENTITY:-}" ] && [ -n "${IOS_PROFILE:-}" ] && [ "$SIM" != --simulator ]; then
  if [ -n "${IOS_NSE_PROFILE:-}" ]; then
    cp "$IOS_NSE_PROFILE" "$nse/embedded.mobileprovision"
    codesign --force --timestamp --sign "$IOS_SIGN_IDENTITY" --entitlements "$(entitlements "$IOS_NSE_PROFILE" nse)" "$nse"
  else
    echo "bundle: no IOS_NSE_PROFILE; the app ships without its notification extension"
    rm -rf "$app/PlugIns"
  fi
  cp "$IOS_PROFILE" "$app/embedded.mobileprovision"
  codesign --force --timestamp --sign "$IOS_SIGN_IDENTITY" --entitlements "$(entitlements "$IOS_PROFILE" app)" "$app"
  signed=yes
else
  codesign --force --sign - "$nse"
  codesign --force --sign - "$app"
  signed=no
fi
codesign --verify --deep --strict --verbose=2 "$app"

suffix=ios
[ "$SIM" = --simulator ] && suffix=ios-simulator
mkdir -p "$work/Payload"
cp -R "$app" "$work/Payload/"
ipa=$OUT/Enclave-$V-$suffix.ipa
rm -f "$ipa"
(cd "$work" && zip -qry "$ipa" Payload)
echo "bundle: $ipa (signed for the App Store: $signed)"

if [ "$signed" = yes ] && [ -n "${ASC_KEY_ID:-}" ] && [ -n "${ASC_ISSUER_ID:-}" ] && [ -n "${ASC_KEY_PATH:-}" ]; then
  mkdir -p "$HOME/.appstoreconnect/private_keys"
  cp "$ASC_KEY_PATH" "$HOME/.appstoreconnect/private_keys/AuthKey_$ASC_KEY_ID.p8"
  xcrun altool --upload-app -f "$ipa" -t ios --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
  echo "bundle: uploaded to TestFlight"
fi
