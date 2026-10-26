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
# without the extension ("New message" only). IOS_BROADCAST_PROFILE (for
# com.aricummings.enclave.broadcast, with the same app group) adds the
# broadcast upload extension that shares the screen in a video call;
# without it, Share screen says it isn't set up in this build. Without them the app is
# signed ad hoc, with the extension,
# which a sideloading tool (AltStore, SideStore) re-signs with its user's
# Apple ID, and which the simulator runs. With ASC_KEY_ID, ASC_ISSUER_ID and
# ASC_KEY_PATH (an App Store Connect API key) a signed .ipa is uploaded to
# TestFlight; App Store Connect takes only builds made with the iOS 26 SDK
# (Xcode 26) or later. IOS_EXPORT_COMPLIANCE_CODE is the key App Store
# Connect gives the app's approved encryption documentation (App
# Information → App Encryption Documentation); without it every build
# asks the export compliance question again, and an app that has
# documentation refuses the upload.
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
# The build number: the Android version code, unless a check build gives
# its own (ios-store-check.yml: below the release's, so the release
# still uploads after it).
BUILD=${IOS_BUILD_NUMBER:-$(cd "$ROOT" && cargo xtask version --android-code "$V")}
export IPHONEOS_DEPLOYMENT_TARGET=16.0
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
export SOURCE_DATE_EPOCH=$epoch
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$ROOT=/src"
# The media process as WebAssembly, run in the app's interpreter sandbox
# (crates/enclave-wasmbox; docs/15-client.md §1.3).
(cd "$ROOT" && cargo build --release --locked --target wasm32-wasip1 -p enclave-mediad --bin enclave-mediad)
export ENCLAVE_MEDIAD_WASM=$ROOT/target/wasm32-wasip1/release/enclave-mediad.wasm

# Snowflake and WebTunnel on devices: lyrebird's clients linked into the
# program (ci/tor/lyrebird.sh archive); the simulator build goes without.
if [ "$SIM" != --simulator ]; then
  ios_sdk=$(xcrun --sdk iphoneos --show-sdk-path)
  export ENCLAVE_LYREBIRD_LIB=$ROOT/nym/target/$TARGET/lyrebird
  CC=$(xcrun --sdk iphoneos -f clang) \
    CGO_CFLAGS="-isysroot $ios_sdk -arch arm64 -miphoneos-version-min=16.0" \
    CGO_LDFLAGS="-isysroot $ios_sdk -arch arm64 -miphoneos-version-min=16.0" \
    "$ROOT/ci/tor/lyrebird.sh" archive "$ENCLAVE_LYREBIRD_LIB" "$TARGET"
fi
(cd "$ROOT/nym" && cargo build --release --locked --target "$TARGET" -p enclave-mobile --bin enclave-ios)
(cd "$ROOT" && cargo build --release --locked --target "$TARGET" -p enclave-nse)

work=$ROOT/nym/target/$TARGET/release/ios
app=$work/Enclave.app
rm -rf "$work" && mkdir -p "$app"
cp "$ROOT/nym/target/$TARGET/release/enclave-ios" "$app/Enclave"
sed -e "s/@VERSION@/${V%%-*}/" -e "s/@BUILD@/$BUILD/" "$ROOT/apps/ios/Info.plist" > "$app/Info.plist"
if [ -n "${IOS_EXPORT_COMPLIANCE_CODE:-}" ]; then
  /usr/libexec/PlistBuddy -c "Add :ITSEncryptionExportComplianceCode string $IOS_EXPORT_COMPLIANCE_CODE" "$app/Info.plist"
fi
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

# What Xcode records about the build, all of it: App Store processing
# reads these to tell which Xcode and SDK made the app, and refuses one it
# can't place as "ITMS-90111: Unsupported SDK or Xcode version". 0.1.3
# (Xcode 27.1) and 0.1.4 (the 27.2 RC, the newest Apple lists) were
# refused so; both lacked DTPlatformBuild, which Xcode writes.
# ios-store-check.yml uploads a build and waits for Apple's verdict, so a
# release is tagged only once one is accepted.
built() {
  local info=$1
  plist() { /usr/libexec/PlistBuddy -c "Add :$1 $2 $3" "$info"; }
  plist CFBundleSupportedPlatforms array ""
  /usr/libexec/PlistBuddy -c "Add :CFBundleSupportedPlatforms:0 string $PLATFORM" "$info"
  plist DTPlatformName string "$SDK"
  plist DTPlatformVersion string "$(xcrun --sdk "$SDK" --show-sdk-version)"
  plist DTSDKName string "$SDK$(xcrun --sdk "$SDK" --show-sdk-version)"
  plist DTSDKBuild string "$(xcrun --sdk "$SDK" --show-sdk-build-version)"
  # The platform's build is the SDK's (as Xcode writes it).
  plist DTPlatformBuild string "$(xcrun --sdk "$SDK" --show-sdk-build-version)"
  # 16.4 → 1640, 26.0.1 → 2601.
  plist DTXcode string "$(xcodebuild -version | awk '/^Xcode/{split($2, v, "."); printf "%02d%d%d", v[1], v[2], v[3]}')"
  plist DTXcodeBuild string "$(xcodebuild -version | awk '/Build version/{print $3}')"
  plist DTCompiler string com.apple.compilers.llvm.clang.1_0
  plist BuildMachineOSBuild string "$(sw_vers -buildVersion)"
}
built "$app/Info.plist"
# The privacy manifest: required-reason APIs and the data App Privacy lists.
cp "$ROOT/apps/ios/PrivacyInfo.xcprivacy" "$app/"

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
cp "$ROOT/apps/ios/nse/PrivacyInfo.xcprivacy" "$nse/"

# The broadcast upload extension (docs/11-calls.md §8.3): sharing the
# screen in a video call; Swift only.
bc=$app/PlugIns/EnclaveBroadcast.appex
mkdir -p "$bc"
xcrun --sdk "$SDK" swiftc -target "$swift_target" -O -parse-as-library -application-extension \
  -module-name EnclaveBroadcast "$ROOT/apps/ios/broadcast/SampleHandler.swift" \
  -framework Foundation -framework ReplayKit -framework CoreImage -framework CoreMedia -framework CoreVideo \
  -Xlinker -e -Xlinker _NSExtensionMain -o "$bc/EnclaveBroadcast"
sed -e "s/@VERSION@/${V%%-*}/" -e "s/@BUILD@/$BUILD/" "$ROOT/apps/ios/broadcast/Info.plist" > "$bc/Info.plist"
built "$bc/Info.plist"

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
    rm -rf "$nse"
  fi
  if [ -n "${IOS_BROADCAST_PROFILE:-}" ]; then
    cp "$IOS_BROADCAST_PROFILE" "$bc/embedded.mobileprovision"
    codesign --force --timestamp --sign "$IOS_SIGN_IDENTITY" --entitlements "$(entitlements "$IOS_BROADCAST_PROFILE" broadcast)" "$bc"
  else
    echo "bundle: no IOS_BROADCAST_PROFILE; the app ships without screen sharing"
    rm -rf "$bc"
  fi
  cp "$IOS_PROFILE" "$app/embedded.mobileprovision"
  codesign --force --timestamp --sign "$IOS_SIGN_IDENTITY" --entitlements "$(entitlements "$IOS_PROFILE" app)" "$app"
  signed=yes
else
  codesign --force --sign - "$nse"
  codesign --force --sign - "$bc"
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
  # The .ipa is a release file either way; a refused upload (no App Store
  # Connect record yet, a build number already used) shouldn't stop the
  # release.
  if xcrun altool --upload-app -f "$ipa" -t ios --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"; then
    echo "bundle: uploaded to TestFlight"
  else
    echo "::warning::the TestFlight upload failed; the .ipa is still in the release"
  fi
fi
