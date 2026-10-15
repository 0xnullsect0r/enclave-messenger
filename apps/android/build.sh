#!/usr/bin/env bash
# Build Enclave for Android (release.yml `android`): the native library
# for arm64-v8a and x86_64 (cargo-ndk, nym/ workspace), then the APKs and
# the app bundle (Gradle), named for the release in OUT.
#
#   apps/android/build.sh OUT
#
# Needs ANDROID_HOME (SDK with platform 36 and build-tools), ANDROID_NDK_HOME
# (r28), cargo-ndk, a JDK 17+, and the targets aarch64-linux-android and
# x86_64-linux-android. The release key comes from ANDROID_KEYSTORE_FILE,
# ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS and ANDROID_KEY_PASSWORD;
# without them a key is made for this run (it installs, but can't update a
# release).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
APP=$ROOT/apps/android
V=${ENCLAVE_VERSION:-$(cd "$ROOT" && cargo xtask version)}
export ENCLAVE_VERSION=$V
ENCLAVE_VERSION_CODE=$(cd "$ROOT" && cargo xtask version --android-code "$V")
export ENCLAVE_VERSION_CODE

# Gradle, at a fixed version and checksum (no wrapper jar in the repository).
GRADLE_VERSION=8.14.3
GRADLE_SHA256=bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531
GRADLE_DIR=$ROOT/target/gradle-$GRADLE_VERSION
if [ ! -x "$GRADLE_DIR/bin/gradle" ]; then
  mkdir -p "$ROOT/target"
  zip=$ROOT/target/gradle-$GRADLE_VERSION-bin.zip
  curl -fsSL "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" -o "$zip"
  echo "$GRADLE_SHA256  $zip" | sha256sum -c -
  (cd "$ROOT/target" && unzip -q -o "$zip")
fi

# Slint's Android backend compiles a little Java against the platform.
export ANDROID_JAR=${ANDROID_JAR:-$ANDROID_HOME/platforms/android-36/android.jar}

# The native library, reproducibly (paths remapped, as `cargo xtask dist`).
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
export SOURCE_DATE_EPOCH=$epoch
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$ROOT=/src"
(cd "$ROOT/nym" && cargo ndk --platform 28 -t arm64-v8a -t x86_64 \
  -o "$APP/app/src/main/jniLibs" build --release --locked -p enclave-mobile)

# Snowflake and WebTunnel: lyrebird's clients as liblyrebird.so next to
# the app's library, which loads it (ci/tor/lyrebird.sh archive).
ndk_bin=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64/bin
for abi in arm64-v8a:aarch64-linux-android x86_64:x86_64-linux-android; do
  CC=$ndk_bin/${abi#*:}28-clang "$ROOT/ci/tor/lyrebird.sh" archive "$APP/app/src/main/jniLibs/${abi%%:*}" "${abi#*:}"
done

if [ -z "${ANDROID_KEYSTORE_FILE:-}" ]; then
  mkdir -p "$APP/app/build"
  rm -f "$APP/app/build/run.keystore"
  keytool -genkeypair -keystore "$APP/app/build/run.keystore" -storepass enclave-run -keypass enclave-run \
    -alias enclave-run -keyalg EC -groupname secp384r1 -validity 30 -dname "CN=Enclave dry run" > /dev/null
fi

# The APKs are the build with no Google code (fdroid); the app bundle for
# Google Play adds Google's push as a choice (play).
(cd "$APP" && "$GRADLE_DIR/bin/gradle" --no-daemon --console=plain assembleFdroidRelease bundlePlayRelease)
apks=$APP/app/build/outputs/apk/fdroid/release
cp "$apks/app-fdroid-universal-release.apk" "$OUT/Enclave-$V-android.apk"
cp "$apks/app-fdroid-arm64-v8a-release.apk" "$OUT/Enclave-$V-android-arm64-v8a.apk"
cp "$apks/app-fdroid-x86_64-release.apk" "$OUT/Enclave-$V-android-x86_64.apk"
cp "$APP/app/build/outputs/bundle/playRelease/app-play-release.aab" "$OUT/Enclave-$V.aab"
ls -la "$OUT"
