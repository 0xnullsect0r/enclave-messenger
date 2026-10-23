#!/usr/bin/env bash
# Send a release's Android app bundle to Google Play (release.yml `play`):
# one Play Developer API edit uploads Enclave-VERSION.aab and releases it on
# a track, PLAY_TRACK (internal by default: testers get it within minutes;
# promote it in Play Console). PLAY_SERVICE_ACCOUNT_JSON is the JSON key of
# a Google Cloud service account invited in Play Console (Users and
# permissions) with the right to release to testing tracks (and production,
# for PLAY_TRACK=production). Google takes an app's first bundle only by
# hand in Play Console; this sends every one after it. While the app has
# never been rolled out, Google keeps API releases as drafts, which this
# says. Without the key it warns and does nothing.
#
#   ci/release/play.sh VERSION DIST
set -euo pipefail
V=$1 DIST=$2
PKG=com.aricummings.enclave
TRACK=${PLAY_TRACK:-internal}
aab=$DIST/Enclave-$V.aab
test -f "$aab"
if [ -z "${PLAY_SERVICE_ACCOUNT_JSON:-}" ]; then
  echo "::warning::PLAY_SERVICE_ACCOUNT_JSON is empty: Enclave-$V.aab is in the release but wasn't sent to Google Play"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077
printf '%s' "$PLAY_SERVICE_ACCOUNT_JSON" > "$work/key.json"
get() { python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
get private_key < "$work/key.json" > "$work/key.pem"
email=$(get client_email < "$work/key.json")

# An OAuth token for the service account: a JWT it signs (RS256), traded
# at Google's token endpoint.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
jwt=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url).$(printf \
  '{"iss":"%s","scope":"https://www.googleapis.com/auth/androidpublisher","aud":"https://oauth2.googleapis.com/token","iat":%d,"exp":%d}' \
  "$email" "$now" $((now + 3600)) | b64url)
jwt=$jwt.$(printf '%s' "$jwt" | openssl dgst -sha256 -sign "$work/key.pem" | b64url)
token=$(curl -fsS https://oauth2.googleapis.com/token \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  --data-urlencode "assertion=$jwt" | get access_token)
echo "::add-mask::$token"
printf 'Authorization: Bearer %s\n' "$token" > "$work/auth"

# api METHOD URL [curl arguments]: the reply on stdout; on an HTTP error,
# the reply on stderr and a failure.
api() {
  local code
  code=$(curl -sS -X "$1" -H @"$work/auth" -o "$work/reply" -w '%{http_code}' "${@:2}")
  case $code in
    2??) cat "$work/reply" ;;
    *) echo "play: $1 ${2%%\?*}: HTTP $code" >&2; cat "$work/reply" >&2; echo >&2; return 1 ;;
  esac
}

base=https://androidpublisher.googleapis.com/androidpublisher/v3/applications/$PKG/edits
edit=$(api POST "$base" | get id)
echo "play: uploading Enclave-$V.aab ($(du -h "$aab" | cut -f1))"
code=$(api POST "https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/$PKG/edits/$edit/bundles?uploadType=media" \
  --max-time 1800 -H 'Content-Type: application/octet-stream' --data-binary @"$aab" | get versionCode)
echo "play: version code $code"

release() {
  printf '{"track":"%s","releases":[{"name":"%s","versionCodes":["%s"],"status":"%s"}]}' "$TRACK" "$V" "$code" "$1" \
    | api PUT "$base/$edit/tracks/$TRACK" -H 'Content-Type: application/json' --data-binary @- > /dev/null
}
status=completed
if ! release completed 2> "$work/err"; then
  if grep -qi 'draft app' "$work/err"; then
    status=draft
    release draft
  else
    cat "$work/err" >&2
    exit 1
  fi
fi

# Google refuses to send some edits for review on its own (after a
# rejection, say); those are committed and sent from Play Console.
if ! api POST "$base/$edit:commit" > /dev/null 2> "$work/err"; then
  grep -q changesNotSentForReview "$work/err" || { cat "$work/err" >&2; exit 1; }
  api POST "$base/$edit:commit?changesNotSentForReview=true" > /dev/null
  echo "::warning::Google Play wants this release sent for review from Play Console (Publishing overview)"
fi
if [ "$status" = draft ]; then
  echo "::warning::Google Play keeps $V as a draft on the $TRACK track until the app's first rollout: roll it out in Play Console (Testing → Internal testing)"
else
  echo "play: $V (version code $code) is released on the $TRACK track"
fi
