#!/usr/bin/env python3
"""Upload an .ipa to App Store Connect and wait for Apple's verdict on it
(ios-store-check.yml): the build's processing state, VALID or INVALID.
A refused build (ITMS-90111 and the like) is INVALID, and the reasons go
to the account's email; this exits 1 then, so a release is tagged only
once a build like it was accepted.

    ci/ios/verdict.py IPA VERSION BUILD

ASC_KEY_ID, ASC_ISSUER_ID and ASC_KEY_PATH name the App Store Connect API
key (the one TestFlight uploads use). Once Apple has its verdict the
build is expired, so TestFlight offers only the release's own builds. Only the standard library and
openssl: the token is an ES256 JWT signed with `openssl dgst`.
"""

import base64
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

API = "https://api.appstoreconnect.apple.com/v1"
BUNDLE_ID = "com.aricummings.enclave"
# Apple takes some minutes to process a build; an hour is ample.
WAIT_S = 60 * 60
POLL_S = 60


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def der_to_raw(der: bytes) -> bytes:
    """An ECDSA signature from openssl (DER: SEQUENCE of two INTEGERs) as
    JWT wants it: r and s, 32 bytes each."""
    if der[0] != 0x30:
        raise ValueError("not a DER signature")
    i = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    out = b""
    for _ in range(2):
        if der[i] != 0x02:
            raise ValueError("not a DER integer")
        n = der[i + 1]
        v = der[i + 2 : i + 2 + n].lstrip(b"\0")
        out += v.rjust(32, b"\0")
        i += 2 + n
    return out


def token(key_id: str, issuer: str, key_path: str) -> str:
    now = int(time.time())
    head = b64url(json.dumps({"alg": "ES256", "kid": key_id, "typ": "JWT"}).encode())
    body = b64url(
        json.dumps(
            {"iss": issuer, "iat": now, "exp": now + 15 * 60, "aud": "appstoreconnect-v1"}
        ).encode()
    )
    signing = f"{head}.{body}".encode()
    der = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key_path],
        input=signing,
        capture_output=True,
        check=True,
    ).stdout
    return f"{head}.{body}.{b64url(der_to_raw(der))}"


def get(path: str, query: dict, auth: str) -> dict:
    url = f"{API}/{path}?{urllib.parse.urlencode(query)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {auth}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def patch(path: str, body: dict, auth: str) -> None:
    req = urllib.request.Request(
        f"{API}/{path}",
        data=json.dumps(body).encode(),
        method="PATCH",
        headers={"Authorization": f"Bearer {auth}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60):
        pass


def expire(build_id: str, auth: str) -> None:
    """The check's build stops being offered to testers; a failure here
    leaves it listed and doesn't change the verdict."""
    try:
        patch(
            f"builds/{build_id}",
            {"data": {"type": "builds", "id": build_id, "attributes": {"expired": True}}},
            auth,
        )
        print("verdict: the check's build is expired in TestFlight")
    except Exception as e:  # noqa: BLE001 - only a warning
        print(f"verdict: couldn't expire the check's build: {e}")


def main() -> int:
    ipa, version, build = sys.argv[1:4]
    key_id = os.environ["ASC_KEY_ID"]
    issuer = os.environ["ASC_ISSUER_ID"]
    key_path = os.environ["ASC_KEY_PATH"]
    keys = os.path.expanduser("~/.appstoreconnect/private_keys")
    os.makedirs(keys, exist_ok=True)
    with open(key_path, "rb") as src, open(f"{keys}/AuthKey_{key_id}.p8", "wb") as dst:
        dst.write(src.read())
    # The upload must work here (in a release a refused upload only warns).
    up = subprocess.run(
        ["xcrun", "altool", "--upload-app", "-f", ipa, "-t", "ios",
         "--apiKey", key_id, "--apiIssuer", issuer],
        capture_output=True,
        text=True,
    )
    print(up.stdout, up.stderr, sep="\n")
    if up.returncode != 0:
        print(f"verdict: the upload failed ({up.returncode})")
        return 1
    apps = get("apps", {"filter[bundleId]": BUNDLE_ID}, token(key_id, issuer, key_path))
    if not apps["data"]:
        print(f"verdict: no app {BUNDLE_ID} in App Store Connect")
        return 1
    app = apps["data"][0]["id"]
    deadline = time.time() + WAIT_S
    state = "not listed yet"
    while time.time() < deadline:
        found = get(
            "builds",
            {
                "filter[app]": app,
                "filter[version]": build,
                "filter[preReleaseVersion.version]": version,
                "fields[builds]": "version,processingState,uploadedDate",
            },
            token(key_id, issuer, key_path),
        )["data"]
        if found:
            state = found[0]["attributes"]["processingState"]
            print(f"verdict: {version} ({build}): {state}", flush=True)
            if state in ("VALID", "INVALID", "FAILED"):
                expire(found[0]["id"], token(key_id, issuer, key_path))
            if state == "VALID":
                return 0
            if state in ("INVALID", "FAILED"):
                print("verdict: Apple refused the build; the reasons are in the account's email")
                return 1
        else:
            print(f"verdict: {version} ({build}) {state}", flush=True)
        time.sleep(POLL_S)
    print(f"verdict: no verdict in {WAIT_S // 60} minutes (last: {state})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
