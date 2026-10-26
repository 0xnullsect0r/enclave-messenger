#!/usr/bin/env python3
"""The per-processor APKs are the universal APK cut down, and nothing else.

    ci/android/apk-check.py BUILD_TOOLS UNIVERSAL.apk SPLIT.apk...

The release's emulator check installs and starts only the universal APK;
the APKs for one processor type (arm64-v8a, x86_64) are made by the same
Gradle build with an ABI split. Each must say what the universal says (its
badging: package, version code and name, SDK levels, permissions,
activities, services), be signed with the same certificate, hold the
universal's own copy of each file it holds, have every native library the
universal has for its processor type, and pass the same 16 KB alignment
check. Anything else is printed and the check fails.
"""

import re
import subprocess
import sys
import zipfile


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def badging(tools, apk):
    """aapt2's badging without the lines that name processor types."""
    lines = run(f"{tools}/aapt2", "dump", "badging", apk).splitlines()
    return [l for l in lines if not l.startswith(("native-code:", "alt-native-code:"))]


def certs(tools, apk):
    out = run(f"{tools}/apksigner", "verify", "--print-certs", apk)
    return sorted(l for l in out.splitlines() if "SHA-256 digest" in l)


def files(apk):
    """Each entry's CRC, size and whether it is stored, signatures left out."""
    with zipfile.ZipFile(apk) as z:
        return {
            i.filename: (i.CRC, i.file_size, i.compress_type)
            for i in z.infolist()
            if not i.filename.startswith("META-INF/")
        }


def main():
    tools, universal, splits = sys.argv[1], sys.argv[2], sys.argv[3:]
    if not splits:
        sys.exit("no per-processor APKs given")
    ub, uc, uf = badging(tools, universal), certs(tools, universal), files(universal)
    if not uc:
        sys.exit(f"{universal}: no signing certificate")
    bad = []
    for apk in splits:
        sf = files(apk)
        abis = sorted({m.group(1) for n in sf if (m := re.match(r"lib/([^/]+)/", n))})
        print(f"{apk}: {len(sf)} files, native code for {', '.join(abis) or 'nothing'}")
        if len(abis) != 1:
            bad.append(f"{apk}: native code for {abis}, not one processor type")
        sb = badging(tools, apk)
        for l in sorted(set(ub) ^ set(sb)):
            side = "only in the universal" if l in ub else "only here"
            bad.append(f"{apk}: badging {side}: {l}")
        if certs(tools, apk) != uc:
            bad.append(f"{apk}: signed with another certificate: {certs(tools, apk)} against {uc}")
        for name, entry in sorted(sf.items()):
            if name not in uf:
                bad.append(f"{apk}: {name} is not in the universal APK")
            elif entry != uf[name]:
                bad.append(f"{apk}: {name} differs from the universal's: {entry} against {uf[name]}")
        for abi in abis:
            want = sorted(n for n in uf if n.startswith(f"lib/{abi}/"))
            missing = [n for n in want if n not in sf]
            bad.extend(f"{apk}: lacks {n}" for n in missing)
        extra = sorted(n for n in uf if not n.startswith("lib/") and n not in sf)
        bad.extend(f"{apk}: lacks {n}" for n in extra)
        r = subprocess.run([f"{tools}/zipalign", "-c", "-P", "16", "4", apk], capture_output=True, text=True)
        if r.returncode != 0:
            bad.append(f"{apk}: not 16 KB aligned: {r.stdout[-400:]}{r.stderr[-400:]}")
    for b in bad:
        print(b)
    if bad:
        sys.exit(f"{len(bad)} differences")
    print("every per-processor APK is the universal APK cut down")


if __name__ == "__main__":
    main()
