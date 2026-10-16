"""Score a call's audio with PESQ (ITU-T P.862.2, wideband): the nightly
job's oracle for `call_quality_under_loss` and the codec alone
(docs/11-calls.md §10). Test-only; nothing here ships.

usage: pesq.py DIR   (reference.wav and loss-00/01/05/10.wav, 48 kHz mono)
"""
import sys

import numpy as np
from pesq import pesq
from scipy.io import wavfile
from scipy.signal import resample_poly

# Least score at each loss rate, end to end (echo canceller, noise
# suppression and gain control included, which PESQ marks down).
FLOOR = {"loss-00.wav": 3.5, "loss-01.wav": 3.5, "loss-05.wav": 3.0, "loss-10.wav": 2.7}


def load(path):
    rate, x = wavfile.read(path)
    x = x.astype(np.float64)
    return resample_poly(x, 1, 3) if rate == 48000 else x


def main(d):
    ref = load(f"{d}/reference.wav")
    bad = False
    for name, floor in FLOOR.items():
        deg = load(f"{d}/{name}")
        k = min(len(ref), len(deg))
        score = pesq(16000, ref[:k], deg[:k], "wb")
        ok = score >= floor
        bad |= not ok
        print(f"{name}: PESQ {score:.2f} (at least {floor}) {'ok' if ok else 'TOO LOW'}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main(sys.argv[1])
