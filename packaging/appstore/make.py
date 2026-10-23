"""App Store screenshots for Enclave: a headline over the app, from 3x
phone and 2x wide renders of enclave-shots (README.md says how).

    ENCLAVE_SHOT_SCALE=3 ENCLAVE_SHOTS=13-list-phone,... enclave-shots PHONE_DIR
    ENCLAVE_SHOT_SCALE=2 ENCLAVE_SHOTS=05-conversation,... enclave-shots WIDE_DIR
    python3 make.py REPO PHONE_DIR WIDE_DIR

Needs Pillow. Writes, next to this file, the sizes App Store Connect
takes: iphone-6.3/ (1206 x 2622, iPhone with Dynamic Island, medium: the
required one), iphone-6.9/ (1320 x 2868, the large one) and ipad-13/
(2752 x 2064).
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

repo, phone_dir, wide_dir = (Path(a) for a in sys.argv[1:4])
here = Path(__file__).resolve().parent
fonts = repo / "crates/enclave-app/ui/fonts"
SEMI = str(fonts / "AtkinsonHyperlegibleNext-SemiBold.ttf")
PAPER, INK, HAIR = "#F6F3EC", "#1C1F1D", "#CFC8BA"

PHONE = [
    ("13-list-phone", "No phone number. No email."),
    ("05-conversation-phone", "Hides who you talk to"),
    ("08-check-code-phone", "Check it's really them"),
    ("14-group-phone", "Groups, end to end"),
    ("61-call-on-phone", "Voice and video calls"),
    ("11-privacy-phone", "Choose how private"),
]
WIDE = [
    ("05-conversation", "Hides who you talk to"),
    ("14-group", "Groups, end to end"),
    ("08-check-code", "Check it's really them"),
    ("61-call-on", "Voice and video calls"),
    ("11-privacy", "Choose how private"),
]


def frame(canvas_size, shot_path, line, font_size, radius, out, shot_width=None):
    cw, ch = canvas_size
    canvas = Image.new("RGB", canvas_size, PAPER)
    d = ImageDraw.Draw(canvas)
    font = ImageFont.truetype(SEMI, font_size)
    shot = Image.open(shot_path).convert("RGB")
    if shot_width and shot_width != shot.width:
        shot = shot.resize((shot_width, round(shot.height * shot_width / shot.width)), Image.LANCZOS)
    margin = (cw - shot.width) // 2
    top = ch - shot.height - margin
    assert top > font_size * 2, (shot_path, top)
    w = d.textlength(line, font=font)
    assert w <= cw - 2 * margin, (line, w)
    d.text(((cw - w) / 2, (top - font_size) / 2 - font_size * 0.15), line, font=font, fill=INK)
    mask = Image.new("L", shot.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, shot.width - 1, shot.height - 1), radius, fill=255)
    canvas.paste(shot, (margin, top), mask)
    d.rounded_rectangle(
        (margin - 3, top - 3, margin + shot.width + 2, top + shot.height + 2),
        radius + 3,
        outline=HAIR,
        width=4,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(out, optimize=True)


for n, (name, line) in enumerate(PHONE, 1):
    frame((1320, 2868), phone_dir / f"{name}-light.png", line, 84, 66,
          here / "iphone-6.9" / f"{n}-{name.removesuffix('-phone')}.png")
    frame((1206, 2622), phone_dir / f"{name}-light.png", line, 72, 60,
          here / "iphone-6.3" / f"{n}-{name.removesuffix('-phone')}.png", shot_width=1072)
for n, (name, line) in enumerate(WIDE, 1):
    frame((2752, 2064), wide_dir / f"{name}-light.png", line, 104, 36,
          here / "ipad-13" / f"{n}-{name}.png")
print("ok")
