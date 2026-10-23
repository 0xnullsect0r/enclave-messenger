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


# Creative assets (App Store Connect → Asset Library; optional): the
# product page header (21:9, 3840 x 1646), the search results image (3:2,
# 3840 x 2560) and a universal one for both (16:9, 5244 x 2950). Apple
# crops them on narrow screens, so what matters sits in the middle.
import io  # noqa: E402

import resvg_py  # noqa: E402

REG = str(fonts / "AtkinsonHyperlegibleNext-Regular.ttf")
PINE, MUTED = "#1D5646", "#585E59"


def seal(size):
    data = resvg_py.svg_to_bytes(svg_path=str(repo / "design/icon/enclave.svg"), width=size, height=size)
    return Image.open(io.BytesIO(bytes(data))).convert("RGBA")


def phone(name, height):
    shot = Image.open(phone_dir / f"{name}-light.png").convert("RGB")
    w = round(shot.width * height / shot.height)
    shot = shot.resize((w, height), Image.LANCZOS)
    r = round(height * 0.035)
    mask = Image.new("L", shot.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, w - 1, height - 1), r, fill=255)
    return shot, mask, r


def place(canvas, name, height, x, y):
    """A phone screen with its top-left corner at (x, y), cut off by the
    canvas edge like a device rising into view."""
    shot, mask, r = phone(name, height)
    canvas.paste(shot, (x, y), mask)
    ImageDraw.Draw(canvas).rounded_rectangle(
        (x - 4, y - 4, x + shot.width + 3, y + shot.height + 3), r + 4, outline=HAIR, width=max(4, height // 400))
    return shot.width


def centred(d, text, font, cx, y, fill):
    w = d.textlength(text, font=font)
    d.text((cx - w / 2, y), text, font=font, fill=fill)


def lockup(canvas, cx, top, seal_px, name_px, tag_px, tag):
    """The seal, the name and a line under it, centred on cx."""
    d = ImageDraw.Draw(canvas)
    s = seal(seal_px)
    canvas.paste(s, (round(cx - seal_px / 2), top), s)
    y = top + seal_px + round(name_px * 0.25)
    centred(d, "Enclave", ImageFont.truetype(SEMI, name_px), cx, y, PINE)
    y += round(name_px * 1.25)
    for line in tag:
        centred(d, line, ImageFont.truetype(REG, tag_px), cx, y, MUTED)
        y += round(tag_px * 1.3)


TAG = ["Private messages", "without a phone number"]

# Header, 21:9: the name in the middle, a phone either side rising from the
# bottom edge.
W, H = 3840, 1646
img = Image.new("RGB", (W, H), PAPER)
pw = phone("05-conversation-phone", 1800)[0].width
place(img, "05-conversation-phone", 1800, 260, 300)
place(img, "61-call-on-phone", 1800, W - 260 - pw, 300)
lockup(img, W // 2, 250, 360, 230, 96, TAG)
img.save(here / "header-21x9.png", optimize=True)

# Search results, 3:2: the line on the left, two phones on the right.
W, H = 3840, 2560
img = Image.new("RGB", (W, H), PAPER)
d = ImageDraw.Draw(img)
s = seal(300)
img.paste(s, (300, 520), s)
head = ImageFont.truetype(SEMI, 176)
for i, line in enumerate(["Private messages", "without a phone", "number"]):
    d.text((300, 900 + i * 210), line, font=head, fill=INK)
sub = ImageFont.truetype(REG, 92)
for i, line in enumerate(["End-to-end encrypted.", "Sent over Tor."]):
    d.text((304, 1600 + i * 124), line, font=sub, fill=MUTED)
pw = phone("13-list-phone", 1800)[0].width
place(img, "13-list-phone", 1800, W - 70 - 2 * pw - 90, 380)
place(img, "05-conversation-phone", 1800, W - 70 - pw, 380)
img.save(here / "search-3x2.png", optimize=True)

# Universal, 16:9: the name above three phones.
W, H = 5244, 2950
img = Image.new("RGB", (W, H), PAPER)
lockup(img, W // 2, 170, 340, 220, 100, ["Private messages without a phone number"])
gap = 120
pw = phone("13-list-phone", 2400)[0].width
x0 = (W - 3 * pw - 2 * gap) // 2
for i, (name, dy) in enumerate([("05-conversation-phone", 1260), ("13-list-phone", 1140), ("61-call-on-phone", 1260)]):
    place(img, name, 2400, x0 + i * (pw + gap), dy)
img.save(here / "universal-16x9.png", optimize=True)
print("creative ok")
