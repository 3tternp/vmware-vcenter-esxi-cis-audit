"""Generate application icons into assets/ (requires Pillow)."""
from pathlib import Path
from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "assets"
OUT.mkdir(exist_ok=True)
S = 1024  # draw large, downsample for smooth edges


def draw():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, S - 1, S - 1), radius=220, fill=(18, 52, 94, 255))
    # shield
    cx = S // 2
    shield = [(cx, 140), (840, 260), (840, 520), (cx, 880), (184, 520), (184, 260)]
    d.polygon(shield, fill=(255, 255, 255, 255))
    inner = [(cx, 220), (770, 310), (770, 505), (cx, 800), (254, 505), (254, 310)]
    d.polygon(inner, fill=(33, 150, 83, 255))
    # check mark
    d.line([(370, 500), (468, 600), (665, 395)], fill=(255, 255, 255, 255), width=70, joint="curve")
    for p in ((370, 500), (468, 600), (665, 395)):
        d.ellipse((p[0] - 35, p[1] - 35, p[0] + 35, p[1] + 35), fill=(255, 255, 255, 255))
    return img


img = draw()
img.resize((256, 256), Image.LANCZOS).save(OUT / "icon.png")
img.resize((64, 64), Image.LANCZOS).save(OUT / "icon_64.png")
img.save(OUT / "icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("wrote", sorted(p.name for p in OUT.iterdir()))
