#!/usr/bin/env python3
"""Generate the WebSSH app icon (frontend/appicon.png) and favicon.

Design language borrowed from the best macOS terminal icons (Termius,
Termix, ServerCat): a deep charcoal squircle, one bold white glyph, and a
single accent colour. No extra badges, no busy glows.

Run: python3 tools/makeicon.py && make package
"""
import os
from PIL import Image, ImageDraw, ImageFilter

SS = 4                      # supersampling factor
def sc(v): return int(round(v * SS))
S = 1024 * SS

mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle(
    (sc(100), sc(100), sc(924), sc(924)), radius=sc(185), fill=255)

# ---- background: near-black charcoal with a hint of centre light ----
grad = Image.new("RGB", (1, 1024))
top, bot = (19, 23, 27), (8, 10, 11)
for y in range(1024):
    t = y / 1023
    grad.putpixel((0, y), tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3)))
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
img.paste(grad.resize((S, S)), (0, 0), mask)

rad = Image.eval(Image.radial_gradient("L").resize((S, S)), lambda v: 255 - v)
glow = Image.new("RGB", (S, S), (42, 52, 60))
glow.putalpha(rad.point(lambda v: int(v * 0.26)))
glow.putalpha(Image.composite(glow.split()[3], Image.new("L", (S, S), 0), mask))
img.alpha_composite(glow)

d = ImageDraw.Draw(img)
d.rounded_rectangle((sc(100), sc(100), sc(924), sc(924)), radius=sc(185),
                    outline=(255, 255, 255, 38), width=sc(2))

def chevron(draw, pts, width, colour):
    draw.line(pts, fill=colour, width=width, joint="curve")
    for p in (pts[0], pts[2]):
        r = width // 2
        draw.ellipse((p[0]-r, p[1]-r, p[0]+r, p[1]+r), fill=colour)

# Prompt chevron and cursor share one optical centre.
pts = [(sc(275), sc(345)), (sc(477), sc(512)), (sc(275), sc(679))]
CW = sc(60)
cur = (sc(529), sc(631), sc(747), sc(685))
cur_r = sc(27)

# drop shadow for depth
sh = Image.new("RGBA", (S, S), (0, 0, 0, 0))
sd = ImageDraw.Draw(sh)
chevron(sd, [(x, y + sc(9)) for x, y in pts], CW, (0, 0, 0, 140))
sd.rounded_rectangle((cur[0], cur[1] + sc(9), cur[2], cur[3] + sc(9)),
                     radius=cur_r, fill=(0, 0, 0, 140))
sh = sh.filter(ImageFilter.GaussianBlur(sc(22)))
sh.putalpha(Image.composite(sh.split()[3], Image.new("L", (S, S), 0), mask))
img.alpha_composite(sh)

# chevron: subtle top-to-bottom white gradient
chev = Image.new("RGBA", (S, S), (0, 0, 0, 0))
chevron(ImageDraw.Draw(chev), pts, CW, (255, 255, 255, 255))
g = Image.new("RGB", (1, 1024))
for y in range(1024):
    v = int(255 - 22 * (y / 1023))
    g.putpixel((0, y), (v, v, v))
gm = Image.new("L", (S, S), 0)
chevron(ImageDraw.Draw(gm), pts, CW, 255)
chev.paste(g.resize((S, S)), (0, 0), gm)
img.alpha_composite(chev)

# cursor: Abernathy blue gradient + tight glow
cglow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(cglow).rounded_rectangle(cur, radius=cur_r, fill=(16, 147, 245, 70))
img.alpha_composite(cglow.filter(ImageFilter.GaussianBlur(sc(26))))

cb = Image.new("RGBA", (S, S), (0, 0, 0, 0))
g2 = Image.new("RGB", (1, 1024))
for y in range(1024):
    t = y / 1023
    g2.putpixel((0, y), (int(48 - 18*t), int(176 - 48*t), int(255 - 22*t)))
cm = Image.new("L", (S, S), 0)
ImageDraw.Draw(cm).rounded_rectangle(cur, radius=cur_r, fill=255)
cb.paste(g2.resize((S, S)), (0, 0), cm)
img.alpha_composite(cb)

# ---- output ----
here = os.path.dirname(os.path.abspath(__file__))
fe = os.path.join(here, "..", "frontend")
out = img.resize((1024, 1024), Image.LANCZOS)
out.save(os.path.join(fe, "appicon.png"))
out.resize((256, 256), Image.LANCZOS).save(os.path.join(fe, "favicon.png"))
print("wrote frontend/appicon.png and frontend/favicon.png")
