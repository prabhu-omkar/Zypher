"""
Generate the Zypher application icon.

Drawn rather than exported from a design file so the repository carries the
source of the icon and not just the artefact — regenerating it after a brand
change is running this script.

The mark in the interface is a Z inside a shield. At 16px a shield outline
collapses into grey mush, so the icon drops the shield and keeps the Z, which is
the half that stays legible. The two read as the same mark because the Z
geometry is identical.
"""
import os

from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zypher.ico")

# The interface's --solid and --on-solid, so the icon belongs to the same
# palette as the application it launches.
INK = (22, 24, 29, 255)
WHITE = (255, 255, 255, 255)

# Windows picks the nearest size; supplying all of them avoids the blurry
# upscale you get from a single 256px source in a 16px tray slot.
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def rounded_square(size: int) -> Image.Image:
    """The dark tile the mark sits on."""
    scale = 8 if size < 64 else 4          # supersample, then downsample
    s = size * scale
    tile = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(tile)
    draw.rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.22), fill=INK)
    return tile, draw, s, scale


def draw_z(draw: ImageDraw.ImageDraw, s: int) -> None:
    """
    Three strokes rather than a font glyph.

    A drawn Z keeps an even stroke weight at every size and does not depend on
    a font being installed wherever this is built.
    """
    width = max(2, int(s * 0.115))
    left, right = s * 0.285, s * 0.715
    top, bottom = s * 0.325, s * 0.675

    # Squared caps on the bars, so the corners meet cleanly at small sizes.
    draw.line([(left, top), (right, top)], fill=WHITE, width=width)
    draw.line([(right, top), (left, bottom)], fill=WHITE, width=width)
    draw.line([(left, bottom), (right, bottom)], fill=WHITE, width=width)

    # The joins are drawn as squares rather than round caps: a round cap on a
    # 16px mark reads as a blob at the corner.
    half = width // 2
    for x, y in ((left, top), (right, top), (left, bottom), (right, bottom)):
        draw.rectangle([x - half, y - half, x + half, y + half], fill=WHITE)


def build() -> None:
    frames = []
    for size in SIZES:
        tile, draw, s, _ = rounded_square(size)
        draw_z(draw, s)
        frames.append(tile.resize((size, size), Image.LANCZOS))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    frames[-1].save(OUT, format="ICO", sizes=[(f.width, f.height) for f in frames])
    print(f"wrote {OUT} with {len(frames)} sizes: "
          f"{', '.join(str(f.width) for f in frames)}")


if __name__ == "__main__":
    build()
