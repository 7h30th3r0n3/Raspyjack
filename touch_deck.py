#!/usr/bin/env python3
"""
touch_deck.py — on-screen touch control deck for the Waveshare 3.5" (35a).

Single source of truth for the touch control layout so the display driver
(LCD_1in44) and the touch daemon (raspyjack_touch) never disagree:

  * button_rects(w, h)  -> {name: (x0, y0, x1, y1)} in DECK-LOCAL coordinates
  * get_deck_image(w,h) -> cached PIL.Image of the rendered deck
  * hit_test(name_rects, lx, ly) -> button name at deck-local (lx, ly) or None

Buttons emit the same names RaspyJack's Web UI sends over rj_input.sock:
  UP, DOWN, LEFT, RIGHT, OK, KEY1, KEY2, KEY3
"""

from PIL import Image, ImageDraw, ImageFont

# Colours (match the Web UI "Control Deck" feel: teal d-pad, green OK, purple keys)
_BG        = (11, 15, 26)
_DIVIDER   = (34, 46, 66)
_DPAD_FILL = (16, 35, 58)
_DPAD_EDGE = (20, 184, 166)
_ARROW     = (52, 211, 153)
_OK_FILL   = (15, 157, 88)
_KEY_FILL  = (75, 42, 122)
_KEY_EDGE  = (139, 92, 246)
_LABEL     = (255, 255, 255)

_BUTTONS = ("UP", "DOWN", "LEFT", "RIGHT", "OK", "KEY1", "KEY2", "KEY3")


def button_rects(w, h):
    """Compute deck-local button rectangles, laid out to align cleanly.

    Top: a 3x3 D-pad cross (UP / LEFT-OK-RIGHT / DOWN).
    Bottom: KEY1 / KEY2 / KEY3 as evenly spaced full-width buttons.
    """
    pad = max(6, round(w * 0.05))
    cell = (w - 2 * pad) / 3.0

    def col(i):
        return pad + i * cell

    dpad_top = pad
    rows = [dpad_top + j * cell for j in range(3)]

    def cellrect(ci, ri):
        x0 = col(ci); y0 = rows[ri]
        return (round(x0), round(y0), round(x0 + cell), round(y0 + cell))

    rects = {
        "UP":    cellrect(1, 0),
        "LEFT":  cellrect(0, 1),
        "OK":    cellrect(1, 1),
        "RIGHT": cellrect(2, 1),
        "DOWN":  cellrect(1, 2),
    }

    # Keys fill the space below the d-pad, evenly spaced.
    keys_top = round(dpad_top + 3 * cell + pad)
    gap = pad
    avail = h - keys_top - pad
    kh = (avail - 2 * gap) / 3.0
    for i, name in enumerate(("KEY1", "KEY2", "KEY3")):
        y0 = round(keys_top + i * (kh + gap))
        rects[name] = (pad, y0, w - pad, round(y0 + kh))
    return rects


def _font(size):
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _rounded(d, rect, radius, fill=None, outline=None, width=1):
    try:
        d.rounded_rectangle(rect, radius=radius, fill=fill, outline=outline, width=width)
    except Exception:
        d.rectangle(rect, fill=fill, outline=outline, width=width)


def _centered(d, rect, text, font):
    x0, y0, x1, y1 = rect
    try:
        bb = d.textbbox((0, 0), text, font=font)
        tw, th = bb[2] - bb[0], bb[3] - bb[1]
        d.text((x0 + (x1 - x0 - tw) / 2 - bb[0], y0 + (y1 - y0 - th) / 2 - bb[1]),
               text, font=font, fill=_LABEL)
    except Exception:
        d.text((x0 + 6, y0 + 6), text, font=font, fill=_LABEL)


def _arrow(d, rect, direction):
    x0, y0, x1, y1 = rect
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    s = min(x1 - x0, y1 - y0) * 0.28
    if direction == "UP":
        pts = [(cx, cy - s), (cx - s, cy + s), (cx + s, cy + s)]
    elif direction == "DOWN":
        pts = [(cx, cy + s), (cx - s, cy - s), (cx + s, cy - s)]
    elif direction == "LEFT":
        pts = [(cx - s, cy), (cx + s, cy - s), (cx + s, cy + s)]
    else:  # RIGHT
        pts = [(cx + s, cy), (cx - s, cy - s), (cx - s, cy + s)]
    d.polygon(pts, fill=_ARROW)


def render_deck(w, h):
    """Render the deck to a fresh PIL image (w x h). Not cached."""
    img = Image.new("RGB", (w, h), _BG)
    d = ImageDraw.Draw(img)
    d.line([(0, 0), (0, h)], fill=_DIVIDER, width=2)  # seam against the UI
    rects = button_rects(w, h)
    rad = max(4, round(w * 0.06))

    for name in ("UP", "DOWN", "LEFT", "RIGHT"):
        _rounded(d, rects[name], rad, fill=_DPAD_FILL, outline=_DPAD_EDGE, width=2)
        _arrow(d, rects[name], name)

    _rounded(d, rects["OK"], rad, fill=_OK_FILL, outline=_DPAD_EDGE, width=2)
    _centered(d, rects["OK"], "OK", _font(max(11, round(h * 0.05))))

    kfont = _font(max(11, round(h * 0.05)))
    for name in ("KEY1", "KEY2", "KEY3"):
        _rounded(d, rects[name], rad, fill=_KEY_FILL, outline=_KEY_EDGE, width=2)
        _centered(d, rects[name], name, kfont)
    return img


_cache = {}


def get_deck_image(w, h):
    """Cached deck image for the given size."""
    key = (int(w), int(h))
    img = _cache.get(key)
    if img is None:
        img = render_deck(*key)
        _cache[key] = img
    return img


def hit_test(rects, lx, ly):
    """Return the button name at deck-local (lx, ly), or None."""
    for name, (x0, y0, x1, y1) in rects.items():
        if x0 <= lx <= x1 and y0 <= ly <= y1:
            return name
    return None


if __name__ == "__main__":
    # Quick offline preview: save a PNG you can eyeball on the dev box.
    out = render_deck(160, 320)
    out.save("touch_deck_preview.png")
    print("wrote touch_deck_preview.png")
    for n, r in button_rects(160, 320).items():
        print(f"  {n:5} {r}")
