"""
Display helper for payloads – automatic 128-base coordinate scaling.

Usage in a payload:
    from payloads._display_helper import ScaledDraw, scaled_font

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)           # drop-in replacement for ImageDraw.Draw
    font = scaled_font()          # readable font for current resolution

All pixel coordinates passed to d.text(), d.rectangle(), d.line(), etc.
are automatically scaled from 128-base to the actual LCD resolution.
"""
import os, sys, json
from PIL import ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# Detect scale factor (same logic as LCD_1in44.py)
# ---------------------------------------------------------------------------
_DISPLAY_TYPE = "ST7735_128"
_CONF_PATHS = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gui_conf.json"),
    "/root/Raspyjack/gui_conf.json",
]
for _p in _CONF_PATHS:
    if os.path.isfile(_p):
        try:
            with open(_p, "r") as _f:
                _conf = json.load(_f)
            _DISPLAY_TYPE = _conf.get("DISPLAY", {}).get("type", _DISPLAY_TYPE)
        except Exception:
            pass
        break

LCD_SCALE = 240 / 128 if _DISPLAY_TYPE == "ST7789_240" else 1.0


def S(v):
    """Scale a 128-base pixel value to the current display resolution."""
    return int(v * LCD_SCALE)


def scaled_font(size=10):
    """Return a TrueType font scaled for the current display.

    *size* is the desired point size on a 128px screen; the returned font
    is proportionally larger on bigger panels.
    """
    scaled_size = S(size)
    try:
        return ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", scaled_size
        )
    except Exception:
        return ImageFont.load_default()


# ---------------------------------------------------------------------------
# ScaledDraw – wraps ImageDraw.Draw, scaling all 128-base coordinates
# ---------------------------------------------------------------------------
def _scale_point(pt):
    """Scale a 2-tuple or 2-list."""
    return (S(pt[0]), S(pt[1]))


def _scale_coords(coords):
    """Scale a flat sequence of coordinates or a list of point tuples."""
    if not coords:
        return coords
    # list/tuple of 2-tuples: [(x,y), (x,y), ...]
    if isinstance(coords[0], (list, tuple)):
        return [_scale_point(p) for p in coords]
    # flat 4-value box: (x0, y0, x1, y1) or [x0, y0, x1, y1]
    if len(coords) == 4:
        return [S(coords[0]), S(coords[1]), S(coords[2]), S(coords[3])]
    # flat 2-value point
    if len(coords) == 2:
        return (S(coords[0]), S(coords[1]))
    return coords


class ScaledDraw:
    """Drop-in replacement for ``ImageDraw.Draw`` that auto-scales coordinates.

    If ``LCD_SCALE == 1.0`` (128x128), no overhead is added.
    """

    def __init__(self, image):
        self._draw = ImageDraw.Draw(image)
        self._passthrough = LCD_SCALE == 1.0

    # -- Scaled drawing primitives ------------------------------------------

    def text(self, xy, text, fill=None, font=None, anchor=None, **kw):
        if not self._passthrough:
            xy = _scale_point(xy)
        self._draw.text(xy, text, fill=fill, font=font, anchor=anchor, **kw)

    def rectangle(self, xy, fill=None, outline=None, width=1, **kw):
        if not self._passthrough:
            xy = _scale_coords(xy)
            width = max(1, S(width)) if width > 1 else width
        self._draw.rectangle(xy, fill=fill, outline=outline, width=width, **kw)

    def line(self, xy, fill=None, width=1, **kw):
        if not self._passthrough:
            xy = _scale_coords(xy)
            width = max(1, S(width)) if width > 1 else width
        self._draw.line(xy, fill=fill, width=width, **kw)

    def ellipse(self, xy, fill=None, outline=None, width=1, **kw):
        if not self._passthrough:
            xy = _scale_coords(xy)
            width = max(1, S(width)) if width > 1 else width
        self._draw.ellipse(xy, fill=fill, outline=outline, width=width, **kw)

    def polygon(self, xy, fill=None, outline=None, **kw):
        if not self._passthrough:
            xy = _scale_coords(xy)
        self._draw.polygon(xy, fill=fill, outline=outline, **kw)

    def arc(self, xy, start, end, fill=None, width=1, **kw):
        if not self._passthrough:
            xy = _scale_coords(xy)
            width = max(1, S(width)) if width > 1 else width
        self._draw.arc(xy, start, end, fill=fill, width=width, **kw)

    def pieslice(self, xy, start, end, fill=None, outline=None, width=1, **kw):
        if not self._passthrough:
            xy = _scale_coords(xy)
            width = max(1, S(width)) if width > 1 else width
        self._draw.pieslice(xy, start, end, fill=fill, outline=outline, width=width, **kw)

    def textbbox(self, xy, text, font=None, **kw):
        if not self._passthrough:
            xy = _scale_point(xy)
        return self._draw.textbbox(xy, text, font=font, **kw)

    def textlength(self, text, font=None, **kw):
        return self._draw.textlength(text, font=font, **kw)

    # -- Passthrough for anything else --------------------------------------
    def __getattr__(self, name):
        return getattr(self._draw, name)
