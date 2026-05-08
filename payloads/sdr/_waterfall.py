"""
SDR Radio Suite – Waterfall and Spectrum Rendering Engine
"""
import numpy as np
from collections import deque
from PIL import Image


def _interp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def _build_lut(stops):
    lut = []
    for i in range(256):
        t = i / 255.0
        for j in range(len(stops) - 1):
            t0 = stops[j][0]
            t1 = stops[j + 1][0]
            if t0 <= t <= t1:
                seg_t = (t - t0) / (t1 - t0) if t1 > t0 else 0
                lut.append(_interp_color(stops[j][1], stops[j + 1][1], seg_t))
                break
        else:
            lut.append(stops[-1][1])
    return lut


COLORMAPS = {
    "turbo": _build_lut([
        (0.0, (48, 18, 59)), (0.15, (0, 91, 197)), (0.3, (0, 167, 225)),
        (0.45, (29, 221, 161)), (0.6, (159, 240, 60)), (0.75, (242, 206, 28)),
        (0.9, (240, 101, 0)), (1.0, (122, 4, 3)),
    ]),
    "inferno": _build_lut([
        (0.0, (0, 0, 4)), (0.2, (40, 11, 84)), (0.4, (101, 21, 110)),
        (0.6, (171, 49, 74)), (0.8, (235, 120, 11)), (1.0, (252, 255, 164)),
    ]),
    "plasma": _build_lut([
        (0.0, (13, 8, 135)), (0.25, (126, 3, 168)), (0.5, (204, 71, 120)),
        (0.75, (248, 149, 64)), (1.0, (240, 249, 33)),
    ]),
    "classic": _build_lut([
        (0.0, (0, 0, 0)), (0.15, (0, 0, 128)), (0.3, (0, 128, 255)),
        (0.5, (0, 255, 0)), (0.7, (255, 255, 0)), (0.85, (255, 0, 0)),
        (1.0, (255, 255, 255)),
    ]),
    "green": _build_lut([
        (0.0, (0, 0, 0)), (0.3, (0, 40, 0)), (0.6, (0, 150, 0)),
        (0.85, (0, 255, 0)), (1.0, (200, 255, 200)),
    ]),
}


class WaterfallBuffer:
    def __init__(self, width, height, colormap="turbo"):
        self.width = width
        self.height = height
        self._lut = COLORMAPS.get(colormap, COLORMAPS["turbo"])
        self._rows = deque(maxlen=height)
        self.db_min = -70
        self.db_max = -10

    def set_colormap(self, name):
        self._lut = COLORMAPS.get(name, COLORMAPS["turbo"])

    def set_range(self, db_min, db_max):
        self.db_min, self.db_max = db_min, db_max

    def push_fft(self, fft_db):
        resampled = np.interp(
            np.linspace(0, len(fft_db) - 1, self.width),
            np.arange(len(fft_db)), fft_db,
        )
        indices = np.clip(
            ((resampled - self.db_min) / max(0.1, self.db_max - self.db_min) * 255),
            0, 255,
        ).astype(np.uint8)
        self._rows.append(indices)

    def render(self, image, x0, y0, w, h):
        rows = list(self._rows)
        if not rows:
            return
        n = min(len(rows), h)
        last_rows = list(rows)[-n:]
        if not last_rows:
            return
        # Stack all rows into a 2D array and vectorize resampling
        stacked = np.array(last_rows, dtype=np.uint8)
        if stacked.shape[1] != w:
            x_old = np.linspace(0, stacked.shape[1] - 1, stacked.shape[1])
            x_new = np.linspace(0, stacked.shape[1] - 1, w)
            resampled = np.zeros((n, w), dtype=np.uint8)
            for i in range(n):
                resampled[i] = np.interp(x_new, x_old, stacked[i]).astype(np.uint8)
            stacked = resampled
        lut_arr = np.array(self._lut, dtype=np.uint8)
        pixels = lut_arr[stacked]
        wf_img = Image.fromarray(pixels, "RGB")
        image.paste(wf_img, (x0, y0 + h - n))


def draw_spectrum(draw, fft_db, x0, y0, w, h, color=(0, 255, 0), fill_color=None, db_min=-70, db_max=-10):
    if len(fft_db) == 0:
        return
    resampled = np.interp(np.linspace(0, len(fft_db) - 1, w), np.arange(len(fft_db)), fft_db)
    points = []
    for i in range(w):
        norm = np.clip((resampled[i] - db_min) / max(0.1, db_max - db_min), 0, 1)
        py = int(y0 + h - norm * h)
        points.append((x0 + i, py))
    if fill_color and len(points) > 1:
        fill_pts = [(x0, y0 + h)] + points + [(x0 + w - 1, y0 + h)]
        try:
            draw.polygon(fill_pts, fill=fill_color)
        except Exception:
            pass
    if len(points) > 1:
        draw.line(points, fill=color, width=1)


def draw_signal_meter(draw, db, x0, y0, w, h, font, color=(0, 255, 0)):
    draw.rectangle((x0, y0, x0 + w, y0 + h), fill=(20, 20, 20), outline=(60, 60, 60))
    s_val = max(0, min(9, int((db + 73) / 6))) if db < -19 else 9
    over = max(0, int(db + 19)) if db >= -19 else 0
    fill_pct = min(1.0, max(0, (db + 80) / 70))
    bar_w = int((w - 4) * fill_pct)
    if fill_pct < 0.5:
        bar_color = (0, 100, 255)
    elif fill_pct < 0.75:
        bar_color = (0, 200, 0)
    elif fill_pct < 0.9:
        bar_color = (255, 200, 0)
    else:
        bar_color = (255, 0, 0)
    if bar_w > 0:
        draw.rectangle((x0 + 2, y0 + 2, x0 + 2 + bar_w, y0 + h - 2), fill=bar_color)
    label = f"S{s_val}" if over == 0 else f"S9+{over}"
    draw.text((x0 + w + 3, y0), f"{label} {db:.0f}dB", fill=color, font=font)


def draw_freq_scale(draw, center_hz, bw_hz, x0, y0, w, font, color=(100, 100, 100)):
    from payloads.sdr._presets import format_freq_short
    left = center_hz - bw_hz // 2
    right = center_hz + bw_hz // 2
    for i in range(5):
        x = x0 + int(w * i / 4)
        freq = left + int(bw_hz * i / 4)
        draw.line([(x, y0), (x, y0 + 3)], fill=color)
        if i == 0 or i == 4 or i == 2:
            lbl = format_freq_short(freq)
            draw.text((x, y0 + 4), lbl, fill=color, font=font)
