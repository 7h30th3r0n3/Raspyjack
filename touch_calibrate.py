#!/usr/bin/env python3
"""
touch_calibrate.py — guided touch calibration for the Waveshare 3.5" (35a).

Draws targets on the panel in a known order, records the raw ADS7846 touch for
each, and solves the affine transform raw(x,y) -> screen(x,y). Handles axis
swap/flip automatically. Saves the result so the touch daemon can map touches to
on-screen controls. Then runs a verify pass (crosshair follows your finger).

IMPORTANT: stop RaspyJack first so it isn't drawing to the framebuffer at the
same time:
    sudo systemctl stop raspyjack
    sudo python3 touch_calibrate.py
    sudo systemctl start raspyjack     # (or reboot)

Deps: python3-evdev, python3-pil, python3-numpy (all installed by RaspyJack).
"""

import os
import sys
import time
import mmap
import struct
import json
import select

try:
    import evdev
    from evdev import ecodes
    import numpy as np
    from PIL import Image, ImageDraw
except Exception as e:
    print("Missing dependency:", e)
    print("Install:  sudo apt-get install -y python3-evdev python3-pil python3-numpy")
    sys.exit(1)

FB = os.environ.get("RJ_FB_DEVICE", "/dev/fb1")
SYS = "/sys/class/graphics/" + os.path.basename(FB)
CAL_PATH = os.environ.get("RJ_TOUCH_CAL", "/root/Raspyjack/config/touch_cal.json")


# ---------- framebuffer drawing (RGB565, like fb_probe.py) -------------------
def fb_info():
    def rd(n, d):
        try:
            return open(os.path.join(SYS, n)).read().strip()
        except Exception:
            return d
    w, h = (int(x) for x in rd("virtual_size", "480,320").split(","))
    bpp = int(rd("bits_per_pixel", "16"))
    return w, h, bpp, w * h * (bpp // 8)


FB_W, FB_H, FB_BPP, FB_SIZE = fb_info()


def blit(img):
    """Push a full-screen PIL RGB image to the framebuffer as RGB565."""
    arr = np.asarray(img.convert("RGB"))
    r = (arr[..., 0].astype(np.uint16) >> 3) << 11
    g = (arr[..., 1].astype(np.uint16) >> 2) << 5
    b = arr[..., 2].astype(np.uint16) >> 3
    buf = (r | g | b).astype("<u2").tobytes()
    fd = os.open(FB, os.O_RDWR)
    try:
        mm = mmap.mmap(fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        mm.seek(0)
        mm.write(buf[:FB_SIZE])
        mm.flush()
        mm.close()
    finally:
        os.close(fd)


def draw_target(px, py, label):
    img = Image.new("RGB", (FB_W, FB_H), (0, 0, 0))
    d = ImageDraw.Draw(img)
    d.text((10, 10), "TOUCH CALIBRATION", fill=(0, 255, 0))
    d.text((10, 24), label, fill=(255, 255, 255))
    d.text((10, FB_H - 16), "Tap the center of the crosshair", fill=(120, 120, 120))
    # crosshair + rings
    for rr, col in ((14, (255, 0, 0)), (7, (255, 200, 0))):
        d.ellipse([px - rr, py - rr, px + rr, py + rr], outline=col)
    d.line([px - 20, py, px + 20, py], fill=(0, 200, 255))
    d.line([px, py - 20, px, py + 20], fill=(0, 200, 255))
    blit(img)


# ---------- touch reading ----------------------------------------------------
def find_touch():
    for path in evdev.list_devices():
        try:
            d = evdev.InputDevice(path)
        except Exception:
            continue
        if "ads7846" in (d.name or "").lower() or "touch" in (d.name or "").lower():
            return d
    print("No touchscreen found."); sys.exit(1)


def read_one_touch(dev):
    """Wait for a press, average raw samples until release, return (rx, ry)."""
    xs, ys = [], []
    x = y = None
    touching = False
    while True:
        r, _, _ = select.select([dev.fd], [], [], None)
        if not r:
            continue
        for ev in dev.read():
            if ev.type == ecodes.EV_ABS:
                if ev.code == ecodes.ABS_X:
                    x = ev.value
                elif ev.code == ecodes.ABS_Y:
                    y = ev.value
                if touching and x is not None and y is not None:
                    xs.append(x); ys.append(y)
            elif ev.type == ecodes.EV_KEY and ev.code == ecodes.BTN_TOUCH:
                if ev.value:
                    touching = True
                    xs, ys = [], []
                else:
                    if xs and ys:
                        # drop the first/last few noisy samples if we have enough
                        if len(xs) > 6:
                            xs, ys = xs[2:-2], ys[2:-2]
                        return sum(xs) / len(xs), sum(ys) / len(ys)
                    touching = False


# ---------- calibration solve ------------------------------------------------
def solve_affine(raw_pts, screen_pts):
    """Least-squares affine: screen = A·[rx,ry,1].  Returns (a,b,c,d,e,f)."""
    A = np.array([[rx, ry, 1.0] for rx, ry in raw_pts])
    sx = np.array([p[0] for p in screen_pts], dtype=float)
    sy = np.array([p[1] for p in screen_pts], dtype=float)
    cx, *_ = np.linalg.lstsq(A, sx, rcond=None)
    cy, *_ = np.linalg.lstsq(A, sy, rcond=None)
    return (*cx, *cy)  # a,b,c,d,e,f


def apply_affine(coef, rx, ry):
    a, b, c, d, e, f = coef
    return a * rx + b * ry + c, d * rx + e * ry + f


def main():
    inset = 40
    targets = [
        (inset, inset, "1/5  TOP-LEFT"),
        (FB_W - inset, inset, "2/5  TOP-RIGHT"),
        (FB_W - inset, FB_H - inset, "3/5  BOTTOM-RIGHT"),
        (inset, FB_H - inset, "4/5  BOTTOM-LEFT"),
        (FB_W // 2, FB_H // 2, "5/5  CENTER"),
    ]
    dev = find_touch()
    print(f"Touch device: {dev.path} ({dev.name!r})   fb={FB_W}x{FB_H}@{FB_BPP}bpp")

    raw_pts, screen_pts = [], []
    for px, py, label in targets:
        draw_target(px, py, label)
        time.sleep(0.4)  # let the user see the new target before it reads
        rx, ry = read_one_touch(dev)
        print(f"  {label:22} screen=({px},{py})  raw=({rx:.0f},{ry:.0f})")
        raw_pts.append((rx, ry)); screen_pts.append((px, py))
        time.sleep(0.25)

    coef = solve_affine(raw_pts, screen_pts)
    # residual error
    errs = []
    for (rx, ry), (sx, sy) in zip(raw_pts, screen_pts):
        ex, ey = apply_affine(coef, rx, ry)
        errs.append(((ex - sx) ** 2 + (ey - sy) ** 2) ** 0.5)
    rms = (sum(e * e for e in errs) / len(errs)) ** 0.5

    cal = {
        "device_name": dev.name,
        "fb": [FB_W, FB_H, FB_BPP],
        "affine": list(coef),           # a,b,c,d,e,f : screen = A·[rawx,rawy,1]
        "raw_seen": {
            "x": [min(p[0] for p in raw_pts), max(p[0] for p in raw_pts)],
            "y": [min(p[1] for p in raw_pts), max(p[1] for p in raw_pts)],
        },
        "rms_px": round(rms, 2),
    }
    os.makedirs(os.path.dirname(CAL_PATH), exist_ok=True)
    with open(CAL_PATH, "w") as f:
        json.dump(cal, f, indent=4)
    print(f"\nSaved calibration -> {CAL_PATH}   (RMS error {rms:.1f}px)")
    if rms > 25:
        print("  WARNING: high error — retry and tap crosshair centers precisely.")

    # ---- verify: crosshair follows finger for ~15s ----
    print("Verify pass: touch anywhere, the crosshair should track your finger (15s).")
    end = time.time() + 15
    last = None
    x = y = None
    while time.time() < end:
        r, _, _ = select.select([dev.fd], [], [], 0.3)
        for ev in (dev.read() if r else []):
            if ev.type == ecodes.EV_ABS:
                if ev.code == ecodes.ABS_X: x = ev.value
                elif ev.code == ecodes.ABS_Y: y = ev.value
        if x is not None and y is not None and (x, y) != last:
            sx, sy = apply_affine(coef, x, y)
            sx = max(0, min(FB_W - 1, int(sx))); sy = max(0, min(FB_H - 1, int(sy)))
            img = Image.new("RGB", (FB_W, FB_H), (0, 0, 0))
            d = ImageDraw.Draw(img)
            d.text((10, 10), "VERIFY — crosshair should sit under your finger", fill=(0, 255, 0))
            d.line([sx - 15, sy, sx + 15, sy], fill=(255, 0, 0))
            d.line([sx, sy - 15, sx, sy + 15], fill=(255, 0, 0))
            d.text((10, FB_H - 16), f"screen=({sx},{sy})", fill=(120, 120, 120))
            blit(img)
            last = (x, y)
    print("Done. Restart RaspyJack:  sudo systemctl start raspyjack")


if __name__ == "__main__":
    main()
