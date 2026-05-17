#!/usr/bin/env python3
"""
RaspyJack Payload -- QR/Barcode Scanner
=========================================
Author: 7h30th3r0n3

Scans QR codes and barcodes using the IMX219 camera.
Continuous scanning with live preview.

Controls:
  OK          Toggle scan on/off
  UP/DOWN     Scroll history
  KEY1        Copy last result to clipboard
  KEY2        Clear history
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import mmap
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
import numpy as np
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)
time.sleep(0.1)
_STUCK_PINS = {name for name, pin in PINS.items() if GPIO.input(pin) == 0}

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(12)

FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = W * H * 2
LOOT_DIR = "/root/Raspyjack/loot/QR_Scans"
DEBOUNCE = 0.20

_running = True
_scanning = False
_results = []
_results_lock = threading.Lock()

C_BG = (0, 5, 10)
C_HEAD = (0, 30, 30)
C_GREEN = (0, 255, 80)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_DARK = (10, 15, 20)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_CYAN = (0, 200, 220)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    btn = get_button(PINS, GPIO)
    if btn and btn in _STUCK_PINS:
        return None
    return btn


def _ensure_pyzbar():
    try:
        from pyzbar.pyzbar import decode  # noqa: F401
        return True
    except ImportError:
        subprocess.run(["apt-get", "install", "-y", "libzbar0"],
                       capture_output=True, timeout=30)
        subprocess.run(["pip3", "install", "--break-system-packages", "pyzbar"],
                       capture_output=True, timeout=60)
        try:
            from pyzbar.pyzbar import decode  # noqa: F401
            return True
        except ImportError:
            return False


def _scan_thread():
    """Continuous scan: capture frames, decode QR/barcodes, display preview."""
    global _scanning
    from pyzbar.pyzbar import decode

    proc = subprocess.Popen(
        ["rpicam-vid", "--width", str(W), "--height", str(H),
         "--framerate", "10", "--codec", "yuv420",
         "--rotation", "180", "-t", "0", "--nopreview", "-o", "-"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

    frame_size = W * H * 3 // 2
    fb_fd = None
    fb_map = None
    try:
        fb_fd = os.open(FB_DEVICE, os.O_RDWR)
        fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED,
                           mmap.PROT_WRITE | mmap.PROT_READ)
    except Exception:
        _scanning = False
        proc.kill()
        return

    seen = set()
    try:
        while _scanning and _running and proc.poll() is None:
            raw = b""
            while len(raw) < frame_size and _scanning:
                chunk = proc.stdout.read(frame_size - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) < frame_size:
                break

            yuv = np.frombuffer(raw, dtype=np.uint8)
            y_plane = yuv[:W * H].reshape(H, W)
            u_raw = yuv[W * H:W * H + W * H // 4].reshape(H // 2, W // 2)
            v_raw = yuv[W * H + W * H // 4:].reshape(H // 2, W // 2)
            u = np.repeat(np.repeat(u_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
            v = np.repeat(np.repeat(v_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
            y16 = y_plane.astype(np.int16)

            r = np.clip(y16 + ((359 * v) >> 8), 0, 255).astype(np.uint8)
            g = np.clip(y16 - ((88 * u + 183 * v) >> 8), 0, 255).astype(np.uint8)
            b = np.clip(y16 + ((454 * u) >> 8), 0, 255).astype(np.uint8)

            rgb565 = ((r.astype(np.uint16) >> 3) << 11) | \
                     ((g.astype(np.uint16) >> 2) << 5) | \
                     (b.astype(np.uint16) >> 3)
            fb_map.seek(0)
            fb_map.write(rgb565.tobytes())

            gray_img = Image.fromarray(y_plane, "L")
            codes = decode(gray_img)
            for code in codes:
                data = code.data.decode(errors="replace")
                if data not in seen:
                    seen.add(data)
                    entry = {
                        "type": code.type,
                        "data": data,
                        "time": datetime.now().strftime("%H:%M:%S"),
                    }
                    with _results_lock:
                        _results.insert(0, entry)
                        if len(_results) > 50:
                            _results.pop()
                    _save_result(entry)
    except Exception:
        pass
    finally:
        proc.kill()
        try:
            if fb_map:
                fb_map.close()
            if fb_fd is not None:
                os.close(fb_fd)
        except Exception:
            pass
        _scanning = False


def _save_result(entry):
    os.makedirs(LOOT_DIR, exist_ok=True)
    path = os.path.join(LOOT_DIR, f"scans_{datetime.now().strftime('%Y%m%d')}.json")
    entries = []
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                entries = json.load(f)
        except Exception:
            pass
    entries.append(entry)
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)


def _draw_results(scroll):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    with _results_lock:
        results = list(_results)

    status = "SCANNING" if _scanning else "PAUSED"
    status_c = C_GREEN if _scanning else C_RED

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "QR SCANNER", font=font_lg, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 45, 1), "QR SCANNER", font=font_lg, fill=C_CYAN)
        d.text((W - 8, 5), status, font=font_sm, fill=status_c,
               anchor="ra") if hasattr(d, 'textbbox') else d.text(
                   (W - 65, 5), status, font=font_sm, fill=status_c)

        y = 24
        if not results:
            d.text((W // 2, H // 2), "Point camera at QR/barcode", font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (20, H // 2 - 7), "Point at QR/barcode", font=font_sm, fill=C_DIM)
        else:
            for i in range(min(5, len(results) - scroll)):
                idx = scroll + i
                if idx >= len(results):
                    break
                r = results[idx]
                ry = y + i * 26
                if i == 0 and scroll == 0:
                    d.rectangle([4, ry, W - 4, ry + 24], fill=C_DARK)
                d.text((8, ry + 2), f"[{r['type']}] {r['data'][:30]}", font=font_sm,
                       fill=C_GREEN if i == 0 and scroll == 0 else C_WHITE)
                d.text((8, ry + 13), r['time'], font=font_sm, fill=C_DIM)

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        action = "OK:Pause" if _scanning else "OK:Detail  K1:Scan"
        d.text((W // 2, H - 8), f"{action}  UP/DN:Scroll  K2:Clear  K3:Exit  [{len(results)}]",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 13), f"{'OK:Pause' if _scanning else 'OK:Det K1:Scan'} [{len(results)}]",
                   font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((15, 1), "QR SCAN", font=font_lg, fill=C_CYAN)
        y = 18
        if not results:
            d.text((4, 50), "Point at QR", font=font, fill=C_DIM)
        else:
            for i in range(min(4, len(results) - scroll)):
                idx = scroll + i
                if idx >= len(results):
                    break
                r = results[idx]
                d.text((4, y + i * 20), r['data'][:16], font=font_sm, fill=C_GREEN)
        d.text((4, 108), f"OK:Scan K3:X [{len(results)}]", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _show_detail(result):
    """Show full decoded data with scrolling."""
    data = result["data"]
    lines = []
    lines.append(f"Type: {result['type']}")
    lines.append(f"Time: {result['time']}")
    lines.append(f"Length: {len(data)} chars")
    lines.append("")
    chunk_len = 38 if IS_WIDE else 16
    for i in range(0, len(data), chunk_len):
        lines.append(data[i:i + chunk_len])

    scroll = 0
    last_btn = 0
    max_vis = 7 if IS_WIDE else 5

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        if IS_WIDE:
            d.rectangle([0, 0, W, 20], fill=C_HEAD)
            d.text((W // 2, 10), "SCAN DETAIL", font=font_lg, fill=C_GREEN,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 45, 1), "SCAN DETAIL", font=font_lg, fill=C_GREEN)
            y = 24
            for i in range(max_vis):
                idx = scroll + i
                if idx >= len(lines):
                    break
                ln = lines[idx]
                color = C_CYAN if idx < 3 else C_WHITE
                d.text((8, y + i * 18), ln, font=font_sm, fill=color)
            d.rectangle([0, H - 16, W, H], fill=C_DARK)
            d.text((W // 2, H - 8), f"UP/DN:Scroll  KEY3:Back  [{scroll+1}/{len(lines)}]",
                   font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (2, H - 13), f"UP/DN K3:Back [{scroll+1}/{len(lines)}]",
                       font=font_sm, fill=C_DIM)
        else:
            d.rectangle([0, 0, 128, 14], fill=C_HEAD)
            d.text((20, 1), "DETAIL", font=font_lg, fill=C_GREEN)
            y = 18
            for i in range(max_vis):
                idx = scroll + i
                if idx >= len(lines):
                    break
                ln = lines[idx]
                color = C_CYAN if idx < 3 else C_WHITE
                d.text((4, y + i * 16), ln[:17], font=font_sm, fill=color)
            d.text((4, 108), "UP/DN K3:Back", font=font_sm, fill=C_DIM)

        LCD.LCD_ShowImage(img, 0, 0)

        btn = _get_btn()
        now = time.time()
        if btn == "KEY3" and now - last_btn > DEBOUNCE:
            return
        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            scroll = max(0, scroll - 1)
        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            scroll = min(scroll + 1, max(0, len(lines) - max_vis))
        time.sleep(0.08)


def main():
    global _running, _scanning

    if not _ensure_pyzbar():
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        d.text((10, H // 2), "pyzbar install failed!", font=font, fill=C_RED)
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    scroll = 0
    last_btn = 0
    scan_thread = None

    _scanning = True
    scan_thread = threading.Thread(target=_scan_thread, daemon=True)
    scan_thread.start()

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            _scanning = False
            break

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            if _scanning:
                _scanning = False
                if scan_thread:
                    scan_thread.join(timeout=3)
            else:
                with _results_lock:
                    results = list(_results)
                if results and scroll < len(results):
                    _show_detail(results[scroll])
                else:
                    _scanning = True
                    scan_thread = threading.Thread(target=_scan_thread, daemon=True)
                    scan_thread.start()

        if btn == "KEY1" and now - last_btn > DEBOUNCE and not _scanning:
            last_btn = now
            _scanning = True
            scan_thread = threading.Thread(target=_scan_thread, daemon=True)
            scan_thread.start()

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            scroll = max(0, scroll - 1)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            with _results_lock:
                scroll = min(scroll + 1, max(0, len(_results) - 3))

        if btn == "KEY2" and now - last_btn > DEBOUNCE:
            last_btn = now
            with _results_lock:
                _results.clear()
            scroll = 0

        if not _scanning:
            _draw_results(scroll)

        time.sleep(0.1)

    _scanning = False
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
