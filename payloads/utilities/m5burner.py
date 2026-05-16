#!/usr/bin/env python3
"""
RaspyJack Payload -- M5Burner
==============================
Author: 7h30th3r0n3

Flash M5Stack firmwares using the official M5Burner catalog.
Downloads binaries from m5burner-cdn.m5stack.com.

Controls:
  OK          Flash selected firmware
  UP/DOWN     Navigate firmware list
  LEFT/RIGHT  Change category
  KEY1        Detect board / Refresh
  KEY2        Erase flash
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess
import glob
import json

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
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
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 17)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(9)
    font_sm = scaled_font(7)
    font_lg = font

CDN_BASE = "https://m5burner-cdn.m5stack.com/firmware/"
API_URL = "http://m5burner-api-fc-hk-cdn.m5stack.com/api/firmware"
FW_DIR = "/root/Raspyjack/loot/Firmwares/M5Stack"
DEBOUNCE = 0.20

_running = True

C_BG = (5, 5, 15)
C_HEAD = (30, 0, 50)
C_PURPLE = (180, 80, 255)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_DARK = (15, 12, 25)
C_SEL = (40, 15, 70)
C_GREEN = (0, 220, 80)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_ORANGE = (255, 140, 0)
C_CYAN = (0, 200, 255)


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


def _ensure_esptool():
    try:
        import esptool  # noqa: F401
        return True
    except ImportError:
        pass
    _show_status("Installing esptool...", C_YELLOW)
    r = subprocess.run(
        ["pip3", "install", "--break-system-packages", "esptool"],
        capture_output=True, timeout=120)
    return r.returncode == 0


def _fetch_catalog():
    """Fetch firmware catalog from M5Stack API."""
    import urllib.request
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "M5Burner-Raspyjack"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        if isinstance(data, list):
            return data
        return data.get("list", data.get("options", []))
    except Exception:
        return []


def _get_categories(catalog):
    cats = {}
    for item in catalog:
        cat = item.get("category", "other")
        if cat not in cats:
            cats[cat] = []
        cats[cat].append(item)
    order = ["cardputer", "stickc", "core", "core2 & tough", "cores3",
             "atoms3", "paper", "sticks3", "tab5", "atom", "stamps3"]
    sorted_cats = []
    for c in order:
        if c in cats:
            sorted_cats.append(c)
    for c in sorted(cats.keys()):
        if c not in sorted_cats:
            sorted_cats.append(c)
    return sorted_cats, cats


def _detect_serial():
    return sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))


def _detect_chip(port):
    try:
        r = subprocess.run(
            ["esptool.py", "--port", port, "chip_id"],
            capture_output=True, text=True, timeout=15)
        output = r.stdout + r.stderr
        for line in output.split("\n"):
            if "Chip type:" in line:
                return line.split("Chip type:")[-1].strip().split("(")[0].strip()
            if "Detecting chip type..." in line:
                raw = line.split("...")[-1].strip()
                if raw:
                    return raw
        return "Unknown" if r.returncode == 0 else None
    except Exception:
        return None


def _download_firmware(file_hash):
    import urllib.request
    os.makedirs(FW_DIR, exist_ok=True)
    dest = os.path.join(FW_DIR, file_hash)
    if os.path.isfile(dest):
        return dest
    url = CDN_BASE + file_hash
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "M5Burner-Raspyjack"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
        return dest if os.path.isfile(dest) else None
    except Exception:
        if os.path.isfile(dest):
            os.remove(dest)
        return None


def _flash(port, fw_path, progress_cb):
    cmd = ["esptool.py", "--port", port, "--baud", "460800",
           "--no-stub", "write_flash", "0x0", fw_path]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)
    while proc.poll() is None:
        line = proc.stdout.readline()
        if not line:
            continue
        if "%" in line:
            try:
                for part in line.split():
                    if "%" in part:
                        pct = int(part.replace("%", "").strip("(").strip(")"))
                        progress_cb(min(pct, 100))
                        break
            except Exception:
                pass
        elif "Writing" in line and "/" in line:
            try:
                parts = line.split("(")
                if len(parts) > 1:
                    pct = int(parts[1].split("%")[0])
                    progress_cb(min(pct, 100))
            except Exception:
                pass
        elif "Hash" in line or "Leaving" in line:
            progress_cb(100)
    proc.wait()
    return proc.returncode == 0


def _erase(port):
    r = subprocess.run(
        ["esptool.py", "--port", port, "erase_flash"],
        capture_output=True, text=True, timeout=30)
    return r.returncode == 0


def _show_status(msg, color=C_PURPLE):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2), msg, font=font, fill=color,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, H // 2 - 7), msg, font=font, fill=color)
    else:
        d.text((64, 60), msg[:18], font=font_sm, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_progress(msg, pct):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.rectangle([0, 0, W, 24], fill=C_HEAD)
        d.text((W // 2, 12), "FLASHING", font=font_lg, fill=C_ORANGE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 40, 2), "FLASHING", font=font_lg, fill=C_ORANGE)
        d.text((W // 2, 50), msg[:35], font=font_sm, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, 42), msg[:35], font=font_sm, fill=C_WHITE)
        bar_x, bar_w = 20, W - 40
        bar_y = 80
        d.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + 16], fill=C_DARK)
        fill_w = int(bar_w * pct / 100)
        if fill_w > 0:
            d.rectangle([bar_x, bar_y, bar_x + fill_w, bar_y + 16], fill=C_PURPLE)
        d.text((W // 2, bar_y + 30), f"{pct}%", font=font, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 12, bar_y + 22), f"{pct}%", font=font, fill=C_WHITE)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((64, 1), "FLASH", font=font, fill=C_ORANGE)
        d.text((64, 30), msg[:16], font=font_sm, fill=C_WHITE)
        d.rectangle([10, 60, 118, 70], fill=C_DARK)
        d.rectangle([10, 60, 10 + int(108 * pct / 100), 70], fill=C_PURPLE)
        d.text((64, 80), f"{pct}%", font=font, fill=C_WHITE)
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    current_cat = cat_names[cat_idx] if cat_names else "?"

    if IS_WIDE:
        d.rectangle([0, 0, W, 24], fill=C_HEAD)
        d.text((W // 2, 12), "M5BURNER", font=font_lg, fill=C_PURPLE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 40, 2), "M5BURNER", font=font_lg, fill=C_PURPLE)

        info_y = 26
        if port and chip:
            d.text((4, info_y), f"{os.path.basename(port)} | {chip}", font=font_sm, fill=C_GREEN)
        else:
            d.text((4, info_y), "No device - KEY1: Scan", font=font_sm, fill=C_RED)

        cat_str = f"< {current_cat} ({len(firmwares)}) >"
        d.text((W - 4, info_y), cat_str, font=font_sm, fill=C_CYAN,
               anchor="ra") if hasattr(d, 'textbbox') else d.text(
                   (W - len(cat_str) * 7, info_y), cat_str, font=font_sm, fill=C_CYAN)

        y = 42
        row_h = 22
        max_visible = 5
        if not firmwares:
            d.text((W // 2, 80), "No firmwares", font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 40, 72), "No firmwares", font=font_sm, fill=C_DIM)
        else:
            for i in range(max_visible):
                idx = page_offset + i
                if idx >= len(firmwares):
                    break
                fw = firmwares[idx]
                ry = y + i * row_h
                is_sel = idx == sel
                if is_sel:
                    d.rectangle([4, ry, W - 4, ry + row_h - 1], fill=C_SEL)
                name = fw.get("name", "?")
                if len(name) > 25:
                    name = name[:22] + "..."
                vers = fw.get("versions", [])
                ver = vers[0].get("version", "") if vers else ""
                color = C_WHITE if is_sel else C_DIM
                d.text((8, ry + 3), name, font=font_sm, fill=color)
                d.text((W - 8, ry + 3), ver[:10], font=font_sm, fill=C_PURPLE,
                       anchor="ra") if hasattr(d, 'textbbox') else d.text(
                           (W - 60, ry + 3), ver[:10], font=font_sm, fill=C_PURPLE)

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        bar = "OK:Details K1:Search K2:Erase/Scan L/R:Cat K3:Exit"
        d.text((W // 2, H - 8), bar, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 13), bar[:44], font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 12], fill=C_HEAD)
        d.text((64, 0), "M5BURNER", font=font_sm, fill=C_PURPLE)
        d.text((64, 13), f"{current_cat}({len(firmwares)})", font=font_sm, fill=C_CYAN)
        y = 26
        row_h = 14
        max_visible = 5
        for i in range(max_visible):
            idx = page_offset + i
            if idx >= len(firmwares):
                break
            fw = firmwares[idx]
            ry = y + i * row_h
            is_sel = idx == sel
            name = fw.get("name", "?")[:16]
            color = C_WHITE if is_sel else C_DIM
            d.text((4, ry), name, font=font_sm, fill=color)
        d.text((64, 115), "OK:Flash K3:Exit", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


_EVDEV_CHARS = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
    57: ' ', 12: '-', 52: '.', 53: '/',
}


def _find_evdev_keyboard():
    try:
        import evdev
        for path in evdev.list_devices():
            dev = evdev.InputDevice(path)
            if "tca8418" in dev.name.lower() or "keyboard" in dev.name.lower():
                return dev
    except Exception:
        pass
    return None


def _search_screen(catalog):
    """Full-screen search with keyboard input. Returns filtered list or None."""
    import evdev
    kbd = _find_evdev_keyboard()
    query = ""
    results = []
    last_btn = 0

    while _running:
        if query:
            q = query.lower()
            results = [fw for fw in catalog
                       if q in fw.get("name", "").lower()
                       or q in fw.get("description", "").lower()
                       or q in fw.get("author", "").lower()]
        else:
            results = []

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        if IS_WIDE:
            d.rectangle([0, 0, W, 24], fill=(30, 30, 0))
            d.text((W // 2, 12), "SEARCH", font=font_lg, fill=C_YELLOW,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 30, 2), "SEARCH", font=font_lg, fill=C_YELLOW)

            cursor = "_" if int(time.time() * 3) % 2 else " "
            d.rectangle([4, 28, W - 4, 44], fill=C_DARK)
            d.text((8, 30), f"{query}{cursor}", font=font, fill=C_WHITE)

            d.text((W - 8, 30), f"{len(results)} results", font=font_sm, fill=C_DIM,
                   anchor="ra") if hasattr(d, 'textbbox') else d.text(
                       (W - 80, 30), f"{len(results)}", font=font_sm, fill=C_DIM)

            y = 50
            for i, fw in enumerate(results[:5]):
                ry = y + i * 22
                name = fw.get("name", "?")
                if len(name) > 30:
                    name = name[:27] + "..."
                d.text((8, ry), name, font=font_sm,
                       fill=C_WHITE if i == 0 else C_DIM)

            d.rectangle([0, H - 16, W, H], fill=C_DARK)
            d.text((W // 2, H - 8), "Type to search | Enter:Select | KEY3:Back",
                   font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (2, H - 13), "Type|Enter:Sel|K3:Back", font=font_sm, fill=C_DIM)
        else:
            d.rectangle([0, 0, 128, 12], fill=(30, 30, 0))
            d.text((64, 0), "SEARCH", font=font_sm, fill=C_YELLOW)
            d.text((4, 14), f"{query}_", font=font_sm, fill=C_WHITE)
            y = 28
            for i, fw in enumerate(results[:4]):
                d.text((4, y + i * 14), fw.get("name", "?")[:16], font=font_sm,
                       fill=C_WHITE if i == 0 else C_DIM)

        LCD.LCD_ShowImage(img, 0, 0)

        btn = _get_btn()
        now = time.time()
        if btn == "KEY3" and now - last_btn > DEBOUNCE:
            return None
        last_btn = now if btn else last_btn

        if kbd:
            try:
                while True:
                    ev = kbd.read_one()
                    if ev is None:
                        break
                    if ev.type == 1 and ev.value == 1:
                        code = ev.code
                        if code == 28:
                            return results if results else None
                        elif code == 14:
                            query = query[:-1]
                        else:
                            ch = _EVDEV_CHARS.get(code, "")
                            if ch:
                                query += ch
            except Exception:
                pass

        time.sleep(0.08)
    return None


def _detail_screen(fw, port):
    """Show firmware details. Returns 'flash' or None."""
    last_btn = 0
    vers = fw.get("versions", [])
    latest = vers[0] if vers else {}

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        if IS_WIDE:
            d.rectangle([0, 0, W, 24], fill=C_HEAD)
            name = fw.get("name", "?")
            if len(name) > 30:
                name = name[:27] + "..."
            d.text((W // 2, 12), name, font=font_lg, fill=C_PURPLE,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (8, 2), name[:30], font=font_lg, fill=C_PURPLE)

            y = 30
            author = fw.get("author", "?")
            d.text((8, y), f"Author: {author}", font=font_sm, fill=C_CYAN)
            y += 16

            ver = latest.get("version", "?")
            date = latest.get("published_at", "?")
            d.text((8, y), f"Version: {ver}  ({date})", font=font_sm, fill=C_WHITE)
            y += 16

            desc = fw.get("description", "No description")
            lines = []
            words = desc.split()
            line = ""
            for w in words:
                if len(line + " " + w) > 42:
                    lines.append(line)
                    line = w
                else:
                    line = (line + " " + w).strip()
            if line:
                lines.append(line)
            for ln in lines[:3]:
                d.text((8, y), ln, font=font_sm, fill=C_DIM)
                y += 14

            changelog = latest.get("change_log", "")
            if changelog:
                y += 4
                d.text((8, y), "Changelog:", font=font_sm, fill=C_YELLOW)
                y += 14
                for cl in changelog.split("\n")[:2]:
                    d.text((8, y), cl[:42], font=font_sm, fill=C_DIM)
                    y += 12

            d.rectangle([0, H - 16, W, H], fill=C_DARK)
            flash_ok = "OK:Flash" if port else "No device!"
            d.text((W // 2, H - 8), f"{flash_ok}  KEY3:Back",
                   font=font_sm, fill=C_GREEN if port else C_RED,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (10, H - 13), f"{flash_ok} K3:Back", font=font_sm,
                       fill=C_GREEN if port else C_RED)
        else:
            d.rectangle([0, 0, 128, 12], fill=C_HEAD)
            d.text((64, 0), fw.get("name", "?")[:16], font=font_sm, fill=C_PURPLE)
            y = 14
            d.text((4, y), f"v{latest.get('version','?')}", font=font_sm, fill=C_WHITE)
            y += 14
            d.text((4, y), fw.get("author", "?")[:16], font=font_sm, fill=C_CYAN)
            y += 14
            desc = fw.get("description", "")[:32]
            d.text((4, y), desc[:16], font=font_sm, fill=C_DIM)
            d.text((64, 110), "OK:Flash K3:Back", font=font_sm, fill=C_DIM)

        LCD.LCD_ShowImage(img, 0, 0)

        btn = _get_btn()
        now = time.time()
        if btn == "KEY3" and now - last_btn > DEBOUNCE:
            return None
        if btn == "OK" and now - last_btn > DEBOUNCE and port:
            return "flash"
        last_btn = now if btn else last_btn
        time.sleep(0.08)
    return None


def main():
    global _running

    if not _ensure_esptool():
        _show_status("esptool failed", C_RED)
        time.sleep(2)
        GPIO.cleanup()
        return 1

    _show_status("Fetching catalog...", C_PURPLE)
    catalog = _fetch_catalog()
    if not catalog:
        _show_status("Fetch failed! Check internet", C_RED)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    cat_names, cat_map = _get_categories(catalog)
    cat_idx = 0
    sel = 0
    page_offset = 0
    max_visible = 5
    last_btn = 0

    port = None
    chip = None
    ports = _detect_serial()
    if ports:
        port = ports[0]
        _show_status("Detecting chip...", C_YELLOW)
        chip = _detect_chip(port)

    firmwares = cat_map.get(cat_names[cat_idx], [])
    _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            break

        if btn == "LEFT" and now - last_btn > DEBOUNCE:
            last_btn = now
            cat_idx = (cat_idx - 1) % len(cat_names)
            firmwares = cat_map.get(cat_names[cat_idx], [])
            sel = 0
            page_offset = 0
            _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)

        if btn == "RIGHT" and now - last_btn > DEBOUNCE:
            last_btn = now
            cat_idx = (cat_idx + 1) % len(cat_names)
            firmwares = cat_map.get(cat_names[cat_idx], [])
            sel = 0
            page_offset = 0
            _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)

        if btn == "UP" and now - last_btn > DEBOUNCE and firmwares:
            last_btn = now
            sel = (sel - 1) % len(firmwares)
            if sel < page_offset:
                page_offset = sel
            elif sel >= page_offset + max_visible:
                page_offset = sel - max_visible + 1
            _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)

        if btn == "DOWN" and now - last_btn > DEBOUNCE and firmwares:
            last_btn = now
            sel = (sel + 1) % len(firmwares)
            if sel >= page_offset + max_visible:
                page_offset = sel - max_visible + 1
            elif sel < page_offset:
                page_offset = sel
            _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)

        if btn == "KEY1" and now - last_btn > DEBOUNCE:
            last_btn = now
            search_results = _search_screen(catalog)
            if search_results:
                firmwares = search_results
                sel = 0
                page_offset = 0
            _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)
            continue

        if btn == "KEY2" and now - last_btn > DEBOUNCE:
            last_btn = now
            if port:
                _show_status("Erasing...", C_ORANGE)
                if _erase(port):
                    _show_status("Erased!", C_GREEN)
                else:
                    _show_status("Erase failed!", C_RED)
                time.sleep(1.5)
            else:
                _show_status("Scanning...", C_YELLOW)
                ports = _detect_serial()
                if ports:
                    port = ports[0]
                    chip = _detect_chip(port)
                else:
                    _show_status("No device found", C_RED)
                    time.sleep(1)
            _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)

        if btn == "OK" and now - last_btn > DEBOUNCE and firmwares:
            last_btn = now
            fw = firmwares[sel]
            action = _detail_screen(fw, port)
            if action != "flash" or not port:
                _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)
                continue

            vers = fw.get("versions", [])
            if not vers:
                _show_status("No version!", C_RED)
                time.sleep(1)
                _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)
                continue
            latest = vers[0]
            file_hash = latest.get("file", "")
            if not file_hash:
                _show_status("No file!", C_RED)
                time.sleep(1)
                _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)
                continue

            _show_status(f"Downloading {fw['name'][:20]}...", C_PURPLE)
            fw_path = _download_firmware(file_hash)
            if not fw_path:
                _show_status("Download failed!", C_RED)
                time.sleep(1.5)
                _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)
                continue

            def _progress(pct):
                _draw_progress(fw["name"][:20], pct)

            _draw_progress(fw["name"][:20], 0)
            ok = _flash(port, fw_path, _progress)
            if ok:
                _show_status("Flash OK!", C_GREEN)
            else:
                _show_status("Flash FAILED!", C_RED)
            time.sleep(2)
            _draw_main(port, chip, cat_names, cat_idx, firmwares, sel, page_offset)

        if not btn:
            time.sleep(0.05)

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
