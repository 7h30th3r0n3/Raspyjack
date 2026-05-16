#!/usr/bin/env python3
"""
RaspyJack Payload -- ESP Terminator
====================================
Author: 7h30th3r0n3

ESP Terminator flasher - downloads and flashes firmware
from espterminator.com catalog to any ESP32/ESP8266 board.

Controls:
  OK          Flash selected firmware / Confirm
  UP/DOWN     Navigate
  KEY1        Detect board / Erase flash
  KEY2        Change flash offset (0x0 / 0x1000 / 0x10000)
  KEY3        Exit / Back
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

import time as _t
_t.sleep(0.1)
_STUCK_PINS = {name for name, pin in PINS.items() if GPIO.input(pin) == 0}

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 18)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(14)
else:
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(12)

FW_DIR = "/root/Raspyjack/loot/Firmwares"
MANIFEST_URL = "https://dagnazty.github.io/esp-terminator/firmware/manifest.json"
DEBOUNCE = 0.20
OFFSETS = ["0x0", "0x1000", "0x10000"]

_running = True

C_BG = (8, 8, 20)
C_HEAD = (0, 20, 50)
C_BLUE = (50, 150, 255)
C_BLUE_DIM = (30, 80, 140)
C_WHITE = (255, 255, 255)
C_DIM = (100, 100, 100)
C_DARK = (20, 20, 30)
C_SEL = (15, 30, 60)
C_GREEN = (0, 220, 80)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_ORANGE = (255, 140, 0)


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
    if r.returncode != 0:
        _show_status("Install failed!", C_RED)
        time.sleep(3)
        return False
    return True




def _serial_monitor(port):
    """Simple serial monitor showing ESP output on LCD."""
    try:
        import serial
    except ImportError:
        subprocess.run(["pip3", "install", "--break-system-packages", "pyserial"],
                       capture_output=True, timeout=60)
        import serial
    lines = []
    max_lines = 6 if IS_WIDE else 5
    last_btn_t = 0

    try:
        ser = serial.Serial(port, 115200, timeout=0.3)
    except Exception as e:
        _show_status(f"Serial error: {e}"[:30], C_RED)
        time.sleep(2)
        return

    try:
        while _running:
            btn = _get_btn()
            now = time.time()
            if btn == "KEY3" and now - last_btn_t > DEBOUNCE:
                break
            last_btn_t = now if btn else last_btn_t

            try:
                raw = ser.readline()
                if raw:
                    line = raw.decode(errors="replace").strip()
                    if line:
                        lines.append(line)
                        if len(lines) > 50:
                            lines = lines[-50:]
            except Exception:
                pass

            img = Image.new("RGB", (W, H), (0, 0, 0))
            d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

            if IS_WIDE:
                d.rectangle([0, 0, W, 20], fill=(20, 20, 40))
                d.text((W // 2, 10), f"SERIAL {os.path.basename(port)} 115200",
                       font=font_sm, fill=C_BLUE,
                       anchor="mm") if hasattr(d, 'textbbox') else d.text(
                           (5, 3), f"SERIAL {os.path.basename(port)} 115200",
                           font=font_sm, fill=C_BLUE)
                y = 24
                visible = lines[-max_lines:] if lines else []
                for i, ln in enumerate(visible):
                    txt = ln[:45]
                    d.text((4, y + i * 22), txt, font=font_sm, fill=C_GREEN)
                d.text((W // 2, H - 10), "KEY3: Exit", font=font_sm, fill=C_DIM,
                       anchor="mm") if hasattr(d, 'textbbox') else d.text(
                           (W // 2 - 25, H - 16), "KEY3: Exit", font=font_sm, fill=C_DIM)
            else:
                d.rectangle([0, 0, 128, 12], fill=(20, 20, 40))
                d.text((4, 0), "SERIAL", font=font_sm, fill=C_BLUE)
                y = 14
                visible = lines[-max_lines:] if lines else []
                for i, ln in enumerate(visible):
                    d.text((2, y + i * 16), ln[:18], font=font_sm, fill=C_GREEN)
                d.text((4, 115), "K3:Exit", font=font_sm, fill=C_DIM)

            LCD.LCD_ShowImage(img, 0, 0)
            time.sleep(0.1)
    finally:
        ser.close()


def _fetch_manifest(chip_name):
    """Fetch ESP Terminator manifest and filter by detected chip."""
    try:
        import urllib.request
        _show_status("Fetching firmware list...", C_YELLOW)
        req = urllib.request.Request(MANIFEST_URL, headers={"User-Agent": "Raspyjack"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        _show_status(f"Fetch failed: {e}"[:35], C_RED)
        time.sleep(2)
        return []

    options = data.get("options", []) if isinstance(data, dict) else data
    chip_lower = (chip_name or "esp32").lower().replace("-", "").replace(" ", "")
    results = []
    for entry in options:
        device = entry.get("device", "").lower().replace("-", "").replace(" ", "")
        if device != chip_lower:
            continue
        name = entry.get("name", "Unknown")
        dl_url = entry.get("downloadUrl", "")
        is_merged = entry.get("isMergedBinary", False)
        files = entry.get("files", [])

        if is_merged:
            url = dl_url
            if not url and files:
                url = files[0].get("downloadUrl", "")
            if url:
                results.append({"name": name, "url": url, "offset": "0x0"})
        elif files:
            for f in files:
                fname = f.get("name", "")
                furl = f.get("downloadUrl", "")
                addr = f.get("address", "0x10000")
                if furl and "bootloader" not in fname and "partition" not in fname:
                    results.append({"name": name, "url": furl, "offset": addr})
                    break
        elif dl_url:
            results.append({"name": name, "url": dl_url, "offset": "0x10000"})
    return results


def _download_firmware(url, dest_name):
    """Download a firmware binary to FW_DIR."""
    import urllib.request
    _ensure_fw_dir()
    dest = os.path.join(FW_DIR, dest_name)
    if url.startswith("./") or url.startswith("firmware/"):
        url = "https://dagnazty.github.io/esp-terminator/" + url.lstrip("./")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Raspyjack"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            with open(dest, "wb") as f:
                f.write(resp.read())
        return dest if os.path.isfile(dest) else None
    except Exception:
        return None


def _show_download_menu(chip):
    """Show downloadable firmwares from ESP Terminator."""
    entries = _fetch_manifest(chip)
    if not entries:
        _show_status("No firmware found online", C_RED)
        time.sleep(2)
        return

    unique = []
    seen_names = set()
    for e in entries:
        if e["name"] not in seen_names:
            seen_names.add(e["name"])
            unique.append(e)

    sel = 0
    page = 0
    max_vis = 5 if IS_WIDE else 4
    last_btn = 0

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        if IS_WIDE:
            d.rectangle([0, 0, W, 26], fill=(30, 30, 0))
            d.text((W // 2, 13), "DOWNLOAD FIRMWARE", font=font_lg, fill=C_YELLOW,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 80, 2), "DOWNLOAD FIRMWARE", font=font_lg, fill=C_YELLOW)

            y = 30
            row_h = 24
            for i in range(max_vis):
                idx = page * max_vis + i
                if idx >= len(unique):
                    break
                ry = y + i * row_h
                is_sel = idx == sel
                if is_sel:
                    d.rectangle([4, ry, W - 4, ry + row_h - 1], fill=C_SEL)
                name = unique[idx]["name"]
                if len(name) > 35:
                    name = name[:32] + "..."
                color = C_WHITE if is_sel else C_DIM
                d.text((8, ry + 3), name, font=font_sm, fill=color)

            d.rectangle([0, H - 18, W, H], fill=C_DARK)
            d.text((W // 2, H - 9), f"OK:Download  KEY3:Back  [{sel+1}/{len(unique)}]",
                   font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (5, H - 15), f"OK:DL K3:Back [{sel+1}/{len(unique)}]",
                       font=font_sm, fill=C_DIM)
        else:
            d.rectangle([0, 0, 128, 14], fill=(30, 30, 0))
            d.text((20, 1), "DOWNLOAD", font=font, fill=C_YELLOW)
            y = 18
            row_h = 16
            for i in range(max_vis):
                idx = page * max_vis + i
                if idx >= len(unique):
                    break
                ry = y + i * row_h
                is_sel = idx == sel
                name = unique[idx]["name"][:16]
                color = C_WHITE if is_sel else C_DIM
                d.text((4, ry), name, font=font_sm, fill=color)
            d.text((4, 110), "OK:DL K3:Back", font=font_sm, fill=C_DIM)

        LCD.LCD_ShowImage(img, 0, 0)

        btn = _get_btn()
        now = time.time()

        if btn == "KEY3" and now - last_btn > DEBOUNCE:
            return
        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            entry = unique[sel]
            fname = entry["name"].replace(" ", "_").replace("/", "_") + ".bin"
            _show_status("Downloading...", C_YELLOW)
            path = _download_firmware(entry["url"], fname)
            if path:
                _show_status("Downloaded!", C_GREEN)
            else:
                _show_status("Download failed!", C_RED)
            time.sleep(1.5)
            return
        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel - 1) % len(unique)
            page = sel // max_vis
        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel + 1) % len(unique)
            page = sel // max_vis

        time.sleep(0.08)


def _ensure_fw_dir():
    os.makedirs(FW_DIR, exist_ok=True)


def _detect_serial():
    ports = glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")
    return sorted(ports)


def _detect_chip(port):
    try:
        r = subprocess.run(
            ["esptool.py", "--port", port, "chip_id"],
            capture_output=True, text=True, timeout=10)
        output = r.stdout + r.stderr
        for line in output.split("\n"):
            if "Chip type:" in line:
                raw = line.split("Chip type:")[-1].strip()
                return raw.split("(")[0].strip()
            if "Detecting chip type..." in line:
                raw = line.split("...")[-1].strip()
                if raw:
                    return raw
            if "Chip is" in line:
                return line.split("Chip is")[-1].strip()
        return "Unknown ESP" if r.returncode == 0 else None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _list_firmwares():
    _ensure_fw_dir()
    files = []
    for ext in ("*.bin", "*.BIN"):
        files.extend(glob.glob(os.path.join(FW_DIR, ext)))
    files.extend(glob.glob(os.path.join(FW_DIR, "**", "*.bin"), recursive=True))
    seen = set()
    result = []
    for f in sorted(files):
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


def _flash_firmware(port, fw_path, offset, progress_cb):
    cmd = ["esptool.py", "--port", port, "--baud", "460800",
           "write_flash", offset, fw_path]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0)
    buf = b""
    output_lines = []
    while proc.poll() is None:
        ch = proc.stdout.read(1)
        if not ch:
            break
        if ch == b"\r" or ch == b"\n":
            line = buf.decode(errors="replace")
            buf = b""
            if not line:
                continue
            output_lines.append(line)
            if "%" in line:
                try:
                    idx = line.index("%")
                    num_str = ""
                    i = idx - 1
                    while i >= 0 and (line[i].isdigit() or line[i] == '.'):
                        num_str = line[i] + num_str
                        i -= 1
                    if num_str:
                        pct = int(float(num_str))
                        progress_cb(min(pct, 100))
                except Exception:
                    pass
            elif "Hash" in line or "Leaving" in line:
                progress_cb(100)
        else:
            buf += ch
    proc.wait()
    return proc.returncode == 0, "\n".join(output_lines[-5:])


def _erase_flash(port, progress_cb):
    progress_cb(0)
    cmd = ["esptool.py", "--port", port, "erase_flash"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    progress_cb(100)
    return r.returncode == 0


def _fmt_size(path):
    try:
        sz = os.path.getsize(path)
        if sz < 1024:
            return f"{sz}B"
        if sz < 1024 * 1024:
            return f"{sz // 1024}KB"
        return f"{sz / (1024 * 1024):.1f}MB"
    except Exception:
        return "?"


def _show_status(msg, color=C_BLUE):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2), msg, font=font, fill=color,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, H // 2 - 8), msg, font=font, fill=color)
    else:
        d.text((4, 55), msg, font=font_sm, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_progress(msg, pct):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.rectangle([0, 0, W, 26], fill=C_HEAD)
        d.text((W // 2, 13), "FLASHING", font=font_lg, fill=C_ORANGE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 45, 2), "FLASHING", font=font_lg, fill=C_ORANGE)
        d.text((W // 2, 60), msg, font=font_sm, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, 52), msg, font=font_sm, fill=C_WHITE)
        bar_x, bar_w = 20, W - 40
        bar_y = 90
        d.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + 14], fill=C_DARK)
        fill_w = int(bar_w * pct / 100)
        if fill_w > 0:
            d.rectangle([bar_x, bar_y, bar_x + fill_w, bar_y + 14], fill=C_ORANGE)
        d.text((W // 2, bar_y + 28), f"{pct}%", font=font, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 15, bar_y + 20), f"{pct}%", font=font, fill=C_WHITE)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((20, 1), "FLASH", font=font, fill=C_ORANGE)
        d.text((4, 28), msg[:17], font=font_sm, fill=C_WHITE)
        d.rectangle([10, 60, 118, 70], fill=C_DARK)
        fill_w = int(108 * pct / 100)
        if fill_w > 0:
            d.rectangle([10, 60, 10 + fill_w, 70], fill=C_ORANGE)
        d.text((50, 78), f"{pct}%", font=font, fill=C_WHITE)
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_main(port, chip, firmwares, sel, offset_idx, page_offset):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 26], fill=C_HEAD)
        d.text((W // 2, 13), "ESP FLASHER", font=font_lg, fill=C_BLUE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 55, 2), "ESP FLASHER", font=font_lg, fill=C_BLUE)

        if port and chip:
            info = f"{os.path.basename(port)} - {chip}"
            d.text((W // 2, 35), info, font=font_sm, fill=C_GREEN,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (8, 30), info[:40], font=font_sm, fill=C_GREEN)
        elif port:
            d.text((W // 2, 35), f"{os.path.basename(port)} - detecting...", font=font_sm, fill=C_YELLOW,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (8, 30), f"{os.path.basename(port)}", font=font_sm, fill=C_YELLOW)
        else:
            d.text((W // 2, 35), "No device - KEY1:Scan", font=font_sm, fill=C_RED,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (8, 30), "No device - KEY1:Scan", font=font_sm, fill=C_RED)

        offset_str = f"Offset: {OFFSETS[offset_idx]}"
        d.text((W - 8, 35), offset_str, font=font_sm, fill=C_DIM,
               anchor="ra") if hasattr(d, 'textbbox') else d.text(
                   (W - 75, 30), offset_str, font=font_sm, fill=C_DIM)

        y = 48
        row_h = 22
        max_visible = 4
        if not firmwares:
            d.text((W // 2, 80), f"No .bin files in", font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (20, 72), "No .bin files in", font=font_sm, fill=C_DIM)
            d.text((W // 2, 96), "loot/Firmwares/", font=font_sm, fill=C_BLUE_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (20, 88), "loot/Firmwares/", font=font_sm, fill=C_BLUE_DIM)
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
                name = os.path.basename(fw)
                if len(name) > 30:
                    name = name[:27] + "..."
                size = _fmt_size(fw)
                color = C_WHITE if is_sel else C_DIM
                d.text((8, ry + 3), name, font=font_sm, fill=color)
                d.text((W - 8, ry + 3), size, font=font_sm, fill=C_BLUE_DIM,
                       anchor="ra") if hasattr(d, 'textbbox') else d.text(
                           (W - 45, ry + 3), size, font=font_sm, fill=C_BLUE_DIM)

        d.rectangle([0, H - 18, W, H], fill=C_DARK)
        bar = "OK:Flash K1:Scan K2:Offset L:DL R:Serial K3:Exit"
        d.text((W // 2, H - 9), bar, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 15), bar[:42], font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 16], fill=C_HEAD)
        d.text((15, 1), "ESP FLASH", font=font_lg, fill=C_BLUE)
        if port and chip:
            d.text((4, 18), chip[:16], font=font_sm, fill=C_GREEN)
        else:
            d.text((4, 18), "No device-K1:Scan", font=font_sm, fill=C_RED)
        y = 32
        row_h = 17
        max_visible = 4
        if not firmwares:
            d.text((4, 60), "No .bin files", font=font, fill=C_DIM)
        else:
            for i in range(max_visible):
                idx = page_offset + i
                if idx >= len(firmwares):
                    break
                fw = firmwares[idx]
                ry = y + i * row_h
                is_sel = idx == sel
                if is_sel:
                    d.rectangle([2, ry, 126, ry + row_h - 2], fill=C_SEL)
                name = os.path.basename(fw)[:16]
                color = C_WHITE if is_sel else C_DIM
                d.text((4, ry + 1), name, font=font, fill=color)
        d.text((4, 112), "OK:Flash L:DL K3:Exit", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_confirm(fw_name, port, offset):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, 30), "Flash firmware?", font=font_lg, fill=C_YELLOW,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 65, 20), "Flash firmware?", font=font_lg, fill=C_YELLOW)
        d.text((W // 2, 60), fw_name[:35], font=font_sm, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, 52), fw_name[:35], font=font_sm, fill=C_WHITE)
        d.text((W // 2, 80), f"to {os.path.basename(port)} @ {offset}", font=font_sm, fill=C_BLUE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, 72), f"to {os.path.basename(port)} @ {offset}", font=font_sm, fill=C_BLUE)
        d.text((W // 2, 120), "OK: Yes   KEY3: No", font=font, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 55, 112), "OK: Yes   KEY3: No", font=font, fill=C_DIM)
    else:
        d.text((20, 20), "Flash?", font=font, fill=C_YELLOW)
        d.text((4, 40), fw_name[:16], font=font_sm, fill=C_WHITE)
        d.text((4, 56), f"{os.path.basename(port)}", font=font_sm, fill=C_BLUE)
        d.text((4, 90), "OK:Yes K3:No", font=font_sm, fill=C_DIM)
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running

    if not _ensure_esptool():
        GPIO.cleanup()
        return 1

    _ensure_fw_dir()

    port = None
    chip = None
    offset_idx = 0
    sel = 0
    page_offset = 0
    max_visible = 4 if IS_WIDE else 5
    last_btn = 0
    state = "main"

    ports = _detect_serial()
    if ports:
        port = ports[0]
        _show_status("Detecting chip...", C_YELLOW)
        chip = _detect_chip(port)

    firmwares = _list_firmwares()
    _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)

    while _running:
        btn = _get_btn()
        now = time.time()

        if state == "main":
            if btn == "KEY3":
                break

            if btn == "KEY1" and now - last_btn > DEBOUNCE:
                last_btn = now
                if not port:
                    _show_status("Scanning USB...", C_YELLOW)
                    ports = _detect_serial()
                    if ports:
                        port = ports[0]
                        _show_status("Detecting chip...", C_YELLOW)
                        chip = _detect_chip(port)
                    else:
                        _show_status("No device found", C_RED)
                        time.sleep(1.5)
                else:
                    _show_status("Erasing flash...", C_ORANGE)
                    ok = _erase_flash(port, lambda p: None)
                    if ok:
                        _show_status("Erase complete!", C_GREEN)
                    else:
                        _show_status("Erase failed!", C_RED)
                    time.sleep(1.5)
                firmwares = _list_firmwares()
                _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)
                continue

            if btn == "KEY2" and now - last_btn > DEBOUNCE:
                last_btn = now
                offset_idx = (offset_idx + 1) % len(OFFSETS)
                _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)

            if btn == "LEFT" and now - last_btn > DEBOUNCE:
                last_btn = now
                _show_download_menu(chip)
                firmwares = _list_firmwares()
                sel = 0
                page_offset = 0
                _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)
                continue

            if btn == "RIGHT" and now - last_btn > DEBOUNCE and port:
                last_btn = now
                _serial_monitor(port)
                _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)
                continue

            if btn == "OK" and now - last_btn > DEBOUNCE and firmwares and port:
                last_btn = now
                state = "confirm"
                _draw_confirm(
                    os.path.basename(firmwares[sel]), port, OFFSETS[offset_idx])
                continue

            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                if firmwares:
                    sel = (sel - 1) % len(firmwares)
                    if sel < page_offset:
                        page_offset = sel
                    elif sel >= page_offset + max_visible:
                        page_offset = sel - max_visible + 1
                    _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)

            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                if firmwares:
                    sel = (sel + 1) % len(firmwares)
                    if sel >= page_offset + max_visible:
                        page_offset = sel - max_visible + 1
                    elif sel < page_offset:
                        page_offset = sel
                    _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)

            if not btn:
                time.sleep(0.05)

        elif state == "confirm":
            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                fw_path = firmwares[sel]
                fw_name = os.path.basename(fw_path)

                def _progress(pct):
                    _draw_progress(fw_name, pct)



                _draw_progress(fw_name, 0)
                ok, output = _flash_firmware(
                    port, fw_path, OFFSETS[offset_idx], _progress)
                if ok:
                    _show_status("Flash OK!", C_GREEN)
                else:
                    _show_status("Flash FAILED!", C_RED)
                time.sleep(2)
                state = "main"
                _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)

            if btn == "KEY3" and now - last_btn > DEBOUNCE:
                last_btn = now
                state = "main"
                _draw_main(port, chip, firmwares, sel, offset_idx, page_offset)

            if not btn:
                time.sleep(0.05)

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
