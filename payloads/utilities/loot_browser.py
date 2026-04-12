#!/usr/bin/env python3
"""
RaspyJack Payload -- Loot Browser
----------------------------------
Author: 7h30th3r0n3
Fixed: Hosseios

Browse /root/Raspyjack/loot/ on the LCD.

Controls:
  UP/DOWN  = navigate files/dirs or scroll preview
  OK       = enter directory or preview file
  LEFT     = go up one directory
  KEY1     = show stats (file count, total size)
  KEY2     = delete selected file (with confirmation)
  KEY3     = exit
"""

import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

LOOT_ROOT = "/root/Raspyjack/loot"
DEBOUNCE = 0.25

# Chars per line depends on screen resolution
_SCALE = getattr(LCD_1in44, "LCD_SCALE", 1.0)
CHARS_PER_LINE = int(20 * _SCALE)  # 20 on 128, ~37 on 240


def _fmt_size(nbytes):
    for unit in ("B", "K", "M", "G"):
        if nbytes < 1024:
            return f"{nbytes}{unit}"
        nbytes //= 1024
    return f"{nbytes}T"


def _list_dir(path):
    entries = []
    try:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            is_dir = os.path.isdir(full)
            try:
                size = os.path.getsize(full) if not is_dir else 0
            except OSError:
                size = 0
            entries.append({"name": name, "is_dir": is_dir, "size": size, "path": full})
    except OSError:
        pass
    return entries


def _dir_stats(path):
    total_files = 0
    total_size = 0
    try:
        for root, dirs, files in os.walk(path):
            total_files += len(files)
            for f in files:
                try:
                    total_size += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except OSError:
        pass
    return total_files, total_size


def _is_text_file(path):
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(512)
            if b"\x00" in chunk:
                return False
            return True
    except OSError:
        return False


def _preview_text(path, max_lines=1000):
    lines = []
    try:
        with open(path, "r", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\n"))
    except OSError:
        lines.append("(read error)")
    return lines


def _file_type_label(path):
    ext = os.path.splitext(path)[1].lower()
    type_map = {
        ".txt": "TEXT", ".log": "LOG", ".csv": "CSV",
        ".json": "JSON", ".xml": "XML", ".pcap": "PCAP",
        ".cap": "CAP", ".png": "IMG", ".jpg": "IMG",
        ".py": "PY", ".sh": "SHELL", ".conf": "CONF",
    }
    return type_map.get(ext, "BIN")


def _draw_browser(lcd, cwd, entries, cursor, scroll_offset, status=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    rel_path = cwd.replace(LOOT_ROOT, "loot") if cwd.startswith(LOOT_ROOT) else cwd
    max_path = CHARS_PER_LINE - 4
    if len(rel_path) > max_path:
        rel_path = "..." + rel_path[-(max_path - 3):]

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((2, 1), rel_path, font=font, fill="#00ff00")
    d.text((110, 1), "K3", font=font, fill="white")

    y = 15
    visible = 7
    start = scroll_offset
    end = min(len(entries), start + visible)

    if not entries:
        d.text((4, 30), "(empty)", font=font, fill="#666666")
    else:
        for idx in range(start, end):
            entry = entries[idx]
            is_cursor = idx == cursor
            prefix = ">" if is_cursor else " "
            if entry["is_dir"]:
                label = f"{prefix}[{entry['name'][:CHARS_PER_LINE - 3]}]"
                color = "#00aaff" if is_cursor else "#5588bb"
            else:
                size_str = _fmt_size(entry["size"])
                name_max = CHARS_PER_LINE - 2 - len(size_str)
                name_short = entry["name"][:name_max]
                label = f"{prefix}{name_short} {size_str}"
                color = "#00ff00" if is_cursor else "#aaaaaa"
            d.text((2, y), label[:CHARS_PER_LINE], font=font, fill=color)
            y += 13

    y = 106
    d.line((0, y, 127, y), fill="#333333")
    d.text((2, y + 2), "OK=open <-=up", font=font, fill="#666666")
    d.text((2, y + 13), "K1=stat K2=del", font=font, fill="#666666")

    if status:
        d.rectangle((0, 50, 127, 75), fill="#222200")
        d.text((2, 55), status[:CHARS_PER_LINE], font=font, fill="#ffff00")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_preview(lcd, path, lines, h_offset=0):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    name = os.path.basename(path)
    max_name = CHARS_PER_LINE - 2
    if len(name) > max_name:
        name = name[:max_name - 3] + "..."
    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((2, 1), name, font=font, fill="#00ff00")

    y = 16
    for line in lines:
        display = line[h_offset:h_offset + CHARS_PER_LINE]
        d.text((2, y), display, font=font, fill="#cccccc")
        y += 12

    # Scroll indicator
    hint = "U/D:scroll L/R:pan"
    if h_offset > 0:
        hint = f"<{h_offset} " + hint
    d.text((2, 116), hint[:CHARS_PER_LINE], font=font, fill="#666666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_confirm(lcd, filename):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 30), "Delete file?", font=font, fill="#ff4444")
    name = filename[:CHARS_PER_LINE]
    d.text((10, 48), name, font=font, fill="#aaaaaa")
    d.text((10, 70), "OK = Yes", font=font, fill="#00ff00")
    d.text((10, 85), "Any = Cancel", font=font, fill="#666666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_stats(lcd, path, file_count, total_size):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 20), "Loot Stats", font=font, fill="#00ff00")
    d.text((10, 40), f"Files: {file_count}", font=font, fill="white")
    d.text((10, 55), f"Size:  {_fmt_size(total_size)}", font=font, fill="white")
    rel = path.replace(LOOT_ROOT, "loot")
    if len(rel) > CHARS_PER_LINE:
        rel = "..." + rel[-(CHARS_PER_LINE - 3):]
    d.text((10, 75), rel, font=font, fill="#888888")
    d.text((10, 100), "Any key=back", font=font, fill="#666666")
    lcd.LCD_ShowImage(img, 0, 0)


def main():
    if not os.path.isdir(LOOT_ROOT):
        try:
            os.makedirs(LOOT_ROOT, exist_ok=True)
        except OSError:
            pass

    cwd = LOOT_ROOT
    entries = _list_dir(cwd)
    cursor = 0
    scroll_offset = 0
    status = ""
    last_press = 0.0
    visible = 7

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # Browse mode
            if btn == "KEY3":
                break
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll_offset:
                    scroll_offset = cursor
                status = ""
            elif btn == "DOWN":
                cursor = min(max(0, len(entries) - 1), cursor + 1)
                if cursor >= scroll_offset + visible:
                    scroll_offset = cursor - visible + 1
                status = ""
            elif btn == "LEFT":
                if cwd != LOOT_ROOT:
                    cwd = os.path.dirname(cwd)
                    entries = _list_dir(cwd)
                    cursor = 0
                    scroll_offset = 0
                    status = ""
            elif btn == "OK" and entries:
                entry = entries[cursor]
                if entry["is_dir"]:
                    cwd = entry["path"]
                    entries = _list_dir(cwd)
                    cursor = 0
                    scroll_offset = 0
                    status = ""
                else:
                    # Scrollable preview
                    if _is_text_file(entry["path"]):
                        lines = _preview_text(entry["path"], max_lines=1000)
                    else:
                        ftype = _file_type_label(entry["path"])
                        lines = [
                            f"Type: {ftype}",
                            f"Size: {_fmt_size(entry['size'])}",
                            "",
                            "(binary file)",
                        ]
                    scroll_offset_preview = 0
                    h_offset = 0
                    max_display = 8
                    while True:
                        visible_lines = lines[scroll_offset_preview:scroll_offset_preview+max_display]
                        _draw_preview(LCD, entry["path"], visible_lines, h_offset)
                        btn_preview = get_button(PINS, GPIO)
                        if btn_preview == "UP":
                            scroll_offset_preview = max(0, scroll_offset_preview - 1)
                        elif btn_preview == "DOWN":
                            scroll_offset_preview = min(max(0, len(lines)-max_display), scroll_offset_preview + 1)
                        elif btn_preview == "RIGHT":
                            h_offset += 10
                        elif btn_preview == "LEFT":
                            h_offset = max(0, h_offset - 10)
                        elif btn_preview == "KEY3":
                            break
                        elif btn_preview:
                            break
                        time.sleep(0.05)

            elif btn == "KEY1":
                fc, ts = _dir_stats(cwd)
                _draw_stats(LCD, cwd, fc, ts)
                while True:
                    btn_stats = get_button(PINS, GPIO)
                    if btn_stats:
                        break
                    time.sleep(0.05)

            elif btn == "KEY2" and entries:
                entry = entries[cursor]
                if not entry["is_dir"]:
                    _draw_confirm(LCD, entry["name"])
                    while True:
                        btn_confirm = get_button(PINS, GPIO)
                        if btn_confirm == "OK":
                            try:
                                os.remove(entry["path"])
                                status = "Deleted!"
                            except OSError as exc:
                                status = f"Err: {str(exc)[:14]}"
                            entries = _list_dir(cwd)
                            cursor = min(cursor, max(0, len(entries) - 1))
                            break
                        elif btn_confirm:
                            status = "Cancelled"
                            break
                        time.sleep(0.05)
                else:
                    status = "Can't del dirs"

            _draw_browser(LCD, cwd, entries, cursor, scroll_offset, status)
            time.sleep(0.08)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
