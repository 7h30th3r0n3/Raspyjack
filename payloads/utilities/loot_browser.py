#!/usr/bin/env python3
"""
RaspyJack Payload -- Loot Browser
----------------------------------
Author: 7h30th3r0n3

Browse /root/Raspyjack/loot/ on the LCD.

Controls:
  UP/DOWN  = navigate files/dirs
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


def _fmt_size(nbytes):
    """Format byte count to human-readable."""
    for unit in ("B", "K", "M", "G"):
        if nbytes < 1024:
            return f"{nbytes}{unit}"
        nbytes //= 1024
    return f"{nbytes}T"


def _list_dir(path):
    """List directory, returning sorted entries as (name, is_dir, size)."""
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
    """Compute total file count and size recursively."""
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
    """Heuristic check if file is text."""
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(512)
            if b"\x00" in chunk:
                return False
            return True
    except OSError:
        return False


def _preview_text(path, max_lines=8):
    """Read first max_lines lines of a text file."""
    lines = []
    try:
        with open(path, "r", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\n")[:20])
    except OSError:
        lines.append("(read error)")
    return lines


def _file_type_label(path):
    """Return a short file type label."""
    ext = os.path.splitext(path)[1].lower()
    type_map = {
        ".txt": "TEXT", ".log": "LOG", ".csv": "CSV",
        ".json": "JSON", ".xml": "XML", ".pcap": "PCAP",
        ".cap": "CAP", ".png": "IMG", ".jpg": "IMG",
        ".py": "PY", ".sh": "SHELL", ".conf": "CONF",
    }
    return type_map.get(ext, "BIN")


def _draw_browser(lcd, cwd, entries, cursor, scroll_offset, status=""):
    """Draw file browser UI."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    rel_path = cwd.replace(LOOT_ROOT, "loot") if cwd.startswith(LOOT_ROOT) else cwd
    if len(rel_path) > 16:
        rel_path = "..." + rel_path[-13:]

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
                label = f"{prefix}[{entry['name'][:13]}]"
                color = "#00aaff" if is_cursor else "#5588bb"
            else:
                size_str = _fmt_size(entry["size"])
                name_max = 14 - len(size_str)
                name_short = entry["name"][:name_max]
                label = f"{prefix}{name_short} {size_str}"
                color = "#00ff00" if is_cursor else "#aaaaaa"

            d.text((2, y), label[:20], font=font, fill=color)
            y += 13

    y = 106
    d.line((0, y, 127, y), fill="#333333")
    d.text((2, y + 2), "OK=open <-=up", font=font, fill="#666666")
    d.text((2, y + 13), "K1=stat K2=del", font=font, fill="#666666")

    if status:
        d.rectangle((0, 50, 127, 75), fill="#222200")
        d.text((2, 55), status[:20], font=font, fill="#ffff00")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_preview(lcd, path, lines):
    """Draw a file preview screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    name = os.path.basename(path)
    if len(name) > 18:
        name = name[:15] + "..."

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((2, 1), name, font=font, fill="#00ff00")

    y = 16
    for line in lines:
        d.text((2, y), line[:20], font=font, fill="#cccccc")
        y += 12

    d.text((2, 116), "Any key=back", font=font, fill="#666666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_confirm(lcd, filename):
    """Draw delete confirmation dialog."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.text((10, 30), "Delete file?", font=font, fill="#ff4444")
    name = filename[:18]
    d.text((10, 48), name, font=font, fill="#aaaaaa")
    d.text((10, 70), "OK = Yes", font=font, fill="#00ff00")
    d.text((10, 85), "Any = Cancel", font=font, fill="#666666")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_stats(lcd, path, file_count, total_size):
    """Draw stats overlay."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.text((10, 20), "Loot Stats", font=font, fill="#00ff00")
    d.text((10, 40), f"Files: {file_count}", font=font, fill="white")
    d.text((10, 55), f"Size:  {_fmt_size(total_size)}", font=font, fill="white")

    rel = path.replace(LOOT_ROOT, "loot")
    if len(rel) > 18:
        rel = "..." + rel[-15:]
    d.text((10, 75), rel, font=font, fill="#888888")
    d.text((10, 100), "Any key=back", font=font, fill="#666666")

    lcd.LCD_ShowImage(img, 0, 0)


def main():
    """Main entry point."""
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
    mode = "browse"  # browse | preview | confirm | stats

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "preview" or mode == "stats":
                if btn:
                    mode = "browse"
                    time.sleep(0.1)
                    continue

            elif mode == "confirm":
                if btn == "OK":
                    entry = entries[cursor]
                    try:
                        os.remove(entry["path"])
                        status = "Deleted!"
                    except OSError as exc:
                        status = f"Err: {str(exc)[:14]}"
                    entries = _list_dir(cwd)
                    cursor = min(cursor, max(0, len(entries) - 1))
                    mode = "browse"
                elif btn:
                    status = "Cancelled"
                    mode = "browse"
                _draw_browser(LCD, cwd, entries, cursor, scroll_offset, status)
                time.sleep(0.08)
                continue

            elif mode == "browse":
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
                        if _is_text_file(entry["path"]):
                            lines = _preview_text(entry["path"], max_lines=8)
                        else:
                            ftype = _file_type_label(entry["path"])
                            lines = [
                                f"Type: {ftype}",
                                f"Size: {_fmt_size(entry['size'])}",
                                "",
                                "(binary file)",
                            ]
                        _draw_preview(LCD, entry["path"], lines)
                        mode = "preview"
                        time.sleep(0.08)
                        continue
                elif btn == "KEY1":
                    fc, ts = _dir_stats(cwd)
                    _draw_stats(LCD, cwd, fc, ts)
                    mode = "stats"
                    time.sleep(0.08)
                    continue
                elif btn == "KEY2" and entries:
                    entry = entries[cursor]
                    if not entry["is_dir"]:
                        _draw_confirm(LCD, entry["name"])
                        mode = "confirm"
                        time.sleep(0.08)
                        continue
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
