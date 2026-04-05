#!/usr/bin/env python3
"""
RaspyJack Payload -- Engagement Log Cleaner
--------------------------------------------
Author: 7h30th3r0n3

Selective cleanup of forensic artifacts after an engagement.
Protects /root/Raspyjack/loot/ (operator data).

Controls:
  UP/DOWN  = scroll items
  OK       = toggle item for cleaning
  KEY1     = clean selected items
  KEY2     = clean ALL items
  KEY3     = exit
"""

import os
import sys
import time
import subprocess

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

DEBOUNCE = 0.25

CLEAN_ITEMS = [
    {"name": "bash_history", "label": "Bash History"},
    {"name": "journal", "label": "System Journal"},
    {"name": "dhcp_leases", "label": "DHCP Leases"},
    {"name": "arp_cache", "label": "ARP Cache"},
    {"name": "dns_cache", "label": "DNS Cache"},
    {"name": "tmp_files", "label": "Tmp Files"},
    {"name": "auth_logs", "label": "Auth Logs"},
]


def _run(cmd):
    """Run a shell command, return (returncode, output)."""
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            shell=isinstance(cmd, str),
        )
        return res.returncode, res.stdout.strip()
    except Exception as exc:
        return 1, str(exc)


def _clean_item(item_name):
    """Clean a single item. Returns (success, message)."""
    if item_name == "bash_history":
        targets = [
            os.path.expanduser("~/.bash_history"),
            "/root/.bash_history",
            os.path.expanduser("~/.zsh_history"),
        ]
        cleaned = 0
        for path in targets:
            if os.path.isfile(path):
                rc, _ = _run(["shred", "-fzu", path])
                if rc == 0:
                    cleaned += 1
        return True, f"Shredded {cleaned} files"

    elif item_name == "journal":
        rc, out = _run(["journalctl", "--vacuum-size=1M"])
        return rc == 0, "Journal vacuumed" if rc == 0 else out[:40]

    elif item_name == "dhcp_leases":
        leases = [
            "/var/lib/dhcp/dhclient.leases",
            "/var/lib/dhcpcd/dhcpcd-eth0.lease",
            "/var/lib/dhcpcd/dhcpcd-wlan0.lease",
            "/var/lib/dhcpcd5/dhcpcd-eth0.lease",
            "/var/lib/dhcpcd5/dhcpcd-wlan0.lease",
        ]
        cleaned = 0
        for path in leases:
            if os.path.isfile(path):
                rc, _ = _run(["shred", "-fzu", path])
                if rc == 0:
                    cleaned += 1
        return True, f"Cleared {cleaned} leases"

    elif item_name == "arp_cache":
        rc, _ = _run(["ip", "neigh", "flush", "all"])
        return rc == 0, "ARP flushed" if rc == 0 else "ARP flush failed"

    elif item_name == "dns_cache":
        rc, _ = _run(["systemctl", "restart", "systemd-resolved"])
        if rc != 0:
            rc, _ = _run(["resolvectl", "flush-caches"])
        return True, "DNS cache cleared"

    elif item_name == "tmp_files":
        cleaned = 0
        for tmp_dir in ["/tmp", "/var/tmp"]:
            if not os.path.isdir(tmp_dir):
                continue
            try:
                for entry in os.listdir(tmp_dir):
                    full = os.path.join(tmp_dir, entry)
                    if os.path.isfile(full):
                        try:
                            os.remove(full)
                            cleaned += 1
                        except OSError:
                            pass
            except OSError:
                pass
        return True, f"Removed {cleaned} tmp files"

    elif item_name == "auth_logs":
        targets = [
            "/var/log/auth.log",
            "/var/log/auth.log.1",
            "/var/log/secure",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/lastlog",
        ]
        cleaned = 0
        for path in targets:
            if os.path.isfile(path):
                rc, _ = _run(["shred", "-fzu", path])
                if rc == 0:
                    cleaned += 1
        return True, f"Shredded {cleaned} logs"

    return False, "Unknown item"


def _draw_checklist(lcd, items, selected_items, cursor, scroll_offset, status=""):
    """Draw the checklist UI."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((2, 1), "Log Cleaner", font=font, fill="#00ff00")
    d.text((100, 1), "K3", font=font, fill="white")

    y = 15
    visible = 7
    start = scroll_offset
    end = min(len(items), start + visible)

    for idx in range(start, end):
        item = items[idx]
        is_cursor = idx == cursor
        is_checked = idx in selected_items
        prefix = ">" if is_cursor else " "
        check = "[X]" if is_checked else "[ ]"
        color = "#00ff00" if is_cursor else "#aaaaaa"
        text = f"{prefix}{check} {item['label']}"
        d.text((2, y), text[:20], font=font, fill=color)
        y += 13

    y = max(y + 2, 106)
    d.line((0, y - 2, 127, y - 2), fill="#333333")
    d.text((2, y), "OK=tog K1=sel K2=all", font=font, fill="#666666")

    if status:
        d.text((2, y + 11), status[:20], font=font, fill="#ffff00")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_progress(lcd, message, progress, total):
    """Draw a progress screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.text((4, 20), "Cleaning...", font=font, fill="#00ff00")
    d.text((4, 40), message[:20], font=font, fill="#aaaaaa")

    bar_x, bar_y = 10, 65
    bar_w, bar_h = 108, 12
    d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), outline="#00ff00")
    if total > 0:
        fill_w = int(bar_w * progress / total)
        d.rectangle((bar_x, bar_y, bar_x + fill_w, bar_y + bar_h), fill="#00ff00")

    pct = int(100 * progress / total) if total > 0 else 0
    d.text((50, bar_y + 16), f"{pct}%", font=font, fill="white")

    lcd.LCD_ShowImage(img, 0, 0)


def _clean_selected(lcd, items, selected_indices):
    """Clean all selected items, showing progress."""
    total = len(selected_indices)
    results = []
    for i, idx in enumerate(sorted(selected_indices)):
        item = items[idx]
        _draw_progress(lcd, item["label"], i, total)
        ok, msg = _clean_item(item["name"])
        results.append((item["label"], ok, msg))
        time.sleep(0.3)

    _draw_progress(lcd, "Done!", total, total)
    time.sleep(0.8)
    return results


def main():
    """Main entry point."""
    cursor = 0
    selected_items = set()
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

            if btn == "KEY3":
                break
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll_offset:
                    scroll_offset = cursor
            elif btn == "DOWN":
                cursor = min(len(CLEAN_ITEMS) - 1, cursor + 1)
                if cursor >= scroll_offset + visible:
                    scroll_offset = cursor - visible + 1
            elif btn == "OK":
                if cursor in selected_items:
                    selected_items = selected_items - {cursor}
                else:
                    selected_items = selected_items | {cursor}
            elif btn == "KEY1":
                if selected_items:
                    _clean_selected(LCD, CLEAN_ITEMS, selected_items)
                    selected_items = set()
                    status = "Cleaned selected!"
                else:
                    status = "Nothing selected"
            elif btn == "KEY2":
                all_indices = set(range(len(CLEAN_ITEMS)))
                _clean_selected(LCD, CLEAN_ITEMS, all_indices)
                selected_items = set()
                status = "All cleaned!"

            _draw_checklist(
                LCD, CLEAN_ITEMS, selected_items, cursor, scroll_offset, status,
            )
            time.sleep(0.08)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
