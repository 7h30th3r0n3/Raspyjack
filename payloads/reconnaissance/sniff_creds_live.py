#!/usr/bin/env python3
"""
RaspyJack Payload -- Credential Aggregator Dashboard
======================================================
Author: 7h30th3r0n3

Scans all loot directories for captured credentials: Responder logs,
HTTP creds, cracked NTLM, cracked WPA, Telnet captures, credential
sniffing, SSDP, Captive Portal, and Enterprise Evil Twin.  Parses
each file format and presents a unified scrollable credential list on
the LCD.

Auto-refreshes every 10 seconds.

Setup / Prerequisites
---------------------
- Various RaspyJack attack payloads populate loot directories.
- Read access to /root/Raspyjack/loot/ and /root/Raspyjack/Responder/logs/.

Controls
--------
  OK          -- Refresh now
  UP / DOWN   -- Scroll credential list
  KEY1        -- Filter by protocol (cycle)
  KEY2        -- Export unified CSV
  KEY3        -- Exit
"""

import os
import sys
import time
import re
import csv
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot/CredDashboard"
os.makedirs(LOOT_DIR, exist_ok=True)

SCAN_DIRS = {
    "Responder":   "/root/Raspyjack/Responder/logs",
    "HTTPCreds":   "/root/Raspyjack/loot/HTTPCreds",
    "CrackedNTLM": "/root/Raspyjack/loot/CrackedNTLM",
    "CrackedWPA":  "/root/Raspyjack/loot/CrackedWPA",
    "Telnet":      "/root/Raspyjack/loot/Telnet",
    "CredSniff":   "/root/Raspyjack/loot/CredSniff",
    "SSDP":        "/root/Raspyjack/loot/SSDP",
    "CaptivePortal": "/root/Raspyjack/loot/CaptivePortal",
    "EvilTwin":    "/root/Raspyjack/loot/EvilTwin",
    "EnterpriseTwin": "/root/Raspyjack/loot/EnterpriseEvilTwin",
}

PROTOCOLS = ["ALL", "NTLM", "HTTP", "WPA", "Telnet", "SSDP", "Other"]
DEBOUNCE = 0.22
REFRESH_INTERVAL = 10

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "creds": [],          # list of dicts: protocol, user, secret, source
    "status": "Idle",
    "scanning": False,
    "scroll": 0,
    "filter_idx": 0,
    "last_refresh": 0.0,
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, list):
            return list(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# Parsers for each loot source
# ---------------------------------------------------------------------------
def _parse_responder(directory):
    """Parse Responder log files for NTLM hashes and cleartext creds."""
    creds = []
    if not os.path.isdir(directory):
        return creds
    for fname in os.listdir(directory):
        fpath = os.path.join(directory, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # NTLMv2: user::domain:challenge:hash:hash
                    if "::" in line and len(line.split(":")) >= 5:
                        parts = line.split(":")
                        user = parts[0]
                        secret = line[:60]
                        creds.append({
                            "protocol": "NTLM",
                            "user": user,
                            "secret": secret,
                            "source": f"Responder/{fname}",
                        })
                    # Cleartext: [TYPE] user:password
                    m = re.match(r"\[(.+?)\]\s+(.+?):(.+)", line)
                    if m:
                        proto = m.group(1).upper()
                        creds.append({
                            "protocol": proto,
                            "user": m.group(2),
                            "secret": m.group(3),
                            "source": f"Responder/{fname}",
                        })
        except Exception:
            pass
    return creds


def _parse_keyvalue_files(directory, protocol, source_prefix):
    """Parse files with user:password or user=password format."""
    creds = []
    if not os.path.isdir(directory):
        return creds
    for fname in os.listdir(directory):
        fpath = os.path.join(directory, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for sep in [":", "=", "\t"]:
                        if sep in line:
                            parts = line.split(sep, 1)
                            if len(parts) == 2 and parts[0] and parts[1]:
                                creds.append({
                                    "protocol": protocol,
                                    "user": parts[0].strip()[:40],
                                    "secret": parts[1].strip()[:60],
                                    "source": f"{source_prefix}/{fname}",
                                })
                            break
        except Exception:
            pass
    return creds


def _parse_wpa_files(directory):
    """Parse cracked WPA files (usually SSID:password format)."""
    return _parse_keyvalue_files(directory, "WPA", "CrackedWPA")


def _parse_json_creds(directory, protocol, source_prefix):
    """Parse JSON files containing credential objects."""
    import json
    creds = []
    if not os.path.isdir(directory):
        return creds
    for fname in os.listdir(directory):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(directory, fname)
        try:
            with open(fpath, "r", errors="ignore") as f:
                data = json.load(f)
            items = data if isinstance(data, list) else [data]
            for item in items:
                if isinstance(item, dict):
                    user = (item.get("user") or item.get("username")
                            or item.get("login") or "?")
                    secret = (item.get("password") or item.get("pass")
                              or item.get("hash") or item.get("key") or "?")
                    creds.append({
                        "protocol": protocol,
                        "user": str(user)[:40],
                        "secret": str(secret)[:60],
                        "source": f"{source_prefix}/{fname}",
                    })
        except Exception:
            pass
    return creds


def _parse_captive_portal(directory):
    """Parse captive portal captures (HTML form data)."""
    creds = []
    if not os.path.isdir(directory):
        return creds
    for fname in os.listdir(directory):
        fpath = os.path.join(directory, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", errors="ignore") as f:
                content = f.read()
            # Look for common form fields
            users = re.findall(
                r"(?:user(?:name)?|email|login)\s*[=:]\s*(.+?)[\r\n&]",
                content, re.IGNORECASE,
            )
            passwords = re.findall(
                r"(?:pass(?:word)?|pwd|key)\s*[=:]\s*(.+?)[\r\n&]",
                content, re.IGNORECASE,
            )
            for i in range(max(len(users), len(passwords))):
                user = users[i].strip() if i < len(users) else "?"
                secret = passwords[i].strip() if i < len(passwords) else "?"
                creds.append({
                    "protocol": "HTTP",
                    "user": user[:40],
                    "secret": secret[:60],
                    "source": f"CaptivePortal/{fname}",
                })
        except Exception:
            pass
    return creds


# ---------------------------------------------------------------------------
# Refresh / scan
# ---------------------------------------------------------------------------
def _do_refresh():
    _set(scanning=True, status="Scanning loot dirs...")

    all_creds = []

    all_creds.extend(_parse_responder(SCAN_DIRS["Responder"]))
    all_creds.extend(
        _parse_keyvalue_files(SCAN_DIRS["HTTPCreds"], "HTTP", "HTTPCreds"))
    all_creds.extend(
        _parse_keyvalue_files(SCAN_DIRS["CrackedNTLM"], "NTLM", "CrackedNTLM"))
    all_creds.extend(_parse_wpa_files(SCAN_DIRS["CrackedWPA"]))
    all_creds.extend(
        _parse_keyvalue_files(SCAN_DIRS["Telnet"], "Telnet", "Telnet"))
    all_creds.extend(
        _parse_keyvalue_files(SCAN_DIRS["CredSniff"], "Other", "CredSniff"))
    all_creds.extend(
        _parse_json_creds(SCAN_DIRS["SSDP"], "SSDP", "SSDP"))
    all_creds.extend(_parse_captive_portal(SCAN_DIRS["CaptivePortal"]))
    all_creds.extend(
        _parse_keyvalue_files(SCAN_DIRS["EvilTwin"], "HTTP", "EvilTwin"))

    # Dedup by (protocol, user, secret)
    seen = set()
    unique = []
    for c in all_creds:
        key = (c["protocol"], c["user"], c["secret"])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    _set(creds=unique, scanning=False, last_refresh=time.time(),
         status=f"Found {len(unique)} credentials")


def _start_refresh():
    if _get("scanning"):
        return
    threading.Thread(target=_do_refresh, daemon=True).start()


# ---------------------------------------------------------------------------
# Export CSV
# ---------------------------------------------------------------------------
def _export_csv():
    creds = _get("creds")
    if not creds:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"creds_{ts}.csv")
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["protocol", "user", "secret", "source"])
        writer.writeheader()
        for c in creds:
            writer.writerow(c)
    return path


# ---------------------------------------------------------------------------
# Filtered view
# ---------------------------------------------------------------------------
def _filtered_creds():
    """Return creds filtered by current protocol filter."""
    creds = _get("creds")
    filt = PROTOCOLS[_get("filter_idx")]
    if filt == "ALL":
        return creds
    return [c for c in creds if c["protocol"].upper() == filt.upper()]


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    scroll = _get("scroll")
    status = _get("status")
    scanning = _get("scanning")
    filt = PROTOCOLS[_get("filter_idx")]

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "CRED DASHBOARD", font=font, fill="#FF4444")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if scanning else "#666")

    filtered = _filtered_creds()
    total = len(_get("creds"))

    # Stats bar
    y = 14
    d.text((2, y), f"Total: {total}  Filter: {filt}", font=font, fill="#AAAAAA")
    y += 13

    if not filtered:
        d.text((4, y + 20), "No credentials found", font=font, fill="#666")
        d.text((4, y + 34), "OK=Refresh", font=font, fill="#666")
    else:
        visible = 6
        for i in range(scroll, min(scroll + visible, len(filtered))):
            c = filtered[i]
            sel = (i == scroll)
            fg = "#00FF00" if sel else "#AAAAAA"
            proto_color = {
                "NTLM": "#FF6600", "HTTP": "#00AAFF",
                "WPA": "#FF00FF", "Telnet": "#FFFF00",
            }.get(c["protocol"], "#888888")

            d.text((2, y), c["protocol"][:5], font=font, fill=proto_color)
            d.text((32, y), c["user"][:14], font=font, fill=fg)
            y += 10
            secret_display = c["secret"][:20]
            d.text((4, y), secret_display, font=font, fill="#888")
            y += 12

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK K1:flt K2:csv K3:x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), line1[:21], font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "CRED DASHBOARD", font=font, fill="#FF4444")
    d.text((4, 32), "Credential aggregator", font=font, fill="#888")
    d.text((4, 52), "OK=Refresh  K1=Filter", font=font, fill="#666")
    d.text((4, 64), "K2=Export CSV", font=font, fill="#666")
    d.text((4, 76), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    _start_refresh()
    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # Auto-refresh
            if now - _get("last_refresh") > REFRESH_INTERVAL:
                _start_refresh()

            if btn == "KEY3":
                break

            elif btn == "OK":
                _start_refresh()

            elif btn == "KEY1":
                idx = _get("filter_idx")
                _set(filter_idx=(idx + 1) % len(PROTOCOLS), scroll=0)

            elif btn == "KEY2":
                path = _export_csv()
                if path:
                    _show_msg("Exported!", path[-20:])
                else:
                    _show_msg("No creds to export")

            elif btn == "UP":
                s = _get("scroll")
                _set(scroll=max(0, s - 1))

            elif btn == "DOWN":
                s = _get("scroll")
                filtered = _filtered_creds()
                _set(scroll=min(max(0, len(filtered) - 1), s + 1))

            _draw_lcd()
            time.sleep(0.05)

    finally:
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
