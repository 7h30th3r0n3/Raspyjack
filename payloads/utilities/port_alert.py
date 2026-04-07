#!/usr/bin/env python3
"""
RaspyJack Payload -- New Port Alert Monitor
=============================================
Author: 7h30th3r0n3

Periodically scans the local subnet with nmap and compares results
against a stored baseline.  Alerts when new open ports are discovered.

Controls
--------
  UP / DOWN  -- Scroll through hosts / ports
  OK         -- Show host details
  KEY1       -- Force rescan
  KEY2       -- Export results to loot
  KEY3       -- Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
DEBOUNCE = 0.22
LOOT_DIR = "/root/Raspyjack/loot/PortAlert"
BASELINE_PATH = os.path.join(LOOT_DIR, "baseline.json")
SCAN_INTERVAL = 120  # seconds between auto-scans


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_running = True
_scanning = False
_lock = threading.Lock()
_baseline = {}   # {"host": {"ports": [int, ...], "first_seen": str}}
_new_finds = []  # [{"host": str, "port": int, "service": str, "ts": str}]
_status_msg = ""
_scan_count = 0


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Subnet detection
# ---------------------------------------------------------------------------

def _get_subnet():
    """Detect local subnet from ip route."""
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            # Match lines like: 192.168.1.0/24 dev wlan0 ...
            match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+\S+", line)
            if match and not line.startswith("default"):
                return match.group(1)
    except Exception:
        pass
    return "192.168.1.0/24"


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

def _load_baseline():
    """Load baseline from disk."""
    if not os.path.isfile(BASELINE_PATH):
        return {}
    try:
        with open(BASELINE_PATH, "r") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_baseline(baseline):
    """Save baseline to disk."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(BASELINE_PATH, "w") as fh:
        json.dump(baseline, fh, indent=2)


# ---------------------------------------------------------------------------
# Nmap scanning
# ---------------------------------------------------------------------------

def _parse_nmap_output(output):
    """Parse nmap text output, return {host: [{"port": int, "service": str}]}."""
    results = {}
    current_host = None
    for line in output.splitlines():
        host_match = re.search(r"Nmap scan report for\s+(\S+)", line)
        if host_match:
            current_host = host_match.group(1)
            results[current_host] = []
            continue
        if current_host is None:
            continue
        port_match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S*)", line)
        if port_match:
            results[current_host].append({
                "port": int(port_match.group(1)),
                "service": port_match.group(3) or "unknown",
            })
    return results


def _run_scan(subnet):
    """Run nmap scan and return parsed results."""
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-F", "--open", "-T4", subnet],
            capture_output=True, text=True, timeout=120,
        )
        return _parse_nmap_output(result.stdout)
    except Exception:
        return {}


def _compare_with_baseline(scan_results, baseline):
    """Compare scan results with baseline, return list of new findings."""
    new_finds = []
    ts = datetime.now().strftime("%H:%M:%S")
    for host, port_entries in scan_results.items():
        known_ports = set()
        if host in baseline:
            known_ports = set(baseline[host].get("ports", []))
        for entry in port_entries:
            if entry["port"] not in known_ports:
                new_finds.append({
                    "host": host,
                    "port": entry["port"],
                    "service": entry["service"],
                    "ts": ts,
                })
    return new_finds


def _update_baseline(scan_results, baseline):
    """Return new baseline incorporating scan results."""
    updated = dict(baseline)
    ts = datetime.now().isoformat()
    for host, port_entries in scan_results.items():
        ports = [e["port"] for e in port_entries]
        if host in updated:
            existing = set(updated[host].get("ports", []))
            updated[host] = dict(updated[host])
            updated[host]["ports"] = sorted(existing | set(ports))
        else:
            updated[host] = {"ports": sorted(ports), "first_seen": ts}
    return updated


def _scan_thread(subnet):
    """Background scan thread."""
    global _scanning, _baseline, _new_finds, _status_msg, _scan_count
    with _lock:
        _status_msg = "Scanning..."
    scan_results = _run_scan(subnet)
    with _lock:
        new = _compare_with_baseline(scan_results, _baseline)
        _new_finds = new + _new_finds
        if len(_new_finds) > 200:
            _new_finds = _new_finds[:200]
        _baseline = _update_baseline(scan_results, _baseline)
        _save_baseline(_baseline)
        _scan_count += 1
        host_count = len(scan_results)
        _status_msg = f"Done: {host_count}h {len(new)}new"
        _scanning = False


def _start_scan(subnet):
    """Start a background nmap scan."""
    global _scanning
    if _scanning:
        return
    _scanning = True
    t = threading.Thread(target=_scan_thread, args=(subnet,), daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_results(baseline, new_finds):
    """Export current data to loot."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"port_scan_{ts}.json")
    data = {
        "timestamp": datetime.now().isoformat(),
        "baseline_hosts": len(baseline),
        "new_findings": new_finds,
        "baseline": baseline,
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_main(lcd, font, baseline, new_finds, cursor, scroll, scanning, status):
    """Draw the main port alert view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    label = "SCANNING..." if scanning else "PORT ALERT"
    d.text((2, 1), label, font=font, fill="#00CCFF")
    d.text((88, 1), f"{len(baseline)}h", font=font, fill="#FFAA00")

    # New findings list
    visible = 7
    y = 16

    if not new_finds:
        d.text((4, 35), "No new ports found", font=font, fill="#666")
        d.text((4, 50), "K1 to scan", font=font, fill="#888")
        total_ports = sum(len(v.get("ports", [])) for v in baseline.values())
        d.text((4, 70), f"Baseline: {len(baseline)} hosts", font=font, fill="#555")
        d.text((4, 82), f"Known ports: {total_ports}", font=font, fill="#555")
    else:
        end = min(len(new_finds), scroll + visible)
        for idx in range(scroll, end):
            entry = new_finds[idx]
            is_sel = idx == cursor
            prefix = ">" if is_sel else " "
            host_short = entry["host"].split(".")[-1]
            line_text = f"{prefix}{host_short}:{entry['port']}/{entry['service'][:6]}"
            color = "#FF4444" if is_sel else "#FFAA00"
            d.text((2, y), line_text[:22], font=font, fill=color)
            y += ROW_H

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if status:
        d.text((2, 117), status[:22], font=font, fill="#FFFF00")
    else:
        d.text((2, 117), "K1:scan K2:exp K3:exit", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_detail(lcd, font, entry, baseline):
    """Draw detail view for a finding."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "NEW PORT FOUND", font=font, fill="#FF4444")

    y = 20
    d.text((2, y), "Host:", font=font, fill="#888")
    y += ROW_H
    d.text((4, y), entry["host"][:20], font=font, fill="#00FF00")
    y += ROW_H + 4
    d.text((2, y), f"Port: {entry['port']}", font=font, fill="#FFAA00")
    y += ROW_H + 2
    d.text((2, y), f"Service: {entry['service']}", font=font, fill="#CCCCCC")
    y += ROW_H + 2
    d.text((2, y), f"Found: {entry['ts']}", font=font, fill="#888")

    # Show all known ports for this host
    host_data = baseline.get(entry["host"], {})
    known = host_data.get("ports", [])
    if known:
        y += ROW_H + 4
        ports_str = ",".join(str(p) for p in known[:8])
        d.text((2, y), f"All: {ports_str}", font=font, fill="#555")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "Any key = back", font=font, fill="#AAA")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, _status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()

    with _lock:
        _baseline.update(_load_baseline())

    subnet = _get_subnet()
    _status_msg = f"Subnet: {subnet}"

    cursor = 0
    scroll = 0
    last_press = 0.0
    last_scan_time = 0.0
    mode = "list"  # list | detail
    visible = 7

    # Initial scan
    _start_scan(subnet)

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "detail":
                if btn:
                    mode = "list"
                    time.sleep(0.1)
                    continue

            if btn == "KEY3":
                break
            elif btn == "KEY1":
                _start_scan(subnet)
                last_scan_time = now
            elif btn == "KEY2":
                with _lock:
                    bl_copy = dict(_baseline)
                    nf_copy = list(_new_finds)
                if bl_copy:
                    try:
                        _export_results(bl_copy, nf_copy)
                        _status_msg = "Exported!"
                    except Exception as exc:
                        _status_msg = f"Err:{str(exc)[:14]}"
                else:
                    _status_msg = "No data"
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
            elif btn == "DOWN":
                with _lock:
                    max_idx = max(0, len(_new_finds) - 1)
                cursor = min(max_idx, cursor + 1)
                if cursor >= scroll + visible:
                    scroll = cursor - visible + 1
            elif btn == "OK":
                with _lock:
                    if _new_finds and cursor < len(_new_finds):
                        entry = dict(_new_finds[cursor])
                        bl_snap = dict(_baseline)
                _draw_detail(lcd, font, entry, bl_snap)
                mode = "detail"
                time.sleep(0.1)
                continue

            # Auto-rescan
            if not _scanning and (now - last_scan_time) > SCAN_INTERVAL:
                _start_scan(subnet)
                last_scan_time = now

            with _lock:
                bl_snap = dict(_baseline)
                nf_snap = list(_new_finds)
                status_snap = _status_msg

            _draw_main(lcd, font, bl_snap, nf_snap, cursor, scroll,
                       _scanning, status_snap)
            time.sleep(0.08)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
