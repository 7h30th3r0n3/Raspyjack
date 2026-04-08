#!/usr/bin/env python3
"""
RaspyJack Payload -- ICMP Ping Alert Monitor
==============================================
Author: 7h30th3r0n3

Monitors incoming ICMP echo requests via tcpdump and alerts on the LCD
when a ping is received.  Shows source IP, timestamp, and a running
counter of total pings.

Controls
--------
  UP / DOWN  -- Scroll through ping sources
  KEY1       -- Start / stop monitoring
  KEY2       -- Export ping log to loot
  KEY3       -- Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
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
LOOT_DIR = "/root/Raspyjack/loot/ICMPAlert"

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_running = True
_monitoring = False
_mon_proc = None
_lock = threading.Lock()
_ping_log = []  # [{"src": str, "ts": str}]
_total_count = 0


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# ICMP monitoring
# ---------------------------------------------------------------------------

def _parse_tcpdump_line(line):
    """Extract source IP from tcpdump ICMP echo request line."""
    # Typical: 12:34:56.789 IP 192.168.1.5 > 192.168.1.1: ICMP echo request ...
    if "echo request" not in line.lower():
        return None
    parts = line.split()
    for i, part in enumerate(parts):
        if part == ">" and i > 0:
            candidate = parts[i - 1]
            # Strip trailing dots or colons
            candidate = candidate.rstrip(".:")
            # Validate looks like an IP
            segments = candidate.split(".")
            if len(segments) >= 4:
                return candidate
    return None


def _monitor_thread():
    """Background thread capturing ICMP echo requests."""
    global _mon_proc, _monitoring, _total_count
    try:
        _mon_proc = subprocess.Popen(
            ["tcpdump", "-i", "any", "-n", "-l", "icmp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        _monitoring = False
        return

    try:
        while _monitoring and _running and _mon_proc.poll() is None:
            line = _mon_proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            src = _parse_tcpdump_line(line)
            if src is None:
                continue
            ts = datetime.now().strftime("%H:%M:%S")
            with _lock:
                _total_count += 1
                _ping_log.append({"src": src, "ts": ts})
                # Keep last 200 entries
                if len(_ping_log) > 200:
                    _ping_log.pop(0)
    except Exception:
        pass
    finally:
        _stop_monitor_proc()


def _stop_monitor_proc():
    """Terminate tcpdump subprocess."""
    global _mon_proc
    if _mon_proc is not None:
        try:
            _mon_proc.terminate()
            _mon_proc.wait(timeout=3)
        except Exception:
            try:
                _mon_proc.kill()
            except Exception:
                pass
        _mon_proc = None


def _start_monitor():
    """Start ICMP monitoring."""
    global _monitoring
    if _monitoring:
        return
    _monitoring = True
    t = threading.Thread(target=_monitor_thread, daemon=True)
    t.start()


def _stop_monitor():
    """Stop ICMP monitoring."""
    global _monitoring
    _monitoring = False
    _stop_monitor_proc()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_log(log, total):
    """Export ping log to loot."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"icmp_{ts}.json")
    data = {
        "timestamp": datetime.now().isoformat(),
        "total_pings": total,
        "entries": log,
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_main(lcd, font, log, total, cursor, scroll, monitoring, status):
    """Draw the main ICMP monitor view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    label = "MONITORING" if monitoring else "ICMP ALERT"
    d.text((2, 1), label, font=font, fill="#00CCFF")
    d.text((90, 1), f"#{total}", font=font, fill="#FFAA00")

    # Ping list (most recent first)
    visible = 7
    y = 16
    reversed_log = list(reversed(log))
    end = min(len(reversed_log), scroll + visible)

    if not reversed_log:
        d.text((4, 40), "No pings received", font=font, fill="#666")
        d.text((4, 55), "K1 to start", font=font, fill="#888")
    else:
        for idx in range(scroll, end):
            entry = reversed_log[idx]
            is_sel = idx == cursor
            prefix = ">" if is_sel else " "
            ip_short = entry["src"][:15]
            color = "#00FF00" if is_sel else "#AAAAAA"
            d.text((2, y), f"{prefix}{entry['ts']}", font=font, fill="#888")
            d.text((52, y), ip_short, font=font, fill=color)
            y += ROW_H

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if status:
        d.text((2, 117), status[:22], font=font, fill="#FFFF00")
    else:
        d.text((2, 117), "K1:mon K2:exp K3:exit", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, _total_count

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()

    cursor = 0
    scroll = 0
    status = ""
    last_press = 0.0
    visible = 7

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break
            elif btn == "KEY1":
                if _monitoring:
                    _stop_monitor()
                    status = "Stopped"
                else:
                    _start_monitor()
                    status = "Monitoring..."
            elif btn == "KEY2":
                with _lock:
                    log_copy = list(_ping_log)
                    total = _total_count
                if log_copy:
                    try:
                        _export_log(log_copy, total)
                        status = "Exported!"
                    except Exception as exc:
                        status = f"Err:{str(exc)[:14]}"
                else:
                    status = "No data"
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                status = ""
            elif btn == "DOWN":
                with _lock:
                    max_idx = max(0, len(_ping_log) - 1)
                cursor = min(max_idx, cursor + 1)
                if cursor >= scroll + visible:
                    scroll = cursor - visible + 1
                status = ""

            with _lock:
                log_snap = list(_ping_log)
                total_snap = _total_count

            _draw_main(lcd, font, log_snap, total_snap, cursor, scroll,
                       _monitoring, status)
            time.sleep(0.08)

    finally:
        _stop_monitor()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
