#!/usr/bin/env python3
"""
RaspyJack Payload -- WPA Handshake Quality Checker
====================================================
Author: 7h30th3r0n3

Lists .cap and .pcap capture files from the loot directory, then analyses
selected files for WPA handshake quality using aircrack-ng and tcpdump.
Rates each handshake as GOOD / PARTIAL / BAD based on EAPOL message
presence and aircrack-ng output.

Controls:
  UP / DOWN  -- Scroll file list / results
  OK         -- Analyse selected file
  KEY1       -- Refresh file list
  KEY2       -- Export report to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/HandshakeQuality/report_<timestamp>.json
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
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
ROWS_VISIBLE = 6
LOOT_SCAN_DIR = "/root/Raspyjack/loot"
LOOT_DIR = "/root/Raspyjack/loot/HandshakeQuality"

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
analysing = False
status_msg = "Scanning files..."

# List of {"path": str, "name": str, "size_kb": int}
cap_files = []

# Analysis result for the currently selected file
# {"essid": str, "handshakes": int, "quality": str, "packet_count": int,
#  "eapol_info": str, "rating_color": str}
analysis_result = None


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

def _find_cap_files():
    """Recursively find .cap and .pcap files under the loot directory."""
    found = []
    if not os.path.isdir(LOOT_SCAN_DIR):
        return found

    for root, _dirs, files in os.walk(LOOT_SCAN_DIR):
        # Skip our own output directory
        if "HandshakeQuality" in root:
            continue
        for fname in sorted(files):
            lower = fname.lower()
            if lower.endswith(".cap") or lower.endswith(".pcap"):
                full = os.path.join(root, fname)
                try:
                    size_kb = os.path.getsize(full) // 1024
                except OSError:
                    size_kb = 0
                found.append({
                    "path": full,
                    "name": fname,
                    "size_kb": size_kb,
                })
    return found


# ---------------------------------------------------------------------------
# Analysis logic
# ---------------------------------------------------------------------------

def _run_aircrack(filepath):
    """Run aircrack-ng and parse output for handshake info."""
    essid = ""
    handshake_count = 0
    eapol_info = "none"

    try:
        result = subprocess.run(
            ["aircrack-ng", "-a2", "-w", "/dev/null", filepath],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout + result.stderr

        # Look for ESSID
        essid_match = re.search(r"ESSID\s*:\s*(.+)", output)
        if not essid_match:
            essid_match = re.search(r"(\S+)\s+\(.*handshake", output, re.IGNORECASE)
        if essid_match:
            essid = essid_match.group(1).strip()

        # Count handshakes found
        hs_match = re.search(r"(\d+)\s+handshake", output, re.IGNORECASE)
        if hs_match:
            handshake_count = int(hs_match.group(1))

        # Check for EAPOL messages
        if "4 of 4" in output or "4/4" in output:
            eapol_info = "4/4 EAPOL (complete)"
        elif "3 of 4" in output or "3/4" in output:
            eapol_info = "3/4 EAPOL (usable)"
        elif "2 of 4" in output or "2/4" in output:
            eapol_info = "2/4 EAPOL (partial)"
        elif "1 of 4" in output or "1/4" in output:
            eapol_info = "1/4 EAPOL (insufficient)"
        elif handshake_count > 0:
            eapol_info = "handshake present"
        else:
            # Check if WPA was detected at all
            if "WPA" in output:
                eapol_info = "WPA detected, no HS"
            else:
                eapol_info = "no WPA data"

    except FileNotFoundError:
        eapol_info = "aircrack-ng not found"
    except subprocess.TimeoutExpired:
        eapol_info = "analysis timeout"
    except Exception as exc:
        eapol_info = f"error: {str(exc)[:20]}"

    return essid, handshake_count, eapol_info


def _count_packets(filepath):
    """Count packets in a capture file using tcpdump."""
    try:
        result = subprocess.run(
            ["tcpdump", "-r", filepath, "-c", "100"],
            capture_output=True, text=True, timeout=10,
            stderr=subprocess.DEVNULL,
        )
        count = len(result.stdout.splitlines())
        return count
    except Exception:
        return 0


def _rate_quality(handshake_count, eapol_info):
    """Return (quality_label, color) based on analysis results."""
    if handshake_count > 0 and ("4/4" in eapol_info or "complete" in eapol_info):
        return "GOOD", "#00FF00"
    if handshake_count > 0 and ("3/4" in eapol_info or "usable" in eapol_info):
        return "GOOD", "#00FF00"
    if handshake_count > 0 and ("present" in eapol_info):
        return "GOOD", "#00FF00"
    if "2/4" in eapol_info or "partial" in eapol_info:
        return "PARTIAL", "#FFAA00"
    if handshake_count > 0:
        return "PARTIAL", "#FFAA00"
    return "BAD", "#FF4444"


def _analyse_thread(filepath):
    """Run full analysis in a background thread."""
    global analysing, analysis_result, status_msg

    with lock:
        analysing = True
        analysis_result = None
        status_msg = "Analysing..."

    essid, hs_count, eapol_info = _run_aircrack(filepath)
    pkt_count = _count_packets(filepath)
    quality, color = _rate_quality(hs_count, eapol_info)

    with lock:
        analysis_result = {
            "file": os.path.basename(filepath),
            "filepath": filepath,
            "essid": essid if essid else "(unknown)",
            "handshakes": hs_count,
            "quality": quality,
            "packet_count": pkt_count,
            "eapol_info": eapol_info,
            "rating_color": color,
        }
        analysing = False
        status_msg = f"{quality}: {essid[:14]}" if essid else f"{quality}"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_report():
    """Export analysis report to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with lock:
        data = {
            "timestamp": ts,
            "result": dict(analysis_result) if analysis_result else {},
        }
    # Remove non-serialisable color field
    if "rating_color" in data.get("result", {}):
        result_copy = dict(data["result"])
        del result_copy["rating_color"]
        data["result"] = result_copy

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filename


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, font_obj, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:22], font=font_obj, fill="#00CCFF")


def _draw_footer(d, font_obj, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font_obj, fill="#888")


def _draw_file_list(lcd, font_obj, selected, scroll):
    """Draw the capture file list screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, font_obj, "HANDSHAKE CHECK")

    with lock:
        msg = status_msg
        files = list(cap_files)

    d.text((2, 16), msg[:24], font=font_obj, fill="#AAAAAA")

    if not files:
        d.text((2, 40), "No .cap/.pcap found", font=font_obj, fill="#FF4444")
        d.text((2, 54), f"in {LOOT_SCAN_DIR}", font=font_obj, fill="#666")
        d.text((2, 72), "KEY1: Refresh", font=font_obj, fill="#666")
    else:
        visible = files[scroll:scroll + ROWS_VISIBLE]
        for i, entry in enumerate(visible):
            y = 28 + i * ROW_H
            idx = scroll + i
            marker = ">" if idx == selected else " "
            color = "#FFAA00" if idx == selected else "#CCCCCC"
            label = f"{marker}{entry['name'][:17]} {entry['size_kb']}K"
            d.text((2, y), label[:24], font=font_obj, fill=color)

    _draw_footer(d, font_obj, f"{len(files)} files  OK:Scan K3:Ex")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_result_screen(lcd, font_obj):
    """Draw the analysis result screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, font_obj, "ANALYSIS RESULT")

    with lock:
        res = dict(analysis_result) if analysis_result else None
        is_busy = analysing

    if is_busy:
        d.text((2, 50), "Analysing...", font=font_obj, fill="#FFAA00")
        d.ellipse((118, 3, 122, 7), fill="#00FF00")
    elif res:
        quality_color = res.get("rating_color", "#CCCCCC")

        # Quality rating (large)
        d.text((2, 18), f"Quality: {res['quality']}", font=font_obj, fill=quality_color)

        # ESSID
        d.text((2, 34), f"ESSID: {res['essid'][:16]}", font=font_obj, fill="#CCCCCC")

        # Handshake count
        d.text((2, 48), f"Handshakes: {res['handshakes']}", font=font_obj, fill="#CCCCCC")

        # EAPOL info
        d.text((2, 62), res["eapol_info"][:24], font=font_obj, fill="#AAAAAA")

        # Packet count
        d.text((2, 76), f"Packets (100): {res['packet_count']}", font=font_obj, fill="#888")

        # File name
        d.text((2, 92), res["file"][:24], font=font_obj, fill="#666")
    else:
        d.text((2, 50), "No result", font=font_obj, fill="#666")

    _draw_footer(d, font_obj, "OK:Back K2:Export K3:Ex")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, cap_files, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    # Initial scan
    cap_files = _find_cap_files()
    status_msg = f"Found {len(cap_files)} captures"

    selected = 0
    scroll = 0
    mode = "list"  # "list" or "result"

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if mode == "list":
                if btn == "UP":
                    selected = max(0, selected - 1)
                    if selected < scroll:
                        scroll = selected
                    time.sleep(0.15)
                elif btn == "DOWN":
                    max_sel = max(0, len(cap_files) - 1)
                    selected = min(selected + 1, max_sel)
                    if selected >= scroll + ROWS_VISIBLE:
                        scroll = selected - ROWS_VISIBLE + 1
                    time.sleep(0.15)
                elif btn == "OK":
                    if cap_files and 0 <= selected < len(cap_files):
                        filepath = cap_files[selected]["path"]
                        threading.Thread(
                            target=_analyse_thread,
                            args=(filepath,),
                            daemon=True,
                        ).start()
                        mode = "result"
                        time.sleep(0.3)
                elif btn == "KEY1":
                    cap_files = _find_cap_files()
                    with lock:
                        status_msg = f"Found {len(cap_files)} captures"
                    selected = 0
                    scroll = 0
                    time.sleep(0.3)

                _draw_file_list(lcd, font_obj, selected, scroll)

            elif mode == "result":
                if btn == "OK":
                    mode = "list"
                    time.sleep(0.3)
                elif btn == "KEY2":
                    with lock:
                        has_result = analysis_result is not None
                    if has_result:
                        fname = _export_report()
                        with lock:
                            status_msg = f"Saved: {fname[:18]}"
                    time.sleep(0.3)

                _draw_result_screen(lcd, font_obj)

            time.sleep(0.05)

    finally:
        _running = False
        time.sleep(0.2)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
