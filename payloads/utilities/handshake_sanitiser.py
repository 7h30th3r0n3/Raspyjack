#!/usr/bin/env python3
"""
RaspyJack Payload -- Handshake File Sanitizer
================================================
Author: 7h30th3r0n3

Strip irrelevant frames from capture files, keeping only EAPOL
handshake packets and beacon frames needed for cracking.

Uses tshark to filter: ``eapol || wlan.fc.type_subtype == 0x08``

Controls
--------
  UP / DOWN  -- Scroll file list
  OK         -- Sanitize selected file
  KEY1       -- Batch process all files
  KEY3       -- Exit

Input:  /root/Raspyjack/loot/ (recursive .cap/.pcap/.pcapng)
Output: /root/Raspyjack/loot/Handshakes_Clean/
"""

import os
import sys
import time
import signal
import subprocess
import threading
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
LOOT_DIR = "/root/Raspyjack/loot"
OUTPUT_DIR = os.path.join(LOOT_DIR, "Handshakes_Clean")
os.makedirs(OUTPUT_DIR, exist_ok=True)
EXTENSIONS = (".cap", ".pcap", ".pcapng")
TSHARK_FILTER = "eapol || wlan.fc.type_subtype == 0x08"
ROW_H = 12
DEBOUNCE = 0.20
VISIBLE_ROWS = 7

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
app_running = True
cap_files = []              # [{"path": ..., "name": ..., "size": ...}]
selected_idx = 0
scroll_pos = 0
view_mode = "list"          # list | processing | result
status_msg = "Loading..."
process_result = {}         # dict with result info
batch_progress = 0
batch_total = 0


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
def _find_cap_files():
    """Recursively find capture files in loot directory."""
    found = []
    for root, _dirs, files in os.walk(LOOT_DIR):
        # Skip output directory
        if root.startswith(OUTPUT_DIR):
            continue
        for fname in sorted(files):
            if fname.lower().endswith(EXTENSIONS):
                full_path = os.path.join(root, fname)
                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    size = 0
                found.append({
                    "path": full_path,
                    "name": fname,
                    "size": size,
                })
    return found


def _fmt_size(size_bytes):
    """Format file size for display."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes // 1024}K"
    return f"{size_bytes // (1024 * 1024)}M"


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------
def _count_packets(filepath, display_filter=None):
    """Count packets in a capture file, optionally with a filter."""
    args = ["tshark", "-r", filepath, "-T", "fields", "-e", "frame.number"]
    if display_filter:
        args.extend(["-Y", display_filter])
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=60,
        )
        lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
        return len(lines)
    except Exception:
        return 0


def _sanitize_file(input_path):
    """Sanitize a single capture file, return result dict."""
    basename = os.path.basename(input_path)
    name_no_ext = os.path.splitext(basename)[0]
    output_path = os.path.join(OUTPUT_DIR, f"{name_no_ext}_clean.pcap")

    input_size = 0
    try:
        input_size = os.path.getsize(input_path)
    except OSError:
        pass

    # Run tshark filter
    args = [
        "tshark", "-r", input_path,
        "-Y", TSHARK_FILTER,
        "-w", output_path,
    ]
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=120,
        )
        success = result.returncode == 0
    except Exception as exc:
        return {
            "success": False,
            "input": basename,
            "error": str(exc),
            "input_size": input_size,
            "output_size": 0,
            "total_pkts": 0,
            "eapol_pkts": 0,
        }

    output_size = 0
    if success and os.path.isfile(output_path):
        try:
            output_size = os.path.getsize(output_path)
        except OSError:
            pass

    # Count packets
    total_pkts = _count_packets(input_path)
    eapol_pkts = _count_packets(input_path, "eapol")

    return {
        "success": success,
        "input": basename,
        "output": os.path.basename(output_path),
        "input_size": input_size,
        "output_size": output_size,
        "total_pkts": total_pkts,
        "eapol_pkts": eapol_pkts,
    }


def _process_single(file_entry):
    """Process a single file in background."""
    global view_mode, status_msg, process_result
    with lock:
        view_mode = "processing"
        status_msg = f"Processing {file_entry['name'][:16]}..."

    result = _sanitize_file(file_entry["path"])

    with lock:
        process_result = result
        view_mode = "result"
        status_msg = "Done" if result["success"] else "Failed"


def _process_batch():
    """Process all files in background."""
    global view_mode, status_msg, process_result, batch_progress, batch_total
    with lock:
        files = list(cap_files)
        batch_total = len(files)
        batch_progress = 0
        view_mode = "processing"

    succeeded = 0
    failed = 0
    for entry in files:
        if not app_running:
            break
        with lock:
            batch_progress += 1
            status_msg = f"{batch_progress}/{batch_total} {entry['name'][:12]}"

        result = _sanitize_file(entry["path"])
        if result["success"]:
            succeeded += 1
        else:
            failed += 1

    with lock:
        process_result = {
            "success": True,
            "batch": True,
            "succeeded": succeeded,
            "failed": failed,
            "total": batch_total,
        }
        view_mode = "result"
        status_msg = f"Batch: {succeeded} ok, {failed} fail"


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------
def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "HANDSHAKE CLEAN", font=font, fill="#00ccff")

    with lock:
        vm = view_mode
        sel = selected_idx
        sp = scroll_pos
        msg = status_msg
        files = list(cap_files)
        res = dict(process_result)
        bp = batch_progress
        bt = batch_total

    if vm == "list":
        y = 16
        if not files:
            d.text((2, 50), "No capture files", font=font, fill="#888888")
        else:
            end = min(len(files), sp + VISIBLE_ROWS)
            for i in range(sp, end):
                f = files[i]
                prefix = ">" if i == sel else " "
                color = "#ffff00" if i == sel else "#cccccc"
                label = f"{prefix}{f['name'][:15]} {_fmt_size(f['size'])}"
                d.text((2, y), label[:22], font=font, fill=color)
                y += ROW_H

        d.text((2, 104), msg[:22], font=font, fill="#888888")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:clean K1:all K3:x", font=font, fill="#666")

    elif vm == "processing":
        d.text((2, 40), "Sanitizing...", font=font, fill="#ffaa00")
        d.text((2, 56), msg[:22], font=font, fill="#cccccc")
        if bt > 0:
            pct = int(bp * 100 / bt)
            d.rectangle((10, 74, 118, 86), outline="#444")
            bar_w = int(106 * pct / 100)
            if bar_w > 0:
                d.rectangle((11, 75, 11 + bar_w, 85), fill="#00ff00")
            d.text((50, 62), f"{pct}%", font=font, fill="#ffffff")

    elif vm == "result":
        y = 18
        if res.get("batch"):
            d.text((2, y), "Batch Complete", font=font, fill="#00ff00")
            y += ROW_H + 2
            d.text((2, y), f"Total: {res.get('total', 0)}", font=font,
                   fill="#cccccc")
            y += ROW_H
            d.text((2, y), f"Success: {res.get('succeeded', 0)}", font=font,
                   fill="#00ff00")
            y += ROW_H
            d.text((2, y), f"Failed: {res.get('failed', 0)}", font=font,
                   fill="#ff4444")
        else:
            ok = res.get("success", False)
            color = "#00ff00" if ok else "#ff4444"
            d.text((2, y), "OK" if ok else "FAILED", font=font, fill=color)
            y += ROW_H + 2
            d.text((2, y), f"In: {_fmt_size(res.get('input_size', 0))}",
                   font=font, fill="#cccccc")
            y += ROW_H
            d.text((2, y), f"Out: {_fmt_size(res.get('output_size', 0))}",
                   font=font, fill="#cccccc")
            y += ROW_H
            d.text((2, y), f"Pkts: {res.get('total_pkts', 0)}",
                   font=font, fill="#cccccc")
            y += ROW_H
            d.text((2, y), f"EAPOL: {res.get('eapol_pkts', 0)}",
                   font=font, fill="#00ccff")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:back K3:exit", font=font, fill="#666")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global app_running, selected_idx, scroll_pos, view_mode
    global cap_files, status_msg

    cap_files = _find_cap_files()
    status_msg = f"{len(cap_files)} file(s) found"
    last_press = 0.0

    try:
        while app_running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                with lock:
                    if view_mode in ("result",):
                        view_mode = "list"
                        btn = None
                    else:
                        break

            if btn == "UP":
                with lock:
                    if view_mode == "list":
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx

            elif btn == "DOWN":
                with lock:
                    if view_mode == "list":
                        selected_idx = min(len(cap_files) - 1,
                                           selected_idx + 1)
                        if selected_idx >= scroll_pos + VISIBLE_ROWS:
                            scroll_pos = selected_idx - VISIBLE_ROWS + 1

            elif btn == "OK":
                with lock:
                    vm = view_mode
                    sel = selected_idx
                if vm == "list" and cap_files:
                    threading.Thread(
                        target=_process_single,
                        args=(cap_files[sel],),
                        daemon=True,
                    ).start()
                elif vm == "result":
                    cap_files = _find_cap_files()
                    with lock:
                        view_mode = "list"
                        selected_idx = 0
                        scroll_pos = 0
                        status_msg = f"{len(cap_files)} file(s)"

            elif btn == "KEY1":
                with lock:
                    if view_mode == "list" and cap_files:
                        pass
                if view_mode == "list" and cap_files:
                    threading.Thread(
                        target=_process_batch, daemon=True,
                    ).start()

            _draw_screen()
            time.sleep(0.1)

    finally:
        app_running = False
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
