#!/usr/bin/env python3
"""
RaspyJack Payload -- HCCAPX Converter for Hashcat
====================================================
Author: 7h30th3r0n3

Convert .cap capture files to .hc22000 format for Hashcat cracking.
Uses hcxpcapngtool (preferred) or falls back to cap2hccapx.

Controls
--------
  UP / DOWN  -- Scroll file list
  OK         -- Convert selected file
  KEY1       -- Batch convert all files
  KEY3       -- Exit

Input:  /root/Raspyjack/loot/ (recursive .cap files)
Output: /root/Raspyjack/loot/Hashcat/
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
OUTPUT_DIR = os.path.join(LOOT_DIR, "Hashcat")
os.makedirs(OUTPUT_DIR, exist_ok=True)
ROW_H = 12
DEBOUNCE = 0.20
VISIBLE_ROWS = 7

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
app_running = True
cap_files = []
selected_idx = 0
scroll_pos = 0
view_mode = "list"          # list | converting | result
status_msg = "Loading..."
convert_result = {}
batch_progress = 0
batch_total = 0
tool_name = ""              # hcxpcapngtool or cap2hccapx


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------
def _detect_tool():
    """Detect available conversion tool."""
    for tool in ("hcxpcapngtool", "cap2hccapx"):
        try:
            result = subprocess.run(
                ["which", tool], capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return tool
        except Exception:
            pass
    return ""


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
def _find_cap_files():
    """Recursively find .cap files in loot directory."""
    found = []
    for root, _dirs, files in os.walk(LOOT_DIR):
        if root.startswith(OUTPUT_DIR):
            continue
        for fname in sorted(files):
            if fname.lower().endswith((".cap", ".pcap", ".pcapng")):
                full_path = os.path.join(root, fname)
                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    size = 0
                found.append({"path": full_path, "name": fname, "size": size})
    return found


def _fmt_size(size_bytes):
    """Format file size."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes // 1024}K"
    return f"{size_bytes // (1024 * 1024)}M"


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------
def _count_hashes(output_path):
    """Count hash lines in output file."""
    try:
        with open(output_path, "r") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


def _convert_file(input_path, tool):
    """Convert a single capture file."""
    basename = os.path.splitext(os.path.basename(input_path))[0]

    if tool == "hcxpcapngtool":
        output_path = os.path.join(OUTPUT_DIR, f"{basename}.hc22000")
        args = ["hcxpcapngtool", "-o", output_path, input_path]
    elif tool == "cap2hccapx":
        output_path = os.path.join(OUTPUT_DIR, f"{basename}.hccapx")
        args = ["cap2hccapx", input_path, output_path]
    else:
        return {"success": False, "error": "No tool available",
                "input": os.path.basename(input_path)}

    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=60,
        )
        success = result.returncode == 0 or os.path.isfile(output_path)
    except Exception as exc:
        return {"success": False, "error": str(exc),
                "input": os.path.basename(input_path),
                "hash_count": 0, "output": ""}

    hash_count = 0
    output_file = ""
    if os.path.isfile(output_path):
        output_size = os.path.getsize(output_path)
        if output_size > 0:
            hash_count = _count_hashes(output_path)
            output_file = os.path.basename(output_path)
            success = True
        else:
            # Empty output means no handshakes found
            os.remove(output_path)
            success = False

    return {
        "success": success,
        "input": os.path.basename(input_path),
        "output": output_file,
        "hash_count": hash_count,
        "error": "" if success else "No handshakes",
    }


def _convert_single(file_entry):
    """Convert single file in background."""
    global view_mode, status_msg, convert_result
    with lock:
        view_mode = "converting"
        status_msg = f"Converting {file_entry['name'][:14]}..."

    result = _convert_file(file_entry["path"], tool_name)
    with lock:
        convert_result = result
        view_mode = "result"
        if result["success"]:
            status_msg = f"{result['hash_count']} hash(es)"
        else:
            status_msg = result.get("error", "Failed")


def _convert_batch():
    """Convert all files in background."""
    global view_mode, status_msg, convert_result
    global batch_progress, batch_total

    with lock:
        files = list(cap_files)
        batch_total = len(files)
        batch_progress = 0
        view_mode = "converting"

    succeeded = 0
    failed = 0
    total_hashes = 0

    for entry in files:
        if not app_running:
            break
        with lock:
            batch_progress += 1
            status_msg = f"{batch_progress}/{batch_total}"

        result = _convert_file(entry["path"], tool_name)
        if result["success"]:
            succeeded += 1
            total_hashes += result.get("hash_count", 0)
        else:
            failed += 1

    with lock:
        convert_result = {
            "success": True,
            "batch": True,
            "succeeded": succeeded,
            "failed": failed,
            "total": batch_total,
            "hash_count": total_hashes,
        }
        view_mode = "result"
        status_msg = f"{succeeded} ok {total_hashes} hashes"


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------
def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "HCCAPX CONV", font=font, fill="#00ccff")

    with lock:
        vm = view_mode
        sel = selected_idx
        sp = scroll_pos
        msg = status_msg
        files = list(cap_files)
        res = dict(convert_result)
        bp = batch_progress
        bt = batch_total

    if vm == "list":
        # Show tool name
        t_label = tool_name[:10] if tool_name else "NO TOOL"
        t_color = "#00ff00" if tool_name else "#ff4444"
        d.text((2, 14), t_label, font=font, fill=t_color)

        y = 26
        if not files:
            d.text((2, 50), "No .cap files", font=font, fill="#888888")
        else:
            end = min(len(files), sp + VISIBLE_ROWS - 1)
            for i in range(sp, end):
                f = files[i]
                prefix = ">" if i == sel else " "
                color = "#ffff00" if i == sel else "#cccccc"
                label = f"{prefix}{f['name'][:14]} {_fmt_size(f['size'])}"
                d.text((2, y), label[:22], font=font, fill=color)
                y += ROW_H

        d.text((2, 104), msg[:22], font=font, fill="#888888")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:conv K1:all K3:x", font=font, fill="#666")

    elif vm == "converting":
        d.text((2, 40), "Converting...", font=font, fill="#ffaa00")
        d.text((2, 56), msg[:22], font=font, fill="#cccccc")
        if bt > 0:
            pct = int(bp * 100 / bt)
            d.rectangle((10, 74, 118, 86), outline="#444")
            bar_w = int(106 * pct / 100)
            if bar_w > 0:
                d.rectangle((11, 75, 11 + bar_w, 85), fill="#00ff00")

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
            y += ROW_H
            d.text((2, y), f"Hashes: {res.get('hash_count', 0)}", font=font,
                   fill="#00ccff")
        else:
            ok = res.get("success", False)
            color = "#00ff00" if ok else "#ff4444"
            d.text((2, y), "OK" if ok else "FAILED", font=font, fill=color)
            y += ROW_H + 2
            d.text((2, y), res.get("input", "")[:22], font=font,
                   fill="#cccccc")
            y += ROW_H
            if ok:
                d.text((2, y), res.get("output", "")[:22], font=font,
                       fill="#00ff00")
                y += ROW_H
                d.text((2, y), f"Hashes: {res.get('hash_count', 0)}",
                       font=font, fill="#00ccff")
            else:
                d.text((2, y), res.get("error", "")[:22], font=font,
                       fill="#ff4444")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:back K3:exit", font=font, fill="#666")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global app_running, selected_idx, scroll_pos, view_mode
    global cap_files, status_msg, tool_name

    tool_name = _detect_tool()
    cap_files = _find_cap_files()
    status_msg = f"{len(cap_files)} file(s)"
    if not tool_name:
        status_msg = "No converter found!"
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
                    if view_mode == "result":
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
                        if selected_idx >= scroll_pos + VISIBLE_ROWS - 1:
                            scroll_pos = selected_idx - VISIBLE_ROWS + 2

            elif btn == "OK":
                with lock:
                    vm = view_mode
                    sel = selected_idx
                if vm == "list" and cap_files and tool_name:
                    threading.Thread(
                        target=_convert_single,
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
                if view_mode == "list" and cap_files and tool_name:
                    threading.Thread(
                        target=_convert_batch, daemon=True,
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
