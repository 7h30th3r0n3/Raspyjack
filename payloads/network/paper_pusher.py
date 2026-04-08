#!/usr/bin/env python3
"""
RaspyJack Payload -- Network Printer Prank
============================================
Author: 7h30th3r0n3

Discovers network printers via nmap and sends text jobs via raw TCP
(JetDirect port 9100).  For authorized penetration testing only.

Setup / Prerequisites
---------------------
- nmap installed.
- Network access to target printers.
- IMPORTANT: For authorized pentesting only.

Controls
--------
  UP / DOWN   -- Navigate printer list / character picker
  OK          -- Select printer
  KEY1        -- Send test page to selected printer
  KEY2        -- Send custom text / confirm text input
  KEY3        -- Exit / Back

Loot: (none, output only)
"""

import os
import sys
import time
import json
import socket
import subprocess
import threading

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

DEBOUNCE = 0.22
ROW_H = 12
VISIBLE_ROWS = 6
CHARSET = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789 .,!?-_:;()@#"
)

lock = threading.Lock()
_printers = []       # [{"ip": ..., "port": ..., "info": ...}]
_status_msg = "Ready"
_jobs_sent = 0
_scanning = False


def _get_subnet():
    """Detect the local subnet."""
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                r2 = subprocess.run(
                    ["ip", "-4", "addr", "show", "dev", iface],
                    capture_output=True, text=True, timeout=5,
                )
                for ln in r2.stdout.splitlines():
                    ln = ln.strip()
                    if ln.startswith("inet "):
                        return ln.split()[1]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""


def _scan_printers():
    """Discover printers via nmap on ports 9100 and 631."""
    global _printers, _status_msg, _scanning
    with lock:
        _scanning = True
        _status_msg = "Scanning..."

    subnet = _get_subnet()
    if not subnet:
        with lock:
            _status_msg = "No subnet found"
            _scanning = False
        return

    found = []
    try:
        result = subprocess.run(
            ["nmap", "-p", "9100,631", "--open", "-sV", "-T4", subnet],
            capture_output=True, text=True, timeout=60,
        )
        current_ip = ""
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Nmap scan report for"):
                parts = stripped.split()
                current_ip = parts[-1].strip("()")
            elif "/tcp" in stripped and "open" in stripped:
                try:
                    port = int(stripped.split("/")[0])
                    info = stripped.split("open")[1].strip() if "open" in stripped else ""
                    found.append({
                        "ip": current_ip,
                        "port": port,
                        "info": info[:20] if info else f"port {port}",
                    })
                except (ValueError, IndexError):
                    pass
    except (subprocess.TimeoutExpired, OSError) as exc:
        with lock:
            _status_msg = f"Err: {str(exc)[:14]}"
            _scanning = False
        return

    with lock:
        _printers = found
        _status_msg = f"Found {len(found)} printer(s)"
        _scanning = False


def _send_text(ip, port, text):
    """Send raw text to a printer via TCP."""
    global _jobs_sent, _status_msg
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        payload = text + "\f"  # form feed to eject page
        s.sendall(payload.encode("ascii", errors="replace"))
        s.close()
        with lock:
            _jobs_sent += 1
            _status_msg = f"Sent to {ip}"
    except (socket.error, OSError) as exc:
        with lock:
            _status_msg = f"Err: {str(exc)[:14]}"


def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:20], font=font, fill="#00ccff")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font, fill="#666")


def _draw_printers(cursor, scroll, status, jobs, scanning):
    """Draw printer list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "PAPER PUSHER")

    y = 16
    d.text((2, y), status[:22], font=font, fill="#ffaa00"); y += ROW_H

    with lock:
        printers = list(_printers)

    if scanning:
        d.text((4, 50), "Scanning network...", font=font, fill="#666")
    elif not printers:
        d.text((4, 50), "No printers found", font=font, fill="#666")
        d.text((4, 64), "OK to rescan", font=font, fill="#888")
    else:
        end = min(len(printers), scroll + VISIBLE_ROWS)
        for i in range(scroll, end):
            p = printers[i]
            is_sel = i == cursor
            color = "#ffff00" if is_sel else "#ccc"
            prefix = ">" if is_sel else " "
            label = f"{prefix}{p['ip']}:{p['port']}"
            d.text((2, y), label[:22], font=font, fill=color)
            y += ROW_H

    d.text((2, 104), f"Jobs sent: {jobs}", font=font, fill="#888")
    _draw_footer(d, "OK:sel K1:test K2:txt")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_text_input(chars, char_idx, target_ip):
    """Draw character picker for custom message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, f"MSG->{target_ip[:12]}")

    d.text((2, 18), "Message:", font=font, fill="#aaa")
    d.text((2, 30), "".join(chars)[:20] + "_", font=font, fill="#ffffff")

    current = CHARSET[char_idx]
    d.text((2, 50), f"Char: [ {current} ]", font=font, fill="#00ff00")

    prev_idx = (char_idx - 1) % len(CHARSET)
    next_idx = (char_idx + 1) % len(CHARSET)
    d.text((2, 62), f"  UP: {CHARSET[prev_idx]}  DN: {CHARSET[next_idx]}", font=font, fill="#555")

    d.text((2, 80), "OK: add char", font=font, fill="#666")
    d.text((2, 92), "KEY1: backspace", font=font, fill="#666")

    _draw_footer(d, "KEY2:send KEY3:cancel")
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _status_msg

    cursor = 0
    scroll = 0
    view = "list"  # list | text_input
    text_chars = list("Hello from RaspyJack!")
    char_idx = 0
    selected_printer = None
    last_press = 0.0

    # Initial scan
    threading.Thread(target=_scan_printers, daemon=True).start()

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                if view == "text_input":
                    view = "list"
                    btn = None
                else:
                    break

            if view == "list":
                with lock:
                    printers = list(_printers)
                    scanning = _scanning

                if btn == "UP":
                    cursor = max(0, cursor - 1)
                    if cursor < scroll:
                        scroll = cursor
                elif btn == "DOWN":
                    if printers:
                        cursor = min(len(printers) - 1, cursor + 1)
                        if cursor >= scroll + VISIBLE_ROWS:
                            scroll = cursor - VISIBLE_ROWS + 1
                elif btn == "OK":
                    if printers and 0 <= cursor < len(printers):
                        selected_printer = printers[cursor]
                    elif not printers and not scanning:
                        threading.Thread(target=_scan_printers, daemon=True).start()
                elif btn == "KEY1":
                    if selected_printer:
                        threading.Thread(
                            target=_send_text,
                            args=(selected_printer["ip"], selected_printer["port"],
                                  "=== RaspyJack Test Page ===\n\nPrinter is accessible.\n"),
                            daemon=True,
                        ).start()
                    else:
                        with lock:
                            _status_msg = "Select printer first"
                elif btn == "KEY2":
                    if selected_printer:
                        text_chars = list("Hello from RaspyJack!")
                        char_idx = 0
                        view = "text_input"
                    else:
                        with lock:
                            _status_msg = "Select printer first"

                with lock:
                    st = _status_msg
                    jobs = _jobs_sent
                    sc = _scanning
                _draw_printers(cursor, scroll, st, jobs, sc)

            elif view == "text_input":
                if btn == "UP":
                    char_idx = (char_idx - 1) % len(CHARSET)
                elif btn == "DOWN":
                    char_idx = (char_idx + 1) % len(CHARSET)
                elif btn == "OK":
                    text_chars = text_chars + [CHARSET[char_idx]]
                elif btn == "KEY1":
                    if text_chars:
                        text_chars = text_chars[:-1]
                elif btn == "KEY2":
                    msg = "".join(text_chars).strip()
                    if msg and selected_printer:
                        threading.Thread(
                            target=_send_text,
                            args=(selected_printer["ip"], selected_printer["port"], msg),
                            daemon=True,
                        ).start()
                    view = "list"

                if view == "text_input":
                    _draw_text_input(text_chars, char_idx, selected_printer["ip"])

            time.sleep(0.08)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
