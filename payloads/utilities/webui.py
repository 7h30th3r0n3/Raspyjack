#!/usr/bin/env python3
"""
RaspyJack payload - WebUI Info & Control
=========================================
Author: 7h30th3r0n3

Displays WebUI URLs for all network interfaces, service status,
and allows restarting raspyjack-webui.service.

Controls:
  UP / DOWN  Scroll interface list
  KEY1       Restart raspyjack-webui.service
  KEY3/LEFT  Back to RaspyJack
"""

import os
import sys
import time
import signal
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..', '..')))

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
font = scaled_font(10)
font_sm = scaled_font(8)
font_bold = scaled_font(11)

running = True


def _handle_exit(*_):
    global running
    running = False


signal.signal(signal.SIGINT, _handle_exit)
signal.signal(signal.SIGTERM, _handle_exit)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_all_interfaces():
    """Return list of {name, ip, type} for all interfaces with an IPv4."""
    ifaces = []
    try:
        r = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            # Format: idx name inet IP/mask ...
            name = parts[1] if len(parts) > 1 else "?"
            ip = ""
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    ip = parts[i + 1].split("/")[0]
                    break
            if name == "lo" or not ip:
                continue
            if name.startswith("wlan"):
                itype = "WiFi"
            elif name.startswith("eth") or name.startswith("enp") or name.startswith("usb"):
                itype = "Ethernet"
            elif name.startswith("tailscale"):
                itype = "Tailscale"
            elif name.startswith("docker") or name.startswith("br-"):
                continue
            else:
                itype = "Other"
            ifaces.append({"name": name, "ip": ip, "type": itype})
    except Exception:
        pass
    return ifaces


def _get_service_status():
    """Return service status string."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "raspyjack-webui"],
            capture_output=True, text=True, timeout=3,
        )
        return r.stdout.strip()
    except Exception:
        return "unknown"


def _restart_service():
    """Restart the webui service."""
    try:
        subprocess.run(
            ["sudo", "systemctl", "restart", "raspyjack-webui.service"],
            capture_output=True, timeout=15,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Build content lines for display
# ---------------------------------------------------------------------------

def _build_lines(ifaces, svc_status):
    """Build list of (text, color) tuples for scrollable display."""
    lines = []

    # Service status
    if svc_status == "active":
        lines.append(("Service: active", "#00FF00"))
    else:
        lines.append((f"Service: {svc_status}", "#FF4444"))

    lines.append(("", "#000000"))  # blank line

    if not ifaces:
        lines.append(("No interfaces found", "#FF4444"))
        return lines

    for ifc in ifaces:
        name = ifc["name"]
        ip = ifc["ip"]
        itype = ifc["type"]

        # Interface header
        lines.append((f"{name} ({itype})", "#FFAA00"))

        # HTTPS URL
        lines.append((f"  https://{ip}/", "#00CCFF"))

        # HTTP URL
        lines.append((f"  http://{ip}:8080", "#58a6ff"))

        # Blank separator
        lines.append(("", "#000000"))

    return lines


# ---------------------------------------------------------------------------
# Draw
# ---------------------------------------------------------------------------

def _draw(lines, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 15), fill="#00A321")
    d.text((4, 1), "WebUI", font=font_bold, fill="black")

    # Scrollable content
    visible_rows = 8
    row_h = 12
    visible = lines[scroll:scroll + visible_rows]
    for i, (text, color) in enumerate(visible):
        y = 18 + i * row_h
        if text:
            d.text((2, y), text[:24], font=font_sm, fill=color)

    # Scroll indicator
    total = len(lines)
    if total > visible_rows:
        bar_total = 90
        bar_h = max(6, int(visible_rows / total * bar_total))
        bar_y = 18 + int(scroll / max(1, total - visible_rows) * (bar_total - bar_h))
        d.rectangle((125, bar_y, 127, bar_y + bar_h), fill="#444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K1:Restart U/D:Scrl K3:X", font=font_sm, fill="#888")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running

    ifaces = _get_all_interfaces()
    svc_status = _get_service_status()
    lines = _build_lines(ifaces, svc_status)
    scroll = 0
    max_scroll = max(0, len(lines) - 8)

    try:
        while running:
            btn = get_button(PINS, GPIO)

            if btn in ("KEY3", "LEFT"):
                break

            elif btn == "KEY1":
                # Show restarting message
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Restarting WebUI...", font=font, fill="yellow")
                LCD.LCD_ShowImage(img, 0, 0)

                _restart_service()
                time.sleep(3)

                # Refresh everything
                ifaces = _get_all_interfaces()
                svc_status = _get_service_status()
                lines = _build_lines(ifaces, svc_status)
                scroll = 0
                max_scroll = max(0, len(lines) - 8)
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                scroll = min(max_scroll, scroll + 1)
                time.sleep(0.15)

            _draw(lines, scroll)
            time.sleep(0.05)

    except KeyboardInterrupt:
        pass
    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
