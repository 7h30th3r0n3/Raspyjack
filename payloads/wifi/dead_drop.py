#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Dead Drop
=====================================
Author: 7h30th3r0n3

Secure anonymous file sharing via WiFi captive portal.
Opens a WiFi AP with a web portal where anyone can upload and download
files from a sandboxed directory.  The system is hardened to prevent
any access beyond the dead drop folder.

Security measures:
  - Sandboxed directory with strict permissions (0700)
  - Path traversal prevention (basename only, no ..)
  - File size limit (configurable, default 50 MB)
  - Filename sanitization (alphanum + .-_ only)
  - Extension blacklist (.py, .sh, .exe, .elf, .bin, .so, .php, .pl, .rb)
  - No internet forwarding (iptables DROP FORWARD)
  - All traffic forced to portal (DNS + HTTP redirect)
  - HTTP server runs as dedicated thread, not subprocess
  - No shell access, no CGI, no directory listing outside sandbox
  - Rate limiting on uploads (max 1 per 3 seconds per IP)

Controls:
  UP / DOWN  -- Scroll file list / stats
  OK         -- Start / Stop dead drop
  KEY1       -- Change SSID
  KEY2       -- Purge all files (with confirmation)
  KEY3       -- Exit + full cleanup

Loot: /root/Raspyjack/loot/DeadDrop/
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
import re
import html
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

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
ROW_H = 12
ROWS_VISIBLE = 6

DROP_DIR = "/root/Raspyjack/loot/DeadDrop/files"
LOG_DIR = "/root/Raspyjack/loot/DeadDrop"
CONFIG_PATH = os.path.join(LOG_DIR, "config.json")

HOSTAPD_CONF = "/tmp/rj_deaddrop_hostapd.conf"
DNSMASQ_CONF = "/tmp/rj_deaddrop_dnsmasq.conf"

GATEWAY_IP = "10.0.77.1"
DHCP_START = "10.0.77.10"
DHCP_END = "10.0.77.250"
PORTAL_PORT = 80

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_FILENAME_LEN = 100
UPLOAD_COOLDOWN = 3  # seconds between uploads per IP

BLOCKED_EXTENSIONS = {
    ".py", ".sh", ".bash", ".zsh", ".exe", ".elf", ".bin", ".so",
    ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".php", ".pl", ".rb",
    ".cgi", ".jsp", ".asp", ".aspx", ".msi", ".deb", ".rpm",
}

SSID_CHARS = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -_."
)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
active = False
status_msg = "Ready"
scroll = 0
upload_count = 0
download_count = 0
connected_clients = 0
_upload_timestamps = {}  # ip -> last upload time

_hostapd_proc = None
_dnsmasq_proc = None
_http_server = None

ssid = "DeadDrop"
confirm_purge = False


def _cleanup_signal(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_config():
    global ssid
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                cfg = json.load(f)
            ssid = str(cfg.get("ssid", ssid))
        except Exception:
            pass


def _save_config():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump({"ssid": ssid}, f, indent=2)

# ---------------------------------------------------------------------------
# Filename sanitization
# ---------------------------------------------------------------------------

_SAFE_RE = re.compile(r"[^a-zA-Z0-9._\-]")


def _sanitize_filename(name):
    """Sanitize filename: basename only, safe chars, block dangerous extensions."""
    name = os.path.basename(name)
    name = _SAFE_RE.sub("_", name)
    if not name or name.startswith("."):
        name = "file_" + name
    if len(name) > MAX_FILENAME_LEN:
        base, ext = os.path.splitext(name)
        name = base[:MAX_FILENAME_LEN - len(ext)] + ext
    ext = os.path.splitext(name)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        name = name + ".blocked"
    return name

# ---------------------------------------------------------------------------
# WiFi interface detection + selection
# ---------------------------------------------------------------------------

def _get_iface_info(iface):
    """Return dict with driver, is_onboard, supports_ap for a wlan interface."""
    info = {"name": iface, "driver": "", "is_onboard": False, "supports_ap": False}
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            info["is_onboard"] = True
    except Exception:
        pass
    try:
        drv = os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
        info["driver"] = drv
        if drv == "brcmfmac":
            info["is_onboard"] = True
    except Exception:
        pass
    # Check AP mode support via iw
    try:
        phy_link = os.path.realpath(f"/sys/class/net/{iface}/phy80211")
        phy_name = os.path.basename(phy_link)
        r = subprocess.run(["iw", "phy", phy_name, "info"],
                           capture_output=True, text=True, timeout=5)
        if "* AP" in r.stdout:
            info["supports_ap"] = True
    except Exception:
        pass
    return info


def _list_wifi_interfaces():
    """Return list of all wlan interface info dicts, sorted: USB first, then onboard."""
    ifaces = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            ifaces.append(_get_iface_info(name))
    except Exception:
        pass
    # Sort: USB (non-onboard) first, then onboard
    return sorted(ifaces, key=lambda x: (x["is_onboard"], x["name"]))


def _select_interface(lcd, font_obj, ifaces):
    """LCD interface selector. Returns selected iface name or None."""
    if not ifaces:
        return None
    if len(ifaces) == 1:
        return ifaces[0]["name"]

    sel = 0
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return None
        elif btn == "OK":
            return ifaces[sel]["name"]
        elif btn == "UP":
            sel = max(0, sel - 1)
            time.sleep(0.15)
        elif btn == "DOWN":
            sel = min(len(ifaces) - 1, sel + 1)
            time.sleep(0.15)

        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 13), fill="#111")
        d.text((2, 1), "SELECT INTERFACE", font=font_obj, fill="#58a6ff")
        d.text((2, 16), "Choose WiFi card:", font=font_obj, fill="#AAAAAA")

        for i, ifc in enumerate(ifaces):
            y = 30 + i * 14
            prefix = ">" if i == sel else " "
            tag = "onboard" if ifc["is_onboard"] else "USB"
            ap_ok = "AP" if ifc["supports_ap"] else "no-AP"
            drv = ifc["driver"][:10] if ifc["driver"] else "?"
            color = "#00FF00" if i == sel else "#CCCCCC"
            warn = "#FF4444" if not ifc["supports_ap"] else color
            d.text((2, y), f"{prefix}{ifc['name']}", font=font_obj, fill=color)
            d.text((60, y), f"{tag}/{ap_ok}", font=font_obj, fill=warn)

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:Select KEY3:Cancel", font=font_obj, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(0.05)

# ---------------------------------------------------------------------------
# Service management
# ---------------------------------------------------------------------------

def _start_services(iface):
    global _hostapd_proc, _dnsmasq_proc, _http_server, status_msg

    # Kill existing
    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "pkill", "-f", f"rj_deaddrop.*{proc_name}"],
                       capture_output=True, timeout=5)

    # Set managed mode and configure IP
    for cmd in [
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", iface, "up"],
        ["sudo", "ip", "addr", "flush", "dev", iface],
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    # hostapd config
    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={iface}\n"
            f"driver=nl80211\n"
            f"ssid={ssid}\n"
            f"hw_mode=g\n"
            f"channel=6\n"
            f"wmm_enabled=0\n"
            f"auth_algs=1\n"
            f"wpa=0\n"
            f"ignore_broadcast_ssid=0\n"
        )

    # dnsmasq config
    with open(DNSMASQ_CONF, "w") as f:
        f.write(
            f"interface={iface}\n"
            f"bind-interfaces\n"
            f"dhcp-range={DHCP_START},{DHCP_END},12h\n"
            f"dhcp-option=6,{GATEWAY_IP}\n"
            f"address=/#/{GATEWAY_IP}\n"
            f"no-resolv\n"
            f"log-queries\n"
        )

    # iptables: block all forwarding, redirect HTTP/DNS to portal
    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F", "FORWARD"],
        ["sudo", "iptables", "-P", "FORWARD", "DROP"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(PORTAL_PORT)],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(PORTAL_PORT)],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface,
         "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", f"{GATEWAY_IP}:53"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    # Start hostapd
    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    # Start dnsmasq
    _dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    # Start HTTP server
    _http_server = _ThreadedHTTPServer((GATEWAY_IP, PORTAL_PORT), _DeadDropHandler)
    threading.Thread(target=_http_server.serve_forever, daemon=True).start()

    with lock:
        status_msg = f"AP '{ssid}' active"


def _stop_services():
    global _hostapd_proc, _dnsmasq_proc, _http_server, status_msg

    if _http_server:
        _http_server.shutdown()
        _http_server = None

    for proc in (_hostapd_proc, _dnsmasq_proc):
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    _hostapd_proc = None
    _dnsmasq_proc = None

    # Clean iptables
    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F", "FORWARD"],
        ["sudo", "iptables", "-P", "FORWARD", "ACCEPT"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    # Kill leftovers
    subprocess.run(["sudo", "pkill", "-f", "rj_deaddrop"], capture_output=True, timeout=5)

    with lock:
        status_msg = "Stopped"


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

_CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;
margin:0;padding:20px;min-height:100vh}
.container{max-width:600px;margin:0 auto}
h1{color:#58a6ff;text-align:center;font-size:1.5em;margin-bottom:5px}
.subtitle{text-align:center;color:#8b949e;margin-bottom:20px;font-size:0.85em}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}
.file-list{list-style:none;padding:0;margin:0}
.file-list li{padding:8px 12px;border-bottom:1px solid #21262d;display:flex;
justify-content:space-between;align-items:center}
.file-list li:last-child{border-bottom:none}
.file-list a{color:#58a6ff;text-decoration:none}
.file-list a:hover{text-decoration:underline}
.size{color:#8b949e;font-size:0.85em}
.btn{background:#238636;color:#fff;border:none;padding:10px 20px;border-radius:6px;
cursor:pointer;font-size:1em;width:100%}
.btn:hover{background:#2ea043}
input[type=file]{color:#c9d1d9;margin:10px 0;width:100%;box-sizing:border-box}
.warn{color:#f85149;font-size:0.85em;text-align:center}
.ok{color:#3fb950;font-size:0.85em;text-align:center}
.stats{display:flex;justify-content:space-around;text-align:center;color:#8b949e;font-size:0.85em}
.stats span{color:#58a6ff;font-weight:bold;display:block;font-size:1.2em}
"""


def _human_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _build_page(message="", msg_class="ok"):
    """Build the dead drop HTML page."""
    files = []
    if os.path.isdir(DROP_DIR):
        for fn in sorted(os.listdir(DROP_DIR)):
            fp = os.path.join(DROP_DIR, fn)
            if os.path.isfile(fp):
                files.append((fn, os.path.getsize(fp)))

    total_size = sum(s for _, s in files)

    file_rows = ""
    if files:
        for fn, sz in files:
            safe_name = html.escape(fn)
            encoded = urllib.parse.quote(fn)
            file_rows += (
                f'<li><a href="/download/{encoded}">{safe_name}</a>'
                f'<span class="size">{_human_size(sz)}</span></li>\n'
            )
    else:
        file_rows = '<li style="color:#8b949e;text-align:center">No files yet</li>'

    msg_html = ""
    if message:
        msg_html = f'<p class="{msg_class}">{html.escape(message)}</p>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dead Drop</title><style>{_CSS}</style></head><body>
<div class="container">
<h1>&#x1f4e6; Dead Drop</h1>
<p class="subtitle">Anonymous file sharing &mdash; no logs, no tracking</p>

<div class="card">
<div class="stats">
<div><span>{len(files)}</span>files</div>
<div><span>{_human_size(total_size)}</span>total</div>
<div><span>{_human_size(MAX_FILE_SIZE)}</span>max upload</div>
</div></div>

{msg_html}

<div class="card">
<h3 style="margin-top:0">&#x1f4e4; Upload</h3>
<form method="POST" action="/upload" enctype="multipart/form-data">
<input type="file" name="file" required>
<button type="submit" class="btn">Upload File</button>
</form>
<p class="warn" style="margin-bottom:0">Blocked: {', '.join(sorted(BLOCKED_EXTENSIONS))}</p>
</div>

<div class="card">
<h3 style="margin-top:0">&#x1f4c1; Files ({len(files)})</h3>
<ul class="file-list">{file_rows}</ul>
</div>

<p class="subtitle" style="margin-top:20px">&#x1f512; Sandboxed &bull; No internet &bull; Files are local only</p>
</div></body></html>"""


# ---------------------------------------------------------------------------
# HTTP handler (sandboxed)
# ---------------------------------------------------------------------------

class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _DeadDropHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the dead drop portal."""

    def log_message(self, fmt, *args):
        pass  # Silence logs

    def _send_html(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/download/"):
            self._handle_download()
        else:
            self._send_html(200, _build_page())

    def do_POST(self):
        if self.path == "/upload":
            self._handle_upload()
        else:
            self._send_html(404, _build_page("Not found", "warn"))

    def _handle_download(self):
        global download_count
        raw_name = urllib.parse.unquote(self.path[len("/download/"):])
        safe_name = os.path.basename(raw_name)

        # Path traversal prevention
        filepath = os.path.join(DROP_DIR, safe_name)
        real_drop = os.path.realpath(DROP_DIR)
        real_file = os.path.realpath(filepath)
        if not real_file.startswith(real_drop + os.sep):
            self._send_html(403, _build_page("Access denied", "warn"))
            return

        if not os.path.isfile(filepath):
            self._send_html(404, _build_page("File not found", "warn"))
            return

        try:
            size = os.path.getsize(filepath)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            with lock:
                download_count += 1
        except Exception:
            self._send_html(500, _build_page("Download error", "warn"))

    def _handle_upload(self):
        global upload_count

        # Rate limiting
        client_ip = self.client_address[0]
        now = time.time()
        with lock:
            last = _upload_timestamps.get(client_ip, 0)
            if now - last < UPLOAD_COOLDOWN:
                self._send_html(429, _build_page(
                    f"Too fast! Wait {UPLOAD_COOLDOWN}s between uploads.", "warn"))
                return
            _upload_timestamps[client_ip] = now

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_html(400, _build_page("Invalid request", "warn"))
            return

        # Parse boundary
        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[9:].strip('"')
                break
        if not boundary:
            self._send_html(400, _build_page("Missing boundary", "warn"))
            return

        # Read body with size limit
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_FILE_SIZE + 4096:
            self._send_html(413, _build_page(
                f"File too large (max {_human_size(MAX_FILE_SIZE)})", "warn"))
            return

        body = self.rfile.read(content_length)

        # Extract filename and file data from multipart
        boundary_bytes = boundary.encode("utf-8")
        parts = body.split(b"--" + boundary_bytes)

        filename = None
        file_data = None
        for part in parts:
            if b"Content-Disposition" not in part:
                continue
            header_end = part.find(b"\r\n\r\n")
            if header_end < 0:
                continue
            headers_raw = part[:header_end].decode("utf-8", errors="replace")
            if 'name="file"' not in headers_raw:
                continue
            # Extract filename
            fn_match = re.search(r'filename="([^"]*)"', headers_raw)
            if fn_match:
                filename = fn_match.group(1)
            file_data = part[header_end + 4:]
            # Remove trailing boundary markers
            if file_data.endswith(b"\r\n"):
                file_data = file_data[:-2]
            break

        if not filename or not file_data:
            self._send_html(400, _build_page("No file received", "warn"))
            return

        if len(file_data) > MAX_FILE_SIZE:
            self._send_html(413, _build_page(
                f"File too large (max {_human_size(MAX_FILE_SIZE)})", "warn"))
            return

        safe_name = _sanitize_filename(filename)
        if safe_name.endswith(".blocked"):
            self._send_html(403, _build_page(
                f"Blocked file type: {os.path.splitext(filename)[1]}", "warn"))
            return

        # Deduplicate filename
        dest = os.path.join(DROP_DIR, safe_name)
        real_drop = os.path.realpath(DROP_DIR)
        real_dest = os.path.realpath(dest)
        if not real_dest.startswith(real_drop + os.sep):
            self._send_html(403, _build_page("Invalid filename", "warn"))
            return

        if os.path.exists(dest):
            base, ext = os.path.splitext(safe_name)
            counter = 1
            while os.path.exists(dest):
                safe_name = f"{base}_{counter}{ext}"
                dest = os.path.join(DROP_DIR, safe_name)
                counter += 1

        try:
            with open(dest, "wb") as f:
                f.write(file_data)
            os.chmod(dest, 0o644)
            with lock:
                upload_count += 1
            self._send_html(200, _build_page(
                f"Uploaded: {safe_name} ({_human_size(len(file_data))})", "ok"))
        except Exception as exc:
            self._send_html(500, _build_page(f"Write error: {exc}", "warn"))


# ---------------------------------------------------------------------------
# LCD Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "DEAD DROP", font=font_obj, fill="#58a6ff")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")

    with lock:
        msg = status_msg
        ul = upload_count
        dl = download_count

    d.text((2, 16), msg[:24], font=font_obj, fill="#AAAAAA")

    if active:
        d.text((2, 30), f"SSID: {ssid[:16]}", font=font_obj, fill="#58a6ff")
        d.text((2, 42), f"Up:{ul} Down:{dl}", font=font_obj, fill="#888")

        # File list
        files = []
        if os.path.isdir(DROP_DIR):
            for fn in sorted(os.listdir(DROP_DIR)):
                fp = os.path.join(DROP_DIR, fn)
                if os.path.isfile(fp):
                    files.append((fn, os.path.getsize(fp)))

        d.text((2, 54), f"Files: {len(files)}", font=font_obj, fill="#888")
        visible = files[scroll:scroll + ROWS_VISIBLE - 1]
        for i, (fn, sz) in enumerate(visible):
            y = 66 + i * ROW_H
            label = f"{fn[:14]} {_human_size(sz)}"
            d.text((2, y), label[:24], font=font_obj, fill="#CCCCCC")
    else:
        d.text((2, 40), f"SSID: {ssid[:16]}", font=font_obj, fill="#666")
        d.text((2, 52), f"Iface: {iface}", font=font_obj, fill="#666")
        d.text((2, 66), "OK: Start", font=font_obj, fill="#666")
        d.text((2, 78), "KEY1: SSID  KEY3: Exit", font=font_obj, fill="#666")

    if confirm_purge:
        d.rectangle((10, 40, 117, 85), fill="#1a1a2e", outline="#f85149")
        d.text((16, 45), "Purge all files?", font=font_obj, fill="#f85149")
        d.text((16, 60), "OK=Yes KEY2=No", font=font_obj, fill="#AAAAAA")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if active:
        d.text((2, 117), "OK:Stop K2:Purge K3:Quit", font=font_obj, fill="#888")
    else:
        d.text((2, 117), "OK:Start K1:SSID K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# SSID editor (simple character picker)
# ---------------------------------------------------------------------------

def _edit_ssid(lcd, font_obj):
    global ssid
    chars = list(ssid)
    cursor = len(chars)
    char_idx = 0

    while _running:
        btn = get_button(PINS, GPIO)

        if btn == "KEY3" or btn == "KEY1":
            ssid = "".join(chars) or "DeadDrop"
            _save_config()
            return
        elif btn == "OK":
            if cursor < len(chars):
                cursor += 1
            ssid = "".join(chars) or "DeadDrop"
            _save_config()
            return
        elif btn == "UP":
            char_idx = (char_idx + 1) % len(SSID_CHARS)
            if cursor < len(chars):
                chars[cursor] = SSID_CHARS[char_idx]
            time.sleep(0.12)
        elif btn == "DOWN":
            char_idx = (char_idx - 1) % len(SSID_CHARS)
            if cursor < len(chars):
                chars[cursor] = SSID_CHARS[char_idx]
            time.sleep(0.12)
        elif btn == "RIGHT":
            if len(chars) < 30:
                chars.append(SSID_CHARS[char_idx])
                cursor = len(chars) - 1
            time.sleep(0.15)
        elif btn == "LEFT":
            if chars:
                chars.pop()
                cursor = max(0, len(chars) - 1)
            time.sleep(0.15)

        # Draw SSID editor
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 13), fill="#111")
        d.text((2, 1), "EDIT SSID", font=font_obj, fill="#58a6ff")

        display = "".join(chars)
        d.text((4, 30), display[:20], font=font_obj, fill="#FFFFFF")
        if len(display) > 20:
            d.text((4, 42), display[20:], font=font_obj, fill="#FFFFFF")

        d.text((4, 60), f"Char: {SSID_CHARS[char_idx]}", font=font_obj, fill="#58a6ff")
        d.text((4, 75), "U/D:char R:add L:del", font=font_obj, fill="#666")
        d.text((4, 87), "OK/K1:confirm", font=font_obj, fill="#666")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), f"Len: {len(chars)}/30", font=font_obj, fill="#888")

        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, active, status_msg, scroll, confirm_purge

    _load_config()
    os.makedirs(DROP_DIR, exist_ok=True)
    os.chmod(DROP_DIR, 0o700)

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    # Detect and select WiFi interface
    ifaces = _list_wifi_interfaces()
    if not ifaces:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "No WiFi interface", font=font_obj, fill="#FF0000")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    iface = _select_interface(lcd, font_obj, ifaces)
    if not iface:
        GPIO.cleanup()
        return 0

    # Show selected interface
    sel_info = next((i for i in ifaces if i["name"] == iface), None)
    with lock:
        tag = "USB" if sel_info and not sel_info["is_onboard"] else "onboard"
        status_msg = f"Using {iface} ({tag})"

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3" and not confirm_purge:
                break

            elif confirm_purge:
                if btn == "OK":
                    # Purge confirmed
                    if os.path.isdir(DROP_DIR):
                        for fn in os.listdir(DROP_DIR):
                            fp = os.path.join(DROP_DIR, fn)
                            if os.path.isfile(fp):
                                os.remove(fp)
                    with lock:
                        status_msg = "All files purged"
                    confirm_purge = False
                    time.sleep(0.3)
                elif btn in ("KEY2", "KEY3"):
                    confirm_purge = False
                    time.sleep(0.3)

            elif btn == "OK":
                if not active:
                    with lock:
                        status_msg = "Starting..."
                    _start_services(iface)
                    active = True
                else:
                    _stop_services()
                    active = False
                time.sleep(0.3)

            elif btn == "KEY1" and not active:
                _edit_ssid(lcd, font_obj)
                time.sleep(0.3)

            elif btn == "KEY2" and active:
                confirm_purge = True
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                file_count = len(os.listdir(DROP_DIR)) if os.path.isdir(DROP_DIR) else 0
                scroll = min(scroll + 1, max(0, file_count - ROWS_VISIBLE + 1))
                time.sleep(0.15)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        if active:
            _stop_services()
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
