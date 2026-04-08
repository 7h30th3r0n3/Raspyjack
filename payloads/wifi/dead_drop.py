#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Dead Drop
=====================================
Author: 7h30th3r0n3

Secure anonymous file sharing via WiFi captive portal.
Opens a WiFi AP with a web portal where anyone can upload and download
files from a sandboxed directory. Real-time dashboard on LCD.

Security:
  Sandboxed directory (0700), path traversal prevention, filename
  sanitization, extension blacklist, file size limit, no internet
  forwarding, rate limiting, no CGI/shell.

Controls:
  UP / DOWN  Scroll file list
  OK         Start / Stop dead drop
  LEFT/RIGHT Switch dashboard view (stats / files / graph)
  KEY1       Change SSID (when stopped)
  KEY2       Purge all files (with confirmation)
  KEY3       Exit + cleanup

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
from collections import deque
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
from payloads._iface_helper import select_interface

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
ROWS_VISIBLE = 5

DROP_DIR = "/root/Raspyjack/loot/DeadDrop/files"
LOG_DIR = "/root/Raspyjack/loot/DeadDrop"
CONFIG_PATH = os.path.join(LOG_DIR, "config.json")

HOSTAPD_CONF = "/tmp/rj_deaddrop_hostapd.conf"
DNSMASQ_CONF = "/tmp/rj_deaddrop_dnsmasq.conf"

GATEWAY_IP = "10.0.77.1"
DHCP_START = "10.0.77.10"
DHCP_END = "10.0.77.250"
PORTAL_PORT = 80

MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_FILENAME_LEN = 100
UPLOAD_COOLDOWN = 3
GRAPH_POINTS = 40

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
dash_view = 0  # 0=stats, 1=files, 2=graph
upload_count = 0
download_count = 0
total_bytes_up = 0
total_bytes_down = 0
connected_ips = set()
_upload_timestamps = {}

# Transfer rate history for graph (bytes per sample)
_rate_up_history = deque([0] * GRAPH_POINTS, maxlen=GRAPH_POINTS)
_rate_down_history = deque([0] * GRAPH_POINTS, maxlen=GRAPH_POINTS)
_last_bytes_up = 0
_last_bytes_down = 0
_last_event = ""  # last upload/download event text

_hostapd_proc = None
_dnsmasq_proc = None
_http_server = None

ssid = "DeadDrop"
confirm_purge = False
iface = None


def _cleanup_signal(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)

# ---------------------------------------------------------------------------
# Rate sampler thread
# ---------------------------------------------------------------------------

def _rate_sampler():
    """Sample transfer rates every 2 seconds for the graph."""
    global _last_bytes_up, _last_bytes_down
    while _running:
        time.sleep(2)
        with lock:
            delta_up = total_bytes_up - _last_bytes_up
            delta_down = total_bytes_down - _last_bytes_down
            _last_bytes_up = total_bytes_up
            _last_bytes_down = total_bytes_down
            _rate_up_history.append(delta_up)
            _rate_down_history.append(delta_down)

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
# Service management
# ---------------------------------------------------------------------------

def _start_services(ifc):
    global _hostapd_proc, _dnsmasq_proc, _http_server, status_msg

    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "pkill", "-f", f"rj_deaddrop.*{proc_name}"],
                       capture_output=True, timeout=5)

    for cmd in [
        ["sudo", "ip", "link", "set", ifc, "down"],
        ["sudo", "iw", "dev", ifc, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", ifc, "up"],
        ["sudo", "ip", "addr", "flush", "dev", ifc],
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", ifc],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={ifc}\ndriver=nl80211\nssid={ssid}\n"
            f"hw_mode=g\nchannel=6\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\nignore_broadcast_ssid=0\n"
        )

    with open(DNSMASQ_CONF, "w") as f:
        f.write(
            f"interface={ifc}\nbind-interfaces\n"
            f"dhcp-range={DHCP_START},{DHCP_END},12h\n"
            f"dhcp-option=6,{GATEWAY_IP}\naddress=/#/{GATEWAY_IP}\n"
            f"no-resolv\n"
        )

    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F", "FORWARD"],
        ["sudo", "iptables", "-P", "FORWARD", "DROP"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", ifc,
         "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(PORTAL_PORT)],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", ifc,
         "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(PORTAL_PORT)],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", ifc,
         "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", f"{GATEWAY_IP}:53"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    _dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    _http_server = _ThreadedHTTPServer((GATEWAY_IP, PORTAL_PORT), _DeadDropHandler)
    threading.Thread(target=_http_server.serve_forever, daemon=True).start()

    with lock:
        status_msg = f"AP '{ssid}' on {ifc}"


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

    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F", "FORWARD"],
        ["sudo", "iptables", "-P", "FORWARD", "ACCEPT"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    subprocess.run(["sudo", "pkill", "-f", "rj_deaddrop"], capture_output=True, timeout=5)
    with lock:
        status_msg = "Stopped"


def _count_clients():
    """Count connected DHCP clients."""
    try:
        r = subprocess.run(["sudo", "cat", "/var/lib/misc/dnsmasq.leases"],
                           capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            return len([l for l in r.stdout.strip().split("\n") if l.strip()])
    except Exception:
        pass
    return len(connected_ips)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}" if size != int(size) else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _list_files():
    files = []
    if os.path.isdir(DROP_DIR):
        for fn in sorted(os.listdir(DROP_DIR)):
            fp = os.path.join(DROP_DIR, fn)
            if os.path.isfile(fp):
                files.append((fn, os.path.getsize(fp)))
    return files

# ---------------------------------------------------------------------------
# HTML portal (multi-file upload)
# ---------------------------------------------------------------------------

_CSS = """
*{box-sizing:border-box}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;
margin:0;padding:15px;min-height:100vh}
.c{max-width:600px;margin:0 auto}
h1{color:#58a6ff;text-align:center;font-size:1.4em;margin:8px 0 2px}
.sub{text-align:center;color:#8b949e;margin-bottom:15px;font-size:0.8em}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;margin:10px 0}
.fl{list-style:none;padding:0;margin:0}
.fl li{padding:7px 10px;border-bottom:1px solid #21262d;display:flex;
justify-content:space-between;align-items:center;font-size:0.9em}
.fl li:last-child{border-bottom:none}
.fl a{color:#58a6ff;text-decoration:none}
.fl a:hover{text-decoration:underline}
.sz{color:#8b949e;font-size:0.8em}
.btn{background:#238636;color:#fff;border:none;padding:10px 16px;border-radius:6px;
cursor:pointer;font-size:0.95em;width:100%}
.btn:hover{background:#2ea043}
input[type=file]{color:#c9d1d9;margin:8px 0;width:100%}
.w{color:#f85149;font-size:0.8em;text-align:center}
.ok{color:#3fb950;font-size:0.8em;text-align:center}
.st{display:flex;justify-content:space-around;text-align:center;color:#8b949e;font-size:0.8em}
.st span{color:#58a6ff;font-weight:bold;display:block;font-size:1.1em}
.prog{width:100%;background:#21262d;border-radius:4px;height:20px;margin:8px 0;overflow:hidden;display:none}
.prog-bar{height:100%;background:#238636;transition:width 0.3s;width:0%}
.prog-text{text-align:center;font-size:0.8em;color:#8b949e;display:none}
"""

_JS = """
document.getElementById('upload-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var files = document.getElementById('file-input').files;
    if (files.length === 0) return;
    var prog = document.getElementById('progress');
    var pbar = document.getElementById('prog-bar');
    var ptxt = document.getElementById('prog-text');
    var results = document.getElementById('results');
    prog.style.display = 'block';
    ptxt.style.display = 'block';
    results.innerHTML = '';
    var done = 0;
    var total = files.length;
    function uploadNext(idx) {
        if (idx >= total) {
            ptxt.textContent = 'All done! Reloading...';
            setTimeout(function(){ location.reload(); }, 1000);
            return;
        }
        var fd = new FormData();
        fd.append('file', files[idx]);
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload', true);
        xhr.upload.onprogress = function(ev) {
            if (ev.lengthComputable) {
                var pct = ((done + ev.loaded/ev.total) / total * 100).toFixed(0);
                pbar.style.width = pct + '%';
            }
        };
        xhr.onload = function() {
            done++;
            var pct = (done / total * 100).toFixed(0);
            pbar.style.width = pct + '%';
            ptxt.textContent = done + '/' + total + ' uploaded';
            var color = xhr.status < 300 ? '#3fb950' : '#f85149';
            results.innerHTML += '<div style="color:'+color+';font-size:0.85em">' +
                files[idx].name + ': ' + (xhr.status < 300 ? 'OK' : 'Error ' + xhr.status) + '</div>';
            uploadNext(idx + 1);
        };
        xhr.onerror = function() {
            done++;
            results.innerHTML += '<div style="color:#f85149;font-size:0.85em">' +
                files[idx].name + ': Network error</div>';
            uploadNext(idx + 1);
        };
        xhr.send(fd);
    }
    uploadNext(0);
});
"""


def _build_page(message="", msg_class="ok"):
    files = _list_files()
    total_size = sum(s for _, s in files)

    file_rows = ""
    if files:
        for fn, sz in files:
            safe_name = html.escape(fn)
            encoded = urllib.parse.quote(fn)
            file_rows += (
                f'<li><a href="/download/{encoded}">{safe_name}</a>'
                f'<span class="sz">{_human_size(sz)}</span></li>\n'
            )
    else:
        file_rows = '<li style="color:#8b949e;text-align:center">No files yet</li>'

    msg_html = ""
    if message:
        msg_html = f'<p class="{msg_class}">{html.escape(message)}</p>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dead Drop</title><style>{_CSS}</style></head><body>
<div class="c">
<h1>&#x1f4e6; Dead Drop</h1>
<p class="sub">Anonymous file sharing &bull; No logs &bull; No tracking</p>
<div class="card"><div class="st">
<div><span>{len(files)}</span>files</div>
<div><span>{_human_size(total_size)}</span>total</div>
<div><span>{_human_size(MAX_FILE_SIZE)}</span>max/file</div>
</div></div>
{msg_html}
<div class="card">
<h3 style="margin-top:0">&#x1f4e4; Upload files</h3>
<form id="upload-form" method="POST" action="/upload" enctype="multipart/form-data">
<input type="file" id="file-input" name="file" multiple required>
<div class="prog" id="progress"><div class="prog-bar" id="prog-bar"></div></div>
<div class="prog-text" id="prog-text"></div>
<div id="results"></div>
<button type="submit" class="btn">Upload</button>
</form>
<p class="w" style="margin-bottom:0">Blocked: {', '.join(sorted(BLOCKED_EXTENSIONS))}</p>
</div>
<div class="card">
<h3 style="margin-top:0">&#x1f4c1; Files ({len(files)})</h3>
<ul class="fl">{file_rows}</ul>
</div>
<p class="sub" style="margin-top:15px">&#x1f512; Sandboxed &bull; No internet &bull; Local only</p>
</div>
<script>{_JS}</script>
</body></html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _DeadDropHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def _send_html(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # Track connected client
        with lock:
            connected_ips.add(self.client_address[0])
        if self.path.startswith("/download/"):
            self._handle_download()
        else:
            self._send_html(200, _build_page())

    def do_POST(self):
        with lock:
            connected_ips.add(self.client_address[0])
        if self.path == "/upload":
            self._handle_upload()
        else:
            self._send_html(404, _build_page("Not found", "w"))

    def _handle_download(self):
        global download_count, total_bytes_down, _last_event
        raw_name = urllib.parse.unquote(self.path[len("/download/"):])
        safe_name = os.path.basename(raw_name)

        filepath = os.path.join(DROP_DIR, safe_name)
        real_drop = os.path.realpath(DROP_DIR)
        real_file = os.path.realpath(filepath)
        if not real_file.startswith(real_drop + os.sep):
            self._send_html(403, _build_page("Access denied", "w"))
            return
        if not os.path.isfile(filepath):
            self._send_html(404, _build_page("File not found", "w"))
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
                total_bytes_down += size
                _last_event = f"DL {safe_name[:14]}"
        except Exception:
            pass

    def _handle_upload(self):
        global upload_count, total_bytes_up, _last_event

        client_ip = self.client_address[0]
        now = time.time()
        with lock:
            last = _upload_timestamps.get(client_ip, 0)
            if now - last < UPLOAD_COOLDOWN:
                self._send_html(429, _build_page(
                    f"Wait {UPLOAD_COOLDOWN}s between uploads", "w"))
                return
            _upload_timestamps[client_ip] = now

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_html(400, _build_page("Invalid request", "w"))
            return

        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[9:].strip('"')
                break
        if not boundary:
            self._send_html(400, _build_page("Missing boundary", "w"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_FILE_SIZE + 8192:
            self._send_html(413, _build_page(
                f"Too large (max {_human_size(MAX_FILE_SIZE)})", "w"))
            return

        body = self.rfile.read(content_length)
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
            fn_match = re.search(r'filename="([^"]*)"', headers_raw)
            if fn_match:
                filename = fn_match.group(1)
            file_data = part[header_end + 4:]
            if file_data.endswith(b"\r\n"):
                file_data = file_data[:-2]
            break

        if not filename or not file_data:
            self._send_html(400, _build_page("No file received", "w"))
            return

        if len(file_data) > MAX_FILE_SIZE:
            self._send_html(413, _build_page(
                f"Too large (max {_human_size(MAX_FILE_SIZE)})", "w"))
            return

        safe_name = _sanitize_filename(filename)
        if safe_name.endswith(".blocked"):
            self._send_html(403, _build_page(
                f"Blocked: {os.path.splitext(filename)[1]}", "w"))
            return

        dest = os.path.join(DROP_DIR, safe_name)
        real_drop = os.path.realpath(DROP_DIR)
        real_dest = os.path.realpath(dest)
        if not real_dest.startswith(real_drop + os.sep):
            self._send_html(403, _build_page("Invalid filename", "w"))
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
            sz = len(file_data)
            with lock:
                upload_count += 1
                total_bytes_up += sz
                _last_event = f"UP {safe_name[:14]}"
            self._send_html(200, _build_page(
                f"OK: {safe_name} ({_human_size(sz)})", "ok"))
        except Exception as exc:
            self._send_html(500, _build_page(f"Error: {exc}", "w"))


# ---------------------------------------------------------------------------
# LCD Dashboard
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj, ifc_name):
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
        bup = total_bytes_up
        bdn = total_bytes_down
        clients = len(connected_ips)
        evt = _last_event
        rates_up = list(_rate_up_history)
        rates_dn = list(_rate_down_history)

    if not active:
        # Idle screen
        d.text((2, 20), f"SSID: {ssid[:16]}", font=font_obj, fill="#666")
        d.text((2, 34), f"Iface: {ifc_name or '?'}", font=font_obj, fill="#666")
        d.text((2, 50), "OK  Start", font=font_obj, fill="#666")
        d.text((2, 62), "KEY1  Change SSID", font=font_obj, fill="#666")
        d.text((2, 74), "KEY3  Exit", font=font_obj, fill="#666")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:Start K1:SSID K3:Exit", font=font_obj, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    # Active dashboard
    if dash_view == 0:
        # Stats view
        d.text((2, 16), f"SSID: {ssid[:14]}", font=font_obj, fill="#58a6ff")

        d.text((2, 30), f"Clients: {clients}", font=font_obj, fill="#00FF00")
        files = _list_files()
        total_sz = sum(s for _, s in files)
        d.text((68, 30), f"Files: {len(files)}", font=font_obj, fill="#FFAA00")

        # Upload / Download counters with totals
        d.text((2, 44), f"UP  {ul}", font=font_obj, fill="#3fb950")
        d.text((40, 44), _human_size(bup), font=font_obj, fill="#3fb950")

        d.text((2, 56), f"DN  {dl}", font=font_obj, fill="#58a6ff")
        d.text((40, 56), _human_size(bdn), font=font_obj, fill="#58a6ff")

        d.text((2, 70), f"Total: {_human_size(total_sz)}", font=font_obj, fill="#888")

        # Last event
        if evt:
            d.text((2, 84), evt[:24], font=font_obj, fill="#FFAA00")

        # Mini sparkline (last 20 points, bottom area)
        graph_y = 96
        graph_h = 16
        pts = rates_up[-20:]
        mx = max(max(pts), 1)
        for i, v in enumerate(pts):
            bh = max(1, int(v / mx * graph_h))
            x = 2 + i * 6
            d.rectangle((x, graph_y + graph_h - bh, x + 4, graph_y + graph_h), fill="#3fb950")

    elif dash_view == 1:
        # File list view
        files = _list_files()
        d.text((2, 16), f"Files: {len(files)}", font=font_obj, fill="#FFAA00")

        visible = files[scroll:scroll + ROWS_VISIBLE]
        for i, (fn, sz) in enumerate(visible):
            y = 28 + i * ROW_H
            d.text((2, y), fn[:14], font=font_obj, fill="#CCCCCC")
            d.text((90, y), _human_size(sz)[:8], font=font_obj, fill="#888")

        if not files:
            d.text((2, 40), "No files yet", font=font_obj, fill="#666")

        d.text((2, 100), f"Clients: {clients}", font=font_obj, fill="#00FF00")

    elif dash_view == 2:
        # Transfer rate graph view
        d.text((2, 16), "Transfer rate", font=font_obj, fill="#AAAAAA")

        # Graph area: y=28 to y=95 (height=67), x=2 to x=125
        graph_top = 28
        graph_bot = 95
        graph_h = graph_bot - graph_top
        graph_w = 123

        # Draw grid lines
        for gy in range(graph_top, graph_bot + 1, 16):
            d.line([(2, gy), (125, gy)], fill="#222")

        # Upload bars (green)
        mx_up = max(max(rates_up), 1)
        bar_w = max(1, graph_w // GRAPH_POINTS)
        for i, v in enumerate(rates_up):
            bh = max(0, int(v / mx_up * graph_h * 0.45))
            mid = graph_top + graph_h // 2
            x = 2 + i * bar_w
            if bh > 0:
                d.rectangle((x, mid - bh, x + bar_w - 1, mid), fill="#3fb950")

        # Download bars (blue, below midline)
        mx_dn = max(max(rates_dn), 1)
        for i, v in enumerate(rates_dn):
            bh = max(0, int(v / mx_dn * graph_h * 0.45))
            mid = graph_top + graph_h // 2
            x = 2 + i * bar_w
            if bh > 0:
                d.rectangle((x, mid + 1, x + bar_w - 1, mid + bh), fill="#58a6ff")

        # Legend
        d.rectangle((2, 98, 8, 104), fill="#3fb950")
        d.text((10, 98), f"UP {_human_size(bup)}", font=font_obj, fill="#3fb950")
        d.rectangle((68, 98, 74, 104), fill="#58a6ff")
        d.text((76, 98), f"DN {_human_size(bdn)}", font=font_obj, fill="#58a6ff")

    # Purge confirmation overlay
    if confirm_purge:
        d.rectangle((10, 40, 117, 80), fill="#1a1a2e", outline="#f85149")
        d.text((16, 45), "Purge all files?", font=font_obj, fill="#f85149")
        d.text((16, 60), "OK=Yes KEY2=No", font=font_obj, fill="#AAAAAA")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    view_names = ["STATS", "FILES", "GRAPH"]
    d.text((2, 117), f"{view_names[dash_view]} L/R:view K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# SSID editor
# ---------------------------------------------------------------------------

def _edit_ssid(lcd, font_obj):
    global ssid
    chars = list(ssid)
    char_idx = 0

    while _running:
        btn = get_button(PINS, GPIO)

        if btn == "KEY3" or btn == "KEY1":
            ssid = "".join(chars) or "DeadDrop"
            _save_config()
            return
        elif btn == "OK":
            ssid = "".join(chars) or "DeadDrop"
            _save_config()
            return
        elif btn == "UP":
            char_idx = (char_idx + 1) % len(SSID_CHARS)
            time.sleep(0.12)
        elif btn == "DOWN":
            char_idx = (char_idx - 1) % len(SSID_CHARS)
            time.sleep(0.12)
        elif btn == "RIGHT":
            if len(chars) < 30:
                chars.append(SSID_CHARS[char_idx])
            time.sleep(0.15)
        elif btn == "LEFT":
            if chars:
                chars.pop()
            time.sleep(0.15)

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
    global _running, active, status_msg, scroll, confirm_purge, dash_view, iface

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

    iface = select_interface(lcd, font_obj, PINS, GPIO, iface_type="wifi")
    if not iface:
        GPIO.cleanup()
        return 1

    with lock:
        status_msg = f"Using {iface}"

    # Start rate sampler
    threading.Thread(target=_rate_sampler, daemon=True).start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3" and not confirm_purge:
                break

            elif confirm_purge:
                if btn == "OK":
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

            elif btn == "LEFT" and active:
                dash_view = (dash_view - 1) % 3
                scroll = 0
                time.sleep(0.2)

            elif btn == "RIGHT" and active:
                dash_view = (dash_view + 1) % 3
                scroll = 0
                time.sleep(0.2)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                file_count = len(os.listdir(DROP_DIR)) if os.path.isdir(DROP_DIR) else 0
                scroll = min(scroll + 1, max(0, file_count - ROWS_VISIBLE))
                time.sleep(0.15)

            _draw_frame(lcd, font_obj, iface)
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
