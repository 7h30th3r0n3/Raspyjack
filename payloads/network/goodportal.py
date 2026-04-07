#!/usr/bin/env python3
"""
RaspyJack Payload -- Whitelist Portal (GoodPortal)
====================================================
Author: 7h30th3r0n3

DNS redirect portal with MAC whitelist.  Whitelisted MACs get full
internet access; all others are redirected to a configurable portal page.

Uses dnsmasq + iptables for traffic steering.

Controls
--------
  UP / DOWN  -- Navigate menu / whitelist
  OK         -- Activate menu item / select
  KEY1       -- Start / Stop portal
  KEY2       -- Add connected client MAC to whitelist
  KEY3       -- Exit (stops portal if running)

Config: /root/Raspyjack/loot/GoodPortal/whitelist.json
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
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
LOOT_DIR = "/root/Raspyjack/loot/GoodPortal"
WHITELIST_PATH = os.path.join(LOOT_DIR, "whitelist.json")
DNSMASQ_CONF = os.path.join(LOOT_DIR, "dnsmasq_portal.conf")
PORTAL_DIR = os.path.join(LOOT_DIR, "portal_pages")
os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(PORTAL_DIR, exist_ok=True)
ROW_H = 12
DEBOUNCE = 0.20
PORTAL_IFACE = "wlan0"
PORTAL_IP = "10.0.0.1"
PORTAL_SUBNET = "10.0.0.0/24"
PORTAL_RANGE_START = "10.0.0.10"
PORTAL_RANGE_END = "10.0.0.50"
REDIRECT_PORT = 80

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
app_running = True
portal_active = False
whitelist = []              # list of MAC strings
connected_clients = []      # [{"mac": ..., "ip": ...}]
menu_items = ["Start Portal", "View Whitelist", "View Clients"]
selected_idx = 0
scroll_pos = 0
view_mode = "menu"          # menu | whitelist | clients
status_msg = "Stopped"
redirected_count = 0


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# Whitelist persistence
# ---------------------------------------------------------------------------
def _load_whitelist():
    """Load whitelist from JSON file."""
    if not os.path.isfile(WHITELIST_PATH):
        return []
    try:
        with open(WHITELIST_PATH, "r") as fh:
            data = json.load(fh)
        return list(data.get("macs", []))
    except (json.JSONDecodeError, OSError):
        return []


def _save_whitelist(macs):
    """Save whitelist to JSON file."""
    data = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "macs": list(macs),
    }
    try:
        with open(WHITELIST_PATH, "w") as fh:
            json.dump(data, fh, indent=2)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Portal control
# ---------------------------------------------------------------------------
def _run_cmd(args, timeout_s=10):
    """Run a shell command and return (success, stdout)."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout_s,
        )
        return result.returncode == 0, result.stdout.strip()
    except Exception as exc:
        return False, str(exc)


def _write_dnsmasq_conf():
    """Generate dnsmasq config for portal."""
    conf = (
        f"interface={PORTAL_IFACE}\n"
        f"bind-interfaces\n"
        f"dhcp-range={PORTAL_RANGE_START},{PORTAL_RANGE_END},12h\n"
        f"address=/#/{PORTAL_IP}\n"
        f"no-resolv\n"
        f"log-queries\n"
        f"log-dhcp\n"
    )
    try:
        with open(DNSMASQ_CONF, "w") as fh:
            fh.write(conf)
        return True
    except OSError:
        return False


def _apply_iptables_rules(wl_macs):
    """Set up iptables for portal redirection."""
    # Flush portal chain if exists
    _run_cmd(["iptables", "-t", "nat", "-F", "GOODPORTAL"])
    _run_cmd(["iptables", "-t", "nat", "-X", "GOODPORTAL"])

    # Create portal chain
    _run_cmd(["iptables", "-t", "nat", "-N", "GOODPORTAL"])

    # Whitelist: skip redirect for known MACs
    for mac in wl_macs:
        _run_cmd(["iptables", "-t", "nat", "-A", "GOODPORTAL",
                  "-m", "mac", "--mac-source", mac, "-j", "RETURN"])

    # Redirect HTTP for non-whitelisted
    _run_cmd(["iptables", "-t", "nat", "-A", "GOODPORTAL",
              "-p", "tcp", "--dport", "80",
              "-j", "DNAT", "--to-destination", f"{PORTAL_IP}:{REDIRECT_PORT}"])
    _run_cmd(["iptables", "-t", "nat", "-A", "GOODPORTAL",
              "-p", "tcp", "--dport", "443",
              "-j", "DNAT", "--to-destination", f"{PORTAL_IP}:{REDIRECT_PORT}"])
    _run_cmd(["iptables", "-t", "nat", "-A", "GOODPORTAL",
              "-p", "udp", "--dport", "53",
              "-j", "DNAT", "--to-destination", f"{PORTAL_IP}:53"])

    # Insert chain into PREROUTING
    _run_cmd(["iptables", "-t", "nat", "-A", "PREROUTING",
              "-i", PORTAL_IFACE, "-j", "GOODPORTAL"])

    # Allow forwarding for whitelisted MACs
    for mac in wl_macs:
        _run_cmd(["iptables", "-A", "FORWARD",
                  "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"])


def _clear_iptables_rules():
    """Remove portal iptables rules."""
    _run_cmd(["iptables", "-t", "nat", "-D", "PREROUTING",
              "-i", PORTAL_IFACE, "-j", "GOODPORTAL"])
    _run_cmd(["iptables", "-t", "nat", "-F", "GOODPORTAL"])
    _run_cmd(["iptables", "-t", "nat", "-X", "GOODPORTAL"])
    _run_cmd(["iptables", "-D", "FORWARD",
              "-m", "mac", "-j", "ACCEPT"])


def _start_portal():
    """Start the captive portal."""
    global portal_active, status_msg

    # Configure interface
    _run_cmd(["ip", "addr", "flush", "dev", PORTAL_IFACE])
    _run_cmd(["ip", "addr", "add", f"{PORTAL_IP}/24", "dev", PORTAL_IFACE])
    _run_cmd(["ip", "link", "set", PORTAL_IFACE, "up"])

    # Enable IP forwarding
    _run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    # Write dnsmasq config
    if not _write_dnsmasq_conf():
        with lock:
            status_msg = "Config write failed"
        return

    # Kill existing dnsmasq on interface
    _run_cmd(["pkill", "-f", f"dnsmasq.*{DNSMASQ_CONF}"])
    time.sleep(0.5)

    # Start dnsmasq
    ok, _ = _run_cmd(["dnsmasq", "-C", DNSMASQ_CONF, "--pid-file",
                      os.path.join(LOOT_DIR, "dnsmasq.pid")])

    # Apply iptables
    with lock:
        wl = list(whitelist)
    _apply_iptables_rules(wl)

    with lock:
        portal_active = True
        menu_items[0] = "Stop Portal"
        status_msg = "Portal ACTIVE"


def _stop_portal():
    """Stop the captive portal."""
    global portal_active, status_msg

    _run_cmd(["pkill", "-f", f"dnsmasq.*{DNSMASQ_CONF}"])
    _clear_iptables_rules()

    with lock:
        portal_active = False
        menu_items[0] = "Start Portal"
        status_msg = "Stopped"


def _get_connected_clients():
    """Get DHCP leases from dnsmasq."""
    clients = []
    lease_file = "/var/lib/misc/dnsmasq.leases"
    try:
        with open(lease_file, "r") as fh:
            for line in fh:
                parts = line.strip().split()
                if len(parts) >= 4:
                    clients.append({
                        "mac": parts[1],
                        "ip": parts[2],
                        "name": parts[3] if parts[3] != "*" else "",
                    })
    except OSError:
        pass
    return clients


def _refresh_clients():
    """Refresh connected clients list."""
    global connected_clients, redirected_count
    clients = _get_connected_clients()
    with lock:
        connected_clients = clients
        wl_set = {m.lower() for m in whitelist}
        redirected_count = sum(
            1 for c in clients if c["mac"].lower() not in wl_set
        )


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------
def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "GOODPORTAL", font=font, fill="#00ccff")

    with lock:
        vm = view_mode
        sel = selected_idx
        sp = scroll_pos
        msg = status_msg
        active = portal_active
        wl = list(whitelist)
        clients = list(connected_clients)
        redir = redirected_count
        items = list(menu_items)

    # Status indicator
    color = "#00ff00" if active else "#ff4444"
    d.rectangle((118, 2, 125, 11), fill=color)

    if vm == "menu":
        y = 18
        for i, item in enumerate(items):
            prefix = ">" if i == sel else " "
            fill = "#ffff00" if i == sel else "#cccccc"
            d.text((2, y), f"{prefix}{item}", font=font, fill=fill)
            y += ROW_H + 3

        # Stats
        d.text((2, 80), f"Whitelist: {len(wl)}", font=font, fill="#aaaaaa")
        d.text((2, 92), f"Redirected: {redir}", font=font, fill="#aaaaaa")
        d.text((2, 104), msg[:22], font=font, fill="#888888")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K1:start/stop K3:exit", font=font, fill="#666")

    elif vm == "whitelist":
        d.text((70, 1), "WL", font=font, fill="#ffaa00")
        y = 16
        if not wl:
            d.text((2, 50), "Whitelist empty", font=font, fill="#888888")
        else:
            end = min(len(wl), sp + 7)
            for i in range(sp, end):
                prefix = ">" if i == sel else " "
                fill = "#ffff00" if i == sel else "#cccccc"
                d.text((2, y), f"{prefix}{wl[i]}", font=font, fill=fill)
                y += ROW_H

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:remove K3:back", font=font, fill="#666")

    elif vm == "clients":
        d.text((70, 1), "CLI", font=font, fill="#ffaa00")
        y = 16
        if not clients:
            d.text((2, 50), "No clients", font=font, fill="#888888")
        else:
            end = min(len(clients), sp + 6)
            for i in range(sp, end):
                c = clients[i]
                prefix = ">" if i == sel else " "
                wl_set = {m.lower() for m in wl}
                is_wl = c["mac"].lower() in wl_set
                fill = "#00ff00" if is_wl else "#ff8800"
                label = f"{prefix}{c['ip']} {c['mac'][-8:]}"
                d.text((2, y), label[:22], font=font, fill=fill)
                y += ROW_H + 2

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K2:add2wl OK:back", font=font, fill="#666")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global app_running, selected_idx, scroll_pos, view_mode
    global whitelist, status_msg

    whitelist = _load_whitelist()
    last_press = 0.0

    try:
        while app_running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                with lock:
                    if view_mode != "menu":
                        view_mode = "menu"
                        selected_idx = 0
                        scroll_pos = 0
                        btn = None
                    else:
                        break

            if btn == "UP":
                with lock:
                    selected_idx = max(0, selected_idx - 1)
                    if selected_idx < scroll_pos:
                        scroll_pos = selected_idx

            elif btn == "DOWN":
                with lock:
                    if view_mode == "menu":
                        selected_idx = min(len(menu_items) - 1,
                                           selected_idx + 1)
                    elif view_mode == "whitelist":
                        selected_idx = min(len(whitelist) - 1,
                                           selected_idx + 1)
                    elif view_mode == "clients":
                        selected_idx = min(len(connected_clients) - 1,
                                           selected_idx + 1)
                    if selected_idx >= scroll_pos + 7:
                        scroll_pos = selected_idx - 6

            elif btn == "OK":
                with lock:
                    vm = view_mode
                    sel = selected_idx

                if vm == "menu":
                    if sel == 0:
                        # Start/Stop handled by KEY1
                        pass
                    elif sel == 1:
                        with lock:
                            view_mode = "whitelist"
                            selected_idx = 0
                            scroll_pos = 0
                    elif sel == 2:
                        _refresh_clients()
                        with lock:
                            view_mode = "clients"
                            selected_idx = 0
                            scroll_pos = 0

                elif vm == "whitelist":
                    # Remove selected MAC
                    with lock:
                        if 0 <= sel < len(whitelist):
                            removed = whitelist[sel]
                            whitelist = [
                                m for i, m in enumerate(whitelist) if i != sel
                            ]
                            _save_whitelist(whitelist)
                            status_msg = f"Removed {removed[-8:]}"
                            selected_idx = min(selected_idx,
                                               max(0, len(whitelist) - 1))

                elif vm == "clients":
                    with lock:
                        view_mode = "menu"
                        selected_idx = 0
                        scroll_pos = 0

            elif btn == "KEY1":
                with lock:
                    active = portal_active
                if active:
                    _stop_portal()
                else:
                    threading.Thread(
                        target=_start_portal, daemon=True,
                    ).start()

            elif btn == "KEY2":
                with lock:
                    vm = view_mode
                    sel = selected_idx
                if vm == "clients":
                    with lock:
                        if 0 <= sel < len(connected_clients):
                            mac = connected_clients[sel]["mac"]
                            if mac.lower() not in {m.lower()
                                                   for m in whitelist}:
                                whitelist = list(whitelist) + [mac]
                                _save_whitelist(whitelist)
                                status_msg = f"Added {mac[-8:]}"

            # Periodic client refresh when portal is active
            if portal_active and int(now) % 5 == 0:
                _refresh_clients()

            _draw_screen()
            time.sleep(0.1)

    finally:
        app_running = False
        if portal_active:
            _stop_portal()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
