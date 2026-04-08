#!/usr/bin/env python3
"""
RaspyJack Payload -- Ethernet Interface Recon
===============================================
Author: 7h30th3r0n3

Scans for available ethernet interfaces and performs host discovery
via arp-scan with optional nmap deep scanning on selected hosts.

Controls:
  UP / DOWN  -- Scroll host list / interface list
  LEFT/RIGHT -- Switch between interface info and host list views
  OK         -- Select interface / Run nmap on selected host
  KEY1       -- Refresh scan
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/EthernetRecon/<timestamp>.json
"""

import os
import sys
import json
import time
import re
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Pin / LCD setup
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

LOOT_DIR = "/root/Raspyjack/loot/EthernetRecon"
ROW_H = 12
ROWS_VISIBLE = 6
CANDIDATE_IFACES = ["eth0", "eth1", "usb0", "usb1", "enp0s3", "ens33"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
scanning = False
status_msg = "Idle"
scroll_pos = 0
selected_idx = 0

# View mode: "iface_list", "host_list", "nmap_result"
view_mode = "iface_list"

# Detected interfaces: [{"name", "link", "ip", "gateway", "dns"}]
interfaces = []

# Selected interface index
iface_sel = 0

# Discovered hosts: [{"ip", "mac", "vendor"}]
hosts = []

# Nmap result text lines
nmap_lines = []
nmap_scroll = 0


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def _get_iface_info(iface):
    """Gather link status, IP, gateway, DNS for an interface."""
    info = {"name": iface, "link": "down", "ip": "", "gateway": "", "dns": ""}

    # Check link status
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        if "state UP" in result.stdout:
            info["link"] = "up"
        elif "state DOWN" in result.stdout:
            info["link"] = "down"
    except Exception:
        return None

    if "NO-CARRIER" in (info.get("_raw", "") or ""):
        info["link"] = "no-carrier"

    # Get IP
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("inet "):
                info["ip"] = stripped.split()[1]
                break
    except Exception:
        pass

    # Get gateway
    try:
        result = subprocess.run(
            ["ip", "route", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "default" in line:
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via") + 1
                    if idx < len(parts):
                        info["gateway"] = parts[idx]
                break
    except Exception:
        pass

    # Get DNS
    try:
        result = subprocess.run(
            ["cat", "/etc/resolv.conf"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("nameserver"):
                info["dns"] = stripped.split()[1]
                break
    except Exception:
        pass

    return info


def _detect_interfaces():
    """Scan for available ethernet interfaces."""
    found = []
    for iface in CANDIDATE_IFACES:
        info = _get_iface_info(iface)
        if info is not None:
            found.append(info)

    # Also check for any interface matching eth* or usb* or enp*
    try:
        result = subprocess.run(
            ["ls", "/sys/class/net/"],
            capture_output=True, text=True, timeout=5,
        )
        known_names = {i["name"] for i in found}
        for name in result.stdout.split():
            name = name.strip()
            if name in known_names:
                continue
            if any(name.startswith(p) for p in ["eth", "usb", "enp", "ens"]):
                info = _get_iface_info(name)
                if info is not None:
                    found.append(info)
    except Exception:
        pass

    return found


# ---------------------------------------------------------------------------
# ARP scan thread
# ---------------------------------------------------------------------------
def _arp_scan_thread(iface):
    """Run arp-scan on the selected interface."""
    global scanning, status_msg, hosts

    with lock:
        status_msg = f"Scanning {iface}..."
        scanning = True
        hosts = []

    try:
        result = subprocess.run(
            ["arp-scan", f"--interface={iface}", "-l"],
            capture_output=True, text=True, timeout=30,
        )
        parsed = []
        for line in result.stdout.splitlines():
            # arp-scan output: IP\tMAC\tVendor
            parts = line.split("\t")
            if len(parts) >= 2:
                ip_match = re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parts[0])
                if ip_match:
                    entry = {
                        "ip": parts[0].strip(),
                        "mac": parts[1].strip().upper(),
                        "vendor": parts[2].strip() if len(parts) >= 3 else "",
                    }
                    parsed.append(entry)

        with lock:
            hosts = parsed
            status_msg = f"Found {len(parsed)} hosts"

    except FileNotFoundError:
        with lock:
            status_msg = "arp-scan not found"
    except subprocess.TimeoutExpired:
        with lock:
            status_msg = "Scan timeout"
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:14]}"
    finally:
        with lock:
            scanning = False


# ---------------------------------------------------------------------------
# Nmap scan thread
# ---------------------------------------------------------------------------
def _nmap_thread(target_ip):
    """Run nmap quick scan on a host."""
    global scanning, status_msg, nmap_lines

    with lock:
        status_msg = f"nmap {target_ip}..."
        scanning = True
        nmap_lines = []

    try:
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "-F", target_ip],
            capture_output=True, text=True, timeout=120,
        )
        parsed = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped:
                parsed.append(stripped)

        with lock:
            nmap_lines = parsed
            status_msg = f"nmap done ({len(parsed)}L)"

    except FileNotFoundError:
        with lock:
            status_msg = "nmap not found"
            nmap_lines = ["nmap is not installed"]
    except subprocess.TimeoutExpired:
        with lock:
            status_msg = "nmap timeout"
            nmap_lines = ["Scan timed out"]
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:14]}"
            nmap_lines = [f"Error: {str(exc)[:30]}"]
    finally:
        with lock:
            scanning = False


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------
def _export_loot():
    """Write recon results to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"ether_{ts}.json")

    with lock:
        data = {
            "timestamp": ts,
            "interfaces": list(interfaces),
            "hosts": list(hosts),
            "nmap_output": list(nmap_lines),
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filepath


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
def _draw_header(d, font, title, active):
    """Draw header bar."""
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00CCFF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#444")


def _draw_footer(d, font, text):
    """Draw footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _draw_iface_list(lcd, font):
    """Draw the interface selection view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = scanning
        st = status_msg
        iface_list = list(interfaces)
        sel = iface_sel

    _draw_header(d, font, "ETH RECON", active)

    d.text((2, 15), f"{st[:22]}", font=font, fill="#888")

    if not iface_list:
        d.text((6, 40), "No ethernet ifaces", font=font, fill="#FF4444")
        d.text((6, 52), "found on device", font=font, fill="#FF4444")
    else:
        d.text((2, 27), "Select interface:", font=font, fill="#AAA")
        for i, iface in enumerate(iface_list):
            y = 40 + i * ROW_H
            if i >= 5:
                break
            prefix = ">" if i == sel else " "
            link_color = "#00FF00" if iface["link"] == "up" else "#FF4444"
            ip_str = iface["ip"][:15] if iface["ip"] else "no-ip"
            line = f"{prefix}{iface['name']:<6s} {ip_str}"
            d.text((1, y), line[:22], font=font, fill=link_color)

    _draw_footer(d, font, "OK:Sel K1:Refresh K3:X")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_host_list(lcd, font):
    """Draw the discovered hosts view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = scanning
        st = status_msg
        host_list = list(hosts)
        sc = scroll_pos
        sel = selected_idx
        iface_name = interfaces[iface_sel]["name"] if interfaces else "?"

    _draw_header(d, font, f"HOSTS [{iface_name}]", active)

    d.text((2, 15), f"{st[:22]}", font=font, fill="#888")

    if not host_list:
        d.text((6, 40), "No hosts found", font=font, fill="#666")
        d.text((6, 52), "K1:Rescan LEFT:Back", font=font, fill="#666")
    else:
        visible = host_list[sc:sc + ROWS_VISIBLE]
        for i, host in enumerate(visible):
            y = 28 + i * ROW_H
            idx = sc + i
            prefix = ">" if idx == sel else " "
            ip = host["ip"]
            vendor = host["vendor"][:6] if host["vendor"] else ""
            line = f"{prefix}{ip:<15s} {vendor}"
            color = "#CCCCCC" if idx != sel else "#00FF00"
            d.text((1, y), line[:22], font=font, fill=color)

        total_items = len(host_list)
        if total_items > ROWS_VISIBLE:
            area_h = ROWS_VISIBLE * ROW_H
            ind_h = max(4, int(ROWS_VISIBLE / total_items * area_h))
            ind_y = 28 + int(sc / total_items * area_h)
            d.rectangle((126, ind_y, 127, ind_y + ind_h), fill="#444")

    _draw_footer(d, font, f"{len(host_list)}H OK:nmap K3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_nmap_result(lcd, font):
    """Draw nmap scan results."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = scanning
        lines = list(nmap_lines)
        sc = nmap_scroll

    _draw_header(d, font, "NMAP RESULT", active)

    if not lines:
        d.text((6, 40), "No results yet", font=font, fill="#666")
    else:
        visible = lines[sc:sc + 8]
        for i, line in enumerate(visible):
            y = 16 + i * ROW_H
            # Truncate long lines
            display_line = line[:22]
            color = "#00FF00" if "open" in line.lower() else "#CCCCCC"
            d.text((1, y), display_line, font=font, fill=color)

    _draw_footer(d, font, "LEFT:Back K3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _show_message(lcd, font, line1, line2=""):
    """Show a brief message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global running, scroll_pos, selected_idx, view_mode
    global interfaces, iface_sel, hosts, nmap_lines, nmap_scroll, scanning

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Splash screen
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "ETHERNET RECON", font=font, fill="#00CCFF")
    d.text((4, 32), "Interface scanner", font=font, fill="#888")
    d.text((4, 44), "with arp-scan and", font=font, fill="#888")
    d.text((4, 56), "nmap integration", font=font, fill="#888")
    d.text((4, 72), "OK:Select K1:Scan", font=font, fill="#666")
    d.text((4, 84), "K2:Export K3:Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    # Initial interface detection
    running = True
    interfaces = _detect_interfaces()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if hosts:
                    _export_loot()
                break

            # ------- Interface list view -------
            if view_mode == "iface_list":
                if btn == "UP":
                    iface_sel = max(0, iface_sel - 1)
                    time.sleep(0.15)

                elif btn == "DOWN":
                    iface_sel = min(len(interfaces) - 1, iface_sel + 1) if interfaces else 0
                    time.sleep(0.15)

                elif btn == "OK" and interfaces and not scanning:
                    selected_iface = interfaces[iface_sel]
                    if selected_iface["link"] == "up" and selected_iface["ip"]:
                        view_mode = "host_list"
                        scroll_pos = 0
                        selected_idx = 0
                        threading.Thread(
                            target=_arp_scan_thread,
                            args=(selected_iface["name"],),
                            daemon=True,
                        ).start()
                    else:
                        _show_message(lcd, font, "Interface down", "or no IP assigned")
                    time.sleep(0.3)

                elif btn == "KEY1":
                    interfaces = _detect_interfaces()
                    iface_sel = 0
                    time.sleep(0.3)

                elif btn == "KEY2":
                    if interfaces:
                        path = _export_loot()
                        _show_message(lcd, font, "Exported!", path[-20:])
                    time.sleep(0.3)

                _draw_iface_list(lcd, font)

            # ------- Host list view -------
            elif view_mode == "host_list":
                if btn == "LEFT":
                    view_mode = "iface_list"
                    time.sleep(0.2)

                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        max_sel = max(0, len(hosts) - 1)
                        selected_idx = min(selected_idx + 1, max_sel)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.15)

                elif btn == "OK" and not scanning:
                    with lock:
                        host_list = list(hosts)
                        sel = selected_idx
                    if host_list and 0 <= sel < len(host_list):
                        target = host_list[sel]["ip"]
                        nmap_scroll = 0
                        view_mode = "nmap_result"
                        threading.Thread(
                            target=_nmap_thread,
                            args=(target,),
                            daemon=True,
                        ).start()
                    time.sleep(0.3)

                elif btn == "KEY1" and not scanning:
                    if interfaces and iface_sel < len(interfaces):
                        scroll_pos = 0
                        selected_idx = 0
                        threading.Thread(
                            target=_arp_scan_thread,
                            args=(interfaces[iface_sel]["name"],),
                            daemon=True,
                        ).start()
                    time.sleep(0.3)

                elif btn == "KEY2":
                    if hosts:
                        path = _export_loot()
                        _show_message(lcd, font, "Exported!", path[-20:])
                    time.sleep(0.3)

                _draw_host_list(lcd, font)

            # ------- Nmap result view -------
            elif view_mode == "nmap_result":
                if btn == "LEFT":
                    view_mode = "host_list"
                    time.sleep(0.2)

                elif btn == "UP":
                    nmap_scroll = max(0, nmap_scroll - 1)
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        max_scroll = max(0, len(nmap_lines) - 8)
                    nmap_scroll = min(nmap_scroll + 1, max_scroll)
                    time.sleep(0.15)

                elif btn == "KEY2":
                    if nmap_lines:
                        path = _export_loot()
                        _show_message(lcd, font, "Exported!", path[-20:])
                    time.sleep(0.3)

                _draw_nmap_result(lcd, font)

            time.sleep(0.05)

    finally:
        running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
