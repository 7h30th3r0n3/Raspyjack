#!/usr/bin/env python3
"""
Quick WiFi Connect payload
--------------------------
Auto-connect to the strongest *saved* WiFi network currently in range.
If no saved network is found, suggest using the full WiFi Manager.
"""

import os
import sys
import subprocess
import time
from payloads._display_helper import ScaledDraw, scaled_font

# Ensure RaspyJack modules are importable when launched directly
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LCD_OK = False
LCD = None
WIDTH = 128
HEIGHT = 128
font = None


def _init_lcd():
    global LCD_OK, LCD, font, WIDTH, HEIGHT
    try:
        import LCD_1in44, LCD_Config  # type: ignore
        from PIL import ImageFont  # type: ignore

        LCD_Config.GPIO_Init()
        LCD = LCD_1in44.LCD()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()
        WIDTH, HEIGHT = LCD.width, LCD.height
        font = scaled_font()
        LCD_OK = True
    except Exception:
        LCD_OK = False


def _show(lines, progress=None):
    text = "\n".join(lines)
    print(text)
    if not LCD_OK:
        return
    try:
        from PIL import Image, ImageDraw  # type: ignore
        from payloads._display_helper import ScaledDraw, scaled_font

        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        draw = ScaledDraw(img)
        y = 5
        for line in lines:
            if line:
                draw.text((5, y), line[:18], font=font, fill="WHITE")
                y += 14
        if progress is not None:
            p = max(0.0, min(1.0, progress))
            x0, y0, x1, y1 = 6, 112, 122, 120
            draw.rectangle((x0, y0, x1, y1), outline="WHITE", fill="BLACK")
            fill_w = int((x1 - x0) * p)
            if fill_w > 0:
                draw.rectangle((x0, y0, x0 + fill_w, y1), fill="WHITE")
        LCD.LCD_ShowImage(img, 0, 0)
    except Exception:
        pass


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


PROFILES_DIR = "/root/Raspyjack/wifi/profiles"


def _get_saved_wifi():
    """Get saved WiFi networks from both nmcli and RaspyJack JSON profiles."""
    saved = {}  # ssid -> password (None if nmcli-only)

    # 1. nmcli saved connections (already known to NetworkManager)
    res = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    if res.returncode == 0:
        for line in res.stdout.strip().splitlines():
            if not line:
                continue
            name, ctype = line.split(":", 1)
            if ctype in ("wifi", "802-11-wireless") and name:
                saved[name] = None  # nmcli knows the password

    # 2. RaspyJack WiFi Manager JSON profiles (may have password nmcli doesn't)
    try:
        import json
        for fname in os.listdir(PROFILES_DIR):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(PROFILES_DIR, fname), "r") as f:
                    profile = json.load(f)
                ssid = profile.get("ssid", "")
                password = profile.get("password", "")
                if ssid and ssid not in saved:
                    saved[ssid] = password
                elif ssid and password and saved.get(ssid) is None:
                    saved[ssid] = password  # enrich nmcli entry with password
            except Exception:
                continue
    except Exception:
        pass

    return saved


def _scan_wifi():
    res = _run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "no"])
    if res.returncode != 0:
        res = _run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes"])
        if res.returncode != 0:
            return []
    networks = []
    for line in res.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        ssid = parts[0].strip()
        if not ssid:
            continue
        try:
            signal = int(parts[1])
        except ValueError:
            signal = 0
        security = parts[2]
        networks.append({"ssid": ssid, "signal": signal, "security": security})
    return networks


def _get_wifi_device():
    res = _run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev"])
    if res.returncode != 0:
        return None
    for line in res.stdout.strip().splitlines():
        if not line:
            continue
        dev, dtype, state = line.split(":", 2)
        if dtype == "wifi" and state in ("connected", "connecting", "disconnected"):
            return dev
    return None


def _select_wifi_iface():
    """Let the user pick a WiFi interface on LCD, or auto-select if only one."""
    if not LCD_OK:
        return _get_wifi_device()
    try:
        import RPi.GPIO as GPIO
        from payloads._iface_helper import select_interface
        from payloads._input_helper import get_button

        PINS = {
            "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
            "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
        }
        GPIO.setmode(GPIO.BCM)
        for p in PINS.values():
            GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        iface = select_interface(LCD, font, PINS, GPIO, iface_type="wifi",
                                 title="CONNECT IFACE")
        return iface
    except Exception:
        return _get_wifi_device()


def _discover_hosts(iface, local_ip):
    """Quick host discovery using arp-scan or nmap ping scan."""
    # Determine subnet from local IP
    try:
        parts = local_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return []

    found_ips = []

    # Try arp-scan first (faster)
    try:
        res = _run(["sudo", "arp-scan", "-l", "-I", iface, "-q"])
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("Interface") or line.startswith("Starting"):
                    continue
                ip_part = line.split("\t")[0].split()[0] if "\t" in line else line.split()[0]
                # Validate it looks like an IP
                if ip_part.count(".") == 3:
                    found_ips.append(ip_part)
            if found_ips:
                return found_ips
    except Exception:
        pass

    # Fallback to nmap ping scan
    try:
        res = _run(["nmap", "-sn", subnet, "-T4", "--max-retries", "1"])
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                line = line.strip()
                if "Nmap scan report for" in line:
                    # Extract IP: "Nmap scan report for 192.168.1.1" or "... for host (192.168.1.1)"
                    if "(" in line:
                        ip_part = line.split("(")[1].rstrip(")")
                    else:
                        ip_part = line.split()[-1]
                    if ip_part.count(".") == 3:
                        found_ips.append(ip_part)
    except Exception:
        pass

    return found_ips


def main():
    _init_lcd()

    # Interface selection
    dev = _select_wifi_iface()
    if not dev:
        _show(["No interface", "selected", "", "Exiting"], progress=1.0)
        time.sleep(0.8)
        return 1

    _show(["Quick WiFi", f"Using: {dev}", "Scanning...", "Please wait"], progress=0.10)
    saved = _get_saved_wifi()
    if not saved:
        _show(["No saved WiFi", "Use WiFi Manager", "", "Exiting"], progress=1.0)
        time.sleep(0.8)
        return 1

    # Rescan on selected interface
    _run(["nmcli", "device", "wifi", "rescan", "ifname", dev])
    time.sleep(2)

    nets = _scan_wifi()
    candidates = [n for n in nets if n["ssid"] in saved]
    if not candidates:
        _show(["No saved", "WiFi in range", "Use WiFi Manager", "Exiting"], progress=1.0)
        time.sleep(0.8)
        return 1

    best = sorted(candidates, key=lambda x: x["signal"], reverse=True)[0]
    ssid = best["ssid"]
    password = saved.get(ssid)
    _show(
        ["SSID:", ssid[:16], f"Signal: {best['signal']}", "Connecting..."],
        progress=0.55,
    )

    # Build nmcli command with password if available
    cmd = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", dev]
    if password:
        cmd += ["password", password]

    res = _run(cmd)
    if res.returncode != 0:
        _show(["Connect failed", ssid[:16], "Use WiFi Manager", ""], progress=1.0)
        time.sleep(0.8)
        return 1
    _show(
        ["Connected", best["ssid"][:16], f"Interface: {dev}", "Getting IP..."],
        progress=0.80,
    )
    ip_res = _run(["ip", "-4", "addr", "show", "dev", dev])
    ip = "unknown"
    if ip_res.returncode == 0:
        for line in ip_res.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ip = line.split()[1].split("/")[0]
                break

    _show(["Connected", best["ssid"][:16], f"IP: {ip[:15]}", "Scanning hosts..."], progress=0.90)

    # Quick host discovery on the connected subnet
    hosts_found = _discover_hosts(dev, ip)
    if hosts_found:
        lines = [f"Connected: {best['ssid'][:14]}", f"Hosts found: {len(hosts_found)}"]
        for host_ip in hosts_found[:4]:
            lines.append(f" {host_ip[:16]}")
        if len(hosts_found) > 4:
            lines.append(f" +{len(hosts_found)-4} more")
        _show(lines, progress=1.0)
    else:
        _show(["Connected", best["ssid"][:16], f"IP: {ip[:15]}", "No hosts found"], progress=1.0)

    time.sleep(1.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
