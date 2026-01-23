#!/usr/bin/env python3
"""
RaspyJack Payload – SMB Probe (port 445)
---------------------------------------
- Detects active subnet
- Scans for SMB (445/tcp) open hosts (no exploitation)
- Saves results to loot/SMB/
- Displays results on LCD, scrollable with UP/DOWN, exit on KEY3
"""

import os
import sys
import time
import subprocess
from datetime import datetime
import ipaddress

# Ensure RaspyJack modules are importable
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO  # type: ignore
import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore

WIDTH, HEIGHT = 128, 128
KEY_UP = 6
KEY_DOWN = 19
KEY_PRESS = 13
KEY3 = 16


def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    return lcd


def draw_lines(lcd, lines, color="white", bg="black"):
    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    y = 5
    for line in lines:
        if line:
            d.text((5, y), line[:18], font=font, fill=color)
            y += 14
    lcd.LCD_ShowImage(img, 0, 0)


def _read(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _iface_carrier_up(name):
    return _read(f"/sys/class/net/{name}/carrier") == "1"


def _iface_ip_cidr(name):
    res = subprocess.run(["ip", "-4", "addr", "show", "dev", name], capture_output=True, text=True)
    if res.returncode != 0:
        return None
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            return line.split()[1]
    return None


def list_interfaces():
    ifaces = []
    for name in os.listdir("/sys/class/net"):
        if name == "lo":
            continue
        cidr = _iface_ip_cidr(name)
        if cidr:
            ifaces.append((name, cidr))
    # prefer eth/wlan first
    def score(n):
        if n.startswith("eth"):
            return 0
        if n.startswith("wlan"):
            return 1
        return 2
    ifaces.sort(key=lambda x: (score(x[0]), x[0]))
    return ifaces


def select_interface_menu(lcd):
    ifaces = list_interfaces()
    if not ifaces:
        return None, None
    idx = 0
    offset = 0
    while True:
        lines = ["Select IFACE"]
        window = ifaces[offset:offset + 5]
        for i, (name, cidr) in enumerate(window):
            real_idx = offset + i
            mark = ">" if real_idx == idx else " "
            lines.append(f"{mark}{name} {cidr.split('/')[0]}")
        lines.append("KEY3=Back")
        draw_lines(lcd, lines)
        time.sleep(0.1)
        if GPIO.input(KEY3) == 0:
            return None, None
        if GPIO.input(KEY_UP) == 0:
            idx = max(0, idx - 1)
        elif GPIO.input(KEY_DOWN) == 0:
            idx = min(len(ifaces) - 1, idx + 1)
        # keep selection within window
        if idx < offset:
            offset = idx
        elif idx >= offset + 5:
            offset = idx - 4
        if GPIO.input(KEY_PRESS) == 0:
            name, cidr = ifaces[idx]
            return name, cidr


def select_mask_menu(lcd, cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        base_ip = str(net.network_address)
    except Exception:
        return cidr
    options = ["/24", "/16"]
    idx = 0
    while True:
        lines = ["Select mask"]
        for i, opt in enumerate(options):
            mark = ">" if i == idx else " "
            lines.append(f"{mark}{base_ip}{opt}")
        lines.append("KEY3=Back")
        draw_lines(lcd, lines)
        time.sleep(0.1)
        if GPIO.input(KEY3) == 0:
            return cidr
        if GPIO.input(KEY_UP) == 0:
            idx = max(0, idx - 1)
        elif GPIO.input(KEY_DOWN) == 0:
            idx = min(len(options) - 1, idx + 1)
        if GPIO.input(KEY_PRESS) == 0:
            chosen = options[idx]
            return f"{base_ip}{chosen}"


def parse_hosts_from_nmap(path):
    hosts = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Nmap scan report for "):
                    host = line.replace("Nmap scan report for ", "").strip()
                    hosts.append(host)
    except Exception:
        pass
    return hosts


def scroll_list(lcd, title, items):
    if not items:
        draw_lines(lcd, [title, "No SMB hosts", "", "KEY3 to exit"])
        while GPIO.input(KEY3) == 1:
            time.sleep(0.1)
        return

    idx = 0
    window = 6
    while True:
        start = max(0, min(idx, max(0, len(items) - window)))
        visible = items[start:start + window]
        lines = [title] + visible
        lines.append("KEY3=Exit")
        draw_lines(lcd, lines)
        time.sleep(0.1)

        if GPIO.input(KEY3) == 0:
            return
        if GPIO.input(KEY_UP) == 0:
            idx = max(0, idx - 1)
        elif GPIO.input(KEY_DOWN) == 0:
            idx = min(len(items) - 1, idx + 1)


def main():
    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(KEY_UP, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY_DOWN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY_PRESS, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY3, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    iface, cidr = select_interface_menu(lcd)
    if not iface or not cidr:
        draw_lines(lcd, ["SMB Probe", "No interface", "", "KEY3 to exit"])
        while GPIO.input(KEY3) == 1:
            time.sleep(0.1)
        return 1

    target = select_mask_menu(lcd, cidr)

    loot_dir = "/root/Raspyjack/loot/SMB"
    os.makedirs(loot_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    out_path = f"{loot_dir}/smb_probe_{ts}.txt"

    draw_lines(lcd, ["SMB Probe", f"IF: {iface}", f"NET: {target[:14]}", "Scanning..."])

    cmd = ["nmap", "-n", "-p", "445", "--open", "-oN", out_path, target]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Allow cancel during scan
    while proc.poll() is None:
        if GPIO.input(KEY3) == 0:
            proc.terminate()
            proc.wait(timeout=3)
            draw_lines(lcd, ["SMB Probe", "Cancelled", "", "KEY3 to exit"])
            while GPIO.input(KEY3) == 1:
                time.sleep(0.1)
            return 0
        time.sleep(0.2)

    hosts = parse_hosts_from_nmap(out_path)
    title = f"SMB Hosts ({len(hosts)})"
    scroll_list(lcd, title, hosts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
