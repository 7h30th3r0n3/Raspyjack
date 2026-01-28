#!/usr/bin/env python3
"""
RaspyJack Payload – Interface Status (eth0/eth1)
------------------------------------------------
Split screen: left = eth0, right = eth1
Live status: operstate, IP, RX/TX bytes
Exit with KEY3
"""

import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO  # type: ignore
import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore

WIDTH, HEIGHT = 128, 128
KEY3 = 16
REFRESH = 0.5


def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    return lcd


def _read(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _iface_ip(name):
    try:
        import subprocess
        res = subprocess.run(["ip", "-4", "addr", "show", "dev", name], capture_output=True, text=True)
        if res.returncode != 0:
            return "-"
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "-"


def _iface_stats(name):
    base = f"/sys/class/net/{name}/statistics"
    rx = _read(os.path.join(base, "rx_bytes"))
    tx = _read(os.path.join(base, "tx_bytes"))
    return rx or "0", tx or "0"


def _iface_state(name):
    return _read(f"/sys/class/net/{name}/operstate") or "unknown"


def _fmt_bytes(n):
    try:
        n = int(n)
    except Exception:
        return "-"
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n}{unit}"
        n //= 1024
    return f"{n}T"


def _short_ip(ip):
    return ip or "-"


def _split_ip_lines(ip):
    if not ip or ip == "-":
        return ["ip:", "-"]
    parts = ip.split(".")
    if len(parts) == 4:
        return ["ip:", f"{parts[0]}.{parts[1]}.", f"{parts[2]}.{parts[3]}"]
    return ["ip:", ip]


def draw(lcd, left, right):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    # Header
    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((4, 1), "Interface Status", font=font, fill="white")
    d.text((92, 1), "KEY3", font=font, fill="white")

    # Divider (shift for swapped columns)
    d.line((63, 12, 63, 127), fill="#333333")

    # Left column (eth1)
    lx = 3
    y = 16
    for line in left:
        d.text((lx, y), line[:10], font=font, fill="white")
        y += 12

    # Right column (eth0)
    rx = 67
    y = 16
    for line in right:
        d.text((rx, y), line[:10], font=font, fill="white")
        y += 12

    lcd.LCD_ShowImage(img, 0, 0)


def main():
    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(KEY3, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    ifaces = ("eth0", "eth1")

    try:
        while True:
            if GPIO.input(KEY3) == 0:
                break

            ip1 = _short_ip(_iface_ip('eth1'))
            left = ["eth1", f"st:{_iface_state('eth1')}"] + _split_ip_lines(ip1)
            rx, tx = _iface_stats("eth1")
            left += [f"rx:{_fmt_bytes(rx)}", f"tx:{_fmt_bytes(tx)}"]

            ip0 = _short_ip(_iface_ip('eth0'))
            right = ["eth0", f"st:{_iface_state('eth0')}"] + _split_ip_lines(ip0)
            rx, tx = _iface_stats("eth0")
            right += [f"rx:{_fmt_bytes(rx)}", f"tx:{_fmt_bytes(tx)}"]

            draw(lcd, left, right)
            time.sleep(REFRESH)
    finally:
        LCD_1in44.LCD().LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
