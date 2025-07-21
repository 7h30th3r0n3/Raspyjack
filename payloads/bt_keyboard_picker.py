#!/usr/bin/env python3
"""
RaspyJack payload – Bluetooth Keyboard Picker
===========================================

Interactive joystick + LCD helper to **scan**, **pair**, **trust** and **connect**
a Bluetooth keyboard (or any HID) without touching the shell.

Fix (2025‑07‑21 – rev 2)
-----------------------
* **KEY3 now exits** cleanly from anywhere (scan menu or after connection) by
  calling `cleanup()` → the outer loop ends; no more unintended restart.

Usage
-----
```bash
sudo python3 payloads/bt_keyboard_picker.py
```
UP/DOWN : navigation OK : sélectionner KEY3 : retour/menu RaspyJack.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
import os, sys, subprocess, signal, time, re
from select import select
from typing import List, Tuple
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO               # Raspberry Pi GPIO access
import LCD_1in44                      # Waveshare LCD driver
from PIL import Image, ImageDraw, ImageFont  # Pillow – draw text

# ---------------------------------------------------------------------------
# 1) GPIO mapping (BCM)
# ---------------------------------------------------------------------------
PINS: dict[str, int] = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

# ---------------------------------------------------------------------------
# 2) GPIO & LCD initialisation
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
FONT = ImageFont.load_default()
FONT_BIG = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)

# ---------------------------------------------------------------------------
# 3) Tiny UI helpers
# ---------------------------------------------------------------------------

def draw(lines: List[str]) -> None:
    """Clear the LCD and write *lines* (≤5)."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    y = 4
    for ln in lines[:5]:
        bbox = d.textbbox((0, 0), ln, font=FONT)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (WIDTH - w) // 2
        d.text((x, y), ln, font=FONT, fill="#00FF00")
        y += h + 4
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 4) Graceful shutdown
# ---------------------------------------------------------------------------
running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Bluetooth helper functions
# ---------------------------------------------------------------------------
SCAN_SECONDS = 10  # adjustable


def discover_devices() -> List[Tuple[str, str]]:
    """Return list of (MAC, name) after scanning for *SCAN_SECONDS*."""
    draw(["Scanning", f"{SCAN_SECONDS} s"])

    proc = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdin and proc.stdout
    proc.stdin.write("scan on\n"); proc.stdin.flush()

    seen: dict[str, str] = {}
    start = time.time()
    try:
        while running and (time.time() - start) < SCAN_SECONDS:
            ready, _, _ = select([proc.stdout], [], [], 0.2)
            if ready:
                line = proc.stdout.readline()
                m = re.search(r"Device ([0-9A-F:]{17}) (.+)", line)
                if m:
                    mac, name = m.group(1), m.group(2).strip()
                    seen[mac] = name
    finally:
        # Stop scan & drain for 2 s
        proc.stdin.write("scan off\n"); proc.stdin.flush()
        end = time.time() + 2
        while time.time() < end:
            ready, _, _ = select([proc.stdout], [], [], 0.2)
            if ready:
                line = proc.stdout.readline()
                m = re.search(r"Device ([0-9A-F:]{17}) (.+)", line)
                if m:
                    mac, name = m.group(1), m.group(2).strip()
                    seen[mac] = name
        proc.terminate()

    return sorted(seen.items(), key=lambda t: (t[1].lower(), t[0]))


def pair_trust_connect(mac: str) -> bool:
    """Return *True* if the whole sequence succeeds."""
    draw(["Pairing", mac])

    proc = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdin and proc.stdout

    def send(cmd: str):
        proc.stdin.write(cmd + "\n"); proc.stdin.flush()

    for cmd in ("power on", "agent on", "default-agent"):
        send(cmd); time.sleep(0.3)

    # ---------------- Pair ----------------
    send(f"pair {mac}")
    paired = False; start = time.time()
    while running and (time.time() - start) < 60:
        ready, _, _ = select([proc.stdout], [], [], 0.5)
        if not ready:
            continue
        line = proc.stdout.readline()
        if "Passkey" in line or "PIN code" in line:
            code = "".join(re.findall(r"\d", line))
            draw(["Type on KB:", code])
        if "Confirm passkey" in line:
            send("yes")
        if "Paired: yes" in line or "Bonded: yes" in line:
            paired = True; break
        if "Failed" in line or "Authentication" in line:
            break
        if not running:  # KEY3 pressed mid‑pairing
            break

    if not paired or not running:
        proc.terminate(); return False

    # ---------------- Trust ----------------
    send(f"trust {mac}"); time.sleep(0.5)

    # ---------------- Connect ----------------
    send(f"connect {mac}")
    connected = False; start = time.time()
    while running and (time.time() - start) < 15:
        ready, _, _ = select([proc.stdout], [], [], 0.5)
        if not ready:
            continue
        line = proc.stdout.readline()
        if "Connection successful" in line or "already" in line:
            connected = True; break
        if "Failed" in line:
            break
        if not running:
            break

    send("quit"); proc.wait(timeout=5)
    return connected and running

# ---------------------------------------------------------------------------
# 6) Joystick menu helpers
# ---------------------------------------------------------------------------

def choose(devices: List[Tuple[str, str]]):
    if not devices:
        draw(["No devices", "KEY3 = back"])
        while running and GPIO.input(PINS["KEY3"]):
            time.sleep(0.1)
        cleanup()  # ensure exit on KEY3
        return None

    idx = 0
    while running:
        mac, name = devices[idx]
        draw([f"{idx+1}/{len(devices)}", name[:16], mac, "UP/DOWN nav", "OK select"])
        pressed = None
        for key, pin in PINS.items():
            if GPIO.input(pin) == 0:
                pressed = key; break
        if pressed == "UP":
            idx = (idx - 1) % len(devices)
        elif pressed == "DOWN":
            idx = (idx + 1) % len(devices)
        elif pressed == "OK":
            return devices[idx]
        elif pressed == "KEY3":
            cleanup(); return None
        time.sleep(0.15)

# ---------------------------------------------------------------------------
# 7) Main loop
# ---------------------------------------------------------------------------
try:
    while running:
        devs = discover_devices()
        choice = choose(devs)
        if not running or not choice:
            break
        mac, name = choice
        if pair_trust_connect(mac):
            draw(["Connected", name[:16], mac, "KEY3 = quit"])
        else:
            draw(["Connection failed", name[:16], mac, "KEY3 = quit"])
        while running:
            if GPIO.input(PINS["KEY3"]) == 0:
                cleanup()
            time.sleep(0.1)
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
finally:
    LCD.LCD_Clear(); GPIO.cleanup()

