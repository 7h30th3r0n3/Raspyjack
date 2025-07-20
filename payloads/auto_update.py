#!/usr/bin/env python3
"""
RaspyJack *payload* – Auto‑Update 
===============================================
Backs‑up the current **/root/Raspyjack** folder, pulls the latest changes
from GitHub and restarts the *raspyjack* systemd service – while showing a
simple progress UI on the 1.44‑inch LCD.

Controls
--------
* **KEY1**  ‑ launch update immediately.
* **KEY3**  ‑ abort and return to menu.

The script mirrors the button/LCD logic of *Periodic Nmap Scan* so the
screen stays informative throughout.
"""

# ---------------------------------------------------------------------------
# 0) Imports & path tweak
# ---------------------------------------------------------------------------
import os, sys, time, signal, subprocess, tarfile, shutil
from datetime import datetime

# Ensure local Raspyjack modules import when run manually
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# 1) Constants
# ---------------------------------------------------------------------------
RASPYJACK_DIR = "/root/Raspyjack"
BACKUP_DIR    = "/root"
REPO_URL      = "https://github.com/7h30th3r0n3/raspyjack.git"
SERVICE_NAME  = "raspyjack"

PINS  = {"KEY1": 21, "KEY3": 16}
WIDTH, HEIGHT = 128, 128
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)

# ---------------------------------------------------------------------------
# 2) Hardware init
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
LCD.LCD_Clear()

# ---------------------------------------------------------------------------
# 3) Display helper
# ---------------------------------------------------------------------------

def show(lines, *, invert=False, spacing=2):
    if isinstance(lines, str):
        lines = lines.split("\n")
    bg = "white" if invert else "black"
    fg = "black" if invert else "#00FF00"
    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    draw = ImageDraw.Draw(img)
    sizes = [draw.textbbox((0,0), l, font=FONT)[2:] for l in lines]
    total_h = sum(h + spacing for _, h in sizes) - spacing
    y = (HEIGHT - total_h) // 2
    for line, (w,h) in zip(lines, sizes):
        x = (WIDTH - w) // 2
        draw.text((x,y), line, font=FONT, fill=fg)
        y += h + spacing
    LCD.LCD_ShowImage(img,0,0)

# ---------------------------------------------------------------------------
# 4) Button helper
# ---------------------------------------------------------------------------

def pressed():
    for name,pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None

# ---------------------------------------------------------------------------
# 5) Core routines
# ---------------------------------------------------------------------------

def backup():
    """Create a timestamped tar.gz of the whole Raspyjack tree."""
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    archive = os.path.join(BACKUP_DIR, f"raspyjack_backup_{ts}.tar.gz")
    try:
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(RASPYJACK_DIR, arcname="Raspyjack")
        return True, archive
    except Exception as exc:
        return False, str(exc)


def reclone():
    """Follow the doc procedure: rm‑rf, clone, mv ⇒ Raspyjack."""
    try:
        # 1. remove existing folder
        if os.path.exists(RASPYJACK_DIR):
            subprocess.run(["rm", "-rf", RASPYJACK_DIR], check=True)
        # 2. git clone into /root/raspyjack (lowercase)
        subprocess.run(["git", "clone", REPO_URL], cwd="/root", check=True)
        # 3. rename to capitalised folder
        subprocess.run(["mv", "raspyjack", "Raspyjack"], cwd="/root", check=True)
        return True, "cloned"
    except subprocess.CalledProcessError as exc:
        return False, f"clone error {exc.returncode}"


def restart_service():
    try:
        subprocess.run(["systemctl", "restart", SERVICE_NAME], check=True)
        return True, "restarted"
    except subprocess.CalledProcessError as exc:
        return False, f"systemctl {exc.returncode}"

# ---------------------------------------------------------------------------
# 6) Main loop
# ---------------------------------------------------------------------------

running = True
signal.signal(signal.SIGINT,  lambda *_: sys.exit(0))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

show(["Auto‑Update", "KEY1: start", "KEY3: exit"])

try:
    while running:
        btn = pressed()
        if btn == "KEY1":
            while pressed() == "KEY1":
                time.sleep(0.05)
            # 1. Backup
            show(["Backing‑up…"])
            ok, info = backup()
            if not ok:
                show(["Backup failed", info], invert=True); time.sleep(4); break
            # 2. Re‑clone repo
            show(["Updating…"])
            ok, info = reclone()
            if not ok:
                show(["Update failed", info], invert=True); time.sleep(4); break
            # 3. Restart service
            show(["Restarting…"])
            ok, info = restart_service()
            if not ok:
                show(["Restart failed", info], invert=True); time.sleep(4); break
            show(["Update done!", "Bye 👋"])
            time.sleep(2)
            running = False
        elif btn == "KEY3":
            running = False
        else:
            time.sleep(0.1)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
