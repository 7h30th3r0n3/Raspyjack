#!/usr/bin/env python3
"""
RaspyJack *payload* – Auto‑Update (LCD‑friendly)
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

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

# ---------------------------- Third‑party libs ----------------------------
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# Shared input helper (WebUI virtual + GPIO)
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# 1) Constants
# ---------------------------------------------------------------------------
RASPYJACK_DIR  = "/root/Raspyjack"
PAYLOADS_DIR   = "/root/Raspyjack/payloads"         # explicitly saved as well
BACKUP_DIR     = "/root"
SERVICE_NAME   = "raspyjack"
GIT_REMOTE     = "origin"
GIT_BRANCH     = "main"

PINS = {"KEY1": 21, "KEY3": 16}                 # buttons we care about
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
# 3) Helper to show centred text
# ---------------------------------------------------------------------------

def show(lines, *, invert=False, spacing=2):
    if isinstance(lines, str):
        lines = lines.split("\n")
    bg = "white" if invert else "black"
    fg = "black" if invert else "#00FF00"
    img  = Image.new("RGB", (WIDTH, HEIGHT), bg)
    draw = ImageDraw.Draw(img)
    sizes = [draw.textbbox((0, 0), l, font=FONT)[2:] for l in lines]
    total_h = sum(h + spacing for _, h in sizes) - spacing
    y = (HEIGHT - total_h) // 2
    for line, (w, h) in zip(lines, sizes):
        x = (WIDTH - w) // 2
        draw.text((x, y), line, font=FONT, fill=fg)
        y += h + spacing
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 4) Button helper
# ---------------------------------------------------------------------------

def pressed() -> str | None:
    return get_button(PINS, GPIO)

# ---------------------------------------------------------------------------
# 5) Core update logic
# ---------------------------------------------------------------------------

def backup() -> tuple[bool, str]:
    """Create a timestamped tar.gz containing Raspyjack + payloads."""
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    archive = os.path.join(BACKUP_DIR, f"raspyjack_backup_{ts}.tar.gz")
    try:
        with tarfile.open(archive, "w:gz") as tar:
            # add Raspyjack root (includes payloads) *and* explicit payloads path
            tar.add(RASPYJACK_DIR, arcname=os.path.basename(RASPYJACK_DIR))
        if os.path.exists(archive) and os.path.getsize(archive) > 0:
            return True, archive
        return False, "backup empty"
    except Exception as exc:
        return False, str(exc)

def check_space(min_mb: int = 200) -> tuple[bool, str]:
    try:
        usage = shutil.disk_usage(BACKUP_DIR)
        free_mb = usage.free // (1024 * 1024)
        if free_mb < min_mb:
            return False, f"low space: {free_mb}MB"
        return True, f"{free_mb}MB free"
    except Exception as exc:
        return False, f"disk {exc}"

def ensure_dependencies() -> tuple[bool, str]:
    """Install missing dependencies via apt when needed."""
    cmd_map = {
        "git": "git",
        "tar": "tar",
        "systemctl": "systemd",
        "nmap": "nmap",
        "tcpdump": "tcpdump",
        "arp-scan": "arp-scan",
        "ettercap": "ettercap-text-only",
        "php": "php",
        "tshark": "tshark",
        "dnsmasq": "dnsmasq",
        "airmon-ng": "aircrack-ng",
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
    }
    missing_cmds = [c for c in cmd_map if shutil.which(c) is None]
    missing_pkgs = sorted({cmd_map[c] for c in missing_cmds})

    py_pkgs = {
        "evdev": "python3-evdev",
        "requests": "python3-requests",
        "PIL": "python3-pil",
        "RPi": "python3-rpi.gpio",
        "netifaces": "python3-netifaces",
        "scapy": "python3-scapy",
        "pyudev": "python3-pyudev",
    }
    missing_py = []
    try:
        import importlib
        for mod, pkg in py_pkgs.items():
            try:
                importlib.import_module(mod)
            except Exception:
                missing_py.append(pkg)
    except Exception:
        pass

    to_install = sorted(set(missing_pkgs + missing_py))
    if to_install:
        try:
            subprocess.run(["apt-get", "update", "-qq"], check=True)
            subprocess.run(["apt-get", "install", "-y", "--no-install-recommends"] + to_install, check=True)
        except subprocess.CalledProcessError as exc:
            return False, f"apt failed {exc.returncode}"

    return True, "ok"

def backup_payloads() -> tuple[bool, str]:
    """Copy current payloads to a temp dir for restore after update."""
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dst = f"/tmp/raspyjack_payloads_backup_{ts}"
    try:
        if not os.path.isdir(PAYLOADS_DIR):
            return False, "payloads dir missing"
        shutil.copytree(PAYLOADS_DIR, dst)
        return True, dst
    except Exception as exc:
        return False, str(exc)

def restore_custom_payloads(backup_dir: str) -> tuple[bool, str]:
    """Restore only payloads that are not present in the repo version."""
    try:
        if not os.path.isdir(backup_dir):
            return False, "payloads backup missing"
        os.makedirs(PAYLOADS_DIR, exist_ok=True)
        current = set(os.listdir(PAYLOADS_DIR))
        restored = 0
        for name in os.listdir(backup_dir):
            if name.startswith("."):
                continue
            src = os.path.join(backup_dir, name)
            dst = os.path.join(PAYLOADS_DIR, name)
            if name not in current and os.path.isfile(src):
                shutil.copy2(src, dst)
                restored += 1
        return True, f"restored {restored}"
    except Exception as exc:
        return False, str(exc)

def git_update() -> tuple[bool, str]:
    """Fast‑forward pull the latest changes."""
    try:
        subprocess.run(
            ["git", "-C", RASPYJACK_DIR, "fetch", GIT_REMOTE],
            check=True, capture_output=True, text=True
        )
        subprocess.run(
            ["git", "-C", RASPYJACK_DIR, "reset", "--hard", f"{GIT_REMOTE}/{GIT_BRANCH}"],
            check=True, capture_output=True, text=True
        )
        return True, "OK"
    except subprocess.CalledProcessError as exc:
        msg = exc.stderr.strip() if exc.stderr else f"git error {exc.returncode}"
        return False, msg


def restart_service() -> tuple[bool, str]:
    try:
        subprocess.run(["systemctl", "restart", SERVICE_NAME], check=True)
        return True, "restarted"
    except subprocess.CalledProcessError as exc:
        return False, f"systemctl {exc.returncode}"

# ---------------------------------------------------------------------------
# 6) Main
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
            # 0. Prechecks
            ok, info = check_space()
            if not ok:
                show(["No space", info], invert=True); time.sleep(4); break
            ok, info = ensure_dependencies()
            if not ok:
                show(["Deps install", info], invert=True); time.sleep(4); break
            # 1. Backup
            show(["Backing‑up…"])
            ok, info = backup()
            if not ok:
                show(["Backup failed", info], invert=True); time.sleep(4); break
            # 1b. Backup payloads for restore
            show(["Saving payloads…"])
            ok, payloads_backup = backup_payloads()
            if not ok:
                show(["Payload save fail", payloads_backup], invert=True); time.sleep(4); break
            # 2. Pull latest
            show(["Updating…"])
            ok, info = git_update()
            if not ok:
                show(["Update failed", info], invert=True); time.sleep(4); break
            # 2b. Restore custom payloads
            show(["Restoring payloads…"])
            ok, info = restore_custom_payloads(payloads_backup)
            if not ok:
                show(["Restore failed", info], invert=True); time.sleep(4); break
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
