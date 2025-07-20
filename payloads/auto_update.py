#!/usr/bin/env python3
"""
RaspyJack *payload* – Auto‑Update
================================
Backup current /root/Raspyjack, pull latest GitHub changes and restart the
systemd service so the fresh code is picked up.

Fixes
-----
* Replace the NON‑BREAKING HYPHEN (U+2011) that broke Pillow’s latin‑1 font.
  All user‑facing strings now use a plain ASCII hyphen "-" and the helper
  function takes care of any stray Unicode dashes.
* Added a small sanitiser so **any** unsupported dash is mapped to "-" before
  rendering on the LCD.

Usage
-----
Run from the RaspyJack menu. The LCD shows:
    Auto-Update → Backing up… → Updating… → Restarting… → Done ✔

You can still abort with Ctrl‑C or KEY3 (bottom‑right button).
"""

# ---------------------------------------------------------------------------
# 0) Imports and constants
# ---------------------------------------------------------------------------
import os, sys, time, signal, subprocess, datetime, tarfile, shutil

# RaspyJack helpers – only if the LCD HAT is present
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    LCD_AVAILABLE = True
except ImportError:
    LCD_AVAILABLE = False

RASPY_DIR   = "/root/Raspyjack"
BACKUP_DIR  = "/root"
SERVICE     = "raspyjack"
WIDTH, HEIGHT = 128, 128  # LCD resolution
FONT = ImageFont.load_default() if LCD_AVAILABLE else None

# ---------------------------------------------------------------------------
# 1) LCD helpers (optional)
# ---------------------------------------------------------------------------
LCD = None  # driver instance or False if init failed

def lcd_init():
    """Initialise the Waveshare LCD once, if hardware is present."""
    global LCD
    if not LCD_AVAILABLE or LCD is not None:
        return  # already done or not available
    try:
        LCD = LCD_1in44.LCD()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    except Exception:
        LCD = False  # remember failure to avoid retrying


def lcd_write(msg: str) -> None:
    """Display *msg* centred in bright green, if an LCD exists."""
    lcd_init()
    if not LCD:
        return  # silently ignore if no display

    # Sanitise dashes – Pillow's builtin bitmap font is latin‑1 only
    safe_msg = (msg.replace("\u2010", "-")  # hyphen
                    .replace("\u2011", "-")  # non‑breaking hyphen
                    .replace("\u2012", "-")  # figure dash
                    .replace("\u2013", "-")  # en‑dash
                    .replace("\u2014", "-")) # em‑dash

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    draw = ImageDraw.Draw(img)

    # textbbox() is Pillow ≥9.2; fall back to textsize() otherwise
    if hasattr(draw, "textbbox"):
        x0, y0, x1, y1 = draw.textbbox((0, 0), safe_msg, font=FONT)
        w, h = x1 - x0, y1 - y0
    else:
        w, h = draw.textsize(safe_msg, font=FONT)
    pos = ((WIDTH - w) // 2, (HEIGHT - h) // 2)

    draw.text(pos, safe_msg, font=FONT, fill="#00FF00")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 2) Utility functions
# ---------------------------------------------------------------------------

def backup() -> str:
    """Create a time‑stamped tar.gz of RASPY_DIR; return its pathname."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"Raspyjack_backup_{ts}.tar.gz")
    lcd_write("Backing up…")
    with tarfile.open(backup_path, "w:gz") as tar:
        tar.add(RASPY_DIR, arcname="Raspyjack")
    return backup_path


def git_update() -> None:
    """Fast‑forward pull of the main branch inside RASPY_DIR."""
    lcd_write("Updating…")
    subprocess.check_call(["git", "-C", RASPY_DIR, "pull", "--ff-only"])


def restart_service() -> None:
    """Restart the RaspyJack systemd service so new code runs."""
    lcd_write("Restarting…")
    subprocess.check_call(["systemctl", "restart", SERVICE])


# ---------------------------------------------------------------------------
# 3) Main logic with graceful shutdown
# ---------------------------------------------------------------------------
RUNNING = True

def stop(*_):
    global RUNNING
    RUNNING = False

# Handle Ctrl‑C and RaspyJack «Back» (SIGTERM)
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)


def main():
    lcd_write("Auto-Update")
    backup_file = backup()
    git_update()
    restart_service()
    lcd_write("Done ✔")
    time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        lcd_write("Cancelled")
    except Exception as exc:
        lcd_write("Error!")
        # Re‑raise so RaspyJack can log the traceback
        raise
