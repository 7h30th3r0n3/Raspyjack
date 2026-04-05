#!/usr/bin/env python3
"""
RaspyJack Payload -- Engagement Timer
======================================
Author: 7h30th3r0n3

Operation timer with phase tracking for penetration testing engagements.
Set duration, start countdown, cycle through engagement phases, and get
alerts when time expires.  Optional Discord webhook notification.

Controls:
  UP / DOWN    -- Adjust hours (setup) / scroll log (running)
  LEFT / RIGHT -- Adjust minutes (setup)
  OK           -- Start / pause countdown
  KEY1         -- Cycle phase (Recon > Exploit > Persist > Exfil > Cleanup)
  KEY2         -- Add 30 minutes
  KEY3         -- Exit

Config: /root/Raspyjack/config/timer.json (for Discord webhook)
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

PHASES = ["Recon", "Exploit", "Persist", "Exfil", "Cleanup"]
PHASE_COLORS = {
    "Recon": "#00CCFF",
    "Exploit": "#FF3300",
    "Persist": "#FF9900",
    "Exfil": "#00FF88",
    "Cleanup": "#AAAAAA",
}

CONFIG_PATH = "/root/Raspyjack/config/timer.json"

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
timer_active = False
timer_paused = False
timer_expired = False
flash_alert = False

# Setup values
setup_hours = 2
setup_minutes = 0

# Runtime values
remaining_seconds = 0
elapsed_seconds = 0
start_time = 0.0

# Phase tracking
phase_idx = 0
phase_log = []  # [{"phase": str, "start": str, "elapsed": int}]

# Discord webhook
discord_webhook_url = ""

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_config():
    """Load Discord webhook URL from config."""
    global discord_webhook_url
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        discord_webhook_url = cfg.get("discord_webhook", "")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _format_time(total_seconds):
    """Format seconds as HH:MM:SS."""
    total_seconds = max(0, int(total_seconds))
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _format_short(total_seconds):
    """Format seconds as compact string."""
    total_seconds = max(0, int(total_seconds))
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    if hours > 0:
        return f"{hours}h{minutes:02d}m"
    return f"{minutes}m"

# ---------------------------------------------------------------------------
# Discord notification
# ---------------------------------------------------------------------------

def _send_discord(message):
    """Send notification to Discord webhook."""
    if not discord_webhook_url:
        return
    payload = json.dumps({"content": message})
    try:
        subprocess.run(
            [
                "curl", "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", payload,
                discord_webhook_url,
            ],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Timer thread
# ---------------------------------------------------------------------------

def _timer_thread(total_seconds):
    """Countdown timer running in background."""
    global remaining_seconds, elapsed_seconds, timer_active
    global timer_expired, flash_alert

    remaining = total_seconds
    tick_start = time.time()

    while _running and timer_active and remaining > 0:
        if timer_paused:
            tick_start = time.time()
            time.sleep(0.1)
            continue

        now = time.time()
        delta = now - tick_start
        if delta >= 1.0:
            elapsed_ticks = int(delta)
            remaining = max(0, remaining - elapsed_ticks)
            tick_start = now

            with lock:
                remaining_seconds = remaining
                elapsed_seconds = total_seconds - remaining

        time.sleep(0.1)

    if remaining <= 0 and timer_active:
        with lock:
            timer_expired = True
            flash_alert = True
            remaining_seconds = 0

        # Send Discord alert
        threading.Thread(
            target=_send_discord,
            args=("**ENGAGEMENT TIMER EXPIRED** -- Time is up!",),
            daemon=True,
        ).start()

        # Flash alert for 10 seconds
        for _ in range(20):
            if not _running:
                break
            with lock:
                flash_alert = not flash_alert
            time.sleep(0.5)

        with lock:
            flash_alert = False
            timer_active = False

# ---------------------------------------------------------------------------
# Phase management
# ---------------------------------------------------------------------------

def _log_phase_change(new_phase_idx):
    """Log the current phase transition."""
    ts = datetime.now().strftime("%H:%M:%S")
    with lock:
        elapsed = elapsed_seconds
    phase_log.append({
        "phase": PHASES[new_phase_idx],
        "start": ts,
        "elapsed": elapsed,
    })

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_big_time(d, time_str, y, color):
    """Draw time string in a larger visible style using the default font."""
    # Since we only have the default small font, draw it doubled
    # by drawing at adjacent positions for a bolder look
    for dx in range(2):
        for dy in range(2):
            d.text((16 + dx, y + dy), time_str, font=font, fill=color)


def _draw_frame(lcd):
    """Render current state to the LCD."""
    with lock:
        is_flashing = flash_alert
        active = timer_active
        paused = timer_paused
        expired = timer_expired
        remain = remaining_seconds
        elapsed = elapsed_seconds
        pidx = phase_idx
        log = list(phase_log)

    bg = "#330000" if is_flashing else "black"
    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    d = ScaledDraw(img)

    # Header
    phase_name = PHASES[pidx]
    phase_color = PHASE_COLORS[phase_name]
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"TIMER - {phase_name}", font=font, fill=phase_color)

    if not active and not expired:
        # Setup mode
        d.text((2, 20), "Set Duration:", font=font, fill="#AAAAAA")

        time_str = f"{setup_hours:02d}h : {setup_minutes:02d}m"
        _draw_big_time(d, time_str, 36, "#FFFFFF")

        total = setup_hours * 3600 + setup_minutes * 60
        d.text((2, 56), f"Total: {_format_time(total)}", font=font, fill="#888")

        d.text((2, 74), "UP/DN: Hours", font=font, fill="#666")
        d.text((2, 86), "LT/RT: Minutes", font=font, fill="#666")
        d.text((2, 98), "OK: Start", font=font, fill="#666")

    elif expired:
        # Expired view
        d.text((20, 30), "TIME UP!", font=font, fill="#FF0000")
        d.text((2, 50), f"Elapsed: {_format_time(elapsed)}", font=font, fill="#AAAAAA")
        d.text((2, 66), f"Phase: {phase_name}", font=font, fill=phase_color)

    else:
        # Running countdown view
        remain_str = _format_time(remain)
        color = "#FF0000" if remain < 300 else "#FFAA00" if remain < 900 else "#00FF00"
        _draw_big_time(d, remain_str, 20, color)

        if paused:
            d.text((90, 20), "PAUSED", font=font, fill="#FF8800")

        d.text((2, 42), f"Elapsed: {_format_time(elapsed)}", font=font, fill="#888")
        d.text((2, 54), f"Phase: {phase_name}", font=font, fill=phase_color)

        # Phase log
        d.text((2, 68), "Phase log:", font=font, fill="#666")
        visible = log[-3:]
        for i, entry in enumerate(visible):
            y = 80 + i * 12
            line = f"{entry['start']} {entry['phase']} +{_format_short(entry['elapsed'])}"
            d.text((2, y), line[:24], font=font, fill="#CCCCCC")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if active:
        d.text((2, 117), "OK:Pause K1:Phase K3:X", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Start K2:+30m K3:X", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Module-level font (used by _draw_big_time and _draw_frame)
font = scaled_font()


def main():
    global _running, timer_active, timer_paused, timer_expired, flash_alert
    global setup_hours, setup_minutes, remaining_seconds, elapsed_seconds
    global phase_idx, start_time

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    _load_config()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if timer_active:
                    # Pause / unpause
                    timer_paused = not timer_paused
                elif not timer_expired:
                    # Start timer
                    total = setup_hours * 3600 + setup_minutes * 60
                    if total > 0:
                        remaining_seconds = total
                        elapsed_seconds = 0
                        timer_active = True
                        timer_paused = False
                        timer_expired = False
                        start_time = time.time()
                        _log_phase_change(phase_idx)
                        threading.Thread(
                            target=_timer_thread, args=(total,), daemon=True
                        ).start()
                else:
                    # Reset after expiry
                    timer_expired = False
                    flash_alert = False
                time.sleep(0.3)

            elif btn == "KEY1":
                # Cycle phase
                phase_idx = (phase_idx + 1) % len(PHASES)
                if timer_active:
                    _log_phase_change(phase_idx)
                time.sleep(0.3)

            elif btn == "KEY2":
                # Add 30 minutes
                if timer_active:
                    with lock:
                        remaining_seconds += 1800
                elif not timer_expired:
                    setup_minutes += 30
                    if setup_minutes >= 60:
                        setup_hours += setup_minutes // 60
                        setup_minutes = setup_minutes % 60
                    setup_hours = min(setup_hours, 24)
                time.sleep(0.3)

            elif btn == "UP":
                if not timer_active and not timer_expired:
                    setup_hours = min(24, setup_hours + 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                if not timer_active and not timer_expired:
                    setup_hours = max(0, setup_hours - 1)
                time.sleep(0.15)

            elif btn == "LEFT":
                if not timer_active and not timer_expired:
                    setup_minutes = max(0, setup_minutes - 5)
                time.sleep(0.15)

            elif btn == "RIGHT":
                if not timer_active and not timer_expired:
                    setup_minutes = min(55, setup_minutes + 5)
                time.sleep(0.15)

            _draw_frame(lcd)
            time.sleep(0.05)

    finally:
        _running = False
        timer_active = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
