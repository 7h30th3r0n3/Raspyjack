#!/usr/bin/env python3
"""
RaspyJack Payload -- Process Manager / Killer
===============================================
Author: 7h30th3r0n3

Browse running processes sorted by memory usage and send signals
to terminate or force-kill them directly from the LCD.

Controls
--------
  UP / DOWN  -- Navigate process list
  KEY1       -- Kill selected process (SIGTERM)
  KEY2       -- Force kill selected process (SIGKILL)
  OK         -- Refresh process list
  KEY3       -- Exit
"""

import os
import sys
import time
import signal
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

DEBOUNCE = 0.20
ROW_H = 12
VISIBLE_ROWS = 7
_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

def _fetch_processes():
    """Return a list of dicts with pid, name, mem from ps aux."""
    try:
        result = subprocess.run(
            ["ps", "aux", "--sort=-%mem"],
            capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.strip().split("\n")
    except Exception:
        return []

    processes = []
    for line in lines[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        mem = parts[3]
        name = parts[10][:20]
        processes.append({"pid": pid, "name": name, "mem": mem})
    return processes


def _kill_process(pid, sig):
    """Send a signal to a process. Return (success, message)."""
    try:
        os.kill(pid, sig)
        label = "SIGTERM" if sig == signal.SIGTERM else "SIGKILL"
        return True, f"Sent {label} to {pid}"
    except ProcessLookupError:
        return False, f"PID {pid} not found"
    except PermissionError:
        return False, f"No perm for {pid}"
    except OSError as exc:
        return False, str(exc)[:24]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PROC MANAGER", font=font, fill="#00ccff")
    d.text((108, 1), "K3", font=font, fill="#888")


def _draw_footer(d, message):
    d.rectangle((0, 116, 127, 127), fill="#111")
    text = message if message else "K1:kill K2:force OK:ref"
    color = "#ffaa00" if message else "#666"
    d.text((2, 117), text[:26], font=font, fill=color)


def _draw_list(processes, cursor, scroll, status_msg):
    """Render process list to LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d)

    y = 16
    end = min(len(processes), scroll + VISIBLE_ROWS)
    for i in range(scroll, end):
        proc = processes[i]
        is_selected = i == cursor
        bg = "#333" if is_selected else None
        fg = "#ffff00" if is_selected else "#ccc"

        if bg:
            d.rectangle((0, y, 127, y + ROW_H - 1), fill=bg)

        label = f"{proc['pid']:>5} {proc['mem']:>4}% {proc['name'][:12]}"
        d.text((2, y), label, font=font, fill=fg)
        y += ROW_H

    if not processes:
        d.text((4, 50), "No processes", font=font, fill="#666")

    # Scroll indicator
    if len(processes) > VISIBLE_ROWS:
        total = len(processes)
        indicator = f"{cursor + 1}/{total}"
        d.text((90, 105), indicator, font=font, fill="#555")

    _draw_footer(d, status_msg)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    processes = _fetch_processes()
    cursor = 0
    scroll = 0
    status_msg = ""
    status_expire = 0.0
    last_press = 0.0

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if now > status_expire:
                status_msg = ""

            if btn == "KEY3":
                break

            elif btn == "DOWN":
                if processes and cursor < len(processes) - 1:
                    cursor += 1
                    if cursor >= scroll + VISIBLE_ROWS:
                        scroll = cursor - VISIBLE_ROWS + 1

            elif btn == "UP":
                if cursor > 0:
                    cursor -= 1
                    if cursor < scroll:
                        scroll = cursor

            elif btn == "OK":
                processes = _fetch_processes()
                cursor = min(cursor, max(0, len(processes) - 1))
                scroll = min(scroll, max(0, len(processes) - VISIBLE_ROWS))
                status_msg = "Refreshed"
                status_expire = now + 1.5

            elif btn == "KEY1" and processes:
                proc = processes[cursor]
                ok, msg = _kill_process(proc["pid"], signal.SIGTERM)
                status_msg = msg
                status_expire = now + 2.0
                time.sleep(0.3)
                processes = _fetch_processes()
                cursor = min(cursor, max(0, len(processes) - 1))

            elif btn == "KEY2" and processes:
                proc = processes[cursor]
                ok, msg = _kill_process(proc["pid"], signal.SIGKILL)
                status_msg = msg
                status_expire = now + 2.0
                time.sleep(0.3)
                processes = _fetch_processes()
                cursor = min(cursor, max(0, len(processes) - 1))

            _draw_list(processes, cursor, scroll, status_msg)
            time.sleep(0.08)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
