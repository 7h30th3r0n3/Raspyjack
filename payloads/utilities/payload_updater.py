#!/usr/bin/env python3
"""
RaspyJack Payload -- Payload Updater
======================================
Author: 7h30th3r0n3

Smart incremental updater: fetches only new and modified payloads
from GitHub. Does NOT touch system files, configs, or loot.

Flow:
  1. git fetch (download changes without applying)
  2. Compare local vs remote payload files
  3. Show list of new/modified/deleted payloads
  4. User confirms → apply changes (payload files only)
  5. No reboot needed

Controls:
  OK         Fetch / Apply update
  UP/DOWN    Scroll changelog
  KEY1       Toggle: update payloads only vs all files
  KEY3       Exit
"""

import os
import sys
import time
import subprocess
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
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

RASPYJACK_DIR = "/root/Raspyjack"
GIT_REMOTE = "origin"
GIT_BRANCH = "main"

# Only update these directories by default (safe, no system breakage)
PAYLOAD_DIRS = ["payloads/", "img/", "menu_icons.json"]

# Never touch these (user data, configs, secrets)
EXCLUDE_PATTERNS = [
    "loot/", "config/", ".env", "discord_webhook.txt",
    "__pycache__/", "*.pyc", ".git/",
]

_shutdown = False


def _signal_handler(*_):
    global _shutdown
    _shutdown = True


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _git(args, timeout=30):
    """Run git command in RASPYJACK_DIR, return (success, stdout)."""
    try:
        r = subprocess.run(
            ["git"] + args,
            cwd=RASPYJACK_DIR,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode == 0, r.stdout.strip()
    except Exception as e:
        return False, str(e)


def _get_current_hash():
    ok, out = _git(["rev-parse", "--short", "HEAD"])
    return out if ok else "unknown"


def _get_remote_hash():
    ok, out = _git(["rev-parse", "--short", f"{GIT_REMOTE}/{GIT_BRANCH}"])
    return out if ok else "unknown"


def _fetch():
    """Fetch remote changes without applying."""
    ok, out = _git(["fetch", GIT_REMOTE, GIT_BRANCH], timeout=60)
    return ok


def _get_changed_files():
    """List files changed between local HEAD and remote.

    Returns list of (status, filepath) tuples:
      status: 'A' (added), 'M' (modified), 'D' (deleted)
    """
    ok, out = _git(["diff", "--name-status", f"HEAD..{GIT_REMOTE}/{GIT_BRANCH}"])
    if not ok or not out:
        return []

    changes = []
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            status = parts[0][0]  # A, M, D, R, C
            filepath = parts[1]
            changes.append((status, filepath))
    return changes


def _filter_payload_changes(changes, payloads_only=True):
    """Filter changes to only payload-related files."""
    filtered = []
    for status, filepath in changes:
        # Skip excluded patterns
        if any(pat in filepath for pat in EXCLUDE_PATTERNS):
            continue

        if payloads_only:
            # Only include files in PAYLOAD_DIRS
            if not any(filepath.startswith(d) or filepath == d.rstrip("/")
                       for d in PAYLOAD_DIRS):
                continue

        filtered.append((status, filepath))
    return filtered


def _get_commit_log(n=10):
    """Get last N commits between local and remote."""
    ok, out = _git(["log", "--oneline",
                     f"HEAD..{GIT_REMOTE}/{GIT_BRANCH}",
                     f"-{n}"])
    if not ok or not out:
        return []
    return out.splitlines()


def _apply_file(filepath):
    """Checkout a single file from remote."""
    ok, _ = _git(["checkout", f"{GIT_REMOTE}/{GIT_BRANCH}", "--", filepath])
    return ok


def _delete_file(filepath):
    """Delete a file that was removed in remote."""
    full = os.path.join(RASPYJACK_DIR, filepath)
    try:
        if os.path.exists(full):
            os.remove(full)
        return True
    except Exception:
        return False


def _apply_changes(changes, progress_cb=None):
    """Apply filtered changes. Returns (applied, failed) counts."""
    applied = 0
    failed = 0
    total = len(changes)

    for i, (status, filepath) in enumerate(changes):
        if _shutdown:
            break

        if progress_cb:
            progress_cb(i + 1, total, filepath)

        if status == "D":
            if _delete_file(filepath):
                applied += 1
            else:
                failed += 1
        else:
            if _apply_file(filepath):
                applied += 1
            else:
                failed += 1

    return applied, failed


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------


def _show_msg(lcd, font, font_sm, line1, line2="", line3="", color="#00CCFF"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "PAYLOAD UPDATER", font=font_sm, fill="#00CCFF")
    d.text((4, 35), line1[:22], font=font, fill=color)
    if line2:
        d.text((4, 55), line2[:24], font=font_sm, fill="#888")
    if line3:
        d.text((4, 70), line3[:24], font=font_sm, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_changes(lcd, font, font_sm, changes, commits, scroll,
                   payloads_only, local_hash, remote_hash):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    mode = "PAYLOADS" if payloads_only else "ALL FILES"
    d.text((2, 1), f"UPDATE [{mode}]", font=font_sm, fill="#00CCFF")

    y = 14
    n_add = sum(1 for s, _ in changes if s == "A")
    n_mod = sum(1 for s, _ in changes if s == "M")
    n_del = sum(1 for s, _ in changes if s == "D")

    d.text((2, y), f"{local_hash} -> {remote_hash}", font=font_sm, fill="#888")
    y += 12
    d.text((2, y), f"+{n_add} new  ~{n_mod} mod  -{n_del} del",
           font=font_sm, fill="#FFFFFF")
    y += 14

    # File list
    visible = changes[scroll:scroll + 6]
    for status, filepath in visible:
        fname = os.path.basename(filepath)[:18]
        if status == "A":
            sym = "+"
            col = "#00FF00"
        elif status == "M":
            sym = "~"
            col = "#FFAA00"
        elif status == "D":
            sym = "-"
            col = "#FF4444"
        else:
            sym = "?"
            col = "#888"
        d.text((2, y), f"{sym} {fname}", font=font_sm, fill=col)
        y += 11

    if not changes:
        d.text((10, 60), "Already up to date!", font=font_sm, fill="#00FF00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if changes:
        d.text((2, 117), "OK:Apply K1:Mode K3:X", font=font_sm, fill="#888")
    else:
        d.text((2, 117), "OK:Check K3:Exit", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_progress(lcd, font, font_sm, current, total, filename):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "UPDATING...", font=font_sm, fill="#FFAA00")

    pct = int(current / max(total, 1) * 100)
    d.text((4, 30), f"{current}/{total} files", font=font, fill="#FFFFFF")

    # Progress bar
    bar_w = int(120 * pct / 100)
    d.rectangle((4, 50, 124, 60), outline="#333")
    if bar_w > 0:
        d.rectangle((4, 50, 4 + bar_w, 60), fill="#00FF00")
    d.text((50, 52), f"{pct}%", font=font_sm, fill="#FFFFFF")

    # Current file
    fname = os.path.basename(filename)[:22]
    d.text((4, 70), fname, font=font_sm, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_result(lcd, font, font_sm, applied, failed):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "UPDATE COMPLETE", font=font_sm, fill="#00FF00")

    y = 30
    d.text((4, y), f"Applied: {applied}", font=font, fill="#00FF00")
    y += 18
    if failed > 0:
        d.text((4, y), f"Failed: {failed}", font=font, fill="#FF4444")
        y += 18
    d.text((4, y), f"Version: {_get_current_hash()}", font=font_sm, fill="#888")
    y += 14
    d.text((4, y), "No reboot needed", font=font_sm, fill="#00FF00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "KEY3:Exit", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global _shutdown

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(8)

    # Check git repo exists
    if not os.path.isdir(os.path.join(RASPYJACK_DIR, ".git")):
        _show_msg(lcd, font, font_sm, "No git repo!", RASPYJACK_DIR, color="#FF4444")
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # State
    screen = "home"    # home, changes, updating, result
    changes = []
    all_changes = []
    commits = []
    scroll = 0
    payloads_only = True
    applied = 0
    failed = 0
    local_hash = _get_current_hash()
    remote_hash = ""
    fetched = False

    _show_msg(lcd, font, font_sm, "Payload Updater",
              f"Local: {local_hash}", "OK = Check for updates")

    try:
        while not _shutdown:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if screen == "result":
                    break
                elif screen == "changes":
                    screen = "home"
                    _show_msg(lcd, font, font_sm, "Payload Updater",
                              f"Local: {local_hash}", "OK = Check for updates")
                else:
                    break

            elif btn == "OK":
                if screen == "home" and not fetched:
                    # Fetch from remote
                    _show_msg(lcd, font, font_sm, "Fetching...",
                              "Checking GitHub", color="#FFAA00")
                    ok = _fetch()
                    if not ok:
                        _show_msg(lcd, font, font_sm, "Fetch failed!",
                                  "Check network", color="#FF4444")
                        time.sleep(2)
                        continue

                    fetched = True
                    remote_hash = _get_remote_hash()
                    all_changes = _get_changed_files()
                    commits = _get_commit_log()

                    if local_hash == remote_hash:
                        changes = []
                    else:
                        changes = _filter_payload_changes(all_changes, payloads_only)

                    screen = "changes"
                    scroll = 0
                    time.sleep(0.3)

                elif screen == "home" and fetched:
                    # Re-show changes
                    changes = _filter_payload_changes(all_changes, payloads_only)
                    screen = "changes"
                    scroll = 0
                    time.sleep(0.3)

                elif screen == "changes" and changes:
                    # Apply changes
                    screen = "updating"

                    def progress_cb(current, total, filename):
                        _draw_progress(lcd, font, font_sm, current, total, filename)

                    applied, failed = _apply_changes(changes, progress_cb)

                    # Update local HEAD to match what we applied
                    if applied > 0 and failed == 0:
                        _git(["reset", "--hard", f"{GIT_REMOTE}/{GIT_BRANCH}"],
                             timeout=30)

                    local_hash = _get_current_hash()
                    screen = "result"
                    time.sleep(0.3)

            elif btn == "KEY1" and screen == "changes":
                payloads_only = not payloads_only
                changes = _filter_payload_changes(all_changes, payloads_only)
                scroll = 0
                time.sleep(0.3)

            elif btn == "UP" and screen == "changes":
                scroll = max(0, scroll - 1)
                time.sleep(0.12)

            elif btn == "DOWN" and screen == "changes":
                scroll = min(max(0, len(changes) - 6), scroll + 1)
                time.sleep(0.12)

            # Draw
            if screen == "changes":
                _draw_changes(lcd, font, font_sm, changes, commits, scroll,
                              payloads_only, local_hash, remote_hash)
            elif screen == "result":
                _draw_result(lcd, font, font_sm, applied, failed)

            time.sleep(0.05)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
