#!/usr/bin/env python3
"""
RaspyJack payload - Auto-Update (LCD-friendly)
================================================
Author: 7h30th3r0n3

Checks for updates from GitHub, shows changelog, backs up configs,
pulls latest code, restores user configs, and reboots.

Controls
--------
  KEY1  Start update / continue after changelog
  KEY2  Rollback to previous backup
  KEY3  Exit

After update runs install_raspyjack.sh then reboots.
"""

import os
import sys
import time
import re
import json
import signal
import subprocess
import shutil
from datetime import datetime

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

def _strip_ansi(text):
    """Remove ANSI escape codes from text."""
    return _ANSI_RE.sub('', text)

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
RASPYJACK_DIR = "/root/Raspyjack"
BACKUP_ROOT = "/root/raspyjack_backups"
SERVICE_NAME = "raspyjack"
GIT_REMOTE = "origin"
GIT_BRANCH = "main"
INSTALL_SCRIPT = "/root/Raspyjack/install_raspyjack.sh"

CONFIG_FILES = [
    "gui_conf.json",
    "discord_webhook.txt",
    "menu_icons.json",
]
CONFIG_DIRS = [
    "config",
]

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

# ---------------------------------------------------------------------------
# Hardware init
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
LCD.LCD_Clear()
WIDTH, HEIGHT = LCD.width, LCD.height
FONT = scaled_font(10)
FONT_SM = scaled_font(8)

_running = True


def _cleanup_signal(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def show(lines, invert=False, spacing=2):
    """Show centered text on LCD."""
    if isinstance(lines, str):
        lines = lines.split("\n")
    bg = "white" if invert else "black"
    fg = "black" if invert else "#00FF00"
    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    d = ScaledDraw(img)
    sizes = [d.textbbox((0, 0), l, font=FONT)[2:] for l in lines]
    total_h = sum(h + spacing for _, h in sizes) - spacing
    y = max(0, (128 - total_h) // 2)
    for line, (w, h) in zip(lines, sizes):
        x = max(0, (128 - w) // 2)
        d.text((x, y), line, font=FONT, fill=fg)
        y += h + spacing
    LCD.LCD_ShowImage(img, 0, 0)


def _wrap_text(text, max_chars=22):
    """Word-wrap text, also splitting long words by character."""
    lines = []
    for raw_line in text.split("\n"):
        words = raw_line.split()
        if not words:
            lines.append("")
            continue
        current = ""
        for w in words:
            if len(w) > max_chars:
                # Split long word (URLs etc.) by character
                if current:
                    lines.append(current)
                    current = ""
                for i in range(0, len(w), max_chars):
                    lines.append(w[i:i + max_chars])
            elif len(current) + len(w) + 1 > max_chars:
                lines.append(current)
                current = w
            else:
                current = f"{current} {w}" if current else w
        if current:
            lines.append(current)
    return lines


def show_error(title, detail):
    """Show scrollable error screen with word-wrapped detail text."""
    lines = _wrap_text(detail, 22)
    scroll = 0
    max_visible = 7

    while _running:
        img = Image.new("RGB", (WIDTH, HEIGHT), "#1a0000")
        d = ScaledDraw(img)

        # Header
        d.rectangle((0, 0, 127, 13), fill="#440000")
        d.text((2, 1), title[:22], font=FONT, fill="#FF4444")

        # Lines
        visible = lines[scroll:scroll + max_visible]
        for i, line in enumerate(visible):
            y = 18 + i * 12
            d.text((4, y), line, font=FONT_SM, fill="#FFFFFF")

        # Scroll indicator if needed
        if len(lines) > max_visible:
            total_h = 84
            bar_h = max(6, int(max_visible / len(lines) * total_h))
            bar_y = 18 + int(scroll / max(1, len(lines) - max_visible) * (total_h - bar_h))
            d.rectangle((125, bar_y, 127, bar_y + bar_h), fill="#444")

        # Footer
        d.rectangle((0, 116, 127, 127), fill="#111")
        hint = "U/D:Scroll OK:Continue" if len(lines) > max_visible else "Any key to continue"
        d.text((2, 117), hint, font=FONT_SM, fill="#888")

        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        if btn == "UP":
            scroll = max(0, scroll - 1)
            time.sleep(0.15)
        elif btn == "DOWN":
            scroll = min(max(0, len(lines) - max_visible), scroll + 1)
            time.sleep(0.15)
        elif btn in ("OK", "KEY1", "KEY2", "KEY3"):
            break
        time.sleep(0.05)


def show_progress(title, detail="", progress_pct=None):
    """Show progress screen with word-wrapped detail and bar at bottom."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "AUTO-UPDATE", font=FONT, fill="#00FF00")

    # Title
    d.text((4, 18), title[:22], font=FONT, fill="#FFFFFF")

    # Word-wrap detail text
    if detail:
        lines = _wrap_text(detail, 24)
        y = 32
        for line in lines:
            if y > 90:
                break
            d.text((4, y), line, font=FONT_SM, fill="#888888")
            y += 11

    # Progress bar + percentage below
    if progress_pct is not None:
        bar_w = int(1.15 * min(100, max(0, progress_pct)))
        d.rectangle((4, 98, 123, 105), outline="#444")
        if bar_w > 0:
            d.rectangle((4, 98, 4 + bar_w, 105), fill="#00FF00")
        d.text((60, 107), f"{int(progress_pct)}%", font=FONT_SM, fill="#888")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _git(args, timeout=30):
    """Run a git command in RASPYJACK_DIR."""
    try:
        r = subprocess.run(
            ["git", "-C", RASPYJACK_DIR] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return False, "", str(e)


def get_current_version():
    """Return (short_hash, date, full_hash)."""
    ok, h, _ = _git(["rev-parse", "--short", "HEAD"])
    short = h if ok else "?"
    ok, fh, _ = _git(["rev-parse", "HEAD"])
    full = fh if ok else ""
    ok, d, _ = _git(["log", "-1", "--format=%cd", "--date=short"])
    date = d if ok else "?"
    return short, date, full


def check_update_available():
    """Fetch remote and check if updates exist. Returns (available, info, count)."""
    show_progress("Checking...", "Fetching remote")
    ok, _, err = _git(["fetch", GIT_REMOTE], timeout=60)
    if not ok:
        return False, f"Fetch failed: {err[:30]}", 0

    ok, local, _ = _git(["rev-parse", "HEAD"])
    ok2, remote, _ = _git(["rev-parse", f"{GIT_REMOTE}/{GIT_BRANCH}"])
    if not ok or not ok2:
        return False, "Can't read hashes", 0

    if local == remote:
        return False, "Already up to date!", 0

    ok, log, _ = _git(["log", "--oneline", f"HEAD..{GIT_REMOTE}/{GIT_BRANCH}"])
    lines = [l for l in log.split("\n") if l.strip()] if log else []
    return True, f"{len(lines)} new commit(s)", len(lines)


def get_changelog(old_hash):
    """Return list of commit messages since old_hash."""
    ok, log, _ = _git(["log", "--oneline", f"{old_hash}..HEAD"])
    if not ok or not log:
        return []
    return [l.strip() for l in log.split("\n") if l.strip()][:10]


# ---------------------------------------------------------------------------
# Backup (lightweight, targeted)
# ---------------------------------------------------------------------------

def _count_backups():
    if not os.path.isdir(BACKUP_ROOT):
        return 0
    return len([d for d in os.listdir(BACKUP_ROOT) if os.path.isdir(os.path.join(BACKUP_ROOT, d))])


def smart_backup():
    """Backup only config files and custom payloads. Returns (ok, backup_path)."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(BACKUP_ROOT, ts)

    try:
        os.makedirs(backup_dir, exist_ok=True)

        # Backup config files
        for fname in CONFIG_FILES:
            src = os.path.join(RASPYJACK_DIR, fname)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(backup_dir, fname))

        # Backup config directories
        for dname in CONFIG_DIRS:
            src = os.path.join(RASPYJACK_DIR, dname)
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(backup_dir, dname))

        # Backup custom payloads (untracked by git)
        ok, untracked, _ = _git(["ls-files", "--others", "--exclude-standard", "payloads/"])
        if ok and untracked:
            custom_dir = os.path.join(backup_dir, "custom_payloads")
            os.makedirs(custom_dir, exist_ok=True)
            for relpath in untracked.split("\n"):
                relpath = relpath.strip()
                if not relpath:
                    continue
                src = os.path.join(RASPYJACK_DIR, relpath)
                dst = os.path.join(custom_dir, os.path.basename(relpath))
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

        return True, backup_dir
    except Exception as e:
        return False, str(e)


def restore_configs(backup_dir):
    """Restore config files from a backup directory."""
    restored = 0
    try:
        # Restore config files
        for fname in CONFIG_FILES:
            src = os.path.join(backup_dir, fname)
            dst = os.path.join(RASPYJACK_DIR, fname)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
                restored += 1

        # Restore config directories
        for dname in CONFIG_DIRS:
            src = os.path.join(backup_dir, dname)
            dst = os.path.join(RASPYJACK_DIR, dname)
            if os.path.isdir(src):
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
                restored += 1

        # Restore custom payloads
        custom_dir = os.path.join(backup_dir, "custom_payloads")
        if os.path.isdir(custom_dir):
            payloads_dir = os.path.join(RASPYJACK_DIR, "payloads")
            for fname in os.listdir(custom_dir):
                src = os.path.join(custom_dir, fname)
                dst = os.path.join(payloads_dir, fname)
                if os.path.isfile(src) and not os.path.isfile(dst):
                    shutil.copy2(src, dst)
                    restored += 1

        return True, f"{restored} items restored"
    except Exception as e:
        return False, str(e)


def cleanup_old_backups(keep=3):
    """Keep only the N most recent backups."""
    if not os.path.isdir(BACKUP_ROOT):
        return
    dirs = sorted([
        d for d in os.listdir(BACKUP_ROOT)
        if os.path.isdir(os.path.join(BACKUP_ROOT, d))
    ])
    while len(dirs) > keep:
        old = dirs.pop(0)
        try:
            shutil.rmtree(os.path.join(BACKUP_ROOT, old))
        except Exception:
            pass


def list_backups():
    """Return sorted list of backup directory names."""
    if not os.path.isdir(BACKUP_ROOT):
        return []
    return sorted([
        d for d in os.listdir(BACKUP_ROOT)
        if os.path.isdir(os.path.join(BACKUP_ROOT, d))
    ], reverse=True)


# ---------------------------------------------------------------------------
# Update + install
# ---------------------------------------------------------------------------

def git_update():
    """Hard reset to latest remote."""
    ok, _, err = _git(["reset", "--hard", f"{GIT_REMOTE}/{GIT_BRANCH}"])
    if not ok:
        return False, err[:40]
    return True, "OK"


def run_install_script():
    """Run install script with live progress on LCD."""
    if not os.path.isfile(INSTALL_SCRIPT):
        return True, "no script"

    # Detect current display type to auto-answer the interactive prompt
    display_choice = "1"  # default ST7735_128
    try:
        with open(os.path.join(RASPYJACK_DIR, "gui_conf.json"), "r") as f:
            cfg = json.load(f)
        if cfg.get("DISPLAY", {}).get("type") == "ST7789_240":
            display_choice = "2"
    except Exception:
        pass

    try:
        proc = subprocess.Popen(
            ["bash", INSTALL_SCRIPT, "--update"],
            cwd=RASPYJACK_DIR,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        # In --update mode, display is auto-detected from gui_conf.json
        # No interactive prompt needed, but send choice as fallback
        try:
            proc.stdin.write(display_choice + "\n")
            proc.stdin.flush()
        except Exception:
            pass
        line_count = 0
        last_line = ""
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            clean = _strip_ansi(line.strip())
            if clean:
                line_count += 1
                last_line = clean
                show_progress("Installing...", clean, min(95, line_count * 2))

        rc = proc.wait(timeout=300)
        if rc != 0:
            return False, f"Exit code {rc}: {last_line}"
        return True, "OK"
    except Exception as e:
        return False, str(e)[:40]


def restart_service():
    try:
        subprocess.run(["systemctl", "restart", SERVICE_NAME], check=True, timeout=10)
        return True, "OK"
    except Exception as e:
        return False, str(e)


def do_reboot():
    subprocess.run(["sync"], check=False)
    subprocess.run(["systemctl", "reboot"], check=False)


# ---------------------------------------------------------------------------
# LCD screens
# ---------------------------------------------------------------------------

def draw_home(version, date, disk_free, backup_count):
    """Draw the home screen with system info."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "AUTO-UPDATE", font=FONT, fill="#00FF00")

    d.text((4, 18), f"Version: {version}", font=FONT, fill="#FFFFFF")
    d.text((4, 32), f"Date: {date}", font=FONT, fill="#888888")
    d.text((4, 46), f"Disk: {disk_free}", font=FONT, fill="#888888")
    d.text((4, 60), f"Backups: {backup_count}", font=FONT, fill="#888888")

    d.text((4, 80), "KEY1  Check & Update", font=FONT_SM, fill="#58a6ff")
    d.text((4, 92), "KEY2  Rollback", font=FONT_SM, fill="#FFAA00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "KEY1:Update K2:Roll K3:X", font=FONT_SM, fill="#888")

    LCD.LCD_ShowImage(img, 0, 0)


def draw_changelog(commits, scroll_pos):
    """Draw changelog screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#002200")
    d.text((2, 1), f"CHANGELOG ({len(commits)})", font=FONT, fill="#00FF00")

    visible = commits[scroll_pos:scroll_pos + 7]
    for i, line in enumerate(visible):
        y = 16 + i * 13
        # Truncate hash, show message
        parts = line.split(" ", 1)
        if len(parts) == 2:
            d.text((2, y), parts[0][:7], font=FONT_SM, fill="#58a6ff")
            d.text((36, y), parts[1][:14], font=FONT_SM, fill="#CCCCCC")
        else:
            d.text((2, y), line[:22], font=FONT_SM, fill="#CCCCCC")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "KEY1:Continue KEY3:Abort", font=FONT_SM, fill="#888")

    LCD.LCD_ShowImage(img, 0, 0)


def draw_rollback(backups, sel):
    """Draw rollback selection screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#442200")
    d.text((2, 1), "ROLLBACK", font=FONT, fill="#FFAA00")

    if not backups:
        d.text((4, 50), "No backups found", font=FONT, fill="#FF4444")
    else:
        visible = backups[:7]
        for i, name in enumerate(visible):
            y = 18 + i * 13
            prefix = ">" if i == sel else " "
            color = "#00FF00" if i == sel else "#CCCCCC"
            # Format: 20260408_223000 -> 2026-04-08 22:30
            display = name
            if len(name) >= 15:
                display = f"{name[:4]}-{name[4:6]}-{name[6:8]} {name[9:11]}:{name[11:13]}"
            d.text((2, y), f"{prefix}{display}", font=FONT_SM, fill=color)

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Restore KEY3:Back", font=FONT_SM, fill="#888")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    # Get system info for home screen
    version, date, full_hash = get_current_version()
    try:
        usage = shutil.disk_usage(RASPYJACK_DIR)
        disk_free = f"{usage.free // (1024*1024)}MB"
    except Exception:
        disk_free = "?"
    backup_count = _count_backups()

    view = "home"
    changelog = []
    changelog_scroll = 0
    rollback_sel = 0
    backups = []
    should_reboot = False
    backup_path = None

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if view == "home":
                if btn == "KEY3":
                    break
                elif btn == "KEY1":
                    # Debounce
                    while get_button(PINS, GPIO) == "KEY1":
                        time.sleep(0.05)

                    # 1. Check for updates
                    available, info, count = check_update_available()
                    if not available:
                        show([info], invert=count == 0)
                        time.sleep(3)
                        # Refresh home info
                        version, date, full_hash = get_current_version()
                        draw_home(version, date, disk_free, backup_count)
                        time.sleep(0.3)
                        continue

                    show([f"{count} update(s)", "available!", "", "Backing up..."])
                    time.sleep(1)

                    # 2. Smart backup
                    show_progress("Backing up...", "Configs & custom")
                    ok, backup_path = smart_backup()
                    if not ok:
                        show_error("BACKUP FAILED", backup_path)
                        continue

                    # 3. Check disk space
                    try:
                        usage = shutil.disk_usage(RASPYJACK_DIR)
                        if usage.free < 100 * 1024 * 1024:
                            show_error("LOW DISK SPACE", f"Only {usage.free//(1024*1024)}MB free, need 100MB minimum")
                            continue
                    except Exception:
                        pass

                    # 4. Git pull
                    old_hash = full_hash
                    show_progress("Updating...", "git reset --hard")
                    ok, info = git_update()
                    if not ok:
                        show_error("UPDATE FAILED", info)
                        continue

                    # 5. Restore configs
                    show_progress("Restoring...", "configs & payloads")
                    ok, info = restore_configs(backup_path)

                    # 6. Cleanup old backups
                    cleanup_old_backups(keep=3)

                    # 7. Show changelog
                    changelog = get_changelog(old_hash)
                    if changelog:
                        changelog_scroll = 0
                        view = "changelog"
                    else:
                        # No changelog, go straight to install
                        show_progress("Installing...", "Please wait")
                        ok, info = run_install_script()
                        if not ok:
                            show_error("INSTALL FAILED", info)
                            continue

                        show(["Update done!", "Rebooting..."])
                        time.sleep(2)
                        should_reboot = True
                        break

                    time.sleep(0.3)

                elif btn == "KEY2":
                    # Rollback menu
                    backups = list_backups()
                    rollback_sel = 0
                    view = "rollback"
                    time.sleep(0.3)

                draw_home(version, date, disk_free, backup_count)

            elif view == "changelog":
                if btn == "KEY3":
                    view = "home"
                    version, date, full_hash = get_current_version()
                    backup_count = _count_backups()
                    time.sleep(0.3)
                elif btn == "KEY1":
                    # Continue to install
                    show_progress("Installing...", "Please wait")
                    ok, info = run_install_script()
                    if not ok:
                        show_error("INSTALL FAILED", info)
                        view = "home"
                        version, date, full_hash = get_current_version()
                        backup_count = _count_backups()
                        continue

                    show(["Update done!", "Rebooting..."])
                    time.sleep(2)
                    should_reboot = True
                    break
                elif btn == "UP":
                    changelog_scroll = max(0, changelog_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    changelog_scroll = min(max(0, len(changelog) - 7), changelog_scroll + 1)
                    time.sleep(0.15)

                draw_changelog(changelog, changelog_scroll)

            elif view == "rollback":
                if btn == "KEY3":
                    view = "home"
                    time.sleep(0.3)
                elif btn == "UP":
                    rollback_sel = max(0, rollback_sel - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    rollback_sel = min(max(0, len(backups) - 1), rollback_sel + 1)
                    time.sleep(0.15)
                elif btn == "OK" and backups:
                    selected = backups[rollback_sel]
                    bpath = os.path.join(BACKUP_ROOT, selected)
                    show_progress("Restoring...", selected[:16])
                    ok, info = restore_configs(bpath)
                    if ok:
                        show(["Restored!", info, "", "Restarting..."])
                        time.sleep(2)
                        restart_service()
                        time.sleep(1)
                        break
                    else:
                        show_error("RESTORE FAILED", info)

                draw_rollback(backups, rollback_sel)

            time.sleep(0.05)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        try:
            GPIO.cleanup()
        except Exception:
            pass

    if should_reboot:
        do_reboot()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
