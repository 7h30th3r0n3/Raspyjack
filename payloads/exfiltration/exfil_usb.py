#!/usr/bin/env python3
"""
RaspyJack Payload -- USB Drive Auto-Copy
==========================================
Author: 7h30th3r0n3

Monitors for USB mass storage insertion using pyudev (or polling /dev/sd*).
When detected: mount the drive, copy all of /root/Raspyjack/loot/ to the
USB under a timestamped folder, then unmount.

Setup / Prerequisites
---------------------
- ``pyudev`` recommended (``pip install pyudev``).
- USB mass storage device.
- Root privileges for mount/umount.

Controls
--------
  OK          -- Force copy now (if USB already inserted)
  KEY1        -- Toggle auto-copy on/off
  KEY2        -- Show USB info (device, filesystem, free space)
  KEY3        -- Exit
"""

import os
import sys
import time
import glob
import shutil
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_ROOT = "/root/Raspyjack/loot"
MOUNT_POINT = "/mnt/raspyjack_usb"
os.makedirs(MOUNT_POINT, exist_ok=True)

DEBOUNCE = 0.22

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "auto_copy": True,
    "usb_device": "",
    "usb_mounted": False,
    "usb_info": {},
    "copying": False,
    "stop": False,
    "status": "Waiting for USB...",
    "progress": "",
    "files_copied": 0,
    "total_files": 0,
    "log": [],
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, (list, dict)):
            return list(val) if isinstance(val, list) else dict(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


def _add_log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    with _lock:
        _state["log"] = (list(_state["log"]) + [entry])[-30:]


# ---------------------------------------------------------------------------
# USB detection
# ---------------------------------------------------------------------------
def _find_usb_device():
    """Find USB storage device path (/dev/sd?1 or /dev/sd?)."""
    # Look for partitions first
    for pattern in ["/dev/sd?1", "/dev/sd?"]:
        devices = sorted(glob.glob(pattern))
        for dev in devices:
            # Verify it's a block device
            try:
                result = subprocess.run(
                    ["lsblk", "-no", "TYPE", dev],
                    capture_output=True, text=True, timeout=5,
                )
                dtype = result.stdout.strip()
                if dtype in ("part", "disk"):
                    return dev
            except Exception:
                pass
    return ""


def _get_usb_info(device):
    """Get USB device info: filesystem, size, label."""
    info = {"device": device, "fs": "?", "size": "?", "label": "?", "free": "?"}
    try:
        out = subprocess.run(
            ["lsblk", "-no", "FSTYPE,SIZE,LABEL", device],
            capture_output=True, text=True, timeout=5,
        )
        parts = out.stdout.strip().split()
        if len(parts) >= 1:
            info["fs"] = parts[0]
        if len(parts) >= 2:
            info["size"] = parts[1]
        if len(parts) >= 3:
            info["label"] = parts[2]
    except Exception:
        pass
    return info


def _mount_usb(device):
    """Mount USB device to MOUNT_POINT."""
    # Unmount if already mounted somewhere
    try:
        subprocess.run(["umount", device], capture_output=True, timeout=10)
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["mount", device, MOUNT_POINT],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            _set(usb_mounted=True)
            return True
        _add_log(f"Mount fail: {result.stderr[:20]}")
    except Exception as exc:
        _add_log(f"Mount err: {str(exc)[:18]}")
    return False


def _unmount_usb():
    """Safely unmount USB."""
    try:
        subprocess.run(["sync"], timeout=10)
        subprocess.run(["umount", MOUNT_POINT],
                        capture_output=True, timeout=10)
        _set(usb_mounted=False)
        return True
    except Exception:
        return False


def _get_free_space(path):
    """Return free space in human-readable format."""
    try:
        stat = os.statvfs(path)
        free_bytes = stat.f_bavail * stat.f_frsize
        if free_bytes > 1073741824:
            return f"{free_bytes / 1073741824:.1f}GB"
        return f"{free_bytes / 1048576:.0f}MB"
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# Copy logic
# ---------------------------------------------------------------------------
def _count_files():
    """Count files in loot directory."""
    count = 0
    if not os.path.isdir(LOOT_ROOT):
        return 0
    for _, _, files in os.walk(LOOT_ROOT):
        count += len(files)
    return count


def _do_copy():
    """Copy loot to USB drive."""
    _set(copying=True, status="Preparing copy...")

    device = _find_usb_device()
    if not device:
        _set(copying=False, status="No USB device found")
        _add_log("No USB found")
        return

    _set(usb_device=device, status="Mounting USB...")
    info = _get_usb_info(device)
    _set(usb_info=info)

    if not _mount_usb(device):
        _set(copying=False, status="Mount failed")
        return

    # Create timestamped folder
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_dir = os.path.join(MOUNT_POINT, f"RaspyJack_Loot_{ts}")
    os.makedirs(dest_dir, exist_ok=True)

    total = _count_files()
    _set(total_files=total, files_copied=0, status="Copying...")
    _add_log(f"Copying {total} files to USB")

    copied = 0
    try:
        for dirpath, dirnames, filenames in os.walk(LOOT_ROOT):
            if _get("stop"):
                break
            rel_dir = os.path.relpath(dirpath, LOOT_ROOT)
            target_dir = os.path.join(dest_dir, rel_dir)
            os.makedirs(target_dir, exist_ok=True)

            for fname in filenames:
                if _get("stop"):
                    break
                src = os.path.join(dirpath, fname)
                dst = os.path.join(target_dir, fname)
                _set(progress=f"{fname[:16]}", status=f"Copy {copied + 1}/{total}")

                try:
                    shutil.copy2(src, dst)
                    copied += 1
                    _set(files_copied=copied)
                except Exception as exc:
                    _add_log(f"Skip: {fname[:14]} {str(exc)[:8]}")
    except Exception as exc:
        _add_log(f"Copy error: {str(exc)[:18]}")

    # Unmount
    _set(status="Unmounting...")
    _unmount_usb()

    _set(copying=False, status=f"Done: {copied}/{total} files")
    _add_log(f"Copied {copied}/{total} files")


def _start_copy():
    if _get("copying"):
        return
    threading.Thread(target=_do_copy, daemon=True).start()


# ---------------------------------------------------------------------------
# USB monitor
# ---------------------------------------------------------------------------
def _usb_monitor():
    """Monitor for USB device insertion."""
    has_pyudev = False
    try:
        import pyudev
        has_pyudev = True
    except ImportError:
        pass

    if has_pyudev:
        _monitor_pyudev()
    else:
        _monitor_polling()


def _monitor_pyudev():
    """Monitor USB events via pyudev."""
    import pyudev
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block", device_type="partition")

    _add_log("pyudev monitor started")

    for device in iter(monitor.poll, None):
        if _get("stop"):
            break
        if device.action == "add":
            dev_path = device.device_node
            _add_log(f"USB detected: {dev_path}")
            _set(usb_device=dev_path, status=f"USB: {dev_path}")
            if _get("auto_copy") and not _get("copying"):
                time.sleep(1)  # Let device settle
                _start_copy()


def _monitor_polling():
    """Fallback: poll /dev/sd* for new devices."""
    _add_log("Polling mode (no pyudev)")
    known = set(glob.glob("/dev/sd?") + glob.glob("/dev/sd?1"))

    while not _get("stop"):
        current = set(glob.glob("/dev/sd?") + glob.glob("/dev/sd?1"))
        new_devs = current - known
        if new_devs:
            dev = sorted(new_devs)[0]
            _add_log(f"USB detected: {dev}")
            _set(usb_device=dev, status=f"USB: {dev}")
            if _get("auto_copy") and not _get("copying"):
                time.sleep(1)
                _start_copy()
        known = current
        time.sleep(2)


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    auto = _get("auto_copy")
    copying = _get("copying")
    status = _get("status")
    device = _get("usb_device")
    files_copied = _get("files_copied")
    total = _get("total_files")
    progress = _get("progress")
    log = _get("log")

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    auto_txt = "AUTO" if auto else "MAN"
    d.text((2, 1), f"USB EXFIL [{auto_txt}]", font=font, fill="#FFAA00")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if copying else "#666")

    y = 14
    d.text((2, y), f"USB: {device or 'none'}", font=font, fill="#AAAAAA")
    y += 12

    if copying:
        d.text((2, y), f"Copying: {files_copied}/{total}", font=font, fill="#00CCFF")
        y += 12
        # Progress bar
        if total > 0:
            pct = files_copied / total
            bar_w = int(120 * pct)
            d.rectangle((4, y, 124, y + 6), outline="#444")
            d.rectangle((4, y, 4 + bar_w, y + 6), fill="#00FF00")
            y += 10
        d.text((2, y), progress[:21], font=font, fill="#888")
        y += 14
    else:
        d.text((2, y), "Waiting for USB...", font=font, fill="#888")
        y += 14

    # Log
    visible = 3
    start = max(0, len(log) - visible)
    for i in range(start, len(log)):
        fg = "#888"
        if "Copied" in log[i] or "Done" in log[i]:
            fg = "#00FF00"
        elif "fail" in log[i].lower() or "err" in log[i].lower():
            fg = "#FF4444"
        d.text((2, y), log[i][:21], font=font, fill=fg)
        y += 11

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:copy K1:auto K3:x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def _show_usb_info():
    """Show USB device details."""
    device = _get("usb_device")
    if not device:
        return
    info = _get_usb_info(device)
    _set(usb_info=info)

    free = _get_free_space(MOUNT_POINT) if _get("usb_mounted") else "?"

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((2, 10), "USB Info", font=font, fill="#FFAA00")
    d.text((2, 28), f"Dev:  {info['device']}", font=font, fill="#AAA")
    d.text((2, 42), f"FS:   {info['fs']}", font=font, fill="#AAA")
    d.text((2, 56), f"Size: {info['size']}", font=font, fill="#AAA")
    d.text((2, 70), f"Label:{info['label']}", font=font, fill="#AAA")
    d.text((2, 84), f"Free: {free}", font=font, fill="#AAA")
    d.text((2, 110), "Press any key...", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)

    while True:
        btn = get_button(PINS, GPIO)
        if btn:
            break
        time.sleep(0.1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "USB AUTO-COPY", font=font, fill="#FFAA00")
    d.text((4, 32), "Loot to USB drive", font=font, fill="#888")
    d.text((4, 52), "OK=Force copy", font=font, fill="#666")
    d.text((4, 64), "K1=Toggle auto", font=font, fill="#666")
    d.text((4, 76), "K2=USB info  K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    # Start USB monitor thread
    threading.Thread(target=_usb_monitor, daemon=True).start()

    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                _set(stop=True)
                break

            elif btn == "OK":
                _start_copy()

            elif btn == "KEY1":
                auto = _get("auto_copy")
                _set(auto_copy=not auto)
                mode = "ON" if not auto else "OFF"
                _add_log(f"Auto-copy: {mode}")

            elif btn == "KEY2":
                _show_usb_info()

            _draw_lcd()
            time.sleep(0.05)

    finally:
        _set(stop=True)
        if _get("usb_mounted"):
            _unmount_usb()
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
