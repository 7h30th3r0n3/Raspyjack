#!/usr/bin/env python3
"""
RaspyJack Payload -- USB Mass Storage Gadget
=============================================
Author: 7h30th3r0n3

Creates a FAT32 disk image and configures the Pi Zero as a USB mass storage
device via Linux configfs.  Can pre-load files from template directories.
Monitors host access via inotify on the mount point.

Setup / Prerequisites:
  - Requires Pi Zero USB OTG port.
  - Creates FAT32 disk image. Target sees Pi as USB drive.

Controls:
  OK         -- Start / stop gadget
  KEY1       -- Select template (empty / documents / autorun)
  KEY2       -- Show access log (file reads from host)
  KEY3       -- Exit + cleanup gadget

Requires: root privileges, configfs support, dosfstools
"""

import os
import sys
import time
import shutil
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

GADGET_NAME = "raspyjack_usb"
CONFIGFS_BASE = "/sys/kernel/config/usb_gadget"
GADGET_PATH = os.path.join(CONFIGFS_BASE, GADGET_NAME)
IMAGE_PATH = "/tmp/raspyjack_usb.img"
MOUNT_PATH = "/tmp/raspyjack_usb_mount"
IMAGE_SIZE_MB = 64
TEMPLATE_DIR = "/root/Raspyjack/templates/usb"

TEMPLATES = ["empty", "documents", "autorun"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
gadget_active = False
template_idx = 0
status_msg = "Ready"
access_log = []
show_log = False
scroll = 0
files_loaded = 0

# ---------------------------------------------------------------------------
# Image creation
# ---------------------------------------------------------------------------

def _create_image(size_mb):
    """Create a FAT32 disk image."""
    try:
        subprocess.run(
            ["dd", "if=/dev/zero", f"of={IMAGE_PATH}",
             "bs=1M", f"count={size_mb}"],
            capture_output=True, timeout=60,
        )
        subprocess.run(
            ["mkfs.vfat", "-F", "32", "-n", "RASPYJACK", IMAGE_PATH],
            capture_output=True, timeout=30,
        )
        return True
    except Exception:
        return False


def _mount_image():
    """Mount the image to load files."""
    os.makedirs(MOUNT_PATH, exist_ok=True)
    try:
        subprocess.run(
            ["mount", "-o", "loop", IMAGE_PATH, MOUNT_PATH],
            capture_output=True, timeout=10,
        )
        return True
    except Exception:
        return False


def _unmount_image():
    """Unmount the image."""
    try:
        subprocess.run(
            ["umount", MOUNT_PATH],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


def _load_template(template_name):
    """Load files from template directory into the image."""
    global files_loaded
    template_path = os.path.join(TEMPLATE_DIR, template_name)

    if not _mount_image():
        return 0

    count = 0
    if template_name == "empty":
        # Just create a readme
        readme = os.path.join(MOUNT_PATH, "README.txt")
        try:
            with open(readme, "w") as f:
                f.write("USB Storage Device\n")
            count = 1
        except Exception:
            pass

    elif template_name == "autorun":
        # Create autorun.inf pointing to a placeholder
        try:
            inf_path = os.path.join(MOUNT_PATH, "autorun.inf")
            with open(inf_path, "w") as f:
                f.write("[autorun]\n")
                f.write("open=setup.exe\n")
                f.write("icon=setup.exe,0\n")
                f.write("label=System Update\n")
            count = 1
        except Exception:
            pass

    elif os.path.isdir(template_path):
        # Copy all files from template directory
        try:
            for item in os.listdir(template_path):
                src = os.path.join(template_path, item)
                dst = os.path.join(MOUNT_PATH, item)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                    count += 1
                elif os.path.isdir(src):
                    shutil.copytree(src, dst)
                    count += 1
        except Exception:
            pass

    _unmount_image()

    with lock:
        files_loaded = count
    return count

# ---------------------------------------------------------------------------
# ConfigFS gadget setup
# ---------------------------------------------------------------------------

def _setup_gadget():
    """Configure USB mass storage gadget via configfs."""
    try:
        os.makedirs(GADGET_PATH, exist_ok=True)

        # Device descriptors
        _write_sysfs(os.path.join(GADGET_PATH, "idVendor"), "0x1d6b")
        _write_sysfs(os.path.join(GADGET_PATH, "idProduct"), "0x0104")
        _write_sysfs(os.path.join(GADGET_PATH, "bcdDevice"), "0x0100")
        _write_sysfs(os.path.join(GADGET_PATH, "bcdUSB"), "0x0200")

        # Strings
        strings_dir = os.path.join(GADGET_PATH, "strings", "0x409")
        os.makedirs(strings_dir, exist_ok=True)
        _write_sysfs(os.path.join(strings_dir, "serialnumber"), "000000000001")
        _write_sysfs(os.path.join(strings_dir, "manufacturer"), "RaspyJack")
        _write_sysfs(os.path.join(strings_dir, "product"), "USB Storage")

        # Mass storage function
        func_dir = os.path.join(GADGET_PATH, "functions", "mass_storage.usb0")
        os.makedirs(func_dir, exist_ok=True)
        lun_dir = os.path.join(func_dir, "lun.0")
        os.makedirs(lun_dir, exist_ok=True)
        _write_sysfs(os.path.join(lun_dir, "cdrom"), "0")
        _write_sysfs(os.path.join(lun_dir, "nofua"), "0")
        _write_sysfs(os.path.join(lun_dir, "removable"), "1")
        _write_sysfs(os.path.join(lun_dir, "ro"), "0")
        _write_sysfs(os.path.join(lun_dir, "file"), IMAGE_PATH)

        # Configuration
        config_dir = os.path.join(GADGET_PATH, "configs", "c.1")
        os.makedirs(config_dir, exist_ok=True)
        config_str = os.path.join(config_dir, "strings", "0x409")
        os.makedirs(config_str, exist_ok=True)
        _write_sysfs(os.path.join(config_str, "configuration"), "Mass Storage")
        _write_sysfs(os.path.join(config_dir, "MaxPower"), "250")

        # Link function to config
        link_path = os.path.join(config_dir, "mass_storage.usb0")
        if not os.path.exists(link_path):
            os.symlink(func_dir, link_path)

        # Bind to UDC
        udc = _find_udc()
        if udc:
            _write_sysfs(os.path.join(GADGET_PATH, "UDC"), udc)
            return True
        return False

    except Exception:
        return False


def _teardown_gadget():
    """Remove the USB gadget configuration."""
    try:
        # Unbind from UDC
        udc_file = os.path.join(GADGET_PATH, "UDC")
        if os.path.exists(udc_file):
            _write_sysfs(udc_file, "")
            time.sleep(0.5)

        # Remove symlink
        link_path = os.path.join(GADGET_PATH, "configs", "c.1", "mass_storage.usb0")
        if os.path.islink(link_path):
            os.unlink(link_path)

        # Remove directories (reverse order)
        for subdir in [
            "configs/c.1/strings/0x409",
            "configs/c.1",
            "functions/mass_storage.usb0/lun.0",
            "functions/mass_storage.usb0",
            "strings/0x409",
        ]:
            path = os.path.join(GADGET_PATH, subdir)
            if os.path.isdir(path):
                try:
                    os.rmdir(path)
                except OSError:
                    pass

        if os.path.isdir(GADGET_PATH):
            os.rmdir(GADGET_PATH)

    except Exception:
        pass


def _find_udc():
    """Find available USB Device Controller."""
    udc_dir = "/sys/class/udc"
    try:
        entries = os.listdir(udc_dir)
        if entries:
            return entries[0]
    except Exception:
        pass
    return None


def _write_sysfs(path, value):
    """Write a value to a sysfs file."""
    with open(path, "w") as f:
        f.write(value)

# ---------------------------------------------------------------------------
# Access monitoring thread
# ---------------------------------------------------------------------------

def _monitor_thread():
    """Monitor the gadget backing file for access."""
    global access_log

    last_mtime = 0.0
    while _running:
        if gadget_active and os.path.exists(IMAGE_PATH):
            try:
                stat = os.stat(IMAGE_PATH)
                if stat.st_mtime != last_mtime and last_mtime > 0:
                    ts = datetime.now().strftime("%H:%M:%S")
                    with lock:
                        access_log.append(f"{ts} Image accessed")
                        if len(access_log) > 50:
                            access_log = access_log[-50:]
                    last_mtime = stat.st_mtime
                elif last_mtime == 0:
                    last_mtime = stat.st_mtime
            except Exception:
                pass
        time.sleep(2)

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "USB MASS STORAGE", font=font_obj, fill="#FF9900")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if gadget_active else "#444")

    with lock:
        msg = status_msg
        template = TEMPLATES[template_idx]
        loaded = files_loaded
        log = list(access_log)
        showing_log = show_log

    if showing_log:
        d.text((2, 16), "Access Log:", font=font_obj, fill="#FFAA00")
        visible = log[scroll:scroll + 7]
        if not visible:
            d.text((2, 30), "No access detected", font=font_obj, fill="#666")
        for i, entry in enumerate(visible):
            d.text((2, 28 + i * 12), entry[:24], font=font_obj, fill="#CCCCCC")
    else:
        d.text((2, 16), f"Status: {'ACTIVE' if gadget_active else 'IDLE'}",
               font=font_obj, fill="#00FF88" if gadget_active else "#888")
        d.text((2, 28), f"Image: {IMAGE_SIZE_MB}MB FAT32", font=font_obj, fill="#AAAAAA")
        d.text((2, 40), f"Template: {template}", font=font_obj, fill="#FFAA00")
        d.text((2, 52), f"Files loaded: {loaded}", font=font_obj, fill="#888")

        udc = _find_udc()
        udc_label = udc[:16] if udc else "none"
        d.text((2, 66), f"UDC: {udc_label}", font=font_obj, fill="#666")
        d.text((2, 78), f"Log entries: {len(log)}", font=font_obj, fill="#666")

        d.text((2, 96), msg[:24], font=font_obj, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if gadget_active:
        d.text((2, 117), "OK:Stop K2:Log K3:Quit", font=font_obj, fill="#888")
    else:
        d.text((2, 117), "OK:Go K1:Tmpl K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, gadget_active, template_idx, show_log, scroll, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    # Check for configfs
    if not os.path.isdir(CONFIGFS_BASE):
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 40), "configfs not found", font=font_obj, fill="#FF0000")
        d.text((4, 55), "modprobe libcomposite", font=font_obj, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Start access monitor
    threading.Thread(target=_monitor_thread, daemon=True).start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if gadget_active:
                    _teardown_gadget()
                    gadget_active = False
                    with lock:
                        status_msg = "Gadget stopped"
                else:
                    with lock:
                        status_msg = "Creating image..."

                    if _create_image(IMAGE_SIZE_MB):
                        template = TEMPLATES[template_idx]
                        _load_template(template)

                        if _setup_gadget():
                            gadget_active = True
                            with lock:
                                status_msg = "Gadget active"
                        else:
                            with lock:
                                status_msg = "Gadget setup failed"
                    else:
                        with lock:
                            status_msg = "Image create failed"
                time.sleep(0.3)

            elif btn == "KEY1" and not gadget_active:
                template_idx = (template_idx + 1) % len(TEMPLATES)
                time.sleep(0.3)

            elif btn == "KEY2":
                show_log = not show_log
                scroll = 0
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(access_log) - 7)
                scroll = min(scroll + 1, max_s)
                time.sleep(0.15)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        if gadget_active:
            _teardown_gadget()
        # Cleanup image
        if os.path.exists(IMAGE_PATH):
            try:
                os.remove(IMAGE_PATH)
            except Exception:
                pass
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
