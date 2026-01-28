#!/usr/bin/env python3
"""
BadUSB detector payload
-----------------------
Watches for USB insertion events and raises a RED alert if:
- a new USB keyboard starts sending keystrokes quickly after insertion
- a removable mass-storage device is mounted
"""

import os
import sys
import time
import threading

# Ensure RaspyJack modules are importable when launched directly
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore
import RPi.GPIO as GPIO  # type: ignore

try:
    import pyudev  # type: ignore
except Exception:
    pyudev = None

try:
    from evdev import InputDevice, ecodes, list_devices  # type: ignore
except Exception:
    InputDevice = None
    ecodes = None
    list_devices = None


WIDTH, HEIGHT = 128, 128
KEY3_PIN = 16
ALERT_WINDOW_SEC = 8
KEY_EVENT_THRESHOLD = 1
KEY_WINDOW_SEC = None
DETECT_ANY_KEYBOARD = True  # Any keyboard device with ID_INPUT_KEYBOARD=1

running = True
alert_active = False
alert_reason = ""
alert_since = 0.0
watched_keyboards = set()
status_message = ""
status_until = 0.0


def _ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    print(f"[{_ts()}] {msg}")


def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    log("LCD initialized")
    return lcd


def draw_screen(lcd, lines, color="white", bg="black"):
    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    y = 5
    for line in lines:
        if line:
            d.text((5, y), line[:18], font=font, fill=color)
            y += 14
    lcd.LCD_ShowImage(img, 0, 0)


def draw_alert(lcd, reason):
    img = Image.new("RGB", (WIDTH, HEIGHT), "red")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    d.rectangle((4, 4, 123, 123), outline="white")
    d.text((10, 12), "!!! ALERT !!!", font=font, fill="white")
    d.text((10, 34), "BadUSB DETECT", font=font, fill="white")
    d.rectangle((10, 56, 118, 98), fill="black")
    d.text((14, 62), reason[:16], font=font, fill="white")
    d.text((10, 104), "KEY3 = Exit", font=font, fill="white")
    lcd.LCD_ShowImage(img, 0, 0)
    # Logging handled when alert is triggered


def _popup(message, duration=1.5):
    global status_message, status_until
    status_message = message
    status_until = time.time() + duration


def draw_status(lcd):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    d.rectangle((0, 0, 127, 16), fill="#1a1a1a")
    d.text((4, 2), "BadUSB Monitor", font=font, fill="white")
    # Simple USB/Keyboard icons
    # USB icon (left)
    d.line((90, 4, 90, 12), fill="white")
    d.line((90, 4, 96, 4), fill="white")
    d.line((96, 4, 96, 6), fill="white")
    d.line((90, 12, 94, 12), fill="white")
    d.line((94, 12, 94, 10), fill="white")
    # Keyboard icon (right)
    d.rectangle((104, 3, 122, 13), outline="white", fill=None)
    d.rectangle((106, 6, 120, 10), outline=None, fill="white")
    d.text((4, 22), "Status: READY", font=font, fill="#00ff00")
    d.text((4, 40), "USB: watching", font=font, fill="white")
    d.text((4, 58), "Keys: any", font=font, fill="white")
    d.text((4, 76), "KEY3 to exit", font=font, fill="white")

    if time.time() < status_until and status_message:
        d.rectangle((6, 92, 121, 120), fill="#2b2b2b", outline="white")
        d.text((10, 98), status_message[:16], font=font, fill="white")
    lcd.LCD_ShowImage(img, 0, 0)


def is_removable_mount_present():
    try:
        with open("/proc/mounts", "r") as f:
            mounts = f.read().splitlines()
        log(f"Mounts checked: {len(mounts)} entries")
        for line in mounts:
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mnt, fstype = parts[0], parts[1], parts[2]
            if device.startswith("/dev/sd") or device.startswith("/dev/mmcblk"):
                # Check removable flag if available
                base = device.replace("/dev/", "").rstrip("0123456789")
                removable = f"/sys/block/{base}/removable"
                if os.path.exists(removable):
                    try:
                        if open(removable).read().strip() == "1":
                            log(f"Removable mounted: {device} at {mnt} ({fstype})")
                            return True, f"Mounted: {os.path.basename(device)}"
                    except Exception:
                        pass
                # Fallback: common mount points for removable media
                if mnt.startswith(("/media/", "/mnt/", "/run/media/")):
                    log(f"Mounted under removable path: {device} at {mnt} ({fstype})")
                    return True, f"Mounted: {os.path.basename(device)}"
    except Exception:
        pass
    return False, ""


def count_keyboard_events_on_device(dev_path, duration_sec=KEY_WINDOW_SEC):
    if not list_devices or not InputDevice or not ecodes:
        log("evdev not available")
        return 0
    count = 0
    try:
        dev = InputDevice(dev_path)
        caps = dev.capabilities()
        if ecodes.EV_KEY not in caps:
            log(f"Device {dev.path} has no EV_KEY capability")
            return 0
        log(f"Monitoring keyboard device: {dev.path} ({dev.name})")
        if hasattr(dev, "set_blocking"):
            dev.set_blocking(False)
        elif hasattr(dev, "setblocking"):
            dev.setblocking(False)
        else:
            try:
                import fcntl
                flags = fcntl.fcntl(dev.fd, fcntl.F_GETFL)
                fcntl.fcntl(dev.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            except Exception:
                pass
        start = time.time()
        while True:
            try:
                for event in dev.read():
                    if event.type == ecodes.EV_KEY and event.value == 1:
                        count += 1
                        if count >= KEY_EVENT_THRESHOLD:
                            log(f"Key threshold reached on {dev_path}")
                            return count
            except Exception:
                pass
            time.sleep(0.02)
            if duration_sec is not None and (time.time() - start) >= duration_sec:
                break
    except Exception as e:
        log(f"Keyboard read error: {e}")
    if duration_sec is None:
        log(f"Keyboard events counted: {count} on {dev_path} (continuous)")
    else:
        log(f"Keyboard events counted: {count} on {dev_path} in {duration_sec:.1f}s")
    return count


def _is_usb_keyboard(devnode):
    if not pyudev:
        return False
    try:
        ctx = pyudev.Context()
        dev = pyudev.Devices.from_device_file(ctx, devnode)
        return dev.get("ID_INPUT_KEYBOARD") == "1" and dev.get("ID_BUS") == "usb"
    except Exception:
        return False


def _list_keycap_devices():
    if not list_devices or not InputDevice or not ecodes:
        return []
    devs = []
    for path in list_devices():
        if not path.startswith("/dev/input/event"):
            continue
        try:
            dev = InputDevice(path)
            caps = dev.capabilities()
            if ecodes.EV_KEY in caps:
                devs.append((dev.path, dev.name))
        except Exception:
            continue
    return devs


def trigger_alert(reason):
    global alert_active, alert_reason, alert_since
    alert_active = True
    alert_reason = reason
    alert_since = time.time()
    log(f"Trigger alert: {reason}")
    _popup(f"ALERT: {reason}", duration=2.0)


def _watch_keyboard_continuous(devnode):
    log(f"Continuous watch started on {devnode}")
    keys = count_keyboard_events_on_device(devnode, duration_sec=None)
    if keys >= KEY_EVENT_THRESHOLD:
        trigger_alert(f"Keys: {keys}")


def monitor_usb():
    if not pyudev:
        log("pyudev not available; cannot monitor USB")
        return
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="usb")
    log("USB monitor started (subsystem=usb)")
    # No snapshot needed in "any keyboard" mode; we will watch all on startup

    for device in iter(monitor.poll, None):
        if not running:
            break
        if device.action == "add":
            log(f"USB add: {device}")
            # Quick checks after insertion
            time.sleep(0.5)
            _popup("USB plugged", duration=1.2)

            mounted, msg = is_removable_mount_present()
            if mounted:
                trigger_alert(msg)
                continue

            # USB add: we just log; keyboard detection handled by input monitor
            if not alert_active:
                log("USB device added; input monitor will handle keyboards")
        elif device.action == "remove":
            log(f"USB remove: {device}")
            _popup("USB removed", duration=1.2)


def monitor_input():
    if not pyudev:
        log("pyudev not available; cannot monitor input")
        return
    context = pyudev.Context()
    mon = pyudev.Monitor.from_netlink(context)
    mon.filter_by(subsystem="input")
    log("Input monitor started (subsystem=input)")

    for device in iter(mon.poll, None):
        if not running:
            break
        if device.action == "add":
            devnode = device.device_node
            if devnode and devnode.startswith("/dev/input/event"):
                try:
                    dev = InputDevice(devnode)
                    caps = dev.capabilities()
                    if ecodes.EV_KEY in caps:
                        if devnode in watched_keyboards:
                            continue
                        watched_keyboards.add(devnode)
                        name = getattr(dev, "name", "input")
                        log(f"Input add (keycap): {devnode} ({name})")
                        _popup("Keyboard added", duration=1.2)
                        t = threading.Thread(
                            target=_watch_keyboard_continuous,
                            args=(devnode,),
                            daemon=True,
                        )
                        t.start()
                    else:
                        log(f"Input add (no-keycap): {devnode}")
                except Exception as e:
                    log(f"Input add read error: {devnode} ({e})")
        elif device.action == "remove":
            devnode = device.device_node
            if devnode and devnode.startswith("/dev/input/event"):
                log(f"Input remove: {devnode}")
                _popup("Keyboard removed", duration=1.2)
                if devnode in watched_keyboards:
                    watched_keyboards.remove(devnode)


def main():
    global running, alert_active

    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(KEY3_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    log("GPIO initialized")

    if not pyudev:
        draw_screen(lcd, ["BadUSB", "pyudev missing", "", "Exit"], color="white", bg="black")
        time.sleep(2)
        log("Exiting: pyudev missing")
        return 1

    t = threading.Thread(target=monitor_usb, daemon=True)
    t.start()
    log("Background USB monitor thread started")

    ti = threading.Thread(target=monitor_input, daemon=True)
    ti.start()
    log("Background input monitor thread started")

    # Start watching any existing keyboards immediately
    try:
        kbds = _list_keycap_devices()
        log(f"Key-capable inputs at start: {len(kbds)}")
        for devnode, name in kbds:
            if devnode in watched_keyboards:
                continue
            watched_keyboards.add(devnode)
            log(f"Watching input: {devnode} ({name})")
            t = threading.Thread(
                target=_watch_keyboard_continuous,
                args=(devnode,),
                daemon=True,
            )
            t.start()
    except Exception as e:
        log(f"Keycap init scan error: {e}")

    draw_status(lcd)
    log("Waiting for USB events")

    while running:
        if GPIO.input(KEY3_PIN) == 0:
            log("Exit requested (KEY3)")
            break

        if alert_active:
            # Show red alert for a bit, then return to idle
            draw_alert(lcd, alert_reason)
            if time.time() - alert_since > ALERT_WINDOW_SEC:
                alert_active = False
                draw_status(lcd)
                log("Alert cleared; back to idle")
        else:
            draw_status(lcd)
        time.sleep(0.1)

    running = False
    draw_screen(lcd, ["BadUSB", "Detector", "", "Bye"], color="white", bg="black")
    log("Shutdown complete")
    time.sleep(0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
