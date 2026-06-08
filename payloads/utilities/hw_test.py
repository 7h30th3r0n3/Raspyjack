#!/usr/bin/env python3
"""
RaspyJack Payload -- Hardware Test
=====================================
Author: 7h30th3r0n3

Full hardware diagnostic for CardputerZero.
Tests every component: LCD, keyboard, speaker, mic, camera,
GPS, WiFi, BT, USB, GPIO, I2C, IR, battery.

Controls:
  OK          Run next test / Confirm
  KEY3        Skip / Exit
"""

import os
import sys
import time
import signal
import subprocess
import struct
import math
import json
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._audio_helper import get_audio_card, get_alsa_dev

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(12)

_running = True
C_BG = (0, 0, 10)
C_PASS = (0, 220, 80)
C_FAIL = (255, 50, 50)
C_WARN = (255, 200, 0)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_HEAD = (20, 20, 50)
C_DARK = (12, 12, 20)
C_CYAN = (0, 200, 220)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    return get_button(PINS, GPIO)


def _draw(title, results, current_test="", hint="OK:Next  KEY3:Skip/Exit", scroll=0):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), title, font=font_lg, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 50, 1), title, font=font_lg, fill=C_CYAN)

        max_visible = (H - 50) // 14
        y = 24
        for i in range(max_visible):
            idx = scroll + i
            if idx >= len(results):
                break
            name, status, detail = results[idx]
            if status == "PASS":
                icon, color = "+", C_PASS
            elif status == "FAIL":
                icon, color = "X", C_FAIL
            elif status == "WARN":
                icon, color = "!", C_WARN
            else:
                icon, color = "?", C_DIM
            line = f"{icon} {name}: {detail[:28]}"
            d.text((8, y), line, font=font_sm, fill=color)
            y += 14

        if current_test:
            d.text((W // 2, H - 28), current_test, font=font_sm, fill=C_WHITE,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (10, H - 32), current_test, font=font_sm, fill=C_WHITE)

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), hint, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 13), hint, font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((15, 1), title[:14], font=font_lg, fill=C_CYAN)
        max_visible = 6
        y = 18
        for i in range(max_visible):
            idx = scroll + i
            if idx >= len(results):
                break
            name, status, detail = results[idx]
            icon = "+" if status == "PASS" else "X" if status == "FAIL" else "!"
            color = C_PASS if status == "PASS" else C_FAIL if status == "FAIL" else C_WARN
            d.text((4, y), f"{icon} {name[:8]}:{detail[:8]}", font=font_sm, fill=color)
            y += 12
        if current_test:
            d.text((4, 102), current_test[:17], font=font_sm, fill=C_WHITE)
        d.text((4, 114), hint[:17], font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _wait_btn(timeout=10):
    t0 = time.time()
    while _running and time.time() - t0 < timeout:
        btn = _get_btn()
        if btn:
            return btn
        time.sleep(0.05)
    return None


# ─── Individual Tests ───

def test_lcd():
    """Test LCD display with color pattern."""
    for color, name in [((255, 0, 0), "RED"), ((0, 255, 0), "GREEN"), ((0, 0, 255), "BLUE"), ((255, 255, 255), "WHITE")]:
        img = Image.new("RGB", (W, H), color)
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(0.5)
    return "PASS", f"{W}x{H} OK"


def test_framebuffer():
    """Test framebuffer access."""
    fb = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
    try:
        fd = os.open(fb, os.O_RDWR)
        os.close(fd)
        return "PASS", fb
    except Exception as e:
        return "FAIL", str(e)[:20]


def test_keyboard():
    """Test keyboard - wait for any key press."""
    _draw("HW TEST", [], "Press any key...", "Waiting for keypress")
    btn = _wait_btn(5)
    if btn:
        return "PASS", f"Key: {btn}"
    return "WARN", "No key (timeout)"


def test_i2c():
    """Scan I2C bus for devices."""
    try:
        r = subprocess.run(["i2cdetect", "-y", "1"], capture_output=True, text=True, timeout=5)
        devices = []
        for line in r.stdout.split("\n"):
            for part in line.split():
                if len(part) == 2 and part != "--" and part not in ("00", "10", "20", "30", "40", "50", "60", "70"):
                    try:
                        int(part, 16)
                        devices.append(f"0x{part}")
                    except ValueError:
                        pass
        if devices:
            return "PASS", f"{len(devices)} devs: {','.join(devices[:4])}"
        return "WARN", "No devices"
    except Exception as e:
        return "FAIL", str(e)[:20]


def test_es8389():
    """Test ES8389 audio codec."""
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        if "ES8388" in r.stdout or "ES8389" in r.stdout:
            for line in r.stdout.split("\n"):
                if "ES8388" in line or "ES8389" in line:
                    card = line.split(":")[0].replace("card", "").strip()
                    return "PASS", f"Card {card}"
            return "PASS", "Found"
        return "FAIL", "Not found"
    except Exception:
        return "FAIL", "aplay error"


def test_speaker():
    """Test speaker output."""
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        card = "0"
        for line in r.stdout.split("\n"):
            if "ES8388" in line or "ES8389" in line:
                card = line.split(":")[0].replace("card", "").strip()
        subprocess.run(["amixer", "-c", card, "sset", "Headphone", "40"], capture_output=True, timeout=2)
        subprocess.run(["amixer", "-c", card, "sset", "DACL", "80%"], capture_output=True, timeout=2)
        subprocess.run(["amixer", "-c", card, "sset", "DACR", "80%"], capture_output=True, timeout=2)
        p = subprocess.Popen(
            ["speaker-test", "-D", f"plughw:CARD=ES8388Audio,DEV=0", "-c", "2", "-t", "sine", "-f", "440", "-l", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.wait(timeout=5)
        return "PASS", "Tone played"
    except subprocess.TimeoutExpired:
        p.kill()
        return "PASS", "Tone played"
    except Exception as e:
        return "FAIL", str(e)[:20]


def test_microphone():
    """Test microphone input."""
    try:
        subprocess.run(["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x01"], capture_output=True, timeout=2)
        subprocess.run(["amixer", "-c", get_audio_card(), "cset", "name=ADC MUX", "0"], capture_output=True, timeout=2)
        subprocess.run(["amixer", "-c", get_audio_card(), "cset", "name=ADCL PGA Volume", "12"], capture_output=True, timeout=2)
        subprocess.run(["amixer", "-c", get_audio_card(), "cset", "name=ADCL Capture Volume", "220"], capture_output=True, timeout=2)
        time.sleep(0.3)

        r = subprocess.run(
            ["arecord", "-D", get_alsa_dev(), "-f", "S16_LE", "-r", "16000", "-c", "1", "-d", "2", "-t", "raw"],
            capture_output=True, timeout=5)
        subprocess.run(["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x03"], capture_output=True, timeout=2)

        if len(r.stdout) > 1000:
            samples = struct.unpack(f"<{len(r.stdout)//2}h", r.stdout)
            rms = math.sqrt(sum(s * s for s in samples) / len(samples))
            if rms > 50:
                return "PASS", f"RMS={rms:.0f}"
            return "WARN", f"Low RMS={rms:.0f}"
        return "FAIL", "No data"
    except Exception as e:
        subprocess.run(["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x03"], capture_output=True, timeout=2)
        return "FAIL", str(e)[:20]


def test_camera():
    """Test IMX219 camera."""
    try:
        r = subprocess.run(["rpicam-hello", "--list-cameras"], capture_output=True, text=True, timeout=5)
        if "imx219" in r.stdout.lower():
            r2 = subprocess.run(
                ["rpicam-still", "-o", "/tmp/hwtest_cam.jpg", "--width", "640", "--height", "480",
                 "-t", "500", "--nopreview", "--rotation", "180"],
                capture_output=True, timeout=10)
            if os.path.isfile("/tmp/hwtest_cam.jpg"):
                sz = os.path.getsize("/tmp/hwtest_cam.jpg")
                os.remove("/tmp/hwtest_cam.jpg")
                return "PASS", f"IMX219 {sz//1024}KB"
            return "WARN", "Detected no capture"
        return "FAIL", "Not detected"
    except Exception as e:
        return "FAIL", str(e)[:20]


def test_wifi():
    """Test WiFi interfaces."""
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=3)
        ifaces = [l.split()[-1] for l in r.stdout.split("\n") if "Interface" in l]
        if ifaces:
            return "PASS", " ".join(ifaces)
        return "FAIL", "No WiFi"
    except Exception:
        return "FAIL", "iw error"


def test_bluetooth():
    """Test Bluetooth."""
    try:
        r = subprocess.run(["hciconfig"], capture_output=True, text=True, timeout=3)
        if "hci0" in r.stdout:
            state = "UP" if "UP" in r.stdout else "DOWN"
            return "PASS" if state == "UP" else "WARN", f"hci0 {state}"
        return "FAIL", "No BT"
    except Exception:
        return "FAIL", "hciconfig error"


def test_usb():
    """Test USB devices."""
    try:
        r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=3)
        devices = [l for l in r.stdout.strip().split("\n") if l]
        return "PASS", f"{len(devices)} devices"
    except Exception:
        return "FAIL", "lsusb error"


def test_gps():
    """Test GPS by reading actual NMEA data."""
    try:
        for dev in ["/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyS0"]:
            if not os.path.exists(dev):
                continue
            r = subprocess.run(
                ["timeout", "3", "cat", dev],
                capture_output=True, timeout=5)
            if b"$GP" in r.stdout or b"$GN" in r.stdout:
                return "PASS", f"{dev} NMEA OK"
        r = subprocess.run(["pgrep", "gpsd"], capture_output=True, timeout=2)
        if r.returncode == 0:
            r2 = subprocess.run(
                ["gpspipe", "-w", "-n", "3"],
                capture_output=True, text=True, timeout=5)
            if "lat" in r2.stdout or "TPV" in r2.stdout:
                return "PASS", "gpsd active"
        return "FAIL", "No GPS data"
    except Exception:
        return "FAIL", "No GPS"


def test_ir():
    """Test IR TX/RX with loopback — TX sends, RX should receive reflection."""
    tx_dev = None
    rx_dev = None
    for dev in ["/dev/lirc0", "/dev/lirc1"]:
        if not os.path.exists(dev):
            continue
        try:
            r = subprocess.run(["ir-ctl", "-d", dev, "--features"],
                               capture_output=True, text=True, timeout=3)
            if "device can send raw" in r.stdout.lower():
                tx_dev = dev
            if "device can receive raw" in r.stdout.lower():
                rx_dev = dev
        except Exception:
            pass

    if not tx_dev and not rx_dev:
        return "FAIL", "No IR driver"

    if not tx_dev or not rx_dev:
        parts = []
        if tx_dev:
            parts.append("TX")
        if rx_dev:
            parts.append("RX")
        return "WARN", f"{'+'.join(parts)} only"

    _draw("HW TEST", [], "Hold paper/hand close", "to IR sensor then OK")
    btn = _wait_btn(15)
    if btn != "OK":
        return "WARN", "Skipped by user"

    _draw("HW TEST", [], "Testing IR loopback...", "Sending + receiving")

    pulse_file = "/tmp/ir_test_pulse"
    with open(pulse_file, "w") as f:
        f.write("carrier 38000\npulse 9000\nspace 4500\n")
        for _ in range(8):
            f.write("pulse 560\nspace 560\n")
        f.write("pulse 560\n")

    rx_proc = subprocess.Popen(
        ["ir-ctl", "-d", rx_dev, "--receive"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    time.sleep(0.3)

    for _ in range(3):
        subprocess.run(["ir-ctl", "-d", tx_dev, f"--send={pulse_file}"],
                       capture_output=True, timeout=2)
        time.sleep(0.2)

    time.sleep(0.5)
    rx_proc.terminate()
    try:
        out, _ = rx_proc.communicate(timeout=2)
    except Exception:
        rx_proc.kill()
        out = b""

    try:
        os.remove(pulse_file)
    except Exception:
        pass

    if b"pulse" in out or b"space" in out or len(out) > 20:
        return "PASS", "TX+RX loopback OK"
    return "FAIL", "TX sent, RX no signal"


def test_ethernet():
    """Test Ethernet interfaces."""
    try:
        ifaces = []
        for name in os.listdir("/sys/class/net"):
            if name.startswith("eth") or name.startswith("enp") or name.startswith("usb"):
                ifaces.append(name)
        if not ifaces:
            return "FAIL", "No ethernet"
        statuses = []
        for iface in ifaces:
            try:
                with open(f"/sys/class/net/{iface}/operstate") as f:
                    state = f.read().strip()
                statuses.append(f"{iface}:{state}")
            except Exception:
                statuses.append(f"{iface}:?")
        return "PASS", " ".join(statuses)
    except Exception:
        return "FAIL", "Error"


def test_backlight():
    """Test LCD backlight control."""
    bl = "/sys/class/backlight/backlight/brightness"
    if not os.path.exists(bl):
        return "FAIL", "No backlight"
    try:
        with open(bl, "r") as f:
            orig = f.read().strip()
        for val in ["20", "100"]:
            with open(bl, "w") as f:
                f.write(val)
            time.sleep(0.3)
        with open(bl, "w") as f:
            f.write(orig)
        return "PASS", f"0-100 range"
    except Exception as e:
        return "FAIL", str(e)[:20]


def test_battery():
    """Test battery/power."""
    try:
        r = subprocess.run(["i2cget", "-f", "-y", "1", "0x55", "0x2c", "w"], capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            return "PASS", "BQ27220 found"
        return "WARN", "No battery IC"
    except Exception:
        return "WARN", "No battery"


def test_storage():
    """Test storage space."""
    try:
        st = os.statvfs("/")
        free_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
        total_gb = (st.f_blocks * st.f_frsize) / (1024 ** 3)
        return "PASS", f"{free_gb:.1f}/{total_gb:.1f}GB free"
    except Exception:
        return "FAIL", "Error"


def test_ram():
    """Test RAM."""
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        total = int(lines[0].split()[1]) // 1024
        avail = int(lines[2].split()[1]) // 1024
        return "PASS", f"{avail}/{total}MB free"
    except Exception:
        return "FAIL", "Error"


def test_network():
    """Test internet connectivity."""
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", "8.8.8.8"], capture_output=True, timeout=5)
        if r.returncode == 0:
            ms = "?"
            for line in r.stdout.decode().split("\n"):
                if "time=" in line:
                    ms = line.split("time=")[1].split()[0]
            return "PASS", f"{ms}ms"
        return "FAIL", "No internet"
    except Exception:
        return "FAIL", "Timeout"


# ─── Main ───

def main():
    global _running

    tests = [
        ("LCD", test_lcd),
        ("Framebuffer", test_framebuffer),
        ("RAM", test_ram),
        ("Storage", test_storage),
        ("I2C Bus", test_i2c),
        ("ES8389", test_es8389),
        ("Speaker", test_speaker),
        ("Microphone", test_microphone),
        ("Camera", test_camera),
        ("WiFi", test_wifi),
        ("Bluetooth", test_bluetooth),
        ("USB", test_usb),
        ("GPS", test_gps),
        ("IR TX/RX", test_ir),
        ("Ethernet", test_ethernet),
        ("Backlight", test_backlight),
        ("Battery", test_battery),
        ("Network", test_network),
        ("Keyboard", test_keyboard),
    ]

    results = []
    passed = 0
    failed = 0
    warned = 0

    test_idx = 0
    scroll = 0

    while test_idx < len(tests) and _running:
        name, test_fn = tests[test_idx]
        _draw("HW TEST", results, f"Next: {name} ({test_idx+1}/{len(tests)})", "OK:Run  KEY3:Skip", scroll)

        while _running:
            btn = _get_btn()
            if btn == "OK":
                break
            if btn == "KEY3":
                results.append((name, "SKIP", "Skipped"))
                test_idx += 1
                break
            if btn == "UP":
                scroll = max(0, scroll - 1)
                _draw("HW TEST", results, f"Next: {name} ({test_idx+1}/{len(tests)})", "OK:Run  KEY3:Skip", scroll)
            if btn == "DOWN":
                scroll = min(max(0, len(results) - 5), scroll + 1)
                _draw("HW TEST", results, f"Next: {name} ({test_idx+1}/{len(tests)})", "OK:Run  KEY3:Skip", scroll)
            time.sleep(0.08)
        else:
            continue

        if btn == "KEY3":
            continue

        _draw("HW TEST", results, f"Testing {name}...", "", scroll)
        try:
            status, detail = test_fn()
        except Exception as e:
            status, detail = "FAIL", str(e)[:20]
        results.append((name, status, detail))
        if status == "PASS":
            passed += 1
        elif status == "FAIL":
            failed += 1
        else:
            warned += 1
        scroll = max(0, len(results) - 8)
        _draw("HW TEST", results, f"{name}: {status} - {detail}", "OK:Next", scroll)
        time.sleep(0.5)
        test_idx += 1

    summary = f"{passed} PASS  {failed} FAIL  {warned} WARN"
    _draw("HW TEST", results, summary, "UP/DN:Scroll OK:Retest K3:Exit", scroll)
    last_btn = 0

    while _running:
        btn = _get_btn()
        now = time.time()
        if btn == "KEY3":
            break
        if btn == "UP" and now - last_btn > 0.15:
            last_btn = now
            scroll = max(0, scroll - 1)
            _draw("HW TEST", results, summary, "UP/DN:Scroll OK:Retest K3:Exit", scroll)
        if btn == "DOWN" and now - last_btn > 0.15:
            last_btn = now
            scroll = min(max(0, len(results) - 5), scroll + 1)
            _draw("HW TEST", results, summary, "UP/DN:Scroll OK:Retest K3:Exit", scroll)
        if btn == "OK" and now - last_btn > 0.3:
            last_btn = now
            # Rerun all tests
            results.clear()
            passed = failed = warned = 0
            scroll = 0
            test_idx = 0
            while test_idx < len(tests) and _running:
                name, test_fn = tests[test_idx]
                _draw("HW TEST", results, f"Next: {name} ({test_idx+1}/{len(tests)})", "OK:Run  KEY3:Skip", scroll)
                while _running:
                    b = _get_btn()
                    if b == "OK":
                        break
                    if b == "KEY3":
                        results.append((name, "SKIP", "Skipped"))
                        test_idx += 1
                        break
                    time.sleep(0.08)
                else:
                    continue
                if b == "KEY3":
                    continue
                _draw("HW TEST", results, f"Testing {name}...", "", scroll)
                try:
                    status, detail = test_fn()
                except Exception as e:
                    status, detail = "FAIL", str(e)[:20]
                results.append((name, status, detail))
                if status == "PASS":
                    passed += 1
                elif status == "FAIL":
                    failed += 1
                else:
                    warned += 1
                scroll = max(0, len(results) - 8)
                _draw("HW TEST", results, f"{name}: {status}", "OK:Next", scroll)
                time.sleep(0.5)
                test_idx += 1
            summary = f"{passed} PASS  {failed} FAIL  {warned} WARN"
            _draw("HW TEST", results, summary, "UP/DN:Scroll OK:Retest K3:Exit", scroll)
        time.sleep(0.1)

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
