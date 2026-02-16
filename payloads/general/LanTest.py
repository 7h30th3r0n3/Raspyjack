#!/usr/bin/env python3
"""
LAN Speed Test (Ethernet-only) – RaspyJack payload
==================================================
Measures LAN throughput using iperf3 against a chosen server. Enforces
Ethernet by requiring the default route device to be an Ethernet interface.

Controls:
  OK     : Start test (Download then Upload)
  KEY1   : Toggle duration (5/10/15s)
  KEY2   : Reload server from loot/speedtest_server.txt
  KEY3   : Exit (cleanup)

Server selection:
  - Reads server IP/hostname from loot/speedtest_server.txt (first line).
  - Falls back to the default gateway IP if file not present.
  - Make sure an iperf3 server runs on that host: `iperf3 -s`.
"""

import os, sys, time, signal, json, subprocess

# Ensure local imports work when launched from payloads/
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button


# --------------------------- Utils ------------------------------------------

def get_default_route() -> tuple[str | None, str | None]:
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "default" and parts[1] == "via":
                gw = parts[2]
                dev = None
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        dev = parts[idx + 1]
                return gw, dev
    except Exception:
        pass
    return None, None


def read_server_from_file(base_dir: str, fallback: str | None) -> str | None:
    path = os.path.join(base_dir, 'loot', 'speedtest_server.txt')
    try:
        if os.path.exists(path):
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        return line
    except Exception:
        pass
    return fallback


def ensure_loot(base_dir: str) -> str:
    loot_dir = os.path.join(base_dir, 'loot')
    os.makedirs(loot_dir, exist_ok=True)
    csv_path = os.path.join(loot_dir, 'speedtest.csv')
    if not os.path.exists(csv_path):
        with open(csv_path, 'w') as f:
            f.write('ts,server,duration_s,download_mbps,upload_mbps\n')
    return csv_path


def iperf3_run(server: str, duration: int, reverse: bool) -> dict | None:
    """Run iperf3 client. reverse=False => upload (client->server), True => download.
    Returns parsed JSON result or None if error.
    """
    cmd = [
        'iperf3', '-c', server, '-J', '-t', str(duration)
    ]
    if reverse:
        cmd.append('-R')
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        return json.loads(out)
    except Exception as e:
        print(f"[speedtest] iperf3 error: {e}")
        return None


def parse_bps(res: dict) -> float | None:
    """Extract bits_per_second from iperf3 JSON (sum_received for download, sum for upload)."""
    try:
        # Try end.sum_received for download tests (-R), fallback to end.sum for upload
        end = res.get('end', {})
        for key in ('sum_received', 'sum_sent', 'sum'):
            block = end.get(key)
            if isinstance(block, dict) and 'bits_per_second' in block:
                return float(block['bits_per_second'])
    except Exception:
        pass
    return None


# --------------------------- LCD + Buttons ----------------------------------

WIDTH, HEIGHT = 128, 128
PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)
def _font(size: int):
    try:
        return ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', size)
    except Exception:
        return ImageFont.load_default()
font_small = _font(8)
font_med = _font(10)
font_big = _font(12)


def btn_pressed() -> str | None:
    return get_button(PINS, GPIO)


def wait_release(btn: str | None) -> None:
    if not btn:
        return
    pin = PINS.get(btn)
    if pin is None:
        return
    try:
        while GPIO.input(pin) == 0:
            time.sleep(0.03)
    except Exception:
        pass


def splash(lines: list[str], color: str = "#AACCFF") -> None:
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    y = 8
    for ln in lines:
        draw.text((4, y), ln[:20], font=font_med, fill=color)
        y += 14
    LCD.LCD_ShowImage(canvas, 0, 0)


def summary(server: str, duration: int, down_mbps: float | None, up_mbps: float | None) -> None:
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    draw.text((4, 4), "LAN Speed Test", font=font_big, fill="#FFFFFF")
    draw.text((4, 22), f"Server: {server[:15]}", font=font_small, fill="#CCCCCC")
    draw.text((4, 34), f"Duration: {duration}s", font=font_small, fill="#CCCCCC")
    dm = f"{down_mbps:.1f} Mbps" if down_mbps is not None else "--"
    um = f"{up_mbps:.1f} Mbps" if up_mbps is not None else "--"
    draw.text((4, 54), f"Download: {dm}", font=font_med, fill="#66FF99")
    draw.text((4, 70), f"Upload:   {um}", font=font_med, fill="#66CCFF")
    draw.text((4, 96), "OK=Run  KEY1=Dur  KEY3=Exit", font=font_small, fill="#AAAAAA")
    LCD.LCD_ShowImage(canvas, 0, 0)


def log_result(csv_path: str, server: str, duration: int, down_mbps: float | None, up_mbps: float | None) -> None:
    try:
        with open(csv_path, 'a') as f:
            ts = int(time.time())
            d = f"{down_mbps:.3f}" if down_mbps is not None else ""
            u = f"{up_mbps:.3f}" if up_mbps is not None else ""
            f.write(f"{ts},{server},{duration},{d},{u}\n")
    except Exception:
        pass


# ---------------------------- Main ------------------------------------------

BASE_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
CSV_PATH = ensure_loot(BASE_DIR)

gw, dev = get_default_route()
server = read_server_from_file(BASE_DIR, gw)
duration = 10

running = True

def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

try:
    # Ethernet-only check
    if not dev or not dev.startswith('eth'):
        splash([
            "Ethernet required",
            f"Route dev: {dev or 'none'}",
            "Plug Ethernet & set",
            "default route via eth*",
            "KEY3 to exit"
        ], color="#FF6666")
        # wait until exit
        while running:
            if btn_pressed() == "KEY3":
                break
            time.sleep(0.1)
    else:
        # Ready screen
        summary(server or "(none)", duration, None, None)

        while running:
            btn = btn_pressed()
            if btn == "KEY3":
                wait_release(btn)
                break
            elif btn == "KEY1":
                duration = {5:10, 10:15, 15:5}[duration]
                summary(server or "(none)", duration, None, None)
                wait_release(btn)
            elif btn == "KEY2":
                server = read_server_from_file(BASE_DIR, gw)
                splash(["Reloaded server:", server or "(none)"])
                time.sleep(1.0)
                summary(server or "(none)", duration, None, None)
                wait_release(btn)
            elif btn == "OK":
                if not server:
                    splash([
                        "No server configured",
                        "Add loot/speedtest_",
                        "server.txt (first line)",
                        "or run iperf3 -s on",
                        "gateway and retry"
                    ], color="#FFCC66")
                    time.sleep(2.0)
                    summary(server or "(none)", duration, None, None)
                    wait_release(btn)
                    continue

                # Download test (reverse)
                splash(["Testing Download…", f"{duration}s to {server}"])
                res_down = iperf3_run(server, duration, reverse=True)
                bps_down = parse_bps(res_down) if res_down else None
                mbps_down = (bps_down / 1e6) if bps_down is not None else None

                # Upload test
                splash(["Testing Upload…", f"{duration}s to {server}"])
                res_up = iperf3_run(server, duration, reverse=False)
                bps_up = parse_bps(res_up) if res_up else None
                mbps_up = (bps_up / 1e6) if bps_up is not None else None

                log_result(CSV_PATH, server, duration, mbps_down, mbps_up)
                summary(server, duration, mbps_down, mbps_up)
                wait_release(btn)

            time.sleep(0.1)

except Exception as exc:
    print(f"[speedtest_lan] ERROR: {exc}")

finally:
    try:
        LCD.LCD_Clear()
    except Exception:
        pass
    GPIO.cleanup()
