#!/usr/bin/env python3
"""
WAN Speed Test – RaspyJack payload
==================================
Measures internet (WAN) download/upload using Speedtest. Prefers the Python
speedtest module; falls back to the Ookla CLI (JSON). Works over whichever
interface has the default route (Ethernet or Wi‑Fi).

Controls:
  OK     : Start test (Download then Upload)
  KEY1   : Toggle single-connection mode (on/off)
  KEY3   : Exit (cleanup)

Logging:
  loot/speedtest_wan.csv – ts, isp, server, location, ping_ms, jitter_ms,
                           download_mbps, upload_mbps, packet_loss_pct, single
"""

import os, sys, time, signal, json, subprocess, shutil

# Ensure local imports when launched from payloads/
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button


# --------------------------- Backends ---------------------------------------

def run_speedtest_python(single: bool) -> dict | None:
    """Run via python speedtest module (speedtest-cli). Returns normalized dict or None."""
    try:
        import speedtest
    except Exception:
        return None

    try:
        s = speedtest.Speedtest()
        s.get_servers()            # find candidate servers
        best = s.get_best_server() # pick best by latency
        dl = s.download(threads=1 if single else None)
        ul = s.upload(threads=1 if single else None)
        res = s.results.dict()

        server = res.get('server', {})
        isp = res.get('client', {}).get('isp') or res.get('client', {}).get('isp_name')
        server_name = server.get('name') or server.get('sponsor')
        location = server.get('country') or server.get('host')

        return {
            'download_mbps': (res.get('download') or 0) / 1e6,
            'upload_mbps'  : (res.get('upload') or 0) / 1e6,
            'ping_ms'      : float(res.get('ping') or 0.0),
            'jitter_ms'    : None,
            'packet_loss_pct': None,
            'server_name'  : server_name,
            'server_location': location,
            'isp'          : isp,
        }
    except Exception as e:
        print(f"[speedtest_wan] python backend error: {e}")
        return None


def run_speedtest_ookla_cli(single: bool) -> dict | None:
    """Run via Ookla CLI. Returns normalized dict or None."""
    # Try modern flags first, then legacy
    cmds = [
        ['speedtest', '--accept-license', '--accept-gdpr', '--format=json'],
        ['speedtest', '--accept-license', '--accept-gdpr', '-f', 'json'],
        ['speedtest-cli', '--json']
    ]
    # single connection (where supported): speedtest doesn't have a simple flag; skip.

    for cmd in cmds:
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
            data = json.loads(out)

            # Ookla CLI JSON
            if 'type' in data and 'download' in data and 'upload' in data:
                dl_bw = float(data.get('download', {}).get('bandwidth') or 0.0)  # bytes/s
                ul_bw = float(data.get('upload', {}).get('bandwidth') or 0.0)
                ping = data.get('ping', {})
                server = data.get('server', {})
                return {
                    'download_mbps': (dl_bw * 8.0) / 1e6,
                    'upload_mbps'  : (ul_bw * 8.0) / 1e6,
                    'ping_ms'      : float(ping.get('latency') or 0.0),
                    'jitter_ms'    : float(ping.get('jitter') or 0.0) if 'jitter' in ping else None,
                    'packet_loss_pct': float(data.get('packetLoss')) if isinstance(data.get('packetLoss'), (int,float)) else None,
                    'server_name'  : server.get('name'),
                    'server_location': server.get('location') or server.get('country'),
                    'isp'          : data.get('isp'),
                }

            # Legacy speedtest-cli JSON
            if 'download' in data and 'upload' in data and 'server' in data:
                server = data.get('server', {})
                return {
                    'download_mbps': float(data.get('download') or 0) / 1e6,
                    'upload_mbps'  : float(data.get('upload') or 0) / 1e6,
                    'ping_ms'      : float(data.get('ping') or 0.0),
                    'jitter_ms'    : None,
                    'packet_loss_pct': None,
                    'server_name'  : server.get('name') or server.get('sponsor'),
                    'server_location': server.get('country') or server.get('host'),
                    'isp'          : data.get('client', {}).get('isp'),
                }
        except Exception as e:
            # try next
            last_err = e
            continue
    print(f"[speedtest_wan] CLI backend unavailable or failed: {last_err}")
    return None


def run_speedtest(single: bool) -> dict | None:
    res = run_speedtest_python(single)
    if res:
        return res
    return run_speedtest_ookla_cli(single)


# ------------------------ Auto-install helpers (apt) ------------------------

def _cmd_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def ensure_speedtest_cli_installed(show_progress) -> bool:
    """Ensure a CLI backend exists via apt (speedtest-cli). Returns True if available."""
    # If either 'speedtest' (Ookla) or 'speedtest-cli' exists, we're good
    if _cmd_exists('speedtest') or _cmd_exists('speedtest-cli'):
        return True

    # Show installing splash
    show_progress(["Installing", "speedtest-cli…", "This may take", "a minute…"])
    try:
        # Non-interactive apt install
        env = os.environ.copy()
        env['DEBIAN_FRONTEND'] = 'noninteractive'
        subprocess.check_call(['apt-get', 'update', '-y', '-qq'], env=env)
        subprocess.check_call(['apt-get', 'install', '-y', '-qq', 'speedtest-cli'], env=env)
    except Exception as e:
        print(f"[speedtest_wan] apt install failed: {e}")
        return _cmd_exists('speedtest') or _cmd_exists('speedtest-cli')

    return _cmd_exists('speedtest') or _cmd_exists('speedtest-cli')


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
font_med   = _font(10)
font_big   = _font(12)


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


def installing_splash(lines: list[str]) -> None:
    # Alias to reuse in ensure_speedtest_cli_installed()
    splash(lines, color="#FFCC66")


def summary(single: bool, res: dict | None = None) -> None:
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    draw.text((4, 4), "WAN Speed Test", font=font_big, fill="#FFFFFF")
    draw.text((4, 20), f"Mode: {'Single' if single else 'Multi'}", font=font_small, fill="#CCCCCC")
    if res:
        isp = res.get('isp') or ""
        srv = res.get('server_name') or ""
        loc = res.get('server_location') or ""
        draw.text((4, 34), f"ISP: {isp[:16]}", font=font_small, fill="#CCCCCC")
        draw.text((4, 46), f"Srv: {srv[:16]}", font=font_small, fill="#CCCCCC")
        draw.text((4, 58), f"Loc: {loc[:16]}", font=font_small, fill="#CCCCCC")

        ping = res.get('ping_ms'); jit = res.get('jitter_ms')
        draw.text((4, 74), f"Ping: {ping:.0f} ms  J:{(jit or 0):.0f}", font=font_med, fill="#FFEE66")
        draw.text((4, 90), f"Down: {res.get('download_mbps'):.1f} Mbps", font=font_med, fill="#66FF99")
        draw.text((4, 106), f"Up:   {res.get('upload_mbps'):.1f} Mbps", font=font_med, fill="#66CCFF")
    else:
        draw.text((4, 46), "OK=Run  KEY1=Mode  KEY3=Exit", font=font_small, fill="#AAAAAA")
    LCD.LCD_ShowImage(canvas, 0, 0)


# ---------------------------- Logging ----------------------------------------

BASE_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
CSV_PATH = os.path.join(BASE_DIR, 'loot', 'speedtest_wan.csv')
os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
if not os.path.exists(CSV_PATH):
    with open(CSV_PATH, 'w') as f:
        f.write('ts,isp,server,location,ping_ms,jitter_ms,download_mbps,upload_mbps,packet_loss_pct,single\n')


def log_result(single: bool, res: dict | None) -> None:
    try:
        with open(CSV_PATH, 'a') as f:
            ts = int(time.time())
            if not res:
                f.write(f"{ts},,,,,,,,{int(single)}\n")
                return
            f.write(
                f"{ts},{(res.get('isp') or '')},{(res.get('server_name') or '')},"
                f"{(res.get('server_location') or '')},{res.get('ping_ms') or ''},"
                f"{res.get('jitter_ms') or ''},{res.get('download_mbps') or ''},"
                f"{res.get('upload_mbps') or ''},{res.get('packet_loss_pct') or ''},{int(single)}\n"
            )
    except Exception:
        pass


# ---------------------------- Main ------------------------------------------

running = True
single = False
last = None


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

try:
    summary(single, None)

    while running:
        btn = btn_pressed()
        if btn == "KEY3":
            wait_release(btn)
            break
        elif btn == "KEY1":
            single = not single
            summary(single, last)
            wait_release(btn)
        elif btn == "OK":
            # Ensure a CLI backend is present if Python backend isn't
            # (We avoid pip; prefer apt-installed speedtest-cli)
            if not _cmd_exists('speedtest') and not _cmd_exists('speedtest-cli'):
                ok = ensure_speedtest_cli_installed(installing_splash)
                if not ok:
                    splash(["Install failed", "speedtest-cli not found", "Check network/apt"]) 
                    time.sleep(1.8)
                    wait_release(btn)
                    continue

            splash(["Testing…", "Selecting server…"]) 
            res = run_speedtest(single)
            if not res:
                splash(["Speedtest failed", "Check internet/CLI"]) 
                time.sleep(1.8)
            else:
                last = res
                log_result(single, res)
                summary(single, last)
            wait_release(btn)
        time.sleep(0.1)

except Exception as exc:
    print(f"[speedtest_wan] ERROR: {exc}")

finally:
    try:
        LCD.LCD_Clear()
    except Exception:
        pass
    GPIO.cleanup()
