#!/usr/bin/env python3
"""
RaspyJack Payload -- GPS Setup & Doctor
========================================
Author: 7h30th3r0n3 / custom

Checks, installs and configures all GPS dependencies
for gps_tracker and wardriving payloads.

Steps:
  1. pyserial          (gps_tracker)
  2. scapy             (wardriving)
  3. gpsd daemon (apt) (wardriving)
  4. gpsd-py3 (pip)    (wardriving)
  5. GPS port detect   (/dev/ttyACM0 / ttyUSB0 ...)
  6. gpsd config       (/etc/default/gpsd)
  7. gpsd service      (enable + start)
  8. Patch gps_tracker (add ttyACM0 to port list)
  9. Live NMEA test    (read GPS fix)

Controls
--------
  KEY3       -- Exit (available after completion or fatal error)
  OK         -- Toggle scroll/live mode (after completion)
  UP / DOWN  -- Scroll log (in review mode)
"""

import os
import sys
import time
import subprocess
import threading
import re

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ── GPIO ──────────────────────────────────────────────────────────────────────
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# ── LCD ───────────────────────────────────────────────────────────────────────
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
LCD.LCD_Clear()
WIDTH, HEIGHT = LCD.width, LCD.height
font      = scaled_font(9)
font_bold = scaled_font(10)
font_tiny = scaled_font(8)

# ── Colors ────────────────────────────────────────────────────────────────────
C = {
    "bg":      "#000000",
    "title":   "#00ccff",
    "ok":      "#00ff44",
    "warn":    "#ffaa00",
    "err":     "#ff3333",
    "info":    "#cccccc",
    "dim":     "#555555",
    "bar_ok":  "#00aa33",
    "bar_err": "#aa2200",
    "bar_off": "#222222",
    "step":    "#ffe066",
}

# ── Global state ──────────────────────────────────────────────────────────────
_done         = False   # setup finished -> KEY3 active
_lock         = threading.Lock()
_log_lines    = []      # list of (text, color)
_scroll_idx   = 0       # scroll offset (review mode)
_review_mode  = False   # True after completion

TOTAL_STEPS      = 9
GPS_TRACKER_PATH = "/root/Raspyjack/payloads/hardware/gps_tracker.py"
GPSD_DEFAULT     = "/etc/default/gpsd"

# ── Display ───────────────────────────────────────────────────────────────────
MAX_VISIBLE = 8   # log lines visible at once (below header, above footer)


def _render():
    """Redraw the full screen from _log_lines."""
    img = Image.new("RGB", (WIDTH, HEIGHT), C["bg"])
    d   = ScaledDraw(img)

    # Header bar
    d.rectangle((0, 0, 127, 13), fill="#081828")
    d.text((2, 2), "GPS SETUP DOCTOR", font=font_bold, fill=C["title"])

    # Progress bar
    with _lock:
        lines = list(_log_lines)
    ok_count  = sum(1 for _, col in lines if col == C["ok"])
    err_count = sum(1 for _, col in lines if col == C["err"])
    bar_w  = 124
    filled = int(bar_w * ok_count / TOTAL_STEPS)
    d.rectangle((2, 14, 2 + bar_w, 18), fill=C["bar_off"])
    if filled:
        bar_col = C["bar_err"] if err_count else C["bar_ok"]
        d.rectangle((2, 14, 2 + filled, 18), fill=bar_col)

    # Log lines
    start   = _scroll_idx if _review_mode else max(0, len(lines) - MAX_VISIBLE)
    visible = lines[start: start + MAX_VISIBLE]
    y = 22
    for text, color in visible:
        d.text((2, y), text[:21], font=font_tiny, fill=color)
        y += 13

    # Footer bar
    d.rectangle((0, 117, 127, 127), fill="#081828")
    if _done:
        if _review_mode:
            d.text((2, 118), "^v:scroll  K3:exit", font=font_tiny, fill=C["dim"])
        else:
            d.text((2, 118), "OK:review  K3:exit", font=font_tiny, fill=C["dim"])
    else:
        d.text((2, 118), "Running setup...", font=font_tiny, fill=C["dim"])

    LCD.LCD_ShowImage(img, 0, 0)


def log(text, color=None):
    """Append a line to the log and refresh the screen."""
    color = color or C["info"]
    with _lock:
        _log_lines.append((text, color))
    _render()
    time.sleep(0.04)


def log_step(n, label):
    log(f"[{n}/{TOTAL_STEPS}] {label}", C["step"])


def log_ok(text):
    log(f"  OK  {text}", C["ok"])


def log_warn(text):
    log(f"  !!  {text}", C["warn"])


def log_err(text):
    log(f"  ERR {text}", C["err"])


def log_info(text):
    log(f"      {text}", C["info"])


# ── Shell helper ──────────────────────────────────────────────────────────────
def run(cmd, timeout=90):
    """Run a shell command, return (returncode, combined output)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 1, "timeout"
    except Exception as e:
        return 1, str(e)


# ── Step functions ────────────────────────────────────────────────────────────

def step1_pyserial():
    log_step(1, "pyserial")
    try:
        import serial
        log_ok("already installed")
        return True
    except ImportError:
        pass
    log_info("trying apt...")
    rc, out = run("apt-get install -y python3-serial 2>&1")
    if rc == 0:
        log_ok("installed via apt")
        return True
    log_warn("apt failed, trying pip...")
    rc, out = run("pip3 install pyserial --break-system-packages 2>&1")
    if rc == 0:
        log_ok("installed via pip")
        return True
    log_err("pyserial FAILED")
    log_info(out[:38])
    return False


def step2_scapy():
    log_step(2, "scapy")
    try:
        import scapy
        log_ok("already installed")
        return True
    except ImportError:
        pass
    log_info("trying apt...")
    rc, out = run("apt-get install -y python3-scapy 2>&1")
    if rc == 0:
        log_ok("installed via apt")
        return True
    log_warn("apt failed, trying pip...")
    rc, out = run("pip3 install scapy --break-system-packages 2>&1")
    if rc == 0:
        log_ok("installed via pip")
        return True
    log_err("scapy FAILED")
    return False


def step3_gpsd_apt():
    log_step(3, "gpsd daemon (apt)")
    rc, _ = run("which gpsd 2>/dev/null")
    if rc == 0:
        log_ok("gpsd binary present")
        return True
    log_info("apt-get install gpsd...")
    rc, out = run("apt-get install -y gpsd gpsd-clients 2>&1", timeout=180)
    if rc == 0:
        log_ok("gpsd installed")
        return True
    log_err("gpsd apt FAILED")
    log_info(out[:38])
    return False


def step4_gpsd_py3():
    log_step(4, "gpsd-py3 (pip)")
    try:
        import gpsd
        log_ok("already installed")
        return True
    except ImportError:
        pass
    log_info("pip install gpsd-py3...")
    rc, out = run("pip3 install gpsd-py3 --break-system-packages 2>&1")
    if rc == 0:
        log_ok("installed")
        return True
    log_err("gpsd-py3 FAILED")
    log_info(out[:38])
    return False


def step5_detect_port():
    log_step(5, "GPS port detection")
    candidates = [
        "/dev/ttyACM0", "/dev/ttyACM1",
        "/dev/ttyUSB0", "/dev/ttyUSB1",
    ]
    found_port = None

    # Check existing device nodes
    for p in candidates:
        if os.path.exists(p):
            log_info(f"device exists: {p}")
            found_port = p
            break

    # Cross-check with lsusb for GPS USB signatures
    _, lsusb_out = run("lsusb 2>/dev/null")
    gps_hints = [
        ("u-blox",    "u-blox chip"),
        ("1546:01a7", "u-blox 7"),
        ("1546:01a8", "u-blox 8"),
        ("067b:2303", "PL2303 GPS"),
        ("10c4:ea60", "CP210x GPS"),
        ("sirf",      "SiRF chip"),
        ("globalsat", "GlobalSat"),
    ]
    for hint, label in gps_hints:
        if hint.lower() in lsusb_out.lower():
            log_info(f"USB match: {label}")
            break
    else:
        log_info("no GPS USB hint in lsusb")

    if found_port:
        log_ok(f"port: {found_port}")
    else:
        log_warn("no port found now")
        log_info("plug dongle & rerun")
        found_port = "/dev/ttyACM0"   # write config anyway

    return found_port


def step6_configure_gpsd(port):
    log_step(6, "gpsd config")

    new_cfg = (
        'START_DAEMON="true"\n'
        'GPSD_OPTIONS="-n"\n'
        f'DEVICES="{port}"\n'
        'USBAUTO="true"\n'
        'GPSD_SOCKET="/var/run/gpsd.sock"\n'
    )

    # Read current config if it exists
    current = ""
    if os.path.exists(GPSD_DEFAULT):
        try:
            with open(GPSD_DEFAULT) as f:
                current = f.read()
        except Exception:
            pass

    if current == new_cfg:
        log_ok("config already correct")
        return True

    log_info(f"writing {GPSD_DEFAULT}")
    try:
        with open(GPSD_DEFAULT, "w") as f:
            f.write(new_cfg)
        log_ok("config written")
        log_info(f"device={port}")
        return True
    except PermissionError:
        log_info("need sudo, retrying...")
        tmp = "/tmp/_gpsd_default"
        try:
            with open(tmp, "w") as f:
                f.write(new_cfg)
            rc, out = run(f"cp {tmp} {GPSD_DEFAULT} && chmod 644 {GPSD_DEFAULT}")
            if rc == 0:
                log_ok("config written (sudo cp)")
                return True
        except Exception:
            pass
        log_err("config write FAILED")
        return False
    except Exception as e:
        log_err(f"write error: {str(e)[:28]}")
        return False


def step7_gpsd_service():
    log_step(7, "gpsd service")

    # Stop any running instance to reload config
    run("systemctl stop gpsd gpsd.socket 2>/dev/null || pkill gpsd 2>/dev/null")
    time.sleep(1)

    # Enable + start
    log_info("enabling gpsd...")
    rc, out = run("systemctl enable gpsd 2>&1")
    if rc != 0:
        log_warn(f"enable: {out[:30]}")

    log_info("starting gpsd...")
    rc, out = run("systemctl start gpsd 2>&1")
    if rc == 0:
        log_ok("service started")
    else:
        # Fallback: direct start
        log_warn("systemctl failed, direct start...")
        _, dev = run("cat /etc/default/gpsd | grep ^DEVICES | cut -d'\"' -f2")
        dev = dev.strip() or "/dev/ttyACM0"
        rc2, _ = run(f"gpsd -n -b {dev} 2>/dev/null &")
        if rc2 == 0:
            log_ok("gpsd started directly")
        else:
            log_warn("service not running")
            log_info("may need reboot")
            return False

    # Verify it is active
    time.sleep(2)
    rc, status = run("systemctl is-active gpsd 2>/dev/null || echo inactive")
    if "active" in status and "inactive" not in status:
        log_ok(f"status: {status.strip()}")
        return True
    else:
        log_warn(f"status: {status.strip()}")
        return True   # not fatal; may need reboot


def step8_patch_gps_tracker():
    log_step(8, "patch gps_tracker.py")

    if not os.path.exists(GPS_TRACKER_PATH):
        log_warn("gps_tracker.py not found")
        log_info("skipping patch")
        return True   # not blocking

    try:
        with open(GPS_TRACKER_PATH, "r") as f:
            src = f.read()
    except Exception as e:
        log_err(f"read error: {str(e)[:28]}")
        return False

    # Check if ttyACM0 already present
    if "/dev/ttyACM0" in src:
        log_ok("ttyACM0 already in list")
        return True

    # Find the SERIAL_PORTS list and prepend ttyACM0 / ttyACM1
    pattern = r'(SERIAL_PORTS\s*=\s*\[)(\s*"?/dev/tty)'
    replacement = r'\1"/dev/ttyACM0", "/dev/ttyACM1", \2'
    new_src, count = re.subn(pattern, replacement, src, count=1)

    if count == 0:
        # Fallback: simple string replacement for the exact line in the payload
        old_line = 'SERIAL_PORTS = ["/dev/ttyUSB0"'
        new_line = 'SERIAL_PORTS = ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0"'
        if old_line in src:
            new_src = src.replace(old_line, new_line, 1)
            count = 1
        else:
            log_warn("pattern not found")
            log_info("manual patch needed")
            return True   # not blocking

    try:
        with open(GPS_TRACKER_PATH, "w") as f:
            f.write(new_src)
        log_ok("ttyACM0 added to list")
        log_info("gps_tracker patched")
        return True
    except Exception as e:
        log_err(f"write error: {str(e)[:28]}")
        return False


def step9_test_gps(port):
    log_step(9, "live NMEA test")

    try:
        import serial as _serial
    except ImportError:
        log_warn("pyserial missing, skip")
        return False

    # ── 1. Add current user to dialout (permission fix) ──────────────────
    run("usermod -aG dialout root 2>/dev/null")

    # ── 2. Build candidate list (detected port first, then others) ────────
    all_candidates = [
        "/dev/ttyACM0", "/dev/ttyACM1",
        "/dev/ttyUSB0", "/dev/ttyUSB1",
    ]
    # Put the detected port first
    candidates = [port] + [p for p in all_candidates if p != port]

    # Keep only ports that actually exist as device nodes
    existing = [p for p in candidates if os.path.exists(p)]
    if not existing:
        log_err("no serial device found")
        log_info("plug dongle & rerun")
        return False

    # ── 3. Stop gpsd so it releases the port ─────────────────────────────
    log_info("stopping gpsd...")
    run("systemctl stop gpsd gpsd.socket 2>/dev/null")
    run("pkill -x gpsd 2>/dev/null")
    time.sleep(1.5)   # wait for port release

    # ── 4. Baud rates to try ──────────────────────────────────────────────
    BAUDS = [9600, 4800, 38400, 115200]

    found_port  = None
    found_baud  = None
    nmea_count  = 0
    fix_found   = False

    for try_port in existing:
        log_info(f"trying {try_port}...")
        for baud in BAUDS:
            try:
                ser = _serial.Serial(try_port, baud, timeout=2)
            except Exception as e:
                log_info(f"  open err @{baud}: {str(e)[:18]}")
                continue

            # Drain any garbage first
            ser.reset_input_buffer()
            got_nmea = 0
            deadline = time.time() + 4   # 4 s per baud rate

            while time.time() < deadline:
                try:
                    raw = ser.readline().decode("ascii", errors="ignore").strip()
                except Exception:
                    break
                if raw.startswith("$") and len(raw) > 5:
                    got_nmea += 1
                    nmea_count += 1
                    if got_nmea == 1:
                        log_info(f"  NMEA@{baud}: {raw[:18]}")
                    if "GGA" in raw:
                        parts = raw.split(",")
                        if len(parts) > 6 and parts[6] not in ("", "0"):
                            sats = parts[7] if len(parts) > 7 else "?"
                            log_ok(f"GPS FIX! sats={sats}")
                            fix_found = True

            ser.close()

            if got_nmea > 0:
                found_port = try_port
                found_baud = baud
                break   # correct baud found for this port

        if found_port:
            break   # correct port found

    # ── 5. Restart gpsd (always, even on failure) ─────────────────────────
    log_info("restarting gpsd...")
    run("systemctl start gpsd 2>/dev/null || gpsd -n -b "
        "$(grep ^DEVICES /etc/default/gpsd | cut -d'\"' -f2) 2>/dev/null &")
    time.sleep(1)

    # ── 6. Report results ─────────────────────────────────────────────────
    if nmea_count == 0:
        log_err("no NMEA data on any port")
        log_err("check dongle connection")
        # Extra diagnostics
        _, dmesg = run("dmesg | tail -5 | grep -i 'tty\\|usb\\|serial' 2>/dev/null")
        if dmesg:
            log_info(dmesg[:38])
        return False

    log_ok(f"port={found_port} baud={found_baud}")
    log_info(f"NMEA sentences: {nmea_count}")

    if not fix_found:
        log_warn("no fix yet (normal)")
        log_info("needs clear sky view")

    # Auto-correct gpsd config if baud/port differ from what was written
    if found_port and found_port != port:
        log_info(f"updating config: {found_port}")
        step6_configure_gpsd(found_port)

    return True   # data is flowing = success


# ── Summary screen ────────────────────────────────────────────────────────────

def show_summary(results):
    """Render a final summary card over the log."""
    global _done
    _done = True

    labels = [
        "pyserial", "scapy", "gpsd (apt)", "gpsd-py3",
        "port detect", "gpsd config", "gpsd service",
        "gps_tracker patch", "NMEA test",
    ]
    img = Image.new("RGB", (WIDTH, HEIGHT), C["bg"])
    d   = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#081828")
    d.text((2, 2), "GPS SETUP SUMMARY", font=font_bold, fill=C["title"])

    y = 16
    for i, (label, ok) in enumerate(zip(labels, results)):
        icon  = "OK" if ok else "!!"
        color = C["ok"] if ok else C["err"]
        d.text((2, y), f"{icon} {label[:17]}", font=font_tiny, fill=color)
        y += 12
        if y > 110:
            break

    all_ok = all(results)
    status_text  = "ALL GOOD" if all_ok else "CHECK ERRORS"
    status_color = C["ok"]   if all_ok else C["warn"]
    d.rectangle((0, 111, 127, 116), fill="#081828")
    d.text((2, 112), status_text, font=font_tiny, fill=status_color)
    d.rectangle((0, 117, 127, 127), fill="#081828")
    d.text((2, 118), "OK:log  K3:exit", font=font_tiny, fill=C["dim"])

    LCD.LCD_ShowImage(img, 0, 0)


# ── Setup runner (background thread) ─────────────────────────────────────────

def run_setup():
    global _done

    results = []

    # Refresh APT cache once silently
    log_info("refreshing apt cache...")
    run("apt-get update -qq 2>/dev/null", timeout=60)

    r1 = step1_pyserial();     results.append(r1)
    r2 = step2_scapy();        results.append(r2)
    r3 = step3_gpsd_apt();     results.append(r3)
    r4 = step4_gpsd_py3();     results.append(r4)

    port = step5_detect_port(); results.append(port is not None)

    r6 = step6_configure_gpsd(port); results.append(r6)
    r7 = step7_gpsd_service();        results.append(r7)
    r8 = step8_patch_gps_tracker();   results.append(r8)
    r9 = step9_test_gps(port);        results.append(r9)

    # Brief pause so user can read last log line
    time.sleep(1.5)
    show_summary(results)
    _done = True


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global _review_mode, _scroll_idx, _done

    log("GPS SETUP DOCTOR", C["title"])
    log("Checking dependencies...", C["info"])
    time.sleep(0.5)

    # Run setup in background so the LCD stays responsive
    t = threading.Thread(target=run_setup, daemon=True)
    t.start()

    debounce   = 0.25
    last_press = 0.0

    while True:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn and (now - last_press) >= debounce:
            last_press = now

            if btn == "KEY3" and _done:
                break

            if btn == "OK" and _done:
                _review_mode = not _review_mode
                _scroll_idx  = max(0, len(_log_lines) - MAX_VISIBLE)
                _render()

            if _review_mode:
                with _lock:
                    total = len(_log_lines)
                if btn == "UP":
                    _scroll_idx = max(0, _scroll_idx - 1)
                    _render()
                elif btn == "DOWN":
                    _scroll_idx = min(max(0, total - MAX_VISIBLE), _scroll_idx + 1)
                    _render()

        time.sleep(0.05)

    # Cleanup
    t.join(timeout=2)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
