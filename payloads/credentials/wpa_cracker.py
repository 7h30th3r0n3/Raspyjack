#!/usr/bin/env python3
"""
RaspyJack Payload -- WPA/WPA2 Cracker
======================================
Author: 7h30th3r0n3

Cracks WPA handshakes (.cap) using aircrack-ng and PMKID hashes
using John the Ripper. Scans loot directories for crack targets.

Setup / Prerequisites:
  - Requires aircrack-ng for .cap handshake files.
  - Requires john for PMKID hash cracking.
  - Optional wordlists: /root/Raspyjack/loot/wordlists/rockyou.txt,
    custom.txt

Controls:
  OK         -- Select file / start cracking
  UP / DOWN  -- Scroll file list / wordlists
  KEY1       -- Stop current crack
  KEY2       -- Export cracked results to loot
  KEY3       -- Exit (kills cracking process)

Loot: /root/Raspyjack/loot/CrackedWPA/
"""

import os
import sys
import re
import time
import signal
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
AIRCRACK_BIN = "/usr/bin/aircrack-ng"
HASHCAT_BIN = "/usr/bin/hashcat"
HCXPCAPNGTOOL_BIN = "/usr/bin/hcxpcapngtool"
JOHN_BIN = "/usr/sbin/john"
WORDLIST_DIR = "/root/Raspyjack/loot/wordlists"
SYSTEM_WORDLIST = "/usr/share/john/password.lst"
HANDSHAKE_DIRS = [
    "/root/Raspyjack/loot/Handshakes",
    "/root/Raspyjack/loot/Pwnagotchi/handshakes",
]
PMKID_DIR = "/root/Raspyjack/loot/PMKID"
LOOT_DIR = "/root/Raspyjack/loot/CrackedWPA"
ROWS_VISIBLE = 6
ROW_H = 12

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
target_files = []       # [{path, name, ftype, size_kb}]
wordlists = []          # [{name, path}] built dynamically
scroll_pos = 0
selected_idx = 0
phase = "files"         # files | wordlist | cracking | results
wl_idx = 0
status_msg = "Scanning for targets..."
keys_tested = 0
speed_kps = ""
elapsed_secs = 0
found_key = ""
_running = True
_crack_proc = None


# ---------------------------------------------------------------------------
# Target file discovery
# ---------------------------------------------------------------------------

def _file_size_kb(filepath):
    """Return file size in KB."""
    try:
        return os.path.getsize(filepath) // 1024
    except Exception:
        return 0


def _scan_targets():
    """Scan for .cap/.pcap handshake files and PMKID hash files."""
    found = []
    seen = set()

    # Handshake .cap / .pcap files from all known directories
    for hs_dir in HANDSHAKE_DIRS:
        if not os.path.isdir(hs_dir):
            continue
        try:
            for fname in sorted(os.listdir(hs_dir)):
                fpath = os.path.join(hs_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                low = fname.lower()
                if low.endswith(".cap") or low.endswith(".pcap"):
                    if fpath not in seen:
                        seen.add(fpath)
                        ftype = "PMKID" if fname.startswith("pmkid_") else "CAP"
                        found.append({
                            "path": fpath,
                            "name": fname,
                            "ftype": ftype,
                            "size_kb": _file_size_kb(fpath),
                        })
        except Exception:
            pass

    # PMKID hash files
    if os.path.isdir(PMKID_DIR):
        try:
            for fname in sorted(os.listdir(PMKID_DIR)):
                fpath = os.path.join(PMKID_DIR, fname)
                if not os.path.isfile(fpath):
                    continue
                if fname.lower().endswith(".txt"):
                    found.append({
                        "path": fpath,
                        "name": fname,
                        "ftype": "PMKID",
                        "size_kb": _file_size_kb(fpath),
                    })
        except Exception:
            pass

    return found


def _build_wordlist_options():
    """Build available wordlist options from loot/wordlists/ and system."""
    options = []

    # Scan project wordlists directory
    if os.path.isdir(WORDLIST_DIR):
        try:
            for fname in sorted(os.listdir(WORDLIST_DIR)):
                fpath = os.path.join(WORDLIST_DIR, fname)
                if not os.path.isfile(fpath):
                    continue
                low = fname.lower()
                if low.endswith(".txt") or low.endswith(".lst"):
                    name = os.path.splitext(fname)[0][:14]
                    options.append({"name": name, "path": fpath})
        except Exception:
            pass

    # System wordlist as fallback
    if os.path.isfile(SYSTEM_WORDLIST):
        options.append({"name": "john_default", "path": SYSTEM_WORDLIST})

    if not options:
        options.append({"name": "john_default", "path": SYSTEM_WORDLIST})
    return options


# ---------------------------------------------------------------------------
# Aircrack-ng output parsing
# ---------------------------------------------------------------------------

# Pattern: [00:01:23] 12345/67890 keys tested (2456.78 k/s)
_AIRCRACK_PROGRESS_RE = re.compile(
    r"\[\d+:\d+:\d+\]\s+([\d,]+)(?:/[\d,]+)?\s+keys?\s+tested\s+\(([^\)]+)\)"
)
# Pattern: KEY FOUND! [ password123 ]
_AIRCRACK_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")


# ---------------------------------------------------------------------------
# Cracking threads
# ---------------------------------------------------------------------------

def _extract_essid_from_filename(fname):
    """Extract ESSID from capture filename.

    Filenames follow patterns like:
      hs_{essid}_{date}.pcap
      hs4_{essid}_{date}.pcap
      hs_half_{essid}_{date}.pcap
      pmkid_{essid}_{date}.pcap
    """
    base = os.path.splitext(os.path.basename(fname))[0]
    # Remove prefix (hs_, hs4_, hs_half_, pmkid_)
    for prefix in ("hs_half_", "hs4_", "hs_", "pmkid_"):
        if base.startswith(prefix):
            rest = base[len(prefix):]
            # Remove trailing _YYYYMMDD_HHMMSS
            parts = rest.rsplit("_", 2)
            if len(parts) >= 3 and len(parts[-1]) == 6 and len(parts[-2]) == 8:
                return "_".join(parts[:-2])
            if len(parts) >= 2 and len(parts[-1]) == 8:
                return "_".join(parts[:-1])
            return rest
    return ""


def _crack_cap_thread(capfile, wordlist_path):
    """Crack a .cap handshake file using aircrack-ng."""
    global _crack_proc, keys_tested, speed_kps, elapsed_secs
    global found_key, phase, status_msg, _running

    start_time = time.time()
    with lock:
        keys_tested = 0
        speed_kps = ""
        elapsed_secs = 0
        found_key = ""
        status_msg = "Starting aircrack-ng..."

    # Try without -e first (beacon in pcap provides ESSID)
    # Only use -e as fallback for old captures without beacon
    cmd = [AIRCRACK_BIN, "-w", wordlist_path, capfile]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _crack_proc = proc

        while _running:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if not line:
                continue

            line = line.rstrip()
            with lock:
                elapsed_secs = int(time.time() - start_time)

            # Check for key found
            key_match = _AIRCRACK_KEY_RE.search(line)
            if key_match:
                with lock:
                    found_key = key_match.group(1)
                    status_msg = "KEY FOUND!"
                continue

            # Check for progress
            progress_match = _AIRCRACK_PROGRESS_RE.search(line)
            if progress_match:
                raw_keys = progress_match.group(1).replace(",", "")
                with lock:
                    try:
                        keys_tested = int(raw_keys)
                    except ValueError:
                        pass
                    speed_kps = progress_match.group(2).strip()
                    status_msg = "Cracking..."

        proc.wait(timeout=5)

    except Exception as exc:
        with lock:
            status_msg = f"Error: {str(exc)[:18]}"
    finally:
        _crack_proc = None
        with lock:
            elapsed_secs = int(time.time() - start_time)
            if phase == "cracking":
                phase = "results"
                if found_key:
                    status_msg = "KEY FOUND!"
                else:
                    status_msg = "Done. Key not found"


def _crack_pmkid_thread(pmkid_file, wordlist_path):
    """Crack PMKID pcap using hcxpcapngtool + hashcat.

    1. Convert .pcap to hashcat 22000 format via hcxpcapngtool
    2. Run hashcat -m 22000 with the wordlist
    """
    global _crack_proc, keys_tested, speed_kps, elapsed_secs
    global found_key, phase, status_msg, _running

    start_time = time.time()
    with lock:
        keys_tested = 0
        speed_kps = ""
        elapsed_secs = 0
        found_key = ""
        status_msg = "Converting PMKID..."

    # Step 1: convert pcap to hashcat 22000 format
    hash_file = pmkid_file + ".22000"
    try:
        conv = subprocess.run(
            [HCXPCAPNGTOOL_BIN, "-o", hash_file, pmkid_file],
            capture_output=True, text=True, timeout=30,
        )
        if not os.path.isfile(hash_file) or os.path.getsize(hash_file) == 0:
            with lock:
                status_msg = "No valid PMKID in file"
                phase = "results"
            return
    except Exception as exc:
        with lock:
            status_msg = f"Convert err: {str(exc)[:14]}"
            phase = "results"
        return

    with lock:
        status_msg = "Cracking PMKID..."

    # Step 2: run hashcat
    cmd = [
        HASHCAT_BIN, "-m", "22000", "-a", "0",
        "--potfile-disable", "--force",
        hash_file, wordlist_path,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _crack_proc = proc

        # hashcat progress: "Progress.........: 12345/67890 (18.17%)"
        progress_re = re.compile(r"Progress.*?:\s*([\d]+)/(\d+)")
        # hashcat speed: "Speed.#1.........:   123.4 kH/s"
        speed_re = re.compile(r"Speed.*?:\s+(.+?)$")
        # hashcat cracked: "hash:password" or shown in status
        cracked_re = re.compile(r"^([0-9a-f*:]+):(.+)$", re.IGNORECASE)

        while _running:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if not line:
                continue

            line = line.rstrip()
            with lock:
                elapsed_secs = int(time.time() - start_time)

            m = cracked_re.match(line)
            if m:
                with lock:
                    found_key = m.group(2).strip()
                    status_msg = "KEY FOUND!"
                continue

            m = progress_re.search(line)
            if m:
                with lock:
                    try:
                        keys_tested = int(m.group(1))
                    except ValueError:
                        pass
                    status_msg = "Cracking PMKID..."

            m = speed_re.search(line)
            if m:
                with lock:
                    speed_kps = m.group(1).strip()[:16]

        proc.wait(timeout=5)

        # Check potfile / stdout for cracked result
        if not found_key:
            show = subprocess.run(
                [HASHCAT_BIN, "-m", "22000", "--show", hash_file],
                capture_output=True, text=True, timeout=10,
            )
            for sline in show.stdout.splitlines():
                if ":" in sline:
                    parts = sline.rsplit(":", 1)
                    if len(parts) == 2 and parts[1].strip():
                        with lock:
                            found_key = parts[1].strip()
                            status_msg = "KEY FOUND!"
                        break

    except Exception as exc:
        with lock:
            status_msg = f"Error: {str(exc)[:18]}"
    finally:
        _crack_proc = None
        # Cleanup temp hash file
        try:
            os.remove(hash_file)
        except Exception:
            pass
        with lock:
            elapsed_secs = int(time.time() - start_time)
            if phase == "cracking":
                phase = "results"
                if found_key:
                    status_msg = "KEY FOUND!"
                else:
                    status_msg = "Done. Key not found"


def _kill_crack_proc():
    """Kill the running cracking process."""
    global _crack_proc
    proc = _crack_proc
    if proc is not None:
        try:
            os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        _crack_proc = None


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_result(target_name):
    """Export cracked WPA key to loot directory."""
    with lock:
        key = found_key
    if not key:
        return None

    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"cracked_{ts}.txt")
    with open(filepath, "w") as fh:
        fh.write(f"Target: {target_name}\n")
        fh.write(f"Key: {key}\n")
        fh.write(f"Date: {datetime.now().isoformat()}\n")
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _fmt_elapsed(secs):
    """Format seconds as MM:SS."""
    m, s = divmod(secs, 60)
    return f"{m:02d}:{s:02d}"


def _fmt_keys(count):
    """Format key count for display."""
    if count >= 1000000:
        return f"{count / 1000000:.1f}M"
    if count >= 1000:
        return f"{count / 1000:.1f}K"
    return str(count)


def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00AAFF")
    with lock:
        active = phase == "cracking"
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#444")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#888")


# ---------------------------------------------------------------------------
# View: file selection
# ---------------------------------------------------------------------------

def _draw_files_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "WPA CRACKER")

    with lock:
        msg = status_msg
        files = list(target_files)
        sc = scroll_pos
        sel = selected_idx

    d.text((2, 16), msg[:24], font=font, fill="#AAAAAA")
    d.text((2, 28), f"Targets: {len(files)}", font=font, fill="#888")

    if not files:
        d.text((8, 50), "No targets found", font=font, fill="#666")
        d.text((8, 64), "Capture handshakes", font=font, fill="#666")
        d.text((8, 78), "or grab PMKIDs first", font=font, fill="#666")
    else:
        visible = files[sc:sc + ROWS_VISIBLE]
        for i, tf in enumerate(visible):
            y = 40 + i * ROW_H
            idx = sc + i
            prefix = ">" if idx == sel else " "
            name = tf["name"][:11]
            color = "#00FF00" if idx == sel else "#CCCCCC"
            d.text((2, y), f"{prefix}{name}", font=font, fill=color)
            type_color = "#00AAFF" if tf["ftype"] == "CAP" else "#FFAA00"
            d.text((88, y), tf["ftype"], font=font, fill=type_color)
            d.text((110, y), f"{tf['size_kb']}K", font=font, fill="#666")

    _draw_footer(d, "OK:Select K3:Exit")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: wordlist selection
# ---------------------------------------------------------------------------

def _draw_wordlist_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "WORDLIST")

    with lock:
        sel = selected_idx
        sc = scroll_pos
        files = list(target_files)
        wl = list(wordlists)

    # Target info (compact, 1 line)
    if files and wl_idx < len(files):
        tf = files[wl_idx]
        d.text((2, 16), f"{tf['name'][:20]}", font=font, fill="#FFAA00")

    # Wordlist list with scroll
    list_y = 28
    wl_rows = 7
    visible = wl[sc:sc + wl_rows]
    for i, wl_entry in enumerate(visible):
        y = list_y + i * ROW_H
        idx = sc + i
        prefix = ">" if idx == sel else " "
        color = "#00FF00" if idx == sel else "#CCCCCC"
        # Show name + file size
        wl_path = wl_entry.get("path", "")
        try:
            sz = os.path.getsize(wl_path)
            if sz >= 1048576:
                sz_str = f"{sz / 1048576:.1f}M"
            elif sz >= 1024:
                sz_str = f"{sz // 1024}K"
            else:
                sz_str = f"{sz}B"
        except Exception:
            sz_str = ""
        d.text((2, y), f"{prefix}{wl_entry['name'][:16]}", font=font, fill=color)
        d.text((105, y), sz_str, font=font, fill="#666")

    # Scroll indicator
    if len(wl) > wl_rows:
        d.text((120, list_y), f"{sel + 1}/{len(wl)}", font=font, fill="#555")

    _draw_footer(d, "OK:Start U/D:Sel K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: cracking status
# ---------------------------------------------------------------------------

def _draw_cracking_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "WPA CRACKER")

    with lock:
        msg = status_msg
        tested = keys_tested
        spd = speed_kps
        elapsed = elapsed_secs
        key = found_key
        cur_phase = phase
        files = list(target_files)

    running = cur_phase == "cracking"

    # Target info
    if files and wl_idx < len(files):
        d.text((2, 16), f"{files[wl_idx]['name'][:22]}", font=font, fill="#888")

    # Status
    color = "#00FF00" if key else ("#FFAA00" if running else "#FF4444")
    d.text((2, 30), msg[:22], font=font, fill=color)

    # Stats
    d.text((2, 46), f"Time: {_fmt_elapsed(elapsed)}", font=font, fill="white")
    d.text((2, 58), f"Keys: {_fmt_keys(tested)}", font=font, fill="#AAAAAA")
    if spd:
        d.text((2, 70), f"Speed: {spd[:16]}", font=font, fill="#AAAAAA")

    # Found key (in green)
    if key:
        d.text((2, 86), "PASSWORD:", font=font, fill="#888")
        d.text((2, 98), key[:22], font=font, fill="#00FF00")

    if running:
        _draw_footer(d, "K1:Stop K3:Exit")
    else:
        _draw_footer(d, "K2:Export OK:Back K3:X")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, phase, scroll_pos, selected_idx, wl_idx
    global status_msg, target_files, wordlists

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 16), "WPA CRACKER", font=font, fill="#00AAFF")
    d.text((4, 36), "aircrack-ng + john", font=font, fill="#888")
    d.text((4, 52), "Scanning for targets...", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)

    # Scan for targets and wordlists
    found = _scan_targets()
    wl_options = _build_wordlist_options()
    with lock:
        target_files = found
        wordlists = wl_options
        status_msg = f"Found {len(found)} targets" if found else "No targets found"

    selected_target = None

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if phase == "wordlist":
                    phase = "files"
                    with lock:
                        scroll_pos = 0
                        selected_idx = 0
                    time.sleep(0.25)
                    continue
                # Exit
                break

            # --- File selection ---
            if phase == "files":
                if btn == "OK" and target_files:
                    with lock:
                        if 0 <= selected_idx < len(target_files):
                            selected_target = dict(target_files[selected_idx])
                            wl_idx = selected_idx
                    if selected_target:
                        phase = "wordlist"
                        with lock:
                            selected_idx = 0
                            scroll_pos = 0
                    time.sleep(0.3)

                elif btn == "UP":
                    selected_idx = max(0, selected_idx - 1)
                    if selected_idx < scroll_pos:
                        with lock:
                            scroll_pos = selected_idx
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        total = len(target_files)
                    selected_idx = min(selected_idx + 1, max(0, total - 1))
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        with lock:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.15)

                _draw_files_view()

            # --- Wordlist selection ---
            elif phase == "wordlist":
                if btn == "OK" and selected_target:
                    with lock:
                        wl_entry = wordlists[selected_idx] if selected_idx < len(wordlists) else wordlists[0]
                    phase = "cracking"
                    with lock:
                        scroll_pos = 0

                    if selected_target["ftype"] == "CAP":
                        threading.Thread(
                            target=_crack_cap_thread,
                            args=(selected_target["path"], wl_entry["path"]),
                            daemon=True,
                        ).start()
                    else:
                        threading.Thread(
                            target=_crack_pmkid_thread,
                            args=(selected_target["path"], wl_entry["path"]),
                            daemon=True,
                        ).start()
                    time.sleep(0.3)

                elif btn == "UP":
                    selected_idx = max(0, selected_idx - 1)
                    if selected_idx < scroll_pos:
                        with lock:
                            scroll_pos = selected_idx
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        total = len(wordlists)
                    selected_idx = min(selected_idx + 1, max(0, total - 1))
                    if selected_idx >= scroll_pos + 7:
                        with lock:
                            scroll_pos = selected_idx - 6
                    time.sleep(0.15)

                _draw_wordlist_view()

            # --- Cracking / results ---
            elif phase in ("cracking", "results"):
                if btn == "KEY1" and phase == "cracking":
                    _kill_crack_proc()
                    with lock:
                        status_msg = "Stopped by user"
                        phase = "results"
                    time.sleep(0.3)

                elif btn == "KEY2" and phase == "results":
                    target_name = selected_target["name"] if selected_target else "unknown"
                    fname = _export_result(target_name)
                    if fname:
                        with lock:
                            status_msg = f"Saved: {fname[:18]}"
                    else:
                        with lock:
                            status_msg = "No key to export"
                    time.sleep(0.3)

                elif btn == "OK" and phase == "results":
                    # Return to file selection
                    phase = "files"
                    with lock:
                        scroll_pos = 0
                        selected_idx = 0
                    found = _scan_targets()
                    with lock:
                        target_files = found
                        status_msg = f"Found {len(found)} targets"
                    time.sleep(0.3)

                _draw_cracking_view()

            time.sleep(0.05)

    finally:
        _running = False
        _kill_crack_proc()
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
