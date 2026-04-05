#!/usr/bin/env python3
"""
RaspyJack Payload -- NTLM Hash Cracker
=======================================
Author: 7h30th3r0n3

Cracks captured NTLM hashes using John the Ripper.
Scans Responder logs and NTLMRelay loot for hash files, then runs
john with user-selected attack mode.

Setup / Prerequisites:
  - Requires john (/usr/sbin/john): apt install john
  - Reads hashes from Responder/logs/ and loot/NTLMRelay/.

Controls:
  OK         -- Select file / start cracking
  UP / DOWN  -- Scroll file list / attack modes
  KEY1       -- Show all cracked passwords (john --show)
  KEY2       -- Export cracked passwords to loot
  KEY3       -- Exit (kills john process)

Loot: /root/Raspyjack/loot/CrackedNTLM/
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
JOHN_BIN = "/usr/sbin/john"
DEFAULT_WORDLIST = "/usr/share/john/password.lst"
CUSTOM_WORDLIST = "/root/Raspyjack/loot/wordlists/custom.txt"
RESPONDER_LOG_DIR = "/root/Raspyjack/Responder/logs"
RELAY_LOOT_DIR = "/root/Raspyjack/loot/NTLMRelay"
LOOT_DIR = "/root/Raspyjack/loot/CrackedNTLM"
ROWS_VISIBLE = 6
ROW_H = 12

ATTACK_MODES = [
    {"name": "Quick", "desc": "Default wordlist"},
    {"name": "Custom", "desc": "Custom wordlist"},
    {"name": "Incremental", "desc": "Brute-force"},
    {"name": "Rules", "desc": "Wordlist + rules"},
]

# ---------------------------------------------------------------------------
# Shared state (immutable swap pattern via lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
hash_files = []         # [{path, name, count, fmt}]
scroll_pos = 0
selected_idx = 0
phase = "files"         # files | modes | cracking | results
mode_idx = 0
status_msg = "Scanning for hashes..."
cracked_count = 0
last_cracked = ""
elapsed_secs = 0
all_cracked = []        # list of cracked password strings
_running = True
_john_proc = None


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _detect_john_format(filename):
    """Auto-detect john format flag from filename."""
    upper = filename.upper()
    if "NTLMV2" in upper:
        return "netntlmv2"
    if "NTLMV1" in upper:
        return "netntlm"
    if "NTLM" in upper:
        return "nt"
    return "netntlmv2"


# ---------------------------------------------------------------------------
# Hash file discovery
# ---------------------------------------------------------------------------

def _count_lines(filepath):
    """Count non-empty, non-comment lines in a file."""
    count = 0
    try:
        with open(filepath, "r", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    count += 1
    except Exception:
        pass
    return count


def _scan_hash_files():
    """Scan known directories for NTLM hash files."""
    found = []
    search_dirs = [
        (RESPONDER_LOG_DIR, ["NTLMv2", "NTLMv1", "NTLM"]),
        (RELAY_LOOT_DIR, None),
    ]

    for dirpath, patterns in search_dirs:
        if not os.path.isdir(dirpath):
            continue
        try:
            for fname in sorted(os.listdir(dirpath)):
                fpath = os.path.join(dirpath, fname)
                if not os.path.isfile(fpath):
                    continue
                if not fname.endswith(".txt"):
                    continue
                if patterns is not None:
                    if not any(p.lower() in fname.lower() for p in patterns):
                        continue
                line_count = _count_lines(fpath)
                if line_count == 0:
                    continue
                fmt = _detect_john_format(fname)
                found.append({
                    "path": fpath,
                    "name": fname,
                    "count": line_count,
                    "fmt": fmt,
                })
        except Exception:
            pass

    return found


# ---------------------------------------------------------------------------
# John the Ripper execution
# ---------------------------------------------------------------------------

def _build_john_cmd(hashfile, fmt, mode_name):
    """Build the john command list for the selected attack mode."""
    base = [JOHN_BIN, f"--format={fmt}"]

    if mode_name == "Quick":
        return base + [f"--wordlist={DEFAULT_WORDLIST}", hashfile]

    if mode_name == "Custom":
        wordlist = CUSTOM_WORDLIST if os.path.isfile(CUSTOM_WORDLIST) else DEFAULT_WORDLIST
        return base + [f"--wordlist={wordlist}", hashfile]

    if mode_name == "Incremental":
        return base + ["--incremental", hashfile]

    if mode_name == "Rules":
        return base + [f"--wordlist={DEFAULT_WORDLIST}", "--rules", hashfile]

    return base + [f"--wordlist={DEFAULT_WORDLIST}", hashfile]


def _crack_thread(hashfile, fmt, mode_name):
    """Run john in a background thread, parse output in real-time."""
    global _john_proc, cracked_count, last_cracked, elapsed_secs
    global phase, status_msg, _running

    cmd = _build_john_cmd(hashfile, fmt, mode_name)
    start_time = time.time()

    with lock:
        cracked_count = 0
        last_cracked = ""
        elapsed_secs = 0
        status_msg = f"Starting {mode_name}..."

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _john_proc = proc

        # Pattern for cracked passwords in john output
        # Typical: "password  (username)"
        crack_re = re.compile(r"^(.+?)\s+\((.+?)\)\s*$")

        while _running:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if not line:
                continue

            line = line.rstrip()
            with lock:
                elapsed_secs = int(time.time() - start_time)

            match = crack_re.match(line)
            if match:
                password = match.group(1).strip()
                with lock:
                    cracked_count += 1
                    last_cracked = password
                    all_cracked.append(f"{match.group(2)}:{password}")
                    status_msg = f"Cracked! {cracked_count} found"

        proc.wait(timeout=5)

    except Exception as exc:
        with lock:
            status_msg = f"Error: {str(exc)[:18]}"
    finally:
        _john_proc = None
        with lock:
            elapsed_secs = int(time.time() - start_time)
            if phase == "cracking":
                phase = "results"
                if cracked_count == 0:
                    status_msg = "Done. No passwords cracked"
                else:
                    status_msg = f"Done. {cracked_count} cracked"


def _kill_john():
    """Kill the running john process."""
    global _john_proc
    proc = _john_proc
    if proc is not None:
        try:
            os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        _john_proc = None


# ---------------------------------------------------------------------------
# Show cracked passwords (john --show)
# ---------------------------------------------------------------------------

def _john_show(hashfile, fmt):
    """Run john --show and return list of cracked entries."""
    try:
        result = subprocess.run(
            [JOHN_BIN, "--show", f"--format={fmt}", hashfile],
            capture_output=True, text=True, timeout=15,
        )
        lines = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped and ":" in stripped and not stripped.startswith("("):
                lines.append(stripped)
        return lines
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_cracked(hashfile, fmt):
    """Export cracked passwords to loot directory."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    shown = _john_show(hashfile, fmt)
    if not shown:
        with lock:
            combined = list(all_cracked)
        if not combined:
            return None
        shown = combined

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"cracked_{ts}.txt")
    with open(filepath, "w") as fh:
        fh.write("\n".join(shown) + "\n")
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _fmt_elapsed(secs):
    """Format seconds as MM:SS."""
    m, s = divmod(secs, 60)
    return f"{m:02d}:{s:02d}"


def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#FF6600")
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
    _draw_header(d, "NTLM CRACKER")

    with lock:
        msg = status_msg
        files = list(hash_files)
        sc = scroll_pos
        sel = selected_idx

    d.text((2, 16), msg[:24], font=font, fill="#AAAAAA")
    d.text((2, 28), f"Files: {len(files)}", font=font, fill="#888")

    if not files:
        d.text((8, 55), "No hash files found", font=font, fill="#666")
    else:
        visible = files[sc:sc + ROWS_VISIBLE]
        for i, hf in enumerate(visible):
            y = 40 + i * ROW_H
            idx = sc + i
            prefix = ">" if idx == sel else " "
            name = hf["name"][:14]
            color = "#00FF00" if idx == sel else "#CCCCCC"
            d.text((2, y), f"{prefix}{name}", font=font, fill=color)
            d.text((104, y), f"{hf['count']}", font=font, fill="#888")

    _draw_footer(d, "OK:Sel K1:Show K3:Quit")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: attack mode selection
# ---------------------------------------------------------------------------

def _draw_modes_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "NTLM CRACKER")

    with lock:
        sel = selected_idx
        files = list(hash_files)
        file_sel = mode_idx  # reusing for file reference

    # Show selected file info
    if files:
        sel_file = files[min(file_sel, len(files) - 1)]
        d.text((2, 16), f"File: {sel_file['name'][:20]}", font=font, fill="#FFAA00")
        d.text((2, 28), f"Format: {sel_file['fmt']} ({sel_file['count']} hashes)",
               font=font, fill="#888")
    else:
        d.text((2, 16), "Select attack mode:", font=font, fill="#FFAA00")

    d.text((2, 42), "Attack mode:", font=font, fill="#AAAAAA")

    for i, mode in enumerate(ATTACK_MODES):
        y = 54 + i * ROW_H
        prefix = ">" if i == sel else " "
        color = "#00FF00" if i == sel else "#CCCCCC"
        d.text((2, y), f"{prefix}{mode['name']}", font=font, fill=color)
        d.text((72, y), mode["desc"][:10], font=font, fill="#666")

    _draw_footer(d, "OK:Start UP/DN:Sel K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: cracking status
# ---------------------------------------------------------------------------

def _draw_cracking_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "NTLM CRACKER")

    with lock:
        msg = status_msg
        count = cracked_count
        last = last_cracked
        elapsed = elapsed_secs
        cur_phase = phase

    running = cur_phase == "cracking"
    color = "#00FF00" if running else "#FFAA00"
    d.text((2, 18), msg[:22], font=font, fill=color)

    d.text((2, 34), f"Elapsed: {_fmt_elapsed(elapsed)}", font=font, fill="white")
    d.text((2, 48), f"Cracked: {count}", font=font, fill="#FFAA00")

    if last:
        d.text((2, 66), "Last found:", font=font, fill="#888")
        d.text((2, 78), last[:22], font=font, fill="#00FF00")
    else:
        d.text((2, 66), "Waiting for results...", font=font, fill="#666")

    if running:
        _draw_footer(d, "K1:Show K3:Exit")
    else:
        _draw_footer(d, "K1:Show K2:Export K3:X")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: cracked results (john --show output)
# ---------------------------------------------------------------------------

def _draw_results_view(show_lines):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "CRACKED PASSWORDS")

    with lock:
        sc = scroll_pos

    if not show_lines:
        d.text((8, 50), "No cracked passwords", font=font, fill="#666")
    else:
        d.text((2, 16), f"Total: {len(show_lines)}", font=font, fill="#FFAA00")
        visible = show_lines[sc:sc + ROWS_VISIBLE]
        for i, line in enumerate(visible):
            y = 30 + i * ROW_H
            d.text((2, y), line[:22], font=font, fill="#00FF00")

    _draw_footer(d, "UP/DN:Scroll K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, phase, scroll_pos, selected_idx, mode_idx
    global status_msg, hash_files

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 16), "NTLM CRACKER", font=font, fill="#FF6600")
    d.text((4, 36), "John the Ripper", font=font, fill="#888")
    d.text((4, 52), "Scanning for hashes...", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)

    # Scan for hash files
    found = _scan_hash_files()
    with lock:
        hash_files = found
        status_msg = f"Found {len(found)} hash files" if found else "No hash files found"

    # Track which file was selected for cracking
    selected_file = None
    show_lines = []
    showing_results = False

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if showing_results:
                    showing_results = False
                    with lock:
                        scroll_pos = 0
                    time.sleep(0.25)
                    continue
                if phase == "modes":
                    phase = "files"
                    with lock:
                        scroll_pos = 0
                        selected_idx = 0
                    time.sleep(0.25)
                    continue
                # Exit
                break

            # --- Show cracked results overlay ---
            if showing_results:
                if btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(
                            max(0, len(show_lines) - 1), scroll_pos + 1
                        )
                    time.sleep(0.15)
                _draw_results_view(show_lines)
                time.sleep(0.05)
                continue

            # --- File selection phase ---
            if phase == "files":
                if btn == "OK" and hash_files:
                    with lock:
                        if 0 <= selected_idx < len(hash_files):
                            selected_file = dict(hash_files[selected_idx])
                    if selected_file:
                        phase = "modes"
                        with lock:
                            selected_idx = 0
                            scroll_pos = 0
                            mode_idx = hash_files.index(selected_file) if selected_file in hash_files else 0
                    time.sleep(0.3)

                elif btn == "UP":
                    selected_idx = max(0, selected_idx - 1)
                    if selected_idx < scroll_pos:
                        with lock:
                            scroll_pos = selected_idx
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        total = len(hash_files)
                    selected_idx = min(selected_idx + 1, max(0, total - 1))
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        with lock:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.15)

                elif btn == "KEY1" and selected_file:
                    show_lines = _john_show(selected_file["path"], selected_file["fmt"])
                    showing_results = True
                    with lock:
                        scroll_pos = 0
                    time.sleep(0.3)

                _draw_files_view()

            # --- Attack mode selection ---
            elif phase == "modes":
                if btn == "OK" and selected_file:
                    with lock:
                        mode_name = ATTACK_MODES[selected_idx]["name"]
                    phase = "cracking"
                    with lock:
                        scroll_pos = 0
                    threading.Thread(
                        target=_crack_thread,
                        args=(selected_file["path"], selected_file["fmt"], mode_name),
                        daemon=True,
                    ).start()
                    time.sleep(0.3)

                elif btn == "UP":
                    selected_idx = max(0, selected_idx - 1)
                    time.sleep(0.15)

                elif btn == "DOWN":
                    selected_idx = min(selected_idx + 1, len(ATTACK_MODES) - 1)
                    time.sleep(0.15)

                _draw_modes_view()

            # --- Cracking / results phase ---
            elif phase in ("cracking", "results"):
                if btn == "KEY1" and selected_file:
                    show_lines = _john_show(selected_file["path"], selected_file["fmt"])
                    showing_results = True
                    with lock:
                        scroll_pos = 0
                    time.sleep(0.3)

                elif btn == "KEY2" and phase == "results" and selected_file:
                    fname = _export_cracked(selected_file["path"], selected_file["fmt"])
                    if fname:
                        with lock:
                            status_msg = f"Saved: {fname[:18]}"
                    else:
                        with lock:
                            status_msg = "Nothing to export"
                    time.sleep(0.3)

                elif btn == "OK" and phase == "results":
                    # Go back to file selection
                    phase = "files"
                    with lock:
                        scroll_pos = 0
                        selected_idx = 0
                    # Rescan files
                    found = _scan_hash_files()
                    with lock:
                        hash_files = found
                        status_msg = f"Found {len(found)} hash files"
                    time.sleep(0.3)

                _draw_cracking_view()

            time.sleep(0.05)

    finally:
        _running = False
        _kill_john()
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
