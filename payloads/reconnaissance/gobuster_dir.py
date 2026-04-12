#!/usr/bin/env python3
"""
RaspyJack Payload -- Gobuster (dir mode)
=========================================
Author: MerlinvdW

Runs gobuster dir against a URL. Wordlists: install_raspyjack.sh fills
loot/wordlists and loot/wordlists/dirbuster (with /usr/share fallbacks).

Authorized testing only; generates many HTTP requests.

Controls:
  KEY1       -- Edit URL (on-screen keyboard)
  KEY2       -- Cycle wordlist preset
  RIGHT      -- Cycle threads (4 / 8 / 12 / 16)
  LEFT       -- Toggle TLS verify skip (-k)
  OK         -- Start scan
  KEY3       -- Stop scan while running, or exit
  UP / DOWN  -- Scroll results
  LEFT       -- Back to idle (from results)

Loot: /root/Raspyjack/loot/Gobuster/
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import signal
import shutil
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._keyboard_helper import lcd_keyboard

log = logging.getLogger(__name__)

# region agent log
_AGENT_DBG_HINTED = False


def _agent_rj_root() -> str:
    """RaspyJack install dir (parent of payloads/)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", ".."))


def _agent_dbg(hypothesis_id: str, location: str, message: str, data: dict | None = None) -> None:
    global _AGENT_DBG_HINTED
    rec = {
        "sessionId": "98bb65",
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data or {},
        "timestamp": int(time.time() * 1000),
    }
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    here = os.path.dirname(os.path.abspath(__file__))
    rj = _agent_rj_root()
    primary = os.path.join(rj, "loot", "Gobuster", "debug-98bb65.log")
    paths = (
        primary,
        os.path.join(here, "debug-98bb65.log"),
        os.path.join(tempfile.gettempdir(), "debug-98bb65.log"),
        "/tmp/debug-98bb65.log",
        os.path.join(rj, "debug-98bb65.log"),
        os.path.normpath(os.path.join(here, "..", "..", "..", "..", "debug-98bb65.log")),
    )
    ok_any = False
    last_err = ""
    for p in paths:
        try:
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(line)
            ok_any = True
            if not _AGENT_DBG_HINTED:
                _AGENT_DBG_HINTED = True
                sys.stderr.write(
                    "[gobuster_dir] DEBUG NDJSON session=98bb65 install="
                    + rj
                    + " log="
                    + primary
                    + " alt="
                    + os.path.join(here, "debug-98bb65.log")
                    + "\n"
                )
                sys.stderr.flush()
        except OSError as exc:
            last_err = repr(exc)
            continue
    if not ok_any:
        try:
            pl = os.path.join(rj, "loot", "payload.log")
            with open(pl, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(
                    "\n## gobuster_dir agent_98bb65 ALL_NDJSON_WRITES_FAILED "
                    + time.strftime("%Y-%m-%d %H:%M:%S")
                    + " last_err="
                    + (last_err[:200] if last_err else "?")
                    + "\n"
                )
        except OSError:
            pass
        try:
            sys.stderr.write(
                "[gobuster_dir] agent_98bb65: could not write NDJSON; "
                "marker appended to loot/payload.log if possible. install="
                + rj
                + "\n"
            )
            sys.stderr.flush()
        except OSError:
            pass
# endregion agent log

# ---------------------------------------------------------------------------
# Pins / constants
# ---------------------------------------------------------------------------

PINS: dict[str, int] = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

LOOT_DIR = "/root/Raspyjack/loot/Gobuster"
DEBOUNCE_S = 0.22
LINE_W = 18
LINE_H = 12
HEADER_H = 12
FOOTER_Y = 112

DRAW_X_MAX = 127
DRAW_Y_MAX = 127

THREAD_OPTIONS: tuple[int, ...] = (4, 8, 12, 16)
DEFAULT_URL = "http://127.0.0.1:8080/"
GOBUSTER_TIMEOUT = "10s"
MAIN_LOOP_SLEEP_S = 0.05
ERROR_SCREEN_PAUSE_S = 1.5
ERROR_SCREEN_LONG_PAUSE_S = 2.0
PROC_WAIT_AFTER_TERM_S = 8.0
PROC_WAIT_AFTER_EXIT_S = 2.0

MAX_CAPTURE_LINES = 500  # stdout lines kept in RAM
KEEP_AFTER_TRIM = 400
TRIM_LINE_LEN = 100

_WORDLIST_PRESETS: list[tuple[str, list[str]]] = [
    ("d:common", [
        "/root/Raspyjack/loot/wordlists/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ]),
    ("d:small", [
        "/root/Raspyjack/loot/wordlists/small.txt",
        "/usr/share/dirb/wordlists/small.txt",
    ]),
    ("DB:small", [
        "/root/Raspyjack/loot/wordlists/dirbuster/small.txt",
        "/usr/share/dirbuster/wordlists/small.txt",
    ]),
    ("DB:common", [
        "/root/Raspyjack/loot/wordlists/dirbuster/common.txt",
        "/usr/share/dirbuster/wordlists/common.txt",
    ]),
    ("DB:big", [
        "/root/Raspyjack/loot/wordlists/dirbuster/big.txt",
        "/usr/share/dirbuster/wordlists/big.txt",
    ]),
    ("DB:ext", [
        "/root/Raspyjack/loot/wordlists/dirbuster/extensions_common.txt",
        "/usr/share/dirbuster/wordlists/extensions_common.txt",
    ]),
]

_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)

LCD: LCD_1in44.LCD | None = None
WIDTH = 0
HEIGHT = 0
FONT = None  # type: ignore[assignment]


def _init_hardware() -> None:
    global LCD, WIDTH, HEIGHT, FONT
    # region agent log
    _agent_dbg("H1", "gobuster_dir:_init_hardware:entry", "init start", {})
    # endregion agent log
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    try:
        lcd.LCD_Clear()
    except Exception as exc:  # noqa: BLE001
        log.debug("LCD_Clear: %s", exc)
    LCD = lcd
    # Must match lcd.width/height for LCD_ShowImage (H2).
    WIDTH = int(lcd.width)
    HEIGHT = int(lcd.height)
    # region agent log
    _agent_dbg(
        "H2",
        "gobuster_dir:_init_hardware:sizes",
        "buffer vs lcd",
        {
            "WIDTH": WIDTH,
            "HEIGHT": HEIGHT,
            "LCD_WIDTH": int(LCD_1in44.LCD_WIDTH),
            "LCD_HEIGHT": int(LCD_1in44.LCD_HEIGHT),
        },
    )
    # endregion agent log
    FONT = scaled_font()
    try:
        os.makedirs(LOOT_DIR, exist_ok=True)
    except OSError as exc:
        log.warning("loot dir: %s", exc)


def _cleanup_hardware() -> None:
    global LCD
    if LCD is not None:
        try:
            LCD.LCD_Clear()
        except Exception as exc:  # noqa: BLE001
            log.debug("LCD clear failed: %s", exc)
    try:
        GPIO.cleanup()
    except Exception as exc:  # noqa: BLE001
        log.debug("GPIO cleanup failed: %s", exc)
    LCD = None


def _find_gobuster() -> str | None:
    return shutil.which("gobuster")


def _wordlist_resolve(preset_idx: int) -> tuple[str | None, str]:
    if not _WORDLIST_PRESETS:
        return None, "?"
    label, paths = _WORDLIST_PRESETS[preset_idx % len(_WORDLIST_PRESETS)]
    for path in paths:
        if os.path.isfile(path):
            return path, label
    return None, label


def _validate_url(value: str) -> bool:
    return bool(_URL_RE.match((value or "").strip()))


def _normalize_url_input(raw: str) -> str | None:
    u = (raw or "").strip()
    if not u:
        return None
    if not u.lower().startswith(("http://", "https://")):
        u = "http://" + u
    return u if _validate_url(u) else None


def _build_gobuster_cmd(
    gobuster_exe: str,
    url: str,
    wordlist: str,
    threads: int,
    skip_tls: bool,
) -> list[str]:
    cmd: list[str] = [
        gobuster_exe,
        "dir",
        "-u",
        url,
        "-w",
        wordlist,
        "-t",
        str(threads),
        "--timeout",
        GOBUSTER_TIMEOUT,
    ]
    if skip_tls:
        cmd.append("-k")
    return cmd


def _terminate_process_group(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        gid = os.getpgid(proc.pid)
        os.killpg(gid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=PROC_WAIT_AFTER_TERM_S)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait(timeout=2.0)


def _close_process_stdout(proc: subprocess.Popen[str] | None) -> None:
    if proc is None or proc.stdout is None:
        return
    try:
        proc.stdout.close()
    except OSError:
        pass


def _append_output_line(lines: list[str], lock: threading.Lock, text: str) -> None:
    trimmed = text[-TRIM_LINE_LEN:] if text else ""
    if not trimmed:
        return
    with lock:
        lines.append(trimmed)
        if len(lines) > MAX_CAPTURE_LINES:
            del lines[:-KEEP_AFTER_TRIM]


def _persist_loot(
    url: str,
    cmd: list[str],
    lines: list[str],
    exit_code: int | None,
) -> str | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"gobuster_{ts}.txt")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# url={url}\n")
            if exit_code is not None:
                fh.write(f"# exit={exit_code}\n")
            fh.write(f"# cmd={cmd!r}\n")
            fh.write("\n".join(lines))
        return path
    except OSError as exc:
        log.warning("Could not write loot file %s: %s", path, exc)
        return None


def _draw_error(msg: str) -> None:
    assert LCD is not None and FONT is not None
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((2, 20), "Gobuster error", font=FONT, fill="#f66")
    y = 36
    for part in msg.replace("|", ";").split(";")[:4]:
        while part and y <= 90:
            d.text((2, y), part[:LINE_W], font=FONT, fill="#ccc")
            part = part[LINE_W:]
            y += LINE_H
    d.text((2, FOOTER_Y + 2), "K3=exit", font=FONT, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_idle(url: str, wl_label: str, threads: int, skip_tls: bool) -> None:
    assert LCD is not None and FONT is not None
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, DRAW_X_MAX, HEADER_H - 1), fill="#1a2e1a")
    d.text((2, 1), "Gobuster dir", font=FONT, fill="#7fff7f")
    d.text((DRAW_X_MAX - 20, 1), "K3", font=FONT, fill="#888")

    y = HEADER_H + 1
    u = url.strip()
    if len(u) > LINE_W:
        u = u[: LINE_W - 2] + ".."
    d.text((2, y), u or "(no url)", font=FONT, fill="#9f9")
    y += LINE_H
    d.text((2, y), f"WL:{wl_label} th:{threads}", font=FONT, fill="#ccc")
    y += LINE_H
    d.text((2, y), "TLS:" + ("skip -k" if skip_tls else "verify"), font=FONT, fill="#fc9")
    y += LINE_H
    d.text((2, y), "K1=URL K2=WL", font=FONT, fill="#888")
    y += LINE_H
    d.text((2, y), "LR=th/TLS OK=go", font=FONT, fill="#888")

    d.rectangle((0, FOOTER_Y, DRAW_X_MAX, DRAW_Y_MAX), fill="#111")
    d.text((2, FOOTER_Y + 2), "authorized only", font=FONT, fill="#555")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_running(lines: list[str], status: str) -> None:
    assert LCD is not None and FONT is not None
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, DRAW_X_MAX, HEADER_H - 1), fill="#2e1a1a")
    d.text((2, 1), "Running… K3=stop", font=FONT, fill="#ff9999")

    y = HEADER_H + 1
    d.text((2, y), status[:LINE_W], font=FONT, fill="#ff0")
    y += LINE_H
    line_h = 11
    max_rows = max(1, (FOOTER_Y - y - 2) // line_h)
    tail = lines[-max_rows:] if lines else ["(waiting…)"]
    for ln in tail:
        d.text((2, y), ln[-LINE_W:], font=FONT, fill="#ddd")
        y += line_h

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_results(lines: list[str], off: int, path_hint: str) -> None:
    assert LCD is not None and FONT is not None
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, DRAW_X_MAX, HEADER_H - 1), fill="#1a1a2e")
    d.text((2, 1), "Results L=back", font=FONT, fill="#9cf")

    y = HEADER_H + 1
    line_h = 11
    max_rows = max(1, (FOOTER_Y - y - 2) // line_h)
    n = len(lines)
    if n == 0:
        d.text((2, y), "(empty)", font=FONT, fill="#666")
        footer_range = "0/0"
    else:
        end = min(n, off + max_rows)
        for i in range(off, end):
            d.text((2, y), lines[i][:LINE_W], font=FONT, fill="#eee")
            y += line_h
        footer_range = f"{off + 1}-{end}/{n}"

    d.rectangle((0, FOOTER_Y, DRAW_X_MAX, DRAW_Y_MAX), fill="#111")
    d.text((2, FOOTER_Y + 1), footer_range, font=FONT, fill="#666")
    if path_hint:
        ph = path_hint if len(path_hint) <= LINE_W else "…" + path_hint[-(LINE_W - 1) :]
        d.text((2, FOOTER_Y + 8), ph, font=FONT, fill="#484")
    LCD.LCD_ShowImage(img, 0, 0)


def _run_gobuster_missing_loop() -> None:
    try:
        while True:
            _draw_error(
                "gobuster not found|apt install gobuster|or re-run install_raspyjack.sh"
            )
            if get_button(PINS, GPIO) == "KEY3":
                break
            time.sleep(0.1)
    finally:
        _cleanup_hardware()


def _stdout_reader(
    proc: subprocess.Popen[str],
    out_lines: list[str],
    out_lock: threading.Lock,
) -> None:
    try:
        if proc.stdout is None:
            return
        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip()
            if line:
                _append_output_line(out_lines, out_lock, line)
    except ValueError:
        pass
    except OSError as exc:
        log.debug("stdout read: %s", exc)


def main() -> None:
    # region agent log
    _agent_dbg("H1", "gobuster_dir:main:entry", "main()", {})
    # endregion agent log
    gobuster_exe = _find_gobuster()
    # region agent log
    _agent_dbg("H1", "gobuster_dir:main:gobuster", "which", {"exe": gobuster_exe or ""})
    # endregion agent log
    if not gobuster_exe:
        _init_hardware()
        _run_gobuster_missing_loop()
        return

    _init_hardware()
    assert LCD is not None

    url = DEFAULT_URL
    wl_preset = 0
    thread_idx = 1
    skip_tls = True
    last_btn_t = 0.0

    mode = "idle"
    proc: subprocess.Popen[str] | None = None
    active_cmd: list[str] = []
    out_lines: list[str] = []
    out_lock = threading.Lock()
    reader_thread: threading.Thread | None = None
    loot_path = ""
    result_off = 0

    try:
        while True:
            now = time.time()
            btn = get_button(PINS, GPIO) if now - last_btn_t > DEBOUNCE_S else None
            if btn:
                last_btn_t = now

            if mode == "idle":
                wl_path, wl_label = _wordlist_resolve(wl_preset)
                label = wl_label + ("!" if not wl_path else "")
                try:
                    _draw_idle(url, label, THREAD_OPTIONS[thread_idx], skip_tls)
                except Exception as exc:  # noqa: BLE001
                    # region agent log
                    _agent_dbg(
                        "H5",
                        "gobuster_dir:main:_draw_idle",
                        type(exc).__name__,
                        {"err": str(exc)[:300]},
                    )
                    # endregion agent log
                    raise

                if btn == "KEY3":
                    break
                if btn == "KEY1":
                    # region agent log
                    _agent_dbg("H3", "gobuster_dir:main:before_keyboard", "KEY1", {"url_len": len(url)})
                    # endregion agent log
                    entered = lcd_keyboard(
                        LCD,
                        FONT,
                        PINS,
                        GPIO,
                        title="Target URL",
                        default=url,
                        charset="url",
                        max_len=120,
                    )
                    # region agent log
                    _agent_dbg(
                        "H3",
                        "gobuster_dir:main:after_keyboard",
                        "keyboard returned",
                        {"entered_is_none": entered is None, "entered_len": len(entered or "")},
                    )
                    # endregion agent log
                    normalized = _normalize_url_input(entered or "")
                    if normalized:
                        url = normalized
                elif btn == "KEY2":
                    wl_preset = (wl_preset + 1) % len(_WORDLIST_PRESETS)
                elif btn == "RIGHT":
                    thread_idx = (thread_idx + 1) % len(THREAD_OPTIONS)
                elif btn == "LEFT":
                    skip_tls = not skip_tls
                elif btn == "OK":
                    resolved, _ = _wordlist_resolve(wl_preset)
                    if not resolved:
                        _draw_error("No wordlist|run install_raspyjack.sh")
                        time.sleep(ERROR_SCREEN_PAUSE_S)
                        continue
                    if not _validate_url(url):
                        _draw_error("Bad URL|need http:// or https://")
                        time.sleep(ERROR_SCREEN_PAUSE_S)
                        continue

                    out_lines.clear()
                    try:
                        active_cmd = _build_gobuster_cmd(
                            gobuster_exe,
                            url,
                            resolved,
                            THREAD_OPTIONS[thread_idx],
                            skip_tls,
                        )
                        proc = subprocess.Popen(
                            active_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            bufsize=1,
                            preexec_fn=os.setsid,
                        )
                        # region agent log
                        _agent_dbg(
                            "H4",
                            "gobuster_dir:main:popen_ok",
                            "scan started",
                            {"pid": proc.pid, "cmd0": active_cmd[0] if active_cmd else ""},
                        )
                        # endregion agent log
                    except OSError as exc:
                        _draw_error(f"spawn failed|{exc}"[:120])
                        time.sleep(ERROR_SCREEN_LONG_PAUSE_S)
                        proc = None
                        continue

                    reader_thread = threading.Thread(
                        target=_stdout_reader,
                        args=(proc, out_lines, out_lock),
                        daemon=True,
                        name="gobuster-stdout",
                    )
                    reader_thread.start()
                    mode = "running"

            elif mode == "running":
                assert proc is not None
                alive = proc.poll() is None
                with out_lock:
                    snap = list(out_lines)
                n = len(snap)
                last_snip = snap[-1][-20:] if snap else ""
                _draw_running(snap, f"lines:{n} {last_snip}")

                if btn == "KEY3":
                    _terminate_process_group(proc)
                    _close_process_stdout(proc)
                    if reader_thread is not None:
                        reader_thread.join(timeout=3.0)
                    with out_lock:
                        loot_lines = list(out_lines)
                    saved = _persist_loot(url, active_cmd, loot_lines, proc.returncode)
                    loot_path = saved or ""
                    proc = None
                    reader_thread = None
                    mode = "results"
                    result_off = 0
                elif not alive:
                    try:
                        proc.wait(timeout=PROC_WAIT_AFTER_EXIT_S)
                    except subprocess.TimeoutExpired:
                        log.warning("gobuster wait after exit timed out")
                    _close_process_stdout(proc)
                    if reader_thread is not None:
                        reader_thread.join(timeout=3.0)
                    rc = proc.returncode
                    with out_lock:
                        loot_lines = list(out_lines)
                    saved = _persist_loot(url, active_cmd, loot_lines, rc)
                    loot_path = saved or ""
                    proc = None
                    reader_thread = None
                    mode = "results"
                    result_off = 0

            elif mode == "results":
                with out_lock:
                    snapshot = list(out_lines)
                max_off = max(0, len(snapshot) - 1)
                result_off = min(result_off, max_off)
                _draw_results(snapshot, result_off, loot_path)

                if btn == "KEY3":
                    break
                if btn == "LEFT":
                    mode = "idle"
                elif btn == "UP":
                    result_off = max(0, result_off - 1)
                elif btn == "DOWN":
                    result_off = min(max_off, result_off + 1)

            if not btn:
                time.sleep(MAIN_LOOP_SLEEP_S)
    finally:
        if proc is not None and proc.poll() is None:
            _terminate_process_group(proc)
            _close_process_stdout(proc)
            if reader_thread is not None and reader_thread.is_alive():
                reader_thread.join(timeout=2.0)
        _cleanup_hardware()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    try:
        sys.stderr.write(
            "[gobuster_dir] boot session=98bb65 install="
            + _agent_rj_root()
            + " argv0="
            + (sys.argv[0] if sys.argv else "")
            + "\n"
        )
        sys.stderr.flush()
    except OSError:
        pass
    try:
        # region agent log
        _agent_dbg("H1", "gobuster_dir:__main__", "process start", {"argv": sys.argv[:3]})
        # endregion agent log
        main()
        # region agent log
        _agent_dbg("H1", "gobuster_dir:__main__", "main returned normally", {})
        # endregion agent log
    except Exception as exc:
        # region agent log
        _agent_dbg(
            "H_FATAL",
            "gobuster_dir:__main__:except",
            type(exc).__name__,
            {"err": str(exc)[:800], "tb": traceback.format_exc()[-6000:]},
        )
        # endregion agent log
        raise
