#!/usr/bin/env python3
"""
claude_ask.py - non-interactive, one-shot Claude Q&A for the tiny screen.

Unlike ``claude_code.py`` (the full interactive TUI), this payload has no live
terminal to render: you type a question on the device keyboard, it runs
``claude -p`` once, and shows the answer as plain, scrollable text. No pyte, no
spinner animation to repaint 15x/s, so the display stays light and the UI is
trivial to use.

Trade-off to know: every question spawns a fresh ``claude`` (node) process, so
you pay the ~40s cold start plus the normal request latency each time. The
interactive payload stays warm and is faster for a back-and-forth; this one is
for "ask one thing, read the answer" without fighting a laggy terminal.

Controls
  Type           build your question (device keyboard)
  Backspace      delete a character
  Enter          send the question / (on the answer screen) ask a new one
  Up / Down      scroll the answer
  Hold ESC 2s    quit back to RaspyJack (also cancels a running query)
"""

import os
import sys
import time
import errno
import fcntl
import select
import signal
import subprocess

# Allow importing RaspyJack root modules when launched standalone.
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# Kill the per-frame web/HDMI mirror before importing the LCD driver (it reads
# these at import time). We draw a plain text view, we never need the mirror.
os.environ.setdefault("RJ_FRAME_MIRROR", "0")
os.environ.setdefault("RJ_CARDPUTER_FRAME_ENABLED", "0")

from PIL import Image, ImageDraw, ImageFont
import LCD_1in44
import LCD_Config

# --------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_PX = 12                 # bigger than the TUI payload: this is for reading
KBD_NAME = "tca8418"
CLAUDE_CMD = ["claude", "-p"]
# Keep answers plain so they render cleanly on a ~45-column screen, and avoid
# tool use (which would stall or block waiting for a permission we cannot
# answer in print mode).
EXTRA_ARGS = [
    "--output-format", "text",
    "--append-system-prompt",
    "Answer directly and concisely in plain text for a tiny 45-column screen. "
    "Do not use any tools.",
]
FREE_DESKTOP = True          # stop the Wayland session once per run so node is
                             # as responsive as this board allows; restored on exit.

_DESKTOP_SERVICES = ["lightdm"]
_DESKTOP_PROCS = [
    "pcmanfm", "xdg-desktop-portal-wlr", "xdg-desktop-portal",
    "pipewire-pulse", "wireplumber", "pipewire", "polkit-mate",
]

# --------------------------------------------------------------------------
# Keyboard: raw evdev scancode -> character (same tca8418 keymap as the TUI).
# --------------------------------------------------------------------------
_KEYS = {
    2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9", 11: "0",
    16: "q", 17: "w", 18: "e", 19: "r", 20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p",
    30: "a", 31: "s", 32: "d", 33: "f", 34: "g", 35: "h", 36: "j", 37: "k", 38: "l",
    44: "z", 45: "x", 46: "c", 47: "v", 48: "b", 49: "n", 50: "m",
    57: " ",
    26: "!", 27: "@", 39: "#", 40: "$", 41: "%", 43: "^",
    51: "&", 52: "*", 53: "(", 94: ")",
    55: "~", 69: "`", 70: "_", 71: "-", 72: "+", 73: "=",
    74: "[", 75: "]", 76: "{", 77: "}",
    79: ";", 80: ":", 81: "'", 82: '"', 83: "<", 85: ">", 86: "\\", 89: "|",
    90: ",", 91: ".", 92: "/", 93: "?",
}
_ENTER, _BKSP, _ESC = 28, 14, 1
_UP, _DOWN = 103, 108

# --------------------------------------------------------------------------
# Colours
# --------------------------------------------------------------------------
_BG = (0, 0, 0)
_FG = (210, 210, 210)
_ACCENT = (0, 220, 120)
_DIM = (120, 120, 120)
_HINT = (90, 90, 90)
_ERR = (255, 90, 90)


def _find_keyboard():
    import evdev
    for path in evdev.list_devices():
        try:
            d = evdev.InputDevice(path)
            if KBD_NAME in (d.name or "").lower():
                return d
        except Exception:
            continue
    try:
        return evdev.InputDevice("/dev/input/event3")
    except Exception:
        return None


def _sysctl_write(path, val):
    try:
        with open(path, "w") as f:
            f.write(val)
        return True
    except Exception:
        return False


def _free_ram():
    """Quiet the Wayland desktop and bias the kernel toward keeping node's heap
    in fast zram. Best-effort. Returns the previous swappiness to restore."""
    for svc in _DESKTOP_SERVICES:
        try:
            subprocess.run(["systemctl", "stop", svc],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=15)
        except Exception:
            pass
    for pat in _DESKTOP_PROCS:
        try:
            subprocess.run(["pkill", "-TERM", "-f", pat],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5)
        except Exception:
            pass
    prev = None
    try:
        with open("/proc/sys/vm/swappiness") as f:
            prev = f.read().strip()
    except Exception:
        pass
    _sysctl_write("/proc/sys/vm/swappiness", "100")
    try:
        subprocess.run(["sync"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)
        _sysctl_write("/proc/sys/vm/drop_caches", "1")
    except Exception:
        pass
    return prev


def _restore_ram(prev):
    if prev:
        _sysctl_write("/proc/sys/vm/swappiness", prev)
    for svc in _DESKTOP_SERVICES:
        try:
            subprocess.run(["systemctl", "start", svc],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=15)
        except Exception:
            pass


# --------------------------------------------------------------------------
# Minimal scrollable text view (full-frame draw, pushed only when it changes).
# --------------------------------------------------------------------------
class UI:
    def __init__(self, lcd):
        self.lcd = lcd
        self.W, self.H = lcd.width, lcd.height
        self.font = ImageFont.truetype(FONT_PATH, FONT_PX)
        self.cw = max(1, int(round(self.font.getlength("M"))))
        asc, desc = self.font.getmetrics()
        self.ch = asc + desc + 1
        self.cols = max(16, self.W // self.cw)
        self.rows = max(4, self.H // self.ch)
        self.body_rows = self.rows - 2          # minus header + footer
        try:
            import numpy as _np
            self._np = _np
        except Exception:
            self._np = None

    def wrap(self, text):
        """Word-wrap text (honouring existing newlines) to the column width."""
        out = []
        for para in text.split("\n"):
            if para == "":
                out.append("")
                continue
            while len(para) > self.cols:
                cut = para.rfind(" ", 0, self.cols)
                if cut <= 0:
                    cut = self.cols
                out.append(para[:cut])
                para = para[cut:].lstrip()
            out.append(para)
        return out

    def _push(self, img):
        if self._np is not None:
            try:
                arr = self._np.asarray(img)
                r = (arr[..., 0].astype(self._np.uint16) >> 3) << 11
                g = (arr[..., 1].astype(self._np.uint16) >> 2) << 5
                b = arr[..., 2].astype(self._np.uint16) >> 3
                data = (r | g | b).astype(self._np.uint16).tobytes()
                fb = LCD_Config._open_fb()
                fb.seek(0)
                fb.write(data)
                return
            except Exception:
                pass
        self.lcd.LCD_ShowImage(img, 0, 0)

    def view(self, title, lines, scroll, footer, title_col=_ACCENT,
             body_col=_FG):
        img = Image.new("RGB", (self.W, self.H), _BG)
        d = ImageDraw.Draw(img)
        # header
        d.rectangle((0, 0, self.W - 1, self.ch - 1), fill=(18, 18, 18))
        d.text((2, 0), title[:self.cols], font=self.font, fill=title_col)
        # body
        y = self.ch
        for ln in lines[scroll:scroll + self.body_rows]:
            d.text((2, y), ln, font=self.font, fill=body_col)
            y += self.ch
        # footer
        fy = self.H - self.ch
        d.rectangle((0, fy, self.W - 1, self.H - 1), fill=(18, 18, 18))
        d.text((2, fy), footer[:self.cols], font=self.font, fill=_HINT)
        self._push(img)

    def splash(self, lines):
        img = Image.new("RGB", (self.W, self.H), _BG)
        d = ImageDraw.Draw(img)
        y = self.H // 2 - len(lines) * self.ch // 2
        for text, col in lines:
            w = int(d.textlength(text, font=self.font))
            d.text(((self.W - w) // 2, y), text, font=self.font, fill=col)
            y += self.ch + 2
        self._push(img)


def _esc_held(kbd, esc_down_at):
    """Return True if ESC has been held >= 2s (force quit)."""
    return esc_down_at is not None and (time.monotonic() - esc_down_at) >= 2.0


def run_query(ui, kbd, prompt):
    """Run `claude -p prompt`, stream stdout into the view. Returns the answer
    text, or None if the user force-quit during the query."""
    import evdev
    env = os.environ.copy()
    env.setdefault("DISABLE_AUTOUPDATER", "1")
    try:
        p = subprocess.Popen(
            CLAUDE_CMD + [prompt] + EXTRA_ARGS,
            cwd=os.path.expanduser("~"),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except Exception as e:
        ui.view("Error", ui.wrap("Could not start claude:\n%s" % e), 0,
                "Enter=back  hold ESC=quit", title_col=_ERR)
        return ""

    fl = fcntl.fcntl(p.stdout, fcntl.F_GETFL)
    fcntl.fcntl(p.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    answer = b""
    t0 = time.monotonic()
    last_draw = 0.0
    esc_down_at = None
    spin = "|/-\\"
    done = False

    while True:
        r, _, _ = select.select([p.stdout, kbd.fd], [], [], 0.2)

        if p.stdout in r:
            try:
                chunk = os.read(p.stdout.fileno(), 65536)
            except OSError as e:
                chunk = b"" if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK) else b""
            if chunk == b"" and p.poll() is not None:
                done = True
            elif chunk:
                answer += chunk

        if kbd.fd in r:
            try:
                for ev in kbd.read():
                    if ev.type != evdev.ecodes.EV_KEY:
                        continue
                    if ev.code == _ESC:
                        if ev.value == 1:
                            esc_down_at = time.monotonic()
                        elif ev.value == 0:
                            esc_down_at = None
                        elif ev.value == 2 and _esc_held(kbd, esc_down_at):
                            try:
                                p.kill()
                            except Exception:
                                pass
                            return None
            except OSError:
                pass

        if p.poll() is not None and not (p.stdout in r):
            done = True

        now = time.monotonic()
        if now - last_draw >= 0.15 or done:
            last_draw = now
            text = answer.decode("utf-8", "replace")
            lines = ui.wrap(text) if text else []
            scroll = max(0, len(lines) - ui.body_rows)
            if not answer and not done:
                head = "Thinking %s %ds" % (spin[int(now * 4) % 4], int(now - t0))
                ui.view(head, ["", "  waiting for Claude...",
                               "  (first answer can take ~60s)"], 0,
                        "hold ESC = cancel", title_col=_DIM)
            else:
                ui.view("Claude", lines, scroll,
                        "Enter=new  Up/Down=scroll  hold ESC=quit")

        if done:
            break

    try:
        p.wait(timeout=2)
    except Exception:
        pass
    return answer.decode("utf-8", "replace").strip()


def input_prompt(ui, kbd):
    """Collect a question from the keyboard. Returns the string, or None to quit."""
    import evdev
    text = ""
    esc_down_at = None
    dirty = True
    while True:
        if dirty:
            dirty = False
            body = ui.wrap(text + "_") if text else ["_"]
            scroll = max(0, len(body) - ui.body_rows)
            ui.view("Ask Claude", body, scroll,
                    "Enter=send  Bksp=del  hold ESC=quit")

        r, _, _ = select.select([kbd.fd], [], [], 0.2)
        if not r:
            # keep the hold-ESC timer responsive even with no new events
            if _esc_held(kbd, esc_down_at):
                return None
            continue
        try:
            for ev in kbd.read():
                if ev.type != evdev.ecodes.EV_KEY:
                    continue
                code, val = ev.code, ev.value
                if code == _ESC:
                    if val == 1:
                        esc_down_at = time.monotonic()
                    elif val == 0:
                        esc_down_at = None
                    elif val == 2 and _esc_held(kbd, esc_down_at):
                        return None
                    continue
                if val not in (1, 2):          # keydown / autorepeat only
                    continue
                if code == _ENTER:
                    if text.strip():
                        return text.strip()
                    continue
                if code == _BKSP:
                    text = text[:-1]
                    dirty = True
                    continue
                ch = _KEYS.get(code)
                if ch:
                    text += ch
                    dirty = True
        except OSError:
            pass
        if _esc_held(kbd, esc_down_at):
            return None


def answer_view(ui, kbd, answer):
    """Show the answer, scrollable. Returns 'new' to ask again or 'quit'."""
    import evdev
    lines = ui.wrap(answer) if answer else ["(empty answer)"]
    scroll = max(0, len(lines) - ui.body_rows)   # start at the bottom
    esc_down_at = None
    dirty = True
    while True:
        if dirty:
            dirty = False
            ui.view("Claude", lines, scroll,
                    "Enter=new  Up/Down=scroll  hold ESC=quit")
        r, _, _ = select.select([kbd.fd], [], [], 0.2)
        if not r:
            if _esc_held(kbd, esc_down_at):
                return "quit"
            continue
        try:
            for ev in kbd.read():
                if ev.type != evdev.ecodes.EV_KEY:
                    continue
                code, val = ev.code, ev.value
                if code == _ESC:
                    if val == 1:
                        esc_down_at = time.monotonic()
                    elif val == 0:
                        esc_down_at = None
                    elif val == 2 and _esc_held(kbd, esc_down_at):
                        return "quit"
                    continue
                if val not in (1, 2):
                    continue
                if code == _ENTER:
                    return "new"
                max_scroll = max(0, len(lines) - ui.body_rows)
                if code == _UP and scroll > 0:
                    scroll -= 1
                    dirty = True
                elif code == _DOWN and scroll < max_scroll:
                    scroll += 1
                    dirty = True
        except OSError:
            pass
        if _esc_held(kbd, esc_down_at):
            return "quit"


def main():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    ui = UI(lcd)

    prev_swappiness = None
    if FREE_DESKTOP:
        ui.splash([("Claude Ask", _ACCENT), ("freeing memory...", _DIM)])
        try:
            prev_swappiness = _free_ram()
        except Exception:
            pass

    try:
        import evdev_keys
        evdev_keys.pause()
    except Exception:
        evdev_keys = None

    kbd = _find_keyboard()
    if kbd is None:
        ui.splash([("No keyboard found", _ERR)])
        time.sleep(3)
        if evdev_keys is not None:
            try:
                evdev_keys.resume()
            except Exception:
                pass
        if FREE_DESKTOP:
            _restore_ram(prev_swappiness)
        return 1

    try:
        kbd.grab()
    except Exception:
        pass

    try:
        while True:
            prompt = input_prompt(ui, kbd)
            if prompt is None:
                break
            answer = run_query(ui, kbd, prompt)
            if answer is None:          # user force-quit during the query
                break
            if answer_view(ui, kbd, answer) == "quit":
                break
    finally:
        try:
            kbd.ungrab()
        except Exception:
            pass
        if evdev_keys is not None:
            try:
                evdev_keys.resume()
            except Exception:
                pass
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        if FREE_DESKTOP:
            _restore_ram(prev_swappiness)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
