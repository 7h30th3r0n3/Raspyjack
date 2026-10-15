#!/usr/bin/env python3
"""
RaspyJack payload - Linux Shell
===============================
Author: 7h30th3r0n3

An interactive bash shell rendered entirely by RaspyJack on the LCD.

The old version used fbterm + openvt/chvt on a kernel VT. That cannot work on
the CardputerZero: its panel is a DRM/MIPI-DBI display with no text console
mapped to it (con2fbmap -> -1, labwc owns the DRM card), so fbterm/openvt paint
to a VT nothing shows. Instead we run bash under a PTY, interpret its ANSI
output with a terminal emulator (pyte), and paint the character grid straight
to the framebuffer through the same path the menu uses - guaranteed visible -
while we own the keyboard (grabbed via evdev) so exit is reliable. This also
works on any other RaspyJack panel size.

Controls:
  Device keyboard  Types straight into the shell (arrows / enter / tab work)
  exit             Quit the shell and return to the menu
  Hold ESC ~2s     Local force-quit (a normal ESC tap is sent to the shell)
  Ctrl+C           Interrupt (if the keyboard exposes Ctrl)
"""

import os
import sys
import pty
import fcntl
import termios
import struct
import select
import signal
import time
import errno

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# Turn OFF the per-frame screen mirror BEFORE importing LCD_1in44 (it reads
# these at import time) - the JPEG mirror is pure CPU waste for a full-screen
# terminal and adds lag on the slow board.
os.environ.setdefault("RJ_FRAME_MIRROR", "0")
os.environ.setdefault("RJ_CARDPUTER_FRAME_ENABLED", "0")

from PIL import Image, ImageDraw, ImageFont
import LCD_1in44
import LCD_Config

# --------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FONT_PX = 9             # glyph pixel height; lower = more columns, harder to read
                        # (9 -> ~64x14 grid on this 320x170 panel)
SHELL_CMD = ["bash", "-i"]
MIN_FRAME_DT = 0.04     # cap redraw rate to spare the CPU
KBD_NAME = "tca8418"    # keyboard device matched by name

# --------------------------------------------------------------------------
# ANSI colour palette (xterm-ish) for pyte Char.fg / Char.bg
# --------------------------------------------------------------------------
_PALETTE = {
    "black": (0, 0, 0), "red": (205, 0, 0), "green": (0, 205, 0),
    "brown": (205, 205, 0), "blue": (0, 0, 238), "magenta": (205, 0, 205),
    "cyan": (0, 205, 205), "white": (229, 229, 229),
    "brightblack": (110, 110, 110), "brightred": (255, 85, 85),
    "brightgreen": (85, 255, 85), "brightbrown": (255, 255, 85),
    "brightblue": (110, 110, 255), "brightmagenta": (255, 85, 255),
    "brightcyan": (85, 255, 255), "brightwhite": (255, 255, 255),
}
_DEFAULT_FG = (210, 210, 210)
_DEFAULT_BG = (0, 0, 0)


def _rgb(name, is_bg):
    if name == "default":
        return _DEFAULT_BG if is_bg else _DEFAULT_FG
    hit = _PALETTE.get(name)
    if hit:
        return hit
    if isinstance(name, str) and len(name) == 6:
        try:
            return (int(name[0:2], 16), int(name[2:4], 16), int(name[4:6], 16))
        except ValueError:
            pass
    return _DEFAULT_BG if is_bg else _DEFAULT_FG


# --------------------------------------------------------------------------
# Keyboard: raw evdev scancode -> bytes written to the PTY.
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
_SPECIAL = {
    28: b"\r", 14: b"\x7f", 15: b"\t", 1: b"\x1b",
    103: b"\x1b[A", 108: b"\x1b[B", 106: b"\x1b[C", 105: b"\x1b[D",
    111: b"\x1b[3~",            # delete
}
_CTRL_CODES = {29, 97}         # left/right ctrl, if present


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


# --------------------------------------------------------------------------
# Terminal renderer (pyte grid -> framebuffer, differential by row band)
# --------------------------------------------------------------------------
class Term:
    def __init__(self, lcd):
        self.lcd = lcd
        self.W, self.H = lcd.width, lcd.height
        self.font = ImageFont.truetype(FONT_PATH, FONT_PX)
        try:
            self.font_b = ImageFont.truetype(FONT_BOLD_PATH, FONT_PX)
        except Exception:
            self.font_b = self.font
        self.cw = max(1, int(round(self.font.getlength("M"))))
        asc, desc = self.font.getmetrics()
        self.ch = asc + desc
        self.cols = max(8, self.W // self.cw)
        self.rows = max(4, self.H // self.ch)
        self._cache = {}
        self._last = 0.0
        self._frame = None
        self._pcy = None
        import numpy as _np
        self._np = _np

    def cell(self, data, fg, bg, bold, reverse):
        key = (data, fg, bg, bold, reverse)
        img = self._cache.get(key)
        if img is None:
            fgc = _rgb(fg, False)
            bgc = _rgb(bg, True)
            if reverse:
                fgc, bgc = bgc, fgc
            img = Image.new("RGB", (self.cw, self.ch), bgc)
            if data and data != " ":
                ImageDraw.Draw(img).text(
                    (0, 0), data, font=(self.font_b if bold else self.font), fill=fgc)
            if len(self._cache) < 4000:
                self._cache[key] = img
        return img

    def _fb_rows(self, y0, y1):
        try:
            band = self._frame.crop((0, y0, self.W, y1))
            arr = self._np.asarray(band)
            r = (arr[..., 0].astype(self._np.uint16) >> 3) << 11
            g = (arr[..., 1].astype(self._np.uint16) >> 2) << 5
            b = arr[..., 2].astype(self._np.uint16) >> 3
            data = (r | g | b).astype(self._np.uint16).tobytes()
            fb = LCD_Config._open_fb()
            fb.seek(y0 * self.W * 2)
            fb.write(data)
            return True
        except Exception:
            return False

    def render(self, screen, force=False):
        now = time.monotonic()
        if not force and (now - self._last) < MIN_FRAME_DT:
            return False
        self._last = now
        buf = screen.buffer
        cx, cy = screen.cursor.x, screen.cursor.y
        cur_on = not screen.cursor.hidden

        if self._frame is None:
            self._frame = Image.new("RGB", (self.W, self.H), _DEFAULT_BG)
            force = True

        if force:
            dirty = set(range(self.rows))
        else:
            dirty = set(screen.dirty)
            dirty.add(cy)
            if self._pcy is not None:
                dirty.add(self._pcy)
        dirty = sorted(y for y in dirty if 0 <= y < self.rows)
        if not dirty:
            return False

        for y in dirty:
            py = y * self.ch
            row = buf[y]
            for x in range(self.cols):
                c = row[x]
                rev = c.reverse
                if cur_on and x == cx and y == cy:
                    rev = not rev
                self._frame.paste(self.cell(c.data, c.fg, c.bg, c.bold, rev),
                                  (x * self.cw, py))
        self._pcy = cy if cur_on else None

        y0 = dirty[0] * self.ch
        y1 = min(self.H, (dirty[-1] + 1) * self.ch)
        if not self._fb_rows(y0, y1):
            self.lcd.LCD_ShowImage(self._frame, 0, 0)
        return True

    def splash(self, lines):
        img = Image.new("RGB", (self.W, self.H), _DEFAULT_BG)
        d = ImageDraw.Draw(img)
        y = self.H // 2 - len(lines) * self.ch // 2
        for text, col in lines:
            w = int(d.textlength(text, font=self.font))
            d.text(((self.W - w) // 2, y), text, font=self.font, fill=col)
            y += self.ch + 2
        self.lcd.LCD_ShowImage(img, 0, 0)


def _resume(evdev_keys):
    if evdev_keys is not None:
        try:
            evdev_keys.resume()
        except Exception:
            pass


def main():
    import pyte

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

    term = Term(lcd)
    term.splash([("Linux Shell", (0, 220, 120)),
                 ("hold ESC to quit", (150, 150, 150)),
                 ("or type 'exit'", (90, 90, 90))])

    # Quiet RaspyJack's own keyboard reader so it does not fight for events.
    try:
        import evdev_keys
        evdev_keys.pause()
    except Exception:
        evdev_keys = None

    kbd = _find_keyboard()
    if kbd is None:
        term.splash([("No keyboard found", (255, 80, 80))])
        time.sleep(3)
        _resume(evdev_keys)
        return 1

    screen = pyte.Screen(term.cols, term.rows)
    stream = pyte.ByteStream(screen)

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ,
                struct.pack("HHHH", term.rows, term.cols, 0, 0))

    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env["LINES"] = str(term.rows)
    env["COLUMNS"] = str(term.cols)
    # Compact prompt that fits a narrow screen (used if the rc file does not
    # override it).
    env.setdefault("PS1", r"\w\$ ")

    pid = os.fork()
    if pid == 0:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        if slave > 2:
            os.close(slave)
        os.close(master)
        home = os.path.expanduser("~")
        try:
            os.chdir(home)
        except Exception:
            pass
        try:
            os.execvpe(SHELL_CMD[0], SHELL_CMD, env)
        except Exception:
            os._exit(127)

    os.close(slave)
    flags = fcntl.fcntl(master, fcntl.F_GETFL)
    fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    try:
        kbd.grab()
    except Exception:
        pass

    screen.dirty.clear()
    ctrl = False
    esc_t0 = None
    alive = True
    try:
        while alive:
            r, _, _ = select.select([master, kbd.fd], [], [], 0.05)

            if master in r:
                try:
                    data = os.read(master, 65536)
                except OSError as e:
                    if e.errno in (errno.EIO,):
                        data = b""
                    elif e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        data = None
                    else:
                        raise
                if data == b"":
                    alive = False
                elif data:
                    stream.feed(data)

            if kbd.fd in r:
                try:
                    import evdev
                    for ev in kbd.read():
                        if ev.type != evdev.ecodes.EV_KEY:
                            continue
                        code, val = ev.code, ev.value
                        if code in _CTRL_CODES:
                            ctrl = val != 0
                            continue
                        if code == 1:              # ESC: tap -> shell, hold 2s -> quit
                            if val == 1:
                                esc_t0 = time.monotonic()
                            elif val == 0:
                                esc_t0 = None
                            elif val == 2 and esc_t0 and time.monotonic() - esc_t0 >= 2.0:
                                alive = False
                                break
                            if val in (1, 2):
                                try:
                                    os.write(master, b"\x1b")
                                except OSError:
                                    alive = False
                                    break
                            continue
                        if val not in (1, 2):      # keydown / autorepeat only
                            continue
                        out = _SPECIAL.get(code)
                        if out is None:
                            chx = _KEYS.get(code)
                            if chx is None:
                                continue
                            if ctrl and chx.isalpha():
                                out = bytes([ord(chx.upper()) & 0x1f])
                            elif ctrl and chx == " ":
                                out = b"\x00"
                            else:
                                out = chx.encode("utf-8")
                        try:
                            os.write(master, out)
                        except OSError:
                            alive = False
                            break
                except OSError:
                    pass

            try:
                wpid, _ = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    try:
                        while True:
                            d = os.read(master, 65536)
                            if not d:
                                break
                            stream.feed(d)
                    except OSError:
                        pass
                    alive = False
            except ChildProcessError:
                alive = False

            if screen.dirty or not alive:
                if term.render(screen, force=not alive):
                    screen.dirty.clear()
    finally:
        try:
            kbd.ungrab()
        except Exception:
            pass
        try:
            os.close(master)
        except Exception:
            pass
        try:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        except Exception:
            pass
        _resume(evdev_keys)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
