#!/usr/bin/env python3
"""
RaspyJack payload - Claude Code terminal
========================================
Author: 7h30th3r0n3

Runs the Claude Code CLI (`claude`) in a terminal rendered entirely by
RaspyJack on the LCD. This device's panel is a DRM/MIPI-DBI display with no
text console mapped to it (con2fbmap -> -1), so fbterm/openvt show nothing.
Instead we do what the APPLaunch `cli` terminal does conceptually: run the
program under a PTY, interpret its ANSI output with a terminal emulator
(pyte), and paint the character grid onto the panel through the same
LCD_ShowImage path the menu uses - so it is guaranteed visible, and we own
the keyboard (grabbed via evdev) so exit is reliable.

Controls:
  Device keyboard  Types straight into Claude Code (arrows/enter/esc work)
  /exit            Quit Claude and return to the menu
  Hold ESC ~2s     Local force-quit (a normal ESC tap goes to Claude)
  Ctrl+C           Interrupt (if the keyboard exposes Ctrl)

Note: the Node app takes ~30-40s to first paint on this device; a splash
with an elapsed counter is shown until Claude's UI appears.

First launch: run `/login` inside Claude (open the URL on a phone/PC and
paste the code back) or export ANTHROPIC_API_KEY in your shell profile.
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
# these at import time). The mirror JPEG-encodes the frame to /dev/shm up to
# 10x/s for the web/HDMI view - pure, heavy CPU waste here that was adding
# seconds of lag per keystroke on this slow board. We don't need it for a
# full-screen terminal.
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
CLAUDE_CMD = ["claude"]
MIN_FRAME_DT = 0.06     # cap redraw rate (~16 fps max) to spare the CPU
KBD_NAME = "tca8418"    # keyboard device matched by name

# This board has only ~350MB RAM and a slow CPU. Claude Code (node) runs fine
# here *once its working set is resident and left undisturbed* - measured
# steady-state keystroke echo is ~50ms. The killer is the Raspberry-Pi Wayland
# desktop (labwc compositor + panel) that keeps waking up and disturbing node's
# hot pages, which turns every keystroke into multi-second swap faults.
#
# APPLaunch (and therefore RaspyJack and this payload) runs as a systemd *user*
# service, completely independent of the labwc/lightdm graphical session, and
# draws straight to /dev/fb0 - so we can stop the whole Wayland session for the
# duration of the Claude session and the screen keeps working. We restart it on
# exit. (lightdm also comes back by itself on reboot.)
FREE_DESKTOP = True      # stop the Wayland session (lightdm) + helpers so Claude
                         # stays resident and responsive; restored on exit.
NODE_OPTIONS = ""        # optional V8 heap cap, e.g. "--max-old-space-size=256"

# systemd *system* services to stop while Claude runs and restart afterwards.
_DESKTOP_SERVICES = ["lightdm"]
# Extra per-user session churn to quiet (best-effort; respawn-managed ones are
# gone once lightdm is stopped, these are the stragglers under user@1000).
_DESKTOP_PROCS = [
    "pcmanfm", "xdg-desktop-portal-wlr", "xdg-desktop-portal",
    "pipewire-pulse", "wireplumber", "pipewire", "polkit-mate",
]

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
    # pyte stores 256-colour / truecolor as a 6-hex string
    if isinstance(name, str) and len(name) == 6:
        try:
            return (int(name[0:2], 16), int(name[2:4], 16), int(name[4:6], 16))
        except ValueError:
            pass
    return _DEFAULT_BG if is_bg else _DEFAULT_FG


# --------------------------------------------------------------------------
# Keyboard: raw evdev scancode -> bytes written to the PTY.
# Letters/digits use standard Linux keycodes; the 32 symbol codes match this
# device's custom tca8418 keymap (firmware emits one code per symbol, so no
# shift layer is needed).
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
    # fallback to the classic node
    try:
        return evdev.InputDevice("/dev/input/event3")
    except Exception:
        return None


# --------------------------------------------------------------------------
# Terminal renderer
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
        # Monospace cell metrics.
        self.cw = max(1, int(round(self.font.getlength("M"))))
        asc, desc = self.font.getmetrics()
        self.ch = asc + desc
        self.cols = max(8, self.W // self.cw)
        self.rows = max(4, self.H // self.ch)
        self._cache = {}
        self._last = 0.0
        self._frame = None     # persistent RGB canvas (diff rendering)
        self._pcy = None       # previous cursor row, to repaint when it moves
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
        """Convert pixel rows [y0, y1) of the persistent frame to RGB565 and
        write just that band to the framebuffer. Falls back to the full-image
        path on any error."""
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
            dirty.add(cy)                 # draw cursor at its new row
            if self._pcy is not None:
                dirty.add(self._pcy)      # and clear it from the old row
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

        # Push only the changed band(s). For typing this is 1-2 rows; for a full
        # repaint it is the whole screen. One contiguous span keeps it simple
        # and is near-optimal for the common cases.
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


def _sysctl_write(path, val):
    try:
        with open(path, "w") as f:
            f.write(val)
        return True
    except Exception:
        return False


def _free_ram():
    """Quiet the Wayland desktop so Claude stays resident, and bias the kernel
    toward keeping its heap in (fast) zram. We run as root here. Best-effort:
    every step is wrapped so a missing tool or process never aborts the
    payload. Returns the previous swappiness value so it can be restored."""
    import subprocess

    for svc in _DESKTOP_SERVICES:
        try:
            subprocess.run(["systemctl", "stop", svc],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=15)
        except Exception:
            pass

    for pat in _DESKTOP_PROCS:
        try:
            subprocess.run(["pkill", "-TERM", "-f", pat],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass

    prev_swappiness = None
    try:
        with open("/proc/sys/vm/swappiness") as f:
            prev_swappiness = f.read().strip()
    except Exception:
        pass

    # swappiness=100: push anonymous pages into zram (fast, in-RAM, compressed)
    # rather than evicting the page cache that holds Claude's big JS bundle -
    # evicting *that* is what made node re-read code from the slow eMMC and
    # stall. Measured: steady-state keystroke echo settles to ~50ms.
    _sysctl_write("/proc/sys/vm/swappiness", "100")

    # Hand clean page cache back to node right away.
    try:
        subprocess.run(["sync"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)
        _sysctl_write("/proc/sys/vm/drop_caches", "1")
    except Exception:
        pass

    return prev_swappiness


def _restore_ram(prev_swappiness):
    """Undo _free_ram: restore swappiness and restart the desktop session."""
    import subprocess
    if prev_swappiness:
        _sysctl_write("/proc/sys/vm/swappiness", prev_swappiness)
    for svc in _DESKTOP_SERVICES:
        try:
            subprocess.run(["systemctl", "start", svc],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=15)
        except Exception:
            pass


def main():
    import pyte

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

    term = Term(lcd)

    prev_swappiness = None
    if FREE_DESKTOP:
        term.splash([("Claude Code", (0, 220, 120)),
                     ("freeing memory...", (150, 150, 150))])
        try:
            prev_swappiness = _free_ram()
        except Exception:
            pass

    term.splash([("Claude Code", (0, 220, 120)),
                 ("starting (~40s)...", (150, 150, 150)),
                 ("/exit to quit", (90, 90, 90))])

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
        if FREE_DESKTOP:
            _restore_ram(prev_swappiness)
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
    # Keep node from auto-updating mid-session (a background update would churn
    # the CPU/disk and wreck the latency we just bought).
    env.setdefault("DISABLE_AUTOUPDATER", "1")
    if NODE_OPTIONS:
        env["NODE_OPTIONS"] = (
            (env.get("NODE_OPTIONS", "") + " " + NODE_OPTIONS).strip())

    pid = os.fork()
    if pid == 0:
        # child -> become session leader with slave as controlling tty, exec claude
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
            os.execvpe(CLAUDE_CMD[0], CLAUDE_CMD, env)
        except Exception:
            os._exit(127)

    os.close(slave)
    flags = fcntl.fcntl(master, fcntl.F_GETFL)
    fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    try:
        kbd.grab()
    except Exception:
        pass

    # Keep the startup splash up (and animated with an elapsed counter) until
    # Claude paints its first frame - node takes ~30-40s to boot on this box.
    screen.dirty.clear()
    first_data = False
    t0 = time.monotonic()
    last_splash = 0.0

    ctrl = False
    esc_t0 = None       # for the hold-ESC local force-quit
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
                    first_data = True
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
                        if code == 1:              # ESC: tap -> Claude, hold 2s -> quit
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

            # reap child if it exited
            try:
                wpid, _ = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    # drain any trailing output
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

            if not first_data and alive:
                now = time.monotonic()
                if now - last_splash >= 0.8:
                    last_splash = now
                    term.splash([("Claude Code", (0, 220, 120)),
                                 ("starting... %ds" % int(now - t0), (150, 150, 150)),
                                 ("(first run ~40s)", (90, 90, 90))])
            elif screen.dirty or not alive:
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
        if FREE_DESKTOP:
            _restore_ram(prev_swappiness)
    return 0


def _resume(evdev_keys):
    if evdev_keys is not None:
        try:
            evdev_keys.resume()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
