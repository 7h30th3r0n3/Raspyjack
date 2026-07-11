#!/usr/bin/env python3
"""
raspyjack_touch.py — touch input daemon for the Waveshare 3.5" (35a).

Reads the ADS7846 touchscreen, maps each tap through the calibration to a screen
coordinate, hit-tests the on-screen control deck (see touch_deck.py), and sends
the corresponding button event to RaspyJack's existing input socket — the SAME
channel the Web UI uses (rj_input.py). So RaspyJack needs zero input-code changes:
navigation, context KEY1/2/3 actions, combos, etc. all work as if a joystick/HAT
button were pressed.

Run alongside a running RaspyJack (which owns the socket):
    sudo python3 raspyjack_touch.py

Requires a calibration file (run touch_calibrate.py once):
    /root/Raspyjack/config/touch_cal.json   (override with RJ_TOUCH_CAL)
"""

import os
import sys
import json
import time
import socket
import select

try:
    import evdev
    from evdev import ecodes
except Exception as e:
    print("Missing python3-evdev:", e)
    sys.exit(1)

import touch_deck

CAL_PATH = os.environ.get("RJ_TOUCH_CAL", "/root/Raspyjack/config/touch_cal.json")
SOCK_PATH = os.environ.get("RJ_INPUT_SOCK", "/dev/shm/rj_input.sock")
DEBOUNCE = float(os.environ.get("RJ_TOUCH_DEBOUNCE", "0.15"))
# Idle backlight dim: 0 disables (default). Set e.g. 120 to blank after 2 min idle.
IDLE_SECS = float(os.environ.get("RJ_IDLE_DIM_SECONDS", "0") or 0)


class Backlight:
    """Optional backlight control via /sys/class/backlight (auto-detected).

    Lets the panel dim after idle and wake on touch, without touching RaspyJack:
    it keeps rendering to the framebuffer underneath while the backlight is off.
    A no-op if the kernel exposes no controllable backlight.
    """

    def __init__(self):
        self.path = None
        self.max = 255
        base = "/sys/class/backlight"
        try:
            for name in sorted(os.listdir(base)):
                p = os.path.join(base, name)
                if os.path.exists(os.path.join(p, "brightness")):
                    self.path = p
                    try:
                        self.max = int(open(os.path.join(p, "max_brightness")).read())
                    except Exception:
                        pass
                    break
        except Exception:
            pass
        self.available = self.path is not None

    def _write(self, fname, val):
        try:
            with open(os.path.join(self.path, fname), "w") as f:
                f.write(str(val))
        except Exception:
            pass

    def on(self):
        if self.available:
            self._write("bl_power", 0)          # FB_BLANK_UNBLANK
            self._write("brightness", self.max)

    def off(self):
        if self.available:
            self._write("brightness", 0)
            self._write("bl_power", 1)          # FB_BLANK_POWERDOWN


def load_cal():
    """Return (affine, fb). Wait (don't crash) if the calibration file isn't there
    yet — lets the service run before the user has calibrated, then pick it up."""
    warned = False
    while True:
        try:
            with open(CAL_PATH) as f:
                cal = json.load(f)
            return cal["affine"], cal.get("fb", [480, 320, 16])
        except Exception as e:
            if not warned:
                print(f"No usable calibration at {CAL_PATH}: {e}")
                print("Waiting… calibrate with: sudo systemctl stop raspyjack && "
                      "sudo python3 touch_calibrate.py  (service will resume after)")
                warned = True
            time.sleep(3)


def find_touch(retries=15):
    """Find the ADS7846 touch device, retrying briefly (it can appear a beat late
    at boot)."""
    for _ in range(retries):
        for path in evdev.list_devices():
            try:
                d = evdev.InputDevice(path)
            except Exception:
                continue
            n = (d.name or "").lower()
            if "ads7846" in n or "xpt2046" in n or "touch" in n:
                return d
        time.sleep(1)
    print("No touchscreen device found."); sys.exit(1)


def apply_affine(coef, rx, ry):
    a, b, c, d, e, f = coef
    return a * rx + b * ry + c, d * rx + e * ry + f


class Sender:
    """Datagram sender to RaspyJack's rj_input socket (same as the Web UI)."""

    def __init__(self, path):
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    def _send(self, button, state):
        msg = json.dumps({"type": "input", "button": button, "state": state}).encode()
        try:
            self.sock.sendto(msg, self.path)
            return True
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            return False  # RaspyJack not up yet / socket missing

    def tap(self, button):
        """Emit a press then release so rj_input's held-button set doesn't stick."""
        ok = self._send(button, "press")
        time.sleep(0.02)
        self._send(button, "release")
        return ok


def main():
    coef, fb = load_cal()
    fb_w, fb_h = fb[0], fb[1]
    # UI is a square (fb_h wide) on the left; the deck fills the rest on the right.
    deck_x0 = fb_h
    deck_w = fb_w - fb_h
    rects = touch_deck.button_rects(deck_w, fb_h)

    dev = find_touch()
    sender = Sender(SOCK_PATH)
    bl = Backlight()
    print(f"touch={dev.path} ({dev.name!r})  fb={fb_w}x{fb_h}  "
          f"deck x>={deck_x0} w={deck_w}  socket={SOCK_PATH}")
    print("Deck buttons:", ", ".join(f"{n}{r}" for n, r in rects.items()))
    if IDLE_SECS > 0:
        print(f"Idle-dim: after {IDLE_SECS:.0f}s — backlight "
              + (f"ctrl={bl.path}" if bl.available
                 else "NOT controllable, idle-dim disabled"))
    else:
        print("Idle-dim: disabled (set RJ_IDLE_DIM_SECONDS to enable)")

    xs, ys = [], []
    x = y = None
    touching = False
    last_emit = 0.0
    last_activity = time.monotonic()
    dimmed = False
    consume_wake = False
    idle_on = IDLE_SECS > 0 and bl.available

    while True:
        r, _, _ = select.select([dev.fd], [], [], 1.0)
        now = time.monotonic()
        # Idle-dim tick (the 1s select timeout gives us a steady heartbeat).
        if idle_on and not dimmed and (now - last_activity) > IDLE_SECS:
            bl.off(); dimmed = True
        if not r:
            continue
        for ev in dev.read():
            if ev.type == ecodes.EV_ABS:
                if ev.code == ecodes.ABS_X:
                    x = ev.value
                elif ev.code == ecodes.ABS_Y:
                    y = ev.value
                if touching and x is not None and y is not None:
                    xs.append(x); ys.append(y)
            elif ev.type == ecodes.EV_KEY and ev.code == ecodes.BTN_TOUCH:
                if ev.value:              # finger down
                    touching = True
                    xs, ys = [], []
                    last_activity = now
                    if dimmed:            # first touch just wakes the screen
                        bl.on(); dimmed = False
                        consume_wake = True
                else:                     # finger up -> resolve the tap
                    touching = False
                    if consume_wake:      # this touch only woke the panel; no button
                        consume_wake = False
                        xs, ys = [], []
                        continue
                    if not xs:
                        continue
                    if len(xs) > 6:
                        xs, ys = xs[2:-2], ys[2:-2]
                    rx, ry = sum(xs) / len(xs), sum(ys) / len(ys)
                    sx, sy = apply_affine(coef, rx, ry)
                    if sx < deck_x0:
                        continue          # tap landed on the UI area, not the deck
                    btn = touch_deck.hit_test(rects, sx - deck_x0, sy)
                    if not btn:
                        continue
                    if now - last_emit < DEBOUNCE:
                        continue
                    last_emit = now
                    last_activity = now
                    ok = sender.tap(btn)
                    print(f"  tap screen=({sx:.0f},{sy:.0f}) -> {btn}"
                          f"{'' if ok else '  [socket unavailable]'}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
