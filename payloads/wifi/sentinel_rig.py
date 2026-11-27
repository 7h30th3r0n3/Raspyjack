#!/usr/bin/env python3
"""
RaspyJack Payload -- Evil-Sentinel rig controller
=================================================
Author: 7h30th3r0n3

Drives an Evil-Sentinel parallel WiFi capture array from the RaspyJack side.
Evil-Sentinel is a set of ESP32 nodes (C3/C6 = 2.4 GHz, C5 = dual-band), each
locked to one channel, streaming raw 802.11 pcap over USB-CDC. This payload is
the on-device equivalent of the project's tools/sentinel.py controller: it
owns every node's serial port in one process, so there is no contention.

What it does, all on the Pi/CardputerZero the rig is plugged into (powered hub):
  * auto-discover sentinel nodes on /dev/serial/by-id (falls back to /dev/ttyACM*)
  * lock / hop / retune each node live from the LCD (2.4 and 5 GHz on a C5)
  * live dashboard: per-channel 2.4 GHz band chart, per-node channel/fps/total
  * MERGE every node's frames into one radiotap pcap stream, and sink it to:
      - a loot capture file  loot/sentinel/cap_<ts>.pcap   (OK toggles record)
      - a live FIFO  /tmp/sentinel.pcap  for wireshark/tshark/tcpdump/kismet
        (KEY2 toggles; attach a reader in a shell, e.g. tshark -r /tmp/sentinel.pcap)

100% passive, receive only. Nodes never transmit. Pure stdlib, no deps.

Serial line protocol (one node, USB-CDC) -- see Evil-Sentinel docs/PROTOCOL.md:
  S           start streaming pcap
  X           stop streaming
  ch N\n      lock channel N (1-14 = 2.4 GHz, 36-165 = 5 GHz on the C5)
  hop\n       sweep 2.4 GHz      hop5\n  sweep 5 GHz (C5)   hopdual\n  both (C5)
  fcs on|off  keep+flag / strip the trailing 802.11 FCS
  id          replies 'sentinel' (+ 'dualband' on a C5); used for discovery
  ping        replies 'pong'

Controls:
  UP/DOWN     select node
  LEFT/RIGHT  retune selected node (cycle HOP / 2.4 locks / 5 GHz on a C5)
  OK          start/stop recording to loot/sentinel/cap_<ts>.pcap
              (when no node is found: rescan)
  KEY1        ALL HOP  (C5 -> hop5, the rest -> hop)
  KEY2        toggle live FIFO export (/tmp/sentinel.pcap)
  KEY3        exit

SPDX-License-Identifier: GPL-3.0-or-later
"""

import os
import sys
import time
import glob
import re
import fcntl
import select
import struct
import termios
import tty
import threading
import queue
import signal
import json
import collections

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ───────────────────────── constants ──────────────────────────────────────
BYID = "/dev/serial/by-id"
PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
FIFO_PATH = "/tmp/sentinel.pcap"
# WebUI bridge: this payload is the sole owner of the rig; it publishes live
# state here and consumes control commands written by the web server.
LIVE_PATH = "/dev/shm/rj_sentinel_live.json"
CTRL_PATH = "/dev/shm/rj_sentinel_control.json"
LOOT_DIR = os.path.join(os.path.abspath(os.path.join(__file__, "..", "..", "..")),
                        "loot", "sentinel")
# Only the 5 GHz channels the ESP32-C5 can actually receive (36..112); the C5
# RX does not demodulate above ~5.56 GHz, so the upper channels are left out.
CH5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112]
# Channel codes: >=1 lock, 0 hop 2.4, -1 hop 5 GHz, -2 hop dual-band.
CYCLE_24 = [0, 1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
CYCLE_DUAL = CYCLE_24 + [-1, -2] + CH5
FCS_MODE = "off"   # strip the FCS: friendliest for kismet/aircrack, Wireshark ignores it

# ───────────────────────── serial helpers (stdlib termios) ─────────────────
def all_ports():
    if os.path.isdir(BYID):
        return sorted(glob.glob(BYID + "/*"))
    return sorted(glob.glob("/dev/ttyACM*"))

def mac_of(path):
    m = re.search(r'([0-9A-Fa-f:]{17})', os.path.basename(path))
    return m.group(1) if m else os.path.basename(path)

def _raw(fd):
    tty.setraw(fd)
    a = termios.tcgetattr(fd)
    a[2] |= (termios.CLOCAL | termios.CREAD)
    termios.tcsetattr(fd, termios.TCSANOW, a)
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)

def open_lock(port):
    """Open + exclusive flock (raises if busy). Caller owns the port until close."""
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _raw(fd)
    except Exception:
        os.close(fd)
        raise
    return fd

def read_for(fd, ms):
    end = time.time() + ms / 1000.0
    out = b""
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], max(0, end - time.time()))
        if not r:
            break
        try:
            d = os.read(fd, 4096)
            if not d:
                break
            out += d
        except OSError:
            break
    return out

def probe(port):
    """Return (is_sentinel, dualband). A busy port is assumed one of ours."""
    try:
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except Exception:
        return (False, False)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            return (True, False)        # busy = assume ours
        _raw(fd)
        os.write(fd, b"id\n")
        reply = read_for(fd, 400)
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:
            pass
        return (b"sentinel" in reply, b"dualband" in reply)
    finally:
        try:
            os.close(fd)
        except Exception:
            pass

def discover():
    """List of (mac, port, dualband) for every node that answers the id probe."""
    out = []
    for p in all_ports():
        ok, dual = probe(p)
        if ok:
            out.append((mac_of(p), p, dual))
    return out

# ───────────────────────── channel encoding ───────────────────────────────
def freq_to_ch(f):
    if f >= 4900:
        return (f - 5000) // 5          # 5 GHz
    if f == 2484:
        return 14
    if f >= 2412:
        return (f - 2412) // 5 + 1       # 2.4 GHz
    return 0

def chan_cmd(ch):
    if ch == 0:
        return b"hop\n"
    if ch == -1:
        return b"hop5\n"
    if ch == -2:
        return b"hopdual\n"
    return ("ch %d\n" % ch).encode()

def chan_label(ch):
    return {0: "HOP", -1: "H5", -2: "HD"}.get(ch, "c%d" % ch)

# ───────────────────────── node reader ─────────────────────────────────────
class Node:
    def __init__(self, mac, port, channel, merged_q, dual=False):
        self.mac = mac
        self.port = port
        self.channel = channel
        self.dual = dual
        self.merged = merged_q
        self.fd = None
        self.thread = None
        self.running = False
        self.total = 0
        self._win = collections.deque()     # recent frame timestamps (fps)
        self.last_freq = 0
        self.chan_count = {}                 # frames per real channel (hopping-aware)
        self.hist = collections.deque([0] * 60, maxlen=60)   # per-second fps, web sparkline

    def cycle(self):
        return CYCLE_DUAL if self.dual else CYCLE_24

    def label(self):
        return chan_label(self.channel)

    def open(self):
        self.fd = open_lock(self.port)
        os.write(self.fd, b"X")
        read_for(self.fd, 120)
        os.write(self.fd, b"fcs off\n" if FCS_MODE == "off" else b"fcs on\n")
        read_for(self.fd, 120)
        os.write(self.fd, chan_cmd(self.channel))
        read_for(self.fd, 120)
        os.write(self.fd, b"S")

    def set_channel(self, ch):
        """Retune a live node; the firmware applies it without a stream restart."""
        if self.fd is None:
            return
        try:
            os.write(self.fd, chan_cmd(ch))
            self.channel = ch
        except OSError:
            pass

    def step_channel(self, direction):
        cyc = self.cycle()
        try:
            i = cyc.index(self.channel)
        except ValueError:
            i = 0
        self.set_channel(cyc[(i + direction) % len(cyc)])

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def fps(self):
        now = time.time()
        while self._win and now - self._win[0] > 1.0:
            self._win.popleft()
        return len(self._win)

    def _run(self):
        buf = b""
        synced = False
        while self.running:
            r, _, _ = select.select([self.fd], [], [], 0.3)
            if not r:
                continue
            try:
                d = os.read(self.fd, 8192)
            except OSError:
                break
            if not d:
                continue
            buf += d
            if not synced:                              # skip this node's pcap global header
                i = buf.find(PCAP_MAGIC)
                if i < 0:
                    if len(buf) > 65536:
                        buf = buf[-64:]
                    continue
                buf = buf[i + 24:]
                synced = True
            while len(buf) >= 16:                        # 16-byte record header + caplen payload
                ts, us, caplen, orig = struct.unpack("<IIII", buf[:16])
                if caplen == 0 or caplen > 4096:
                    buf = buf[1:]                        # resync on garbage
                    continue
                if len(buf) < 16 + caplen:
                    break
                rec = buf[16:16 + caplen]
                buf = buf[16 + caplen:]
                self.total += 1
                self._win.append(time.time())
                if caplen >= 12:                         # radiotap freq at offset 10
                    f = struct.unpack("<H", rec[10:12])[0]
                    self.last_freq = f
                    c = freq_to_ch(f)
                    if c:
                        self.chan_count[c] = self.chan_count.get(c, 0) + 1
                try:
                    self.merged.put_nowait(rec)
                except queue.Full:
                    pass

    def stop(self):
        self.running = False
        try:
            os.write(self.fd, b"X")
        except Exception:
            pass
        try:
            if self.fd is not None:
                os.close(self.fd)
        except Exception:
            pass

# ───────────────────────── merged pcap writer ──────────────────────────────
def le32(v):
    return struct.pack("<I", v)

def le16(v):
    return struct.pack("<H", v)

def global_header():
    # magic, ver 2.4, tz 0, sigfigs 0, snaplen 525, linktype 127 (radiotap)
    return le32(0xa1b2c3d4) + le16(2) + le16(4) + le32(0) + le32(0) + le32(525) + le32(127)

class Sink:
    """Owns the merged-pcap sinks (a loot file and/or a live FIFO). The UI thread
    flips want flags; this writer thread reconciles the real fds and drains the
    queue, so file I/O never blocks the node readers."""

    def __init__(self, merged_q, stop_evt):
        self.q = merged_q
        self.stop = stop_evt
        self.lock = threading.Lock()
        self.want_file = False
        self.file_path = None
        self.want_fifo = False
        self.file_fd = None
        self.fifo_fd = None
        self.file_frames = 0
        self.fifo_ready = False

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    # -- toggles (UI thread or web control) ----------------------------------
    def set_file(self, on):
        """Open/close the loot file right here so recording starts the instant it
        is requested, with no window where early frames are dropped between the
        toggle and a lazy open in the writer thread. Returns the resulting state."""
        with self.lock:
            if not on:
                self.want_file = False
                if self.file_fd is not None:
                    try:
                        os.close(self.file_fd)
                    except Exception:
                        pass
                    self.file_fd = None
                return False
            if self.want_file:
                return True
            os.makedirs(LOOT_DIR, exist_ok=True)
            self.file_path = os.path.join(LOOT_DIR, "cap_%s.pcap" % time.strftime("%Y%m%d_%H%M%S"))
            self.file_frames = 0
            try:
                self.file_fd = os.open(self.file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
                os.write(self.file_fd, global_header())
                self.want_file = True
                return True
            except OSError:
                self.file_fd = None
                return False

    def toggle_file(self):
        return self.set_file(not self.want_file)

    def set_fifo(self, on):
        with self.lock:
            self.want_fifo = bool(on)
            if not self.want_fifo:
                self.fifo_ready = False
            return self.want_fifo

    def toggle_fifo(self):
        return self.set_fifo(not self.want_fifo)

    def _reconcile(self):
        """Writer-thread side: only the FIFO is reconciled here (the loot file is
        opened/closed by toggle_file on the UI thread). The FIFO must stay lazy:
        O_WRONLY on a FIFO gives ENXIO until a reader attaches, so just retry."""
        with self.lock:
            wfifo = self.want_fifo
        if wfifo and self.fifo_fd is None:
            try:
                if not os.path.exists(FIFO_PATH):
                    os.mkfifo(FIFO_PATH)
                fd = os.open(FIFO_PATH, os.O_WRONLY | os.O_NONBLOCK)
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
                os.write(fd, global_header())
                self.fifo_fd = fd
                self.fifo_ready = True
            except OSError:
                pass                                    # no reader yet; retry next loop
        elif (not wfifo) and self.fifo_fd is not None:
            try:
                os.close(self.fifo_fd)
            except Exception:
                pass
            self.fifo_fd = None

    def _run(self):
        while not self.stop.is_set():
            self._reconcile()
            try:
                rec = self.q.get(timeout=0.2)
            except queue.Empty:
                continue
            ms = time.time()
            hdr = le32(int(ms)) + le32(int((ms % 1) * 1e6)) + le32(len(rec)) + le32(len(rec))
            blob = hdr + rec
            with self.lock:                             # file_fd is shared with the UI thread
                if self.file_fd is not None:
                    try:
                        os.write(self.file_fd, blob)
                        self.file_frames += 1
                    except OSError:
                        pass
            if self.fifo_fd is not None:
                try:
                    os.write(self.fifo_fd, blob)
                except (BrokenPipeError, OSError):      # reader went away
                    try:
                        os.close(self.fifo_fd)
                    except Exception:
                        pass
                    self.fifo_fd = None
                    self.fifo_ready = False
        # shutdown
        for fd in (self.file_fd, self.fifo_fd):
            try:
                if fd is not None:
                    os.close(fd)
            except Exception:
                pass
        try:
            if os.path.exists(FIFO_PATH):
                os.unlink(FIFO_PATH)
        except Exception:
            pass

# ───────────────────────── LCD UI ──────────────────────────────────────────
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for _p in PINS.values():
    GPIO.setup(_p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height

F_HDR = scaled_font(9)
F_ROW = scaled_font(8)
F_SM = scaled_font(6)

_running = True
def _stop(*_):
    global _running
    _running = False
signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)

def human(n):
    if n >= 1000:
        return "%.1fk" % (n / 1000.0)
    return str(n)

def draw_nodes(nodes, sel, sink, msg=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    ftot = sum(n.fps() for n in nodes)
    tot = sum(n.total for n in nodes)

    # header
    d.text((2, 0), "SENTINEL", font=F_HDR, fill="#2de0c8")
    d.text((58, 1), "%dn %df/s" % (len(nodes), ftot), font=F_SM, fill="#cfe9e0")
    rec = "REC" if sink.want_file else ""
    fifo = "PIPE" if sink.want_fifo else ""
    tag = (rec + (" " if rec and fifo else "") + fifo)
    if tag:
        d.text((98, 1), tag, font=F_SM, fill="#ff5d5d" if rec else "#f2c744")
    d.line((2, 11, 124, 11), fill="#1c2a36")

    # 2.4 GHz band chart (channels 1..13), tallied from each frame's real channel
    tot_by = {c: 0 for c in range(1, 14)}
    for n in nodes:
        for c, v in n.chan_count.items():
            if 1 <= c <= 13:
                tot_by[c] += v
    peak = max(list(tot_by.values()) + [1])
    x0, cw, base, bh = 4, 9, 30, 16
    for i, c in enumerate(range(1, 14)):
        x = x0 + i * cw
        h = int(round(tot_by[c] / peak * bh))
        on = tot_by[c] > 0
        col = "#39d98a" if on else "#17323a"
        if h > 0:
            d.rectangle((x, base - h, x + 6, base), fill=col)
        if c in (1, 6, 11):
            d.text((x - 1, base + 1), str(c), font=F_SM, fill="#5f7d78")

    # node list, windowed around the selection
    ny = 42
    rh = 12
    vis = max(1, (HEIGHT // (rh * (HEIGHT / 128.0))))  # approximate; clamp below
    vis = 6
    top = 0
    if len(nodes) > vis:
        top = min(max(0, sel - vis // 2), len(nodes) - vis)
    for row, n in enumerate(nodes[top:top + vis]):
        idx = top + row
        y = ny + row * rh
        if idx == sel:
            d.rectangle((1, y - 1, 126, y + rh - 2), fill="#0d2a26")
            d.text((2, y), ">", font=F_ROW, fill="#2de0c8")
        seen = freq_to_ch(n.last_freq)
        d.text((8, y), n.mac[-5:], font=F_ROW, fill="#dff5ee")
        d.text((44, y), n.label(), font=F_ROW, fill="#2de0c8")
        f = n.fps()
        fcol = "#ff5d5d" if f > 80 else "#f2c744" if f > 30 else "#39d98a"
        d.text((66, y), "%d" % f, font=F_ROW, fill=fcol)
        d.text((86, y), human(n.total), font=F_ROW, fill="#5f7d78")
        if n.dual:
            d.text((112, y), "5G", font=F_SM, fill="#2de0c8")
        if seen and n.channel >= 1 and seen != n.channel:
            d.text((112, y + 5), "!c%d" % seen, font=F_SM, fill="#ff5d5d")

    # footer
    d.line((2, 118, 124, 118), fill="#1c2a36")
    foot = msg or "OK rec  K1 hop  K2 pipe  K3 exit"
    d.text((2, 120), foot, font=F_SM, fill="#5f7d78")
    LCD.LCD_ShowImage(img, 0, 0)

def draw_center(lines, color="#cfe9e0"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((2, 0), "SENTINEL", font=F_HDR, fill="#2de0c8")
    d.line((2, 11, 124, 11), fill="#1c2a36")
    y = 40
    for ln in lines:
        d.text((6, y), ln, font=F_ROW, fill=color)
        y += 14
    LCD.LCD_ShowImage(img, 0, 0)

# ───────────────────────── WebUI bridge ────────────────────────────────────
def build_live(nodes, sink, t0):
    """Snapshot the rig state in the same shape Evil-Sentinel's web /stats uses,
    plus record/FIFO status, so web/sentinel.html can render it directly."""
    b24 = [0] * 13                                   # channels 1..13, hopping-aware
    b5 = {c: 0 for c in CH5}
    for n in nodes:
        for c, cnt in n.chan_count.items():
            if 1 <= c <= 13:
                b24[c - 1] += cnt
            elif c in b5:
                b5[c] += cnt
    return {
        "ts": time.time(),
        "running": True,
        "nodes": [{
            "mac": n.mac, "ch": n.channel, "label": n.label(), "fps": n.fps(),
            "total": n.total, "ch_seen": freq_to_ch(n.last_freq), "dual": n.dual,
            "hist": list(n.hist),
        } for n in nodes],
        "total": sum(n.total for n in nodes),
        "fps_total": sum(n.fps() for n in nodes),
        "uptime": time.time() - t0,
        "band24": b24, "ch5": CH5, "band5": [b5[c] for c in CH5],
        "has5": any(n.dual for n in nodes),
        "rec": sink.want_file, "rec_frames": sink.file_frames,
        "rec_path": os.path.basename(sink.file_path or "") if sink.want_file else "",
        "fifo": sink.want_fifo, "fifo_ready": sink.fifo_ready, "fifo_path": FIFO_PATH,
    }

def write_live(state):
    try:
        tmp = LIVE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, LIVE_PATH)
    except Exception:
        pass

def apply_control(nodes, sink):
    """Consume one control command written by the web server (set / allhop /
    record / fifo), apply it, and delete the file. Validated server-side too."""
    try:
        with open(CTRL_PATH) as f:
            cmd = json.load(f)
    except (FileNotFoundError, ValueError):
        return
    except Exception:
        return
    finally:
        try:
            os.unlink(CTRL_PATH)
        except OSError:
            pass
    act = cmd.get("action")
    if act == "allhop":
        for n in nodes:
            n.set_channel(-1 if n.dual else 0)
    elif act == "set":
        mac = cmd.get("mac")
        ch = cmd.get("ch")
        if isinstance(ch, int):
            for n in nodes:
                if n.mac != mac:
                    continue
                ok = ch == 0 or (1 <= ch <= 14)               # hop + 2.4 locks: any node
                if n.dual:
                    ok = ok or ch in (-1, -2) or ch in CH5     # 5 GHz only on dual-band
                if ok:
                    n.set_channel(ch)
    elif act == "record":
        sink.set_file(bool(cmd.get("on")))
    elif act == "fifo":
        sink.set_fifo(bool(cmd.get("on")))


# ───────────────────────── main ────────────────────────────────────────────
def main():
    merged_q = queue.Queue(maxsize=20000)
    stop_evt = threading.Event()
    sink = Sink(merged_q, stop_evt)
    sink.start()
    nodes = []

    def open_nodes(raw):
        out = []
        for (mac, port, dual) in raw:
            ch = -1 if dual else 0                      # band-aware default: everyone hops
            n = Node(mac, port, ch, merged_q, dual=dual)
            try:
                n.open()
                n.start()
                out.append(n)
                print("node %s -> %s (%s)%s" % (mac, n.label(), port,
                      " dualband" if dual else ""))
            except Exception as e:
                print("  ! %s busy/err: %s" % (mac, e))
        return out

    draw_center(["Scanning USB for", "sentinel nodes..."])
    nodes = open_nodes(discover())

    sel = 0
    last_draw = 0.0
    DEBOUNCE = 0.14
    last_btn = 0.0
    t0 = time.time()
    last_live = 0.0
    last_ctrl = 0.0
    last_sample = time.time()

    try:
        while _running:
            now = time.time()

            # WebUI bridge: apply any pending web command, sample for sparklines,
            # publish live state. Cheap enough to run every loop / sub-second.
            if now - last_ctrl >= 0.2:
                last_ctrl = now
                if nodes:
                    apply_control(nodes, sink)
            if now - last_sample >= 1.0:
                last_sample = now
                for n in nodes:
                    n.hist.append(n.fps())
            if now - last_live >= 0.5:
                last_live = now
                if nodes:
                    write_live(build_live(nodes, sink, t0))

            btn = get_button(PINS, GPIO)
            if btn and now - last_btn >= DEBOUNCE:
                last_btn = now
                if btn == "KEY3":
                    break
                if not nodes:
                    if btn == "OK":                      # rescan
                        draw_center(["Scanning USB for", "sentinel nodes..."])
                        nodes = open_nodes(discover())
                        sel = 0
                else:
                    if btn == "UP":
                        sel = (sel - 1) % len(nodes)
                    elif btn == "DOWN":
                        sel = (sel + 1) % len(nodes)
                    elif btn == "LEFT":
                        nodes[sel].step_channel(-1)
                    elif btn == "RIGHT":
                        nodes[sel].step_channel(+1)
                    elif btn == "OK":
                        sink.toggle_file()
                    elif btn == "KEY1":
                        for n in nodes:
                            n.set_channel(-1 if n.dual else 0)
                    elif btn == "KEY2":
                        sink.toggle_fifo()
                last_draw = 0.0                          # force immediate redraw

            if now - last_draw >= 0.33:
                last_draw = now
                if not nodes:
                    draw_center(["No sentinel node.", "Plug the rig in,",
                                 "OK = rescan  K3 = exit"], color="#f2c744")
                else:
                    msg = ""
                    if sink.want_fifo:
                        msg = ("PIPE: reader attached" if sink.fifo_ready
                               else "PIPE: waiting reader")
                    elif sink.want_file:
                        msg = "REC %s fr" % human(sink.file_frames)
                    draw_nodes(nodes, sel, sink, msg=msg)
            time.sleep(0.03)
    finally:
        stop_evt.set()
        for n in nodes:
            n.stop()
        time.sleep(0.3)                                  # let the sink flush/close
        try:
            os.unlink(LIVE_PATH)                         # tell the WebUI the rig is gone
        except OSError:
            pass
        LCD.LCD_Clear()
        GPIO.cleanup()

if __name__ == "__main__":
    main()
