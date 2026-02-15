#!/usr/bin/env python3
"""
Latency/Jitter Monitor (RaspyJack payload)
==========================================
Measures TCP connect RTT (no monitor mode), estimates jitter, and shows a
rolling graph on the 128x128 LCD. Designed to work over Ethernet or managed
Wi‑Fi without special privileges.

Controls
--------
OK      : Start/Pause measurements
KEY2    : Reset stats/history
KEY3    : Exit (clean up LCD/GPIO)
"""

import os, sys, time, signal, socket, statistics, json
import requests
from collections import deque

# Ensure local imports work when launched directly from payloads/
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button


# --------------------------- Configuration ---------------------------------

WIDTH, HEIGHT = 128, 128
HISTORY_LEN = 64              # number of points to show in the sparkline
PROBE_TIMEOUT_S = 1.0         # TCP connect timeout per probe
JITTER_WINDOW = 10            # last N samples to compute jitter
TICK_INTERVAL = 0.15          # UI refresh cadence (seconds)


# --------------------------- Targets discovery ------------------------------

def get_default_route() -> tuple[str | None, str | None]:
    try:
        # Example: default via 192.168.1.1 dev wlan0 proto dhcp metric 600
        import subprocess
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "default" and parts[1] == "via":
                gw = parts[2]
                # find device after 'dev'
                dev = None
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        dev = parts[idx + 1]
                return gw, dev
    except Exception:
        pass
    return None, None


def get_primary_dns() -> str | None:
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except Exception:
        pass
    return None


class Target:
    def __init__(self, label: str, host: str, port: int, *, method: str = "tcp", iface: str | None = None):
        self.label = label
        self.host = host
        self.port = port
        self.method = method  # "tcp" or "icmp"
        self.iface = iface
        self.history: deque[float | None] = deque(maxlen=HISTORY_LEN)
        self.attempts = 0
        self.failures = 0

    def record(self, rtt_ms: float | None) -> None:
        self.attempts += 1
        if rtt_ms is None:
            self.failures += 1
        self.history.append(rtt_ms)

    def last_rtt(self) -> float | None:
        for v in reversed(self.history):
            if v is not None:
                return v
        return None

    def jitter_ms(self) -> float | None:
        values = [v for v in list(self.history)[-JITTER_WINDOW:] if v is not None]
        if len(values) < 2:
            return None
        try:
            return statistics.pstdev(values)
        except statistics.StatisticsError:
            return None

    def loss_pct(self) -> float:
        if self.attempts == 0:
            return 0.0
        return (self.failures / self.attempts) * 100.0


def build_targets() -> list[Target]:
    t: list[Target] = []
    gw, dev = get_default_route()
    if gw:
        # Probe gateway with ICMP; ARP fallback will use 'dev' if available
        t.append(Target("Gateway", gw, 0, method="icmp", iface=dev))
    dns = get_primary_dns()
    if dns:
        t.append(Target("DNS", dns, 53))
    # Public references
    t.append(Target("1.1.1.1", "1.1.1.1", 53))
    t.append(Target("8.8.8.8", "8.8.8.8", 53))
    return t


# ------------------------------- Probing ------------------------------------

def tcp_rtt_ms(host: str, port: int, timeout_s: float) -> float | None:
    start = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        s.connect((host, port))
        end = time.perf_counter()
        return (end - start) * 1000.0
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def icmp_rtt_ms(host: str, timeout_s: float) -> float | None:
    """Measure RTT using system ping (no raw sockets needed). Returns ms or None."""
    try:
        import subprocess, math, re
        timeout = max(1, int(math.ceil(timeout_s)))
        # -n numeric, -c 1 one packet, -w timeout seconds
        out = subprocess.check_output(["ping", "-n", "-c", "1", "-w", str(timeout), host], text=True, stderr=subprocess.STDOUT)
        # Look for time=XX ms
        m = re.search(r"time=([0-9.]+)\s*ms", out)
        if m:
            return float(m.group(1))
    except Exception:
        return None
    return None


def arp_rtt_ms(host: str, iface: str | None, timeout_s: float) -> float | None:
    """Best-effort ARP probe using system arping. Returns ms or None."""
    try:
        import subprocess, math, re
        timeout = max(1, int(math.ceil(timeout_s)))
        cmd = ["arping", "-c", "1", "-w", str(timeout), host]
        if iface:
            cmd = ["arping", "-I", iface, "-c", "1", "-w", str(timeout), host]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        # Example: Unicast reply from 192.168.1.1 [..]  1.123ms
        m = re.search(r"\s([0-9.]+)ms", out)
        if m:
            return float(m.group(1))
    except Exception:
        return None
    return None


# --------------------------- LCD + Buttons ----------------------------------

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)
def _font(size: int):
    try:
        return ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', size)
    except Exception:
        return ImageFont.load_default()
font_small = _font(8)
font_medium = _font(10)


def color_for_value(ms: float | None) -> str:
    if ms is None:
        return "#888888"
    if ms <= 30:
        return "#00CC66"  # green
    if ms <= 80:
        return "#FFCC00"  # yellow
    return "#FF5555"      # red


def draw_header(running: bool) -> None:
    draw.rectangle((0, 0, WIDTH, 12), fill="#000020")
    status = "RUN" if running else "PAUSE"
    draw.text((2, 2), f"Latency/Jitter [{status}]", font=font_small, fill="#AACCFF")


def draw_targets(targets: list[Target]) -> None:
    # Per-target rows with last RTT, jitter and sparkline
    top = 14
    row_h = 28
    plot_w = WIDTH - 4
    for i, t in enumerate(targets[:4]):  # 4 rows max on 128px
        y0 = top + i * row_h
        y1 = y0 + row_h - 2
        draw.rectangle((0, y0, WIDTH, y1), fill="#000000")

        last = t.last_rtt()
        jit = t.jitter_ms()
        loss = t.loss_pct()
        draw.text((2, y0), f"{t.label}", font=font_medium, fill="#FFFFFF")
        rtt_text = f"{last:.0f}ms" if last is not None else "--"
        jit_text = f"J{jit:.0f}" if jit is not None else "J--"
        loss_text = f"L{loss:.0f}%" if loss > 0 else "L0%"
        draw.text((70, y0), f"{rtt_text} {jit_text} {loss_text}", font=font_small, fill=color_for_value(last))

        # Sparkline area
        hx = list(t.history)
        if not hx:
            continue
        # Determine scale: use 95th percentile or max of window, min 10ms
        vals = [v for v in hx if v is not None]
        vmax = max(vals) if vals else 10.0
        vmax = max(10.0, min(vmax, 500.0))
        # Plot left->right
        px_w = plot_w // HISTORY_LEN
        base_y = y1 - 4
        for x, v in enumerate(hx[-HISTORY_LEN:]):
            x0 = 2 + x * px_w
            x1 = x0 + max(1, px_w - 1)
            if v is None:
                # draw a faint dot for loss
                draw.line((x0, base_y, x1, base_y), fill="#333333")
            else:
                h = int((v / vmax) * (row_h - 12))
                h = max(1, min(h, row_h - 12))
                draw.rectangle((x0, base_y - h, x1, base_y), fill=color_for_value(v))


def show() -> None:
    LCD.LCD_ShowImage(canvas, 0, 0)


# ------------------------------ Logging -------------------------------------

BASE_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
LOOT_FILE = os.path.join(BASE_DIR, 'loot', 'latency_jitter.csv')


def ensure_loot():
    try:
        os.makedirs(os.path.dirname(LOOT_FILE), exist_ok=True)
        if not os.path.exists(LOOT_FILE):
            with open(LOOT_FILE, 'w') as f:
                f.write('ts,label,host,port,rtt_ms,ok\n')
    except Exception:
        pass


def log_sample(t: Target, rtt_ms: float | None) -> None:
    try:
        with open(LOOT_FILE, 'a') as f:
            ts = int(time.time())
            ok = 1 if rtt_ms is not None else 0
            val = f"{rtt_ms:.2f}" if rtt_ms is not None else ""
            f.write(f"{ts},{t.label},{t.host},{t.port},{val},{ok}\n")
    except Exception:
        pass


# ------------------------------ Main loop -----------------------------------

running = True
measuring = True
targets = build_targets()
ensure_loot()


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def button_pressed() -> str | None:
    return get_button(PINS, GPIO)


def wait_release(btn: str | None) -> None:
    if not btn:
        return
    pin = PINS.get(btn)
    if pin is None:
        return
    try:
        while GPIO.input(pin) == 0:
            time.sleep(0.03)
    except Exception:
        pass


# ------------------------------ Discord summary ------------------------------

BASE_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))


def _read_webhook() -> str | None:
    path = os.path.join(BASE_DIR, 'discord_webhook.txt')
    try:
        with open(path, 'r') as f:
            url = f.read().strip()
            if url and url.startswith("https://discord.com/api/webhooks/"):
                return url
            return None
    except Exception:
        return None


def _send_discord(webhook: str, message: str) -> bool:
    """Send message like Nmap payload (requests, form-encoded)."""
    try:
        resp = requests.post(webhook, data={"content": message}, timeout=10)
        # Discord webhooks return 204 No Content on success
        return resp.status_code == 204
    except Exception:
        return False


def _percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    idx = max(0, min(len(values) - 1, int(round(p * (len(values) - 1)))))
    return float(values[idx])


def _build_summary(targets: list[Target]) -> str:
    lines: list[str] = ["📊 Network Quality (1m)"]
    for t in targets:
        vals = [v for v in list(t.history) if v is not None]
        last = t.last_rtt()
        avg = (sum(vals) / len(vals)) if vals else None
        p95 = _percentile(vals, 0.95)
        jit = t.jitter_ms()
        loss = t.loss_pct()

        def f(ms):
            return f"{ms:.0f}ms" if ms is not None else "--"

        lines.append(f"- {t.label}: last {f(last)}, avg {f(avg)}, p95 {f(p95)}, J {f(jit)}, L {loss:.0f}%")
    return "\n".join(lines)


try:
    last_probe_idx = 0
    webhook_url = _read_webhook()
    last_summary_ts = 0.0
    draw_header(measuring)
    draw_targets(targets)
    show()

    while running:
        # Handle buttons
        btn = button_pressed()
        if btn == "OK":
            measuring = not measuring
            wait_release(btn)
        elif btn == "KEY2":
            # reset stats
            for t in targets:
                t.history.clear()
                t.attempts = 0
                t.failures = 0
            wait_release(btn)
        elif btn == "KEY3":
            wait_release(btn)
            break

        # Do one probe per tick to keep UI responsive
        if measuring and targets:
            t = targets[last_probe_idx % len(targets)]
            if t.method == "icmp":
                rtt = icmp_rtt_ms(t.host, PROBE_TIMEOUT_S)
                if rtt is None:
                    # optional ARP fallback on LAN
                    rtt = arp_rtt_ms(t.host, t.iface, PROBE_TIMEOUT_S)
            else:
                rtt = tcp_rtt_ms(t.host, t.port, PROBE_TIMEOUT_S)
            t.record(rtt)
            log_sample(t, rtt)
            last_probe_idx += 1

        # Redraw
        draw_header(measuring)
        draw_targets(targets)
        show()
        # Every ~60s, send a Discord summary if configured
        if webhook_url:
            now = time.time()
            if now - last_summary_ts >= 60.0:
                summary = _build_summary(targets)
                _send_discord(webhook_url, summary)
                last_summary_ts = now
        time.sleep(TICK_INTERVAL)

except Exception as exc:
    # minimal error print; RaspyJack will capture stdout
    print(f"[latency_jitter_monitor] ERROR: {exc}")

finally:
    try:
        LCD.LCD_Clear()
    except Exception:
        pass
    GPIO.cleanup()
