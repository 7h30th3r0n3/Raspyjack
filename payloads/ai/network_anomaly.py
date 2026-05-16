#!/usr/bin/env python3
"""
RaspyJack Payload -- Network Anomaly Detector
===============================================
Author: 7h30th3r0n3

ML-based network traffic anomaly detection.
Learns normal traffic patterns, then alerts on anomalies.
Uses Isolation Forest (sklearn) for unsupervised detection.

Controls:
  OK          Start/Stop monitoring
  UP/DOWN     Switch view (Live / Alerts / Stats)
  KEY1        Train model on current traffic (learn normal)
  KEY2        Clear alerts
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import struct
import json
from datetime import datetime
from collections import deque, Counter

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

time.sleep(0.1)
_STUCK_PINS = {name for name, pin in PINS.items() if GPIO.input(pin) == 0}

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(12)

DEBOUNCE = 0.20
MODEL_PATH = "/root/Raspyjack/loot/AI/anomaly_model.pkl"
ALERTS_PATH = "/root/Raspyjack/loot/AI/anomaly_alerts.json"
WINDOW_SEC = 10

_running = True
_monitoring = False
_model = None
_trained = False

C_BG = (5, 0, 10)
C_HEAD = (40, 0, 20)
C_RED = (255, 50, 50)
C_GREEN = (0, 220, 80)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_DARK = (15, 10, 20)
C_YELLOW = (255, 200, 0)
C_PURPLE = (180, 80, 255)
C_CYAN = (0, 200, 220)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    btn = get_button(PINS, GPIO)
    if btn and btn in _STUCK_PINS:
        return None
    return btn


def _ensure_sklearn():
    try:
        from sklearn.ensemble import IsolationForest
        return True
    except ImportError:
        pass
    _show_status("Installing sklearn...", C_YELLOW)
    r = subprocess.run(
        ["pip3", "install", "--break-system-packages", "scikit-learn"],
        capture_output=True, timeout=300)
    return r.returncode == 0


def _show_status(msg, color=C_PURPLE):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2), msg, font=font, fill=color,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, H // 2 - 7), msg, font=font, fill=color)
    else:
        d.text((4, 55), msg[:17], font=font, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)


class TrafficFeatures:
    """Extract features from network traffic in time windows."""

    def __init__(self):
        self.packets = deque(maxlen=5000)
        self.lock = threading.Lock()

    def add_packet(self, size, proto, src_port, dst_port, flags):
        with self.lock:
            self.packets.append({
                "ts": time.time(),
                "size": size,
                "proto": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags": flags,
            })

    def get_features(self):
        """Extract feature vector for current window."""
        now = time.time()
        with self.lock:
            window = [p for p in self.packets if now - p["ts"] < WINDOW_SEC]

        if len(window) < 5:
            return None

        sizes = [p["size"] for p in window]
        protos = Counter(p["proto"] for p in window)
        ports = Counter(p["dst_port"] for p in window)

        pps = len(window) / WINDOW_SEC
        avg_size = sum(sizes) / len(sizes)
        max_size = max(sizes)
        min_size = min(sizes)
        std_size = (sum((s - avg_size) ** 2 for s in sizes) / len(sizes)) ** 0.5

        tcp_ratio = protos.get(6, 0) / len(window)
        udp_ratio = protos.get(17, 0) / len(window)
        icmp_ratio = protos.get(1, 0) / len(window)

        unique_ports = len(ports)
        top_port_ratio = ports.most_common(1)[0][1] / len(window) if ports else 0

        syn_count = sum(1 for p in window if p["flags"] & 0x02)
        syn_ratio = syn_count / len(window)

        return [
            pps, avg_size, max_size, min_size, std_size,
            tcp_ratio, udp_ratio, icmp_ratio,
            unique_ports, top_port_ratio, syn_ratio,
        ]


_features = TrafficFeatures()
_alerts = deque(maxlen=100)
_stats = {"packets": 0, "anomalies": 0, "last_score": 0.0}


def _sniff_thread(iface):
    """Capture packets using raw socket."""
    import socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((iface, 0))
        sock.settimeout(1.0)
    except Exception:
        return

    while _monitoring and _running:
        try:
            raw, _ = sock.recvfrom(65535)
            if len(raw) < 34:
                continue

            eth_proto = struct.unpack("!H", raw[12:14])[0]
            if eth_proto != 0x0800:
                continue

            ip_header = raw[14:34]
            proto = ip_header[9]
            total_len = struct.unpack("!H", ip_header[2:4])[0]

            src_port = dst_port = 0
            flags = 0
            ihl = (ip_header[0] & 0x0F) * 4
            transport = raw[14 + ihl:]

            if proto == 6 and len(transport) >= 14:
                src_port = struct.unpack("!H", transport[0:2])[0]
                dst_port = struct.unpack("!H", transport[2:4])[0]
                flags = transport[13]
            elif proto == 17 and len(transport) >= 8:
                src_port = struct.unpack("!H", transport[0:2])[0]
                dst_port = struct.unpack("!H", transport[2:4])[0]

            _features.add_packet(total_len, proto, src_port, dst_port, flags)
            _stats["packets"] += 1

        except socket.timeout:
            continue
        except Exception:
            continue

    sock.close()


def _detect_thread():
    """Run anomaly detection on feature windows."""
    global _model
    while _monitoring and _running:
        time.sleep(2)
        if not _trained or _model is None:
            continue

        features = _features.get_features()
        if features is None:
            continue

        try:
            import numpy as np
            X = np.array([features])
            score = _model.decision_function(X)[0]
            pred = _model.predict(X)[0]
            _stats["last_score"] = float(score)

            if pred == -1:
                _stats["anomalies"] += 1
                alert = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "score": f"{score:.3f}",
                    "pps": f"{features[0]:.0f}",
                    "avg_size": f"{features[1]:.0f}",
                    "syn_ratio": f"{features[10]:.2f}",
                    "ports": f"{int(features[8])}",
                }
                _alerts.appendleft(alert)
        except Exception:
            pass


def _train_model():
    """Train Isolation Forest on current traffic features."""
    global _model, _trained
    import numpy as np
    from sklearn.ensemble import IsolationForest

    _show_status("Training model...", C_YELLOW)
    samples = []
    for _ in range(30):
        f = _features.get_features()
        if f:
            samples.append(f)
        time.sleep(0.5)

    if len(samples) < 10:
        _show_status("Not enough data!", C_RED)
        time.sleep(1)
        return False

    X = np.array(samples)
    _model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    _model.fit(X)
    _trained = True

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    try:
        import pickle
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(_model, f)
    except Exception:
        pass

    _show_status(f"Trained on {len(samples)} samples!", C_GREEN)
    time.sleep(1)
    return True


def _load_model():
    global _model, _trained
    if not os.path.isfile(MODEL_PATH):
        return False
    try:
        import pickle
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        _trained = True
        return True
    except Exception:
        return False


def _list_interfaces():
    """List all network interfaces."""
    ifaces = []
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo":
                continue
            ifaces.append(name)
    except Exception:
        ifaces = ["eth0", "wlan0"]
    return sorted(ifaces)


def _get_default_iface():
    """Find default network interface."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=3)
        parts = r.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    ifaces = _list_interfaces()
    return ifaces[0] if ifaces else "eth0"


def _delete_model():
    global _model, _trained
    _model = None
    _trained = False
    try:
        os.remove(MODEL_PATH)
    except Exception:
        pass


def _show_settings_menu(iface):
    """Settings menu: interface, model management."""
    ifaces = _list_interfaces()
    if iface in ifaces:
        iface_idx = ifaces.index(iface)
    else:
        iface_idx = 0

    items = [
        ("", "Interface: "),
        ("", "Train model (15s)"),
        ("", "Load saved model"),
        ("", "Save current model"),
        ("", "Delete model (reset)"),
        ("", "Back"),
    ]
    sel = 0
    last_btn = 0

    while _running:
        items[0] = ("", f"Interface: {ifaces[iface_idx]}")

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        if IS_WIDE:
            d.rectangle([0, 0, W, 20], fill=C_HEAD)
            d.text((W // 2, 10), "SETTINGS", font=font_lg, fill=C_YELLOW,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 35, 1), "SETTINGS", font=font_lg, fill=C_YELLOW)
            y = 28
            for i, (icon, label) in enumerate(items):
                ry = y + i * 22
                if i == sel:
                    d.rectangle([4, ry, W - 4, ry + 20], fill=(30, 20, 40))
                color = C_WHITE if i == sel else C_DIM
                d.text((10, ry + 3), f"{icon} {label}", font=font_sm, fill=color)

            d.rectangle([0, H - 16, W, H], fill=C_DARK)
            model_str = "Model: loaded" if _trained else "Model: none"
            d.text((W // 2, H - 8), f"OK:Select UP/DN:Nav | {model_str}",
                   font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (2, H - 13), f"OK:Sel | {model_str}", font=font_sm, fill=C_DIM)
        else:
            d.rectangle([0, 0, 128, 14], fill=C_HEAD)
            d.text((20, 1), "SETTINGS", font=font_lg, fill=C_YELLOW)
            y = 18
            for i, (icon, label) in enumerate(items):
                ry = y + i * 16
                if i == sel:
                    d.rectangle([2, ry, 126, ry + 15], fill=(30, 20, 40))
                color = C_WHITE if i == sel else C_DIM
                d.text((4, ry + 1), f"{icon} {label}"[:17], font=font_sm, fill=color)

        LCD.LCD_ShowImage(img, 0, 0)

        btn = _get_btn()
        now = time.time()

        if btn == "KEY3" and now - last_btn > DEBOUNCE:
            return ifaces[iface_idx]

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel - 1) % len(items)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel + 1) % len(items)

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            if sel == 0:
                iface_idx = (iface_idx + 1) % len(ifaces)
            elif sel == 1:
                return ("train", ifaces[iface_idx])
            elif sel == 2:
                if _load_model():
                    _show_status("Model loaded!", C_GREEN)
                else:
                    _show_status("No saved model", C_RED)
                time.sleep(1)
            elif sel == 3:
                if _trained and _model:
                    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
                    import pickle
                    with open(MODEL_PATH, "wb") as f:
                        pickle.dump(_model, f)
                    _show_status("Model saved!", C_GREEN)
                else:
                    _show_status("No model to save", C_RED)
                time.sleep(1)
            elif sel == 4:
                _delete_model()
                _show_status("Model deleted!", C_GREEN)
                time.sleep(1)
            elif sel == 5:
                return ifaces[iface_idx]

        time.sleep(0.08)

    return ifaces[iface_idx]


def _draw_live():
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    status_color = C_GREEN if _monitoring else C_RED
    trained_str = "ML Ready" if _trained else "Not trained"
    trained_color = C_GREEN if _trained else C_YELLOW

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "ANOMALY DETECTOR", font=font_lg, fill=C_PURPLE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 65, 1), "ANOMALY DETECTOR", font=font_lg, fill=C_PURPLE)

        y = 26
        status = "MONITORING" if _monitoring else "STOPPED"
        d.text((8, y), f"Status: {status}", font=font, fill=status_color)
        d.text((W - 8, y), trained_str, font=font_sm, fill=trained_color,
               anchor="ra") if hasattr(d, 'textbbox') else d.text(
                   (W - 80, y), trained_str, font=font_sm, fill=trained_color)
        y += 20

        d.text((8, y), f"Packets: {_stats['packets']}", font=font_sm, fill=C_WHITE)
        y += 14
        d.text((8, y), f"Anomalies: {_stats['anomalies']}", font=font_sm,
               fill=C_RED if _stats['anomalies'] > 0 else C_DIM)
        y += 14
        d.text((8, y), f"Score: {_stats['last_score']:.3f}", font=font_sm, fill=C_CYAN)
        y += 20

        if _alerts:
            d.text((8, y), "Latest alerts:", font=font_sm, fill=C_YELLOW)
            y += 14
            for alert in list(_alerts)[:3]:
                d.text((12, y), f"{alert['time']} pps={alert['pps']} ports={alert['ports']} syn={alert['syn_ratio']}",
                       font=font_sm, fill=C_RED)
                y += 13

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        iface_str = f"[{_get_default_iface()}]" if not _monitoring else ""
        d.text((W // 2, H - 8), f"OK:Mon K1:Train K2:Clear L:Settings K3:Exit {iface_str}",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 13), "OK K1:Train L:Set K3:X", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((8, 1), "ANOMALY DET", font=font_lg, fill=C_PURPLE)
        y = 18
        status = "ON" if _monitoring else "OFF"
        d.text((4, y), f"{status} Pkts:{_stats['packets']}", font=font_sm, fill=status_color)
        y += 14
        d.text((4, y), f"Anom:{_stats['anomalies']} Scr:{_stats['last_score']:.2f}", font=font_sm, fill=C_CYAN)
        y += 14
        if _alerts:
            alert = list(_alerts)[0]
            d.text((4, y), f"{alert['time']} pps={alert['pps']}", font=font_sm, fill=C_RED)
        d.text((4, 108), "OK K1:Train K3:X", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running, _monitoring

    if not _ensure_sklearn():
        _show_status("sklearn install failed!", C_RED)
        time.sleep(2)
        GPIO.cleanup()
        return 1

    _load_model()
    iface = _get_default_iface()
    sniff_t = None
    detect_t = None
    last_btn = 0

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            _monitoring = False
            break

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            if not _monitoring:
                _monitoring = True
                _stats["packets"] = 0
                sniff_t = threading.Thread(target=_sniff_thread, args=(iface,), daemon=True)
                sniff_t.start()
                detect_t = threading.Thread(target=_detect_thread, daemon=True)
                detect_t.start()
            else:
                _monitoring = False

        if btn == "KEY1" and now - last_btn > DEBOUNCE and _monitoring:
            last_btn = now
            _train_model()

        if btn == "KEY2" and now - last_btn > DEBOUNCE:
            last_btn = now
            _alerts.clear()
            _stats["anomalies"] = 0

        if btn == "LEFT" and now - last_btn > DEBOUNCE:
            last_btn = now
            result = _show_settings_menu(iface)
            if isinstance(result, tuple) and result[0] == "train":
                iface = result[1]
                _monitoring = True
                _stats["packets"] = 0
                sniff_t = threading.Thread(target=_sniff_thread, args=(iface,), daemon=True)
                sniff_t.start()
                time.sleep(1)
                _train_model()
                _monitoring = False
                detect_t = threading.Thread(target=_detect_thread, daemon=True)
                detect_t.start()
                _monitoring = True
            else:
                iface = result

        _draw_live()
        time.sleep(0.3)

    _monitoring = False
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
