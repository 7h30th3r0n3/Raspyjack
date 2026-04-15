"""
Shared input helper for RaspyJack payloads.
Checks WebUI virtual input first, then falls back to GPIO.
Reads flip setting from gui_conf.json to swap controls when flipped.
"""

import os
import json
import time
import uuid

try:
    import rj_input
except Exception:
    rj_input = None

_VIRTUAL_TO_BTN = {
    "KEY_UP_PIN": "UP",
    "KEY_DOWN_PIN": "DOWN",
    "KEY_LEFT_PIN": "LEFT",
    "KEY_RIGHT_PIN": "RIGHT",
    "KEY_PRESS_PIN": "OK",
    "KEY1_PIN": "KEY1",
    "KEY2_PIN": "KEY2",
    "KEY3_PIN": "KEY3",
}

# ---------------------------------------------------------------------------
# Flip detection: swap button meanings when device is flipped 180
# ---------------------------------------------------------------------------
_FLIP_MAP = {
    "UP": "DOWN", "DOWN": "UP",
    "LEFT": "RIGHT", "RIGHT": "LEFT",
    "KEY1": "KEY3", "KEY3": "KEY1",
    "OK": "OK", "KEY2": "KEY2",
}

_flip_enabled = None  # None = not yet loaded, lazy init on first use

_CONF_PATHS = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gui_conf.json"),
    "/root/Raspyjack/gui_conf.json",
]
_TEXT_SESSION_FILE = os.environ.get("RJ_TEXT_SESSION_FILE", "/dev/shm/rj_text_session.json")
_TEXT_SESSION_TIMEOUT = float(os.environ.get("RJ_TEXT_SESSION_TIMEOUT", "30"))


def _is_flip_enabled():
    """Lazy-load flip setting on first call, cache result."""
    global _flip_enabled
    if _flip_enabled is not None:
        return _flip_enabled
    _flip_enabled = False
    for p in _CONF_PATHS:
        if os.path.isfile(p):
            try:
                with open(p, "r") as f:
                    _flip_enabled = json.load(f).get("DISPLAY", {}).get("flip", False)
            except Exception:
                pass
            break
    return _flip_enabled


def _flip(btn):
    """Apply flip mapping if device is flipped 180."""
    if _is_flip_enabled() and btn:
        return _FLIP_MAP.get(btn, btn)
    return btn


def get_virtual_button():
    """Return a WebUI virtual button name or None."""
    if rj_input is None:
        return None
    try:
        name = rj_input.get_virtual_button()
    except Exception:
        return None
    if not name:
        return None
    return _flip(_VIRTUAL_TO_BTN.get(name))


def get_button(pins, gpio):
    """
    Return a button name using WebUI virtual input if available,
    otherwise fall back to GPIO.
    """
    mapped = get_virtual_button()
    if mapped:
        return mapped
    for btn, pin in pins.items():
        if gpio.input(pin) == 0:
            return _flip(btn)
    return None


def get_held_buttons():
    """Return set of currently held WebUI button names (for continuous input like games)."""
    if rj_input is None:
        return set()
    try:
        held = rj_input.get_held_buttons()
    except Exception:
        return set()
    mapped = {_VIRTUAL_TO_BTN.get(b, b) for b in held if b in _VIRTUAL_TO_BTN}
    if _is_flip_enabled():
        return {_FLIP_MAP.get(b, b) for b in mapped}
    return mapped


def _write_text_session(payload):
    directory = os.path.dirname(_TEXT_SESSION_FILE)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temp_path = f"{_TEXT_SESSION_FILE}.tmp.{os.getpid()}"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
    os.replace(temp_path, _TEXT_SESSION_FILE)


def open_remote_text_session(title="Input", default="", charset="full", max_len=64):
    session_id = uuid.uuid4().hex
    payload = {
        "active": True,
        "session_id": session_id,
        "title": str(title or "Input")[:32],
        "default": str(default or "")[:128],
        "charset": str(charset or "full"),
        "max_len": int(max_len),
        "started_at": time.time(),
        "timeout": _TEXT_SESSION_TIMEOUT,
    }
    _write_text_session(payload)
    if rj_input is not None:
        try:
            rj_input.flush_text_events()
        except Exception:
            pass
    return session_id


def close_remote_text_session(session_id=None):
    current = {}
    try:
        if os.path.isfile(_TEXT_SESSION_FILE):
            with open(_TEXT_SESSION_FILE, "r", encoding="utf-8") as handle:
                current = json.load(handle) or {}
    except Exception:
        current = {}
    if session_id and current.get("session_id") not in (None, session_id):
        return
    payload = {
        "active": False,
        "session_id": session_id or current.get("session_id", ""),
        "closed_at": time.time(),
    }
    try:
        _write_text_session(payload)
    except Exception:
        pass


def get_remote_text_event(session_id=None):
    if rj_input is None:
        return None
    for _ in range(4):
        try:
            event = rj_input.get_text_event()
        except Exception:
            return None
        if not event:
            return None
        if not isinstance(event, dict):
            continue
        event_session = event.get("session_id")
        if session_id and event_session and event_session != session_id:
            continue
        return event
    return None


def flush_input():
    """Clear all queued and held button state."""
    if rj_input is not None:
        try:
            rj_input.flush()
        except Exception:
            pass
