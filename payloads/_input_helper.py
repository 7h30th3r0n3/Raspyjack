"""
Shared input helper for RaspyJack payloads.
Checks WebUI virtual input first, then falls back to GPIO.
Reads flip setting from gui_conf.json to swap controls when flipped.
"""

import os
import json

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


def flush_input():
    """Clear all queued and held button state."""
    if rj_input is not None:
        try:
            rj_input.flush()
        except Exception:
            pass
