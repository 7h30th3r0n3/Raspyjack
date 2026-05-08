"""
evdev_keys – TCA8418 keyboard reader for M5Stack CardputerZero
"""

import threading
import evdev
import os

EVDEV_DEVICE = os.environ.get('RJ_KEYBOARD_DEVICE', '/dev/input/event3')

_KEYMAP = {
    103: 'KEY_UP_PIN',
    108: 'KEY_DOWN_PIN',
    105: 'KEY_LEFT_PIN',
    106: 'KEY_RIGHT_PIN',
    33:  'KEY_UP_PIN',
    44:  'KEY_LEFT_PIN',
    45:  'KEY_DOWN_PIN',
    46:  'KEY_RIGHT_PIN',
    28:  'KEY_PRESS_PIN',
    1:   'KEY3_PIN',
    57:  'KEY1_PIN',
    14:  'KEY2_PIN',
    15:  'KEY3_PIN',
}

_REVERSE_MAP = {}
for _code, _name in _KEYMAP.items():
    _REVERSE_MAP.setdefault(_name, []).append(_code)

_key_state = {}
_lock = threading.Lock()
_device = None
_thread = None


def _reader_loop():
    global _device
    while True:
        try:
            if _device is None:
                _device = evdev.InputDevice(EVDEV_DEVICE)
            for event in _device.read_loop():
                if event.type != evdev.ecodes.EV_KEY:
                    continue
                with _lock:
                    _key_state[event.code] = event.value > 0
        except Exception:
            _device = None
            import time
            time.sleep(0.5)


def start():
    global _thread
    if _thread is not None:
        return
    _thread = threading.Thread(target=_reader_loop, daemon=True)
    _thread.start()


def is_pressed(button_name: str) -> bool:
    codes = _REVERSE_MAP.get(button_name, [])
    with _lock:
        return any(_key_state.get(c, False) for c in codes)


def is_key_pressed(evdev_code: int) -> bool:
    with _lock:
        return _key_state.get(evdev_code, False)


def any_pressed() -> bool:
    with _lock:
        return any(_key_state.values())


def get_pressed_button():
    with _lock:
        for code, pressed in _key_state.items():
            if pressed and code in _KEYMAP:
                return _KEYMAP[code]
    return None


start()
