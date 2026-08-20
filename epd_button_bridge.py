"""
    Physical (BCM)   Short press        Long press (>= HOLD_THRESHOLD_S)
    5                KEY_UP_PIN         KEY1_PIN
    6                KEY_DOWN_PIN       KEY2_PIN
    13               KEY_LEFT_PIN       KEY3_PIN
    19               KEY_PRESS_PIN      KEY_RIGHT_PIN

IMPORTANT — process scope: the GPIO monkey-patch and poll thread only exist
within the Python process that imports this module.
"""

import threading
import time

import RPi.GPIO as GPIO

HOLD_THRESHOLD_S = 0.35
PULSE_S = 0.15          # how long a short-press pulse reads as "pressed"
POLL_INTERVAL_S = 0.01  # ~100Hz

# physical BCM pin -> (short-press virtual name, long-press virtual name)
PHYSICAL = {
    5:  ("KEY_UP_PIN", "KEY1_PIN"),
    6:  ("KEY_DOWN_PIN", "KEY2_PIN"),
    13: ("KEY_LEFT_PIN", "KEY3_PIN"),
    19: ("KEY_PRESS_PIN", "KEY_RIGHT_PIN"),
}

# Sentinel numbers, never collide with real BCM pins (0-27).
VIRTUAL_PIN = {
    "KEY_UP_PIN": 900, "KEY_DOWN_PIN": 901,
    "KEY_LEFT_PIN": 902, "KEY_RIGHT_PIN": 903,
    "KEY_PRESS_PIN": 904, "KEY1_PIN": 905,
    "KEY2_PIN": 906, "KEY3_PIN": 907,
}

_real_input = GPIO.input
_real_setup = GPIO.setup

_state_lock = threading.Lock()
_virtual_state = {pin: GPIO.HIGH for pin in VIRTUAL_PIN.values()}  # HIGH = released


def classify_press(press_time, release_time, hold_threshold_s=HOLD_THRESHOLD_S):
    if release_time is None:
        return "long" if (time.monotonic() - press_time) >= hold_threshold_s else None
    return "long" if (release_time - press_time) >= hold_threshold_s else "short"


def _set_virtual(name, pressed):
    pin = VIRTUAL_PIN[name]
    with _state_lock:
        _virtual_state[pin] = GPIO.LOW if pressed else GPIO.HIGH


def _pulse_virtual(name, duration=PULSE_S):
    _set_virtual(name, True)

    def _release():
        time.sleep(duration)
        _set_virtual(name, False)

    threading.Thread(target=_release, daemon=True).start()


def _patched_input(pin, *args, **kwargs):
    if pin in _virtual_state:
        with _state_lock:
            return _virtual_state[pin]
    return _real_input(pin, *args, **kwargs)


def _patched_setup(pin, *args, **kwargs):
    if isinstance(pin, (list, tuple)):
        real_pins = [p for p in pin if p not in _virtual_state]
        if real_pins:
            return _real_setup(real_pins, *args, **kwargs)
        return None
    if pin in _virtual_state:
        return None  # virtual pins need no hardware setup
    return _real_setup(pin, *args, **kwargs)


GPIO.input = _patched_input
GPIO.setup = _patched_setup


def _poll_loop():
    press_started = {phys: None for phys in PHYSICAL}
    long_fired = {phys: False for phys in PHYSICAL}
    while True:
        for phys_pin, (short_name, long_name) in PHYSICAL.items():
            try:
                pressed = _real_input(phys_pin) == GPIO.LOW
            except Exception:
                # A payload likely called GPIO.cleanup() on this pin; back
                # off until _setup_gpio() re-initialises it.
                continue
            started = press_started[phys_pin]
            if pressed and started is None:
                press_started[phys_pin] = time.monotonic()
                long_fired[phys_pin] = False
            elif pressed and started is not None:
                if not long_fired[phys_pin] and classify_press(started, None) == "long":
                    _set_virtual(long_name, True)
                    long_fired[phys_pin] = True
            elif not pressed and started is not None:
                if long_fired[phys_pin]:
                    _set_virtual(long_name, False)
                elif classify_press(started, time.monotonic()) == "short":
                    _pulse_virtual(short_name)
                press_started[phys_pin] = None
                long_fired[phys_pin] = False
        time.sleep(POLL_INTERVAL_S)


def start():
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for phys_pin in PHYSICAL:
        try:
            _real_setup(phys_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        except Exception:
            pass
    threading.Thread(target=_poll_loop, daemon=True).start()


start()
