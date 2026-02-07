"""
Shared input helper for RaspyJack payloads.
Checks WebUI virtual input first, then falls back to GPIO.
"""

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
    return _VIRTUAL_TO_BTN.get(name)


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
            return btn
    return None
