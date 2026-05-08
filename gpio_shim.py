"""
gpio_shim – Drop-in replacement for RPi.GPIO on M5Stack CardputerZero.
Translates GPIO.input() calls to evdev key state via evdev_keys module.
GPIO.output/setup/setmode are no-ops (no physical GPIO buttons on this device).
"""

import evdev_keys

# RPi.GPIO constants
BCM = 11
BOARD = 10
IN = 0
OUT = 1
PUD_UP = 22
PUD_DOWN = 21
HIGH = 1
LOW = 0

# Map GPIO pin numbers -> Raspyjack button names
_PIN_TO_BUTTON = {
    6:  'KEY_UP_PIN',
    19: 'KEY_DOWN_PIN',
    5:  'KEY_LEFT_PIN',
    26: 'KEY_RIGHT_PIN',
    13: 'KEY_PRESS_PIN',
    21: 'KEY1_PIN',
    20: 'KEY2_PIN',
    16: 'KEY3_PIN',
}


def setmode(mode):
    pass


def setwarnings(flag):
    pass


def setup(pin, direction, pull_up_down=None):
    pass


def output(pin, value):
    pass


def input(pin):
    button = _PIN_TO_BUTTON.get(pin)
    if button is None:
        return 1
    return 0 if evdev_keys.is_pressed(button) else 1


def cleanup():
    pass
