"""
RPi.GPIO shim – Detects platform and delegates accordingly.
On CardputerZero: uses gpio_shim (evdev-based).
On standard Raspberry Pi: falls through to the real RPi.GPIO system package.
"""

import os as _os
import json as _json
import sys as _sys

_IS_CARDPUTER = False
try:
    for _p in [
        _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "gui_conf.json"),
        "/root/Raspyjack/gui_conf.json",
    ]:
        if _os.path.isfile(_p):
            with open(_p, "r") as _f:
                _IS_CARDPUTER = _json.load(_f).get("DISPLAY", {}).get("type") == "CARDPUTER_320"
            break
except Exception:
    pass

if _IS_CARDPUTER:
    from gpio_shim import *
else:
    # Remove this local RPi package from sys.modules so the real one loads
    _this_pkg = "RPi"
    _this_mod = "RPi.GPIO"
    if _this_pkg in _sys.modules:
        del _sys.modules[_this_pkg]
    if _this_mod in _sys.modules:
        del _sys.modules[_this_mod]

    # Temporarily remove our directory from sys.path to find the REAL RPi.GPIO
    _our_dir = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    _saved_path = list(_sys.path)
    _sys.path = [p for p in _sys.path if _os.path.abspath(p) != _our_dir]

    try:
        import RPi.GPIO as _real_gpio
        # Re-export everything from the real RPi.GPIO
        for _attr in dir(_real_gpio):
            if not _attr.startswith("__"):
                globals()[_attr] = getattr(_real_gpio, _attr)
    finally:
        _sys.path = _saved_path
