# RaspyJack Extensions

Author: m0usem0use

This directory holds shared helpers that payloads can import when they need a reusable gate or action.

The current focus is BLE-driven workflow control. Instead of embedding the same wait logic in multiple payloads, RaspyJack exposes a small extension API that any payload can call.

On RaspyJack, the BLE path uses the Pi's onboard Bluetooth through BlueZ and `bluetoothctl`. It does not depend on a separate UART BLE module.

## What is here

- `gates.py` provides condition-style helpers such as `WAIT_FOR_PRESENT` and `WAIT_FOR_NOTPRESENT`.
- `actions.py` provides shared actions such as `REQUIRE_CAPABILITY` and `RUN_PAYLOAD`.
- `api.py` re-exports the public helpers for payload authors.
- the command-line scripts in this directory are thin wrappers over the same API.

## Public API

Payloads should import the helpers from `EXTENSIONS.api`:

```python
from EXTENSIONS.api import (
    WAIT_FOR_PRESENT,
    WAIT_FOR_NOTPRESENT,
    REQUIRE_CAPABILITY,
    RUN_PAYLOAD,
)
```

These imports are regular Python functions. There is no extra payload language or parser layer.

## Example usage

Wait until a known BLE advertiser is present, then continue:

```bash
python3 /root/Raspyjack/EXTENSIONS/wait_for_present.py --name TestRJ --timeout-seconds 30
```

Require a dependency before the payload continues:

```bash
python3 /root/Raspyjack/EXTENSIONS/require_capability.py binary bluetoothctl
```

Run another payload by relative path:

```bash
python3 /root/Raspyjack/EXTENSIONS/run_payload.py utilities/trigger_marker.py test_run
```

## Notes for payload authors

- Extensions do not replace the normal payload template.
- Interactive payloads should still use `ScaledDraw`, `scaled_font()`, and `get_button`.
- Keeping the payload in the standard `try/finally` layout is still the right way to guarantee `LCD.LCD_Clear()` and `GPIO.cleanup()` on both supported screen sizes.
