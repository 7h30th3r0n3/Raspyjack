# RaspyJack Payload Development Guide

Everything you need to build a RaspyJack payload from scratch. A payload is a
standalone Python script that takes over the LCD and buttons, does its job, and
returns cleanly to the RaspyJack menu.

This file lives at the repo root so it is available wherever you start working.

---

## 1. What a payload is

A payload is a `.py` file placed under `payloads/`. RaspyJack discovers it
automatically, lists it in the on-screen menu, and runs it as a separate
process when the user selects it.

Discovery rules (`list_payloads()` in `raspyjack.py`):

- The tree under `payloads/` is walked recursively.
- A file is a payload only if it ends in `.py` **and does not start with `_`**.
- Files starting with `_` are shared libraries/helpers, never shown in the menu
  (for example `_display_helper.py`, `_input_helper.py`).
- Folders starting with `.` and `__pycache__` are skipped.
- The **top-level folder name is the category** shown in the menu. Files sitting
  directly in `payloads/` land in the `general` category.
- Nesting up to 3 levels is supported (`category/subdir/file.py`).

So to add a payload you only drop a file in the right folder. No registration,
no manifest.

Existing categories (folders): `hardware`, `nfc_rfid`, `usb`, `remote_access`,
`wifi`, `network`, `credentials`, `bluetooth`, `exfiltration`, `evasion`,
`recon`, `utilities`, `games`, `sdr`, `ai`, `examples`, and more. Pick the one
that fits, or create a new folder.

---

## 2. Minimal skeleton

Copy `payloads/examples/_payload_template.py`. Here is the essence:

```python
#!/usr/bin/env python3
import os, sys, time, signal

# Make RaspyJack root importable when run standalone (3 dirs up from a
# category/payload.py file). Required so `import LCD_1in44` works.
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13,
    "KEY1": 21, "KEY2": 20, "KEY3": 16,   # KEY3 = back / exit by convention
}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

running = True
def _stop(*_):          # menu-stop sends SIGTERM; Ctrl-C sends SIGINT
    global running
    running = False
signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)

def draw(lines):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)                 # author in 128-base coords
    y = 4
    for line in lines:
        d.text((4, y), line, font=font, fill="white")
        y += 12
    LCD.LCD_ShowImage(img, 0, 0)

try:
    draw(["Payload ready", "KEY3 = exit"])
    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        if btn:
            draw([f"Pressed: {btn}", "KEY3 = exit"])
        time.sleep(0.05)
finally:
    LCD.LCD_Clear()      # never leave a ghost image
    GPIO.cleanup()       # release the pins for the next payload / menu
```

That is a complete, well-behaved payload.

---

## 3. Lifecycle: how RaspyJack runs you

From `exec_payload()` in `raspyjack.py`:

- The payload runs as a **blocking subprocess**: `python3 <full path>`.
- Working directory is the RaspyJack root (`/root/Raspyjack`), and `PYTHONPATH`
  is prepended with it, so `import LCD_1in44`, `import evdev_keys`, etc. resolve.
- On device, payloads run **as root** (home is `/root`).
- `stdout` and `stderr` are redirected to `loot/payload.log`. Use `print()` for
  debug traces; they land there.
- A **non-zero exit code** pops a "Payload error / Check payload.log" dialog.
  Exit 0 on success.
- When the user stops the payload from the menu, RaspyJack sends **SIGTERM** to
  the process. Trap it and exit cleanly (see skeleton).
- After you return, RaspyJack re-initialises GPIO + LCD and redraws its menu.
  Your `GPIO.cleanup()` and `LCD.LCD_Clear()` keep that transition clean.

Hard rules for a good payload:

1. Always wrap the body in `try/finally` with `LCD.LCD_Clear()` + `GPIO.cleanup()`.
2. Handle SIGTERM and SIGINT so a menu-stop does not kill you mid-draw.
3. Provide an on-screen way to exit (KEY3 by convention).
4. Do not leave background threads or child processes running after you return.

---

## 4. Display

### The driver
```python
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
# build a PIL "RGB" Image, then:
LCD.LCD_ShowImage(img, 0, 0)
```

### Resolution independence (use this)
RaspyJack runs on panels of different sizes:

| Panel                     | Resolution | Notes                         |
|---------------------------|------------|-------------------------------|
| Waveshare 1.44" (original)| 128x128    | base coordinate system        |
| ST7789                    | 240x240    | square                        |
| CardputerZero             | 320x170    | wide, RGB565 via `/dev/fb0`   |

`payloads/_display_helper.py` solves this. Author everything in **128-base
coordinates** and let it scale:

```python
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY, S

d = ScaledDraw(img)          # drop-in for ImageDraw.Draw, auto-scales coords
font = scaled_font(10)       # point size as if on a 128px screen
# SX(x) / SY(y) scale a single axis; S(v) scales uniformly (fonts, widths)
```

`ScaledDraw` wraps `text`, `rectangle`, `line`, `ellipse`, `polygon`, `arc`,
`pieslice`, `textbbox`, `textlength`, and passes through anything else. On a
128x128 panel it is a zero-cost passthrough.

If you need true pixel art at native resolution, render to your own internal
Image and `.resize((WIDTH, HEIGHT), Image.NEAREST)` before `LCD_ShowImage`
(see `payloads/examples/example_show_buttons.py`).

---

## 5. Input

### Buttons (joystick + 3 keys)
Logical names: `UP DOWN LEFT RIGHT OK KEY1 KEY2 KEY3`. All active-low with
`PUD_UP`. Never poll GPIO directly for menu navigation. Use the shared helper:

```python
from payloads._input_helper import get_button, get_held_buttons, flush_input

btn = get_button(PINS, GPIO)   # returns a name or None
```

`get_button()` does three things you want for free:
- checks the **WebUI virtual buttons** first (so the payload is drivable from the
  web interface), then falls back to physical GPIO;
- applies the global **debounce**;
- applies the **flip** mapping when the screen is configured upside-down.

For continuous input (games) use `get_held_buttons()` which returns a set of
currently held button names. `flush_input()` clears queued/held state.

Convention: **KEY3 = back/exit**. When flipped, KEY1 and KEY3 swap, which the
helper handles.

### Physical QWERTY keyboard (CardputerZero / TCA8418)
```python
import evdev_keys
if evdev_keys.is_key_pressed(code):   # code = Linux evdev key code
    ...
```
Key codes: letters/numbers/symbols map per the table in
`payloads/_keyboard_helper.py` (e.g. 28 = Enter, 14 = Backspace, 57 = Space).
This reader does not grab the device, so it coexists with the menu.

### On-screen keyboard (text entry on any panel)
```python
from payloads._keyboard_helper import lcd_keyboard

value = lcd_keyboard(LCD, font, PINS, GPIO,
                     title="Enter IP", default="192.168.1.1",
                     charset="ip", max_len=32)
# returns the string, or None if the user cancelled (KEY3)
```
Charsets: `full`, `alpha`, `digits`, `ip`, `hex`, `mac`, `url`. It also accepts
input from the physical keyboard and from the WebUI remote text session at the
same time. Controls shown on screen: UP/DOWN/LEFT/RIGHT move, OK types, KEY1
switches page, KEY2 backspace, KEY3 cancel, DONE button confirms.

---

## 6. Shared helpers (import, do not reinvent)

All live in `payloads/` with a leading underscore so they stay out of the menu.

| Module                | What it gives you                                              |
|-----------------------|----------------------------------------------------------------|
| `_display_helper`     | `ScaledDraw`, `scaled_font`, `SX/SY/S` coordinate scaling       |
| `_input_helper`       | `get_button`, `get_held_buttons`, WebUI remote text session     |
| `_keyboard_helper`    | `lcd_keyboard` on-screen keyboard (all charsets)                |
| `_dep_helper`         | `ensure_apt`, `ensure_pip`, `ensure_all` auto-install deps      |
| `_iface_helper`       | `select_interface(...)` pick a wifi/eth interface on the LCD    |
| `_gps_helper`         | `start_gps`, `get_gps_data` auto-detect + start gpsd            |
| `_audio_helper`       | ALSA playback/capture device detection, volume, capture stream  |
| `_nfc_cap_detect`     | detect which NFC/RFID hardware is attached                      |
| `_st25r_driver`, `_nfc_emulator`, `_iso14443_4`, `_emv_reader`, `_crypto1`, `_mfkey32` | NFC stack building blocks |
| `_cc1101_driver`, `_cc1101_protocols`, `_cc1101_usb` | sub-GHz CC1101 (HAT or USB bridge) |
| `_tagtinker_driver`   | ESL / TagTinker                                                 |

Import pattern from inside a payload:
```python
from payloads._dep_helper import ensure_all
ensure_all(apt=["direwolf"], pip=["sgp4"])
```

### Optional workflow extensions
`EXTENSIONS/api.py` exposes gate/action helpers usable as plain functions:
```python
from EXTENSIONS.api import (
    WAIT_FOR_PRESENT, WAIT_FOR_NOTPRESENT, REQUIRE_CAPABILITY, RUN_PAYLOAD,
)
```
Use `REQUIRE_CAPABILITY("binary", "bluetoothctl")` to assert a dependency, or
`RUN_PAYLOAD("utilities/x.py", "arg")` to chain payloads. See `EXTENSIONS/README.md`.

---

## 7. Menu icon

Icons are defined in `menu_icons.json`. Add your payload under the `payloads`
object. The key is a **leading space + the filename without `.py`**, the value
is a FontAwesome 6 Solid codepoint (an emoji also works):

```json
"payloads": {
    " my_payload": ""
}
```

Browse codepoints at https://fontawesome.com/v6/search?o=r&s=solid . Without an
entry the payload still appears, using a category fallback icon.

---

## 8. Output / loot

Write artefacts under `loot/` in the RaspyJack root so the WebUI and file
browser can find them. Existing conventions:

- `loot/Nmap/`, `loot/MITM/`, `loot/wardriving/`, etc. per feature.
- `loot/payload.log` is the shared payload stdout/stderr log.

Create your own subfolder with `os.makedirs(path, exist_ok=True)` and timestamp
your files (`time.strftime("%Y%m%d_%H%M%S")`).

---

## 9. CardputerZero notes (constrained target)

The CardputerZero (M5Stack, aarch64, Debian trixie) is the tight one: ~361 MB
RAM, 4 slow ARM cores, slow eMMC/SD, panel is 320x170 RGB565 drawn to
`/dev/fb0`. Guidance:

- Keep the resident working set small. Heavy Node/Python/ML processes will swap
  and stall. Memory, not CPU, is the usual wall.
- Prefer differential drawing: redraw only the lines/region that changed instead
  of rebuilding and pushing a full frame every tick.
- There is a frame-mirror path (JPEG-encodes frames to `/dev/shm` for the web/HDMI
  mirror). If you do not need it and want the CPU back, set
  `RJ_FRAME_MIRROR=0` and `RJ_CARDPUTER_FRAME_ENABLED=0` in the environment
  **before** `import LCD_1in44`.
- The physical keyboard is on `/dev/input/event3` via `evdev_keys` (no grab).
- The same payload still runs on the 128x128 and 240x240 panels thanks to
  `ScaledDraw`. Test your layout at 128-base before assuming it fits.

---

## 10. Checklist before shipping a payload

- [ ] File under the right `payloads/<category>/` folder, no leading `_`.
- [ ] `sys.path.append(...root...)` header so it runs standalone too.
- [ ] GPIO set up with `PUD_UP`; input via `get_button(PINS, GPIO)`.
- [ ] Drawing via `ScaledDraw` + `scaled_font()` (works on all panels).
- [ ] SIGTERM + SIGINT trapped; KEY3 (or equivalent) exits.
- [ ] `try/finally` with `LCD.LCD_Clear()` + `GPIO.cleanup()`.
- [ ] Exit code 0 on success; errors printed (they go to `loot/payload.log`).
- [ ] No orphan threads/processes left running.
- [ ] Icon added to `menu_icons.json` (optional but nice).
- [ ] Tested on device: select from menu, run, stop from menu, confirm the
      menu returns clean.

### Quick manual test on device
```bash
# from the RaspyJack root, same env as the menu launcher
cd /root/Raspyjack
PYTHONPATH=/root/Raspyjack python3 payloads/<category>/<name>.py
```

---

## Reference files

- `payloads/examples/_payload_template.py` : canonical starting point.
- `payloads/examples/example_show_buttons.py` : fully commented input/draw demo.
- `payloads/_display_helper.py`, `_input_helper.py`, `_keyboard_helper.py` : the
  three helpers every interactive payload uses.
- `raspyjack.py` : `list_payloads()`, `list_payloads_by_category()`,
  `exec_payload()` define discovery and the run contract.
- `menu_icons.json` : icon mapping.
- `EXTENSIONS/README.md` : optional workflow gates/actions.
