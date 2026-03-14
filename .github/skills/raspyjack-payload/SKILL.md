---
name: raspyjack-payload
description: 'Create RaspyJack payloads — Python scripts for Raspberry Pi with 128x128 LCD HAT. USE FOR: writing new payloads, games, recon tools, network utilities, honeypots, exfiltration scripts for the RaspyJack framework. Covers GPIO buttons, LCD drawing (Pillow), input handling (WebUI + physical), signal cleanup, frame mirroring, advanced events, loot storage, Discord integration. DO NOT USE FOR: editing raspyjack.py core, WebUI frontend, LCD driver internals.'
---

# RaspyJack Payload Development Guide

## Overview

RaspyJack payloads are standalone Python 3 scripts in `payloads/` that run on a Raspberry Pi with a Waveshare 1.44" LCD HAT (128×128, ST7735S, SPI). They are launched as subprocesses by `raspyjack.py` via `exec_payload()`. Each payload has full control over the LCD and GPIO buttons during execution.

## Mandatory Skeleton

Every payload MUST follow this structure. Use `payloads/examples/_payload_template.py` as the starting point:

```python
#!/usr/bin/env python3
"""Short description of the payload."""

import os, sys, time, signal

# CRITICAL: allow imports from RaspyJack root (two levels up from payloads/subdir/)
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button  # unified WebUI + GPIO input

# --- Pin mapping (BCM) — DO NOT CHANGE these values ---
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

# --- GPIO init ---
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# --- LCD init ---
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.load_default()

# --- Graceful shutdown ---
running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)   # Ctrl+C
signal.signal(signal.SIGTERM, cleanup)  # RaspyJack stop

# --- Main loop ---
try:
    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        # ... payload logic ...
        time.sleep(0.05)
except Exception as exc:
    print(f"[ERROR] {exc}", file=sys.stderr)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
```

## Critical Rules

1. **Always use `sys.path.append`** with `os.path.join(__file__, "..", "..")` — payloads may be in subdirectories like `payloads/games/`.
2. **Always use `from payloads._input_helper import get_button`** — this ensures BOTH physical GPIO buttons AND WebUI virtual buttons work. Never poll GPIO directly without also checking virtual input.
3. **Always handle SIGINT and SIGTERM** — RaspyJack sends SIGTERM when stopping a payload from the menu.
4. **Always call `LCD.LCD_Clear()` and `GPIO.cleanup()` in a `finally` block** — leaving ghost images or locked GPIO breaks the main UI.
5. **KEY3 is the universal "exit/back" button** — every payload MUST exit when KEY3 is pressed.
6. **Never modify GPIO pin numbers** — they are hardware-defined: UP=6, DOWN=19, LEFT=5, RIGHT=26, OK=13, KEY1=21, KEY2=20, KEY3=16.

## Input System

### Basic Input (`get_button`)
```python
from payloads._input_helper import get_button

btn = get_button(PINS, GPIO)  # Returns: "UP"|"DOWN"|"LEFT"|"RIGHT"|"OK"|"KEY1"|"KEY2"|"KEY3"|None
```
- Non-blocking — returns `None` if no button pressed
- Checks WebUI virtual buttons first (Unix socket `/dev/shm/rj_input.sock`), then GPIO
- All buttons are active-LOW (read 0 when pressed, pulled HIGH by 10kΩ)
- Poll in a loop with `time.sleep(0.05)` minimum (50ms = 20 FPS max)

### Advanced Events (`input_events.py`)
For payloads needing long-press, double-click, or repeat:
```python
from input_events import ButtonEventManager, PRESS, CLICK, DOUBLE_CLICK, LONG_PRESS, REPEAT
import threading

stop = threading.Event()
mgr = ButtonEventManager(PINS, stop)
mgr.start()

evt = mgr.get_event(timeout=0.1)  # blocking with timeout
# or: evt = mgr.poll()             # non-blocking
if evt:
    print(evt["type"], evt["button"])  # e.g. "LONG_PRESS", "KEY1"
```
Event types: `PRESS`, `RELEASE`, `CLICK`, `DOUBLE_CLICK`, `LONG_PRESS`, `REPEAT`
Timing: debounce=40ms, long_press=800ms, double_click_window=300ms, repeat_delay=500ms, repeat_interval=150ms

### Button Conventions
| Button | Standard Role |
|--------|--------------|
| UP/DOWN/LEFT/RIGHT | Navigation, scrolling, direction |
| OK | Confirm, start, select |
| KEY1 | Toggle mode, switch view |
| KEY2 | Secondary action, reset stats |
| KEY3 | **EXIT** (mandatory in every payload) |

## LCD Drawing

### Canvas Setup
```python
img = Image.new("RGB", (128, 128), "black")  # always 128×128, black background
d = ImageDraw.Draw(img)
```

### Drawing Primitives
```python
# Text
d.text((x, y), "Hello", font=font, fill="#00FF00")

# Centered text
bbox = d.textbbox((0, 0), text, font=font)
w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
d.text(((128 - w) // 2, (128 - h) // 2), text, font=font, fill="white")

# Rectangles (filled / outline)
d.rectangle([x0, y0, x1, y1], fill="#FF0000")
d.rectangle([x0, y0, x1, y1], outline="#00FF00")

# Lines
d.line([(x0, y0), (x1, y1)], fill="white", width=1)
```

### Pushing to LCD
```python
LCD.LCD_ShowImage(img, 0, 0)  # always (img, 0, 0)
```
The LCD driver automatically mirrors the frame to `/dev/shm/raspyjack_last.jpg` for WebUI display. The framerate is throttled by the `RJ_FRAME_FPS` env var (default 10).

### Fonts
```python
# Fallback (tiny, always available)
font = ImageFont.load_default()

# Preferred (if available on the system)
try:
    font_big = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
    font_mono = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 8)
except:
    font_big = font_mono = ImageFont.load_default()
```
Typical sizes: 6–8pt for dense data, 9–10pt for labels, 11–12pt for headings. Max ~18 characters per line with default font.

### Color Palette (Project Standard)
| Purpose | Color |
|---------|-------|
| Background | `#000000` (black) |
| Primary text/borders | `#00FF00` or `#05ff00` (green) |
| Alerts/errors | `#FF0000` (red) |
| Warnings | `#FFFF00` (yellow) |
| Info/headers | `#00FFFF` (cyan) |
| Neutral text | `#FFFFFF` (white) |

## File Organization

### Payload Placement
Place payloads in the appropriate category subdirectory:
```
payloads/
├── _input_helper.py          # DO NOT MODIFY
├── examples/                 # Templates and tutorials
├── games/                    # Interactive games (snake, tetris, 2048, breakout)
├── general/                  # Utilities (WiFi, speed test, USB detector, updates)
├── reconnaissance/           # Scanning, OSINT, RF analysis, wardriving
├── interception/             # Deauth, MITM, rogue DHCP, bridge
├── evil_portal/              # Honeypots, captive portals
├── exfiltration/             # Data upload (Discord, etc.)
├── remote_access/            # Shell, VPN control
```

### Loot Storage
Save scan results, captures, and logs to `loot/`:
```python
LOOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "loot", "MyPayload")
os.makedirs(LOOT_DIR, exist_ok=True)
```

### Logging
stdout/stderr from payloads is captured to `loot/payload.log` by `exec_payload()`. Use `print()` for debug output and `print(..., file=sys.stderr)` for errors.

## Payload Patterns

### Simple Display Loop (utilities, monitors)
```python
while running:
    btn = get_button(PINS, GPIO)
    if btn == "KEY3": break
    if btn == "OK": do_action()

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    # ... draw status info ...
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.1)  # 10 FPS for display
```

### Game Loop (fixed timestep)
```python
FPS = 8
frame_time = 1.0 / FPS

while running:
    t0 = time.time()
    btn = get_button(PINS, GPIO)
    if btn == "KEY3": break

    update_game_state(btn)
    render_frame()

    elapsed = time.time() - t0
    if elapsed < frame_time:
        time.sleep(frame_time - elapsed)
```

### Multi-View UI (KEY1/KEY2 to cycle views)
```python
views = ["stats", "recent", "config"]
view_idx = 0

while running:
    btn = get_button(PINS, GPIO)
    if btn == "KEY3": break
    if btn == "KEY1": view_idx = (view_idx + 1) % len(views)
    if btn == "KEY2": reset_data()

    if views[view_idx] == "stats":
        draw_stats_view()
    elif views[view_idx] == "recent":
        draw_recent_view()
    # ...
```

### Background Thread + LCD UI (scanners, monitors)
```python
import threading

data_lock = threading.Lock()
scan_data = {}

def scanner_thread():
    while running:
        result = do_scan()
        with data_lock:
            scan_data.update(result)
        time.sleep(1.0)

t = threading.Thread(target=scanner_thread, daemon=True)
t.start()

while running:
    btn = get_button(PINS, GPIO)
    if btn == "KEY3": break
    with data_lock:
        draw_data(scan_data)
    time.sleep(0.1)
```

### Scrollable List
```python
items = ["Item 1", "Item 2", ...]
sel = 0
scroll = 0
VISIBLE = 9  # lines that fit on 128px

while running:
    btn = get_button(PINS, GPIO)
    if btn == "KEY3": break
    if btn == "DOWN": sel = min(sel + 1, len(items) - 1)
    if btn == "UP": sel = max(sel - 1, 0)
    if btn == "OK": activate(items[sel])

    # Auto-scroll to keep selection visible
    if sel < scroll: scroll = sel
    if sel >= scroll + VISIBLE: scroll = sel - VISIBLE + 1

    img = Image.new("RGB", (128, 128), "black")
    d = ImageDraw.Draw(img)
    for i, item in enumerate(items[scroll:scroll + VISIBLE]):
        y = 4 + i * 13
        color = "#00FF00" if (scroll + i) == sel else "#FFFFFF"
        d.text((4, y), item[:18], font=font, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.05)
```

## Optional Integrations

### Discord Webhook
```python
from pathlib import Path
WEBHOOK_FILE = Path(__file__).resolve().parents[2] / "discord_webhook.txt"

def get_webhook_url():
    try:
        return WEBHOOK_FILE.read_text().strip()
    except:
        return None

def send_discord(message, file_path=None):
    url = get_webhook_url()
    if not url:
        return
    import requests
    if file_path:
        with open(file_path, "rb") as f:
            requests.post(url, files={"file": f}, data={"content": message}, timeout=10)
    else:
        requests.post(url, json={"content": message}, timeout=10)
```

### Optional LCD (headless mode)
For payloads that may run without LCD (e.g., honeypots, servers):
```python
HAS_LCD = False
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HAS_LCD = True
except Exception:
    pass
```

### External Tool Dependencies
Always handle missing dependencies gracefully:
```python
try:
    from scapy.all import sniff
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[WARN] scapy not installed – WiFi capture disabled", file=sys.stderr)
```

## Performance Guidelines

| Parameter | Recommended Value |
|-----------|------------------|
| Main loop sleep | 50ms (20 FPS polling) |
| LCD refresh | 100ms (10 FPS display) |
| Input debounce | 50–180ms |
| Background scan interval | 1–15s depending on task |
| Frame mirror | Automatic, throttled by `RJ_FRAME_FPS` |

## Common Mistakes to Avoid

1. **Forgetting `sys.path.append`** — imports of `LCD_1in44`, `payloads._input_helper` will fail.
2. **Polling only GPIO without `get_button()`** — WebUI users won't be able to control the payload.
3. **No SIGTERM handler** — payload becomes unkillable from the RaspyJack menu.
4. **No `finally` cleanup** — ghost images on LCD, blocked GPIO for next payload.
5. **Sleeping too long** — `time.sleep(1.0)` in the main loop makes buttons feel unresponsive. Keep ≤100ms.
6. **Drawing outside 128×128** — pixels beyond the display are silently clipped.
7. **Using `d.textsize()`** — deprecated in Pillow ≥10. Use `d.textbbox((0, 0), text, font=font)` instead.
8. **Hardcoding paths** — use `os.path.dirname(__file__)` or `Path(__file__).resolve()` for relative paths.
9. **Not checking `running` flag** — long operations should periodically check `running` to allow graceful exit.
10. **Blocking the main thread** — use daemon threads for network I/O, scanning, etc. Keep the UI loop responsive.
