#!/usr/bin/env python3
"""
RaspyJack *payload* – **Show USB Keyboard Key**
==============================================
Displays the name of the key pressed on a USB keyboard connected to the
Raspberry Pi. It listens to the first detected *evdev* keyboard device and
shows the key name centred in bright green on the Waveshare 1.44‑inch LCD.

The script exits cleanly when:
* **ESC** is pressed on the keyboard;
* **KEY3** (bottom‑right button) is pressed on the HAT;
* the user hits *Ctrl‑C* in the terminal;
* RaspyJack UI sends a *SIGTERM* signal.

Make sure the runtime dependency is installed:

```bash
sudo apt install python3-evdev
```
"""

# ---------------------------------------------------------------------------
# 0) Ensure we can import RaspyJack helpers when launched directly
# ---------------------------------------------------------------------------
import os, sys, time, signal, select, fcntl
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Third‑party libs -----------------------------
import LCD_1in44, LCD_Config          # Waveshare LCD driver
from PIL import Image, ImageDraw, ImageFont
from evdev import InputDevice, categorize, ecodes, list_devices
import RPi.GPIO as GPIO               # Raspberry Pi GPIO access

# ---------------------------------------------------------------------------
# 1) GPIO initialisation (only KEY3 used for «Back to menu»)
# ---------------------------------------------------------------------------
KEY3_PIN = 16                         # BCM pin number
GPIO.setmode(GPIO.BCM)
GPIO.setup(KEY3_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# ---------------------------------------------------------------------------
# 2) LCD initialisation
# ---------------------------------------------------------------------------
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.load_default()


def draw(text: str) -> None:
    """Clear the screen and draw *text* centred in bright green."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    # Pillow ≥ 9.2 offers textbbox(); fall back to textsize() otherwise
    if hasattr(d, "textbbox"):
        x0, y0, x1, y1 = d.textbbox((0, 0), text, font=font)
        w, h = x1 - x0, y1 - y0
    else:
        w, h = d.textsize(text, font=font)

    pos = ((WIDTH - w) // 2, (HEIGHT - h) // 2)
    d.text(pos, text, font=font, fill="#00FF00")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# 3) Helper: find the first keyboard‑like input device
# ---------------------------------------------------------------------------

def find_keyboard() -> InputDevice:
    """Return the first /dev/input/event* that reports EV_KEY events."""
    for path in list_devices():
        dev = InputDevice(path)
        if ecodes.EV_KEY in dev.capabilities():
            return dev
    raise RuntimeError("No keyboard event device found")


# ---------------------------------------------------------------------------
# 4) Graceful shutdown – SIGINT/SIGTERM & KEY3/ESC
# ---------------------------------------------------------------------------

running = True  # global flag for the main loop


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Main loop – poll keyboard & update display
# ---------------------------------------------------------------------------

try:
    keyboard = find_keyboard()

    # -----------------------------------------------------------------------
    # Make the device *non‑blocking* – works across all evdev versions
    # -----------------------------------------------------------------------
    if hasattr(keyboard, "set_blocking"):
        keyboard.set_blocking(False)        # evdev ≥ 1.5
    elif hasattr(keyboard, "setblocking"):
        keyboard.setblocking(False)         # very old evdev (< 1.3)
    else:
        # Fallback: set O_NONBLOCK flag on the file descriptor manually
        flags = fcntl.fcntl(keyboard.fd, fcntl.F_GETFL)
        fcntl.fcntl(keyboard.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    draw("Ready!")

    poller = select.poll()
    poller.register(keyboard.fd, select.POLLIN)

    while running:
        # Alternate exit: KEY3 on the HAT acts as «Back to menu»
        if GPIO.input(KEY3_PIN) == 0:
            break

        # Poll keyboard with 50 ms timeout
        if poller.poll(50):
            for event in keyboard.read():
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    if key_event.keystate == key_event.key_down:
                        key_name = (
                            key_event.keycode
                            if isinstance(key_event.keycode, str)
                            else key_event.keycode[0]
                        )
                        draw(str(key_name))
                        if key_name in ("KEY_ESC", "ESC"):
                            running = False

        time.sleep(0.01)  # small sleep to reduce CPU usage

except Exception as exc:
    # Log unexpected errors
    print(f"[ERROR] {exc}", file=sys.stderr)

finally:
    # -----------------------------------------------------------------------
    # 6) Always executed: clear the screen and release resources
    # -----------------------------------------------------------------------
    LCD.LCD_Clear()
    GPIO.cleanup()
    try:
        keyboard.close()
    except Exception:
        pass
