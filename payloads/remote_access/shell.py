#!/usr/bin/env python3
"""
RaspyJack payload – Linux Shell
================================
Author: 7h30th3r0n3

Launches a native Linux terminal (fbterm) on the LCD framebuffer.
The kernel handles keyboard (tca8418) and display (st7789v) natively.
No Python keyboard handling needed.

ESC to exit fbterm.
"""

import os
import sys
import subprocess
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
from PIL import Image
import LCD_1in44
import LCD_Config
from payloads._display_helper import ScaledDraw, scaled_font


def main():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(16, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

    W, H = lcd.width, lcd.height
    font = scaled_font(9)

    img = Image.new("RGB", (W, H), "black")
    d = ScaledDraw(img)
    # Check/install fbterm
    if subprocess.run(["which", "fbterm"], capture_output=True).returncode != 0:
        d = ScaledDraw(img)
        d.text((W // 2, 40), "Installing fbterm...", font=font, fill="#FFAA00", anchor="mm")
        lcd.LCD_ShowImage(img, 0, 0)
        r = subprocess.run(["sudo", "apt", "install", "-y", "fbterm"],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            img = Image.new("RGB", (W, H), "black")
            d = ScaledDraw(img)
            d.text((W // 2, 40), "Install failed!", font=font, fill="#FF4444", anchor="mm")
            lcd.LCD_ShowImage(img, 0, 0)
            import time; time.sleep(3)
            GPIO.cleanup()
            return 1
        img = Image.new("RGB", (W, H), "black")

    # Load CardputerZero sym keymap
    kmap = "/usr/share/keymaps/tca8418_keypad_m5stack_keymap.map"
    if os.path.isfile(kmap):
        subprocess.run(["sudo", "loadkeys", kmap], capture_output=True)

    d = ScaledDraw(img)
    d.text((W // 2, 40), "Starting Shell...", font=font, fill="#00FF00", anchor="mm")
    d.text((W // 2, 60), "KEY3 to exit", font=scaled_font(8), fill="#888888", anchor="mm")
    lcd.LCD_ShowImage(img, 0, 0)

    import threading
    import time
    import evdev_keys

    env = os.environ.copy()
    env["TERM"] = "fbterm"
    env["FRAMEBUFFER"] = "/dev/fb1"

    try:
        proc = subprocess.Popen(
            ["sudo", "openvt", "--switch", "--wait", "--",
             "bash", "-c",
             f"FRAMEBUFFER=/dev/fb1 TERM=fbterm fbterm -s 10 -- bash --login"],
        )

        def _watch_key3():
            while proc.poll() is None:
                if evdev_keys.is_pressed("KEY3_PIN"):
                    proc.terminate()
                    subprocess.run(["sudo", "chvt", "1"], capture_output=True)
                    break
                time.sleep(0.1)

        threading.Thread(target=_watch_key3, daemon=True).start()
        proc.wait()
        subprocess.run(["sudo", "chvt", "1"], capture_output=True)
    except FileNotFoundError:
        img = Image.new("RGB", (W, H), "black")
        d = ScaledDraw(img)
        d.text((W // 2, 40), "fbterm not found", font=font, fill="#FF4444", anchor="mm")
        d.text((W // 2, 60), "apt install fbterm", font=scaled_font(8), fill="#888", anchor="mm")
        lcd.LCD_ShowImage(img, 0, 0)
        import time
        time.sleep(3)
        GPIO.cleanup()
        return 1
    except Exception as e:
        print(f"[shell] Error: {e}", file=sys.stderr)

    lcd.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
