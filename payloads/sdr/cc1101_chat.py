#!/usr/bin/env python3
"""
RaspyJack Payload -- CC1101 Sub-GHz Chat
==========================================
Author: 7h30th3r0n3

Walkie-talkie-style text chat over CC1101 at 868 MHz (2-FSK).
Messages are sent/received as packets with sync word + CRC.
Uses the TCA8418 keyboard for typing on CardputerZero.

Controls:
  OK          Send message
  UP/DOWN     Scroll message history
  KEY3        Exit

Keyboard: Type message directly via TCA8418

Requires: CardputerZero Cap CC1101 HAT
"""

import os
import sys
import time
import signal
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY
from payloads._input_helper import get_button
from payloads._cc1101_driver import CC1101

try:
    import evdev_keys
    EVDEV_OK = True
except ImportError:
    EVDEV_OK = False

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(9)
    font_sm = scaled_font(7)
    font_lg = scaled_font(12)

CHAT_FREQ = 868.0
LOOT_DIR = "/root/Raspyjack/loot/CC1101/chat"
DEBOUNCE = 0.18

C_BG = (10, 10, 20)
C_HEAD = (20, 30, 60)
C_ORANGE = (255, 165, 0)
C_GREEN = (0, 220, 80)
C_RED = (255, 60, 60)
C_WHITE = (255, 255, 255)
C_DIM = (80, 90, 110)
C_DARK = (15, 18, 30)
C_SELF = (0, 120, 200)
C_OTHER = (200, 120, 0)

_EVDEV_CHARS = {
    2:'1',3:'2',4:'3',5:'4',6:'5',7:'6',8:'7',9:'8',10:'9',11:'0',
    16:'q',17:'w',18:'e',19:'r',20:'t',21:'y',22:'u',23:'i',24:'o',25:'p',
    30:'a',31:'s',32:'d',33:'f',34:'g',35:'h',36:'j',37:'k',38:'l',
    44:'z',45:'x',46:'c',47:'v',48:'b',49:'n',50:'m',
    57:' ',
    26:'!',27:'@',39:'#',40:'$',41:'%',43:'^',
    51:'&',52:'*',53:'(',94:')',
    55:'~',69:'`',70:'_',71:'-',72:'+',73:'=',
    74:'[',75:']',76:'{',77:'}',
    79:';',80:':',81:"'",82:'"',83:'<',85:'>',
    86:'\\',89:'|',90:',',91:'.',92:'/',93:'?',
}

_running = True
_messages = []
_msg_lock = threading.Lock()
_last_btn = 0


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    if b:
        now = time.time()
        if now - _last_btn < DEBOUNCE:
            return None
        _last_btn = now
    return b


def _get_typed_char():
    if not EVDEV_OK:
        return None
    for code, char in _EVDEV_CHARS.items():
        if evdev_keys.is_key_pressed(code):
            return char
    if evdev_keys.is_key_pressed(14):
        return '\b'
    if evdev_keys.is_key_pressed(28):
        return '\n'
    return None


def _draw_ctx(img):
    if IS_WIDE:
        return ImageDraw.Draw(img)
    return ScaledDraw(img)


def _rx_thread(radio):
    """Background receiver thread."""
    radio.start_rx()
    while _running:
        pkt = radio.read_packet(timeout=0.5)
        if pkt and pkt["crc_ok"] and pkt["data"]:
            try:
                text = pkt["data"].decode("utf-8", errors="replace").strip("\x00")
                if text:
                    with _msg_lock:
                        _messages.append({
                            "dir": "rx",
                            "text": text,
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "rssi": pkt["rssi"],
                        })
                        if len(_messages) > 100:
                            _messages.pop(0)
            except Exception:
                pass


def _send_message(radio, text):
    data = text.encode("utf-8")[:58]
    radio.idle()
    ok = radio.send_packet(data)
    radio.start_rx()
    with _msg_lock:
        _messages.append({
            "dir": "tx",
            "text": text,
            "time": datetime.now().strftime("%H:%M:%S"),
            "rssi": 0,
        })
    return ok


def _draw_chat(scroll, input_text):
    img = Image.new("RGB", (W, H), C_BG)
    d = _draw_ctx(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 22], fill=C_HEAD)
        d.text((8, 3), "SubGHz Chat", font=font_lg, fill=C_ORANGE)
        d.text((W - 8, 3), f"{CHAT_FREQ:.0f}MHz", font=font_sm, fill=C_DIM, anchor="ra")
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((2, 1), "SubG Chat", font=font, fill=C_ORANGE)

    with _msg_lock:
        msgs = list(_messages)

    msg_y_start = 24 if IS_WIDE else 16
    msg_y_end = H - 26 if IS_WIDE else H - 20
    row_h = 16 if IS_WIDE else 12
    visible = max(1, (msg_y_end - msg_y_start) // row_h)

    y = msg_y_start
    start_idx = max(0, len(msgs) - visible - scroll)
    end_idx = max(0, len(msgs) - scroll)

    for i in range(start_idx, end_idx):
        if y + row_h > msg_y_end:
            break
        msg = msgs[i]
        is_self = msg["dir"] == "tx"
        col = C_SELF if is_self else C_OTHER
        prefix = ">" if is_self else "<"
        t = msg["time"]
        text = msg["text"]
        max_chars = 32 if IS_WIDE else 16

        if IS_WIDE:
            d.text((6, y), t, font=font_sm, fill=C_DIM)
            d.text((60, y), f"{prefix} {text[:max_chars]}", font=font_sm, fill=col)
            if not is_self and msg.get("rssi"):
                d.text((W - 6, y), f"{msg['rssi']:.0f}dB", font=font_sm, fill=C_DIM, anchor="ra")
        else:
            d.text((2, y), f"{prefix}{text[:max_chars]}", font=font_sm, fill=col)
        y += row_h

    # Input box
    if IS_WIDE:
        d.rectangle([0, H - 24, W, H], fill=C_DARK)
        d.rectangle([4, H - 22, W - 50, H - 4], fill=(20, 25, 40))
        blink = int(time.time() * 2) % 2
        cur = "|" if blink else ""
        d.text((8, H - 20), f"{input_text[-28:]}{cur}", font=font_sm, fill=C_WHITE)
        d.text((W - 6, H - 18), "OK:Send", font=font_sm, fill=C_DIM, anchor="ra")
    else:
        d.rectangle([0, H - 18, 128, H], fill=C_DARK)
        d.rectangle([2, H - 16, 100, H - 2], fill=(20, 25, 40))
        blink = int(time.time() * 2) % 2
        cur = "|" if blink else ""
        d.text((4, H - 14), f"{input_text[-12:]}{cur}", font=font_sm, fill=C_WHITE)
        d.text((104, H - 14), "OK", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _save_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"chat_{ts}.txt")
    with _msg_lock:
        msgs = list(_messages)
    with open(path, "w") as f:
        for m in msgs:
            prefix = "TX" if m["dir"] == "tx" else "RX"
            f.write(f"[{m['time']}] {prefix}: {m['text']}\n")
    return path


def main():
    radio = CC1101()

    img = Image.new("RGB", (W, H), C_BG)
    d = _draw_ctx(img)
    if IS_WIDE:
        d.text((W // 2, H // 2 - 10), "SubGHz Chat", font=font_lg, fill=C_ORANGE, anchor="mm")
        d.text((W // 2, H // 2 + 10), "Initializing CC1101...", font=font_sm, fill=C_DIM, anchor="mm")
    else:
        d.text((64, 50), "SubG Chat", font=font, fill=C_ORANGE)
        d.text((64, 68), "Init CC1101...", font=font_sm, fill=C_DIM)
    LCD.LCD_ShowImage(img, 0, 0)

    if not radio.open():
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw_ctx(img)
        if IS_WIDE:
            d.text((W // 2, H // 2 - 10), "CC1101 HAT not found", font=font, fill=C_RED, anchor="mm")
            d.text((W // 2, H // 2 + 10), "Check Cap connection", font=font_sm, fill=C_DIM, anchor="mm")
        else:
            d.text((64, 50), "No CC1101", font=font, fill=C_RED)
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    radio.set_frequency(CHAT_FREQ)
    radio.set_profile("2fsk_mid")

    rx = threading.Thread(target=_rx_thread, args=(radio,), daemon=True)
    rx.start()

    input_text = ""
    scroll = 0
    last_char_time = 0.0

    try:
        while _running:
            now = time.time()
            typed = _get_typed_char() if EVDEV_OK else None
            if typed and now - last_char_time > 0.12:
                last_char_time = now
                if typed == '\b':
                    input_text = input_text[:-1]
                elif typed == '\n':
                    if input_text.strip():
                        _send_message(radio, input_text.strip())
                        input_text = ""
                        scroll = 0
                elif len(input_text) < 58:
                    input_text += typed

            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "OK" and input_text.strip():
                _send_message(radio, input_text.strip())
                input_text = ""
                scroll = 0
            elif btn == "UP":
                scroll = min(scroll + 1, max(0, len(_messages) - 3))
            elif btn == "DOWN":
                scroll = max(0, scroll - 1)
            elif btn == "KEY1":
                path = _save_log()
                img = Image.new("RGB", (W, H), C_BG)
                d = _draw_ctx(img)
                if IS_WIDE:
                    d.text((W // 2, H // 2), f"Saved {os.path.basename(path)}", font=font_sm, fill=C_GREEN, anchor="mm")
                else:
                    d.text((64, 60), "Saved!", font=font_sm, fill=C_GREEN)
                LCD.LCD_ShowImage(img, 0, 0)
                time.sleep(1)

            _draw_chat(scroll, input_text)
            time.sleep(0.06)
    finally:
        _running = False
        radio.close()
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
