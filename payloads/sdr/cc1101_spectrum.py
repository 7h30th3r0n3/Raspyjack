#!/usr/bin/env python3
"""
RaspyJack Payload -- CC1101 Sub-GHz Spectrum Analyzer
======================================================
Author: 7h30th3r0n3

Real-time spectrum analyzer and waterfall display using CC1101 RSSI sweep.
Covers 300-928 MHz sub-GHz bands. No RTL-SDR needed.

Controls:
  UP/DOWN     Change band (315/433/868/915)
  LEFT/RIGHT  Adjust span (narrow/wide)
  OK          Toggle waterfall / peak hold
  KEY1        Toggle peak hold
  KEY2        Reset peak hold
  KEY3        Exit
"""

import os
import sys
import time
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY
from payloads._input_helper import get_button

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
        FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 13)
        FONT_SM = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 10)
        FONT_XS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 9)
    except Exception:
        FONT = scaled_font(9)
        FONT_SM = scaled_font(7)
        FONT_XS = scaled_font(6)
else:
    FONT = scaled_font(9)
    FONT_SM = scaled_font(7)
    FONT_XS = scaled_font(6)

DEBOUNCE = 0.2
_running = True

BANDS = [
    {"name": "FULL 300-928", "center": 615.0, "span": 628.0},
    {"name": "300-450", "center": 375.0, "span": 150.0},
    {"name": "800-928", "center": 864.0, "span": 128.0},
    {"name": "315 MHz", "center": 315.0, "span": 4.0},
    {"name": "418 MHz", "center": 418.0, "span": 4.0},
    {"name": "433.92 ISM", "center": 433.92, "span": 4.0},
    {"name": "868 ISM", "center": 868.0, "span": 4.0},
    {"name": "915 ISM", "center": 915.0, "span": 4.0},
    {"name": "Car Keys", "center": 433.42, "span": 2.0},
    {"name": "Garage", "center": 433.92, "span": 1.0},
    {"name": "TPMS", "center": 315.0, "span": 2.0},
    {"name": "LoRa EU", "center": 868.1, "span": 2.0},
    {"name": "LoRa US", "center": 915.0, "span": 26.0},
    {"name": "PMR446", "center": 446.1, "span": 1.0},
    {"name": "Weather", "center": 433.92, "span": 1.0},
]

SPANS = [1.0, 2.0, 4.0, 8.0, 10.0, 20.0, 50.0, 150.0, 300.0, 628.0]

WATERFALL_COLORS = []
for i in range(256):
    if i < 64:
        WATERFALL_COLORS.append((0, 0, int(i * 4)))
    elif i < 128:
        WATERFALL_COLORS.append((0, int((i - 64) * 4), 255))
    elif i < 192:
        WATERFALL_COLORS.append((int((i - 128) * 4), 255, 255 - int((i - 128) * 4)))
    else:
        WATERFALL_COLORS.append((255, 255 - int((i - 192) * 4), 0))


def _sig_handler(sig, frame):
    global _running
    _running = False

signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


def _rssi_to_color(rssi, floor=-105, ceil=-30):
    norm = max(0.0, min(1.0, (rssi - floor) / (ceil - floor)))
    return WATERFALL_COLORS[min(255, int(norm * 255))]


def _rssi_sweep(radio, center, span, num_bins):
    start = center - span / 2.0
    step = span / num_bins
    rssi_data = []
    FOSC = 26_000_000
    for i in range(num_bins):
        freq_mhz = start + i * step
        freq_hz = int(freq_mhz * 1_000_000)
        freq_word = int(freq_hz * (2**16) / FOSC)
        radio._strobe(0x36)  # SIDLE
        radio._write_reg(0x0D, (freq_word >> 16) & 0xFF)
        radio._write_reg(0x0E, (freq_word >> 8) & 0xFF)
        radio._write_reg(0x0F, freq_word & 0xFF)
        radio._strobe(0x3A)  # SFRX
        radio._strobe(0x34)  # SRX
        time.sleep(0.003)
        raw = radio._spi.xfer2([0x34 | 0xC0, 0x00])[1]
        if raw >= 128:
            rssi = (raw - 256) / 2.0 - 74
        else:
            rssi = raw / 2.0 - 74
        rssi_data.append(rssi)
    return rssi_data


def main():
    from payloads._cc1101_driver import CC1101

    img = Image.new("RGB", (W, H), "#000")
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    d.text((W // 2, H // 2 - 10), "CC1101 Spectrum", font=FONT, fill="#00E5FF", anchor="mm")
    d.text((W // 2, H // 2 + 10), "Connecting...", font=FONT_SM, fill="#666", anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)

    radio = CC1101()
    if not radio.open():
        d.rectangle((0, 0, W, H), fill="#000")
        d.text((W // 2, H // 2), "CC1101 not found", font=FONT, fill="#FF4444", anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(2)
        GPIO.cleanup()
        return 1

    radio.set_profile("AM650")
    radio._write_reg(0x12, 0x30)  # MDMCFG2: OOK, no sync
    radio._write_reg(0x08, 0x42)  # PKTCTRL0: async serial (RSSI always valid)
    radio._write_reg(0x18, 0x18)  # MCSM0: auto-cal IDLE->RX

    band_idx = 0
    show_waterfall = True
    peak_hold = True
    last_btn = 0

    center = BANDS[band_idx]["center"]
    span = BANDS[band_idx].get("span", 4.0)

    HDR_H = 16 if IS_WIDE else 12
    FTR_H = 14 if IS_WIDE else 10
    NUM_BINS = 128

    waterfall_img = Image.new("RGB", (NUM_BINS, 200), "#000")
    wf_row = 0
    peak = [-120.0] * NUM_BINS
    rssi_floor = -105
    rssi_ceil = -30

    while _running:
        btn = get_button(PINS, GPIO)

        if btn == "KEY3":
            break

        now = time.time()
        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            band_idx = (band_idx - 1) % len(BANDS)
            center = BANDS[band_idx]["center"]
            span = BANDS[band_idx].get("span", 4.0)
            peak = [-120.0] * NUM_BINS
            waterfall_img = Image.new("RGB", (NUM_BINS, 200), "#000")
            wf_row = 0

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            band_idx = (band_idx + 1) % len(BANDS)
            center = BANDS[band_idx]["center"]
            span = BANDS[band_idx].get("span", 4.0)
            peak = [-120.0] * NUM_BINS
            waterfall_img = Image.new("RGB", (NUM_BINS, 200), "#000")
            wf_row = 0

        if btn == "RIGHT" and now - last_btn > DEBOUNCE:
            last_btn = now
            span = min(628.0, span * 2)
            peak = [-120.0] * NUM_BINS
            waterfall_img = Image.new("RGB", (NUM_BINS, 200), "#000")
            wf_row = 0

        if btn == "LEFT" and now - last_btn > DEBOUNCE:
            last_btn = now
            span = max(0.5, span / 2)
            peak = [-120.0] * NUM_BINS
            waterfall_img = Image.new("RGB", (NUM_BINS, 200), "#000")
            wf_row = 0

        if btn == "OK" and now - last_btn > 0.3:
            last_btn = now
            show_waterfall = not show_waterfall

        if btn == "KEY1" and now - last_btn > 0.3:
            last_btn = now
            peak_hold = not peak_hold
            if not peak_hold:
                peak = [-120.0] * NUM_BINS

        if btn == "KEY2" and now - last_btn > 0.3:
            last_btn = now
            peak = [-120.0] * NUM_BINS

        rssi_data = _rssi_sweep(radio, center, span, NUM_BINS)

        if peak_hold:
            for i in range(NUM_BINS):
                if rssi_data[i] > peak[i]:
                    peak[i] = rssi_data[i]

        spec_h = (H - HDR_H - FTR_H) // 2 if show_waterfall else (H - HDR_H - FTR_H)
        wf_h = H - HDR_H - FTR_H - spec_h if show_waterfall else 0
        bar_w = max(1, W / NUM_BINS)

        img = Image.new("RGB", (W, H), "#000")
        d = ImageDraw.Draw(img)

        # Header
        d.rectangle((0, 0, W, HDR_H - 1), fill="#0a0a1a")
        d.text((4, 2), "CC1101", font=FONT_SM, fill="#00E5FF")
        center_str = "%.2f MHz" % center
        d.text((W // 2, 2), center_str, font=FONT_SM, fill="#00FF00", anchor="ma")
        span_str = "Span %.1f" % span
        d.text((W - 4, 2), span_str, font=FONT_XS, fill="#666", anchor="ra")

        # Spectrum bars
        spec_top = HDR_H
        spec_bot = spec_top + spec_h

        for i in range(NUM_BINS):
            rssi = rssi_data[i]
            norm = max(0.0, min(1.0, (rssi - rssi_floor) / (rssi_ceil - rssi_floor)))
            bar_h = int(norm * spec_h)
            x1 = int(i * bar_w)
            x2 = int((i + 1) * bar_w) - 1
            if x2 < x1:
                x2 = x1
            if bar_h > 1:
                col = _rssi_to_color(rssi, rssi_floor, rssi_ceil)
                d.rectangle((x1, spec_bot - bar_h, x2, spec_bot - 1), fill=col)

            if peak_hold and peak[i] > rssi_floor + 5:
                pnorm = max(0.0, min(1.0, (peak[i] - rssi_floor) / (rssi_ceil - rssi_floor)))
                py = spec_bot - int(pnorm * spec_h)
                d.rectangle((x1, py, x2, py), fill="#FF4444")

        # Grid lines
        for db in range(-100, -20, 20):
            norm = max(0.0, min(1.0, (db - rssi_floor) / (rssi_ceil - rssi_floor)))
            y = spec_bot - int(norm * spec_h)
            if spec_top < y < spec_bot:
                d.line([(0, y), (W, y)], fill="#1a1a1a")
                d.text((2, y - 8), "%d" % db, font=FONT_XS, fill="#333")

        # Waterfall
        if show_waterfall and wf_h > 0:
            for i in range(NUM_BINS):
                col = _rssi_to_color(rssi_data[i], rssi_floor, rssi_ceil)
                waterfall_img.putpixel((i, wf_row % 200), col)
            wf_row += 1

            wf_top = spec_bot + 1
            for row in range(wf_h):
                src_row = (wf_row - 1 - row) % 200
                if src_row < 0:
                    continue
                y = wf_top + row
                if y >= H - FTR_H:
                    break
                for i in range(NUM_BINS):
                    col = waterfall_img.getpixel((i, src_row))
                    x1 = int(i * bar_w)
                    x2 = int((i + 1) * bar_w) - 1
                    if x2 < x1:
                        x2 = x1
                    if col != (0, 0, 0):
                        d.rectangle((x1, y, x2, y), fill=col)

        # Footer
        d.rectangle((0, H - FTR_H, W, H), fill="#0a0a1a")
        start_f = center - span / 2
        end_f = center + span / 2
        d.text((4, H - FTR_H + 2), "%.1f" % start_f, font=FONT_XS, fill="#666")
        d.text((W - 4, H - FTR_H + 2), "%.1f" % end_f, font=FONT_XS, fill="#666", anchor="ra")

        indicators = []
        if peak_hold:
            indicators.append("PK")
        if show_waterfall:
            indicators.append("WF")
        indicators.append(BANDS[band_idx]["name"])
        d.text((W // 2, H - FTR_H + 2), " ".join(indicators), font=FONT_XS, fill="#FF8C00", anchor="ma")

        LCD.LCD_ShowImage(img, 0, 0)

    radio.close()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
