#!/usr/bin/env python3
"""
RaspyJack Payload -- Doodle Jump (IMU)
=======================================
Author: 7h30th3r0n3

Tilt the CardputerZero to move left/right, auto-bounce
on platforms, climb as high as you can!

Controls:
  Tilt L/R   -- Move left/right (D-pad fallback)
  OK         -- Restart
  KEY3       -- Exit
"""

import os
import sys
import math
import time
import random
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

C_BG = "#0a0a12"
C_BG_GRAD = "#06060e"
C_PLAT = "#00E676"
C_PLAT_MOVE = "#FFD740"
C_PLAT_BREAK = "#FF5252"
C_PLAT_SPRING = "#7C4DFF"
C_PLAYER = "#00E5FF"
C_PLAYER_HL = "#80F0FF"
C_EYES = "#0a0a12"
C_TEXT = "#E0E0E0"
C_MUTED = "#888888"
C_HEADER = "#0d1117"
C_GOLD = "#FFD740"
C_RED = "#FF5252"
C_STAR = "#FFD740"

SCREEN_W = 128
SCREEN_H = 128
PLAYER_W = 8
PLAYER_H = 8
PLAT_W = 20
PLAT_H = 3
GRAVITY = 0.18
JUMP_VEL = -4.5
SPRING_VEL = -7.0
MOVE_SPEED = 0.35
MAX_HSPEED = 3.0

PLAT_NORMAL = 0
PLAT_MOVING = 1
PLAT_BREAKING = 2
PLAT_SPRING = 3


def _check_and_install_deps():
    try:
        import smbus2
        return True
    except ImportError:
        pass
    import subprocess
    subprocess.run(
        ["pip3", "install", "--break-system-packages", "smbus2"],
        capture_output=True, timeout=60,
    )
    try:
        import smbus2
        return True
    except ImportError:
        return False


class IMUReader:
    _CTRL1_XL = 0x10
    _OUTX_L_XL = 0x28

    def __init__(self, bus_num=1, addr=0x6A):
        import smbus2
        self._bus = smbus2.SMBus(bus_num)
        self._addr = addr
        self._bus.write_byte_data(self._addr, self._CTRL1_XL, 0x40)
        self._sens = 0.000061
        self._off = 0.0

    def _read_raw_tilt(self):
        data = []
        for reg in (self._OUTX_L_XL, self._OUTX_L_XL + 2):
            low = self._bus.read_byte_data(self._addr, reg)
            high = self._bus.read_byte_data(self._addr, reg + 1)
            val = (high << 8) | low
            if val >= 0x8000:
                val -= 0x10000
            data.append(val * self._sens)
        return data[0]

    def calibrate(self, samples=25, delay=0.02):
        s = 0.0
        for _ in range(samples):
            s += self._read_raw_tilt()
            time.sleep(delay)
        self._off = s / samples

    def read_tilt(self):
        return self._read_raw_tilt() - self._off

    def close(self):
        try:
            self._bus.close()
        except Exception:
            pass


class Platform:
    def __init__(self, x, y, ptype=PLAT_NORMAL):
        self.x = x
        self.y = y
        self.w = PLAT_W
        self.ptype = ptype
        self.alive = True
        self.move_dir = 1 if random.random() < 0.5 else -1
        self.move_speed = 0.5 + random.random() * 0.5
        self.break_timer = 0

    def update(self):
        if self.ptype == PLAT_MOVING:
            self.x += self.move_dir * self.move_speed
            if self.x < 0:
                self.x = 0
                self.move_dir = 1
            elif self.x + self.w > SCREEN_W:
                self.x = SCREEN_W - self.w
                self.move_dir = -1
        if self.ptype == PLAT_BREAKING and self.break_timer > 0:
            self.break_timer -= 1
            self.y += 0.5
            if self.break_timer <= 0:
                self.alive = False


class DoodleGame:
    def __init__(self):
        self.px = SCREEN_W / 2 - PLAYER_W / 2
        self.py = SCREEN_H - 10 - PLAYER_H
        self.vx = 0.0
        self.vy = 0.0
        self.score = 0
        self.high_score = 0
        self.cam_y = 0.0
        self.game_over = False
        self.platforms = []
        self._stars = [(random.randint(0, 127), random.randint(0, 500), random.random() * 0.5 + 0.3) for _ in range(15)]
        self._generate_initial()
        self._facing_left = False

    def _generate_initial(self):
        floor = Platform(0, SCREEN_H - 10)
        floor.x = 0
        floor.w = SCREEN_W
        self.platforms.append(floor)
        y = SCREEN_H - 30
        while y > -SCREEN_H:
            x = random.randint(0, SCREEN_W - PLAT_W)
            self.platforms.append(Platform(x, y))
            y -= random.randint(14, 24)

    def _difficulty(self):
        s = self.score
        if s < 500:
            return 0
        if s < 1500:
            return 1
        if s < 3000:
            return 2
        if s < 5000:
            return 3
        return 4

    def _spawn_platform(self, y):
        diff = self._difficulty()
        x = random.randint(0, SCREEN_W - PLAT_W)
        r = random.random()

        if diff == 0:
            ptype = PLAT_NORMAL
        elif diff == 1:
            ptype = PLAT_MOVING if r < 0.15 else PLAT_NORMAL
        elif diff == 2:
            if r < 0.2:
                ptype = PLAT_MOVING
            elif r < 0.3:
                ptype = PLAT_BREAKING
            elif r < 0.35:
                ptype = PLAT_SPRING
            else:
                ptype = PLAT_NORMAL
        elif diff == 3:
            if r < 0.25:
                ptype = PLAT_MOVING
            elif r < 0.4:
                ptype = PLAT_BREAKING
            elif r < 0.5:
                ptype = PLAT_SPRING
            else:
                ptype = PLAT_NORMAL
        else:
            if r < 0.3:
                ptype = PLAT_MOVING
            elif r < 0.5:
                ptype = PLAT_BREAKING
            elif r < 0.6:
                ptype = PLAT_SPRING
            else:
                ptype = PLAT_NORMAL

        return Platform(x, y, ptype)

    def _gap(self):
        diff = self._difficulty()
        base = 22
        vary = 8 + diff * 3
        return base + random.randint(0, vary)

    def update(self, tilt):
        if self.game_over:
            return

        self.vx = tilt * MOVE_SPEED * 8
        if abs(self.vx) > MAX_HSPEED:
            self.vx = MAX_HSPEED if self.vx > 0 else -MAX_HSPEED
        if self.vx < -0.1:
            self._facing_left = True
        elif self.vx > 0.1:
            self._facing_left = False

        self.vy += GRAVITY
        self.px += self.vx
        self.py += self.vy

        if self.px + PLAYER_W < 0:
            self.px = SCREEN_W
        elif self.px > SCREEN_W:
            self.px = -PLAYER_W

        if self.vy > 0:
            for plat in self.platforms:
                if not plat.alive:
                    continue
                if (self.px + PLAYER_W > plat.x and
                    self.px < plat.x + plat.w and
                    self.py + PLAYER_H >= plat.y and
                    self.py + PLAYER_H <= plat.y + PLAT_H + self.vy + 1):
                    if plat.ptype == PLAT_BREAKING:
                        self.vy = JUMP_VEL
                        plat.break_timer = 15
                    elif plat.ptype == PLAT_SPRING:
                        self.vy = SPRING_VEL
                    else:
                        self.vy = JUMP_VEL

        for plat in self.platforms:
            plat.update()

        if self.py < self.cam_y + SCREEN_H * 0.35:
            new_cam = self.py - SCREEN_H * 0.35
            scroll = self.cam_y - new_cam
            self.cam_y = new_cam
            self.score = max(self.score, int(-self.cam_y))

        self.platforms = [p for p in self.platforms if p.alive and p.y < self.cam_y + SCREEN_H + 20]

        if self.platforms:
            top = min(p.y for p in self.platforms)
        else:
            top = self.cam_y
        while top > self.cam_y - 40:
            top -= self._gap()
            self.platforms.append(self._spawn_platform(top))

        if self.py > self.cam_y + SCREEN_H + 20:
            self.game_over = True
            self.high_score = max(self.high_score, self.score)

    def draw(self, d, fonts):
        font_s, font_t = fonts

        for sx, sy, bright in self._stars:
            star_y = (sy - self.cam_y * 0.3) % (SCREEN_H + 20) - 10
            if 0 <= star_y <= 127:
                c = int(40 + 30 * abs(math.sin(time.monotonic() * bright * 2)))
                d.point((sx, int(star_y)), fill=f"#{c:02x}{c:02x}{c:02x}")

        for plat in self.platforms:
            sx = int(plat.x)
            sy = int(plat.y - self.cam_y)
            if sy < -5 or sy > 130:
                continue
            if plat.ptype == PLAT_NORMAL:
                col = C_PLAT
            elif plat.ptype == PLAT_MOVING:
                col = C_PLAT_MOVE
            elif plat.ptype == PLAT_BREAKING:
                col = C_PLAT_BREAK
            else:
                col = C_PLAT_SPRING

            d.rectangle((sx, sy, sx + plat.w, sy + PLAT_H), fill=col)
            if plat.ptype == PLAT_SPRING:
                spring_x = sx + plat.w // 2
                d.line([(spring_x, sy), (spring_x - 2, sy - 3),
                        (spring_x + 2, sy - 5), (spring_x, sy - 7)], fill=C_GOLD, width=1)

        if not self.game_over:
            px = int(self.px)
            py = int(self.py - self.cam_y)
            # Body
            d.rectangle((px + 1, py + 2, px + PLAYER_W - 1, py + PLAYER_H), fill=C_PLAYER)
            # Head
            d.rectangle((px + 1, py, px + PLAYER_W - 1, py + 3), fill=C_PLAYER_HL)
            # Eyes
            if self._facing_left:
                d.rectangle((px + 1, py + 2, px + 2, py + 3), fill=C_EYES)
                d.rectangle((px + 4, py + 2, px + 5, py + 3), fill=C_EYES)
            else:
                d.rectangle((px + 3, py + 2, px + 4, py + 3), fill=C_EYES)
                d.rectangle((px + 6, py + 2, px + 7, py + 3), fill=C_EYES)
            # Feet
            d.rectangle((px + 1, py + PLAYER_H, px + 3, py + PLAYER_H + 1), fill=C_PLAYER)
            d.rectangle((px + PLAYER_W - 3, py + PLAYER_H, px + PLAYER_W - 1, py + PLAYER_H + 1), fill=C_PLAYER)

        d.text((2, 1), f"Score: {self.score}", font=font_t, fill=C_TEXT)

        diff = self._difficulty()
        diff_names = ["Easy", "Medium", "Hard", "Expert", "Insane"]
        diff_cols = [C_PLAT, C_PLAT_MOVE, C_GOLD, C_RED, "#FF00FF"]
        d.text((90, 1), diff_names[diff], font=font_t, fill=diff_cols[diff])

        if self.game_over:
            d.rectangle((14, 35, 114, 90), fill="#0a0a12")
            d.rectangle((14, 35, 114, 90), outline=C_RED)
            d.text((64, 42), "GAME OVER", font=font_s, fill=C_RED, anchor="mt")
            d.text((64, 56), f"Score: {self.score}", font=font_s, fill=C_GOLD, anchor="mt")
            d.text((64, 70), f"Best: {self.high_score}", font=font_t, fill=C_MUTED, anchor="mt")
            d.text((64, 82), "OK restart", font=font_t, fill=C_MUTED, anchor="mt")


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font_s = scaled_font(10)
    font_t = scaled_font(8)
    fonts = (font_s, font_t)

    _check_and_install_deps()

    imu = None
    try:
        imu = IMUReader()
    except Exception:
        pass

    use_imu = imu is not None

    if use_imu:
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((64, 40), "DOODLE JUMP", font=font_s, fill=C_PLAYER, anchor="mm")
        d.text((64, 56), "Calibrating...", font=font_t, fill=C_GOLD, anchor="mm")
        d.text((64, 72), "Keep device flat", font=font_t, fill=C_MUTED, anchor="mm")
        lcd.LCD_ShowImage(img, 0, 0)
        imu.calibrate(samples=30, delay=0.02)

    ctrl = "Tilt left/right!" if use_imu else "D-pad left/right"
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)
    d.text((64, 30), "DOODLE JUMP", font=font_s, fill=C_PLAYER, anchor="mm")
    d.text((64, 50), ctrl, font=font_t, fill=C_MUTED, anchor="mm")
    d.text((64, 66), "Bounce higher!", font=font_t, fill=C_PLAT, anchor="mm")
    d.text((64, 82), "KEY3 to quit", font=font_t, fill=C_MUTED, anchor="mm")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(2)

    game = DoodleGame()
    high_score = 0
    target_dt = 1.0 / 30

    try:
        while True:
            t0 = time.monotonic()

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break
            if btn == "OK" and game.game_over:
                high_score = max(high_score, game.score)
                game = DoodleGame()
                game.high_score = high_score

            if use_imu:
                tilt = max(-1.0, min(1.0, imu.read_tilt()))
            else:
                tilt = 0.0
                if btn == "LEFT":
                    tilt = -0.7
                elif btn == "RIGHT":
                    tilt = 0.7
            game.update(tilt)

            img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            d = ScaledDraw(img)
            game.draw(d, fonts)
            lcd.LCD_ShowImage(img, 0, 0)

            elapsed = time.monotonic() - t0
            if elapsed < target_dt:
                time.sleep(target_dt - elapsed)

    finally:
        if imu:
            imu.close()
        lcd.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
