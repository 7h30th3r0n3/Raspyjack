#!/usr/bin/env python3
"""
RaspyJack Payload -- Cyber Swarm (Pikmin-like)
================================================
Author: 7h30th3r0n3

Pikmin-style game in a cyberpunk network world.
Control a hacker leading a swarm of bots through servers.

Controls:
  D-pad     -- Move leader
  OK        -- Throw bot in facing direction
  KEY1      -- Whistle (recall all bots)
  KEY2      -- Cycle bot type
  KEY3      -- Exit

Bot types:
  RED (Exploit)  -- 2x damage, breaks firewalls
  BLUE (Worm)    -- Crosses water/barriers
  YELLOW (Miner) -- Collects heavy data
"""

import os, sys, time, signal, random, math, mmap
import numpy as np
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

font = scaled_font(13)
font_sm = scaled_font(11)
font_xs = scaled_font(9)

from PIL import ImageFont as _IF
try:
    _native_font = _IF.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    _native_font_sm = _IF.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
    _native_font_xs = _IF.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
except Exception:
    _native_font = _IF.load_default()
    _native_font_sm = _native_font
    _native_font_xs = _native_font

C_BG = "#060612"
C_GRID = "#0A0F1A"
C_LEADER = "#00E5FF"
C_LEADER_HL = "#88FFFF"
C_CYAN = "#00E5FF"
C_RED = "#FF5252"
C_BLUE = "#448AFF"
C_YELLOW = "#FFD740"
C_GREEN = "#00E676"
C_PURPLE = "#7C4DFF"
C_WHITE = "#E0E0E0"
C_DIM = "#333344"
C_WALL = "#1A1A3A"
C_DATA = "#00FF88"
C_ENEMY = "#FF0066"
C_BOSS = "#FF00FF"
C_WATER = "#003388"
C_HEADER = "#0d1117"

BOT_TYPES = ["exploit", "worm", "miner"]
BOT_COLORS = {"exploit": C_RED, "worm": C_BLUE, "miner": C_YELLOW}
BOT_NAMES = {"exploit": "EXP", "worm": "WRM", "miner": "MNR"}

TILE_EMPTY = 0
TILE_WALL = 1
TILE_WATER = 2
TILE_BOT_SPAWN = 4

MAP_W, MAP_H = 40, 40
VIEW_TILES_W = 14
VIEW_TILES_H = 12
TILE_SIZE = 8

_running = True


def _sig(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


class FloatText:
    __slots__ = ('x', 'y', 'text', 'color', 'life')

    def __init__(self, x, y, text, color=C_WHITE):
        self.x = x
        self.y = y
        self.text = text
        self.color = color
        self.life = 20

    def update(self):
        self.y -= 0.3
        self.life -= 1
        return self.life > 0


class Bot:
    __slots__ = ('x', 'y', 'btype', 'target_x', 'target_y', 'state', 'hp', 'max_hp', 'atk_cd', 'facing', 'moving')

    def __init__(self, x, y, btype):
        self.x = float(x)
        self.y = float(y)
        self.btype = btype
        self.target_x = x
        self.target_y = y
        self.state = "follow"
        self.hp = 4
        self.max_hp = 4
        self.atk_cd = 0
        self.facing = "down"
        self.moving = False


class Enemy:
    __slots__ = ('x', 'y', 'hp', 'max_hp', 'attack', 'is_boss', 'dead', 'flash', 'name', 'facing', 'prev_x', 'prev_y')

    def __init__(self, x, y, hp=5, attack=1, is_boss=False, name="Firewall"):
        self.x = x
        self.y = y
        self.hp = hp
        self.max_hp = hp
        self.attack = attack
        self.is_boss = is_boss
        self.dead = False
        self.flash = 0
        self.name = name
        self.facing = "down"
        self.prev_x = x
        self.prev_y = y


class DataItem:
    __slots__ = ('x', 'y', 'collected', 'weight')

    def __init__(self, x, y, weight=1):
        self.x = x
        self.y = y
        self.collected = False
        self.weight = weight


class Game:
    def __init__(self):
        self.px = 5.0
        self.py = 5.0
        self.face_dx = 1
        self.face_dy = 0
        self.is_moving = False
        self.leader_hp = 10
        self.leader_max_hp = 10
        self.leader_hurt_timer = 0
        self.leader_atk_cd = 0
        self.lives = 3
        self.dead = False
        self.respawn_timer = 0
        self.bots = []
        self.enemies = []
        self.data_items = []
        self.floats = []
        self.tilemap = [[TILE_EMPTY] * MAP_W for _ in range(MAP_H)]
        self._map_img = None
        self._last_frame = None
        self._last_cam = (-1, -1)
        self.score = 0
        self.level = 1
        self.bot_type_idx = 0
        self.whistle_timer = 0
        self.msg = ""
        self.msg_timer = 0
        self.frame = 0
        self.data_total = 0
        self.data_collected = 0
        self.flash_screen = 0
        self.paused = False
        self._seen_types = set()
        self._popup = None
        self._popup_timer = 0
        self._generate_level()

    def _generate_level(self):
        for y in range(MAP_H):
            for x in range(MAP_W):
                self.tilemap[y][x] = TILE_EMPTY

        for y in range(MAP_H):
            self.tilemap[y][0] = TILE_WALL
            self.tilemap[y][MAP_W - 1] = TILE_WALL
        for x in range(MAP_W):
            self.tilemap[0][x] = TILE_WALL
            self.tilemap[MAP_H - 1][x] = TILE_WALL

        n_walls = 20 + self.level * 8
        for _ in range(n_walls):
            wx = random.randint(2, MAP_W - 3)
            wy = random.randint(2, MAP_H - 3)
            if abs(wx - int(self.px)) < 4 and abs(wy - int(self.py)) < 4:
                continue
            length = random.randint(2, 4)
            horiz = random.random() < 0.5
            for i in range(length):
                nx = wx + (i if horiz else 0)
                ny = wy + (0 if horiz else i)
                if 1 <= nx < MAP_W - 1 and 1 <= ny < MAP_H - 1:
                    self.tilemap[ny][nx] = TILE_WALL

        if self.level > 1:
            for _ in range(3 + self.level):
                wx = random.randint(3, MAP_W - 4)
                wy = random.randint(3, MAP_H - 4)
                for dy in range(random.randint(1, 3)):
                    for dx in range(random.randint(2, 4)):
                        ny, nx = wy + dy, wx + dx
                        if 1 <= nx < MAP_W - 1 and 1 <= ny < MAP_H - 1:
                            if self.tilemap[ny][nx] == TILE_EMPTY:
                                self.tilemap[ny][nx] = TILE_WATER

        self.enemies = []
        enemy_names = ["Firewall", "IDS", "Proxy", "WAF", "Guard"]
        if self.level == 1:
            n_enemies = 2
        else:
            n_enemies = 2 + self.level * 2
        for i in range(n_enemies):
            for _ in range(20):
                ex = random.randint(8, MAP_W - 3)
                ey = random.randint(8, MAP_H - 3)
                if self.tilemap[ey][ex] == TILE_EMPTY:
                    hp = 3 + self.level
                    name = enemy_names[i % len(enemy_names)]
                    self.enemies.append(Enemy(ex, ey, hp=hp, attack=max(1, self.level - 1), name=name))
                    break

        if self.level > 1:
            for _ in range(20):
                bx = random.randint(MAP_W - 10, MAP_W - 3)
                by = random.randint(MAP_H - 10, MAP_H - 3)
                if self.tilemap[by][bx] == TILE_EMPTY:
                    self.enemies.append(Enemy(bx, by, hp=8 + self.level * 4,
                                              attack=self.level, is_boss=True, name="ROOT"))
                    break

        self.data_items = []
        n_data = 4 + self.level * 2
        for _ in range(n_data):
            for _ in range(20):
                dx = random.randint(3, MAP_W - 3)
                dy = random.randint(3, MAP_H - 3)
                if self.tilemap[dy][dx] == TILE_EMPTY:
                    w = 1 if random.random() < 0.7 else 3
                    self.data_items.append(DataItem(dx, dy, weight=w))
                    break
        self.data_total = len(self.data_items)
        self.data_collected = 0

        n_spawns = 5 + self.level * 2
        for _ in range(n_spawns):
            for _ in range(20):
                sx = random.randint(2, MAP_W - 3)
                sy = random.randint(2, MAP_H - 3)
                if self.tilemap[sy][sx] == TILE_EMPTY:
                    self.tilemap[sy][sx] = TILE_BOT_SPAWN
                    break
        self._render_map_cache()

    def _render_map_cache(self):
        from PIL import ImageDraw
        sx_f = WIDTH / 128.0
        sy_f = HEIGHT / 128.0
        ts_x = int(TILE_SIZE * sx_f)
        ts_y = int(TILE_SIZE * sy_f)
        self._ts_x = ts_x
        self._ts_y = ts_y
        self._sx_f = sx_f
        self._sy_f = sy_f
        self._map_img = Image.new("RGB", (MAP_W * ts_x, MAP_H * ts_y), C_BG)
        draw = ImageDraw.Draw(self._map_img)
        wall_rgb = (26, 26, 58)
        water_rgb = (0, 51, 85)
        spawn_rgb = (0, 68, 0)
        for my in range(MAP_H):
            for mx in range(MAP_W):
                tile = self.tilemap[my][mx]
                if tile == TILE_EMPTY:
                    continue
                sx = mx * ts_x
                sy = my * ts_y
                if tile == TILE_WALL:
                    draw.rectangle((sx, sy, sx + ts_x - 1, sy + ts_y - 1), fill=wall_rgb)
                elif tile == TILE_WATER:
                    draw.rectangle((sx, sy, sx + ts_x - 1, sy + ts_y - 1), fill=water_rgb)
                elif tile == TILE_BOT_SPAWN:
                    draw.rectangle((sx + 2, sy + 2, sx + ts_x - 3, sy + ts_y - 3), fill=spawn_rgb)

    def _float(self, x, y, text, color=C_WHITE):
        self.floats.append(FloatText(x, y, text, color))

    def _msg(self, text, dur=35):
        self.msg = text
        self.msg_timer = dur

    def _can_walk(self, x, y, is_worm=False):
        ix, iy = int(x), int(y)
        if ix < 0 or iy < 0 or ix >= MAP_W or iy >= MAP_H:
            return False
        t = self.tilemap[iy][ix]
        if t == TILE_WALL:
            return False
        if t == TILE_WATER and not is_worm:
            return False
        return True

    def update(self, dx, dy, throw, whistle, cycle_type):
        self.frame += 1

        if self.msg_timer > 0:
            self.msg_timer -= 1
            if self.msg_timer <= 0:
                self.msg = ""

        if self.flash_screen > 0:
            self.flash_screen -= 1

        self.floats = [f for f in self.floats if f.update()]

        if cycle_type:
            self.bot_type_idx = (self.bot_type_idx + 1) % len(BOT_TYPES)
            t = BOT_TYPES[self.bot_type_idx]
            n = sum(1 for b in self.bots if b.btype == t)
            self._msg(f"{BOT_NAMES[t]} x{n}", 20)

        self.is_moving = dx != 0 or dy != 0
        if self.is_moving:
            self.face_dx = dx
            self.face_dy = dy

        speed = 0.3
        aspect = self._sx_f / max(self._sy_f, 0.01)
        nx = self.px + dx * speed
        ny = self.py + dy * speed * aspect
        if self._can_walk(nx, self.py):
            self.px = nx
        if self._can_walk(self.px, ny):
            self.py = ny
        self.px = max(1, min(MAP_W - 2, self.px))
        self.py = max(1, min(MAP_H - 2, self.py))

        ix, iy = int(self.px), int(self.py)
        if self.tilemap[iy][ix] == TILE_BOT_SPAWN:
            self.tilemap[iy][ix] = TILE_EMPTY
            if self._map_img:
                from PIL import ImageDraw
                ts = TILE_SIZE
                mdraw = ImageDraw.Draw(self._map_img)
                mdraw.rectangle((ix * ts, iy * ts, ix * ts + ts - 1, iy * ts + ts - 1),
                                fill=(6, 6, 18))
            btype = random.choice(BOT_TYPES)
            self.bots.append(Bot(self.px, self.py, btype))
            self._float(self.px, self.py - 1, f"+{BOT_NAMES[btype]}", BOT_COLORS[btype])
            self._msg(f"Recruited {BOT_NAMES[btype]}!", 25)
            if btype not in self._seen_types:
                self._seen_types.add(btype)
                descs = {
                    "exploit": ("EXPLOIT Bot!", "Strong fighter.\n2x damage to enemies.\nThrow at firewalls!"),
                    "worm": ("WORM Bot!", "Can cross water!\nFast movement.\nExplore everywhere."),
                    "miner": ("MINER Bot!", "Collects heavy data.\nNeeded for big items.\nSlow but strong."),
                }
                title, desc = descs.get(btype, ("New Bot!", ""))
                self._popup = (title, desc, BOT_COLORS[btype])
                self._popup_timer = 0

        if whistle:
            self.whistle_timer = 10
            for bot in self.bots:
                bot.state = "follow"
            self._msg("RECALL!", 15)

        if throw:
            threw = False
            if self.bots:
                selected_type = BOT_TYPES[self.bot_type_idx]
                candidates = [b for b in self.bots if b.btype == selected_type and b.state == "follow"]
                if not candidates:
                    candidates = [b for b in self.bots if b.state == "follow"]
                if candidates:
                    bot = candidates[0]
                    bot.target_x = self.px + self.face_dx * 6
                    bot.target_y = self.py + self.face_dy * 6
                    bot.state = "thrown"
                    threw = True
            if not threw and self.leader_atk_cd <= 0:
                for enemy in self.enemies:
                    if enemy.dead:
                        continue
                    if math.hypot(self.px - enemy.x, self.py - enemy.y) < 2.5:
                        enemy.hp -= 1
                        enemy.flash = 3
                        self.leader_atk_cd = 12
                        self._float(enemy.x, enemy.y - 1, "-1", C_CYAN)
                        if enemy.hp <= 0:
                            enemy.dead = True
                            pts = 100 if enemy.is_boss else 20
                            self.score += pts
                            self._float(enemy.x, enemy.y - 2, f"+{pts}", C_YELLOW)
                            self.flash_screen = 6
                            if enemy.is_boss:
                                self._popup = ("ROOT DEFEATED!", f"{enemy.name} destroyed!\n+{pts} points\nCollect data to advance.", C_BOSS)
                            else:
                                self._msg(f"{enemy.name} destroyed!", 30)
                        break

        for bot in self.bots:
            is_worm = bot.btype == "worm"
            hp_ratio = bot.hp / bot.max_hp
            old_x, old_y = bot.x, bot.y
            if bot.state == "follow":
                tdx = self.px - bot.x + random.uniform(-0.3, 0.3)
                tdy = self.py - bot.y + random.uniform(-0.3, 0.3)
                dist = math.hypot(tdx, tdy)
                if dist > 1.2:
                    spd = 0.25 * (0.4 + 0.6 * hp_ratio)
                    nx = bot.x + (tdx / dist) * spd
                    ny = bot.y + (tdy / dist) * spd
                    if self._can_walk(nx, bot.y, is_worm):
                        bot.x = nx
                    if self._can_walk(bot.x, ny, is_worm):
                        bot.y = ny
            elif bot.state == "thrown":
                tdx = bot.target_x - bot.x
                tdy = bot.target_y - bot.y
                dist = math.hypot(tdx, tdy)
                if dist > 0.5:
                    spd = 0.5 * (0.5 + 0.5 * hp_ratio)
                    nx = bot.x + (tdx / dist) * spd
                    ny = bot.y + (tdy / dist) * spd
                    if self._can_walk(nx, bot.y, is_worm):
                        bot.x = nx
                    if self._can_walk(bot.x, ny, is_worm):
                        bot.y = ny
                    if not self._can_walk(nx, ny, is_worm):
                        bot.state = "idle"
                else:
                    bot.state = "idle"
            dx_b = bot.x - old_x
            dy_b = bot.y - old_y
            bot.moving = abs(dx_b) > 0.01 or abs(dy_b) > 0.01
            if bot.moving:
                if abs(dx_b) > abs(dy_b):
                    bot.facing = "right" if dx_b > 0 else "left"
                else:
                    bot.facing = "down" if dy_b > 0 else "up"
            elif bot.state == "attacking":
                if bot.atk_cd > 0:
                    bot.atk_cd -= 1
                has_target = False
                for enemy in self.enemies:
                    if not enemy.dead and math.hypot(bot.x - enemy.x, bot.y - enemy.y) < 2.5:
                        has_target = True
                        break
                if not has_target:
                    bot.state = "follow"

        for enemy in self.enemies:
            if enemy.dead:
                continue
            if enemy.flash > 0:
                enemy.flash -= 1

            e_key = "boss" if enemy.is_boss else "enemy"
            if e_key not in self._seen_types:
                pdist = math.hypot(self.px - enemy.x, self.py - enemy.y)
                if pdist < 8:
                    self._seen_types.add(e_key)
                    if enemy.is_boss:
                        self._popup = ("ROOT ACCESS!", "Boss firewall!\nDeploy all bots.\nDefeat to advance.", C_BOSS)
                    else:
                        self._popup = ("FIREWALL!", "Enemy detected!\nThrow Exploits at it.\nWatch your bots' HP.", C_ENEMY)
                    self._popup_timer = 0

            for bot in self.bots:
                if bot.hp <= 0:
                    continue
                dist = math.hypot(bot.x - enemy.x, bot.y - enemy.y)
                if dist < 1.8:
                    bot.state = "attacking"
                    bot.target_x = enemy.x
                    bot.target_y = enemy.y
                    if bot.atk_cd <= 0:
                        dmg = 2 if bot.btype == "exploit" else 1
                        enemy.hp -= dmg
                        enemy.flash = 4
                        bot.atk_cd = 10
                        self._float(enemy.x, enemy.y - 1, f"-{dmg}", C_RED)
                        if enemy.hp <= 0:
                            enemy.dead = True
                            pts = 100 if enemy.is_boss else 20
                            self.score += pts
                            self._float(enemy.x, enemy.y - 2, f"+{pts}", C_YELLOW)
                            self.flash_screen = 6
                            if enemy.is_boss:
                                self._popup = ("ROOT DEFEATED!", f"{enemy.name} destroyed!\n+{pts} points\nCollect data to advance.", C_BOSS)
                            else:
                                self._msg(f"{enemy.name} destroyed!", 30)

            if not enemy.dead and self.frame % 8 == 0:
                enemy.prev_x, enemy.prev_y = enemy.x, enemy.y
                pdist = math.hypot(self.px - enemy.x, self.py - enemy.y)
                if pdist < 12:
                    edx = self.px - enemy.x
                    edy = self.py - enemy.y
                    ed = max(0.1, math.hypot(edx, edy))
                    spd = 0.15 if not enemy.is_boss else 0.1
                    nx = enemy.x + (edx / ed) * spd
                    ny = enemy.y + (edy / ed) * spd
                    if self._can_walk(nx, ny):
                        enemy.x = nx
                        enemy.y = ny
                    dx_e = enemy.x - enemy.prev_x
                    dy_e = enemy.y - enemy.prev_y
                    if abs(dx_e) > 0.01 or abs(dy_e) > 0.01:
                        if abs(dx_e) > abs(dy_e):
                            enemy.facing = "right" if dx_e > 0 else "left"
                        else:
                            enemy.facing = "down" if dy_e > 0 else "up"

            if not enemy.dead and self.frame % 25 == 0:
                for bot in self.bots:
                    if bot.hp <= 0:
                        continue
                    if math.hypot(bot.x - enemy.x, bot.y - enemy.y) < 1.8:
                        bot.hp -= enemy.attack
                        if bot.hp <= 0:
                            self._float(bot.x, bot.y - 1, "LOST", C_RED)
                if math.hypot(self.px - enemy.x, self.py - enemy.y) < 2.0:
                    if self.leader_hurt_timer <= 0:
                        self.leader_hp -= enemy.attack
                        self.leader_hurt_timer = 15
                        self._float(self.px, self.py - 1, f"-{enemy.attack}", C_RED)
                        if self.leader_hp <= 0:
                            self.leader_hp = 0
                            self.lives -= 1
                            if self.lives <= 0:
                                self.dead = True
                                self._popup = ("GAME OVER", f"System destroyed!\nFinal score: {self.score}\nOK to restart", C_RED)
                            else:
                                self._popup = ("SYSTEM CRASH!", f"Lost a life!\nLives: {self.lives}\nRespawning...", C_RED)
                                self.respawn_timer = 1

        if self.leader_hurt_timer > 0:
            self.leader_hurt_timer -= 1

        if self.leader_atk_cd > 0:
            self.leader_atk_cd -= 1

        if self.respawn_timer > 0 and self._popup is None:
            self.respawn_timer = 0
            self.px = 5.0
            self.py = 5.0
            self.leader_hp = self.leader_max_hp
            self.leader_hurt_timer = 30
            for bot in self.bots:
                bot.x = self.px + random.uniform(-1, 1)
                bot.y = self.py + random.uniform(-1, 1)
                bot.state = "follow"

        if self.frame % 60 == 0 and self.leader_hp < self.leader_max_hp and self.leader_hp > 0:
            self.leader_hp = min(self.leader_max_hp, self.leader_hp + 1)

        self.bots = [b for b in self.bots if b.hp > 0]

        for item in self.data_items:
            if item.collected:
                continue
            leader_dist = math.hypot(self.px - item.x, self.py - item.y)
            nearby = [b for b in self.bots if math.hypot(b.x - item.x, b.y - item.y) < 2.0]
            if item.weight <= 1:
                if leader_dist < 1.5 or len(nearby) >= 1:
                    item.collected = True
                    self.score += 10
                    self.data_collected += 1
                    self._float(item.x, item.y - 1, "+10", C_DATA)
            else:
                miners = [b for b in nearby if b.btype == "miner"]
                if miners or len(nearby) >= 3:
                    item.collected = True
                    self.score += 25
                    self.data_collected += 1
                    self._float(item.x, item.y - 1, "+25", C_YELLOW)
                elif leader_dist < 1.5 and len(nearby) >= 1:
                    self._msg("Need Miner or 3 bots!", 20)

        boss_alive = [e for e in self.enemies if e.is_boss and not e.dead]
        if self.level == 1:
            all_enemies_dead = all(e.dead for e in self.enemies)
            if all_enemies_dead and self.data_collected >= max(1, self.data_total // 2):
                self._next_level()
        elif not boss_alive and self.data_collected >= max(1, self.data_total // 2):
            self._next_level()

    def _next_level(self):
        self.level += 1
        self.px = 5.0
        self.py = 5.0
        for bot in self.bots:
            bot.x = self.px + random.uniform(-1, 1)
            bot.y = self.py + random.uniform(-1, 1)
            bot.state = "follow"
            bot.hp = bot.max_hp
        self._generate_level()
        self.flash_screen = 10
        n_foes = sum(1 for e in self.enemies if not e.dead)
        has_boss = any(e.is_boss for e in self.enemies)
        desc = f"Enemies: {n_foes}"
        if has_boss:
            desc += "\nBoss awaits!"
        desc += f"\nData: {self.data_total} packets"
        desc += f"\nBots healed!"
        self._popup = (f"LEVEL {self.level}", desc, C_CYAN)

    def draw(self, d):
        cam_x = int(self.px) - VIEW_TILES_W // 2
        cam_y = int(self.py) - VIEW_TILES_H // 2
        cam_x = max(0, min(MAP_W - VIEW_TILES_W, cam_x))
        cam_y = max(0, min(MAP_H - VIEW_TILES_H, cam_y))

        ox, oy = 0, 13

        if self._map_img:
            from payloads._display_helper import SX, SY
            ts = TILE_SIZE
            crop_x = cam_x * ts
            crop_y = cam_y * ts
            crop_w = VIEW_TILES_W * ts
            crop_h = VIEW_TILES_H * ts
            region = self._map_img.crop((crop_x, crop_y, crop_x + crop_w, crop_y + crop_h))
            pw = int(SX(crop_w))
            ph = int(SY(crop_h))
            px = int(SX(ox))
            py = int(SY(oy))
            if region.size != (pw, ph):
                region = region.resize((pw, ph), Image.NEAREST)
            d._draw._image.paste(region, (px, py))

        for item in self.data_items:
            if item.collected:
                continue
            sx = ox + int((item.x - cam_x) * TILE_SIZE)
            sy = oy + int((item.y - cam_y) * TILE_SIZE)
            if ox <= sx < ox + VIEW_TILES_W * TILE_SIZE and oy <= sy < oy + VIEW_TILES_H * TILE_SIZE:
                if item.weight <= 1:
                    d.rectangle((sx, sy, sx + 3, sy + 3), fill=C_DATA)
                else:
                    d.rectangle((sx - 1, sy - 1, sx + 4, sy + 4), fill=C_YELLOW, outline="#AA8800")

        for enemy in self.enemies:
            if enemy.dead:
                continue
            sx = ox + int((enemy.x - cam_x) * TILE_SIZE)
            sy = oy + int((enemy.y - cam_y) * TILE_SIZE)
            if not (ox <= sx < ox + VIEW_TILES_W * TILE_SIZE):
                continue
            col = C_BOSS if enemy.is_boss else C_ENEMY
            if enemy.flash > 0:
                col = C_WHITE
            sz = 4 if enemy.is_boss else 3
            d.rectangle((sx - sz, sy - sz, sx + sz, sy + sz), fill=col)
            if enemy.is_boss:
                d.rectangle((sx - sz + 1, sy - sz + 1, sx + sz - 1, sy - 1), fill="#880044")
            bar_w = sz * 2 + 2
            bar_x = sx - bar_w // 2
            hp_pct = max(0, enemy.hp / enemy.max_hp)
            d.rectangle((bar_x, sy - sz - 4, bar_x + bar_w, sy - sz - 2), fill="#1A1A2E")
            fw = int(bar_w * hp_pct)
            if fw > 0:
                d.rectangle((bar_x, sy - sz - 4, bar_x + fw, sy - sz - 2), fill=C_RED)

        for bot in self.bots:
            sx = ox + int((bot.x - cam_x) * TILE_SIZE)
            sy = oy + int((bot.y - cam_y) * TILE_SIZE)
            if not (ox <= sx < ox + VIEW_TILES_W * TILE_SIZE):
                continue
            col = BOT_COLORS.get(bot.btype, C_WHITE)
            if bot.hp < bot.max_hp:
                col = C_DIM
            d.rectangle((sx, sy, sx + 2, sy + 2), fill=col)
            if bot.state == "attacking" and self.frame % 4 < 2:
                d.point((sx + 1, sy - 1), fill=C_WHITE)

        lx = ox + int((self.px - cam_x) * TILE_SIZE)
        ly = oy + int((self.py - cam_y) * TILE_SIZE)
        d.rectangle((lx - 2, ly - 2, lx + 3, ly + 3), fill=C_LEADER, outline=C_LEADER_HL)
        d.rectangle((lx, ly, lx + 1, ly + 1), fill=C_WHITE)

        if self.bots and self.frame % 8 < 5:
            ax = lx + self.face_dx * 8
            ay = ly + self.face_dy * 8
            d.point((ax, ay), fill=C_DIM)

        if self.whistle_timer > 0:
            self.whistle_timer -= 1
            r = (10 - self.whistle_timer) * 2
            d.ellipse((lx - r, ly - r, lx + r, ly + r), outline=C_LEADER_HL)

        for ft in self.floats:
            sx = ox + int((ft.x - cam_x) * TILE_SIZE)
            sy = oy + int((ft.y - cam_y) * TILE_SIZE)
            if ox <= sx < ox + VIEW_TILES_W * TILE_SIZE:
                d.text((sx, sy), ft.text, font=font_xs, fill=ft.color)

        d.rectangle((0, 0, 127, 11), fill=C_HEADER)
        sel_type = BOT_TYPES[self.bot_type_idx]
        sel_col = BOT_COLORS[sel_type]
        d.text((2, 1), f"L{self.level}", font=font_xs, fill=C_CYAN)
        d.text((18, 1), f"x{len(self.bots)}", font=font_xs, fill=sel_col)
        d.text((35, 1), BOT_NAMES[sel_type], font=font_xs, fill=sel_col)
        d.text((58, 1), f"D:{self.data_collected}/{self.data_total}", font=font_xs, fill=C_DATA)
        d.text((100, 1), f"{self.score}", font=font_xs, fill=C_YELLOW)

        d.rectangle((0, 115, 127, 127), fill=C_HEADER)
        n_e = sum(1 for b in self.bots if b.btype == "exploit")
        n_w = sum(1 for b in self.bots if b.btype == "worm")
        n_m = sum(1 for b in self.bots if b.btype == "miner")
        d.text((2, 116), f"E{n_e}", font=font_xs, fill=C_RED)
        d.text((18, 116), f"W{n_w}", font=font_xs, fill=C_BLUE)
        d.text((34, 116), f"M{n_m}", font=font_xs, fill=C_YELLOW)
        alive_e = sum(1 for e in self.enemies if not e.dead)
        d.text((55, 116), f"Foe:{alive_e}", font=font_xs, fill=C_ENEMY)
        obj = "Kill all" if self.level == 1 else "Kill BOSS + data"
        d.text((95, 116), obj[:8], font=font_xs, fill=C_DIM)

        if self.msg:
            d.rectangle((10, 104, 118, 114), fill="#0A0F2A", outline=C_CYAN)
            d.text((64, 105), self.msg[:22], font=font_xs, fill=C_WHITE, anchor="mt")

        if self.flash_screen > 0:
            d.rectangle((0, 0, 127, 127), outline=C_WHITE)

    def draw_native(self, d):
        """Draw at native screen resolution with sub-pixel smooth scrolling."""
        sf_x = self._sx_f
        sf_y = self._sy_f
        tx = self._ts_x
        ty = self._ts_y

        cam_fx = self.px - VIEW_TILES_W / 2.0
        cam_fy = self.py - VIEW_TILES_H / 2.0
        cam_fx = max(0.0, min(MAP_W - VIEW_TILES_W, cam_fx))
        cam_fy = max(0.0, min(MAP_H - VIEW_TILES_H, cam_fy))
        cam_x = int(cam_fx)
        cam_y = int(cam_fy)
        sub_x = int((cam_fx - cam_x) * tx)
        sub_y = int((cam_fy - cam_y) * ty)
        n_ox = 0
        n_oy = int(13 * sf_y)

        wall_c1 = (26, 26, 58)
        wall_c2 = (34, 34, 68)
        water_c1 = (0, 44, 100)
        water_c2 = (0, 55, 110)
        water_pick = water_c1 if self.frame % 16 < 8 else water_c2
        spawn_on = self.frame % 12 < 7
        for tty in range(-1, VIEW_TILES_H + 1):
            my = cam_y + tty
            if my < 0 or my >= MAP_H:
                continue
            row = self.tilemap[my]
            sy = n_oy + tty * ty - sub_y
            for ttx in range(-1, VIEW_TILES_W + 1):
                mx = cam_x + ttx
                if mx < 0 or mx >= MAP_W:
                    continue
                tile = row[mx]
                if tile == TILE_EMPTY:
                    continue
                sx = n_ox + ttx * tx - sub_x
                if tile == TILE_WALL:
                    d.rectangle((sx, sy, sx + tx - 1, sy + ty - 1), fill=wall_c1)
                    # Brick pattern
                    if (mx + my) % 2 == 0:
                        d.rectangle((sx + 1, sy + 1, sx + tx - 2, sy + ty // 2), fill=wall_c2)
                    else:
                        d.rectangle((sx + 1, sy + ty // 2, sx + tx - 2, sy + ty - 2), fill=wall_c2)
                elif tile == TILE_WATER:
                    d.rectangle((sx, sy, sx + tx - 1, sy + ty - 1), fill=water_pick)
                    # Wave line
                    wy = sy + ty // 2
                    d.line((sx, wy, sx + tx - 1, wy), fill=(0, 80, 140))
                elif tile == TILE_BOT_SPAWN:
                    if spawn_on:
                        d.rectangle((sx, sy, sx + tx - 1, sy + ty - 1), fill=(0, 180, 80), outline=(0, 100, 50))
                    else:
                        d.rectangle((sx + 2, sy + 1, sx + tx - 3, sy + ty - 2), fill=(0, 60, 30))

        vw = VIEW_TILES_W * tx
        vh = VIEW_TILES_H * ty

        p = int(sf_x)  # pixel unit

        # -- Data items --
        for item in self.data_items:
            if item.collected:
                continue
            sx = n_ox + int((item.x - cam_fx) * tx)
            sy = n_oy + int((item.y - cam_fy) * ty)
            if not (n_ox - tx <= sx < n_ox + vw + tx and n_oy - ty <= sy < n_oy + vh + ty):
                continue
            if item.weight <= 1:
                # Small data packet — diamond shape
                cx, cy = sx + 2*p, sy + 2*p
                d.polygon([(cx, cy - 2*p), (cx + 2*p, cy), (cx, cy + 2*p), (cx - 2*p, cy)], fill=(0, 255, 136))
                d.point((cx, cy), fill=C_WHITE)
            else:
                # Heavy data — box with stripes
                d.rectangle((sx, sy, sx + 5*p, sy + 4*p), fill=(255, 215, 64), outline=(170, 136, 0))
                d.line((sx + p, sy + p, sx + 4*p, sy + p), fill=(200, 170, 0))
                d.line((sx + p, sy + 3*p, sx + 4*p, sy + 3*p), fill=(200, 170, 0))

        anim = self.frame % 8 < 4  # walk cycle toggle

        # -- Enemies --
        for enemy in self.enemies:
            if enemy.dead:
                continue
            sx = n_ox + int((enemy.x - cam_fx) * tx)
            sy = n_oy + int((enemy.y - cam_fy) * ty)
            if not (n_ox - tx <= sx < n_ox + vw + tx):
                continue

            if enemy.flash > 0:
                body_c = (255, 255, 255)
            elif enemy.is_boss:
                body_c = (255, 0, 255)
            else:
                body_c = (255, 0, 102)

            # Idle bob animation
            bob = p if (self.frame + id(enemy)) % 12 < 6 else 0

            if enemy.is_boss:
                sz = 5 * p
                d.rectangle((sx - sz, sy - sz - bob, sx + sz, sy + sz - bob), fill=body_c)
                d.rectangle((sx - sz + p, sy - sz + p - bob, sx + sz - p, sy + sz - p - bob), fill=(100, 0, 50))
                # Animated eyes (blink)
                if self.frame % 40 < 35:
                    d.rectangle((sx - 2*p, sy - 2*p - bob, sx - p, sy - p - bob), fill=C_WHITE)
                    d.rectangle((sx + p, sy - 2*p - bob, sx + 2*p, sy - p - bob), fill=C_WHITE)
                d.line((sx - 2*p, sy + p - bob, sx + 2*p, sy + p - bob), fill=C_WHITE)
                d.rectangle((sx - sz, sy - sz - p - bob, sx + sz, sy - sz - bob), fill=C_YELLOW)
                # Animated legs
                if anim:
                    d.rectangle((sx - 3*p, sy + sz - bob, sx - p, sy + sz + 2*p - bob), fill=body_c)
                    d.rectangle((sx + p, sy + sz - bob, sx + 3*p, sy + sz + 2*p - bob), fill=body_c)
                else:
                    d.rectangle((sx - 2*p, sy + sz - bob, sx, sy + sz + 2*p - bob), fill=body_c)
                    d.rectangle((sx + 2*p, sy + sz - bob, sx + 4*p, sy + sz + 2*p - bob), fill=body_c)
            else:
                sz = 3 * p
                d.rectangle((sx - sz, sy - sz - bob, sx + sz, sy + sz - bob), fill=body_c)
                # Animated eyes (look direction)
                eye_off = p if self.px > enemy.x else -p
                d.rectangle((sx - p + eye_off, sy - p - bob, sx + eye_off, sy - bob), fill=C_WHITE)
                d.rectangle((sx + p + eye_off, sy - p - bob, sx + 2*p + eye_off, sy - bob), fill=C_WHITE)
                # Antenna with sway
                ant_x = sx + (p if anim else -p)
                d.line((ant_x, sy - sz - bob, ant_x, sy - sz - 2*p - bob), fill=body_c)
                d.point((ant_x, sy - sz - 2*p - bob), fill=C_YELLOW)
                # Legs walk animation
                if anim:
                    d.rectangle((sx - 2*p, sy + sz - bob, sx - p, sy + sz + p - bob), fill=body_c)
                    d.rectangle((sx + p, sy + sz - bob, sx + 2*p, sy + sz + p - bob), fill=body_c)
                else:
                    d.rectangle((sx - p, sy + sz - bob, sx, sy + sz + p - bob), fill=body_c)
                    d.rectangle((sx + 2*p, sy + sz - bob, sx + 3*p, sy + sz + p - bob), fill=body_c)

            bar_w = (5 if enemy.is_boss else 3) * 2 * p + 2
            bar_x = sx - bar_w // 2
            bar_top = sy - (5 if enemy.is_boss else 3) * p - 4*p - bob
            d.rectangle((bar_x, bar_top, bar_x + bar_w, bar_top + 2*p), fill=(26, 26, 46))
            fw = int(bar_w * max(0, enemy.hp / enemy.max_hp))
            if fw > 0:
                d.rectangle((bar_x, bar_top, bar_x + fw, bar_top + 2*p), fill=C_RED)

        # -- Bots --
        for bot in self.bots:
            sx = n_ox + int((bot.x - cam_fx) * tx)
            sy = n_oy + int((bot.y - cam_fy) * ty)
            if not (n_ox - tx <= sx < n_ox + vw + tx):
                continue
            col = BOT_COLORS.get(bot.btype, C_WHITE)
            hurt = bot.hp < bot.max_hp
            head_c = (80, 80, 80) if hurt else col
            ba = bot.moving and (self.frame + id(bot) % 7) % 6 < 3
            f = bot.facing

            # Body (center)
            d.rectangle((sx, sy, sx + 3*p, sy + 3*p), fill=head_c)
            # Direction-specific details
            if f == "down":
                d.rectangle((sx + p, sy + p, sx + 2*p, sy + 2*p), fill=C_WHITE)  # eye
                if ba:
                    d.rectangle((sx, sy + 3*p, sx + p, sy + 4*p), fill=head_c)
                    d.rectangle((sx + 2*p, sy + 3*p, sx + 3*p, sy + 4*p), fill=head_c)
            elif f == "up":
                d.rectangle((sx + p, sy, sx + 2*p, sy + p), fill=(40, 40, 40))  # back
                if ba:
                    d.rectangle((sx, sy + 3*p, sx + p, sy + 4*p), fill=head_c)
                    d.rectangle((sx + 2*p, sy + 3*p, sx + 3*p, sy + 4*p), fill=head_c)
            elif f == "right":
                d.rectangle((sx + 2*p, sy + p, sx + 3*p, sy + 2*p), fill=C_WHITE)
                if ba:
                    d.rectangle((sx + p, sy + 3*p, sx + 2*p, sy + 4*p), fill=head_c)
            elif f == "left":
                d.rectangle((sx, sy + p, sx + p, sy + 2*p), fill=C_WHITE)
                if ba:
                    d.rectangle((sx + p, sy + 3*p, sx + 2*p, sy + 4*p), fill=head_c)
            # Attack animation
            if bot.state == "attacking" and self.frame % 4 < 2:
                d.line((sx + 3*p, sy + p, sx + 5*p, sy), fill=C_YELLOW)

        # -- Leader --
        lx = n_ox + int((self.px - cam_fx) * tx)
        ly = n_oy + int((self.py - cam_fy) * ty)
        ldx, ldy = self.face_dx, self.face_dy
        walk = anim and self.is_moving
        body_c = (0, 180, 200)
        head_c = (0, 229, 255)
        limb_c = (0, 150, 170)

        hurt_flash = self.leader_hurt_timer > 0 and self.frame % 4 < 2
        if hurt_flash:
            body_c = (255, 100, 100)
            head_c = (255, 150, 150)

        # Leg animation: alternate which leg extends
        leg_a = anim  # True = left forward, False = right forward

        if abs(ldy) >= abs(ldx) and ldy < 0:
            d.rectangle((lx - 3*p, ly - 2*p, lx + 3*p, ly + 4*p), fill=body_c)
            d.rectangle((lx - 2*p, ly - 5*p, lx + 2*p, ly - 2*p), fill=head_c)
            d.rectangle((lx - p, ly - 4*p, lx + p, ly - 3*p), fill=(0, 100, 120))
            if walk:
                la = ly + 6*p if leg_a else ly + 5*p
                ra = ly + 5*p if leg_a else ly + 6*p
                d.rectangle((lx - 2*p, ly + 4*p, lx - p, la), fill=limb_c)
                d.rectangle((lx + p, ly + 4*p, lx + 2*p, ra), fill=limb_c)
            else:
                d.rectangle((lx - 2*p, ly + 4*p, lx - p, ly + 5*p), fill=limb_c)
                d.rectangle((lx + p, ly + 4*p, lx + 2*p, ly + 5*p), fill=limb_c)
        elif abs(ldx) > abs(ldy) and ldx < 0:
            d.rectangle((lx - 2*p, ly - 2*p, lx + 2*p, ly + 4*p), fill=body_c)
            d.rectangle((lx - 2*p, ly - 5*p, lx + p, ly - 2*p), fill=head_c)
            d.rectangle((lx - 2*p, ly - 4*p, lx - p, ly - 3*p), fill=C_WHITE)
            d.rectangle((lx - 3*p, ly, lx - 2*p, ly + 2*p), fill=limb_c)
            if walk:
                la = ly + 6*p if leg_a else ly + 5*p
                ra = ly + 5*p if leg_a else ly + 6*p
                d.rectangle((lx - p, ly + 4*p, lx, la), fill=limb_c)
                d.rectangle((lx + p, ly + 4*p, lx + 2*p, ra), fill=limb_c)
            else:
                d.rectangle((lx - p, ly + 4*p, lx, ly + 5*p), fill=limb_c)
                d.rectangle((lx + p, ly + 4*p, lx + 2*p, ly + 5*p), fill=limb_c)
        elif abs(ldx) > abs(ldy) and ldx > 0:
            d.rectangle((lx - 2*p, ly - 2*p, lx + 2*p, ly + 4*p), fill=body_c)
            d.rectangle((lx - p, ly - 5*p, lx + 2*p, ly - 2*p), fill=head_c)
            d.rectangle((lx + p, ly - 4*p, lx + 2*p, ly - 3*p), fill=C_WHITE)
            d.rectangle((lx + 2*p, ly, lx + 3*p, ly + 2*p), fill=limb_c)
            if walk:
                la = ly + 5*p if leg_a else ly + 6*p
                ra = ly + 6*p if leg_a else ly + 5*p
                d.rectangle((lx - p, ly + 4*p, lx, la), fill=limb_c)
                d.rectangle((lx + p, ly + 4*p, lx + 2*p, ra), fill=limb_c)
            else:
                d.rectangle((lx - p, ly + 4*p, lx, ly + 5*p), fill=limb_c)
                d.rectangle((lx + p, ly + 4*p, lx + 2*p, ly + 5*p), fill=limb_c)
        else:
            d.rectangle((lx - 3*p, ly - 2*p, lx + 3*p, ly + 4*p), fill=body_c)
            d.rectangle((lx - 2*p, ly - 5*p, lx + 2*p, ly - 2*p), fill=head_c)
            d.rectangle((lx - p, ly - 4*p, lx + 2*p, ly - 3*p), fill=C_WHITE)
            d.rectangle((lx - 4*p, ly, lx - 3*p, ly + 2*p), fill=limb_c)
            d.rectangle((lx + 3*p, ly, lx + 4*p, ly + 2*p), fill=limb_c)
            if walk:
                la = ly + 6*p if leg_a else ly + 5*p
                ra = ly + 5*p if leg_a else ly + 6*p
                d.rectangle((lx - 2*p, ly + 4*p, lx - p, la), fill=limb_c)
                d.rectangle((lx + p, ly + 4*p, lx + 2*p, ra), fill=limb_c)
            else:
                d.rectangle((lx - 2*p, ly + 4*p, lx - p, ly + 5*p), fill=limb_c)
                d.rectangle((lx + p, ly + 4*p, lx + 2*p, ly + 5*p), fill=limb_c)

        # Whistle effect
        if self.whistle_timer > 0:
            self.whistle_timer -= 1
            r = int((10 - self.whistle_timer) * 3 * p)
            d.ellipse((lx - r, ly - r, lx + r, ly + r), outline=(136, 255, 255))

        # -- Float texts --
        for ft in self.floats:
            sx = n_ox + int((ft.x - cam_fx) * tx)
            sy = n_oy + int((ft.y - cam_fy) * ty)
            if n_ox <= sx < n_ox + vw:
                d.text((sx, sy), ft.text, font=_native_font_xs, fill=ft.color)

        hh = int(13 * sf_y)
        d.rectangle((0, 0, WIDTH - 1, hh - 1), fill=C_HEADER)
        sel_type = BOT_TYPES[self.bot_type_idx]
        sel_col = BOT_COLORS[sel_type]
        d.text((2, 1), f"L{self.level}", font=_native_font_xs, fill=C_CYAN)
        lives_x = int(15 * sf_x)
        for lv in range(self.lives):
            d.rectangle((lives_x + lv * int(4 * sf_x), 3, lives_x + lv * int(4 * sf_x) + int(3 * sf_x), int(hh * 0.6)), fill=C_CYAN)
        d.text((int(30 * sf_x), 1), f"x{len(self.bots)}", font=_native_font_xs, fill=sel_col)
        d.text((int(35 * sf_x), 1), BOT_NAMES[sel_type], font=_native_font_xs, fill=sel_col)
        d.text((int(58 * sf_x), 1), f"D:{self.data_collected}/{self.data_total}", font=_native_font_xs, fill=C_DATA)
        d.text((int(100 * sf_x), 1), f"{self.score}", font=_native_font_xs, fill=C_YELLOW)

        fy = int(115 * sf_y)
        d.rectangle((0, fy, WIDTH - 1, HEIGHT - 1), fill=C_HEADER)
        # Leader HP bar
        hp_w = int(25 * sf_x)
        hp_pct = max(0, self.leader_hp / self.leader_max_hp)
        hp_col = (0, 229, 255) if hp_pct > 0.5 else (255, 215, 64) if hp_pct > 0.25 else (255, 82, 82)
        d.rectangle((2, fy + 2, 2 + hp_w, fy + int(4 * sf_y)), fill=(26, 26, 46))
        if int(hp_w * hp_pct) > 0:
            d.rectangle((2, fy + 2, 2 + int(hp_w * hp_pct), fy + int(4 * sf_y)), fill=hp_col)
        bx = int(28 * sf_x)
        d.text((bx, fy + 1), f"E{sum(1 for b in self.bots if b.btype == 'exploit')}", font=_native_font_xs, fill=C_RED)
        d.text((int(42 * sf_x), fy + 1), f"W{sum(1 for b in self.bots if b.btype == 'worm')}", font=_native_font_xs, fill=C_BLUE)
        d.text((int(34 * sf_x), fy + 1), f"M{sum(1 for b in self.bots if b.btype == 'miner')}", font=_native_font_xs, fill=C_YELLOW)
        d.text((int(55 * sf_x), fy + 1), f"Foe:{sum(1 for e in self.enemies if not e.dead)}", font=_native_font_xs, fill=C_ENEMY)

        if self.msg:
            mx1 = int(10 * sf_x)
            mx2 = int(118 * sf_x)
            my1 = int(104 * sf_y)
            my2 = int(114 * sf_y)
            d.rectangle((mx1, my1, mx2, my2), fill="#0A0F2A", outline=C_CYAN)
            d.text((WIDTH // 2, my1 + 1), self.msg[:22], font=_native_font_xs, fill=C_WHITE, anchor="mt")

        if self._popup:
            title, desc, color = self._popup
            bx1 = int(10 * sf_x)
            bx2 = int(118 * sf_x)
            by1 = int(25 * sf_y)
            by2 = int(95 * sf_y)
            d.rectangle((bx1, by1, bx2, by2), fill=(6, 6, 18), outline=color)
            d.rectangle((bx1 + 2, by1 + 2, bx2 - 2, by1 + int(14 * sf_y)), fill=color)
            d.text((WIDTH // 2, by1 + 3), title, font=_native_font_sm, fill=C_WHITE, anchor="mt")
            for i, line in enumerate(desc.split("\n")):
                d.text((WIDTH // 2, by1 + int((18 + i * 12) * sf_y)), line, font=_native_font_xs, fill=C_WHITE, anchor="mt")
            d.text((WIDTH // 2, by2 - int(3 * sf_y)), "OK to continue", font=_native_font_xs, fill=C_DIM, anchor="mb")


def _show_tutorial(lcd):
    pages = [
        ("CYBER SWARM", [
            "You are a hacker",
            "Build a bot army",
            "Hack the network!",
        ], C_CYAN),
        ("CONTROLS", [
            "D-pad: Move",
            "OK: Throw bot",
            "K1: Recall bots",
            "K2: Change bot type",
        ], C_GREEN),
        ("BOT TYPES", [
            "RED Exploit: 2x dmg",
            "BLUE Worm: cross water",
            "YLW Miner: heavy data",
        ], C_YELLOW),
        ("OBJECTIVE", [
            "Collect green spawns",
            "Throw bots at enemies",
            "Collect data packets",
            "Kill boss to advance",
        ], C_RED),
    ]
    for title, lines, color in pages:
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((64, 18), title, font=font, fill=color, anchor="mm")
        for i, line in enumerate(lines):
            d.text((64, 38 + i * 16), line, font=font_sm, fill=C_WHITE, anchor="mm")
        d.text((64, 112), "OK: next  K3: skip", font=font_xs, fill=C_DIM, anchor="mm")
        lcd.LCD_ShowImage(img, 0, 0)
        while _running:
            b = get_button(PINS, GPIO)
            if b == "KEY3":
                return False
            if b in ("OK", "KEY1", "RIGHT"):
                break
            time.sleep(0.05)
    return True


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    if not _show_tutorial(lcd):
        lcd.LCD_Clear()
        GPIO.cleanup()
        return 0

    game = Game()
    target_dt = 1.0 / 18

    fb_size = WIDTH * HEIGHT * 2
    fb_fd = None
    fb_map = None
    use_fb = os.path.exists(FB_DEVICE)
    if use_fb:
        try:
            fb_fd = os.open(FB_DEVICE, os.O_RDWR)
            fb_map = mmap.mmap(fb_fd, fb_size, mmap.MAP_SHARED,
                               mmap.PROT_WRITE | mmap.PROT_READ)
        except Exception:
            use_fb = False

    from PIL import ImageDraw as _ID

    try:
        while _running:
            t0 = time.monotonic()

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break

            dx, dy = 0, 0
            if GPIO.input(PINS["UP"]) == 0:
                dy = -1
            if GPIO.input(PINS["DOWN"]) == 0:
                dy = 1
            if GPIO.input(PINS["LEFT"]) == 0:
                dx = -1
            if GPIO.input(PINS["RIGHT"]) == 0:
                dx = 1

            if game._popup:
                game._popup_timer += 1
                if btn == "OK" and game._popup_timer > 10:
                    if game.dead:
                        game = Game()
                    else:
                        game._popup = None
                    game._popup_timer = 0
            else:
                throw = btn == "OK"
                whistle = btn == "KEY1"
                cycle = btn == "KEY2"
                game.update(dx, dy, throw, whistle, cycle)

            img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            d_raw = _ID.Draw(img)
            game.draw_native(d_raw)

            if use_fb and fb_map:
                arr = np.array(img, dtype=np.uint16)
                r = (arr[:, :, 0] >> 3).astype(np.uint16)
                g = (arr[:, :, 1] >> 2).astype(np.uint16)
                b = (arr[:, :, 2] >> 3).astype(np.uint16)
                rgb565 = (r << 11) | (g << 5) | b
                fb_map.seek(0)
                fb_map.write(rgb565.astype('<u2').tobytes())
            else:
                lcd.LCD_ShowImage(img, 0, 0)

            elapsed = time.monotonic() - t0
            if elapsed < target_dt:
                time.sleep(target_dt - elapsed)

    finally:
        if fb_map:
            try:
                fb_map.close()
            except Exception:
                pass
        if fb_fd is not None:
            try:
                os.close(fb_fd)
            except Exception:
                pass
        lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        lcd.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
