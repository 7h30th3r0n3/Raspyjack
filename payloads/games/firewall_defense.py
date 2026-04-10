#!/usr/bin/env python3
"""
RaspyJack Payload -- Firewall Defense
--------------------------------------
A polished tower defense game with network security theming,
pixel-art sprites, path-based enemy movement, laser effects,
explosions and a detailed UI.

Controls:
  Joystick   : Move cursor
  OK         : Place tower / Start wave / Restart
  KEY1       : Cycle tower type
  KEY2       : Sell tower (50% refund) / Toggle range preview
  KEY3       : Exit

Author: 7h30th3r0n3
"""

import os, sys, time, random, math
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
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
WIDTH, HEIGHT = LCD.width, LCD.height
_GW, _GH = 128, 128
font = ImageFont.load_default()

# ═══════════════════════════════════════════════════════════════
# GRID & LAYOUT
# ═══════════════════════════════════════════════════════════════
CELL = 10
COLS = 12
ROWS = 10
GX0 = 2
GY0 = 14
HUD_H = 13
BAR_H = 11
FPS = 14
FRAME_DT = 1.0 / FPS

# ═══════════════════════════════════════════════════════════════
# PATH: snake-like route enemies follow (grid coords)
# ═══════════════════════════════════════════════════════════════
PATH = []
def _build_path():
    """Build a snake path from right to left across the grid."""
    global PATH
    PATH = []
    # Enter from right, row 1
    r = 1
    # Right to left
    for c in range(COLS - 1, 1, -1):
        PATH.append((c, r))
    # Down
    for rr in range(r, r + 3):
        PATH.append((2, rr))
    r += 2
    # Left to right
    for c in range(2, COLS - 2):
        PATH.append((c, r))
    # Down
    for rr in range(r, r + 3):
        PATH.append((COLS - 3, rr))
    r += 2
    # Right to left
    for c in range(COLS - 3, 1, -1):
        PATH.append((c, r))
    # Down
    for rr in range(r, r + 3):
        PATH.append((2, rr))
    r += 2
    # Left to right toward exit
    for c in range(2, COLS):
        PATH.append((c, r))

_build_path()

# Set of path cells for quick lookup
PATH_SET = set(PATH)

# ═══════════════════════════════════════════════════════════════
# PIXEL ART SPRITE DRAWING
# ═══════════════════════════════════════════════════════════════
def _draw_sprite_firewall(d, x, y):
    """Firewall tower: brick wall pattern."""
    d.rectangle((x+1, y+1, x+8, y+8), fill=(30, 60, 120))
    # Bricks
    for row_off in (2, 5):
        d.line((x+1, y+row_off, x+8, y+row_off), fill=(20, 40, 90))
    for col_off in (3, 6):
        d.line((x+col_off, y+1, x+col_off, y+4), fill=(20, 40, 90))
    for col_off in (4, 7):
        d.line((x+col_off, y+5, x+col_off, y+8), fill=(20, 40, 90))
    # Glow outline
    d.rectangle((x+1, y+1, x+8, y+8), outline=(0, 150, 255))

def _draw_sprite_ids(d, x, y):
    """IDS tower: radar/eye icon."""
    d.rectangle((x+1, y+1, x+8, y+8), fill=(40, 40, 10))
    # Eye shape
    d.arc((x+1, y+2, x+8, y+7), 0, 360, fill=(255, 255, 0))
    # Pupil
    d.rectangle((x+4, y+4, x+5, y+5), fill=(255, 200, 0))
    d.point((x+4, y+4), fill=(0, 0, 0))
    d.rectangle((x+1, y+1, x+8, y+8), outline=(200, 200, 0))

def _draw_sprite_honeypot(d, x, y):
    """Honeypot: jar with honey glow."""
    # Jar
    d.rectangle((x+2, y+3, x+7, y+8), fill=(180, 80, 0))
    d.rectangle((x+3, y+4, x+6, y+7), fill=(255, 160, 0))
    # Lid
    d.rectangle((x+1, y+2, x+8, y+3), fill=(140, 60, 0))
    # Glow dots
    d.point((x+4, y+5), fill=(255, 255, 100))
    d.point((x+5, y+6), fill=(255, 255, 100))
    d.rectangle((x+1, y+1, x+8, y+8), outline=(255, 120, 0))

def _draw_sprite_waf(d, x, y):
    """WAF tower: shield icon."""
    d.rectangle((x+1, y+1, x+8, y+8), fill=(50, 0, 60))
    # Shield shape
    pts = [(x+4, y+2), (x+7, y+3), (x+7, y+5), (x+4, y+8), (x+2, y+5), (x+2, y+3)]
    d.polygon(pts, fill=(160, 0, 220), outline=(220, 100, 255))
    # Inner mark
    d.line((x+4, y+3, x+4, y+6), fill=(255, 200, 255))
    d.line((x+3, y+5, x+5, y+5), fill=(255, 200, 255))

TOWER_DRAWERS = [_draw_sprite_firewall, _draw_sprite_ids, _draw_sprite_honeypot, _draw_sprite_waf]

def _draw_sprite_enemy(d, x, y, etype, frame, slowed):
    """Draw enemy sprite with simple animation."""
    colors = [
        (255, 30, 30),    # VIR - red
        (255, 100, 0),    # WRM - orange
        (180, 0, 80),     # TRJ - magenta
        (200, 0, 200),    # DDS - purple
        (255, 220, 0),    # RAT - yellow
        (255, 255, 255),  # R00T - white
    ]
    col = colors[min(etype, len(colors) - 1)]
    if slowed > 0:
        col = (col[0] // 2, col[1] // 2, max(col[2], 150))  # blueish tint

    # Body
    d.rectangle((x+2, y+2, x+7, y+7), fill=col)

    # Animated "legs" / glitch effect
    anim = frame % 4
    if etype == 0:  # Virus: pulsing
        if anim < 2:
            d.point((x+1, y+3), fill=col)
            d.point((x+8, y+6), fill=col)
        else:
            d.point((x+1, y+6), fill=col)
            d.point((x+8, y+3), fill=col)
    elif etype == 1:  # Worm: wiggle
        off = 1 if anim < 2 else -1
        d.point((x+1, y+4+off), fill=col)
        d.point((x+8, y+4-off), fill=col)
    elif etype == 2:  # Trojan: horse shape
        d.line((x+3, y+1, x+6, y+1), fill=col)
        d.point((x+4, y+8), fill=col)
        d.point((x+5, y+8), fill=col)
    elif etype == 3:  # DDoS: multiple dots
        for dx, dy in [(1,2),(8,2),(1,7),(8,7)]:
            d.point((x+dx, y+dy), fill=col)
    elif etype == 4:  # RAT: antenna
        d.line((x+4, y+1, x+4, y+2), fill=col)
        d.point((x+3, y+1), fill=col)
        d.point((x+5, y+1), fill=col)
    else:  # R00T: crown
        for dx in (2, 4, 6):
            d.point((x+dx, y+1), fill=(255, 215, 0))
        d.line((x+2, y+2, x+6, y+2), fill=(255, 215, 0))

    # Eyes (2 pixels)
    d.point((x+3, y+4), fill=(0, 0, 0))
    d.point((x+6, y+4), fill=(0, 0, 0))

def _draw_server(d, x0, y0):
    """Draw server rack on left edge."""
    for r in range(ROWS):
        y = y0 + r * CELL
        # Server unit
        d.rectangle((0, y+1, x0, y+CELL-1), fill=(0, 50, 0))
        d.rectangle((0, y+2, x0-1, y+CELL-2), fill=(0, 80, 0))
        # LED
        d.point((1, y + CELL//2), fill=(0, 255, 0))

def _draw_circuit_bg(d, gx0, gy0):
    """Draw faint circuit board pattern on non-path cells."""
    for r in range(ROWS):
        for c in range(COLS):
            if (c, r) in PATH_SET:
                continue
            x = gx0 + c * CELL
            y = gy0 + r * CELL
            # Subtle circuit traces
            if (c + r) % 3 == 0:
                d.point((x+5, y+5), fill=(0, 15, 0))
                d.line((x+5, y+3, x+5, y+7), fill=(0, 12, 0))
            if (c * 7 + r * 3) % 5 == 0:
                d.line((x+2, y+5, x+8, y+5), fill=(0, 12, 0))

# ═══════════════════════════════════════════════════════════════
# EFFECTS
# ═══════════════════════════════════════════════════════════════
def _draw_laser(d, x1, y1, x2, y2, color, glow=True):
    """Draw a laser beam with optional glow."""
    if glow:
        gc = (color[0]//3, color[1]//3, color[2]//3)
        d.line((x1-1, y1, x2-1, y2), fill=gc)
        d.line((x1+1, y1, x2+1, y2), fill=gc)
    d.line((x1, y1, x2, y2), fill=color, width=1)

def _draw_explosion(d, x, y, frame, size=6):
    """Draw expanding explosion ring."""
    t = frame % 8
    if t > 5:
        return
    r = t * 2 + 2
    colors = [(255,255,100), (255,200,0), (255,100,0), (255,50,0), (100,0,0)]
    col = colors[min(t, len(colors)-1)]
    d.ellipse((x-r, y-r, x+r, y+r), outline=col)
    if t < 3:
        d.ellipse((x-r+1, y-r+1, x+r-1, y+r-1), outline=(255,255,200))

def _draw_range_circle(d, cx, cy, radius):
    """Draw tower range indicator."""
    px = GX0 + cx * CELL + CELL // 2
    py = GY0 + cy * CELL + CELL // 2
    r = int(radius * CELL)
    d.ellipse((px-r, py-r, px+r, py+r), outline=(0, 80, 80))

# ═══════════════════════════════════════════════════════════════
# TOWER / ENEMY DEFS
# ═══════════════════════════════════════════════════════════════
TOWERS = [
    {"name": "FW",  "full": "Firewall", "cost": 10, "dmg": 3,  "rng": 2.2, "rate": 8,  "col": (0,150,255)},
    {"name": "IDS", "full": "IDS",      "cost": 15, "dmg": 1,  "rng": 3.5, "rate": 3,  "col": (255,255,0)},
    {"name": "HP",  "full": "Honeypot", "cost": 8,  "dmg": 0,  "rng": 2.5, "rate": 10, "col": (255,120,0)},
    {"name": "WAF", "full": "WAF",      "cost": 25, "dmg": 6,  "rng": 1.8, "rate": 14, "col": (200,0,255)},
]

ENEMIES = [
    {"name": "VIR",  "hp": 5,  "spd": 1.0, "rew": 5},
    {"name": "WRM",  "hp": 8,  "spd": 1.4, "rew": 8},
    {"name": "TRJ",  "hp": 14, "spd": 0.7, "rew": 12},
    {"name": "DDS",  "hp": 25, "spd": 0.5, "rew": 20},
    {"name": "RAT",  "hp": 10, "spd": 2.0, "rew": 15},
    {"name": "R00T", "hp": 40, "spd": 0.4, "rew": 35},
]

# ═══════════════════════════════════════════════════════════════
# GAME STATE
# ═══════════════════════════════════════════════════════════════
def _make_wave(wn):
    elist = []
    count = min(4 + wn * 2, 25)
    for i in range(count):
        mt = min(wn // 2, len(ENEMIES) - 1)
        et = random.randint(0, mt)
        tpl = ENEMIES[et]
        scale = 1.0 + (wn - 1) * 0.18
        elist.append({
            "t": et, "path_pos": -(i * 1.8 + 1.0),
            "hp": int(tpl["hp"] * scale), "mhp": int(tpl["hp"] * scale),
            "spd": tpl["spd"], "alive": True, "slowed": 0,
        })
    return elist

def _new_state():
    return {
        "grid": [[None]*COLS for _ in range(ROWS)],
        "cx": 5, "cy": 3, "tt": 0,
        "credits": 25, "hp": 20, "wave": 1,
        "enemies": [], "lasers": [], "explosions": [],
        "cds": {}, "wave_on": False, "wave_cd": 80,
        "over": False, "kills": 0, "f": 0, "show_range": False,
    }

def _cell_px(c, r):
    return GX0 + c * CELL + CELL // 2, GY0 + r * CELL + CELL // 2

def _path_xy(pos):
    """Interpolate position along path."""
    if pos < 0:
        # Before first waypoint
        fx, fy = PATH[0]
        return float(fx) + abs(pos), float(fy)
    idx = int(pos)
    frac = pos - idx
    if idx >= len(PATH) - 1:
        return float(PATH[-1][0]), float(PATH[-1][1])
    ax, ay = PATH[idx]
    bx, by = PATH[min(idx + 1, len(PATH) - 1)]
    return ax + (bx - ax) * frac, ay + (by - ay) * frac

def _dist(x1, y1, x2, y2):
    return math.sqrt((x1-x2)**2 + (y1-y2)**2)

# ═══════════════════════════════════════════════════════════════
# UPDATE
# ═══════════════════════════════════════════════════════════════
def _update(s):
    if s["over"]:
        return s

    f = s["f"] + 1
    enemies = s["enemies"]
    hp = s["hp"]
    kills = s["kills"]
    credits = s["credits"]
    lasers = []
    explosions = [e for e in s["explosions"] if e["ttl"] > 0]
    for ex in explosions:
        ex["ttl"] -= 1

    # Wave management
    wave_on = s["wave_on"]
    wave_cd = s["wave_cd"]
    if not wave_on:
        wave_cd -= 1
        if wave_cd <= 0:
            enemies = _make_wave(s["wave"])
            wave_on = True
    else:
        if enemies and all(not e["alive"] for e in enemies):
            bonus = 5 + s["wave"] * 3
            return {**s, "wave": s["wave"]+1, "wave_on": False, "wave_cd": 90,
                    "enemies": [], "credits": credits+bonus, "f": f,
                    "lasers": [], "explosions": explosions}

    # Move enemies along path
    for e in enemies:
        if not e["alive"]:
            continue
        spd = e["spd"]
        if e["slowed"] > 0:
            spd *= 0.35
            e["slowed"] -= 1
        e["path_pos"] += spd / FPS * 2.5
        if e["path_pos"] >= len(PATH) - 1:
            e["alive"] = False
            hp -= 1
            explosions.append({"x": GX0, "y": GY0 + ROWS*CELL//2, "ttl": 8})

    if hp <= 0:
        return {**s, "hp": 0, "over": True, "enemies": enemies, "f": f,
                "kills": kills, "lasers": [], "explosions": explosions}

    # Tower shooting
    grid = s["grid"]
    cds = dict(s["cds"])
    for r in range(ROWS):
        for c in range(COLS):
            tw = grid[r][c]
            if tw is None:
                continue
            td = TOWERS[tw]
            key = (c, r)
            cd = cds.get(key, 0)
            if cd > 0:
                cds[key] = cd - 1
                continue
            best = None
            best_d = td["rng"] + 1
            for e in enemies:
                if not e["alive"] or e["path_pos"] < 0:
                    continue
                ex, ey = _path_xy(e["path_pos"])
                dd = _dist(c, r, ex, ey)
                if dd <= td["rng"] and dd < best_d:
                    best = e
                    best_d = dd
            if best is None:
                continue
            ex, ey = _path_xy(best["path_pos"])
            if td["dmg"] > 0:
                best["hp"] -= td["dmg"]
                lasers.append({"x1": c, "y1": r, "x2": ex, "y2": ey,
                               "col": td["col"], "ttl": 3})
            if td["name"] == "HP" and best["alive"]:
                best["slowed"] = FPS * 2
            if best["hp"] <= 0 and best["alive"]:
                best["alive"] = False
                kills += 1
                credits += ENEMIES[best["t"]]["rew"]
                px = GX0 + int(ex * CELL) + CELL//2
                py = GY0 + int(ey * CELL) + CELL//2
                explosions.append({"x": px, "y": py, "ttl": 8})
            cds[key] = td["rate"]

    return {**s, "hp": hp, "enemies": enemies, "f": f, "wave_on": wave_on,
            "wave_cd": wave_cd, "cds": cds, "lasers": lasers, "kills": kills,
            "credits": credits, "grid": grid, "explosions": explosions}

# ═══════════════════════════════════════════════════════════════
# RENDER
# ═══════════════════════════════════════════════════════════════
def _draw(lcd, s):
    img = Image.new("RGB", (_GW, _GH), (0, 0, 0))
    d = ImageDraw.Draw(img)

    # ── HUD ──
    d.rectangle((0, 0, _GW, HUD_H - 1), fill=(0, 15, 0))
    d.line((0, HUD_H - 1, _GW, HUD_H - 1), fill=(0, 60, 0))
    # Health bar
    hp_pct = max(0, s["hp"]) / 20
    d.rectangle((1, 2, 30, 10), outline=(80, 0, 0))
    d.rectangle((2, 3, 2 + int(27 * hp_pct), 9), fill=(int(255*(1-hp_pct)), int(255*hp_pct), 0))
    d.text((33, 1), f"${s['credits']}", font=font, fill=(255, 220, 0))
    d.text((65, 1), f"W{s['wave']}", font=font, fill=(0, 200, 255))
    d.text((90, 1), f"{s['kills']}K", font=font, fill=(0, 200, 0))

    # ── Circuit background ──
    _draw_circuit_bg(d, GX0, GY0)

    # ── Path ──
    for i, (c, r) in enumerate(PATH):
        x = GX0 + c * CELL
        y = GY0 + r * CELL
        shade = 18 + (i % 2) * 5
        d.rectangle((x, y, x+CELL-1, y+CELL-1), fill=(shade, shade+5, shade))

    # ── Server ──
    _draw_server(d, GX0, GY0)

    # ── Towers ──
    for r in range(ROWS):
        for c in range(COLS):
            tw = s["grid"][r][c]
            if tw is not None:
                x = GX0 + c * CELL
                y = GY0 + r * CELL
                TOWER_DRAWERS[tw](d, x, y)

    # ── Range preview ──
    if s["show_range"]:
        tw = s["grid"][s["cy"]][s["cx"]]
        if tw is not None:
            _draw_range_circle(d, s["cx"], s["cy"], TOWERS[tw]["rng"])
        else:
            _draw_range_circle(d, s["cx"], s["cy"], TOWERS[s["tt"]]["rng"])

    # ── Enemies ──
    for e in s["enemies"]:
        if not e["alive"] or e["path_pos"] < -0.5:
            continue
        ex, ey = _path_xy(e["path_pos"])
        px = GX0 + int(ex * CELL)
        py = GY0 + int(ey * CELL)
        _draw_sprite_enemy(d, px, py, e["t"], s["f"], e["slowed"])
        # HP bar
        if e["hp"] < e["mhp"]:
            pct = e["hp"] / e["mhp"]
            bw = CELL - 2
            d.rectangle((px+1, py-1, px+1+bw, py), fill=(60, 0, 0))
            d.rectangle((px+1, py-1, px+1+int(bw*pct), py), fill=(0, 220, 0))

    # ── Lasers ──
    for las in s["lasers"]:
        if las["ttl"] <= 0:
            continue
        x1, y1 = _cell_px(las["x1"], las["y1"])
        x2 = GX0 + int(las["x2"] * CELL) + CELL//2
        y2 = GY0 + int(las["y2"] * CELL) + CELL//2
        _draw_laser(d, x1, y1, x2, y2, las["col"])

    # ── Explosions ──
    for ex in s["explosions"]:
        _draw_explosion(d, ex["x"], ex["y"], 8 - ex["ttl"])

    # ── Cursor ──
    cx = GX0 + s["cx"] * CELL
    cy = GY0 + s["cy"] * CELL
    # Animated cursor corners
    blink = (s["f"] // 4) % 2
    cc = (0, 255, 255) if blink else (0, 180, 180)
    # Top-left
    d.line((cx, cy, cx+3, cy), fill=cc)
    d.line((cx, cy, cx, cy+3), fill=cc)
    # Top-right
    d.line((cx+CELL, cy, cx+CELL-3, cy), fill=cc)
    d.line((cx+CELL, cy, cx+CELL, cy+3), fill=cc)
    # Bottom-left
    d.line((cx, cy+CELL, cx+3, cy+CELL), fill=cc)
    d.line((cx, cy+CELL, cx, cy+CELL-3), fill=cc)
    # Bottom-right
    d.line((cx+CELL, cy+CELL, cx+CELL-3, cy+CELL), fill=cc)
    d.line((cx+CELL, cy+CELL, cx+CELL, cy+CELL-3), fill=cc)

    # ── Bottom bar ──
    by0 = _GH - BAR_H
    d.rectangle((0, by0, _GW, _GH), fill=(0, 15, 0))
    d.line((0, by0, _GW, by0), fill=(0, 60, 0))
    td = TOWERS[s["tt"]]
    # Tower preview
    TOWER_DRAWERS[s["tt"]](d, 1, by0)
    d.text((12, by0 + 1), td["name"], font=font, fill=td["col"])
    d.text((32, by0 + 1), f"${td['cost']}", font=font, fill=(255, 220, 0))
    d.text((58, by0 + 1), f"D{td['dmg']}", font=font, fill=(255, 80, 80))
    d.text((80, by0 + 1), f"R{td['rng']:.0f}", font=font, fill=(80, 200, 255))
    # Affordable indicator
    if s["credits"] >= td["cost"]:
        d.rectangle((105, by0 + 2, 110, by0 + 8), fill=(0, 180, 0))
    else:
        d.rectangle((105, by0 + 2, 110, by0 + 8), fill=(180, 0, 0))

    # ── Wave incoming ──
    if not s["wave_on"] and not s["over"]:
        secs = max(0, s["wave_cd"] // FPS)
        # Semi-transparent banner
        d.rectangle((20, 48, 108, 72), fill=(0, 20, 30))
        d.rectangle((20, 48, 108, 49), fill=(0, 150, 255))
        d.rectangle((20, 71, 108, 72), fill=(0, 150, 255))
        d.text((28, 50), f"WAVE {s['wave']} in {secs}s", font=font, fill=(0, 220, 255))
        d.text((28, 61), "OK=Go  K1=Tower", font=font, fill=(0, 100, 100))

    # ── Game Over ──
    if s["over"]:
        d.rectangle((14, 35, 114, 92), fill=(30, 0, 0))
        d.rectangle((14, 35, 114, 37), fill=(255, 0, 0))
        d.rectangle((14, 90, 114, 92), fill=(255, 0, 0))
        # Skull-ish icon
        d.text((25, 38), "BREACH!", font=font, fill=(255, 0, 0))
        d.text((20, 50), "NETWORK OFFLINE", font=font, fill=(255, 50, 50))
        d.text((30, 63), f"Waves: {s['wave']-1}", font=font, fill=(0, 200, 255))
        d.text((30, 73), f"Kills: {s['kills']}", font=font, fill=(0, 255, 0))
        d.text((18, 82), "OK=retry  K3=quit", font=font, fill=(100, 100, 100))

    # Resize for LCD
    if _GW != WIDTH or _GH != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    lcd.LCD_ShowImage(img, 0, 0)


# ═══════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════
def main():
    state = _new_state()

    try:
        while True:
            t0 = time.time()
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if state["over"]:
                if btn == "OK":
                    state = _new_state()
                _draw(LCD, state)
                dt = FRAME_DT - (time.time() - t0)
                if dt > 0:
                    time.sleep(dt)
                continue

            if btn == "UP":
                state = {**state, "cy": max(0, state["cy"] - 1)}
            elif btn == "DOWN":
                state = {**state, "cy": min(ROWS - 1, state["cy"] + 1)}
            elif btn == "LEFT":
                state = {**state, "cx": max(0, state["cx"] - 1)}
            elif btn == "RIGHT":
                state = {**state, "cx": min(COLS - 1, state["cx"] + 1)}
            elif btn == "KEY1":
                state = {**state, "tt": (state["tt"] + 1) % len(TOWERS)}
            elif btn == "KEY2":
                tw = state["grid"][state["cy"]][state["cx"]]
                if tw is not None:
                    refund = TOWERS[tw]["cost"] // 2
                    ng = [row[:] for row in state["grid"]]
                    ng[state["cy"]][state["cx"]] = None
                    state = {**state, "grid": ng, "credits": state["credits"] + refund}
                else:
                    state = {**state, "show_range": not state["show_range"]}
            elif btn == "OK":
                cx, cy = state["cx"], state["cy"]
                td = TOWERS[state["tt"]]
                if (cx, cy) not in PATH_SET and state["grid"][cy][cx] is None \
                        and state["credits"] >= td["cost"]:
                    ng = [row[:] for row in state["grid"]]
                    ng[cy][cx] = state["tt"]
                    state = {**state, "grid": ng, "credits": state["credits"] - td["cost"]}
                if not state["wave_on"]:
                    enemies = _make_wave(state["wave"])
                    state = {**state, "wave_on": True, "enemies": enemies}

            state = _update(state)
            _draw(LCD, state)

            dt = FRAME_DT - (time.time() - t0)
            if dt > 0:
                time.sleep(dt)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
