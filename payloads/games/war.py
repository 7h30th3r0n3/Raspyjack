#!/usr/bin/env python3
"""
RaspyJack Payload -- Network War
----------------------------------
Author: 7h30th3r0n3

Cyber warfare strategy game. Hack enemy servers, defend your network.
Each side has 5 nodes. Destroy all enemy nodes to win.

Controls:
  UP/DOWN    -- Select node/target
  LEFT/RIGHT -- Cycle action
  OK         -- Confirm
  KEY1       -- Skip turn
  KEY3       -- Exit
"""
import os, sys, time, signal, random, math
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

font = scaled_font(10)
font_sm = scaled_font(8)
font_xs = scaled_font(7)

C_BG = "#060612"
C_HEADER = "#0d1117"
C_PLAYER = "#00E676"
C_PLAYER_DIM = "#004D25"
C_ENEMY = "#FF5252"
C_ENEMY_DIM = "#4D0000"
C_SELECT = "#FFD740"
C_HP_BG = "#1A1A2E"
C_HP_GREEN = "#00E676"
C_HP_RED = "#FF5252"
C_CYAN = "#00E5FF"
C_GOLD = "#FFD740"
C_PURPLE = "#7C4DFF"
C_WHITE = "#E0E0E0"
C_DIM = "#555555"
C_MSG_BG = "#0A0F2A"

ACTIONS = ["SCAN", "ATTACK", "DEFEND", "PATCH"]
ACTION_ICONS = ["?", "!", "+D", "+H"]
ACTION_COLORS = [C_CYAN, C_ENEMY, C_PURPLE, C_HP_GREEN]
NODE_NAMES = ["WEB", "DB", "DNS", "FW", "VPN"]

_running = True


def _sig(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


class Node:
    def __init__(self, name):
        self.name = name
        self.hp = 100
        self.defense = random.randint(5, 15)
        self.attack = random.randint(12, 22)
        self.scanned = False
        self.flash = 0
        self.flash_color = C_WHITE

    @property
    def alive(self):
        return self.hp > 0


def _draw_hp_bar(d, x, y, w, hp, is_player):
    d.rectangle((x, y, x + w, y + 3), fill=C_HP_BG)
    bar_w = int(w * max(0, min(100, hp)) / 100)
    if bar_w > 0:
        col = C_HP_GREEN if is_player else C_HP_RED
        if hp < 30:
            col = C_GOLD
        d.rectangle((x, y, x + bar_w, y + 3), fill=col)


def _draw_node(d, node, x, y, selected, is_player):
    if node.flash > 0:
        node.flash -= 1
        outline = node.flash_color
    elif selected:
        outline = C_SELECT
    elif is_player:
        outline = C_PLAYER if node.alive else C_PLAYER_DIM
    else:
        outline = C_ENEMY if node.alive else C_ENEMY_DIM

    fill = C_PLAYER_DIM if is_player else C_ENEMY_DIM
    if not node.alive:
        fill = "#111111"

    d.rectangle((x, y, x + 12, y + 12), fill=fill, outline=outline)

    if node.alive:
        inner_col = C_PLAYER if is_player else C_ENEMY
        d.rectangle((x + 3, y + 3, x + 9, y + 9), fill=inner_col)


def _draw_game(d, player, enemy, sel, sel_action, turn, msg, phase, frame):
    d.rectangle((0, 0, 127, 11), fill=C_HEADER)
    d.text((2, 1), f"T:{turn}", font=font_xs, fill=C_CYAN)
    p_alive = sum(1 for n in player if n.alive)
    e_alive = sum(1 for n in enemy if n.alive)
    d.text((30, 1), f"YOU:{p_alive}", font=font_xs, fill=C_PLAYER)
    d.text((75, 1), f"FOE:{e_alive}", font=font_xs, fill=C_ENEMY)

    for i, node in enumerate(player):
        ny = 15 + i * 20
        is_sel = phase == "select_node" and i == sel
        _draw_node(d, node, 2, ny, is_sel, True)
        label_col = C_WHITE if node.alive else C_DIM
        d.text((17, ny + 1), node.name, font=font_xs, fill=label_col)
        _draw_hp_bar(d, 17, ny + 10, 38, node.hp, True)

    cx = 63
    for i in range(4):
        ly = 20 + i * 22
        pulse = int(math.sin(frame * 0.15 + i) * 20 + 40)
        col = f"#{pulse:02X}{pulse:02X}{pulse+20:02X}"
        d.line((56, ly + 6, 70, ly + 6), fill=col)
    d.rectangle((59, 14, 67, 112), outline="#1A1A2E")

    for i, node in enumerate(enemy):
        ny = 15 + i * 20
        is_sel = phase == "select_target" and i == sel
        _draw_node(d, node, 113, ny, is_sel, False)
        if node.scanned or not node.alive:
            d.text((75, ny + 1), node.name, font=font_xs, fill=C_WHITE if node.alive else C_DIM)
            _draw_hp_bar(d, 75, ny + 10, 36, node.hp, False)
        else:
            d.text((80, ny + 1), "???", font=font_xs, fill=C_DIM)

    if phase == "select_action":
        d.rectangle((0, 112, 127, 127), fill="#141428")
        action_name = ACTIONS[sel_action]
        action_col = ACTION_COLORS[sel_action]
        d.text((4, 114), f"< {action_name} >", font=font_sm, fill=action_col)
        d.text((90, 114), "OK", font=font_xs, fill=C_DIM)
    elif phase == "select_target":
        d.rectangle((0, 112, 127, 127), fill="#281414")
        d.text((4, 114), "Select target", font=font_sm, fill=C_ENEMY)
        d.text((90, 114), "OK", font=font_xs, fill=C_DIM)
    elif phase == "select_node":
        d.rectangle((0, 112, 127, 127), fill="#142814")
        d.text((4, 114), "Select node", font=font_sm, fill=C_PLAYER)
        d.text((90, 114), "OK", font=font_xs, fill=C_DIM)
    else:
        d.rectangle((0, 112, 127, 127), fill=C_HEADER)

    if msg:
        d.rectangle((2, 100, 126, 111), fill=C_MSG_BG, outline=C_CYAN)
        d.text((64, 101), msg[:24], font=font_xs, fill=C_WHITE, anchor="mt")


def _ai_turn(player, enemy):
    alive_ai = [n for n in enemy if n.alive]
    alive_p = [n for n in player if n.alive]
    if not alive_ai or not alive_p:
        return "No moves"

    attacker = random.choice(alive_ai)
    target = min(alive_p, key=lambda n: n.hp)
    damage = max(0, attacker.attack - target.defense + random.randint(-8, 8))
    target.hp = max(0, target.hp - damage)
    target.flash = 6
    target.flash_color = C_ENEMY
    return f"FOE hit {target.name} -{damage}"


def _execute(action, player, enemy, p_idx, t_idx):
    p_node = player[p_idx]

    if action == "SCAN":
        enemy[t_idx].scanned = True
        enemy[t_idx].flash = 4
        enemy[t_idx].flash_color = C_CYAN
        return f"Scanned {enemy[t_idx].name}"

    if action == "ATTACK":
        damage = max(0, p_node.attack - enemy[t_idx].defense + random.randint(-8, 8))
        if enemy[t_idx].scanned:
            damage = int(damage * 1.3)
        enemy[t_idx].hp = max(0, enemy[t_idx].hp - damage)
        enemy[t_idx].flash = 6
        enemy[t_idx].flash_color = C_GOLD
        return f"Hit {enemy[t_idx].name} -{damage}"

    if action == "DEFEND":
        p_node.defense = min(30, p_node.defense + 5)
        p_node.flash = 4
        p_node.flash_color = C_PURPLE
        return f"{p_node.name} DEF+5"

    if action == "PATCH":
        healed = min(25, 100 - p_node.hp)
        p_node.hp = min(100, p_node.hp + healed)
        p_node.flash = 4
        p_node.flash_color = C_HP_GREEN
        return f"{p_node.name} HP+{healed}"

    return ""


def _first_alive(nodes):
    for i, n in enumerate(nodes):
        if n.alive:
            return i
    return 0


def _wait_btn():
    btn = get_button(PINS, GPIO)
    if btn:
        time.sleep(0.15)
    return btn


def _render(lcd, player, enemy, sel, sel_action, turn, msg, phase, frame):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)
    _draw_game(d, player, enemy, sel, sel_action, turn, msg, phase, frame)
    lcd.LCD_ShowImage(img, 0, 0)


def main():
    global _running

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    while _running:
        player = [Node(n) for n in NODE_NAMES]
        enemy = [Node(n) for n in NODE_NAMES]
        turn = 1
        msg = "YOUR TURN"
        sel_node = 0
        sel_action = 0
        frame = 0

        while _running:
            frame += 1

            if sum(1 for n in enemy if n.alive) == 0:
                _render(lcd, player, enemy, 0, 0, turn, "VICTORY!", "", frame)
                while _running:
                    b = _wait_btn()
                    if b == "KEY3":
                        _running = False
                    if b in ("OK", "KEY1"):
                        break
                    time.sleep(0.05)
                break

            if sum(1 for n in player if n.alive) == 0:
                _render(lcd, player, enemy, 0, 0, turn, "DEFEATED!", "", frame)
                while _running:
                    b = _wait_btn()
                    if b == "KEY3":
                        _running = False
                    if b in ("OK", "KEY1"):
                        break
                    time.sleep(0.05)
                break

            sel_node = max(0, min(4, sel_node))
            if not player[sel_node].alive:
                sel_node = _first_alive(player)

            phase = "select_node"
            _render(lcd, player, enemy, sel_node, sel_action, turn, msg, phase, frame)

            node_chosen = False
            while _running and not node_chosen:
                btn = _wait_btn()
                if btn == "KEY3":
                    _running = False
                    break
                if btn == "KEY1":
                    msg = "Skipped"
                    node_chosen = True
                    break
                if btn == "UP":
                    sel_node = (sel_node - 1) % 5
                    while not player[sel_node].alive:
                        sel_node = (sel_node - 1) % 5
                elif btn == "DOWN":
                    sel_node = (sel_node + 1) % 5
                    while not player[sel_node].alive:
                        sel_node = (sel_node + 1) % 5
                elif btn == "OK":
                    node_chosen = True
                frame += 1
                _render(lcd, player, enemy, sel_node, sel_action, turn, msg, phase, frame)
                time.sleep(0.03)

            if not _running:
                break
            if msg == "Skipped":
                ai_msg = _ai_turn(player, enemy)
                msg = ai_msg
                _render(lcd, player, enemy, sel_node, sel_action, turn, msg, "", frame)
                time.sleep(0.6)
                turn += 1
                msg = "YOUR TURN"
                continue

            phase = "select_action"
            _render(lcd, player, enemy, sel_node, sel_action, turn, f"Node: {player[sel_node].name}", phase, frame)

            action_chosen = False
            while _running and not action_chosen:
                btn = _wait_btn()
                if btn == "KEY3":
                    _running = False
                    break
                if btn == "LEFT":
                    sel_action = (sel_action - 1) % len(ACTIONS)
                elif btn == "RIGHT":
                    sel_action = (sel_action + 1) % len(ACTIONS)
                elif btn == "OK":
                    action_chosen = True
                frame += 1
                _render(lcd, player, enemy, sel_node, sel_action, turn, f"Node: {player[sel_node].name}", phase, frame)
                time.sleep(0.03)

            if not _running:
                break

            chosen = ACTIONS[sel_action]

            if chosen in ("ATTACK", "SCAN"):
                alive_idx = [i for i, n in enumerate(enemy) if n.alive]
                if not alive_idx:
                    continue
                t_idx = alive_idx[0]
                phase = "select_target"
                _render(lcd, player, enemy, t_idx, sel_action, turn, f"{chosen} -> ?", phase, frame)

                target_chosen = False
                while _running and not target_chosen:
                    btn = _wait_btn()
                    if btn == "KEY3":
                        _running = False
                        break
                    if btn in ("UP", "DOWN"):
                        cur = alive_idx.index(t_idx)
                        cur = (cur + (-1 if btn == "UP" else 1)) % len(alive_idx)
                        t_idx = alive_idx[cur]
                    elif btn == "OK":
                        target_chosen = True
                    frame += 1
                    _render(lcd, player, enemy, t_idx, sel_action, turn, f"{chosen} -> ?", phase, frame)
                    time.sleep(0.03)

                if not _running:
                    break
            else:
                t_idx = sel_node

            result = _execute(chosen, player, enemy, sel_node, t_idx)
            _render(lcd, player, enemy, sel_node, sel_action, turn, result, "", frame)
            time.sleep(0.7)

            ai_msg = _ai_turn(player, enemy)
            msg = ai_msg
            _render(lcd, player, enemy, sel_node, sel_action, turn, msg, "", frame)
            time.sleep(0.5)

            turn += 1
            msg = "YOUR TURN"

    try:
        lcd.LCD_Clear()
    except Exception:
        pass
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
