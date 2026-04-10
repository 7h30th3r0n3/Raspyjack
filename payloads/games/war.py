#!/usr/bin/env python3
"""
RaspyJack Payload -- Network War Game
--------------------------------------
Author: 7h30th3r0n3

Turn-based strategy game simulating network attack/defense.
Player and AI each have 5 network nodes. Destroy all enemy nodes to win.

Controls:
  UP/DOWN    = select node
  LEFT/RIGHT = cycle action
  OK         = confirm action
  KEY1       = skip turn
  KEY3       = exit
"""
import os, sys, time, signal, random
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
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
_GAME_W, _GAME_H = 128, 128

font = ImageFont.load_default()

running = True


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- Colors ---
COL_BG = (0, 0, 0)
COL_TEXT = (255, 255, 255)
COL_PLAYER = (0, 200, 0)
COL_PLAYER_DIM = (0, 80, 0)
COL_AI = (200, 0, 0)
COL_AI_DIM = (80, 0, 0)
COL_SELECT = (255, 255, 0)
COL_HP_BG = (40, 40, 40)
COL_HP_GREEN = (0, 200, 0)
COL_HP_RED = (200, 0, 0)
COL_HUD = (0, 180, 255)
COL_ACTION = (255, 200, 0)

ACTIONS = ["SCAN", "ATTACK", "DEFEND", "PATCH"]
NODE_NAMES = ["WEB", "DB", "DNS", "FW", "VPN"]


def make_node(name):
    """Create a fresh network node dict."""
    return {
        "name": name,
        "hp": 100,
        "defense": random.randint(5, 15),
        "attack": random.randint(12, 22),
        "scanned": False,
    }


def make_nodes():
    """Return a list of 5 fresh nodes."""
    return [make_node(n) for n in NODE_NAMES]


def clamp(val, lo, hi):
    """Clamp value between lo and hi."""
    if val < lo:
        return lo
    if val > hi:
        return hi
    return val


def nodes_alive(nodes):
    """Return count of nodes with hp > 0."""
    return sum(1 for n in nodes if n["hp"] > 0)


def first_alive_index(nodes):
    """Return index of first alive node."""
    for i, n in enumerate(nodes):
        if n["hp"] > 0:
            return i
    return 0


def draw_health_bar(draw, x, y, w, hp, is_player):
    """Draw a small health bar."""
    draw.rectangle([x, y, x + w, y + 4], fill=COL_HP_BG)
    bar_w = int(w * clamp(hp, 0, 100) / 100)
    if bar_w > 0:
        col = COL_HP_GREEN if is_player else COL_HP_RED
        draw.rectangle([x, y, x + bar_w, y + 4], fill=col)


def draw_game(player, ai, sel_node, sel_action, turn, msg, phase):
    """Render the full game state to LCD."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # HUD bar
    d.text((2, 1), f"T:{turn}", font=font, fill=COL_HUD)
    p_alive = nodes_alive(player)
    a_alive = nodes_alive(ai)
    d.text((30, 1), f"P:{p_alive}", font=font, fill=COL_PLAYER)
    d.text((60, 1), f"E:{a_alive}", font=font, fill=COL_AI)

    # Draw player nodes (left column)
    for i, node in enumerate(player):
        ny = 14 + i * 22
        is_sel = (phase == "select_node" and i == sel_node)
        outline = COL_SELECT if is_sel else COL_PLAYER
        fill = COL_PLAYER if node["hp"] > 0 else COL_PLAYER_DIM
        d.ellipse([4, ny, 16, ny + 12], fill=fill, outline=outline)
        label = node["name"]
        d.text((19, ny + 1), label, font=font, fill=COL_TEXT)
        draw_health_bar(d, 19, ny + 11, 40, node["hp"], True)

    # Draw AI nodes (right column)
    for i, node in enumerate(ai):
        ny = 14 + i * 22
        fill = COL_AI if node["hp"] > 0 else COL_AI_DIM
        d.ellipse([110, ny, 122, ny + 12], fill=fill, outline=COL_AI)
        if node["scanned"]:
            d.text((72, ny + 1), node["name"], font=font, fill=COL_TEXT)
            draw_health_bar(d, 72, ny + 11, 36, node["hp"], False)
        else:
            d.text((80, ny + 1), "???", font=font, fill=(100, 100, 100))

    # Action selector at bottom
    if phase == "select_action":
        d.rectangle([0, 112, 127, 127], fill=(20, 20, 40))
        action_name = ACTIONS[sel_action]
        d.text((4, 114), f"< {action_name} >", font=font, fill=COL_ACTION)
        d.text((80, 114), "OK=Go", font=font, fill=COL_TEXT)
    elif phase == "select_target":
        d.rectangle([0, 112, 127, 127], fill=(40, 20, 20))
        d.text((4, 114), "UP/DN target OK", font=font, fill=COL_AI)

    # Message area
    if msg:
        d.rectangle([2, 100, 126, 111], fill=(0, 0, 60))
        d.text((4, 101), msg[:22], font=font, fill=COL_TEXT)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def wait_btn(timeout=0.05):
    """Poll for a button press with debounce."""
    btn = get_button(PINS, GPIO)
    if btn:
        time.sleep(0.18)
    return btn


def ai_turn(player, ai):
    """Simple AI logic: attack a random alive player node."""
    alive_ai = [n for n in ai if n["hp"] > 0]
    alive_player = [n for n in player if n["hp"] > 0]
    if not alive_ai or not alive_player:
        return "AI has no moves", player

    attacker = random.choice(alive_ai)
    target = random.choice(alive_player)
    damage = max(0, attacker["attack"] - target["defense"] + random.randint(-10, 10))
    new_hp = max(0, target["hp"] - damage)
    updated_player = []
    for n in player:
        if n is target:
            updated_node = dict(n)
            updated_node["hp"] = new_hp
            updated_player.append(updated_node)
        else:
            updated_player.append(dict(n))
    return f"AI hit {target['name']} -{damage}", updated_player


def execute_action(action, player, ai, p_idx, t_idx):
    """Execute a player action. Returns (msg, new_player, new_ai)."""
    new_player = [dict(n) for n in player]
    new_ai = [dict(n) for n in ai]
    p_node = new_player[p_idx]

    if action == "SCAN":
        new_ai[t_idx]["scanned"] = True
        return f"Scanned {NODE_NAMES[t_idx]}", new_player, new_ai

    if action == "ATTACK":
        damage = max(0, p_node["attack"] - new_ai[t_idx]["defense"] + random.randint(-10, 10))
        new_ai[t_idx]["hp"] = max(0, new_ai[t_idx]["hp"] - damage)
        return f"Hit {NODE_NAMES[t_idx]} -{damage}", new_player, new_ai

    if action == "DEFEND":
        new_player[p_idx]["defense"] = min(30, p_node["defense"] + 5)
        return f"{p_node['name']} DEF+5", new_player, new_ai

    if action == "PATCH":
        healed = min(25, 100 - p_node["hp"])
        new_player[p_idx]["hp"] = min(100, p_node["hp"] + healed)
        return f"{p_node['name']} HP+{healed}", new_player, new_ai

    return "", new_player, new_ai


def play():
    """Main game loop."""
    global running

    while running:
        player = make_nodes()
        ai = make_nodes()
        turn = 1
        msg = "YOUR TURN"
        sel_node = 0
        sel_action = 0

        while running:
            # Check win/loss
            if nodes_alive(ai) == 0:
                draw_game(player, ai, 0, 0, turn, "YOU WIN!", "")
                time.sleep(0.5)
                if not wait_for_restart():
                    return
                break
            if nodes_alive(player) == 0:
                draw_game(player, ai, 0, 0, turn, "DEFEATED!", "")
                time.sleep(0.5)
                if not wait_for_restart():
                    return
                break

            # Phase 1: select player node
            sel_node = clamp(sel_node, 0, 4)
            if player[sel_node]["hp"] <= 0:
                sel_node = first_alive_index(player)
            phase = "select_node"
            draw_game(player, ai, sel_node, sel_action, turn, msg, phase)

            node_chosen = False
            while running and not node_chosen:
                btn = wait_btn()
                if btn == "KEY3":
                    cleanup()
                    return
                if btn == "KEY1":
                    # Skip turn
                    node_chosen = True
                    msg = "Turn skipped"
                    break
                if btn == "UP":
                    sel_node = (sel_node - 1) % 5
                    while player[sel_node]["hp"] <= 0:
                        sel_node = (sel_node - 1) % 5
                elif btn == "DOWN":
                    sel_node = (sel_node + 1) % 5
                    while player[sel_node]["hp"] <= 0:
                        sel_node = (sel_node + 1) % 5
                elif btn == "OK":
                    node_chosen = True
                draw_game(player, ai, sel_node, sel_action, turn, msg, phase)
                time.sleep(0.03)

            if not running:
                return
            if msg == "Turn skipped":
                ai_msg, player = ai_turn(player, ai)
                msg = ai_msg
                turn += 1
                continue

            # Phase 2: select action
            phase = "select_action"
            draw_game(player, ai, sel_node, sel_action, turn, f"Node:{player[sel_node]['name']}", phase)

            action_chosen = False
            while running and not action_chosen:
                btn = wait_btn()
                if btn == "KEY3":
                    cleanup()
                    return
                if btn == "LEFT":
                    sel_action = (sel_action - 1) % len(ACTIONS)
                elif btn == "RIGHT":
                    sel_action = (sel_action + 1) % len(ACTIONS)
                elif btn == "OK":
                    action_chosen = True
                draw_game(player, ai, sel_node, sel_action, turn, f"Node:{player[sel_node]['name']}", phase)
                time.sleep(0.03)

            if not running:
                return

            chosen_action = ACTIONS[sel_action]

            # Phase 3: if ATTACK or SCAN, select target
            if chosen_action in ("ATTACK", "SCAN"):
                t_idx = 0
                alive_ai_indices = [i for i, n in enumerate(ai) if n["hp"] > 0]
                if not alive_ai_indices:
                    continue
                t_idx = alive_ai_indices[0]
                phase = "select_target"
                draw_game(player, ai, t_idx, sel_action, turn, f"{chosen_action}->?", phase)

                target_chosen = False
                while running and not target_chosen:
                    btn = wait_btn()
                    if btn == "KEY3":
                        cleanup()
                        return
                    if btn == "UP" or btn == "DOWN":
                        cur = alive_ai_indices.index(t_idx)
                        if btn == "UP":
                            cur = (cur - 1) % len(alive_ai_indices)
                        else:
                            cur = (cur + 1) % len(alive_ai_indices)
                        t_idx = alive_ai_indices[cur]
                    elif btn == "OK":
                        target_chosen = True
                    draw_game(player, ai, t_idx, sel_action, turn, f"{chosen_action}->?", phase)
                    time.sleep(0.03)

                if not running:
                    return
            else:
                t_idx = sel_node  # self-target for DEFEND/PATCH

            # Execute action
            result_msg, player, ai = execute_action(chosen_action, player, ai, sel_node, t_idx)
            draw_game(player, ai, sel_node, sel_action, turn, result_msg, "")
            time.sleep(0.8)

            # AI turn
            ai_msg, player = ai_turn(player, ai)
            msg = ai_msg
            draw_game(player, ai, sel_node, sel_action, turn, msg, "")
            time.sleep(0.6)

            turn += 1
            msg = "YOUR TURN"


def wait_for_restart():
    """Wait for OK/KEY1 to restart or KEY3 to quit. Returns True to restart."""
    while running:
        btn = wait_btn()
        if btn == "KEY3":
            cleanup()
            return False
        if btn in ("OK", "KEY1"):
            return True
        time.sleep(0.05)
    return False


if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
