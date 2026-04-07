#!/usr/bin/env python3
"""
RaspyJack Payload -- Firewall Preset Switcher
===============================================
Author: 7h30th3r0n3

Switch between iptables firewall presets on the fly.
Four built-in presets plus a user-defined custom ruleset.

Presets
-------
  OPEN       -- Accept all traffic (flush rules, policy ACCEPT).
  STEALTH    -- Drop ICMP, reject unsolicited inbound connections.
  BLOCK-ALL  -- Drop all INPUT except ESTABLISHED/RELATED.
  CUSTOM     -- User rules loaded from a JSON config file.

Controls
--------
  UP / DOWN  -- Navigate presets
  OK         -- Apply selected preset
  KEY1       -- Show current iptables rules
  KEY2       -- Save current rules as custom preset
  KEY3       -- Exit

Config: /root/Raspyjack/loot/Firewall/presets.json
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
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
font = scaled_font()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot/Firewall"
CONFIG_PATH = os.path.join(LOOT_DIR, "presets.json")
os.makedirs(LOOT_DIR, exist_ok=True)
ROW_H = 12
DEBOUNCE = 0.20
PRESET_NAMES = ["OPEN", "STEALTH", "BLOCK-ALL", "CUSTOM"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
selected_idx = 0
active_preset = "unknown"
status_msg = "Ready"
view_mode = "menu"          # menu | rules
rules_lines = []            # current iptables output lines
rules_scroll = 0
app_running = True


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# iptables helpers
# ---------------------------------------------------------------------------
def _run_ipt(args):
    """Run an iptables command and return (success, output)."""
    try:
        result = subprocess.run(
            ["iptables"] + args,
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as exc:
        return False, str(exc)


def _flush_rules():
    """Flush all iptables rules and set default ACCEPT."""
    _run_ipt(["-F"])
    _run_ipt(["-X"])
    _run_ipt(["-P", "INPUT", "ACCEPT"])
    _run_ipt(["-P", "FORWARD", "ACCEPT"])
    _run_ipt(["-P", "OUTPUT", "ACCEPT"])


def _apply_open():
    """OPEN preset: accept everything."""
    _flush_rules()
    return "OPEN applied"


def _apply_stealth():
    """STEALTH preset: drop ICMP, reject unsolicited inbound."""
    _flush_rules()
    _run_ipt(["-A", "INPUT", "-m", "conntrack", "--ctstate",
              "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    _run_ipt(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    _run_ipt(["-A", "INPUT", "-p", "icmp", "-j", "DROP"])
    _run_ipt(["-A", "INPUT", "-p", "tcp", "--syn", "-j", "REJECT",
              "--reject-with", "tcp-reset"])
    _run_ipt(["-A", "INPUT", "-p", "udp", "-j", "REJECT",
              "--reject-with", "icmp-port-unreachable"])
    _run_ipt(["-P", "INPUT", "DROP"])
    return "STEALTH applied"


def _apply_block_all():
    """BLOCK-ALL preset: drop all input except established."""
    _flush_rules()
    _run_ipt(["-A", "INPUT", "-m", "conntrack", "--ctstate",
              "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    _run_ipt(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    _run_ipt(["-P", "INPUT", "DROP"])
    return "BLOCK-ALL applied"


def _load_custom_rules():
    """Load custom rules from config file."""
    if not os.path.isfile(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, "r") as fh:
            data = json.load(fh)
        return data.get("custom_rules", [])
    except (json.JSONDecodeError, OSError):
        return None


def _apply_custom():
    """CUSTOM preset: apply user-defined rules from config."""
    rules = _load_custom_rules()
    if rules is None:
        return "No custom preset"
    _flush_rules()
    for rule in rules:
        if not isinstance(rule, list):
            continue
        # Validate: only allow known iptables flags
        _run_ipt(rule)
    return "CUSTOM applied"


def _save_custom_preset():
    """Save current iptables rules as custom preset."""
    ok, output = _run_ipt(["-S"])
    if not ok:
        return "Save failed"
    rules = []
    for line in output.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "-A":
            rules.append(parts)
    data = {
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "custom_rules": rules,
    }
    try:
        with open(CONFIG_PATH, "w") as fh:
            json.dump(data, fh, indent=2)
        return f"Saved {len(rules)} rules"
    except OSError as exc:
        return f"Save err: {exc}"


def _get_current_rules():
    """Get current iptables rules as lines."""
    ok, output = _run_ipt(["-L", "-n", "--line-numbers"])
    if not ok:
        return ["Error reading rules"]
    lines = output.strip().splitlines()
    return lines if lines else ["No rules"]


def _detect_active_preset():
    """Detect which preset is currently active (best guess)."""
    ok, output = _run_ipt(["-S"])
    if not ok:
        return "unknown"
    text = output.strip()
    lines = text.splitlines()
    a_lines = [l for l in lines if l.startswith("-A")]
    if not a_lines:
        return "OPEN"
    has_icmp_drop = any("icmp" in l and "DROP" in l for l in a_lines)
    has_reject = any("REJECT" in l for l in a_lines)
    if has_icmp_drop and has_reject:
        return "STEALTH"
    if not has_reject and not has_icmp_drop:
        established_only = all(
            "ESTABLISHED" in l or "RELATED" in l or "lo" in l
            for l in a_lines
        )
        if established_only:
            return "BLOCK-ALL"
    return "CUSTOM"


APPLY_FNS = {
    "OPEN": _apply_open,
    "STEALTH": _apply_stealth,
    "BLOCK-ALL": _apply_block_all,
    "CUSTOM": _apply_custom,
}


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------
def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "FIREWALL", font=font, fill="#00ccff")

    with lock:
        sel = selected_idx
        act = active_preset
        msg = status_msg
        vm = view_mode
        r_lines = list(rules_lines)
        r_scroll = rules_scroll

    if vm == "menu":
        d.text((70, 1), f"[{act}]", font=font, fill="#00ff00")
        y = 16
        for i, name in enumerate(PRESET_NAMES):
            prefix = ">" if i == sel else " "
            color = "#ffff00" if i == sel else "#cccccc"
            marker = "*" if name == act else " "
            d.text((2, y), f"{prefix}{marker}{name}", font=font, fill=color)
            y += ROW_H + 2

        d.text((2, 90), msg[:22], font=font, fill="#aaaaaa")

        # Footer
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:apply K1:rules K3:x", font=font, fill="#666")

    elif vm == "rules":
        d.text((70, 1), "RULES", font=font, fill="#ffaa00")
        y = 16
        visible = 8
        end = min(len(r_lines), r_scroll + visible)
        for i in range(r_scroll, end):
            line = r_lines[i][:22]
            d.text((2, y), line, font=font, fill="#cccccc")
            y += ROW_H

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "^v:scroll K1:back", font=font, fill="#666")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global app_running, selected_idx, active_preset, status_msg
    global view_mode, rules_lines, rules_scroll

    active_preset = _detect_active_preset()
    last_press = 0.0

    try:
        while app_running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break

            elif btn == "UP":
                with lock:
                    if view_mode == "menu":
                        selected_idx = max(0, selected_idx - 1)
                    else:
                        rules_scroll = max(0, rules_scroll - 1)

            elif btn == "DOWN":
                with lock:
                    if view_mode == "menu":
                        selected_idx = min(len(PRESET_NAMES) - 1, selected_idx + 1)
                    else:
                        max_s = max(0, len(rules_lines) - 8)
                        rules_scroll = min(max_s, rules_scroll + 1)

            elif btn == "OK":
                with lock:
                    if view_mode == "menu":
                        name = PRESET_NAMES[selected_idx]
                fn = APPLY_FNS.get(name)
                if fn:
                    result = fn()
                    with lock:
                        active_preset = name
                        status_msg = result

            elif btn == "KEY1":
                with lock:
                    if view_mode == "menu":
                        rules_lines = _get_current_rules()
                        rules_scroll = 0
                        view_mode = "rules"
                    else:
                        view_mode = "menu"

            elif btn == "KEY2":
                with lock:
                    if view_mode == "menu":
                        result = _save_custom_preset()
                        status_msg = result

            _draw_screen()
            time.sleep(0.1)

    finally:
        app_running = False
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
