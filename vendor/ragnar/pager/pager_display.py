#pager_display.py
# Pager LCD display for Ragnar - multi-screen dashboard mirroring the web UI.
# Renders on the WiFi Pineapple Pager's 222x480 portrait LCD via pagerctl.
#
# Screens (cycle with LEFT/RIGHT):
#   0: Dashboard       - stats grid, status, AI comment, level bar
#   1: Hosts           - scrollable list of discovered hosts with ports
#   2: Credentials     - scrollable list of cracked credentials
#   3: Vulnerabilities - scrollable list of found vulnerabilities
#   4: Scan Settings   - vuln scan, intervals, nmap timing, port range
#   5: Attack Settings - enable attacks, timeouts, retry config
#   6: Network Config  - manual mode, blacklist, WiFi, ethernet
#   7: System Config   - web server, AI, notifications, debug
#
# B (RED) = pause/control menu    UP/DOWN = scroll/select    A (GREEN) = edit setting

import threading
import time
import os
import sys
import signal
import logging
import random
import glob
import subprocess
import csv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pagerctl import Pager
from init_shared import shared_data
from comment import Commentaireia
from logger import Logger

logger = Logger(name="pager_display.py", level=logging.INFO)

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

SCREEN_DASHBOARD = 0
SCREEN_HOSTS = 1
SCREEN_CREDS = 2
SCREEN_VULNS = 3
SCREEN_SCAN_SETTINGS = 4
SCREEN_ATTACK_SETTINGS = 5
SCREEN_NETWORK_SETTINGS = 6
SCREEN_SYSTEM_SETTINGS = 7
SCREEN_COUNT = 8

SCREEN_NAMES = ["Dashboard", "Hosts", "Creds", "Vulns", "Scan Cfg", "Atk Cfg", "Net Cfg", "System"]

# Screens that use interactive settings (UP/DOWN=select, A=edit)
SETTINGS_SCREENS = {SCREEN_SCAN_SETTINGS, SCREEN_ATTACK_SETTINGS, SCREEN_NETWORK_SETTINGS, SCREEN_SYSTEM_SETTINGS}

# ---------------------------------------------------------------------------
# Settings page definitions
# Each entry: key, label, type ('bool'/'int'/'choice'), plus type-specific opts
# ---------------------------------------------------------------------------

SCAN_SETTINGS = [
    {'key': 'scan_vuln_running',    'label': 'Vuln Scan Enabled',    'type': 'bool'},
    {'key': 'scan_vuln_no_ports',   'label': 'Scan No-Port Hosts',   'type': 'bool'},
    {'key': 'scan_interval',        'label': 'Scan Interval (s)',     'type': 'int',    'min': 30,   'max': 3600,  'step': 30},
    {'key': 'scan_vuln_interval',   'label': 'Vuln Interval (s)',     'type': 'int',    'min': 60,   'max': 7200,  'step': 60},
    {'key': 'nmap_scan_aggressivity','label': 'Nmap Timing',          'type': 'choice', 'choices': ['-T1', '-T2', '-T3', '-T4', '-T5']},
    {'key': 'portstart',            'label': 'Port Range Start',      'type': 'int',    'min': 1,    'max': 65535, 'step': 100},
    {'key': 'portend',              'label': 'Port Range End',        'type': 'int',    'min': 1,    'max': 65535, 'step': 100},
    {'key': 'vuln_scan_timeout',    'label': 'Vuln Timeout (s)',      'type': 'int',    'min': 60,   'max': 7200,  'step': 60},
    {'key': 'action_timeout',       'label': 'Action Timeout (s)',    'type': 'int',    'min': 30,   'max': 3600,  'step': 30},
]

ATTACK_SETTINGS = [
    {'key': 'enable_attacks',       'label': 'Enable Attacks',        'type': 'bool'},
    {'key': 'retry_success_actions','label': 'Retry Success',         'type': 'bool'},
    {'key': 'retry_failed_actions', 'label': 'Retry Failures',        'type': 'bool'},
    {'key': 'success_retry_delay',  'label': 'Success Retry (s)',     'type': 'int',    'min': 30,   'max': 3600,  'step': 30},
    {'key': 'failed_retry_delay',   'label': 'Failed Retry (s)',      'type': 'int',    'min': 30,   'max': 3600,  'step': 30},
    {'key': 'timewait_ssh',         'label': 'SSH Timewait (s)',      'type': 'int',    'min': 0,    'max': 3600,  'step': 60},
    {'key': 'timewait_ftp',         'label': 'FTP Timewait (s)',      'type': 'int',    'min': 0,    'max': 3600,  'step': 60},
    {'key': 'timewait_smb',         'label': 'SMB Timewait (s)',      'type': 'int',    'min': 0,    'max': 3600,  'step': 60},
    {'key': 'timewait_rdp',         'label': 'RDP Timewait (s)',      'type': 'int',    'min': 0,    'max': 3600,  'step': 60},
    {'key': 'timewait_sql',         'label': 'SQL Timewait (s)',      'type': 'int',    'min': 0,    'max': 3600,  'step': 60},
    {'key': 'timewait_telnet',      'label': 'Telnet Timewait (s)',   'type': 'int',    'min': 0,    'max': 3600,  'step': 60},
]

NETWORK_SETTINGS = [
    # Pager-relevant network settings only — no Ethernet (pager has none)
    {'key': 'manual_mode',                    'label': 'Manual Mode',         'type': 'bool'},
    {'key': 'blacklistcheck',                 'label': 'MAC Blacklist',       'type': 'bool'},
    {'key': 'network_max_failed_pings',       'label': 'Max Failed Pings',    'type': 'int',  'min': 1,  'max': 100, 'step': 5},
    {'key': 'network_device_retention_days',  'label': 'Host Retention (d)',  'type': 'int',  'min': 1,  'max': 365, 'step': 1},
    {'key': 'network_confirmation_scans',     'label': 'Confirm Scans',       'type': 'int',  'min': 1,  'max': 10,  'step': 1},
    {'key': 'wifi_multi_network_scans_enabled','label': 'Multi-Network Scan', 'type': 'bool'},
    {'key': 'wifi_monitor_enabled',           'label': 'WiFi Monitor',        'type': 'bool'},
    {'key': 'wifi_connection_timeout',        'label': 'WiFi Timeout (s)',    'type': 'int',  'min': 10, 'max': 300, 'step': 10},
    {'key': 'wifi_max_attempts',              'label': 'WiFi Max Attempts',   'type': 'int',  'min': 1,  'max': 10,  'step': 1},
]

SYSTEM_SETTINGS = [
    # Pager-relevant system settings only.
    # Web server is controlled by the startup menu (RAGNAR_WEB_UI env var), not this config.
    {'key': 'ai_enabled',      'label': 'AI Features',        'type': 'bool'},
    {'key': 'pushover_enabled','label': 'Push Notifications', 'type': 'bool'},
    {'key': 'debug_mode',      'label': 'Debug Mode',         'type': 'bool'},
    {'key': 'startup_delay',   'label': 'Startup Delay (s)',  'type': 'int',  'min': 0, 'max': 60,  'step': 1},
    {'key': 'comment_delaymin','label': 'Comment Freq Min',   'type': 'int',  'min': 5, 'max': 120, 'step': 5},
    {'key': 'comment_delaymax','label': 'Comment Freq Max',   'type': 'int',  'min': 5, 'max': 120, 'step': 5},
]

SETTINGS_MAP = {
    SCREEN_SCAN_SETTINGS:    SCAN_SETTINGS,
    SCREEN_ATTACK_SETTINGS:  ATTACK_SETTINGS,
    SCREEN_NETWORK_SETTINGS: NETWORK_SETTINGS,
    SCREEN_SYSTEM_SETTINGS:  SYSTEM_SETTINGS,
}


def discover_launchers():
    """Scan PAYLOAD_DIR for launch_*.sh scripts with valid # Requires: paths."""
    launchers = []
    pattern = os.path.join(PAYLOAD_DIR, 'launch_*.sh')
    matches = sorted(glob.glob(pattern))
    for path in matches:
        basename = os.path.basename(path)
        if basename == 'launch_ragnar.sh':
            continue
        title = None
        requires = None
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('# Title:'):
                        title = line[len('# Title:'):].strip()
                    elif line.startswith('# Requires:'):
                        requires = line[len('# Requires:'):].strip()
                    if title and requires:
                        break
        except Exception as e:
            logger.error(f"discover_launchers: error reading {path}: {e}")
            continue
        if not title:
            continue
        if requires and not os.path.isdir(requires):
            continue
        launchers.append((title, path))
    return launchers


class PagerDisplay:
    """Multi-screen pager dashboard for Ragnar."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.config = self.shared_data.config
        self.shared_data.ragnarstatustext2 = "Awakening..."
        self.commentaire_ia = Commentaireia()
        self.semaphore = threading.Semaphore(10)

        # Initialize pagerctl
        try:
            logger.info("Initializing pagerctl display...")
            self.pager = Pager()
            self.pager.init()
            self.pager.set_rotation(270)  # Landscape 480x222

            self.width = self.pager.width    # 222
            self.height = self.pager.height  # 480
            logger.info(f"Pager display initialized: {self.width}x{self.height}")

            self.shared_data.width = self.width
            self.shared_data.height = self.height
        except Exception as e:
            logger.error(f"Error initializing pagerctl: {e}")
            raise

        # Colors
        self.BLACK = self.pager.BLACK
        self.WHITE = self.pager.WHITE
        self.GRAY = self.pager.rgb(128, 128, 128)
        self.DARK_GRAY = self.pager.rgb(64, 64, 64)
        self.LIGHT_GRAY = self.pager.rgb(200, 200, 200)
        self.GREEN = self.pager.rgb(0, 200, 0)
        self.RED = self.pager.rgb(220, 0, 0)
        self.YELLOW = self.pager.rgb(220, 200, 0)
        self.CYAN = self.pager.rgb(0, 180, 220)
        self.BLUE = self.pager.rgb(50, 100, 220)
        self.ORANGE = self.pager.rgb(220, 140, 0)
        self.PURPLE = self.pager.rgb(160, 80, 220)
        self.DARK_BG = self.pager.rgb(20, 20, 30)
        self.CARD_BG = self.pager.rgb(35, 35, 50)
        self.HEADER_BG = self.pager.rgb(15, 15, 25)

        # Fonts
        self.font_arial = self.shared_data.font_arial_path
        self.font_viking = self.shared_data.font_viking_path

        # Screen state
        self.current_screen = SCREEN_DASHBOARD
        self.scroll_offset = 0
        self.dialog_showing = False
        self._handoff_launcher_path = None

        # Settings screen state: per-screen selected index and scroll position
        self._settings_selected = {s: 0 for s in SETTINGS_SCREENS}
        self._settings_scroll = {s: 0 for s in SETTINGS_SCREENS}

        # Cached data for list screens
        self._hosts_data = []
        self._creds_data = []
        self._vulns_data = []
        self._last_data_refresh = 0

        # Animation
        self.main_image_path = None
        self.last_led_status = None

        # Brightness/dim
        self.screen_brightness = getattr(self.shared_data, 'screen_brightness', 80)
        self.screen_dim_brightness = getattr(self.shared_data, 'screen_dim_brightness', 20)
        self.screen_dim_timeout = getattr(self.shared_data, 'screen_dim_timeout', 60)
        self.last_activity_time = time.time()
        self.is_dimmed = False

        try:
            self.pager.set_brightness(self.screen_brightness)
            logger.info(f"Screen brightness set to {self.screen_brightness}%")
        except Exception as e:
            logger.debug(f"Could not set brightness: {e}")

        self.start_threads()
        logger.info("PagerDisplay initialization complete.")

    def start_threads(self):
        threading.Thread(target=self.schedule_update_shared_data, daemon=True).start()
        threading.Thread(target=self.schedule_update_vuln_count, daemon=True).start()
        threading.Thread(target=self.handle_input_loop, daemon=True).start()

    def schedule_update_shared_data(self):
        while not self.shared_data.display_should_exit:
            self.update_shared_data()
            time.sleep(25)

    def schedule_update_vuln_count(self):
        while not self.shared_data.display_should_exit:
            self.update_vuln_count()
            time.sleep(300)

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------

    def wake_screen(self):
        if self.is_dimmed:
            try:
                self.pager.set_brightness(self.screen_brightness)
                self.is_dimmed = False
            except Exception:
                pass
        self.last_activity_time = time.time()

    def dim_screen(self):
        if not self.is_dimmed:
            try:
                self.pager.set_brightness(self.screen_dim_brightness)
                self.is_dimmed = True
            except Exception:
                pass

    def check_dim_timeout(self):
        if self.screen_dim_timeout > 0 and not self.is_dimmed:
            if time.time() - self.last_activity_time > self.screen_dim_timeout:
                self.dim_screen()

    def handle_input_loop(self):
        """Handle button input for navigation and pause menu."""
        logger.info("Input handler: Monitoring for button presses")
        while not self.shared_data.display_should_exit:
            try:
                event = self.pager.get_input_event()
                if not event:
                    time.sleep(0.016)
                    continue

                button, event_type, timestamp = event
                if event_type != Pager.EVENT_PRESS:
                    continue

                self.wake_screen()

                if button == Pager.BTN_B:
                    logger.info("Red button pressed - showing pause menu")
                    action = self.show_exit_confirmation()
                    if action is None:
                        continue
                    logger.info(f"Menu action: exit code {action}")
                    self.shared_data.should_exit = True
                    self.shared_data.display_should_exit = True
                    self.shared_data.orchestrator_should_exit = True
                    if action == 42:
                        data_dir = os.path.join(PAYLOAD_DIR, 'data')
                        os.makedirs(data_dir, exist_ok=True)
                        next_payload_path = os.path.join(data_dir, '.next_payload')
                        with open(next_payload_path, 'w') as f:
                            f.write(self._handoff_launcher_path)
                    self.cleanup()
                    os._exit(action)

                elif button == Pager.BTN_LEFT:
                    self.current_screen = (self.current_screen - 1) % SCREEN_COUNT
                    self.scroll_offset = 0

                elif button == Pager.BTN_RIGHT:
                    self.current_screen = (self.current_screen + 1) % SCREEN_COUNT
                    self.scroll_offset = 0

                elif button == Pager.BTN_UP:
                    if self.current_screen in SETTINGS_SCREENS:
                        self._settings_move_selection(-1)
                    elif self.scroll_offset > 0:
                        self.scroll_offset -= 1

                elif button == Pager.BTN_DOWN:
                    if self.current_screen in SETTINGS_SCREENS:
                        self._settings_move_selection(1)
                    else:
                        self.scroll_offset += 1

                elif button == Pager.BTN_A:
                    if self.current_screen in SETTINGS_SCREENS:
                        self._settings_activate()

            except Exception as e:
                logger.error(f"Error in input handler: {e}")
                time.sleep(1.0)

    # ------------------------------------------------------------------
    # Data loading for list screens
    # ------------------------------------------------------------------

    def refresh_list_data(self):
        """Refresh host/cred/vuln lists from CSV files (max once per 5s)."""
        now = time.time()
        if now - self._last_data_refresh < 5:
            return
        self._last_data_refresh = now

        # Hosts from SQLite DB (primary) or netkb.csv (fallback)
        self._hosts_data = []
        try:
            if self.shared_data.db is not None:
                for h in self.shared_data.db.get_all_hosts():
                    if h.get('mac') == 'STANDALONE':
                        continue
                    self._hosts_data.append({
                        'ip': h.get('ip', '?'),
                        'hostname': h.get('hostname', ''),
                        'alive': h.get('status') == 'alive',
                        'ports': h.get('ports', ''),
                        'mac': h.get('mac', ''),
                    })
            elif os.path.exists(self.shared_data.netkbfile):
                with open(self.shared_data.netkbfile, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get("MAC Address") == "STANDALONE":
                            continue
                        self._hosts_data.append({
                            'ip': row.get('IPs', '?'),
                            'hostname': row.get('Hostnames', ''),
                            'alive': row.get('Alive', '0') == '1',
                            'ports': row.get('Ports', ''),
                            'mac': row.get('MAC Address', ''),
                        })
        except Exception as e:
            logger.debug(f"Error reading hosts: {e}")

        # Credentials from crackedpwd/*.csv
        self._creds_data = []
        try:
            cred_files = glob.glob(f"{self.shared_data.crackedpwddir}/*.csv")
            for filepath in cred_files:
                service = os.path.basename(filepath).replace('.csv', '').upper()
                try:
                    with open(filepath, 'r') as f:
                        reader = csv.reader(f)
                        header = next(reader, None)
                        for row in reader:
                            if len(row) >= 3:
                                self._creds_data.append({
                                    'service': service,
                                    'host': row[0] if row else '',
                                    'user': row[1] if len(row) > 1 else '',
                                    'password': row[2] if len(row) > 2 else '',
                                })
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Error reading creds: {e}")

        # Vulnerabilities from SQLite DB (primary) or vulnerability_summary.csv (fallback)
        self._vulns_data = []
        try:
            if self.shared_data.db is not None:
                for h in self.shared_data.db.get_all_hosts():
                    if h.get('mac') == 'STANDALONE':
                        continue
                    vulns = h.get('vulnerabilities', '')
                    if vulns:
                        self._vulns_data.append({
                            'ip': h.get('ip', '?'),
                            'hostname': h.get('hostname', ''),
                            'port': h.get('ports', ''),
                            'vulns': vulns,
                        })
            elif os.path.exists(self.shared_data.vuln_summary_file):
                with open(self.shared_data.vuln_summary_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        vulns = row.get('Vulnerabilities', '')
                        if vulns:
                            self._vulns_data.append({
                                'ip': row.get('IP', '?'),
                                'hostname': row.get('Hostname', ''),
                                'port': row.get('Port', ''),
                                'vulns': vulns,
                            })
        except Exception as e:
            logger.debug(f"Error reading vulns: {e}")

    # ------------------------------------------------------------------
    # Drawing helpers
    # ------------------------------------------------------------------

    def sanitize_text(self, text):
        if not text:
            return text
        replacements = {
            '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
            '\u2013': '-', '\u2014': '-', '\u2026': '...',
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def draw_icon_scaled(self, x, y, w, h, icon_name):
        icon_path = self.shared_data.static_images.get(icon_name)
        if icon_path and os.path.exists(icon_path):
            try:
                self.pager.draw_image_file_scaled(x, y, w, h, icon_path)
                return True
            except Exception:
                pass
        return False

    def _draw_screen_header(self, title):
        """Draw the top header bar with title, screen dots, and nav hint."""
        h = 24
        self.pager.fill_rect(0, 0, self.width, h, self.HEADER_BG)
        self.pager.draw_ttf(8, 2, title, self.WHITE, self.font_viking, 18)

        # Compact screen indicator dots (6px spacing, fits 8 screens in 56px)
        DOT_SIZE = 4
        DOT_SPACING = 6
        total_dots_w = SCREEN_COUNT * DOT_SPACING
        dot_x_start = self.width - total_dots_w - 8
        dot_y = 10
        for i in range(SCREEN_COUNT):
            dx = dot_x_start + i * DOT_SPACING
            # Settings screens get a distinct color (purple) when inactive
            if i in SETTINGS_SCREENS:
                color = self.CYAN if i == self.current_screen else self.PURPLE
            else:
                color = self.CYAN if i == self.current_screen else self.DARK_GRAY
            self.pager.fill_rect(dx, dot_y, DOT_SIZE, DOT_SIZE, color)

        # Nav hint: show adjacent screen names compactly
        left_name = SCREEN_NAMES[(self.current_screen - 1) % SCREEN_COUNT]
        right_name = SCREEN_NAMES[(self.current_screen + 1) % SCREEN_COUNT]
        hint = f"<{left_name} {right_name}>"
        self.pager.draw_ttf(dot_x_start - 120, 4, hint, self.DARK_GRAY, self.font_arial, 10)

    def _draw_stat_card(self, x, y, w, h, value, label, color):
        """Draw a single stat card with big number and label."""
        self.pager.fill_rect(x, y, w, h, self.CARD_BG)
        self.pager.rect(x, y, w, h, self.DARK_GRAY)
        val_str = str(value)
        vw = self.pager.ttf_width(val_str, self.font_arial, 18)
        self.pager.draw_ttf(x + (w - vw) // 2, y + 2, val_str, color, self.font_arial, 18)
        lw = self.pager.ttf_width(label, self.font_arial, 10)
        self.pager.draw_ttf(x + (w - lw) // 2, y + h - 14, label, self.GRAY, self.font_arial, 10)

    # ------------------------------------------------------------------
    # Screen 0: Dashboard
    # ------------------------------------------------------------------

    def draw_dashboard(self):
        """Dashboard layout for 480x222 landscape."""
        self.pager.clear(self.DARK_BG)
        self._draw_screen_header("RAGNAR")

        # Layout: left panel (stats + status), right panel (character + comment)
        left_w = 300
        right_x = left_w + 4
        right_w = self.width - right_x - 2
        y = 26

        # Status bar (full width)
        status = self.shared_data.ragnarorch_status or "IDLE"
        status2 = self.shared_data.ragnarstatustext2 or ""
        status_color = self.GREEN if "IDLE" in status else self.CYAN
        if "Bruteforce" in status:
            status_color = self.RED
        elif "Steal" in status:
            status_color = self.YELLOW

        self.pager.fill_rect(2, y, self.width - 4, 20, self.CARD_BG)
        self.pager.draw_ttf(8, y + 2, status[:30], status_color, self.font_arial, 13)
        tw = self.pager.ttf_width(status2[:30], self.font_arial, 11)
        self.pager.draw_ttf(self.width - tw - 8, y + 4, status2[:30], self.GRAY, self.font_arial, 11)
        y += 24

        # Stats grid: 6 cards in 2 rows x 3 cols (left panel)
        card_w = (left_w - 12) // 3
        card_h = 34
        gap = 3
        stats = [
            (self.shared_data.targetnbr, "TRGT", self.GREEN),
            (self.shared_data.portnbr, "PORT", self.CYAN),
            (self.shared_data.vulnnbr, "VULN", self.RED),
            (self.shared_data.crednbr, "CRED", self.YELLOW),
            (self.shared_data.zombiesnbr, "ZOMB", self.PURPLE),
            (self.shared_data.datanbr, "DATA", self.ORANGE),
        ]

        for i, (val, label, color) in enumerate(stats):
            col = i % 3
            row = i // 3
            cx = 4 + col * (card_w + gap)
            cy = y + row * (card_h + gap)
            self._draw_stat_card(cx, cy, card_w, card_h, val, label, color)

        # Level bar below stats
        stats_bottom = y + 2 * (card_h + gap) + 2
        level = self.shared_data.levelnbr
        coins = self.shared_data.coinnbr
        ppl = self.shared_data.points_per_level if hasattr(self.shared_data, 'points_per_level') else 200
        progress = (coins % ppl) / ppl if ppl > 0 else 0

        self.pager.draw_ttf(6, stats_bottom, f"Lvl {level}", self.PURPLE, self.font_arial, 12)
        self.pager.draw_ttf(60, stats_bottom, f"{coins}pts", self.GRAY, self.font_arial, 11)
        bar_x = 120
        bar_y = stats_bottom + 4
        bar_w = left_w - bar_x - 6
        bar_h = 5
        self.pager.fill_rect(bar_x, bar_y, bar_w, bar_h, self.DARK_GRAY)
        fill_w = max(1, int(bar_w * progress))
        self.pager.fill_rect(bar_x, bar_y, fill_w, bar_h, self.PURPLE)

        # AI Comment below level
        comment_y = stats_bottom + 16
        comment_h = self.height - comment_y - 2
        if comment_h > 10:
            comment = self.sanitize_text(self.shared_data.ragnarsays) or "..."
            lines = self.shared_data.wrap_text(comment, max_chars=38)
            for i, line in enumerate(lines[:3]):
                self.pager.draw_ttf(6, comment_y + i * 15, line, self.LIGHT_GRAY, self.font_arial, 12)

        # Right panel: Network info
        info_y = y
        self.pager.fill_rect(right_x + 2, info_y, right_w - 4, self.height - info_y - 4, self.CARD_BG)
        self.pager.rect(right_x + 2, info_y, right_w - 4, self.height - info_y - 4, self.DARK_GRAY)
        mode = "AUTO" if not self.shared_data.manual_mode else "MANUAL"
        mode_color = self.GREEN if not self.shared_data.manual_mode else self.ORANGE
        self.pager.draw_ttf(right_x + 8, info_y + 4, mode, mode_color, self.font_arial, 14)
        self.pager.draw_ttf(right_x + 8, info_y + 22, f"KB: {self.shared_data.networkkbnbr}", self.GRAY, self.font_arial, 12)
        self.pager.draw_ttf(right_x + 8, info_y + 38, f"Atk: {self.shared_data.attacksnbr}", self.GRAY, self.font_arial, 12)
        wifi = "WiFi: ON" if self.shared_data.wifi_connected else "WiFi: --"
        self.pager.draw_ttf(right_x + 8, info_y + 54, wifi, self.CYAN if self.shared_data.wifi_connected else self.DARK_GRAY, self.font_arial, 12)

    # ------------------------------------------------------------------
    # Screen 1: Hosts
    # ------------------------------------------------------------------

    def draw_hosts(self):
        """Hosts list for 480x222 landscape."""
        self.pager.clear(self.DARK_BG)
        self.refresh_list_data()

        alive = sum(1 for h in self._hosts_data if h['alive'])
        self._draw_screen_header(f"HOSTS ({alive} alive)")

        y = 26
        max_y = self.height - 2
        row_h = 24
        visible = (max_y - y) // row_h

        hosts = self._hosts_data
        total = len(hosts)
        self.scroll_offset = min(self.scroll_offset, max(0, total - visible))

        if not hosts:
            self.pager.draw_ttf_centered(100, "No hosts found yet", self.GRAY, self.font_arial, 16)
        else:
            # Column headers
            self.pager.draw_ttf(8, y, "IP", self.GRAY, self.font_arial, 10)
            self.pager.draw_ttf(150, y, "HOSTNAME", self.GRAY, self.font_arial, 10)
            self.pager.draw_ttf(310, y, "PORTS", self.GRAY, self.font_arial, 10)
            y += 16

            for i in range(self.scroll_offset, min(self.scroll_offset + visible - 1, total)):
                h = hosts[i]
                cy = y + (i - self.scroll_offset) * row_h

                # Alternating row bg
                if (i - self.scroll_offset) % 2 == 0:
                    self.pager.fill_rect(2, cy, self.width - 4, row_h - 2, self.CARD_BG)

                # Status dot
                dot_color = self.GREEN if h['alive'] else self.RED
                self.pager.fill_rect(4, cy + 7, 5, 5, dot_color)

                # IP
                self.pager.draw_ttf(12, cy + 3, h['ip'][:18], self.WHITE, self.font_arial, 13)
                # Hostname
                hn = h['hostname'][:18] if h['hostname'] else ""
                self.pager.draw_ttf(150, cy + 3, hn, self.GRAY, self.font_arial, 12)
                # Ports
                ports = h['ports'][:22] if h['ports'] else "-"
                self.pager.draw_ttf(310, cy + 3, ports, self.CYAN, self.font_arial, 11)

            # Scroll indicator
            if total > visible:
                sb_h = max(8, int((max_y - 42) * visible / total))
                sb_y = 42 + int((max_y - 42 - sb_h) * self.scroll_offset / max(1, total - visible))
                self.pager.fill_rect(self.width - 3, sb_y, 2, sb_h, self.GRAY)

    # ------------------------------------------------------------------
    # Screen 2: Credentials
    # ------------------------------------------------------------------

    def draw_credentials(self):
        """Credentials list for 480x222 landscape."""
        self.pager.clear(self.DARK_BG)
        self.refresh_list_data()

        count = len(self._creds_data)
        self._draw_screen_header(f"CREDENTIALS ({count})")

        y = 26
        max_y = self.height - 2
        row_h = 24
        visible = (max_y - y) // row_h

        creds = self._creds_data
        total = len(creds)
        self.scroll_offset = min(self.scroll_offset, max(0, total - visible))

        if not creds:
            self.pager.draw_ttf_centered(100, "No credentials yet", self.GRAY, self.font_arial, 16)
        else:
            # Column headers
            self.pager.draw_ttf(8, y, "SERVICE", self.GRAY, self.font_arial, 10)
            self.pager.draw_ttf(100, y, "HOST", self.GRAY, self.font_arial, 10)
            self.pager.draw_ttf(260, y, "USER:PASS", self.GRAY, self.font_arial, 10)
            y += 16

            for i in range(self.scroll_offset, min(self.scroll_offset + visible - 1, total)):
                c = creds[i]
                cy = y + (i - self.scroll_offset) * row_h

                if (i - self.scroll_offset) % 2 == 0:
                    self.pager.fill_rect(2, cy, self.width - 4, row_h - 2, self.CARD_BG)

                self.pager.draw_ttf(8, cy + 3, c['service'][:12], self.YELLOW, self.font_arial, 12)
                self.pager.draw_ttf(100, cy + 3, c['host'][:18], self.WHITE, self.font_arial, 12)
                cred = f"{c['user']}:{c['password']}"[:28]
                self.pager.draw_ttf(260, cy + 3, cred, self.GREEN, self.font_arial, 12)

            if total > visible:
                sb_h = max(8, int((max_y - 42) * visible / total))
                sb_y = 42 + int((max_y - 42 - sb_h) * self.scroll_offset / max(1, total - visible))
                self.pager.fill_rect(self.width - 3, sb_y, 2, sb_h, self.GRAY)

    # ------------------------------------------------------------------
    # Screen 3: Vulnerabilities
    # ------------------------------------------------------------------

    def draw_vulnerabilities(self):
        """Vulnerabilities list for 480x222 landscape."""
        self.pager.clear(self.DARK_BG)
        self.refresh_list_data()

        count = len(self._vulns_data)
        self._draw_screen_header(f"VULNS ({count})")

        y = 26
        max_y = self.height - 2
        row_h = 24
        visible = (max_y - y) // row_h

        vulns = self._vulns_data
        total = len(vulns)
        self.scroll_offset = min(self.scroll_offset, max(0, total - visible))

        if not vulns:
            self.pager.draw_ttf_centered(100, "No vulnerabilities found", self.GRAY, self.font_arial, 16)
        else:
            # Column headers
            self.pager.draw_ttf(8, y, "HOST:PORT", self.GRAY, self.font_arial, 10)
            self.pager.draw_ttf(180, y, "HOSTNAME", self.GRAY, self.font_arial, 10)
            self.pager.draw_ttf(310, y, "CVEs", self.GRAY, self.font_arial, 10)
            y += 16

            for i in range(self.scroll_offset, min(self.scroll_offset + visible - 1, total)):
                v = vulns[i]
                cy = y + (i - self.scroll_offset) * row_h

                if (i - self.scroll_offset) % 2 == 0:
                    self.pager.fill_rect(2, cy, self.width - 4, row_h - 2, self.CARD_BG)

                host_text = f"{v['ip']}:{v['port']}"[:22]
                self.pager.draw_ttf(8, cy + 3, host_text, self.RED, self.font_arial, 12)
                if v['hostname']:
                    self.pager.draw_ttf(180, cy + 3, v['hostname'][:16], self.GRAY, self.font_arial, 11)
                vuln_list = v['vulns'][:24]
                self.pager.draw_ttf(310, cy + 3, vuln_list, self.ORANGE, self.font_arial, 11)

            if total > visible:
                sb_h = max(8, int((max_y - 42) * visible / total))
                sb_y = 42 + int((max_y - 42 - sb_h) * self.scroll_offset / max(1, total - visible))
                self.pager.fill_rect(self.width - 3, sb_y, 2, sb_h, self.GRAY)

    # ------------------------------------------------------------------
    # Settings screens (4-7) - interactive configuration
    # ------------------------------------------------------------------

    def _get_settings_for_screen(self, screen):
        """Return the settings list for a given settings screen."""
        return SETTINGS_MAP.get(screen, [])

    def _settings_move_selection(self, direction):
        """Move the selection cursor on a settings screen."""
        screen = self.current_screen
        settings = self._get_settings_for_screen(screen)
        if not settings:
            return
        n = len(settings)
        current = self._settings_selected.get(screen, 0)
        new_idx = (current + direction) % n
        self._settings_selected[screen] = new_idx

        # Keep scroll window in sync so selected item is always visible
        ROW_H = 26
        header_h = 26
        visible = (self.height - header_h) // ROW_H
        scroll = self._settings_scroll.get(screen, 0)
        if new_idx < scroll:
            scroll = new_idx
        elif new_idx >= scroll + visible:
            scroll = new_idx - visible + 1
        self._settings_scroll[screen] = max(0, scroll)

    def _settings_activate(self):
        """Edit the currently selected setting on a settings screen."""
        screen = self.current_screen
        settings = self._get_settings_for_screen(screen)
        if not settings:
            return
        idx = self._settings_selected.get(screen, 0)
        if idx >= len(settings):
            return
        self._edit_setting(settings[idx])

    def _save_setting(self, key, value):
        """Persist a setting change to shared_data config and disk."""
        try:
            self.shared_data.config[key] = value
            setattr(self.shared_data, key, value)
            self.shared_data.save_config()
            logger.info(f"Setting saved: {key} = {value}")
        except Exception as e:
            logger.error(f"Error saving setting {key}: {e}")

    def _edit_setting(self, setting):
        """Dispatch to the appropriate editor based on setting type."""
        key = setting['key']
        stype = setting['type']
        label = setting['label']

        if stype == 'bool':
            # Boolean: immediate toggle, no dialog needed
            current = bool(self.shared_data.config.get(key, False))
            self._save_setting(key, not current)

        elif stype == 'int':
            self._edit_int_dialog(
                key, label,
                setting.get('min', 0),
                setting.get('max', 9999),
                setting.get('step', 1)
            )

        elif stype == 'choice':
            self._edit_choice_dialog(key, label, setting['choices'])

    def _edit_int_dialog(self, key, label, min_val, max_val, step):
        """Show a dialog to edit an integer setting with UP/DOWN to change value."""
        self.dialog_showing = True
        try:
            current = int(self.shared_data.config.get(key, min_val))
            current = max(min_val, min(max_val, current))

            # Dialog box: 400w x 148h, centred on 480x222
            DW, DH = 400, 148
            DX = (self.width - DW) // 2    # 40
            DY = (self.height - DH) // 2   # 37

            def draw():
                # Box
                self.pager.fill_rect(DX, DY, DW, DH, self.CARD_BG)
                self.pager.rect(DX, DY, DW, DH, self.CYAN)
                self.pager.rect(DX + 2, DY + 2, DW - 4, DH - 4, self.DARK_GRAY)

                # Label — 16px (TTF_MEDIUM), readable
                lw = self.pager.ttf_width(label[:28], self.font_arial, 16)
                self.pager.draw_ttf((self.width - lw) // 2, DY + 10, label[:28],
                                    self.WHITE, self.font_arial, 16)

                # Value — 36px, very prominent
                val_str = str(current)
                vw = self.pager.ttf_width(val_str, self.font_arial, 36)
                self.pager.draw_ttf((self.width - vw) // 2, DY + 38, val_str,
                                    self.CYAN, self.font_arial, 36)

                # Range hint — 13px (TTF_SMALL)
                hint = f"{min_val} - {max_val}   step {step}"
                hw = self.pager.ttf_width(hint, self.font_arial, 13)
                self.pager.draw_ttf((self.width - hw) // 2, DY + 94, hint,
                                    self.GRAY, self.font_arial, 13)

                # Button hints — 13px
                self.pager.draw_ttf_centered(DY + 118, "UP: increase   DOWN: decrease   A: save   B: cancel",
                                             self.GRAY, self.font_arial, 13)
                self.pager.flip()

            draw()

            while True:
                button = self.pager.wait_button()
                if button & Pager.BTN_UP:
                    current = min(max_val, current + step)
                    draw()
                elif button & Pager.BTN_DOWN:
                    current = max(min_val, current - step)
                    draw()
                elif button & Pager.BTN_A:
                    self._save_setting(key, current)
                    break
                elif button & Pager.BTN_B:
                    break
        except Exception as e:
            logger.error(f"Error in int dialog for {key}: {e}")
        finally:
            self.dialog_showing = False

    def _edit_choice_dialog(self, key, label, choices):
        """Show a dialog to select from a list of string choices."""
        self.dialog_showing = True
        try:
            current_val = self.shared_data.config.get(key, choices[0])
            try:
                selected = choices.index(current_val)
            except ValueError:
                selected = 0

            # Each option row: 28px.  Dialog: label(28) + options + hint(22)
            OPT_H = 28
            DW = 340
            DH = 30 + len(choices) * OPT_H + 26   # e.g. 5 choices → 196px
            DX = (self.width - DW) // 2
            DY = max(4, (self.height - DH) // 2)

            def draw():
                self.pager.fill_rect(DX, DY, DW, DH, self.CARD_BG)
                self.pager.rect(DX, DY, DW, DH, self.CYAN)

                # Label — 16px
                lw = self.pager.ttf_width(label[:26], self.font_arial, 16)
                self.pager.draw_ttf((self.width - lw) // 2, DY + 7, label[:26],
                                    self.WHITE, self.font_arial, 16)

                for i, choice in enumerate(choices):
                    cy = DY + 30 + i * OPT_H
                    if i == selected:
                        self.pager.fill_rect(DX + 4, cy - 2, DW - 8, OPT_H - 2, self.BLUE)
                    cw = self.pager.ttf_width(choice, self.font_arial, 16)
                    color = self.WHITE if i == selected else self.LIGHT_GRAY
                    self.pager.draw_ttf((self.width - cw) // 2, cy + 4, choice,
                                        color, self.font_arial, 16)

                # Hint — 13px
                hint_y = DY + DH - 22
                self.pager.draw_ttf_centered(hint_y, "UP/DOWN: select   A: save   B: cancel",
                                             self.GRAY, self.font_arial, 13)
                self.pager.flip()

            draw()

            while True:
                button = self.pager.wait_button()
                if button & Pager.BTN_UP:
                    selected = (selected - 1) % len(choices)
                    draw()
                elif button & Pager.BTN_DOWN:
                    selected = (selected + 1) % len(choices)
                    draw()
                elif button & Pager.BTN_A:
                    self._save_setting(key, choices[selected])
                    break
                elif button & Pager.BTN_B:
                    break
        except Exception as e:
            logger.error(f"Error in choice dialog for {key}: {e}")
        finally:
            self.dialog_showing = False

    def _get_setting_value_str(self, setting):
        """Return a display string for the current value of a setting."""
        key = setting['key']
        stype = setting['type']
        raw = self.shared_data.config.get(key)
        if raw is None:
            raw = getattr(self.shared_data, key, None)
        if raw is None:
            return '?'
        if stype == 'bool':
            return 'ON' if bool(raw) else 'OFF'
        return str(raw)

    def _get_setting_value_color(self, setting):
        """Return a color for the current value display."""
        key = setting['key']
        stype = setting['type']
        raw = self.shared_data.config.get(key)
        if raw is None:
            raw = getattr(self.shared_data, key, None)
        if stype == 'bool':
            # Special colors for high-impact settings
            if key == 'enable_attacks':
                return self.RED if bool(raw) else self.DARK_GRAY
            if key == 'manual_mode':
                return self.ORANGE if bool(raw) else self.GREEN
            return self.GREEN if bool(raw) else self.DARK_GRAY
        return self.CYAN

    def _draw_settings_screen(self, screen_id, title):
        """Generic renderer for settings screens.

        Font sizes match pager_menu.py's tuned values for 480x222:
          labels/values: 16px (TTF_MEDIUM — proven readable on this screen)
          bottom hint:   13px (TTF_SMALL)
        Row height 28px gives 6 visible rows in the content area.
        """
        self.pager.clear(self.DARK_BG)
        self._draw_screen_header(title)

        settings = self._get_settings_for_screen(screen_id)
        if not settings:
            self.pager.draw_ttf_centered(100, "No settings available", self.GRAY, self.font_arial, 20)
            return

        # Layout constants — tuned for 480x222 with 24px header + 18px hint bar
        ROW_H = 28          # 28px per row → 6 rows in 168px content area
        HINT_H = 18         # bottom hint bar height
        y_start = 26        # immediately after 24px header + 2px gap
        content_h = self.height - y_start - HINT_H
        visible = content_h // ROW_H   # = 168 // 28 = 6

        # Column positions
        SEL_X = 4           # ">" selection arrow
        LABEL_X = 20        # setting label start
        VALUE_X = 330       # current value (right side)
        DOT_X = self.width - 10   # type-indicator dot

        scroll = self._settings_scroll.get(screen_id, 0)
        selected = self._settings_selected.get(screen_id, 0)

        for i in range(scroll, min(scroll + visible, len(settings))):
            s = settings[i]
            row_y = y_start + (i - scroll) * ROW_H
            is_selected = (i == selected)

            # Row background
            if is_selected:
                self.pager.fill_rect(2, row_y, self.width - 4, ROW_H - 2, self.BLUE)
            elif (i - scroll) % 2 == 0:
                self.pager.fill_rect(2, row_y, self.width - 4, ROW_H - 2, self.CARD_BG)

            # Selection arrow
            if is_selected:
                self.pager.draw_ttf(SEL_X, row_y + 6, ">", self.CYAN, self.font_arial, 14)

            # Label — 16px, same as pager_menu TTF_MEDIUM
            label_color = self.WHITE if is_selected else self.LIGHT_GRAY
            self.pager.draw_ttf(LABEL_X, row_y + 6, s['label'][:26], label_color, self.font_arial, 16)

            # Value — 16px, color-coded by meaning
            val_str = self._get_setting_value_str(s)
            val_color = self._get_setting_value_color(s) if not is_selected else self.WHITE
            self.pager.draw_ttf(VALUE_X, row_y + 6, val_str[:10], val_color, self.font_arial, 16)

            # Small type-indicator dot (green=bool, cyan=int, yellow=choice)
            type_colors = {'bool': self.GREEN, 'int': self.CYAN, 'choice': self.YELLOW}
            self.pager.fill_rect(DOT_X, row_y + 11, 5, 5, type_colors.get(s['type'], self.GRAY))

        # Scroll bar
        total = len(settings)
        if total > visible:
            sb_area = content_h
            sb_h = max(10, int(sb_area * visible / total))
            sb_y = y_start + int((sb_area - sb_h) * scroll / max(1, total - visible))
            self.pager.fill_rect(self.width - 3, sb_y, 2, sb_h, self.GRAY)

        # Bottom hint bar — 13px (TTF_SMALL), readable without eating row space
        hint_y = self.height - HINT_H
        self.pager.fill_rect(0, hint_y, self.width, HINT_H, self.HEADER_BG)
        self.pager.draw_ttf_centered(hint_y + 2, "UP/DN: select   A: edit/toggle   B: menu",
                                     self.GRAY, self.font_arial, 13)

    # ------------------------------------------------------------------
    # Pause menu (kept from original)
    # ------------------------------------------------------------------

    def show_exit_confirmation(self):
        """Show pause menu. Returns: None=back, 99=main menu, 42=handoff, 0=exit."""
        self.dialog_showing = True
        time.sleep(0.2)

        current_brightness = self.pager.get_brightness()
        if current_brightness < 0:
            current_brightness = self.screen_brightness

        green_color = self.pager.rgb(0, 150, 0)
        yellow_color = self.pager.rgb(180, 150, 0)
        blue_color = self.pager.rgb(50, 100, 220)
        red_color = self.pager.rgb(200, 0, 0)

        options = [
            ("BACK", green_color, None),
            ("Main Menu", yellow_color, 99),
        ]

        launchers = discover_launchers()
        for title, path in launchers:
            options.append((f"> {title}", blue_color, (42, path)))

        options.append(("Exit Ragnar", red_color, 0))

        num_options = len(options)
        selected = 0

        def draw_menu():
            self.pager.fill_rect(0, 0, self.width, self.height, self.WHITE)
            box_y = int(self.height * 0.10)
            box_h = int(self.height * 0.80)
            self.pager.fill_rect(10, box_y, self.width - 20, box_h, self.WHITE)
            self.pager.rect(10, box_y, self.width - 20, box_h, self.BLACK)
            self.pager.rect(12, box_y + 2, self.width - 24, box_h - 4, self.BLACK)

            title_y = box_y + 15
            self.pager.draw_ttf_centered(title_y, "MENU", self.BLACK, self.font_viking, 24)

            bright_y = box_y + 60
            self.pager.draw_ttf_centered(bright_y, "BRIGHTNESS", self.BLACK, self.font_arial, 16)

            bar_y = bright_y + 30
            bar_x = 30
            bar_w = self.width - 60
            bar_h = 20
            self.pager.fill_rect(bar_x, bar_y, bar_w, bar_h, self.GRAY)
            fill_w = int(bar_w * current_brightness / 100)
            self.pager.fill_rect(bar_x, bar_y, fill_w, bar_h, self.BLACK)
            self.pager.rect(bar_x, bar_y, bar_w, bar_h, self.BLACK)

            pct_y = bar_y + bar_h + 5
            self.pager.draw_ttf_centered(pct_y, f"{current_brightness}%", self.BLACK, self.font_arial, 16)

            btn_w = 140
            btn_h = 32
            btn_x = (self.width - btn_w) // 2
            btn_gap = 10
            font_size = 16
            first_btn_y = pct_y + 30

            for i, (label, color, _action) in enumerate(options):
                btn_y = first_btn_y + i * (btn_h + btn_gap)
                if i == selected:
                    self.pager.fill_rect(btn_x - 4, btn_y - 4, btn_w + 8, btn_h + 8, self.BLACK)
                self.pager.fill_rect(btn_x, btn_y, btn_w, btn_h, color)
                text_w = self.pager.ttf_width(label, self.font_arial, font_size)
                text_x = btn_x + (btn_w - text_w) // 2
                text_y = btn_y + (btn_h - font_size) // 2
                self.pager.draw_ttf(text_x, text_y, label, self.WHITE, self.font_arial, font_size)

            self.pager.flip()

        draw_menu()

        while True:
            button = self.pager.wait_button()
            if button & self.pager.BTN_DOWN:
                current_brightness = max(20, current_brightness - 10)
                self.pager.set_brightness(current_brightness)
                self.screen_brightness = current_brightness
                draw_menu()
            elif button & self.pager.BTN_UP:
                current_brightness = min(100, current_brightness + 10)
                self.pager.set_brightness(current_brightness)
                self.screen_brightness = current_brightness
                draw_menu()
            elif button & self.pager.BTN_LEFT:
                selected = (selected - 1) % num_options
                draw_menu()
            elif button & self.pager.BTN_RIGHT:
                selected = (selected + 1) % num_options
                draw_menu()
            elif button & self.pager.BTN_A:
                self.dialog_showing = False
                action = options[selected][2]
                if action is None:
                    return None
                elif isinstance(action, tuple):
                    self._handoff_launcher_path = action[1]
                    return 42
                else:
                    return action
            elif button & self.pager.BTN_B:
                self.dialog_showing = False
                return None

    # ------------------------------------------------------------------
    # Data update (kept from original)
    # ------------------------------------------------------------------

    def update_vuln_count(self):
        with self.semaphore:
            try:
                if not os.path.exists(self.shared_data.vuln_summary_file):
                    with open(self.shared_data.vuln_summary_file, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                    self.shared_data.vulnnbr = 0
                else:
                    alive_macs = set()
                    if os.path.exists(self.shared_data.netkbfile):
                        with open(self.shared_data.netkbfile, 'r') as file:
                            reader = csv.DictReader(file)
                            for row in reader:
                                if row.get("Alive") == "1" and row.get("MAC Address") != "STANDALONE":
                                    alive_macs.add(row.get("MAC Address"))
                    with open(self.shared_data.vuln_summary_file, 'r') as file:
                        reader = csv.DictReader(file)
                        all_vulnerabilities = set()
                        for row in reader:
                            mac_address = row.get("MAC Address", "")
                            if mac_address in alive_macs and mac_address != "STANDALONE":
                                vulnerabilities = row.get("Vulnerabilities", "")
                                if vulnerabilities and isinstance(vulnerabilities, str):
                                    all_vulnerabilities.update(vulnerabilities.split("; "))
                        self.shared_data.vulnnbr = len(all_vulnerabilities)
            except Exception as e:
                logger.error(f"Error in update_vuln_count: {e}")

    def update_shared_data(self):
        with self.semaphore:
            try:
                # Read stats from SQLite DB (primary source)
                if self.shared_data.db is not None:
                    try:
                        db_stats = self.shared_data.db.get_stats()
                        hosts = self.shared_data.db.get_all_hosts()
                        alive = [h for h in hosts if h.get('status') == 'alive']
                        self.shared_data.targetnbr = len(alive)
                        self.shared_data.networkkbnbr = db_stats.get('total_hosts', 0)
                        self.shared_data.portnbr = sum(
                            len(h['ports'].split(',')) for h in alive if h.get('ports')
                        )
                        self.shared_data.vulnnbr = db_stats.get('hosts_with_vulns', 0)
                    except Exception as e:
                        logger.debug(f"DB stats read failed: {e}")
                elif os.path.exists(self.shared_data.livestatusfile):
                    # Fallback: read from CSV
                    with open(self.shared_data.livestatusfile, 'r') as file:
                        reader = csv.DictReader(file)
                        for row in reader:
                            self.shared_data.portnbr = int(row.get('Total Open Ports', 0) or 0)
                            self.shared_data.targetnbr = int(row.get('Alive Hosts Count', 0) or 0)
                            self.shared_data.networkkbnbr = int(row.get('All Known Hosts Count', 0) or 0)
                            self.shared_data.vulnnbr = int(row.get('Vulnerabilities Count', 0) or 0)
                            break

                crackedpw_files = glob.glob(f"{self.shared_data.crackedpwddir}/*.csv")
                total_passwords = 0
                for filepath in crackedpw_files:
                    try:
                        with open(filepath, 'r') as f:
                            reader = csv.reader(f)
                            next(reader, None)
                            total_passwords += sum(1 for _ in reader)
                    except Exception:
                        pass
                self.shared_data.crednbr = total_passwords

                total_data = sum([len(files) for r, d, files in os.walk(self.shared_data.datastolendir)])
                self.shared_data.datanbr = total_data

                total_zombies = sum([len(files) for r, d, files in os.walk(self.shared_data.zombiesdir)])
                self.shared_data.zombiesnbr = total_zombies

                self.shared_data.update_stats()
                self.shared_data.wifi_connected = self.is_wifi_connected()

            except FileNotFoundError as e:
                logger.debug(f"Data file not ready: {e}")
            except Exception as e:
                logger.error(f"Error updating shared data: {e}")

    def display_comment(self, status):
        comment = self.commentaire_ia.get_commentaire(status)
        if comment:
            self.shared_data.ragnarsays = comment
            self.shared_data.ragnarstatustext = self.shared_data.ragnarorch_status

    def is_wifi_connected(self):
        try:
            result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True, timeout=5)
            return bool(result.stdout.strip())
        except Exception:
            return False

    def update_leds(self, status):
        if status == self.last_led_status:
            return
        self.last_led_status = status
        try:
            if status == "IDLE":
                self.pager.led_dpad("up", 0x000033)
                self.pager.led_dpad("down", 0x000033)
                self.pager.led_dpad("left", 0x000033)
                self.pager.led_dpad("right", 0x000033)
            elif "Scanner" in status or "Scan" in status:
                self.pager.led_dpad("up", 0x00FFFF)
                self.pager.led_dpad("down", 0x003333)
                self.pager.led_dpad("left", 0x003333)
                self.pager.led_dpad("right", 0x00FFFF)
            elif "Bruteforce" in status:
                self.pager.led_dpad("up", 0xFF0000)
                self.pager.led_dpad("down", 0xFF0000)
                self.pager.led_dpad("left", 0x330000)
                self.pager.led_dpad("right", 0x330000)
            elif "Steal" in status:
                self.pager.led_dpad("up", 0xFFFF00)
                self.pager.led_dpad("down", 0x333300)
                self.pager.led_dpad("left", 0xFFFF00)
                self.pager.led_dpad("right", 0x333300)
            else:
                self.pager.led_dpad("up", 0x00FF00)
                self.pager.led_dpad("down", 0x003300)
                self.pager.led_dpad("left", 0x003300)
                self.pager.led_dpad("right", 0x00FF00)
        except Exception as e:
            logger.debug(f"LED update error: {e}")

    # ------------------------------------------------------------------
    # Main render + run loop
    # ------------------------------------------------------------------

    def render_frame(self):
        if self.dialog_showing:
            return
        if self.current_screen == SCREEN_DASHBOARD:
            self.draw_dashboard()
        elif self.current_screen == SCREEN_HOSTS:
            self.draw_hosts()
        elif self.current_screen == SCREEN_CREDS:
            self.draw_credentials()
        elif self.current_screen == SCREEN_VULNS:
            self.draw_vulnerabilities()
        elif self.current_screen == SCREEN_SCAN_SETTINGS:
            self._draw_settings_screen(SCREEN_SCAN_SETTINGS, "SCAN SETTINGS")
        elif self.current_screen == SCREEN_ATTACK_SETTINGS:
            self._draw_settings_screen(SCREEN_ATTACK_SETTINGS, "ATTACK SETTINGS")
        elif self.current_screen == SCREEN_NETWORK_SETTINGS:
            self._draw_settings_screen(SCREEN_NETWORK_SETTINGS, "NETWORK CONFIG")
        elif self.current_screen == SCREEN_SYSTEM_SETTINGS:
            self._draw_settings_screen(SCREEN_SYSTEM_SETTINGS, "SYSTEM CONFIG")
        if not self.dialog_showing:
            self.pager.flip()

    def run(self):
        logger.info("Starting pager display main loop...")
        while not self.shared_data.display_should_exit:
            try:
                if self.dialog_showing:
                    time.sleep(0.1)
                    continue
                self.check_dim_timeout()
                self.display_comment(self.shared_data.ragnarorch_status)
                self.shared_data.update_ragnarstatus()
                self.update_leds(self.shared_data.ragnarorch_status)
                self.render_frame()
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in display loop: {e}")
                time.sleep(0.1)
        logger.info("Pager display loop exiting...")
        self.cleanup()

    def cleanup(self):
        try:
            logger.info("Cleaning up pager display...")
            self.pager.led_all_off()
            self.pager.clear(self.BLACK)
            self.pager.flip()
            self.pager.cleanup()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


def handle_exit_pager_display(signum, frame, display_instance=None, exit_process=True):
    logger.info("Exit signal received...")
    shared_data.display_should_exit = True
    shared_data.should_exit = True
    if display_instance:
        display_instance.cleanup()
    if exit_process:
        sys.exit(0)


if __name__ == "__main__":
    display_instance = None
    try:
        logger.info("Starting Ragnar pager display...")
        display_instance = PagerDisplay(shared_data)
        signal.signal(signal.SIGINT, lambda s, f: handle_exit_pager_display(s, f, display_instance))
        signal.signal(signal.SIGTERM, lambda s, f: handle_exit_pager_display(s, f, display_instance))
        display_instance.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if display_instance:
            display_instance.cleanup()
        sys.exit(1)
