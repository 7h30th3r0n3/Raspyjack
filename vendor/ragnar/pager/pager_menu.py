"""
Graphical startup menu for Ragnar on WiFi Pineapple Pager.
Uses libpagerctl.so for fast native rendering in landscape mode (270, 480x222).
Adapted from pineapple_pager_bjorn's bjorn_menu.py for Ragnar branding.
"""

import os
import sys
import subprocess
import time
import json
import traceback

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

# Add lib directory to Python path
_lib_path = os.path.join(PAYLOAD_DIR, 'lib')
if os.path.exists(_lib_path) and _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# Font paths
FONTS_DIR = os.path.join(PAYLOAD_DIR, 'resources', 'fonts')
FONT_VIKING = os.path.join(FONTS_DIR, 'Viking.TTF')
FONT_DEJAVU = os.path.join(FONTS_DIR, 'DejaVuSansMono.ttf')
# Fallback to Arial if DejaVu not available
if not os.path.exists(FONT_DEJAVU):
    FONT_DEJAVU = os.path.join(FONTS_DIR, 'Arial.ttf')

# TTF font sizes (tuned for 480x222 Pager LCD)
TTF_SMALL = 13.0
TTF_MEDIUM = 16.0
TTF_LARGE = 20.0

# Loot directory paths (use Ragnar data dir structure)
DATA_DIR = os.path.join(PAYLOAD_DIR, "data")
LOGS_DIR = os.path.join(DATA_DIR, "logs")
CREDS_DIR = os.path.join(DATA_DIR, "output", "crackedpwd")
STOLEN_DIR = os.path.join(DATA_DIR, "output", "data_stolen")

# Try to import pagerctl with error handling
try:
    from pagerctl import Pager
except Exception as e:
    # Log the error to a file since we can't use the display yet
    error_log = os.path.join(PAYLOAD_DIR, 'pagerctl_error.log')
    with open(error_log, 'w') as f:
        f.write(f"Failed to import pagerctl: {e}\n")
        f.write(f"PAYLOAD_DIR: {PAYLOAD_DIR}\n")
        f.write(f"libpagerctl.so exists: {os.path.exists(os.path.join(PAYLOAD_DIR, 'libpagerctl.so'))}\n")
        f.write(f"pagerctl.py exists: {os.path.exists(os.path.join(PAYLOAD_DIR, 'pagerctl.py'))}\n")
        f.write(f"sys.path: {sys.path}\n")
        f.write(f"Traceback:\n")
        traceback.print_exc(file=f)
    print(f"ERROR: Failed to import pagerctl: {e}")
    print(f"See {error_log} for details")
    sys.exit(1)

# Theme colors
TITLE_COLOR = Pager.rgb(100, 200, 255)
SELECTED_COLOR = Pager.GREEN
UNSELECTED_COLOR = Pager.WHITE
ON_COLOR = Pager.GREEN
OFF_COLOR = Pager.RED
DIM_COLOR = Pager.GRAY
WARNING_COLOR = Pager.rgb(255, 100, 0)
SUBMENU_COLOR = Pager.YELLOW


def detect_interfaces():
    """Detect network interfaces with IP addresses."""
    interfaces = []

    try:
        if sys.platform == 'win32':
            # Windows: use ipconfig parsing
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            current_iface = None
            for line in result.stdout.split('\n'):
                line = line.rstrip()
                if line and not line[0].isspace() and ':' in line:
                    current_iface = line.split(':')[0].strip()
                    # Clean up adapter name
                    for prefix in ['Ethernet adapter ', 'Wireless LAN adapter ',
                                   'Ethernet-kort ', 'Tr\xe5dl\xf6st n\xe4tverkskort ']:
                        if current_iface.startswith(prefix):
                            current_iface = current_iface[len(prefix):]
                elif current_iface and ('IPv4' in line or 'IPv4' in line.replace('v', 'v')):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        if ip and ip != '127.0.0.1' and not ip.startswith('169.254'):
                            interfaces.append({
                                'name': current_iface,
                                'ip': ip,
                                'subnet': ip + '/24',
                            })
                            current_iface = None
        else:
            # Linux: use ip addr
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
            current_iface = None
            for line in result.stdout.split('\n'):
                if line and not line[0].isspace() and ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        current_iface = parts[1].strip()
                elif 'inet ' in line and current_iface:
                    parts = line.strip().split()
                    for i, p in enumerate(parts):
                        if p == 'inet' and i + 1 < len(parts):
                            cidr = parts[i + 1]
                            ip = cidr.split('/')[0]
                            if ip != '127.0.0.1':
                                interfaces.append({
                                    'name': current_iface,
                                    'ip': ip,
                                    'subnet': cidr,
                                })
                            break
    except Exception:
        pass
    return interfaces


class RagnarMenu:
    """Graphical startup menu for Ragnar on the Pager LCD."""

    def __init__(self, interfaces):
        self.interfaces = interfaces
        self.scan_prefix = 24
        try:
            config_path = os.path.join(PAYLOAD_DIR, 'config', 'shared_config.json')
            with open(config_path, 'r') as f:
                cfg = json.load(f)
            self.scan_prefix = cfg.get('scan_network_prefix', 24)
        except Exception:
            pass
        self.gfx = Pager()
        self.gfx.init()
        self.gfx.set_rotation(270)  # Landscape 480x222
        self.gfx.clear_input_events()  # Flush stale events from service takeover

    def cleanup(self):
        if hasattr(self, 'gfx'):
            try:
                # Clear screen to black before releasing hardware so the
                # display doesn't freeze on the last drawn frame while
                # pineapplepager is restarting.
                self.gfx.clear(Pager.BLACK)
                self.gfx.flip()
            except Exception:
                pass
            try:
                self.gfx.cleanup()
            except Exception:
                pass

    def _adjust_brightness(self, direction):
        """Adjust screen brightness. direction: +1 or -1."""
        cur = self.gfx.get_brightness()
        max_br = self.gfx.get_max_brightness()
        new = max(1, min(max_br, cur + direction))
        if new != cur:
            self.gfx.set_brightness(new)

    def _wait_button(self):
        """Wait for a button press using thread-safe event queue.
        LEFT/RIGHT adjust brightness and are not returned to callers."""
        while True:
            event = self.gfx.get_input_event()
            if event:
                button, event_type, timestamp = event
                if event_type == Pager.EVENT_PRESS:
                    if button == Pager.BTN_LEFT:
                        self._adjust_brightness(-1)
                        continue
                    if button == Pager.BTN_RIGHT:
                        self._adjust_brightness(1)
                        continue
                    if button == Pager.BTN_UP:
                        return 'UP'
                    if button == Pager.BTN_DOWN:
                        return 'DOWN'
                    if button == Pager.BTN_A:
                        return 'SELECT'
                    if button == Pager.BTN_B:
                        return 'BACK'
            else:
                time.sleep(0.016)

    def _draw_main_menu(self, selected, iface_idx, web_ui):
        self.gfx.clear(Pager.BLACK)

        # Title using Viking font
        self.gfx.draw_ttf_centered(2, "Ragnar", TITLE_COLOR, FONT_VIKING, 38.0)

        y = 50
        items = self._get_menu_items(iface_idx, web_ui)

        for i, item in enumerate(items):
            is_selected = (i == selected)

            if item.get('toggle'):
                label = item['label']
                value = item['value']
                value_color = item['value_color']
                label_color = SELECTED_COLOR if is_selected else UNSELECTED_COLOR

                max_value = item.get('max_value', value)
                label_width = self.gfx.ttf_width(label, FONT_DEJAVU, TTF_MEDIUM)
                max_value_width = self.gfx.ttf_width(max_value, FONT_DEJAVU, TTF_MEDIUM)
                total_width = label_width + 8 + max_value_width
                start_x = max(2, (480 - total_width) // 2)
                self.gfx.draw_ttf(start_x, y, label, label_color, FONT_DEJAVU, TTF_MEDIUM)
                self.gfx.draw_ttf(start_x + label_width + 8, y, value, value_color, FONT_DEJAVU, TTF_MEDIUM)
            else:
                color = SELECTED_COLOR if is_selected else UNSELECTED_COLOR
                self.gfx.draw_ttf_centered(y, item['label'], color, FONT_DEJAVU, TTF_MEDIUM)

            y += 22

        self.gfx.flip()

    def _get_menu_items(self, iface_idx, web_ui):
        items = [{'label': 'Start Ragnar'}]

        if self.interfaces:
            iface = self.interfaces[iface_idx]
            iface_text = f"{iface['name']} ({iface['ip']}/{self.scan_prefix})"
            # Truncate long interface text to fit 480px display
            if len(iface_text) > 28:
                iface_text = iface_text[:27] + '\u2026'
        else:
            iface_text = "none"

        items.append({
            'toggle': True,
            'label': 'Interface:',
            'value': iface_text,
            'value_color': UNSELECTED_COLOR,
            'max_value': iface_text,
        })

        items.append({
            'toggle': True,
            'label': 'Web UI:',
            'value': 'ON :8000' if web_ui else 'OFF',
            'value_color': ON_COLOR if web_ui else OFF_COLOR,
            'max_value': 'ON :8000',
        })

        items.append({'label': 'Clear Data'})
        items.append({'label': 'Exit'})
        return items

    def show_main_menu(self):
        """Show the main menu. Returns config dict or None to exit."""
        selected = 0
        iface_idx = 0
        web_ui = True
        num_options = 5

        self._draw_main_menu(selected, iface_idx, web_ui)

        while True:
            btn = self._wait_button()

            if btn == 'UP':
                selected = (selected - 1) % num_options
                self._draw_main_menu(selected, iface_idx, web_ui)
            elif btn == 'DOWN':
                selected = (selected + 1) % num_options
                self._draw_main_menu(selected, iface_idx, web_ui)
            elif btn == 'SELECT':
                if selected == 0:
                    if not self.interfaces:
                        self._show_message("No network!", WARNING_COLOR, "Connect to a network first", DIM_COLOR)
                        self._wait_button()
                        self._draw_main_menu(selected, iface_idx, web_ui)
                        continue
                    iface = self.interfaces[iface_idx]
                    return {
                        'interface': iface['name'],
                        'ip': iface['ip'],
                        'web_ui': web_ui,
                    }
                elif selected == 1 and self.interfaces:
                    iface_idx = (iface_idx + 1) % len(self.interfaces)
                    self._draw_main_menu(selected, iface_idx, web_ui)
                elif selected == 2:
                    web_ui = not web_ui
                    self._draw_main_menu(selected, iface_idx, web_ui)
                elif selected == 3:
                    self._show_clear_data_menu()
                    self._draw_main_menu(selected, iface_idx, web_ui)
                elif selected == 4:
                    return None
            elif btn == 'BACK':
                return None

    def _show_message(self, text, color, subtext=None, subcolor=None):
        self.gfx.clear(Pager.BLACK)
        self.gfx.draw_ttf_centered(80, text, color, FONT_DEJAVU, TTF_LARGE)
        if subtext and subcolor:
            self.gfx.draw_ttf_centered(115, subtext, subcolor, FONT_DEJAVU, TTF_SMALL)
        self.gfx.flip()

    def _show_clear_data_menu(self):
        selected = 0
        options = ['Clear Logs', 'Clear Credentials', 'Clear Stolen Data', 'Clear All', 'Back']

        while True:
            self.gfx.clear(Pager.BLACK)
            self.gfx.draw_ttf_centered(10, "CLEAR DATA", SUBMENU_COLOR, FONT_DEJAVU, TTF_LARGE)

            y = 42
            for i, opt in enumerate(options):
                color = SELECTED_COLOR if i == selected else UNSELECTED_COLOR
                self.gfx.draw_ttf_centered(y, opt, color, FONT_DEJAVU, TTF_MEDIUM)
                y += 24

            self.gfx.flip()

            btn = self._wait_button()
            if btn == 'UP':
                selected = (selected - 1) % len(options)
            elif btn == 'DOWN':
                selected = (selected + 1) % len(options)
            elif btn == 'SELECT':
                if selected == 4:
                    return
                if selected == 0:
                    if self._confirm("Clear Logs?"):
                        self._clear_logs()
                elif selected == 1:
                    if self._confirm("Clear Credentials?"):
                        self._clear_credentials()
                elif selected == 2:
                    if self._confirm("Clear Stolen Data?"):
                        self._clear_stolen()
                elif selected == 3:
                    if self._confirm("Clear ALL Data?"):
                        self._clear_all()
            elif btn == 'BACK':
                return

    def _confirm(self, prompt):
        selected = 1  # Default NO

        while True:
            self.gfx.clear(Pager.BLACK)
            self.gfx.draw_ttf_centered(60, prompt, WARNING_COLOR, FONT_DEJAVU, TTF_LARGE)

            center = 480 // 2
            yes_color = SELECTED_COLOR if selected == 0 else UNSELECTED_COLOR
            no_color = SELECTED_COLOR if selected == 1 else UNSELECTED_COLOR
            self.gfx.draw_ttf(center - 85, 115, "YES", yes_color, FONT_DEJAVU, TTF_MEDIUM)
            self.gfx.draw_ttf(center + 45, 115, "NO", no_color, FONT_DEJAVU, TTF_MEDIUM)
            self.gfx.flip()

            btn = self._wait_button()
            if btn in ['UP', 'DOWN']:
                selected = 1 - selected
            elif btn == 'SELECT':
                return selected == 0
            elif btn == 'BACK':
                return False

    def _clear_logs(self):
        try:
            subprocess.run(['rm', '-rf', LOGS_DIR], timeout=5)
            os.makedirs(LOGS_DIR, exist_ok=True)
        except Exception:
            pass
        self._show_message("Logs Cleared!", ON_COLOR)
        time.sleep(0.5)

    def _clear_credentials(self):
        try:
            for f in os.listdir(CREDS_DIR):
                if f.endswith('.csv'):
                    os.remove(os.path.join(CREDS_DIR, f))
        except Exception:
            pass
        self._show_message("Credentials Cleared!", ON_COLOR)
        time.sleep(0.5)

    def _clear_stolen(self):
        try:
            subprocess.run(['rm', '-rf', STOLEN_DIR], timeout=5)
            os.makedirs(STOLEN_DIR, exist_ok=True)
        except Exception:
            pass
        self._show_message("Stolen Data Cleared!", ON_COLOR)
        time.sleep(0.5)

    def _clear_all(self):
        try:
            subprocess.run(['rm', '-rf', LOGS_DIR], timeout=5)
            os.makedirs(LOGS_DIR, exist_ok=True)
        except Exception:
            pass
        try:
            for f in os.listdir(CREDS_DIR):
                if f.endswith('.csv'):
                    os.remove(os.path.join(CREDS_DIR, f))
        except Exception:
            pass
        try:
            subprocess.run(['rm', '-rf', STOLEN_DIR], timeout=5)
            os.makedirs(STOLEN_DIR, exist_ok=True)
        except Exception:
            pass
        for name in ['netkb.csv', 'livestatus.csv']:
            try:
                path = os.path.join(DATA_DIR, name)
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
        for subdir in ['output/scan_results', 'output/vulnerabilities', 'output/zombies']:
            try:
                path = os.path.join(DATA_DIR, subdir)
                subprocess.run(['rm', '-rf', path], timeout=5)
                os.makedirs(path, exist_ok=True)
            except Exception:
                pass
        self._show_message("All Data Cleared!", ON_COLOR)
        time.sleep(0.5)


def main():
    """Main entry point: menu loop -> launch Ragnar -> repeat."""
    menu = None
    log_file = os.path.join(DATA_DIR, 'payload.log')
    try:
        while True:
            interfaces = detect_interfaces()
            time.sleep(0.3)

            try:
                menu = RagnarMenu(interfaces)
            except Exception as e:
                time.sleep(1)
                try:
                    menu = RagnarMenu(interfaces)
                except Exception:
                    sys.stderr.write(f"Failed to init display: {e}\n")
                    break

            result = menu.show_main_menu()

            if result is None:
                menu.cleanup()
                menu = None
                # Brief delay lets the hardware fully settle before
                # pineapplepager service restarts and re-claims the display.
                time.sleep(0.5)
                break

            menu._show_message("Starting Ragnar...", TITLE_COLOR, result['interface'] + " " + result['ip'], DIM_COLOR)
            menu.cleanup()
            menu = None

            # Small delay to let the display hardware settle after cleanup
            time.sleep(0.3)

            # Launch PagerRagnar as subprocess
            env = os.environ.copy()
            env['RAGNAR_INTERFACE'] = result['interface']
            env['RAGNAR_IP'] = result['ip']
            env['RAGNAR_WEB_UI'] = 'on' if result['web_ui'] else 'off'

            # Open log for capturing subprocess output
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                with open(log_file, 'a') as lf:
                    lf.write(f"\n=== PagerRagnar.py starting at {time.strftime('%H:%M:%S')} ===\n")
                    proc = subprocess.run(
                        ['python3', 'PagerRagnar.py'],
                        cwd=PAYLOAD_DIR,
                        env=env,
                        stdout=lf,
                        stderr=lf,
                    )
            except Exception as e:
                sys.stderr.write(f"Failed to launch PagerRagnar.py: {e}\n")
                break

            if proc.returncode == 42:
                sys.exit(42)
            elif proc.returncode == 99:
                continue
            elif proc.returncode != 0:
                sys.stderr.write(f"PagerRagnar.py exited with code {proc.returncode}\n")
                break

            break
    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.stderr.write(f"Menu error: {e}\n")
        traceback.print_exc(file=sys.stderr)
    finally:
        if menu:
            menu.cleanup()


if __name__ == "__main__":
    main()
    # Explicit sys.exit prevents Python's GC from triggering any further
    # calls into libpagerctl.so after we've already called pager_cleanup().
    sys.exit(0)
