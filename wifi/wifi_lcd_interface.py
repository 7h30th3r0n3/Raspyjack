#!/usr/bin/env python3
"""
RaspyJack WiFi LCD Interface
===========================
LCD-based WiFi management interface for RaspyJack

Features:
- Network scanning and selection
- Profile management (add/edit/delete)
- Connection status display
- Interface selection for tools

Button Layout:
- UP/DOWN: Navigate menus
- LEFT/RIGHT: Change values
- CENTER: Select/Confirm
- KEY1: Quick connect/disconnect
- KEY2: Refresh/Scan
- KEY3: Back/Exit
"""

import sys
import time
import threading
sys.path.append('/root/Raspyjack/')

try:
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    import RPi.GPIO as GPIO
    from wifi_manager import WiFiManager
    LCD_AVAILABLE = True
except Exception as e:
    print(f"LCD not available: {e}")
    LCD_AVAILABLE = False

class WiFiLCDInterface:
    def __init__(self):
        if not LCD_AVAILABLE:
            raise Exception("LCD hardware not available")
        
        self.wifi_manager = WiFiManager()
        
        # LCD setup
        self.LCD = LCD_1in44.LCD()
        self.LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        self.canvas = Image.new("RGB", (self.LCD.width, self.LCD.height), "black")
        self.draw = ImageDraw.Draw(self.canvas)
        self._s = LCD_1in44.LCD_SCALE if hasattr(LCD_1in44, 'LCD_SCALE') else 1.0
        self.font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", int(8 * self._s))
        self.icon_font = ImageFont.truetype("/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf", int(10 * self._s))
        self._row_h = int(12 * self._s)    # row height scaled
        self._hdr_h = int(12 * self._s)    # header height
        self._foot_y = int(100 * self._s)  # footer hint y
        self._stat_y = int(115 * self._s)  # status bar y
        
        # GPIO setup
        GPIO.setmode(GPIO.BCM)
        self.setup_buttons()
        
        # Menu state
        self.current_menu = "main"
        self.menu_index = 0
        self.in_submenu = False
        self.running = True
        
        # Keyboard state
        self.kb_layout = [
            "abcdefghijkl",
            "mnopqrstuvwx",
            "yzABCDEFGHIJ",
            "KLMNOPQRSTUV",
            "WXYZ01234567",
            "89!@#$%^&*()",
            "_+-=[]{}|;':",
            "\",./<>?     "
        ]
        self.kb_text = ""
        self.kb_cursor_x = 0
        self.kb_cursor_y = 0
        self.kb_target_ssid = ""
        
        # Data
        self.scanned_networks = []
        self.saved_profiles = []
        self.refresh_data()
    
    def setup_buttons(self):
        """Setup GPIO buttons."""
        self.buttons = {
            'UP': 6,
            'DOWN': 19, 
            'LEFT': 5,
            'RIGHT': 26,
            'CENTER': 13,
            'KEY1': 21,
            'KEY2': 20,
            'KEY3': 16
        }
        
        for pin in self.buttons.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    
    def refresh_data(self):
        """Refresh networks and profiles."""
        self.wifi_manager.log("Refreshing WiFi data...")
        self.scanned_networks = self.wifi_manager.scan_networks()
        self.saved_profiles = self.wifi_manager.load_profiles()
    
    def draw_header(self, title):
        """Draw menu header."""
        self.canvas.paste(Image.new("RGB", (self.LCD.width, self.LCD.height), "black"))
        self.draw.text((2, 0), title[:18], fill="yellow", font=self.font)
        self.draw.line([(0, self._hdr_h), (self.LCD.width, self._hdr_h)], fill="blue", width=1)
    
    def draw_status_bar(self):
        """Draw connection status at bottom."""
        status = self.wifi_manager.get_connection_status()
        if status["status"] == "connected":
            status_text = f"~ {status['ssid'][:12]}"
            color = "green"
        else:
            status_text = "~ Disconnected"
            color = "red"
        
        self.draw.text((2, self._stat_y), status_text, fill=color, font=self.font)
    
    def draw_main_menu(self):
        """Draw main WiFi menu."""
        self.draw_header("WiFi Manager")
        
        menu_icons = ["\uf002", "\uf0c7", "\uf0e8", "\uf085", "\uf05a", "\uf2f5"]
        menu_labels = [
            "Scan Networks",
            "Saved Profiles",
            "Quick Connect",
            "Interface Config",
            "Status & Info",
            "Exit"
        ]

        y_pos = int(18 * self._s)
        for i, label in enumerate(menu_labels):
            if i == self.menu_index:
                self.draw.rectangle([(0, y_pos-2), (self.LCD.width, y_pos+self._row_h-2)], fill="blue")
                color = "white"
            else:
                color = "white"
            
            self.draw.text((4, y_pos), menu_icons[i], fill=color, font=self.icon_font)
            self.draw.text((18, y_pos), label[:14], fill=color, font=self.font)
            y_pos += self._row_h

        # Button hints
        self.draw.text((2, self._foot_y), "U/D Nav  OK Select", fill="cyan", font=self.font)
        self.draw_status_bar()
    
    def draw_network_scan(self):
        """Draw scanned networks list."""
        self.draw_header("Available Networks")
        
        if not self.scanned_networks:
            self.draw.text((4, int(25 * self._s)), "No networks found", fill="red", font=self.font)
            self.draw.text((4, int(40 * self._s)), "KEY2: Scan again", fill="cyan", font=self.font)
        else:
            y_pos = int(18 * self._s)
            display_count = min(6, len(self.scanned_networks))
            start_idx = max(0, self.menu_index - 2)
            
            for i in range(start_idx, min(start_idx + display_count, len(self.scanned_networks))):
                network = self.scanned_networks[i]
                ssid = network.get('ssid', 'Unknown')[:12]
                
                if i == self.menu_index:
                    self.draw.rectangle([(0, y_pos-2), (self.LCD.width, y_pos+self._row_h-2)], fill="blue")
                    color = "white"
                else:
                    color = "white"
                
                # Show encryption status
                encrypted = "[L]" if network.get('encrypted', False) else "[O]"
                self.draw.text((4, y_pos), f"{encrypted} {ssid}", fill=color, font=self.font)
                y_pos += self._row_h
        
        self.draw.text((2, self._foot_y), "OK Connect  KEY3: Back", fill="cyan", font=self.font)
        self.draw_status_bar()
    
    def draw_saved_profiles(self):
        """Draw saved WiFi profiles."""
        self.draw_header("Saved Profiles")
        
        if not self.saved_profiles:
            self.draw.text((4, int(25 * self._s)), "No saved profiles", fill="red", font=self.font)
            self.draw.text((4, int(40 * self._s)), "Scan & save networks", fill="cyan", font=self.font)
        else:
            y_pos = int(18 * self._s)
            display_count = min(6, len(self.saved_profiles))
            start_idx = max(0, min(self.menu_index, len(self.saved_profiles) - display_count))
            
            for i in range(start_idx, start_idx + display_count):
                if i >= len(self.saved_profiles):
                    break
                profile = self.saved_profiles[i]
                ssid = profile.get('ssid', 'Unknown')[:12]
                priority = profile.get('priority', 1)
                
                if i == self.menu_index:
                    self.draw.rectangle([(0, y_pos-2), (self.LCD.width, y_pos+self._row_h-2)], fill="blue")
                    color = "white"
                else:
                    color = "white"
                
                self.draw.text((4, y_pos), f"📁 {ssid} ({priority})", fill=color, font=self.font)
                y_pos += self._row_h
        
        self.draw.text((2, self._foot_y), "OK Con  K2: Del  K3: Back", fill="cyan", font=self.font)
        self.draw_status_bar()
    
    def draw_interface_config(self):
        """Draw interface configuration."""
        self.draw_header("Interface Config")
        
        interfaces = ["eth0"] + self.wifi_manager.wifi_interfaces
        current_interface = self.wifi_manager.get_interface_for_tool()
        
        y_pos = int(18 * self._s)
        self.draw.text((4, y_pos), "Default Interface:", fill="yellow", font=self.font)
        y_pos += int(15 * self._s)
        
        for i, interface in enumerate(interfaces):
            if i == self.menu_index:
                self.draw.rectangle([(0, y_pos-2), (self.LCD.width, y_pos+self._row_h-2)], fill="blue")
                color = "white"
            else:
                color = "white"
            
            # Show current selection
            marker = "●" if interface == current_interface else "○"
            self.draw.text((4, y_pos), f"{marker} {interface}", fill=color, font=self.font)
            y_pos += self._row_h
        
        self.draw.text((2, self._foot_y), "OK Select  KEY3: Back", fill="cyan", font=self.font)
        self.draw_status_bar()
    
    def draw_status_info(self):
        """Draw detailed status information."""
        self.draw_header("Status & Info")
        
        status = self.wifi_manager.get_connection_status()
        
        y_pos = int(18 * self._s)
        
        # WiFi Status
        if status["status"] == "connected":
            self.draw.text((4, y_pos), f"WiFi: {status['ssid']}", fill="green", font=self.font)
            y_pos += self._row_h
            self.draw.text((4, y_pos), f"IP: {status['ip']}", fill="green", font=self.font)
            y_pos += self._row_h
            self.draw.text((4, y_pos), f"IF: {status['interface']}", fill="green", font=self.font)
        else:
            self.draw.text((4, y_pos), "WiFi: Disconnected", fill="red", font=self.font)
            y_pos += self._row_h
        
        y_pos += int(5 * self._s)

        # Interface info
        self.draw.text((4, y_pos), f"WiFi dongles: {len(self.wifi_manager.wifi_interfaces)}", fill="white", font=self.font)
        y_pos += self._row_h

        if self.wifi_manager.wifi_interfaces:
            for iface in self.wifi_manager.wifi_interfaces:
                self.draw.text((4, y_pos), f"  {iface}", fill="cyan", font=self.font)
                y_pos += self._row_h

        self.draw.text((2, self._stat_y), "KEY3: Back", fill="cyan", font=self.font)

    def draw_keyboard(self):
        """Draw the on-screen keyboard for password entry."""
        self.draw_header(f"PW: {self.kb_target_ssid[:12]}")
        
        # Draw current text
        display_text = self.kb_text
        if len(display_text) > 18:
            display_text = "..." + display_text[-15:]
        self.draw.text((4, int(16 * self._s)), f"> {display_text}_", fill="green", font=self.font)

        # Draw grid
        start_y = int(30 * self._s)
        cell_w = int(10 * self._s)
        cell_h = int(10 * self._s)
        
        for r, row in enumerate(self.kb_layout):
            for c, char in enumerate(row):
                x = 4 + c * cell_w
                y = start_y + r * cell_h
                
                if r == self.kb_cursor_y and c == self.kb_cursor_x:
                    self.draw.rectangle([(x-1, y-1), (x+cell_w-2, y+cell_h-1)], fill="blue")
                    txt_color = "white"
                else:
                    txt_color = "white"
                    
                display_char = char
                if char == ' ':
                    display_char = '_'
                self.draw.text((x, y), display_char, fill=txt_color, font=self.font)
        
        self.draw.text((2, 115), "K1:Del K2:OK K3:Back", fill="cyan", font=self.font)
    
    def handle_main_menu(self, button):
        """Handle main menu button presses."""
        if button == "UP":
            self.menu_index = (self.menu_index - 1) % 6
        elif button == "DOWN":
            self.menu_index = (self.menu_index + 1) % 6
        elif button == "CENTER":
            if self.menu_index == 0:  # Scan Networks
                self.current_menu = "scan"
                self.menu_index = 0
                self.refresh_data()
            elif self.menu_index == 1:  # Saved Profiles
                self.current_menu = "profiles"
                self.menu_index = 0
            elif self.menu_index == 2:  # Quick Connect
                self.quick_connect()
            elif self.menu_index == 3:  # Interface Config
                self.current_menu = "interface"
                self.menu_index = 0
            elif self.menu_index == 4:  # Status
                self.current_menu = "status"
            elif self.menu_index == 5:  # Exit
                self.running = False
    
    def handle_scan_menu(self, button):
        """Handle network scan menu."""
        if button == "UP" and self.scanned_networks:
            self.menu_index = (self.menu_index - 1) % len(self.scanned_networks)
        elif button == "DOWN" and self.scanned_networks:
            self.menu_index = (self.menu_index + 1) % len(self.scanned_networks)
        elif button == "CENTER" and self.scanned_networks:
            self.connect_to_scanned_network()
        elif button == "KEY2":
            self.refresh_data()
        elif button == "KEY3":
            self.current_menu = "main"
            self.menu_index = 0
    
    def handle_profiles_menu(self, button):
        """Handle saved profiles menu."""
        if not self.saved_profiles:
            if button == "KEY3":
                self.current_menu = "main"
                self.menu_index = 0
            return
            
        if button == "UP":
            self.menu_index = (self.menu_index - 1) % len(self.saved_profiles)
        elif button == "DOWN":
            self.menu_index = (self.menu_index + 1) % len(self.saved_profiles)
        elif button == "CENTER":
            self.connect_to_saved_profile()
        elif button == "KEY2":
            self.delete_profile()
        elif button == "KEY3":
            self.current_menu = "main"
            self.menu_index = 0
    
    def handle_interface_menu(self, button):
        """Handle interface configuration menu."""
        interfaces = ["eth0"] + self.wifi_manager.wifi_interfaces
        
        if button == "UP":
            self.menu_index = (self.menu_index - 1) % len(interfaces)
        elif button == "DOWN":
            self.menu_index = (self.menu_index + 1) % len(interfaces)
        elif button == "CENTER":
            selected_interface = interfaces[self.menu_index]
            # Here you would save the interface preference
            self.show_message(f"Selected: {selected_interface}")
        elif button == "KEY3":
            self.current_menu = "main"
            self.menu_index = 0
            
    def handle_keyboard_menu(self, button):
        """Handle keyboard input."""
        if button == "UP":
            self.kb_cursor_y = (self.kb_cursor_y - 1) % len(self.kb_layout)
        elif button == "DOWN":
            self.kb_cursor_y = (self.kb_cursor_y + 1) % len(self.kb_layout)
        elif button == "LEFT":
            self.kb_cursor_x = (self.kb_cursor_x - 1) % len(self.kb_layout[0])
        elif button == "RIGHT":
            self.kb_cursor_x = (self.kb_cursor_x + 1) % len(self.kb_layout[0])
        elif button == "CENTER":
            char = self.kb_layout[self.kb_cursor_y][self.kb_cursor_x]
            if char == ' ':
                self.kb_text += ' '
            else:
                self.kb_text += char
        elif button == "KEY1":  # Backspace
            if len(self.kb_text) > 0:
                self.kb_text = self.kb_text[:-1]
        elif button == "KEY2":  # Submit
            self.show_message(f"Connecting...")
            success = self.wifi_manager.connect_to_network(self.kb_target_ssid, self.kb_text)
            if success:
                self.show_message("Connected!")
                self.wifi_manager.save_profile(self.kb_target_ssid, self.kb_text, "auto", 1, True)
                self.current_menu = "main"
                self.menu_index = 0
            else:
                self.show_message("Connection failed")
        elif button == "KEY3":  # Cancel
            self.current_menu = "scan"
    
    def quick_connect(self):
        """Quick connect to best available network."""
        self.show_message("Connecting...")
        success = self.wifi_manager.auto_connect()
        if success:
            self.show_message("Connected!")
        else:
            self.show_message("Connection failed")
    
    def connect_to_scanned_network(self):
        """Connect to selected scanned network."""
        if self.menu_index < len(self.scanned_networks):
            network = self.scanned_networks[self.menu_index]
            ssid = network.get('ssid')
            
            if network.get('encrypted', False):
                # Switch to keyboard mode for password input
                self.kb_target_ssid = ssid
                self.kb_text = ""
                self.kb_cursor_x = 0
                self.kb_cursor_y = 0
                self.current_menu = "keyboard"
                return
            
            self.show_message(f"Connecting to {ssid}...")
            success = self.wifi_manager.connect_to_network(ssid)
            
            if success:
                self.show_message("Connected!")
                # Auto-save successful connections
                self.wifi_manager.save_profile(ssid, "", "auto", 1, True)
            else:
                self.show_message("Connection failed")
    
    def connect_to_saved_profile(self):
        """Connect to selected saved profile."""
        if self.menu_index < len(self.saved_profiles):
            profile = self.saved_profiles[self.menu_index]
            ssid = profile.get('ssid')
            
            self.show_message(f"Connecting to {ssid}...")
            success = self.wifi_manager.connect_to_profile(profile)
            
            if success:
                self.show_message("Connected!")
            else:
                self.show_message("Connection failed")
    
    def delete_profile(self):
        """Delete selected profile."""
        if self.menu_index < len(self.saved_profiles):
            profile = self.saved_profiles[self.menu_index]
            ssid = profile.get('ssid')
            
            success = self.wifi_manager.delete_profile(ssid)
            if success:
                self.show_message(f"Deleted {ssid}")
                self.saved_profiles = self.wifi_manager.load_profiles()
                if self.menu_index >= len(self.saved_profiles):
                    self.menu_index = max(0, len(self.saved_profiles) - 1)
            else:
                self.show_message("Delete failed")
    
    def show_message(self, message, duration=2):
        """Show a temporary message."""
        self.canvas.paste(Image.new("RGB", (self.LCD.width, self.LCD.height), "black"))
        self.draw.text((4, int(50 * self._s)), message[:16], fill="yellow", font=self.font)
        self.LCD.LCD_ShowImage(self.canvas, 0, 0)
        time.sleep(duration)
    
    def check_buttons(self):
        """Check for button presses with non-blocking debouncing."""
        if not hasattr(self, '_last_pressed'):
            self._last_pressed = {}
            self._button_states = {name: 1 for name in self.buttons.keys()}
            
        current_time = time.time()
        for name, pin in self.buttons.items():
            current_state = GPIO.input(pin)
            
            # Detect falling edge (1 -> 0)
            if self._button_states[name] == 1 and current_state == 0:
                # Basic debounce (ignore if pressed in last 150ms)
                if current_time - self._last_pressed.get(name, 0) > 0.15:
                    self._last_pressed[name] = current_time
                    self._button_states[name] = current_state
                    return name
            
            self._button_states[name] = current_state
            
        return None
    
    def update_display(self):
        """Update the LCD display based on current menu."""
        if self.current_menu == "main":
            self.draw_main_menu()
        elif self.current_menu == "scan":
            self.draw_network_scan()
        elif self.current_menu == "profiles":
            self.draw_saved_profiles()
        elif self.current_menu == "interface":
            self.draw_interface_config()
        elif self.current_menu == "status":
            self.draw_status_info()
        elif self.current_menu == "keyboard":
            self.draw_keyboard()
        
        self.LCD.LCD_ShowImage(self.canvas, 0, 0)
    
    def run(self):
        """Main interface loop."""
        self.wifi_manager.log("Starting WiFi LCD interface")
        
        # Force initial display update
        self.update_display()
        last_update = time.time()
        
        try:
            while self.running:
                # Update display periodically if no buttons pressed (e.g. for status changes)
                # But don't do it every single tight loop iteration
                if time.time() - last_update > 2.0:
                    self.update_display()
                    last_update = time.time()
                
                button = self.check_buttons()
                if button:
                    if self.current_menu == "main":
                        self.handle_main_menu(button)
                    elif self.current_menu == "scan":
                        self.handle_scan_menu(button)
                    elif self.current_menu == "profiles":
                        self.handle_profiles_menu(button)
                    elif self.current_menu == "interface":
                        self.handle_interface_menu(button)
                    elif self.current_menu == "keyboard":
                        self.handle_keyboard_menu(button)
                    elif self.current_menu == "status":
                        if button == "KEY3":
                            self.current_menu = "main"
                            self.menu_index = 0
                            
                    # Update display immediately after a button press
                    self.update_display()
                    last_update = time.time()
                
                # Tiny sleep to prevent 100% CPU usage, but fast enough for snappy input
                time.sleep(0.01)
                
        except KeyboardInterrupt:
            pass
        finally:
            self.wifi_manager.log("WiFi LCD interface stopped")
            GPIO.cleanup()

def main():
    """Run the WiFi LCD interface."""
    try:
        interface = WiFiLCDInterface()
        interface.run()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main() 