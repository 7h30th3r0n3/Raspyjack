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
        self.canvas = Image.new("RGB", (128, 128), "black")
        self.draw = ImageDraw.Draw(self.canvas)
        self.font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 8)
        
        # GPIO setup
        GPIO.setmode(GPIO.BCM)
        self.setup_buttons()
        
        # Menu state
        self.current_menu = "main"
        self.menu_index = 0
        self.in_submenu = False
        self.running = True
        
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
        self.canvas.paste(Image.new("RGB", (128, 128), "black"))
        self.draw.text((2, 0), title[:18], fill="yellow", font=self.font)
        self.draw.line([(0, 12), (128, 12)], fill="blue", width=1)
    
    def draw_status_bar(self):
        """Draw connection status at bottom."""
        status = self.wifi_manager.get_connection_status()
        if status["status"] == "connected":
            status_text = f"📶 {status['ssid'][:12]}"
            color = "green"
        else:
            status_text = "📶 Disconnected"
            color = "red"
        
        self.draw.text((2, 115), status_text, fill=color, font=self.font)
    
    def draw_main_menu(self):
        """Draw main WiFi menu."""
        self.draw_header("WiFi Manager")
        
        menu_items = [
            "📡 Scan Networks",
            "💾 Saved Profiles", 
            "🔗 Quick Connect",
            "⚙️  Interface Config",
            "📊 Status & Info",
            "🚪 Exit"
        ]
        
        y_pos = 18
        for i, item in enumerate(menu_items):
            if i == self.menu_index:
                self.draw.rectangle([(0, y_pos-2), (128, y_pos+10)], fill="blue")
                color = "white"
            else:
                color = "white"
            
            self.draw.text((4, y_pos), item[:16], fill=color, font=self.font)
            y_pos += 12
        
        # Button hints
        self.draw.text((2, 100), "↕️ Navigate  ⭕ Select", fill="cyan", font=self.font)
        self.draw_status_bar()
    
    def draw_network_scan(self):
        """Draw scanned networks list."""
        self.draw_header("Available Networks")
        
        if not self.scanned_networks:
            self.draw.text((4, 25), "No networks found", fill="red", font=self.font)
            self.draw.text((4, 40), "KEY2: Scan again", fill="cyan", font=self.font)
        else:
            y_pos = 18
            display_count = min(6, len(self.scanned_networks))
            start_idx = max(0, self.menu_index - 2)
            
            for i in range(start_idx, min(start_idx + display_count, len(self.scanned_networks))):
                network = self.scanned_networks[i]
                ssid = network.get('ssid', 'Unknown')[:12]
                
                if i == self.menu_index:
                    self.draw.rectangle([(0, y_pos-2), (128, y_pos+10)], fill="blue")
                    color = "white"
                else:
                    color = "white"
                
                # Show encryption status
                encrypted = "🔒" if network.get('encrypted', False) else "🔓"
                self.draw.text((4, y_pos), f"{encrypted} {ssid}", fill=color, font=self.font)
                y_pos += 12
        
        self.draw.text((2, 100), "⭕ Connect  KEY3: Back", fill="cyan", font=self.font)
        self.draw_status_bar()
    
    def draw_saved_profiles(self):
        """Draw saved WiFi profiles."""
        self.draw_header("Saved Profiles")
        
        if not self.saved_profiles:
            self.draw.text((4, 25), "No saved profiles", fill="red", font=self.font)
            self.draw.text((4, 40), "Scan & save networks", fill="cyan", font=self.font)
        else:
            y_pos = 18
            display_count = min(6, len(self.saved_profiles))
            start_idx = max(0, self.menu_index - 2)
            
            for i in range(start_idx, min(start_idx + display_count, len(self.saved_profiles))):
                profile = self.saved_profiles[i]
                ssid = profile.get('ssid', 'Unknown')[:12]
                priority = profile.get('priority', 1)
                
                if i == self.menu_index:
                    self.draw.rectangle([(0, y_pos-2), (128, y_pos+10)], fill="blue")
                    color = "white"
                else:
                    color = "white"
                
                self.draw.text((4, y_pos), f"📁 {ssid} ({priority})", fill=color, font=self.font)
                y_pos += 12
        
        self.draw.text((2, 100), "⭕ Connect  🗑️ Del", fill="cyan", font=self.font)
        self.draw_status_bar()
    
    def draw_interface_config(self):
        """Draw interface configuration."""
        self.draw_header("Interface Config")
        
        interfaces = ["eth0"] + self.wifi_manager.wifi_interfaces
        current_interface = self.wifi_manager.get_interface_for_tool()
        
        y_pos = 18
        self.draw.text((4, y_pos), "Default Interface:", fill="yellow", font=self.font)
        y_pos += 15
        
        for i, interface in enumerate(interfaces):
            if i == self.menu_index:
                self.draw.rectangle([(0, y_pos-2), (128, y_pos+10)], fill="blue")
                color = "white"
            else:
                color = "white"
            
            # Show current selection
            marker = "●" if interface == current_interface else "○"
            self.draw.text((4, y_pos), f"{marker} {interface}", fill=color, font=self.font)
            y_pos += 12
        
        self.draw.text((2, 100), "⭕ Select  KEY3: Back", fill="cyan", font=self.font)
        self.draw_status_bar()
    
    def draw_status_info(self):
        """Draw detailed status information."""
        self.draw_header("Status & Info")
        
        status = self.wifi_manager.get_connection_status()
        
        y_pos = 18
        
        # WiFi Status
        if status["status"] == "connected":
            self.draw.text((4, y_pos), f"WiFi: {status['ssid']}", fill="green", font=self.font)
            y_pos += 12
            self.draw.text((4, y_pos), f"IP: {status['ip']}", fill="green", font=self.font)
            y_pos += 12
            self.draw.text((4, y_pos), f"IF: {status['interface']}", fill="green", font=self.font)
        else:
            self.draw.text((4, y_pos), "WiFi: Disconnected", fill="red", font=self.font)
            y_pos += 12
        
        y_pos += 5
        
        # Interface info
        self.draw.text((4, y_pos), f"WiFi dongles: {len(self.wifi_manager.wifi_interfaces)}", fill="white", font=self.font)
        y_pos += 12
        
        if self.wifi_manager.wifi_interfaces:
            for iface in self.wifi_manager.wifi_interfaces:
                self.draw.text((4, y_pos), f"  {iface}", fill="cyan", font=self.font)
                y_pos += 10
        
        self.draw.text((2, 115), "KEY3: Back", fill="cyan", font=self.font)
    
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
        if button == "UP" and self.saved_profiles:
            self.menu_index = (self.menu_index - 1) % len(self.saved_profiles)
        elif button == "DOWN" and self.saved_profiles:
            self.menu_index = (self.menu_index + 1) % len(self.saved_profiles)
        elif button == "CENTER" and self.saved_profiles:
            self.connect_to_saved_profile()
        elif button == "LEFT" and self.saved_profiles:  # Delete
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
                # For demo, use a simple password prompt
                # In real implementation, you'd have a password input screen
                self.show_message("Need password input")
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
        self.canvas.paste(Image.new("RGB", (128, 128), "black"))
        self.draw.text((4, 50), message[:16], fill="yellow", font=self.font)
        self.LCD.LCD_ShowImage(self.canvas, 0, 0)
        time.sleep(duration)
    
    def check_buttons(self):
        """Check for button presses."""
        for name, pin in self.buttons.items():
            if GPIO.input(pin) == 0:  # Button pressed
                # Debounce
                time.sleep(0.1)
                if GPIO.input(pin) == 0:
                    # Wait for release
                    while GPIO.input(pin) == 0:
                        time.sleep(0.05)
                    return name
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
        
        self.LCD.LCD_ShowImage(self.canvas, 0, 0)
    
    def run(self):
        """Main interface loop."""
        self.wifi_manager.log("Starting WiFi LCD interface")
        
        try:
            while self.running:
                self.update_display()
                
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
                    elif self.current_menu == "status":
                        if button == "KEY3":
                            self.current_menu = "main"
                            self.menu_index = 0
                
                time.sleep(0.1)
                
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