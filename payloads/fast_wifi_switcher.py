#!/usr/bin/env python3
"""
FAST WiFi Switcher - Responsive wlan0/wlan1 Control
===================================================
Fast, responsive interface for switching between wlan0 and wlan1.
No bullshit, no delays, just quick switching that actually works.

CONTROLS:
- KEY1: Switch to wlan0
- KEY2: Switch to wlan1  
- KEY3: Exit
- UP/DOWN: Quick toggle between interfaces
- CENTER: Show current status

FEATURES:
- Instant response to button presses
- Actual routing changes (not just display)
- Real-time verification
- Minimal delay interface
"""

import os
import sys
import time
import subprocess
import signal

# Add the required paths
sys.path.append('/root/Raspyjack/')
sys.path.append('/root/Raspyjack/wifi/')

try:
    # Import RaspyJack LCD functions (PROPER WAY)
    import LCD_1in44, LCD_Config
    import RPi.GPIO as GPIO
    from PIL import Image, ImageDraw, ImageFont
    
    # Import WiFi integration functions
    from wifi.raspyjack_integration import (
        set_raspyjack_interface,
        get_current_raspyjack_interface,
        get_interface_status,
        ensure_interface_default
    )
    
    IMPORTS_OK = True
except Exception as e:
    print(f"Import error: {e}")
    IMPORTS_OK = False

class FastWiFiSwitcher:
    def __init__(self):
        if not IMPORTS_OK:
            raise Exception("Required modules not available")
        
        # LCD setup - proper initialization
        LCD_Config.GPIO_Init()
        self.lcd = LCD_1in44.LCD()
        self.lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        self.lcd.LCD_Clear()
        self.WIDTH, self.HEIGHT = 128, 128
        self.font = ImageFont.load_default()
        
        # GPIO setup with FAST response
        GPIO.setmode(GPIO.BCM)
        self.buttons = {
            'UP': 6,
            'DOWN': 19,
            'LEFT': 5,
            'RIGHT': 26,
            'CENTER': 13,
            'KEY1': 21,  # wlan0
            'KEY2': 20,  # wlan1
            'KEY3': 16   # exit
        }
        
        for pin in self.buttons.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        
        self.running = True
        self.last_update = 0
        self.current_interface = self.get_current()
        
        # Button state tracking for responsiveness
        self.button_states = {pin: 1 for pin in self.buttons.values()}
        self.last_press_time = {pin: 0 for pin in self.buttons.values()}
        
        print("🚀 Fast WiFi Switcher initialized")
    
    def get_current(self):
        """Get current interface quickly."""
        try:
            return get_current_raspyjack_interface()
        except:
            return "unknown"
    
    def show_fast(self, line1, line2="", line3="", line4="", color="white"):
        """Ultra-fast LCD display with proper PIL rendering."""
        try:
            # Create black canvas
            img = Image.new("RGB", (self.WIDTH, self.HEIGHT), "black")
            d = ImageDraw.Draw(img)
            
            # Draw text lines
            y = 5
            for line in [line1, line2, line3, line4]:
                if line:
                    d.text((5, y), line[:18], font=self.font, fill=color)
                    y += 15
            
            # Show on LCD
            self.lcd.LCD_ShowImage(img, 0, 0)
        except Exception as e:
            print(f"LCD error: {e}")
            print(f"Display: {line1} {line2} {line3} {line4}")
    
    def check_interface_fast(self, interface):
        """Fast interface status check."""
        try:
            result = subprocess.run(['ip', 'addr', 'show', interface], 
                                  capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                if 'state UP' in result.stdout and 'inet ' in result.stdout:
                    # Extract IP quickly
                    for line in result.stdout.split('\n'):
                        if 'inet ' in line:
                            ip = line.split('inet ')[1].split('/')[0]
                            return {'up': True, 'ip': ip}
            return {'up': False, 'ip': None}
        except:
            return {'up': False, 'ip': None}
    
    def switch_interface_fast(self, target_interface):
        """Ultra-fast interface switching using the fixed integration function."""
        self.show_fast("SWITCHING...", f"To: {target_interface}", "Please wait", "", "yellow")
        
        def lcd_callback(msg):
            """Callback to show status on LCD."""
            self.show_fast("SWITCHING", f"To: {target_interface}", msg[:15], "", "yellow")
            time.sleep(0.5)  # Brief pause to read status
        
        try:
            print(f"🔄 Fast switching to {target_interface} using integration function")
            
            # Use the FIXED set_raspyjack_interface function with LCD callback
            # This includes all our bug fixes:
            # - SSID parsing fix
            # - Auto-connect using WiFi profiles  
            # - Disconnected interface handling
            # - LCD-friendly status messages
            success = set_raspyjack_interface(target_interface, lcd_callback)
            
            if success:
                # Quick status check for display
                status = self.check_interface_fast(target_interface)
                if status['up']:
                    self.show_fast("SUCCESS!", f"Now using:", target_interface, f"IP: {status['ip'][:12]}", "green")
                else:
                    self.show_fast("SUCCESS!", f"Switched to:", target_interface, "Getting IP...", "green")
                
                self.current_interface = target_interface
                print(f"✅ Successfully switched to {target_interface}")
                time.sleep(1.5)
                return True
            else:
                self.show_fast("FAILED!", f"{target_interface}", "switch failed", "Check logs", "red")
                print(f"❌ Failed to switch to {target_interface}")
                time.sleep(2)
                return False
                
        except Exception as e:
            self.show_fast("ERROR!", str(e)[:15], "", "", "red")
            print(f"❌ Switch error: {e}")
            time.sleep(2)
            return False
    
    def read_buttons_fast(self):
        """Ultra-fast button reading with debouncing."""
        current_time = time.time()
        pressed_buttons = []
        
        for button_name, pin in self.buttons.items():
            current_state = GPIO.input(pin)
            
            # Detect button press (transition from 1 to 0)
            if self.button_states[pin] == 1 and current_state == 0:
                # Debouncing - ignore if pressed too recently
                if current_time - self.last_press_time[pin] > 0.1:  # 100ms debounce
                    pressed_buttons.append(button_name)
                    self.last_press_time[pin] = current_time
            
            self.button_states[pin] = current_state
        
        return pressed_buttons
    
    def show_status(self):
        """Show current interface status."""
        current = self.get_current()
        
        # Quick status check for current interface
        if current.startswith('wlan'):
            status = self.check_interface_fast(current)
            if status['up']:
                self.show_fast("Current:", current, f"IP: {status['ip'][:12]}", "KEY1/2: Switch", "white")
            else:
                self.show_fast("Current:", current, "NOT CONNECTED", "KEY1/2: Switch", "red")
        else:
            self.show_fast("Current:", current, "Non-WiFi iface", "KEY1/2: Switch", "yellow")
    
    def run(self):
        """Main fast response loop."""
        self.show_fast("Fast WiFi", "Switcher", "KEY1: wlan0", "KEY2: wlan1")
        time.sleep(1)
        
        while self.running:
            try:
                # Fast button check - no delays
                pressed = self.read_buttons_fast()
                
                if pressed:
                    for button in pressed:
                        if button == 'KEY1':
                            # Switch to wlan0
                            print("KEY1 pressed - switching to wlan0")
                            self.switch_interface_fast('wlan0')
                            
                        elif button == 'KEY2':
                            # Switch to wlan1
                            print("KEY2 pressed - switching to wlan1")
                            self.switch_interface_fast('wlan1')
                            
                        elif button == 'KEY3':
                            # Exit
                            self.show_fast("Exiting...", "", "", "")
                            time.sleep(0.5)
                            self.running = False
                            break
                            
                        elif button == 'UP' or button == 'DOWN':
                            # Quick toggle
                            current = self.get_current()
                            if current == 'wlan0':
                                self.switch_interface_fast('wlan1')
                            elif current == 'wlan1':
                                self.switch_interface_fast('wlan0')
                            else:
                                self.switch_interface_fast('wlan1')  # Default to wlan1
                                
                        elif button == 'CENTER':
                            # Show status
                            self.show_status()
                            time.sleep(1.5)
                
                # Update display periodically (but not too often)
                current_time = time.time()
                if current_time - self.last_update > 2.0:  # Every 2 seconds
                    if not pressed:  # Only update if no button activity
                        current = self.get_current()
                        if current != self.current_interface:
                            self.current_interface = current
                        
                        self.show_fast("Fast Switcher", f"Current: {current}", "KEY1: wlan0", "KEY2: wlan1")
                    self.last_update = current_time
                
                # Ultra-fast loop - minimal delay
                time.sleep(0.01)  # 10ms loop for maximum responsiveness
                
            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                print(f"Error in main loop: {e}")
                time.sleep(0.1)
    
    def cleanup(self):
        """Clean up resources."""
        try:
            self.show_fast("Goodbye!", "", "", "")
            time.sleep(0.5)
            self.lcd.LCD_Clear()
            GPIO.cleanup()
        except:
            pass

def main():
    """Main function."""
    print("🚀 Starting Fast WiFi Switcher")
    
    if not IMPORTS_OK:
        print("❌ Required modules not available")
        return
    
    switcher = None
    try:
        switcher = FastWiFiSwitcher()
        switcher.run()
    except KeyboardInterrupt:
        print("\n⏹️  Interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if switcher:
            switcher.cleanup()

if __name__ == "__main__":
    main() 