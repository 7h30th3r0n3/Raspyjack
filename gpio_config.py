#!/usr/bin/env python3
"""
GPIO Pin Configuration Manager for Raspyjack
"""

import json
from typing import Dict, Optional

class GPIOConfig:
    """Manages GPIO pin configurations from gui_conf.json"""
    
    def __init__(self, config_path: Optional[str] = None):
        # Default to local gui_conf.json if no path specified
        if config_path is None:
            # Try local directory first, then fallback to /root/Raspyjack/
            import os
            local_config = os.path.join(os.path.dirname(__file__), "gui_conf.json")
            if os.path.exists(local_config):
                self.config_path = local_config
            else:
                self.config_path = "/root/Raspyjack/gui_conf.json"
        else:
            self.config_path = config_path
        self._config_data = None
        self._pins = None
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                self._config_data = json.load(f)
                self._pins = self._config_data.get("PINS", {})
        except FileNotFoundError:
            print(f"GPIO config file not found: {self.config_path}")
            # Default pin configuration if file doesn't exist
            self._pins = {
                "KEY1_PIN": 21,
                "KEY2_PIN": 20,
                "KEY3_PIN": 16,
                "KEY_DOWN_PIN": 19,
                "KEY_LEFT_PIN": 5,
                "KEY_PRESS_PIN": 13,
                "KEY_RIGHT_PIN": 26,
                "KEY_UP_PIN": 6
            }
            self._config_data = {"PINS": self._pins}
        except Exception as e:
            print(f"Error loading GPIO config: {e}")
            self._pins = {}
            self._config_data = {}
    
    def save_config(self) -> None:
        """Save current configuration back to JSON file"""
        try:
            if self._config_data:
                with open(self.config_path, 'w') as f:
                    json.dump(self._config_data, f, indent=4, sort_keys=True)
                print("GPIO configuration saved successfully")
        except Exception as e:
            print(f"Error saving GPIO config: {e}")
    
    @property
    def pins(self) -> Dict[str, int]:
        """Get all pin mappings"""
        return self._pins.copy() if self._pins else {}
    
    def get_pin(self, pin_name: str) -> int:
        """Get specific pin number by name"""
        return self._pins.get(pin_name, -1) if self._pins else -1
    
    def set_pin(self, pin_name: str, pin_number: int) -> None:
        """Set specific pin number"""
        if self._pins is not None:
            self._pins[pin_name] = pin_number
            if self._config_data:
                self._config_data["PINS"] = self._pins
    
    # Convenience properties for specific pins
    @property
    def key1_pin(self) -> int:
        return self.get_pin("KEY1_PIN")
    
    @property
    def key2_pin(self) -> int:
        return self.get_pin("KEY2_PIN")
    
    @property
    def key3_pin(self) -> int:
        return self.get_pin("KEY3_PIN")
    
    @property
    def key_up_pin(self) -> int:
        return self.get_pin("KEY_UP_PIN")
    
    @property
    def key_down_pin(self) -> int:
        return self.get_pin("KEY_DOWN_PIN")
    
    @property
    def key_left_pin(self) -> int:
        return self.get_pin("KEY_LEFT_PIN")
    
    @property
    def key_right_pin(self) -> int:
        return self.get_pin("KEY_RIGHT_PIN")
    
    @property
    def key_press_pin(self) -> int:
        return self.get_pin("KEY_PRESS_PIN")
    
    def __str__(self) -> str:
        return f"GPIOConfig(pins={self._pins})"
    
    def __repr__(self) -> str:
        return self.__str__()

# Global instance for easy access
gpio_config = GPIOConfig()

__all__ = ['GPIOConfig', 'gpio_config']