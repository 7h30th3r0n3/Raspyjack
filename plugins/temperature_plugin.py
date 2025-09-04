"""
Temperature status overlay plugin for RaspyJack.

Reads temperature from the system's thermal sensor and renders a small
text widget on the top-left corner, without disturbing the existing status line.

Example configuration (plugins_conf.json):
{
  "temperature_plugin": {
    "enabled": true,
    "priority": 30,
    "options": {
      "refresh_interval": 2.0,
      "text_color": "white",
      "show_unit": true
    }
  }
}
"""
from __future__ import annotations
import time
from .base import Plugin

class TemperaturePlugin(Plugin):
    name = "Temperature"
    priority = 30

    def on_load(self, ctx: dict) -> None:
        """Called when the plugin is loaded."""
        self.ctx = ctx
        opts = getattr(self, 'options', {}) or {}
        self.refresh_interval = float(opts.get('refresh_interval', 2.0))
        self.color = opts.get('text_color', 'white')
        self.show_unit = bool(opts.get('show_unit', True))
        
        self._last_poll = 0.0
        self.temperature = 0.0
        self.ok = self._check_sensor()

    def _check_sensor(self) -> bool:
        """Checks if the temperature sensor is accessible."""
        try:
            with open("/sys/class/thermal/thermal_zone0/temp", 'r') as f:
                f.read()
            return True
        except Exception as e:
            print(f"[{self.name}] Sensor not found: {e}")
            return False

    def _read_temp(self) -> float:
        """Reads the temperature from the system sensor."""
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return int(f.read()) / 1000.0

    def on_tick(self, dt: float) -> None:
        """Called periodically to update the temperature value."""
        if not self.ok:
            return
        now = time.time()
        if now - self._last_poll >= self.refresh_interval:
            self._last_poll = now
            try:
                self.temperature = self._read_temp()
            except Exception as e:
                print(f"[{self.name}] Read error: {e}")
                self.temperature = 0.0

    def on_render_overlay(self, image, draw) -> None:
        """Draws the temperature overlay on the LCD."""
        if not self.ok:
            return
            
        # Do not draw if the main status bar is busy
        try:
            if 'status_bar' in self.ctx and self.ctx['status_bar'].is_busy():
                return
        except Exception:
            pass

        unit = "°C" if self.show_unit else ""
        temp_text = f"{self.temperature:.0f}{unit}"
        
        # Use the same font object from raspyjack.py if available
        font = self.ctx.get('font', None)
        draw.text((2, 0), temp_text, fill=self.color, font=font)

plugin = TemperaturePlugin()
