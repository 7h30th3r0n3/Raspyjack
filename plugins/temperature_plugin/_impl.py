from __future__ import annotations
import time
from plugins.base import Plugin

class TemperaturePlugin(Plugin):

    def on_load(self, ctx: dict) -> None:
        self.ctx = ctx
        opts = getattr(self, 'options', {}) or {}
        self.refresh_interval = float(self.get_config_value('refresh_interval', 2.0))
        self.colorize = bool(self.get_config_value('colorize', True))
        self.show_unit = self.get_config_value("show_unit", True)
        self.enable_display = self.get_config_value("enable_display", True)
        self.align = str(self.get_config_value('temp_align', 'left')).lower()
        try:
            self.offset = int(self.get_config_value('temp_offset', 0))
        except Exception:
            self.offset = 0
        self.warn_threshold = float(self.get_config_value('warn_threshold', 65.0))
        self.critical_threshold = float(self.get_config_value('critical_threshold', 80.0))
        if self.critical_threshold < self.warn_threshold:
            self.critical_threshold = self.warn_threshold + 5.0
        
        self._last_poll = 0.0
        self.temperature = 0.0
        self.ok = self._check_sensor()
        self._warn_active = False
        self._crit_active = False
        if not self.ok:
            self.emit('temperature.sensor.error', path='/sys/class/thermal/thermal_zone0/temp')

    def _check_sensor(self) -> bool:
        try:
            with open("/sys/class/thermal/thermal_zone0/temp", 'r') as f:
                f.read()
            return True
        except Exception as e:
            print(f"[{self.name}] Sensor not found: {e}")
            return False

    def _read_temp(self) -> float:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return int(f.read()) / 1000.0

    def on_tick(self, dt: float) -> None:
        if not self.ok or not self.get_config_value("enable_display", True):
            return
            
        now = time.time()
        if now - self._last_poll >= self.refresh_interval:
            self._last_poll = now
            try:
                value = self._read_temp()
                self.temperature = value
                self.emit('temperature.updated', value=value, ts=now)
                # Threshold transitions
                self._handle_thresholds(value)
            except Exception as e:
                print(f"[{self.name}] Read error: {e}")
                self.temperature = 0.0
                self.emit('temperature.read.failed', error=str(e), ts=now)

    def on_render_overlay(self, image, draw) -> None:
        if not self.ok or not self.get_config_value("enable_display", True):
            return
            
        try:
            if 'status_bar' in self.ctx and self.ctx['status_bar'].is_busy():
                return
        except Exception:
            pass
            
        unit = "°C" if self.get_config_value("show_unit", True) else ""
        temp_text = f"{self.temperature:.0f}{unit}"
        
        font = self.ctx.get('font', None)
        # Determine horizontal position based on alignment + offset
        w, h = image.size
        text_w = len(temp_text) * 6  # rough monospace width heuristic
        if self.align == 'center':
            x = (w - text_w) // 2
        elif self.align == 'right':
            x = w - text_w - 2
        else:
            x = 2
        x += self.offset
        if x < 0:
            x = 0
        if x + text_w > w:
            x = max(0, w - text_w)
        draw.text((x, 0), temp_text, fill=self._current_color(), font=font)
    
    def on_config_changed(self, key: str, old_value, new_value) -> None:
        """React to configuration changes."""
        if key == "enable_display":
            status = "enabled" if new_value else "disabled"
            print(f"[{self.name}] Temperature display {status}")
        elif key == "show_unit":
            status = "shown" if new_value else "hidden"
            print(f"[{self.name}] Temperature unit {status}")
        elif key == 'refresh_interval':
            self.refresh_interval = max(0.25, float(new_value))
            print(f"[{self.name}] Refresh interval set to {self.refresh_interval}s")
        elif key == 'warn_threshold':
            self.warn_threshold = float(new_value)
            print(f"[{self.name}] Warn threshold = {self.warn_threshold}C")
        elif key == 'critical_threshold':
            self.critical_threshold = float(new_value)
            if self.critical_threshold < self.warn_threshold:
                self.critical_threshold = self.warn_threshold + 1.0
            print(f"[{self.name}] Critical threshold = {self.critical_threshold}C")
        elif key == 'colorize':
            self.colorize = bool(new_value)
            print(f"[{self.name}] Colorize {'enabled' if self.colorize else 'disabled'}")
        elif key == 'temp_align':
            self.align = str(new_value).lower()
        elif key == 'temp_offset':
            try:
                self.offset = int(new_value)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Menu integration
    # ------------------------------------------------------------------
    def _menu_set_alignment(self):
        wctx = self.ctx.get('widget_context') if self.ctx else None
        if not wctx:
            return
        try:
            from ui.widgets import ScrollableTextLines, yn_dialog, dialog_info
        except Exception:
            return
        # Simple cycle left->center->right
        order = ['left','center','right']
        try:
            idx = order.index(self.align) if self.align in order else 0
        except Exception:
            idx = 0
        new_align = order[(idx + 1) % len(order)]
        self.align = new_align
        self.set_config_value('temp_align', new_align)
        try:
            self.persist_option('temp_align', new_align, create_if_missing=True)
        except Exception:
            pass
        try:
            from ui.widgets import dialog_info as _dlg
            _dlg(wctx, f"Align: {new_align}", wait=True, center=True)
        except Exception:
            pass

    def _menu_set_offset(self):
        wctx = self.ctx.get('widget_context') if self.ctx else None
        if not wctx:
            return
        try:
            from ui.widgets import numeric_picker, dialog_info
        except Exception:
            return
        current = int(self.offset)
        new_val = numeric_picker(wctx, label="OFF", min_value=-40, max_value=40, initial_value=current, step=1)
        if new_val == current:
            dialog_info(wctx, f"Offset unchanged\n{new_val}", wait=True, center=True)
            return
        self.offset = new_val
        self.set_config_value('temp_offset', new_val)
        try:
            self.persist_option('temp_offset', new_val, create_if_missing=True)
        except Exception:
            pass
        dialog_info(wctx, f"Offset set\n{new_val}", wait=True, center=True)

    def provide_menu_items(self):
        return [
            ("Temp Align", self._menu_set_alignment, "\uf037", "Cycle temperature overlay alignment"),
            ("Temp Offset", self._menu_set_offset, "\uf07d", "Adjust overlay horizontal offset")
        ]

    def _current_color(self) -> str:
        if not self.colorize:
            return 'white'
        t = self.temperature
        if t >= self.critical_threshold:
            return 'red'
        if t >= self.warn_threshold:
            return 'yellow'
        return 'white'

    # ------------------------------------------------------------------
    # Threshold handling
    # ------------------------------------------------------------------
    def _handle_thresholds(self, value: float) -> None:
        # Critical threshold
        if not self._crit_active and value >= self.critical_threshold:
            self._crit_active = True
            try:
                self.emit('temperature.threshold.critical', value=value, threshold=self.critical_threshold)
            except Exception:
                pass
        elif self._crit_active and value < (self.critical_threshold - 2):  # hysteresis
            self._crit_active = False
            try:
                self.emit('temperature.threshold.critical.cleared', value=value, threshold=self.critical_threshold)
            except Exception:
                pass
        # Warning threshold (only if not already critical)
        if not self._warn_active and value >= self.warn_threshold:
            if value < self.critical_threshold:  # avoid double firing when jumping straight to critical
                self._warn_active = True
                try:
                    self.emit('temperature.threshold.warn', value=value, threshold=self.warn_threshold)
                except Exception:
                    pass
        elif self._warn_active and value < (self.warn_threshold - 2):  # hysteresis
            self._warn_active = False
            try:
                self.emit('temperature.threshold.warn.cleared', value=value, threshold=self.warn_threshold)
            except Exception:
                pass
    
    def get_info(self) -> str:
        if not self.ok:
            return "Temperature sensor not available\nPath: /sys/class/thermal/thermal_zone0/temp\nStatus: Sensor not found"
        
        # Get current configuration
        enable_display = self.get_config_value("enable_display", True)
        show_unit = self.get_config_value("show_unit", True)
        
        status_lines = [
            f"Current Temperature: {self.temperature:.1f}°C",
            f"Sensor Status: Active",
            "",
            "Current Configuration:",
            f"• HUD Display: {'ON' if enable_display else 'OFF'}",
            f"• Show Unit: {'ON' if show_unit else 'OFF'}",
            "",
            f"Colorize: {'ON' if self.colorize else 'OFF'}",
            f"Align: {self.align}  Offset: {self.offset}",
            f"Refresh Interval: {self.refresh_interval}s",
            f"Last Poll: {time.strftime('%H:%M:%S', time.localtime(self._last_poll))}",
            f"Warn Threshold: {self.warn_threshold}°C",
            f"Critical Threshold: {self.critical_threshold}°C",
        ]
        
        return "\n".join(status_lines)

plugin = TemperaturePlugin()
