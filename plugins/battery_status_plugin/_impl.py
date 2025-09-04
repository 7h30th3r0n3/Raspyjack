from __future__ import annotations
import time

try:
    import smbus  # type: ignore
except Exception:  # Allow running without I2C libs
    smbus = None

from plugins.base import Plugin

_REG_CONFIG       = 0x00
_REG_SHUNTVOLTAGE = 0x01
_REG_BUSVOLTAGE   = 0x02
_REG_POWER        = 0x03
_REG_CURRENT      = 0x04
_REG_CALIBRATION  = 0x05

class _INA219:
    def __init__(self, i2c_bus: int = 1, addr: int = 0x43):
        if smbus is None:
            raise RuntimeError("smbus not available")
        self.bus = smbus.SMBus(i2c_bus)
        self.addr = addr
        self._current_lsb = 0.1524
        self._power_lsb = 0.003048
        self._cal_value = 26868
        self._configure()

    def _write(self, reg: int, value: int):
        self.bus.write_i2c_block_data(self.addr, reg, [(value >> 8) & 0xFF, value & 0xFF])

    def _read16(self, reg: int) -> int:
        data = self.bus.read_i2c_block_data(self.addr, reg, 2)
        return (data[0] << 8) | data[1]

    def _configure(self):
        self._write(_REG_CALIBRATION, self._cal_value)
        config = (0x00 << 13) | (0x01 << 11) | (0x0D << 7) | (0x0D << 3) | 0x07
        self._write(_REG_CONFIG, config)

    def bus_voltage(self) -> float:
        self._write(_REG_CALIBRATION, self._cal_value)
        _ = self._read16(_REG_BUSVOLTAGE)
        value = self._read16(_REG_BUSVOLTAGE)
        return (value >> 3) * 0.004

    def shunt_voltage(self) -> float:
        self._write(_REG_CALIBRATION, self._cal_value)
        value = self._read16(_REG_SHUNTVOLTAGE)
        if value > 32767:
            value -= 65535
        return value * 0.00001

    def current_a(self) -> float:
        value = self._read16(_REG_CURRENT)
        if value > 32767:
            value -= 65535
        return (value * self._current_lsb) / 1000.0

    def power_w(self) -> float:
        self._write(_REG_CALIBRATION, self._cal_value)
        value = self._read16(_REG_POWER)
        if value > 32767:
            value -= 65535
        return value * self._power_lsb

class BatteryStatusPlugin(Plugin):

    # ------------------------------------------------------------------
    # Life-cycle
    # ------------------------------------------------------------------
    def on_load(self, ctx: dict) -> None:
        """Initialize battery monitoring state and attempt sensor setup."""
        self.ctx = ctx

        # Configuration (manifest-driven with defaults)
        self.addr = int(self.get_config_value("address", 67))  # decimal (0x43)
        self.bus_num = int(self.get_config_value("i2c_bus", 1))
        self.base_refresh_interval = float(self.get_config_value("refresh_interval", 2.0))
        self.v_min = float(self.get_config_value("voltage_min", 3.0))
        self.v_max = float(self.get_config_value("voltage_max", 4.2))
        self.warn_threshold = int(self.get_config_value("warn_threshold", 25))
        self.crit_threshold = int(self.get_config_value("crit_threshold", 10))
        self.colorize = bool(self.get_config_value("colorize", True))
        self.align = str(self.get_config_value("battery_align", "right")).lower()
        self.offset = int(self.get_config_value("battery_offset", 0))

        # State
        self._last_poll = 0.0
        self.percent = None              # type: float | None
        self.last_emit_percent = None    # type: int | None
        self.read_errors = 0
        self.samples_ok = 0
        self._stable_high_cycles = 0     # used for adaptive polling
        self._blink_phase = False        # for critical blink
        self.ok = False
        self._charge_state = None        # None (unknown), 'charging', 'discharging'

        # Sensor init
        try:
            self.sensor = _INA219(self.bus_num, self.addr)
            self.ok = True
        except Exception as e:
            print(f"[BatteryStatus] Disabled (I2C init failed): {e}")
            self.sensor = None
            self.emit("battery.sensor_error", error=str(e))

        # Build voltage table now that v_min is known
        try:
            self._voltage_table = self._build_voltage_table()
        except Exception:
            self._voltage_table = []

    # ------------------------------------------------------------------
    # Voltage / percentage table & conversion
    # ------------------------------------------------------------------
    def _build_voltage_table(self) -> list[tuple[float, int]]:
        """Build a voltage->percent table dynamically using configured v_min.
        Strategy:
          - Keep higher plateau reference points (>= ~3.74V) static (typical Li-ion curve).
          - Interpolate mid/low region down to configured v_min with extra steps:
              7%, 5%, 4%, 3%, 2%, 1%, 0%
          - Ensure voltages are monotonic descending.
        """
        v_min = self.v_min
        # Dynamic top based on configured v_max
        top = self.v_max
        # Ensure top reasonably above v_min
        if top <= v_min + 0.25:
            top = v_min + 0.25  # enforce minimal span
        # 90% point ~100mV below top (or 70% of span if span small)
        span = top - v_min
        delta_90 = 0.10 if span >= 0.50 else span * 0.2
        v_90 = max(v_min + 0.01, top - delta_90)
        # Mid/high references proportionally spaced if span large enough
        # We map rough Li-ion shape but scale around top
        def interp(p):
            # p is desired percent; convert to voltage using simple proportion within span, then adjust curvature
            frac = (100 - p) / 100.0
            return top - (span * (frac ** 1.2))  # slight curve
        # Build ordered list high→lower (descending volts)
        perc_points = [100, 90, 80, 70, 60, 50, 40, 30, 20, 10]
        volts_map = {}
        for p in perc_points:
            if p == 100:
                volts_map[p] = round(top, 3)
            elif p == 90:
                volts_map[p] = round(v_90, 3)
            else:
                volts_map[p] = round(interp(p), 3)
        # Ensure strictly descending
        ordered = []
        last_v = top + 1
        for p in perc_points:
            v_p = volts_map[p]
            if v_p >= last_v:  # enforce descending by nudging
                v_p = last_v - 0.01
            ordered.append((v_p, p))
            last_v = v_p
        high = ordered
        # We map 5% around 3.50V traditionally; adapt if v_min higher.
        v_5 = max(v_min + 0.18, min(3.50, 3.68 - 0.15))  # ensure spacing ~0.18V above v_min
        # Generate tail points with gentle slope toward v_min
        tail_perc = [7,5,4,3,2,1,0]
        tail = []
        # Distribute voltages linearly between v_5 and v_min
        tail_span = v_5 - v_min if v_5 > v_min else 0.05
        for i, p in enumerate(tail_perc):
            frac = i / (len(tail_perc) - 1) if len(tail_perc) > 1 else 1
            v_point = v_5 - frac * tail_span
            tail.append((round(v_point, 3), p))
        table = high + tail
        # Remove any duplicates or non-descending anomalies
        cleaned = []
        last_v = 10.0
        for v,p in table:
            if v < last_v - 0.0005:  # enforce descending with minimal gap
                cleaned.append((v,p))
                last_v = v
            elif v < last_v and cleaned:
                # adjust slightly if almost equal
                adj_v = last_v - 0.002
                cleaned.append((adj_v, p))
                last_v = adj_v
        return cleaned

    def _voltage_to_percent(self, v: float) -> float:
        """Convert voltage to approximate percent via linear interpolation over a piecewise table."""
        # Build table lazily if not present (after on_load)
        if not hasattr(self, '_voltage_table') or not self._voltage_table:
            try:
                self._voltage_table = self._build_voltage_table()
            except Exception:
                # Fallback to a minimal static table if build fails
                self._voltage_table = [
                    (4.20, 100), (3.90, 70), (3.74, 20), (self.v_min, 0)
                ]
        table = self._voltage_table
        # Clamp
        if v >= table[0][0]:
            return 100.0
        if v <= table[-1][0]:
            return 0.0
        # Find segment
        for i in range(len(table) - 1):
            v_hi, p_hi = table[i]
            v_lo, p_lo = table[i + 1]
            if v_hi >= v >= v_lo:
                # Linear interpolation within segment
                span = v_hi - v_lo
                if span <= 0:
                    return float(p_lo)
                ratio = (v - v_lo) / span
                return p_lo + ratio * (p_hi - p_lo)
        return 0.0

    # ------------------------------------------------------------------
    # Polling / adaptive interval
    # ------------------------------------------------------------------
    def _effective_interval(self) -> float:
        """Compute adaptive polling interval.

        Strategy:
          - If percent is high and stable, back off (slower polling).
          - If low (<= warn threshold) or unknown, use base interval.
        """
        pct = self.percent if self.percent is not None else 0
        if pct >= 80 and self._stable_high_cycles >= 5:
            return self.base_refresh_interval * 4  # slow down when very stable
        if pct >= 60 and self._stable_high_cycles >= 3:
            return self.base_refresh_interval * 2
        if pct <= self.crit_threshold:
            return max(0.5, self.base_refresh_interval * 0.5)  # speed up when critical
        if pct <= self.warn_threshold:
            return max(1.0, self.base_refresh_interval * 0.75)
        return self.base_refresh_interval

    # ------------------------------------------------------------------
    # Runtime polling & event emission
    # ------------------------------------------------------------------
    def on_tick(self, dt: float) -> None:
        if not self.ok or self.sensor is None or not self.get_config_value("enable_monitoring", True):
            return
        now = time.time()
        interval = self._effective_interval()
        if now - self._last_poll < interval:
            return
        self._last_poll = now
        try:
            v = self.sensor.bus_voltage()
            # Determine instantaneous charging/discharging from current reading (>= ~5mA threshold)
            try:
                cur_a = self.sensor.current_a()
            except Exception:
                cur_a = 0.0
            raw_pct = self._voltage_to_percent(v)
            # Exponential smoothing
            if self.percent is None:
                self.percent = raw_pct
            else:
                alpha = 0.25
                self.percent = self.percent + alpha * (raw_pct - self.percent)
            self.samples_ok += 1
            # Stability tracking (increment if change < 0.5%)
            if self.last_emit_percent is not None and self.percent is not None:
                if abs(self.percent - self.last_emit_percent) < 0.5:
                    self._stable_high_cycles += 1
                else:
                    self._stable_high_cycles = 0
            # Event emission control
            if self.percent is not None:
                rounded = int(self.percent)
                emit_change = (self.last_emit_percent is None or abs(rounded - self.last_emit_percent) >= 1)
                if emit_change:
                    # Determine charge state transition before updating last_emit_percent
                    new_state = None
                    # Positive current -> charging; negative (or zero) -> discharging
                    if cur_a > 0.005:  # 5 mA threshold to avoid noise
                        new_state = 'charging'
                    else:
                        new_state = 'discharging'
                    if new_state != self._charge_state and new_state is not None:
                        # Emit transition event
                        if new_state == 'charging':
                            self.emit('battery.charging', percent=rounded, voltage=v, current=cur_a)
                        else:
                            self.emit('battery.discharging', percent=rounded, voltage=v, current=cur_a)
                        self._charge_state = new_state
                    self.emit("battery.updated", percent=rounded, voltage=v, ts=now,
                              errors=self.read_errors, samples=self.samples_ok)
                    # Threshold events
                    if rounded <= self.crit_threshold:
                        self.emit("battery.critical", percent=rounded, voltage=v, ts=now)
                    elif rounded <= self.warn_threshold:
                        if self.last_emit_percent is None or self.last_emit_percent > self.warn_threshold:
                            self.emit("battery.low", percent=rounded, voltage=v, ts=now)
                    elif (self.last_emit_percent is not None and
                          self.last_emit_percent <= self.warn_threshold and
                          rounded > self.warn_threshold):
                        self.emit("battery.recovered", percent=rounded, voltage=v, ts=now)
                    self.last_emit_percent = rounded
        except Exception as e:
            self.read_errors += 1
            if self.read_errors == 1 or self.read_errors % 10 == 0:
                print(f"[BatteryStatus] read error: {e}")
            if self.read_errors in (1, 10):
                self.emit("battery.sensor_error", error=str(e), ts=now, count=self.read_errors)

    # ------------------------------------------------------------------
    # Overlay rendering
    # ------------------------------------------------------------------
    def on_render_overlay(self, image, draw) -> None:
        if (self.percent is None or 
            not self.get_config_value("enable_monitoring", True) or 
            (not self.get_config_value("show_percentage", True) and not self.get_config_value("show_icon", True))):
            return

        try:
            if 'status_bar' in getattr(self, 'ctx', {}) and self.ctx['status_bar'].is_busy():
                return
        except Exception:
            pass

        w, h = image.size
        rounded = int(self.percent)

        # Determine colors
        fill_color = "white"
        text_color = "white"
        if self.colorize:
            if rounded <= self.crit_threshold:
                # Blink effect (toggle phase each render call)
                self._blink_phase = not self._blink_phase
                fill_color = "red" if self._blink_phase else "black"
                text_color = "red"
            elif rounded <= self.warn_threshold:
                fill_color = "yellow"
                text_color = "yellow"
            else:
                fill_color = "lime"
                text_color = "lime"

        show_icon = self.get_config_value("show_icon", True)
        show_pct = self.get_config_value("show_percentage", True)
        icon_w = 18
        icon_h = 8
        gap = 3  # space between text and icon
        pct_text = f"{rounded:02d}%" if show_pct else ""
        text_w = len(pct_text) * 5 if show_pct else 0
        block_w = 0
        if show_icon:
            block_w += icon_w
        if show_pct:
            if show_icon:
                block_w += gap
            block_w += text_w
        # Determine starting x based on alignment
        if self.align == "left":
            start_x = 2 + self.offset
        elif self.align == "center":
            start_x = (w - block_w) // 2 + self.offset
        else:  # right
            start_x = w - block_w - 2 + self.offset
        # Clamp
        if start_x < 0:
            start_x = 0
        if start_x + block_w > w:
            start_x = max(0, w - block_w)

        cur_x = start_x
        y1 = 0
        if show_pct and not show_icon:
            # Only text
            draw.text((cur_x, y1), pct_text, fill=text_color)
        elif show_icon:
            # Draw text first if alignment chosen produced text before icon
            if show_pct and self.align == 'left':
                draw.text((cur_x, y1), pct_text, fill=text_color)
                cur_x += text_w + gap
            # Battery icon
            x1 = cur_x
            x2 = x1 + icon_w
            y2 = y1 + icon_h
            draw.rectangle((x1, y1, x2 - 3, y2), outline=text_color, fill=None)
            draw.rectangle((x2 - 3, y1 + 2, x2, y2 - 2), outline=text_color, fill=text_color)
            inner_w = icon_w - 6
            fill_w = int(inner_w * (rounded / 100.0))
            if fill_w > 0:
                draw.rectangle((x1 + 2, y1 + 2, x1 + 2 + fill_w, y2 - 2), fill=fill_color)
            cur_x = x2 + gap
            # If text should appear after icon (center/right or no left case)
            if show_pct and self.align != 'left':
                draw.text((cur_x, y1), pct_text, fill=text_color)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    def on_unload(self) -> None:
        """Attempt to close I2C bus cleanly."""
        try:
            if getattr(self, 'sensor', None) and hasattr(self.sensor, 'bus') and hasattr(self.sensor.bus, 'close'):
                self.sensor.bus.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Configuration updates
    # ------------------------------------------------------------------
    def on_config_changed(self, key: str, old_value, new_value) -> None:
        """React to configuration changes."""
        try:
            changed = False
            if key == "enable_monitoring":
                status = "enabled" if new_value else "disabled"
                print(f"[{self.name}] Battery monitoring {status}")
            elif key == "show_percentage":
                status = "enabled" if new_value else "disabled"
                print(f"[{self.name}] Percentage display {status}")
            elif key == "show_icon":
                status = "enabled" if new_value else "disabled"
                print(f"[{self.name}] Icon display {status}")
            elif key == "colorize":
                self.colorize = bool(new_value)
                changed = True
            elif key == "battery_align":
                self.align = str(new_value).lower()
                changed = True
            elif key == "battery_offset":
                try:
                    self.offset = int(new_value)
                except Exception:
                    pass
                changed = True
            elif key == "warn_threshold":
                try:
                    self.warn_threshold = int(new_value)
                    changed = True
                except Exception:
                    pass
            elif key == "crit_threshold":
                try:
                    self.crit_threshold = int(new_value)
                    changed = True
                except Exception:
                    pass
            elif key in ("voltage_min", "voltage_max"):
                # Update voltage range and rebuild table.
                try:
                    if key == "voltage_min":
                        self.v_min = float(new_value)
                    else:
                        self.v_max = float(new_value)
                    self._voltage_table = self._build_voltage_table()
                    # Recalculate current percent if we have latest voltage
                    try:
                        if self.sensor is not None:
                            v_now = self.sensor.bus_voltage()
                            raw_pct = self._voltage_to_percent(v_now)
                            self.percent = raw_pct
                            self.last_emit_percent = None
                    except Exception:
                        pass
                    changed = True
                except Exception as e:
                    print(f"[{self.name}] Voltage table rebuild failed: {e}")
            # If a visual / calculation element changed and we have a reading, emit updated event
            if changed and self.percent is not None:
                try:
                    pct_int = int(self.percent)
                    self.emit("battery.updated", percent=pct_int, voltage=None, ts=time.time(),
                              errors=self.read_errors, samples=self.samples_ok, reason=key)
                except Exception:
                    pass
        except Exception as e:
            print(f"[{self.name}] on_config_changed error for {key}: {e}")

    # ------------------------------------------------------------------
    # Menu helpers
    # ------------------------------------------------------------------
    def _menu_cycle_alignment(self):
        wctx = self.ctx.get('widget_context') if getattr(self, 'ctx', None) else None
        order = ['left', 'center', 'right']
        current = getattr(self, 'align', 'right')
        try:
            idx = (order.index(current) + 1) % len(order)
        except ValueError:
            idx = 0
        new_align = order[idx]
        self.align = new_align
        try:
            self.persist_option('battery_align', new_align)
        except Exception:
            pass
        if wctx:
            try:
                from ui.widgets import dialog_info as _dlg
                _dlg(wctx, f"Align: {new_align}", wait=True, center=True)
            except Exception:
                pass
        print(f"[{self.name}] alignment -> {new_align}")

    def _menu_set_offset(self):
        wctx = self.ctx.get('widget_context') if getattr(self, 'ctx', None) else None
        if not wctx:
            return
        try:
            from ui.widgets import numeric_picker, dialog_info
        except Exception:
            print(f"[{self.name}] numeric_picker unavailable")
            return
        current = int(getattr(self, 'offset', 0)) if hasattr(self, 'offset') else 0
        new_val = numeric_picker(wctx, label="OFF", min_value=-128, max_value=128, initial_value=current, step=1)
        if new_val == current:
            try:
                dialog_info(wctx, f"Offset unchanged\n{new_val}", wait=True, center=True)
            except Exception:
                pass
            return
        self.offset = new_val
        try:
            self.persist_option('battery_offset', int(new_val))
        except Exception:
            pass
        try:
            dialog_info(wctx, f"Offset set\n{new_val}", wait=True, center=True)
        except Exception:
            pass
        print(f"[{self.name}] offset -> {new_val}")

    def provide_menu_items(self):
        items = []
        items.append(("Battery Align", self._menu_cycle_alignment, "\uf037", 'Cycle overlay alignment'))
        items.append(("Battery Offset", self._menu_set_offset, "\uf07d", 'Set horizontal pixel offset'))
        return items

    # ------------------------------------------------------------------
    # Info reporting
    # ------------------------------------------------------------------
    def get_info(self) -> str:
        if not self.ok or self.sensor is None:
            info_lines = [
                "Battery monitoring unavailable",
                f"I2C Bus: {self.bus_num}",
                f"Address: 0x{self.addr:02X}",
                "Status: Sensor not found",
                "",
                "Requirements:",
                "• INA219 current sensor",
                "• I2C connection",
                "• smbus Python library"
            ]
            return "\n".join(info_lines)
        
        try:
            voltage = self.sensor.bus_voltage()
            current = self.sensor.current_a()
            power = self.sensor.power_w()
            shunt_v = self.sensor.shunt_voltage()
        except Exception as e:
            voltage = current = power = shunt_v = 0.0
        
        # Get current configuration
        enable_monitoring = self.get_config_value("enable_monitoring", True)
        show_percentage = self.get_config_value("show_percentage", True)
        show_icon = self.get_config_value("show_icon", True)
        
        info_lines = [
            f"Battery Level: {self.percent:.1f}%" if self.percent is not None else "Battery Level: Reading...",
            f"Bus Voltage: {voltage:.3f}V",
            f"Current: {current:.3f}A",
            f"Power: {power:.3f}W",
            f"Shunt Voltage: {shunt_v:.3f}V",
            "",
            "Current Configuration:",
            f"• Monitoring: {'ON' if enable_monitoring else 'OFF'}",
            f"• Show Percentage: {'ON' if show_percentage else 'OFF'}",
            f"• Show Icon: {'ON' if show_icon else 'OFF'}",
            f"• Warn Threshold: {self.warn_threshold}%",
            f"• Critical Threshold: {self.crit_threshold}%",
            f"• Colorize: {'ON' if self.colorize else 'OFF'}",
            "",
            "Hardware Configuration:",
            f"I2C Address: 0x{self.addr:02X}",
            f"I2C Bus: {self.bus_num}",
            f"Base Refresh: {self.base_refresh_interval}s (adaptive)",
            f"Voltage Range: {self.v_min}V - {self.v_max}V",
            "",
            f"Sensor Status: {'Active' if self.ok else 'Error'}",
            f"Samples OK: {self.samples_ok}  Errors: {self.read_errors}",
            f"Last Update: {time.strftime('%H:%M:%S', time.localtime(self._last_poll))}"
        ]
        return "\n".join(info_lines)

plugin = BatteryStatusPlugin()
