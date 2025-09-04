"""Screenshot Plugin

Captures the current framebuffer image when the user performs a LONG_PRESS
on KEY2_PIN and saves it under screenshots/ with a timestamped filename.

Event usage:
  - Listens to on_button_event for LONG_PRESS of KEY2_PIN.
  - Debounces so only one capture per long press activation.

File format: PNG (lossless, small for 128x128).
"""
from __future__ import annotations
import os
from datetime import datetime
import time
from plugins.base import Plugin

class ScreenshotPlugin(Plugin):

    def __init__(self):
        self.ctx = None
        self._last_capture_ts = 0.0
        self._screens_dir = None
        self._last_periodic = 0.0
        self._periodic_enabled = False
        self._periodic_interval = 60.0

    def on_load(self, ctx: dict) -> None:
        self.ctx = ctx
        self._periodic_enabled = bool(self.get_config_value('periodic_enabled', False))
        self._periodic_interval = float(self.get_config_value('periodic_interval', 60))
        self._periodic_interval = max(5.0, self._periodic_interval)
        print(f"[{self.name}] Plugin loaded. Hold KEY2 for screenshot.")

    def _ensure_dir_ready(self):
        if self._screens_dir and os.path.isdir(self._screens_dir):
            return
        install_root = getattr(self.ctx['defaults'], 'install_path', '/root/Raspyjack')
        self._screens_dir = os.path.join(install_root, 'screenshots')
        try:
            os.makedirs(self._screens_dir, exist_ok=True)
            self.emit('screenshot.directory.ready', path=self._screens_dir)
        except Exception as e:
            print(f"[{self.name}] Could not create screenshots directory: {e}")
            self.emit('screenshot.directory.error', path=self._screens_dir, error=str(e))

    def _capture(self, periodic: bool = False):
        if not self.ctx:
            return
        self._ensure_dir_ready()
        try:
            self.emit('screenshot.capture.start', periodic=periodic)
            img = self.ctx['draw_image']()
            # Copy to avoid race with render loop
            snap = img.copy()
            ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
            fname = f"shot_{ts}.png"
            target = os.path.join(self._screens_dir or '.', fname)
            snap.save(target, format='PNG')
            print(f"[{self.name}] Saved {target}")
            self.emit('screenshot.captured', file=target, timestamp=ts, periodic=periodic)
            # Temporary status bar message
            try:
                if 'status_bar' in self.ctx and self.ctx['status_bar']:
                    if not self.ctx['status_bar'].is_busy():
                        self.ctx['status_bar'].set_temp_status("Screenshot saved", 2.0)
            except Exception:
                pass
        except Exception as e:
            print(f"[{self.name}] Capture failed: {e}")
            self.emit('screenshot.capture.failed', error=str(e), periodic=periodic)

    def on_button_event(self, event: dict) -> None:
        if event.get('type') == 'LONG_PRESS' and event.get('button') == 'KEY2_PIN':
            self._capture(periodic=False)

    def on_tick(self, dt: float) -> None:
        if not self._periodic_enabled:
            return
        now = time.time()
        if (now - self._last_periodic) >= self._periodic_interval:
            self._last_periodic = now
            self._capture(periodic=True)

    def on_config_changed(self, key: str, old_value, new_value) -> None:
        if key == 'periodic_enabled':
            self._periodic_enabled = bool(new_value)
            if self._periodic_enabled:
                self._last_periodic = 0.0  # force immediate on next tick
        elif key == 'periodic_interval':
            try:
                self._periodic_interval = max(5.0, float(new_value))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Menu integration
    # ------------------------------------------------------------------
    def _menu_set_periodic_interval(self):
        """Interactive numeric picker to adjust periodic capture interval.

        Shown only when periodic captures are enabled. Uses the shared
        widget numeric picker (range 5..3600 seconds). Persists the new
        value into plugin configuration so it survives restarts.
        """
        if not self._periodic_enabled:
            return
        try:
            wctx = self.ctx.get('widget_context') if self.ctx else None
            if not wctx:
                return
            from ui.widgets import numeric_picker, dialog_info
            current = int(self._periodic_interval)
            new_val = numeric_picker(wctx, label="SECS", min_value=5, max_value=3600, initial_value=current, step=5)
            if new_val == current:
                dialog_info(wctx, f"Interval unchanged\n{new_val}s", wait=True, center=True)
                return
            old = self._periodic_interval
            self.set_config_value('periodic_interval', new_val)
            self._periodic_interval = float(new_val)
            # Persist (best-effort)
            try:
                self.persist_option('periodic_interval', new_val, create_if_missing=True)
            except Exception:
                pass
            # Notify change hook manually since we bypass manager helper
            try:
                self.on_config_changed('periodic_interval', old, new_val)
            except Exception:
                pass
            dialog_info(wctx, f"Interval set\n{new_val}s", wait=True, center=True)
        except Exception as e:
            print(f"[ScreenshotPlugin] Interval picker error: {e}")

    def provide_menu_items(self):
        if not self._periodic_enabled:
            return []
        # (label, callable, icon, description)
        return [
            ("Periodic Interval", self._menu_set_periodic_interval, "\uf017", "Set periodic screenshot interval (s)")
        ]

    def get_info(self) -> str:
        """Return status information about stored screenshots.

        Shows directory path, number of PNG files, last capture timestamp
        (based on filename ordering), and approximate total size.
        """
        self._ensure_dir_ready()
        if not self._screens_dir:
            return "Screenshots directory not initialized"
        try:
            files = [f for f in os.listdir(self._screens_dir) if f.lower().endswith('.png')]
            count = len(files)
            last = sorted(files)[-1] if files else "(none)"
            total_bytes = 0
            for f in files:
                try:
                    total_bytes += os.path.getsize(os.path.join(self._screens_dir, f))
                except Exception:
                    pass
            size_kb = total_bytes / 1024.0
            lines = [
                f"Directory: {self._screens_dir}",
                f"Files: {count}",
                f"Last: {last}",
                f"Total Size: {size_kb:.1f} KB",
                "Trigger: LONG_PRESS KEY2_PIN",
            ]
            return "\n".join(lines)
        except Exception as e:
            return f"Error reading screenshots: {e}"

plugin = ScreenshotPlugin()
