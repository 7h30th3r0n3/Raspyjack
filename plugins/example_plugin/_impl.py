"""Example Plugin Implementation

This file provides a fully documented reference implementation showing how to
create a RaspyJack plugin. Copy this folder, rename it, and adapt the code.

Key Concepts:
  * The class must inherit from plugins.base.Plugin
  * Provide a `plugin = YourClass()` instance at module level OR expose a subclass
  * Implement optional lifecycle hooks as needed
  * Define configuration options in `plugin.json` (config_schema)
  * Use on_config_changed() to react to runtime toggles
  * Keep every hook non‑blocking; long operations should spawn threads.

Lifecycle Hooks (all optional):
  on_load(ctx)                            - Called once after load
  on_unload()                             - Called before plugin manager shutdown/reload
  on_tick(dt)                             - Called periodically (~every 0.5s by default)
  on_button_event(event)                  - React to button events (new preferred method)
  on_render_overlay(image, draw)          - Draw lightweight overlay elements

Runtime Events (subscribe via self.on(pattern, handler)):
    payload.before_exec   -> handler(topic, data{payload_name})
    payload.after_exec    -> handler(topic, data{payload_name, success})
    scan.before           -> handler(topic, data{label, args})
    scan.after            -> handler(topic, data{label, args, result_path})

Configuration Schema:
  Declared statically in the plugin's `plugin.json` manifest under `config_schema`.
  Each key maps to a descriptor object with: type, label, description, default.
  Defaults are written to plugins_conf.json when the plugin is first discovered.

Event Bus:
    Use `self.emit('domain.event', key=value)` to publish and `self.on('pattern', handler)` to subscribe.
    Wildcards supported (e.g. `self.on('ethernet.*', handler)`).

Overlay Drawing:
  Keep it tiny: draw only what you need (text, small icons). Do not clear the
  whole frame. Use transparency if compositing an RGBA layer. Query current
  config values using self.get_config_value("key", fallback).

Threading / Safety:
  Avoid blocking in hooks. If you must perform IO, do it asynchronously.

"""
from __future__ import annotations
import time
from typing import Any, Dict

from plugins.base import Plugin


class ExamplePlugin(Plugin):

    # Internal state variables
    def __init__(self):
        self.ctx: Dict[str, Any] | None = None
        self._last_tick = 0.0
        self._counter = 0
        self._enabled_runtime_feature = True


    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def on_load(self, ctx: dict) -> None:
        """Initialize the plugin.

        The context dictionary currently contains helpers:
          exec_payload(name), is_responder_running(), is_mitm_running(),
          draw_image(), draw_obj(), status_bar
        """
        self.ctx = ctx
        self._last_tick = time.time()
        self._counter = 0
        self._enabled_runtime_feature = self.get_config_value("enable_runtime_feature", True)
        # Subscribe to runtime events
        self.on("payload.before_exec", self._on_payload_before)
        self.on("payload.after_exec", self._on_payload_after)
        self.on("scan.before", self._on_scan_before)
        self.on("scan.after", self._on_scan_after)
        print(f"[{self.name}] Loaded (runtime_feature={self._enabled_runtime_feature})")

    def on_unload(self) -> None:
        print(f"[{self.name}] Unloaded")

    # ------------------------------------------------------------------
    # Event Hooks
    # ------------------------------------------------------------------
    def on_tick(self, dt: float) -> None:
        # Called every tick (dt = seconds since last tick)
        if not self.get_config_value("show_counter", True):
            return
        # Simple rate limit: update internal counter every second
        now = time.time()
        if now - self._last_tick >= 1.0:
            self._last_tick = now
            self._counter += 1

    def on_button_event(self, event: dict) -> None:
        if self.get_config_value("enable_runtime_feature", True):
            print(f"[{self.name}] Button event {event.get('type')}: {event.get('button')}")

    def on_render_overlay(self, image, draw) -> None:
        # Draw a very small HUD element (avoid overlapping other plugins if possible)
        if not self.get_config_value("show_counter", True):
            return
        try:
            # If status bar is busy we can skip drawing (cooperative behavior)
            if self.ctx and 'status_bar' in self.ctx and self.ctx['status_bar'].is_busy():
                return
        except Exception:
            pass
        text = f"EX:{self._counter}"  # keep short to avoid layout conflicts
        draw.text((30, 0), text, fill="white")

    # (Legacy scan/payload hooks removed — using event bus subscriptions instead.)

    def _on_payload_before(self, topic: str, data: dict):
        print(f"[{self.name}] Before payload: {data.get('payload_name')}")

    def _on_payload_after(self, topic: str, data: dict):
        print(f"[{self.name}] After payload: {data.get('payload_name')} (success={data.get('success')})")

    def _on_scan_before(self, topic: str, data: dict):
        print(f"[{self.name}] Before scan: {data.get('label')} args={data.get('args')}")

    def _on_scan_after(self, topic: str, data: dict):
        print(f"[{self.name}] After scan: {data.get('label')} -> {data.get('result_path')}")

    # ------------------------------------------------------------------
    # Config change reaction
    # ------------------------------------------------------------------
    def on_config_changed(self, key: str, old_value, new_value) -> None:
        print(f"[{self.name}] Config changed: {key} {old_value} -> {new_value}")
        if key == "enable_runtime_feature":
            self._enabled_runtime_feature = bool(new_value)

    # ------------------------------------------------------------------
    # Info panel
    # ------------------------------------------------------------------
    def get_info(self) -> str:
        return "\n".join([
            f"Plugin: {self.name}",
            f"Counter: {self._counter}",
            f"Runtime Feature: {'ON' if self._enabled_runtime_feature else 'OFF'}",
            f"Show Counter HUD: {'ON' if self.get_config_value('show_counter', True) else 'OFF'}",
            "Hooks Implemented: tick, button_event, render_overlay, scan, payload",
            "Try toggling options in the Plugins > example_plugin menu.",
        ])


# Expose plugin instance for auto-discovery
plugin = ExamplePlugin()
