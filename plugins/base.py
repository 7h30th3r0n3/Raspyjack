"""Core plugin abstractions for RaspyJack.

Life‑cycle / callback methods (all optional):

    on_load(context: dict) -> None
        Called once right after the plugin is instantiated and registered.
        `context` contains helper callables and shared state references.
        Currently provided keys (may expand):
            exec_payload(name)          -> Run a payload script by relative filename.
            is_responder_running()      -> Bool indicating Responder activity.
            is_mitm_running()           -> Bool indicating MITM/sniff activity.
            draw_image()                -> PIL base image (DO NOT mutate globally — copy if needed).
            draw_obj()                  -> PIL ImageDraw tied to the base image.
            status_bar                  -> StatusBar instance (set_temp_status, is_busy, etc.).
            widget_context              -> WidgetContext instance (interactive UI helpers).
            plugin_manager              -> PluginManager instance (advanced access; prefer helpers below).
            defaults                    -> Defaults object (paths: install_path, payload_path, payload_log, etc.).

        Notes:
            - Some keys (widget_context, plugin_manager, defaults)
                are injected AFTER initial plugin load once the UI is fully initialized; if accessed
              inside on_load they may be None. Use on_tick or later, or defensively check for None.
            - Event bus helpers are available as instance methods: self.emit/self.on/self.once/self.off/self.off_pattern.
            - Avoid mutating objects you don't own (draw over small regions, never reassign globals).

    on_unload() -> None
        Called during shutdown (Leave) so the plugin can release resources.

    on_tick(dt: float) -> None
        Called periodically from the stats loop (roughly every cycle). Use this
        for polling hardware or timers. Keep it short (non‑blocking!).

    on_button_event(event: dict) -> None
        New pattern: receives a dictionary with keys:
            type   -> 'PRESS','RELEASE','CLICK','DOUBLE_CLICK','LONG_PRESS','REPEAT'
            button -> logical name (e.g. 'KEY_UP_PIN')
            ts     -> monotonic timestamp
            count  -> optional (multi-click)

    on_render_overlay(image, draw) -> None
        Gives a chance to draw on the current PIL image right before it is
        pushed to the LCD. Do not clear the whole screen; draw only what you
        own (e.g., small HUD elements). You can call other helpers from
        context if needed.

    provide_menu_items() -> list
        Return a list of custom menu entries to be added to this
        plugin's submenu in the UI. Each entry can be one of:
            - A MenuItem instance (preferred)
            - A tuple (label, callable)
            - A tuple (label, callable, icon) where icon is a Font Awesome
              glyph string. The core UI will wrap tuples into MenuItem objects.
        Use this to expose plugin-specific actions (e.g., quick commands,
        diagnostics) without modifying the core menu system. Called each time
        plugin menus are rebuilt, so it should be fast and side‑effect free.

Runtime events (now dispatched exclusively through the event bus; subscribe
with self.on(pattern, handler)):
    payload.before_exec   data: { payload_name }
    payload.after_exec    data: { payload_name, success }
    scan.before           data: { label, args }
    scan.after            data: { label, args, result_path }

Per-plugin bin exposure:
If a plugin package contains a `bin` directory, its executable files are
mirrored into the root `bin` directory (without overwriting existing files).
We attempt to create a small shim wrapper when running on non-Unix systems or
if symlinks are not permitted. This allows payloads to invoke plugin-provided
commands uniformly.
"""
from __future__ import annotations

from dataclasses import dataclass
import importlib
import time
import traceback
from types import ModuleType
from typing import List, Sequence
import os
import shutil


class Plugin:
    # Backing fields populated by loader from manifest
    _manifest_name: str | None = None
    _manifest_priority: int | None = None
    _manifest_requires: list[str] | None = None
    _manifest_config_schema: dict | None = None
    # Filled with plugin configuration block at runtime
    config: dict | None = None
    # Internal: path to module file (set by PluginManager) for persistence helpers
    _module_file: str | None = None

    # Properties expose manifest-sourced metadata (with sane fallbacks)
    @property
    def name(self) -> str:
        return self._manifest_name or self.__class__.__name__

    @name.setter
    def name(self, value: str) -> None:
        # Allow loader to assign; ignore empty
        if value:
            self._manifest_name = value

    @property
    def priority(self) -> int:
        return self._manifest_priority if isinstance(self._manifest_priority, int) else 100

    @priority.setter
    def priority(self, value: int) -> None:
        try:
            self._manifest_priority = int(value)
        except Exception:
            pass

    @property
    def requires(self) -> list[str]:
        return list(self._manifest_requires) if self._manifest_requires else []

    @requires.setter
    def requires(self, value):
        if isinstance(value, list):
            self._manifest_requires = [v for v in value if isinstance(v, str) and v]

    # --- Life‑cycle hooks -------------------------------------------------
    def on_load(self, ctx: dict) -> None: ...
    def on_unload(self) -> None: ...

    # --- Event hooks ------------------------------------------------------
    def on_tick(self, dt: float) -> None: ...
    def on_button_event(self, event: dict) -> None: ...
    def on_render_overlay(self, image, draw) -> None: ...
    def provide_menu_items(self) -> list: return []
    
    def get_info(self) -> str:
        return "No information available for this plugin."
    
    # --- Configuration system ---------------------------------------------
    
    def get_config_value(self, key: str, default=None):
        """Get current value of a configuration setting."""
        if not self.config:
            return default
        
        options = self.config.get('options', {})
        if key in options:
            return options[key]
        
        # Fallback to schema default if available
        schema = getattr(self, '_manifest_config_schema', {}) or {}
        if key in schema:
            return schema[key].get('default', default)
        return default
    
    def set_config_value(self, key: str, value) -> None:
        """Set a configuration value. Note: This only updates the in-memory config.
        Use PluginManager.save_plugin_config() to persist changes."""
        if not self.config:
            self.config = {}
        
        if 'options' not in self.config:
            self.config['options'] = {}
        
        self.config['options'][key] = value
    
    def on_config_changed(self, key: str, old_value, new_value) -> None:
        """Called when a configuration value changes. Override to react to config changes."""
        pass

    # --- Event bus convenience (assigned when loaded) -----------------
    def emit(self, event: str, **data) -> None:
        mgr = getattr(self, '_plugin_manager', None)
        if mgr and hasattr(mgr, 'emit_event'):
            mgr.emit_event(event, **data)

    def on(self, pattern: str, handler) -> None:
        mgr = getattr(self, '_plugin_manager', None)
        if mgr and hasattr(mgr, 'subscribe_event'):
            mgr.subscribe_event(pattern, handler)

    def once(self, pattern: str, handler) -> None:
        mgr = getattr(self, '_plugin_manager', None)
        if mgr and hasattr(mgr, 'once_event'):
            mgr.once_event(pattern, handler)

    def off(self, handler) -> None:
        mgr = getattr(self, '_plugin_manager', None)
        if mgr and hasattr(mgr, 'unsubscribe_event'):
            mgr.unsubscribe_event(handler)

    def off_pattern(self, pattern: str) -> None:
        mgr = getattr(self, '_plugin_manager', None)
        if mgr and hasattr(mgr, 'unsubscribe_event_pattern'):
            mgr.unsubscribe_event_pattern(pattern)

    # --- Persistence convenience -----------------------------------------
    def persist_option(self, key: str, value, create_if_missing: bool = True) -> bool:
        """Persist a single option value into plugins_conf.json for this plugin.

        Attempts to use runtime helpers (load_plugins_conf / save_plugins_conf)
        to avoid races with concurrent writes. Falls back to a direct JSON
        edit if those are unavailable. Silent best-effort; returns True on
        apparent success, False otherwise.

        Parameters:
            key: option key inside this plugin's options dict
            value: JSON-serializable value to store
            create_if_missing: if True, create plugin entry when absent
        """
        plugin_module_name = None
        try:
            # Determine plugin package folder name from owning module file path
            if self._module_file:
                import os
                plugin_module_name = os.path.basename(os.path.dirname(self._module_file))
            else:
                # Fallback: attempt to infer via class module path
                mod_name = self.__class__.__module__
                if mod_name.startswith('plugins.'):
                    plugin_module_name = mod_name.split('.')[1]
        except Exception:
            pass
        if not plugin_module_name:
            return False
        # First path: runtime helpers
        try:
            from plugins.runtime import load_plugins_conf as _load_conf, save_plugins_conf as _save_conf
            from pathlib import Path
            base = Path(self._module_file).resolve() if self._module_file else Path(__file__).resolve()
            while base.name != 'plugins' and base.parent != base:
                base = base.parent
            install_root = base.parent
            conf = _load_conf(str(install_root))
            entry = conf.get(plugin_module_name)
            if entry is None:
                if not create_if_missing:
                    return False
                entry = {'enabled': True, 'options': {}}
                conf[plugin_module_name] = entry
            opts = entry.setdefault('options', {})
            opts[key] = value
            _save_conf(conf, str(install_root))
            return True
        except Exception:
            return False


@dataclass
class _LoadedPlugin:
    instance: Plugin
    module: ModuleType


class PluginManager:
    """Loads and dispatches events to registered plugins."""

    def __init__(self, verbose: bool = True, event_bus=None):
        self._loaded: List[_LoadedPlugin] = []
        self._last_tick: float = time.time()
        self._ctx: dict = {}
        self.verbose = verbose
        # Event bus (wildcard capable) can be injected
        if event_bus is None:
            from .event_bus import EventBus
            event_bus = EventBus()
        self._event_bus = event_bus
        # Internal synchronization
        import threading
        self._lock = threading.RLock()
        # Overlay snapshot (RGBA) updated after ticks
        from PIL import Image
        self._overlay_image = Image.new('RGBA', (128, 128), (0, 0, 0, 0))

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    def load_all(self, module_names: Sequence[str], context: dict) -> None:
        with self._lock:
            self._ctx = context
            manifests = context.get('plugin_manifests', {}) if isinstance(context, dict) else {}
            for name in module_names:
                name = name.strip()
                if not name:
                    continue
                mod_qual = f"plugins.{name}"
                try:
                    mod = importlib.import_module(mod_qual)
                except Exception as e:
                    self._log(f"[PLUGIN] Failed to import '{mod_qual}': {e}")
                    self._log(traceback.format_exc())
                    continue

                instance = getattr(mod, "plugin", None)
                if instance is None:
                    for attr in dir(mod):
                        obj = getattr(mod, attr)
                        if isinstance(obj, type) and issubclass(obj, Plugin) and obj is not Plugin:
                            try:
                                instance = obj()
                            except Exception as e:
                                self._log(f"[PLUGIN] Could not instantiate {obj}: {e}")
                            break

                if instance is None:
                    self._log(f"[PLUGIN] No plugin object found in {mod_qual}")
                    continue

                # Apply manifest metadata prior to on_load
                manifest = manifests.get(name, {}) if isinstance(manifests, dict) else {}
                if manifest:
                    try:
                        if 'name' in manifest:
                            try: instance.name = manifest['name']
                            except Exception: pass
                        if 'priority' in manifest:
                            try: instance._manifest_priority = int(manifest['priority'])
                            except Exception: pass
                        if 'requires' in manifest and isinstance(manifest.get('requires'), list):
                            try: instance._manifest_requires = list(manifest['requires'])
                            except Exception: pass
                        if 'config_schema' in manifest and isinstance(manifest.get('config_schema'), dict):
                            try: instance._manifest_config_schema = manifest['config_schema']
                            except Exception: pass
                    except Exception:
                        pass

                try:
                    try:
                        setattr(instance, '_plugin_manager', self)
                    except Exception:
                        pass
                    instance.on_load(context)
                except Exception as e:
                    self._log(f"[PLUGIN] on_load error in {getattr(instance,'name', name)}: {e}")
                    self._log(traceback.format_exc())
                    continue
                try:
                    instance._module_file = getattr(mod, '__file__', None)
                except Exception:
                    pass

                self._loaded.append(_LoadedPlugin(instance=instance, module=mod))

            # Sort using manifest priority if present, fallback 100
            self._loaded.sort(key=lambda lp: getattr(lp.instance, '_manifest_priority', 100))
            if self.verbose:
                self._log("[PLUGIN] Loaded: " + ", ".join(getattr(p.instance, 'name', '?') for p in self._loaded) or "(none)")

    # ------------------------------------------------------------------
    # New configuration based loading
    # ------------------------------------------------------------------
    def load_from_config(self, config: dict, context: dict) -> None:
        """Load plugins from a config mapping.

        Expected structure (JSON example)::

            {
              "example_plugin": {
                "enabled": true,
                "priority": 50,
                "options": {"show_seconds": true}
              },
              "other_plugin": {
                "enabled": false
              }
            }

        Any plugin with enabled set to false (or missing) is skipped.
        """
        with self._lock:
            self._ctx = context
            # Perform a dependency-aware multi-pass load.
            manifests = context.get('plugin_manifests', {}) if isinstance(context, dict) else {}
            pending: dict[str, tuple[dict, ModuleType | None, Plugin | None, dict]] = {}
            for module_name, pconf in config.items():
                if not isinstance(pconf, dict) or not pconf.get("enabled", False):
                    continue
                manifest = manifests.get(module_name, {}) if isinstance(manifests, dict) else {}
                pending[module_name] = (pconf, None, None, manifest)

            progressed = True
            while progressed and pending:
                progressed = False
                for module_name in list(pending.keys()):
                    pconf, mod_ref, inst_ref, manifest = pending[module_name]
                    mod_qual = f"plugins.{module_name}"
                    if mod_ref is None:
                        try:
                            mod_ref = importlib.import_module(mod_qual)
                        except Exception as e:
                            self._log(f"[PLUGIN] Failed to import '{mod_qual}': {e}")
                            del pending[module_name]
                            continue
                    if inst_ref is None:
                        inst_ref = getattr(mod_ref, "plugin", None)
                        if inst_ref is None:
                            for attr in dir(mod_ref):
                                obj = getattr(mod_ref, attr)
                                if isinstance(obj, type) and issubclass(obj, Plugin) and obj is not Plugin:
                                    try:
                                        inst_ref = obj()
                                    except Exception as e:
                                        self._log(f"[PLUGIN] Could not instantiate {obj}: {e}")
                                    break
                        if inst_ref is None:
                            self._log(f"[PLUGIN] No plugin object found in {mod_qual}")
                            del pending[module_name]
                            continue
                    # Apply manifest metadata before dependency resolution
                    try:
                        if manifest:
                            if 'priority' in manifest:
                                try: inst_ref._manifest_priority = int(manifest['priority'])
                                except Exception: pass
                            if 'requires' in manifest and isinstance(manifest.get('requires'), list):
                                try: inst_ref._manifest_requires = list(manifest['requires'])
                                except Exception: pass
                            if 'name' in manifest:
                                try: inst_ref.name = manifest['name']
                                except Exception: pass
                            if 'config_schema' in manifest and isinstance(manifest.get('config_schema'), dict):
                                try: inst_ref._manifest_config_schema = manifest['config_schema']
                                except Exception: pass
                    except Exception:
                        pass
                    # Check dependencies (could be from manifest or class attribute)
                    reqs = getattr(inst_ref, '_manifest_requires', None) or []
                    unmet = [r for r in reqs if not self._is_module_loaded(r)]
                    if unmet:
                        # Dependency not yet loaded; skip this round
                        pending[module_name] = (pconf, mod_ref, inst_ref, manifest)
                        continue
                    # Apply config
                    if "priority" in pconf:
                        try: inst_ref._manifest_priority = int(pconf["priority"])
                        except Exception: pass
                    inst_ref.config = pconf
                    if "options" in pconf and isinstance(pconf["options"], dict):
                        inst_ref.options = pconf["options"]
                    # Load
                    try:
                        try:
                            setattr(inst_ref, '_plugin_manager', self)
                        except Exception:
                            pass
                        inst_ref.on_load(context)
                    except Exception as e:
                        self._log(f"[PLUGIN] on_load error in {inst_ref.name}: {e}")
                        del pending[module_name]
                        continue
                    try:
                        inst_ref._module_file = getattr(mod_ref, '__file__', None)
                    except Exception:
                        pass
                    self._loaded.append(_LoadedPlugin(instance=inst_ref, module=mod_ref))
                    try:
                        self._expose_plugin_bin(mod_ref)
                    except Exception as e:
                        self._log(f"[PLUGIN] bin expose error for {module_name}: {e}")
                    del pending[module_name]
                    progressed = True
            # Report unresolved dependencies
            for leftover in pending.keys():
                self._log(f"[PLUGIN] Skipped '{leftover}' due to unmet dependencies: {getattr(pending[leftover][2], '_manifest_requires', None)}")
            self._loaded.sort(key=lambda lp: getattr(lp.instance, '_manifest_priority', 100))
            if self.verbose:
                self._log("[PLUGIN] Loaded (config): " + ", ".join(p.instance.name for p in self._loaded) or "(none)")

    def unload_all(self) -> None:
        with self._lock:
            for lp in self._loaded:
                try:
                    lp.instance.on_unload()
                except Exception as e:
                    self._log(f"[PLUGIN] on_unload error in {lp.instance.name}: {e}")
            self._loaded.clear()

    # ------------------------------------------------------------------
    # Dispatch helpers
    # ------------------------------------------------------------------
    def dispatch_tick(self) -> None:
        with self._lock:
            now = time.time()
            dt = now - self._last_tick
            self._last_tick = now
            for lp in self._loaded:
                try:
                    lp.instance.on_tick(dt)
                except Exception:
                    self._log(f"[PLUGIN] tick error in {lp.instance.name}")

    def dispatch_button_event(self, event: dict) -> None:
        """Dispatch a rich button event (PRESS, RELEASE, LONG_PRESS, etc.)."""
        with self._lock:
            for lp in self._loaded:
                try:
                    lp.instance.on_button_event(event)
                except Exception:
                    self._log(f"[PLUGIN] button_event error in {lp.instance.name}")

    def dispatch_render_overlay(self, image, draw) -> None:
        # This remains for legacy direct rendering paths; prefer overlay snapshot methods.
        with self._lock:
            for lp in self._loaded:
                try:
                    lp.instance.on_render_overlay(image, draw)
                except Exception:
                    self._log(f"[PLUGIN] render_overlay error in {lp.instance.name}")

    # --- Overlay snapshot pipeline ---------------------------------
    def rebuild_overlay(self, size: tuple[int, int] = (128, 128)) -> None:
        """Rebuild cached overlay by invoking plugins on a fresh RGBA layer."""
        from PIL import Image, ImageDraw
        tmp = Image.new('RGBA', size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(tmp)
        with self._lock:
            for lp in self._loaded:
                try:
                    lp.instance.on_render_overlay(tmp, draw)
                except Exception:
                    self._log(f"[PLUGIN] rebuild_overlay error in {lp.instance.name}")
            self._overlay_image = tmp  # atomic swap

    def get_overlay(self):
        """Return last built overlay (do not mutate)."""
        return self._overlay_image

    def get_plugin_info(self, name: str) -> str:
        """Get info string from a specific plugin by name."""
        for lp in self._loaded:
            # Compare against the module name, not the class name
            module_short_name = lp.module.__name__.split('.')[-1]
            if module_short_name == name:
                try:
                    return lp.instance.get_info()
                except Exception as e:
                    self._log(f"[PLUGIN] get_info error in {lp.instance.name}: {e}")
                    return "Error getting info."
        return "Plugin not loaded or without info."
    
    def get_plugin_config_schema(self, name: str) -> dict:
        """Get configuration schema (manifest-defined) for a specific plugin by module name."""
        for lp in self._loaded:
            module_short_name = lp.module.__name__.split('.')[-1]
            if module_short_name == name:
                return getattr(lp.instance, '_manifest_config_schema', {}) or {}
        return {}
    
    def get_plugin_config_value(self, plugin_name: str, config_key: str, default=None):
        """Get current configuration value for a plugin."""
        for lp in self._loaded:
            module_short_name = lp.module.__name__.split('.')[-1]
            if module_short_name == plugin_name:
                try:
                    return lp.instance.get_config_value(config_key, default)
                except Exception as e:
                    self._log(f"[PLUGIN] get_config_value error in {lp.instance.name}: {e}")
                    return default
        return default
    
    def set_plugin_config_value(self, plugin_name: str, config_key: str, value) -> bool:
        """Set configuration value for a plugin and notify of change."""
        for lp in self._loaded:
            module_short_name = lp.module.__name__.split('.')[-1]
            if module_short_name == plugin_name:
                try:
                    old_value = lp.instance.get_config_value(config_key)
                    lp.instance.set_config_value(config_key, value)
                    try:
                        lp.instance.on_config_changed(config_key, old_value, value)
                    except Exception as e:
                        self._log(f"[PLUGIN] on_config_changed error in {lp.instance.name}: {e}")
                    return True
                except Exception as e:
                    self._log(f"[PLUGIN] set_config_value error in {lp.instance.name}: {e}")
                    return False
        return False

    # ------------------------------------------------------------------
    # Utils
    # ------------------------------------------------------------------
    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    # ------------------------------------------------------------------
    # Event Bus
    # ------------------------------------------------------------------
    def subscribe_event(self, event: str, handler) -> None:
        """Subscribe a handler(event_name: str, data: dict) to an event (supports wildcards)."""
        if self._event_bus is not None:
            self._event_bus.subscribe(event, handler)

    def once_event(self, event: str, handler) -> None:
        if self._event_bus is not None:
            try:
                self._event_bus.once(event, handler)
            except Exception:
                self._log(f"[PLUGIN] event bus once error for {event}")

    def emit_event(self, event: str, **data) -> None:
        """Emit an event to all subscribers (wildcard patterns honored)."""
        if self._event_bus is not None:
            try:
                self._event_bus.emit(event, **data)
            except Exception:
                self._log(f"[PLUGIN] event bus emit error for {event}")

    def unsubscribe_event(self, handler) -> None:
        if self._event_bus is not None:
            try:
                self._event_bus.unsubscribe(handler)
            except Exception:
                self._log("[PLUGIN] event bus unsubscribe error")

    def unsubscribe_event_pattern(self, pattern: str) -> None:
        if self._event_bus is not None:
            try:
                self._event_bus.unsubscribe_pattern(pattern)
            except Exception:
                self._log("[PLUGIN] event bus unsubscribe_pattern error")

    def get_event_bus(self):
        return self._event_bus

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------
    def get_plugin_instance(self, module_name: str):
        for lp in self._loaded:
            if lp.module.__name__.split('.')[-1] == module_name:
                return lp.instance
        return None

    def _is_module_loaded(self, module_name: str) -> bool:
        for lp in self._loaded:
            if lp.module.__name__.split('.')[-1] == module_name:
                return True
        return False

    # ------------------------------------------------------------------
    # Bin exposure helpers
    # ------------------------------------------------------------------
    def _expose_plugin_bin(self, module: ModuleType) -> None:
        """Expose executables from a plugin's bin/ directory into top-level bin/.
            - Detect plugin package path via module.__file__.
            - Look for sibling 'bin' directory.
            - For each entry (file) without extension (or any executable), create
            a symlink under project_root/bin if possible; otherwise create a
            small wrapper script that calls the source file with Python or shell.
            - Never overwrite existing targets; log and skip collisions.
        """
        mod_file = getattr(module, '__file__', None)
        if not mod_file:
            return
        plugin_dir = os.path.dirname(mod_file)
        bin_dir = os.path.join(plugin_dir, 'bin')
        if not os.path.isdir(bin_dir):
            return
        # project root assumed two levels up from plugins package file path
        # e.g., /path/Raspyjack/plugins/my_plugin/__init__.py
        project_root = plugin_dir
        while project_root and os.path.basename(project_root) != 'Raspyjack' and os.path.dirname(project_root) != project_root:
            project_root = os.path.dirname(project_root)
        top_bin = os.path.join(project_root, 'bin')
        if not os.path.isdir(top_bin):
            try:
                os.makedirs(top_bin, exist_ok=True)
            except Exception:
                return
        for name in os.listdir(bin_dir):
            src_path = os.path.join(bin_dir, name)
            if os.path.isdir(src_path):
                continue
            dest_path = os.path.join(top_bin, name)
            if os.path.exists(dest_path):
                # Do not overwrite existing global command
                continue
            
            # Ensure source file has execute permissions first
            try:
                os.chmod(src_path, 0o755)
            except Exception:
                pass
            
            try:
                # Try symlink first
                os.symlink(src_path, dest_path)
                self._log(f"[PLUGIN] Created symlink: bin/{name} -> {src_path}")
                # For symlinks, also ensure destination has correct permissions
                try:
                    os.chmod(dest_path, 0o755)
                except Exception:
                    pass
            except Exception:
                # Fallback: copy or create wrapper
                try:
                    shutil.copy2(src_path, dest_path)
                    self._log(f"[PLUGIN] Copied executable: bin/{name} from {src_path}")
                    # Ensure copied file has execute permissions
                    try:
                        os.chmod(dest_path, 0o755)
                    except Exception:
                        pass
                except Exception:
                    # Last resort: create python wrapper if src is .py
                    if src_path.endswith('.py'):
                        with open(dest_path, 'w', encoding='utf-8') as f:
                            f.write('#!/usr/bin/env python3\n')
                            f.write(f"import runpy, sys; sys.path.insert(0, '{plugin_dir}'); runpy.run_path('{src_path}', run_name='__main__')\n")
                        self._log(f"[PLUGIN] Created Python wrapper: bin/{name} for {src_path}")
                        try:
                            os.chmod(dest_path, 0o755)
                        except Exception:
                            pass

    @property
    def plugins(self) -> List[Plugin]:
        return [lp.instance for lp in self._loaded]
