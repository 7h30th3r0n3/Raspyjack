"""Ethernet Hook Plugin

Monitors a configured Ethernet interface and triggers payload execution when
it gains or loses an IPv4 address.

Configuration options (auto-added to plugins_conf.json on first discovery):
  interface (str)
      Network interface name to monitor (default: eth0)
  show_status_icon (bool)
      Whether to draw a tiny Ethernet link icon in the status overlay when the
      interface has a valid IPv4.
  icon_horizontal_pos (number)
      Horizontal pixel X coordinate for the status icon (default: 30)
  on_ethernet_connected (list[str])
      Ordered list of payload script names to execute (sequentially) when the
      interface transitions from NO IP -> HAS IP.
  on_ethernet_disconnected (list[str])
      Ordered list of payload script names to execute (sequentially) when the
      interface transitions from HAS IP -> NO IP.

Execution model:
  - on_tick polls the interface state at a modest interval (poll every 2s)
  - Transitions are debounced: only fire once per actual change
  - Payloads are executed via the provided context['exec_payload'] helper in a
    background thread so UI is not blocked.

Notes:
  - Payload execution is best-effort; failures are logged but do not stop other payloads.
  - If multiple payloads are configured they run sequentially in the same thread.
  - IPv4 detection uses the `ip` command to avoid external dependencies.
"""
from __future__ import annotations

import subprocess
import threading
import time
from typing import Any, Dict, List

from plugins.base import Plugin

_POLL_INTERVAL = 2.0  # seconds


def _get_ipv4(interface: str) -> str | None:
    """Return IPv4 address (without mask) for interface or None if absent.

    We avoid complex shell / awk pipelines to keep things portable and reduce
    parsing issues (especially with braces in f-strings). Instead, run the
    `ip` command and parse lines starting with 'inet '.
    """
    try:
        # Example line: 'inet 192.168.1.42/24 brd 192.168.1.255 scope global eth0'
        res = subprocess.run(["ip", "-4", "addr", "show", interface], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                if len(parts) >= 2:
                    cidr = parts[1]
                    return cidr.split('/')[0]
    except Exception:
        pass
    return None


class EthernetHookPlugin(Plugin):

    def __init__(self):
        self.ctx: Dict[str, Any] | None = None
        self._last_poll = 0.0
        self._last_ip: str | None = None
        self._current_ip: str | None = None
        self._runner_lock = threading.Lock()
        self._pending_thread: threading.Thread | None = None
        self._fa_font = None  # lazy-loaded Font Awesome font


    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def on_load(self, ctx: dict) -> None:
        self.ctx = ctx
        # Load initial IP state
        iface = self._get_interface_name()
        self._current_ip = _get_ipv4(iface)
        self._last_ip = self._current_ip
        print(f"[EthernetHook] Monitoring {iface} (initial IP={self._current_ip or 'None'})")

    def on_unload(self) -> None:
        # Nothing persistent to clean up
        pass

    # ------------------------------------------------------------------
    # Helper accessors for configuration
    # ------------------------------------------------------------------
    def _get_interface_name(self) -> str:
        # 'interface' is stored outside boolean-only UI; fallback to eth0
        raw = self.get_config_value('interface', 'eth0')
        if isinstance(raw, str) and raw:
            return raw
        return 'eth0'

    def _get_payload_list(self, key: str) -> List[str]:
        cfg = getattr(self, 'config', None) or {}
        opts = cfg.get('options', {}) if isinstance(cfg, dict) else {}
        val = opts.get(key)
        if isinstance(val, list):
            return [v for v in val if isinstance(v, str) and v.strip()]
        return []

    # ------------------------------------------------------------------
    # Tick loop logic
    # ------------------------------------------------------------------
    def on_tick(self, dt: float) -> None:
        now = time.time()
        if now - self._last_poll < _POLL_INTERVAL:
            return
        self._last_poll = now

        iface = self._get_interface_name()
        self._current_ip = _get_ipv4(iface)
        prev = self._last_ip

        if prev != self._current_ip:
            # State changed
            if prev is None and self._current_ip is not None:
                # Connected event
                self._fire_hooks('ethernet.connected', self._current_ip)
            elif prev is not None and self._current_ip is None:
                # Disconnected event
                self._fire_hooks('ethernet.disconnected', prev)
            self._last_ip = self._current_ip

    # ------------------------------------------------------------------
    # Hook firing
    # ------------------------------------------------------------------
    def _fire_hooks(self, event_key: str, ip: str | None):
        payloads = self._get_payload_list(event_key)
        self.emit(event_key, interface=self._get_interface_name(), ip=ip)

        if not payloads:
            return

        if self._pending_thread and self._pending_thread.is_alive():
            # Skip launching another payload batch while one is active.
            print(f"[EthernetHook] Payload runner busy; skipping payloads for {event_key}")
            return

        def runner():
            print(f"[EthernetHook] Executing {event_key} payloads ({len(payloads)}) ip={ip or 'None'}")
            for p in payloads:
                try:
                    exec_payload = self.ctx.get('exec_payload') if self.ctx else None
                    if callable(exec_payload):
                        exec_payload(p)
                    else:
                        print(f"[EthernetHook] exec_payload helper not available for '{p}'")
                except Exception as e:
                    print(f"[EthernetHook] Payload '{p}' failed: {e}")
            print(f"[EthernetHook] Done {event_key}")

        self._pending_thread = threading.Thread(target=runner, daemon=True)
        self._pending_thread.start()

    # ------------------------------------------------------------------
    # Overlay icon
    # ------------------------------------------------------------------
    def on_render_overlay(self, image, draw) -> None:
        if not self.get_config_value('show_status_icon', True):
            return
        if self._current_ip is None:
            return
        # Attempt to use Font Awesome "network-wired" icon (unicode f6ff) centered in status bar (0..12 px)
        # If a status message is currently displayed, skip drawing to avoid overlap.
        try:
            if self.ctx and 'status_bar' in self.ctx:
                sb = self.ctx['status_bar']
                if hasattr(sb, 'is_busy') and sb.is_busy():
                    return
        except Exception:
            pass
        # Lazy-load font
        if self._fa_font is None:
            try:
                from PIL import ImageFont
                self._fa_font = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', 11)
            except Exception:
                self._fa_font = False  # sentinel
        if not self._fa_font:
            return  # Cannot draw icon
        icon_char = '\uf6ff'  # network-wired
        # Position within top bar using configured X clamped to screen.
        raw_x = self.get_config_value('icon_horizontal_pos', 30)
        try:
            cfg_x = int(raw_x)
        except (TypeError, ValueError):
            cfg_x = 30
        try:
            draw.text((cfg_x, 0), icon_char, font=self._fa_font, fill='white')
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Info panel
    # ------------------------------------------------------------------
    def get_info(self) -> str:
        iface = self._get_interface_name()
        connected = self._current_ip is not None
        payload_c = self._get_payload_list('on_ethernet_connected')
        payload_d = self._get_payload_list('on_ethernet_disconnected')
        return "\n".join([
            f"Interface: {iface}",
            f"Current IP: {self._current_ip or 'None'}",
            f"Status: {'CONNECTED' if connected else 'DISCONNECTED'}",
            "",
            f"Connect payloads: {payload_c or '[]'}",
            f"Disconnect payloads: {payload_d or '[]'}",
            f"Show Icon: {'YES' if self.get_config_value('show_status_icon', True) else 'NO'}",
        ])

    # ------------------------------------------------------------------
    # Menu integration
    # ------------------------------------------------------------------
    def _menu_set_icon_pos(self):
        """Interactive numeric picker to set icon horizontal position (0..120)."""
        try:
            # Lazy imports to avoid hard dependencies at load time
            from ui.widgets import numeric_picker, dialog_info
            # Obtain widget context from shared plugin context
            wctx = None
            if self.ctx:
                wctx = self.ctx.get('widget_context')
            if not wctx:
                print("[EthernetHook] Widget context not ready for numeric picker")
                return
            current = self.get_config_value('icon_horizontal_pos', 30)
            current_int = int(current)
            new_val = numeric_picker(wctx, label="ETH X", min_value=0, max_value=120, initial_value=current_int, step=1)
            if new_val == current_int:
                dialog_info(wctx, f"Ethernet Icon\nUnchanged ({new_val})", wait=True, center=True)
                return
            # Update in-memory config and persist
            self.set_config_value('icon_horizontal_pos', new_val)
            self.persist_option('icon_horizontal_pos', new_val, create_if_missing=True)
            dialog_info(wctx, f"Ethernet Icon\nX = {new_val}", wait=True, center=True)
        except Exception as e:
            print(f"[EthernetHook] Icon position picker error: {e}")

    def _menu_add_connect_payload(self):
        """Browse payload directory and append a script to on_ethernet_connected list."""
        try:
            if not self.ctx:
                return
            wctx = self.ctx.get('widget_context')
            if not wctx:
                print("[EthernetHook] Widget context not ready for payload picker")
                return
            # Lazy import helpers
            from ui.widgets import explorer, dialog_info, yn_dialog
            defaults_obj = self.ctx.get('defaults') if self.ctx else None
            if not defaults_obj or not hasattr(defaults_obj, 'payload_path'):
                print('[EthernetHook] defaults object with payload_path not available')
                return
            payload_base_path = getattr(defaults_obj, 'payload_path')
            selected = explorer(wctx, payload_base_path, extensions='.py|.sh')
            if not selected:
                return
            import os
            rel = os.path.relpath(selected, payload_base_path)
            if rel.startswith('..'):
                dialog_info(wctx, 'Invalid selection', wait=True, center=True)
                return
            # Confirm addition
            if not yn_dialog(wctx, question='Add payload?', yes_text='Yes', no_text='No', second_line=rel):
                return
            current_list = self.get_config_value('on_ethernet_connected', []) or []
            if rel in current_list:
                dialog_info(wctx, 'Already present', wait=True, center=True)
                return
            current_list.append(rel)
            # Update in-memory config & persist
            self.set_config_value('on_ethernet_connected', current_list)
            self.persist_option('on_ethernet_connected', current_list, create_if_missing=True)
            dialog_info(wctx, 'Added!', wait=True, center=True)
        except Exception as e:
            print(f"[EthernetHook] Add connect payload error: {e}")

    def _menu_clear_connect_payloads(self):
        """Clear all configured connect payloads after confirmation."""
        try:
            if not self.ctx:
                return
            wctx = self.ctx.get('widget_context')
            if not wctx:
                return
            from ui.widgets import dialog_info, yn_dialog
            current_list = self.get_config_value('on_ethernet_connected', []) or []
            if not current_list:
                dialog_info(wctx, 'List already empty', wait=True, center=True)
                return
            if not yn_dialog(wctx, question='Clear list?', yes_text='Yes', no_text='No', second_line=f'{len(current_list)} items'):
                return
            self.set_config_value('on_ethernet_connected', [])
            self.persist_option('on_ethernet_connected', [], create_if_missing=True)
            dialog_info(wctx, 'Cleared!', wait=True, center=True)
        except Exception as e:
            print(f"[EthernetHook] Clear connect payloads error: {e}")


    def provide_menu_items(self) -> list:
        """Expose custom submenu actions for this plugin."""
        return [
            ("Set Icon Position", self._menu_set_icon_pos, "\uf6ff", "Adjust Ethernet icon X (0-120)"),
            ("Add Connect Payload", self._menu_add_connect_payload, "\uf067", "Append payload to run on link up"),
            ("Clear Connect Payloads", self._menu_clear_connect_payloads, "\uf1f8", "Remove all connect payloads"),
        ]


plugin = EthernetHookPlugin()
