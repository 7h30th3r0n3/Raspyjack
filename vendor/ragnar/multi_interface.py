"""Multi-interface coordination utilities for Ragnar."""

from __future__ import annotations

import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass
import threading
import time
from typing import Dict, List, Optional

from logger import Logger
from wifi_interfaces import gather_wifi_interfaces, gather_ethernet_interfaces, is_ethernet_available, get_active_ethernet_interface, is_link_local_ip

logger = Logger(name="multi_interface", level=logging.INFO)


@dataclass
class ScanJob:
    """Represents a scheduled Wi-Fi or Ethernet scanning job for a network interface."""
    interface: str
    ssid: str
    role: str
    ip_address: Optional[str] = None
    cidr: Optional[int] = None
    network_cidr: Optional[str] = None
    interface_type: str = 'wifi'  # 'wifi' or 'ethernet'


class NetworkContextRegistry:
    """Provides safe context switching between per-network storage roots."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._lock = threading.RLock()

    def _snapshot_current(self) -> Optional[Dict[str, str]]:
        ssid = self.shared_data.active_network_ssid
        try:
            return self.shared_data.storage_manager.get_context_snapshot(ssid)
        except Exception as exc:
            logger.warning(f"Unable to snapshot current network context: {exc}")
            return None

    def _apply_context(self, context: Optional[Dict[str, str]]):
        if not context:
            return
        self.shared_data._apply_network_context(context, configure_db=False)
        self.shared_data._refresh_network_components()

    @contextmanager
    def activate(self, ssid: Optional[str]):
        """Temporarily switch shared data to the requested SSID context."""
        if not ssid:
            yield None
            return

        with self._lock:
            previous_context = self._snapshot_current()
            target_context = self.shared_data.storage_manager.get_context_snapshot(ssid)
            self._apply_context(target_context)

        try:
            yield target_context
        finally:
            with self._lock:
                self._apply_context(previous_context)


class MultiInterfaceState:
    """Tracks Wi-Fi and Ethernet interfaces and orchestrates multi-network scanning limits."""

    MODE_SINGLE = 'single'
    MODE_MULTI = 'multi'
    _iface_pattern = re.compile(r'^[A-Za-z0-9_.:-]+$')

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._lock = threading.RLock()
        self.interfaces: Dict[str, Dict] = {}
        self.ethernet_interfaces: Dict[str, Dict] = {}
        raw_overrides = shared_data.config.get('wifi_scan_interface_overrides') or {}
        self.scan_overrides: Dict[str, bool] = {k: bool(v) for k, v in raw_overrides.items()}
        self.last_refresh = 0.0
        self.ethernet_last_refresh = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def refresh_from_system(self) -> List[Dict]:
        """Probe system interfaces and update cached state."""
        default_iface = self.shared_data.config.get('wifi_default_interface', 'wlan0')
        discovered = gather_wifi_interfaces(default_iface)
        self.sync_from_interfaces(discovered)
        # Also refresh Ethernet interfaces
        self.refresh_ethernet_interfaces()
        return discovered

    def refresh_ethernet_interfaces(self) -> List[Dict]:
        """Probe Ethernet interfaces and update cached state."""
        default_eth = self.shared_data.config.get('ethernet_default_interface', 'eth0')
        discovered = gather_ethernet_interfaces(default_eth)
        self.sync_ethernet_interfaces(discovered)
        return discovered

    def sync_ethernet_interfaces(self, interfaces: List[Dict]):
        """Sync Ethernet interface metadata."""
        timestamp = time.time()
        ethernet_scan_enabled = self.shared_data.config.get('ethernet_scan_enabled', True)
        default_eth = self.shared_data.config.get('ethernet_default_interface', 'eth0')

        with self._lock:
            new_state: Dict[str, Dict] = {}
            for iface in interfaces:
                name = iface.get('name')
                if not name:
                    continue

                has_carrier = iface.get('has_carrier', False)
                is_connected = iface.get('connected', False)
                ip_address = iface.get('ip_address')
                
                # Check for link-local IP (169.254.x.x) - not a valid connection
                has_link_local = is_link_local_ip(ip_address)
                if has_link_local:
                    logger.debug(f"Ethernet interface {name} has link-local IP - treating as not connected")
                    ip_address = None
                    is_connected = False

                # Determine if this interface can be used for scanning
                # Requires: enabled, carrier, connected, valid (non-link-local) IP
                can_scan = ethernet_scan_enabled and has_carrier and is_connected and ip_address and not has_link_local

                entry = {
                    'name': name,
                    'type': 'ethernet',
                    'role': 'internal' if name == default_eth else 'external',
                    'state': iface.get('state', 'UNKNOWN'),
                    'connected': is_connected,
                    'has_carrier': has_carrier,
                    'ip_address': ip_address,
                    'cidr': iface.get('cidr'),
                    'network_cidr': iface.get('network_cidr'),
                    'mac_address': iface.get('mac_address'),
                    'scan_enabled': can_scan,
                    'last_refresh': timestamp,
                    'is_link_local': has_link_local,
                    'reason': None if can_scan else ('link_local' if has_link_local else 'disabled' if not ethernet_scan_enabled else 'no_connection'),
                }
                new_state[name] = entry

            self.ethernet_interfaces = new_state
            self.ethernet_last_refresh = timestamp

    def get_ethernet_status(self) -> Dict:
        """Get current Ethernet interface status."""
        with self._lock:
            active_interface = None
            for iface in self.ethernet_interfaces.values():
                # Only consider interfaces with valid (non-link-local) IPs
                if (iface.get('connected') and 
                    iface.get('has_carrier') and 
                    iface.get('ip_address') and
                    not iface.get('is_link_local')):
                    active_interface = iface
                    break

            ethernet_scan_enabled = self.shared_data.config.get('ethernet_scan_enabled', True)
            has_active_connection = active_interface is not None

            return {
                'available': bool(self.ethernet_interfaces),
                'active': has_active_connection,
                'active_interface': active_interface,
                'interfaces': list(self.ethernet_interfaces.values()),
                'scan_enabled': ethernet_scan_enabled,
                'can_toggle_scan': has_active_connection,
                'last_refresh': self.ethernet_last_refresh,
            }

    def set_ethernet_scan_enabled(self, enabled: bool) -> Dict:
        """Enable or disable scanning over Ethernet."""
        self.shared_data.config['ethernet_scan_enabled'] = bool(enabled)
        self.shared_data.save_config()

        # Refresh to apply new setting
        self.refresh_ethernet_interfaces()
        return self.get_ethernet_status()

    def get_preferred_scan_interface(self) -> Optional[Dict]:
        """
        Get the preferred interface for scanning.
        If Ethernet is available and preferred, use it. Otherwise use WiFi.
        """
        prefer_ethernet = self.shared_data.config.get('ethernet_prefer_over_wifi', True)
        ethernet_scan_enabled = self.shared_data.config.get('ethernet_scan_enabled', True)

        if prefer_ethernet and ethernet_scan_enabled:
            with self._lock:
                for iface in self.ethernet_interfaces.values():
                    if iface.get('connected') and iface.get('has_carrier') and iface.get('ip_address'):
                        return {**iface, 'preferred_reason': 'ethernet_preferred'}

        # Fall back to WiFi
        with self._lock:
            for iface in self.interfaces.values():
                if iface.get('connected') and iface.get('ip_address'):
                    return {**iface, 'type': 'wifi', 'preferred_reason': 'wifi_fallback'}

        return None

    def sync_from_interfaces(self, interfaces: List[Dict]):
        """Sync incoming interface metadata (from nmcli, wifi manager, or API)."""
        selected = self._select_interfaces(interfaces)
        timestamp = time.time()
        global_enabled = self.is_multi_mode_enabled()
        default_iface = self.shared_data.config.get('wifi_default_interface', 'wlan0')
        focus_interface = self.get_focus_interface()

        with self._lock:
            new_state: Dict[str, Dict] = {}
            for iface in selected:
                name = iface.get('name')
                if not name:
                    continue
                role = 'internal' if name == default_iface else 'external'
                base_enabled = self._resolve_enabled_flag(name, global_enabled)
                entry = {
                    'name': name,
                    'role': role,
                    'state': iface.get('state', 'UNKNOWN'),
                    'connected': bool(iface.get('connected')),
                    'connected_ssid': iface.get('connected_ssid'),
                    'ip_address': iface.get('ip_address'),
                    'cidr': iface.get('cidr'),
                    'network_cidr': iface.get('network_cidr'),
                    'mac_address': iface.get('mac_address'),
                    'scan_enabled': base_enabled,
                    'last_refresh': timestamp,
                    'reason': None,
                    'focus_selected': bool(name and name == focus_interface),
                }

                if not global_enabled:
                    entry['scan_enabled'] = False
                    entry['reason'] = 'global_disabled'
                elif not entry['connected_ssid']:
                    entry['scan_enabled'] = False
                    entry['reason'] = 'no_ssid'
                elif not entry['connected']:
                    entry['scan_enabled'] = False
                    entry['reason'] = 'disconnected'

                new_state[name] = entry

            self.interfaces = new_state
            self.last_refresh = timestamp
            self._refresh_focus_flags()

    def get_scan_jobs(self) -> List[ScanJob]:
        """Return all scan jobs respecting interface limits and enable flags.

        Ethernet interfaces are added first when preferred (they are faster and
        more reliable than WiFi for local-network scanning).  WiFi interfaces
        fill the remaining slots up to *max_interfaces*.
        """
        max_interfaces = max(1, int(self.shared_data.config.get('wifi_multi_scan_max_interfaces', 2)))
        if not self.is_multi_mode_enabled():
            logger.info("[MULTI-SCAN] get_scan_jobs: multi mode not enabled, returning empty")
            return []

        prefer_ethernet = self.shared_data.config.get('ethernet_prefer_over_wifi', True)
        ethernet_scan_enabled = self.shared_data.config.get('ethernet_scan_enabled', True)

        jobs: List[ScanJob] = []

        with self._lock:
            # --- Ethernet interfaces first (if preferred) ---
            if prefer_ethernet and ethernet_scan_enabled:
                for entry in self.ethernet_interfaces.values():
                    if len(jobs) >= max_interfaces:
                        break
                    if not entry.get('connected') or not entry.get('ip_address'):
                        continue
                    if entry.get('is_link_local'):
                        continue
                    logger.info(f"[MULTI-SCAN] Adding ethernet job: {entry.get('name')} -> {entry.get('ip_address')}")
                    jobs.append(
                        ScanJob(
                            interface=entry['name'],
                            ssid='LAN',
                            role='ethernet',
                            ip_address=entry.get('ip_address'),
                            cidr=entry.get('cidr'),
                            network_cidr=entry.get('network_cidr'),
                            interface_type='ethernet',
                        )
                    )

            # --- WiFi interfaces ---
            logger.info(f"[MULTI-SCAN] get_scan_jobs: checking {len(self.interfaces)} wifi + {len(self.ethernet_interfaces)} ethernet (max={max_interfaces})")
            for entry in self.interfaces.values():
                if len(jobs) >= max_interfaces:
                    break
                if not entry.get('scan_enabled'):
                    continue
                if not entry.get('connected') or not entry.get('connected_ssid'):
                    continue
                logger.info(f"[MULTI-SCAN] Adding wifi job: {entry.get('name')} -> {entry.get('connected_ssid')}")
                jobs.append(
                    ScanJob(
                        interface=entry['name'],
                        ssid=entry['connected_ssid'],
                        role=entry['role'],
                        ip_address=entry.get('ip_address'),
                        cidr=entry.get('cidr'),
                        network_cidr=entry.get('network_cidr'),
                        interface_type='wifi',
                    )
                )

            # --- Ethernet at end if not preferred but enabled ---
            if not prefer_ethernet and ethernet_scan_enabled:
                for entry in self.ethernet_interfaces.values():
                    if len(jobs) >= max_interfaces:
                        break
                    if not entry.get('connected') or not entry.get('ip_address'):
                        continue
                    if entry.get('is_link_local'):
                        continue
                    logger.info(f"[MULTI-SCAN] Adding ethernet job (non-preferred): {entry.get('name')}")
                    jobs.append(
                        ScanJob(
                            interface=entry['name'],
                            ssid='LAN',
                            role='ethernet',
                            ip_address=entry.get('ip_address'),
                            cidr=entry.get('cidr'),
                            network_cidr=entry.get('network_cidr'),
                            interface_type='ethernet',
                        )
                    )

        return jobs

    def get_state_payload(self) -> Dict:
        with self._lock:
            focus_name = self.get_focus_interface()
            focus_entry = self.interfaces.get(focus_name) if focus_name else None

            # Combine WiFi and Ethernet interfaces for the UI
            all_interfaces = list(self.interfaces.values())
            for eth in self.ethernet_interfaces.values():
                if eth.get('connected') and eth.get('ip_address') and not eth.get('is_link_local'):
                    all_interfaces.append({
                        'name': eth['name'],
                        'role': 'ethernet',
                        'state': eth.get('state', 'UP'),
                        'connected': True,
                        'connected_ssid': 'LAN',
                        'ip_address': eth.get('ip_address'),
                        'cidr': eth.get('cidr'),
                        'network_cidr': eth.get('network_cidr'),
                        'mac_address': eth.get('mac_address'),
                        'scan_enabled': self.shared_data.config.get('ethernet_scan_enabled', True),
                        'interface_type': 'ethernet',
                        'last_refresh': eth.get('last_refresh', self.ethernet_last_refresh),
                    })

            payload = {
                'global_enabled': self.is_multi_mode_enabled(),
                'max_parallel': max(1, int(self.shared_data.config.get('wifi_multi_scan_max_parallel', 1))),
                'max_interfaces': max(1, int(self.shared_data.config.get('wifi_multi_scan_max_interfaces', 2))),
                'last_refresh': self.last_refresh,
                'interfaces': all_interfaces,
                'scan_mode': self.get_scan_mode(),
                'focus_interface': focus_name,
                'focus_interface_connected': bool(focus_entry and focus_entry.get('connected')),
                'focus_interface_ssid': focus_entry.get('connected_ssid') if focus_entry else None,
            }
            return payload

    def set_scan_enabled(self, interface_name: str, enabled: bool) -> Dict:
        """Override scan enable flag for a specific interface."""
        with self._lock:
            self.scan_overrides[interface_name] = bool(enabled)
            self.shared_data.config['wifi_scan_interface_overrides'] = self.scan_overrides
            self.shared_data.save_config()
            if interface_name in self.interfaces:
                self.interfaces[interface_name]['scan_enabled'] = bool(enabled)
                if not enabled:
                    self.interfaces[interface_name]['reason'] = 'user_disabled'
                else:
                    self.interfaces[interface_name]['reason'] = None
                return self.interfaces[interface_name]
        return {}

    def get_scan_mode(self) -> str:
        raw_mode = str(self.shared_data.config.get('wifi_multi_scan_mode', '') or '').strip().lower()
        if raw_mode in (self.MODE_SINGLE, self.MODE_MULTI):
            return raw_mode
        legacy_enabled = bool(self.shared_data.config.get('wifi_multi_network_scans_enabled', False))
        return self.MODE_MULTI if legacy_enabled else self.MODE_SINGLE

    def is_multi_mode_enabled(self) -> bool:
        return self.get_scan_mode() == self.MODE_MULTI

    def get_focus_interface(self) -> Optional[str]:
        focus = self.shared_data.config.get('wifi_multi_scan_focus_interface') or ''
        focus = str(focus).strip()
        return focus or None

    def get_focus_job(self) -> Optional[ScanJob]:
        focus_name = self.get_focus_interface()
        if not focus_name:
            return None
        with self._lock:
            entry = self.interfaces.get(focus_name)
            if not entry and self.interfaces:
                fallback = self._auto_focus_interface()
                if fallback and fallback in self.interfaces:
                    entry = self.interfaces.get(fallback)
                    focus_name = fallback
                    self.shared_data.config['wifi_multi_scan_focus_interface'] = fallback
                    try:
                        self.shared_data.save_config()
                    except Exception as exc:
                        logger.debug(f"Unable to persist fallback focus interface: {exc}")
                    self._refresh_focus_flags()
            if not entry:
                return None
            if not entry.get('connected') or not entry.get('connected_ssid'):
                return None
            return ScanJob(
                interface=entry['name'],
                ssid=entry['connected_ssid'],
                role=entry.get('role', 'internal'),
                ip_address=entry.get('ip_address'),
                cidr=entry.get('cidr'),
                network_cidr=entry.get('network_cidr'),
            )

    def update_scan_mode(self, mode: Optional[str] = None, focus_interface: Optional[str] = None) -> Dict:
        requested_mode = self.get_scan_mode()
        if mode is not None:
            normalized = str(mode).strip().lower()
            if normalized not in (self.MODE_SINGLE, self.MODE_MULTI):
                raise ValueError("mode must be 'single' or 'multi'")
            requested_mode = normalized

        focus_provided = focus_interface is not None
        sanitized_focus = None
        if focus_provided:
            sanitized_focus = self._sanitize_interface_name(focus_interface)

        changed = False
        if self.shared_data.config.get('wifi_multi_scan_mode') != requested_mode:
            self.shared_data.config['wifi_multi_scan_mode'] = requested_mode
            changed = True

        desired_multi_flag = (requested_mode == self.MODE_MULTI)
        if bool(self.shared_data.config.get('wifi_multi_network_scans_enabled', False)) != desired_multi_flag:
            self.shared_data.config['wifi_multi_network_scans_enabled'] = desired_multi_flag
            changed = True

        if focus_provided:
            self.shared_data.config['wifi_multi_scan_focus_interface'] = sanitized_focus or ''
            changed = True
        elif requested_mode == self.MODE_SINGLE and not self.get_focus_interface():
            auto_focus = self._auto_focus_interface() or ''
            self.shared_data.config['wifi_multi_scan_focus_interface'] = auto_focus
            changed = True

        if changed:
            try:
                self.shared_data.save_config()
            except Exception as exc:
                logger.warning(f"Unable to persist multi-interface scan mode: {exc}")

        self._refresh_focus_flags()
        return self.get_state_payload()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _sanitize_interface_name(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        candidate = str(value).strip()
        if not candidate:
            return None
        if not self._iface_pattern.match(candidate):
            raise ValueError('Invalid interface name')
        return candidate

    def _auto_focus_interface(self) -> Optional[str]:
        default_iface = self.shared_data.config.get('wifi_default_interface', 'wlan0')
        with self._lock:
            if default_iface in self.interfaces:
                return default_iface
            for entry in self.interfaces.values():
                if entry.get('connected') and entry.get('connected_ssid'):
                    return entry.get('name')
            if self.interfaces:
                return next(iter(self.interfaces.keys()))
        return default_iface

    def _refresh_focus_flags(self):
        focus_name = self.get_focus_interface()
        with self._lock:
            for entry in self.interfaces.values():
                entry['focus_selected'] = bool(entry.get('name') == focus_name)

    def _resolve_enabled_flag(self, interface_name: str, global_enabled: bool) -> bool:
        if interface_name in self.scan_overrides:
            return bool(self.scan_overrides[interface_name])
        return global_enabled

    def _select_interfaces(self, interfaces: List[Dict]) -> List[Dict]:
        max_interfaces = max(1, int(self.shared_data.config.get('wifi_multi_scan_max_interfaces', 2)))
        default_iface = self.shared_data.config.get('wifi_default_interface', 'wlan0')
        hint = (self.shared_data.config.get('wifi_external_interface_hint') or '').strip()

        primary = next((iface for iface in interfaces if iface.get('name') == default_iface), None)
        externals = [iface for iface in interfaces if iface.get('name') != default_iface]
        externals.sort(key=lambda iface: (hint and iface.get('name') != hint, not iface.get('connected'), iface.get('name') or ''))

        selected: List[Dict] = []
        if primary:
            selected.append(primary)
        if externals:
            selected.append(externals[0])

        allowed = self.shared_data.config.get('wifi_allowed_scan_interfaces') or []
        if allowed:
            whitelisted = []
            for iface in selected:
                if iface.get('name') in allowed or iface.get('name') == default_iface:
                    whitelisted.append(iface)
            selected = whitelisted

        return selected[:max_interfaces]
