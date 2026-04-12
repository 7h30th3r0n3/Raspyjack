#!/usr/bin/env python3
"""Network-aware storage management for Ragnar."""

import os
import re
import shutil
from typing import Dict, Optional


class NetworkStorageManager:
    """Keeps per-network storage isolated inside data/networks."""

    def __init__(self, base_data_dir: str):
        self.base_data_dir = base_data_dir
        self.networks_dir = os.path.join(base_data_dir, 'networks')
        self.default_ssid = 'default'
        self.active_ssid: Optional[str] = None
        self.active_slug: Optional[str] = None
        self.last_ssid_file = os.path.join(self.networks_dir, '.last_ssid')

        os.makedirs(self.networks_dir, exist_ok=True)

        self._bootstrap_legacy_layout()

        remembered_ssid = self._load_last_ssid()
        self.activate_network(remembered_ssid)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_active_context(self) -> Dict[str, str]:
        """Return context for the currently active network."""
        if self.active_slug is None:
            self.activate_network(self.default_ssid)
        return self._build_context(self.active_ssid, self.active_slug or '')

    def activate_network(self, ssid: Optional[str]) -> Dict[str, str]:
        """Activate storage for the provided SSID (None => default)."""
        slug = self._slugify(ssid)
        normalized_ssid = ssid.strip() if ssid else None

        if slug != self.active_slug or normalized_ssid != self.active_ssid:
            self.active_slug = slug
            self.active_ssid = normalized_ssid
            self._write_last_ssid(normalized_ssid)

        return self._build_context(self.active_ssid, self.active_slug or '')

    def get_context_snapshot(self, ssid: Optional[str]) -> Dict[str, str]:
        """Return a storage context for SSID without changing the active network."""
        slug = self._slugify(ssid)
        normalized_ssid = ssid.strip() if ssid else None
        return self._build_context(normalized_ssid, slug)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _build_context(self, ssid: Optional[str], slug: str) -> Dict[str, str]:
        (network_dir,
         db_dir,
         intelligence_dir,
         threat_dir,
         data_stolen_dir,
         credentials_dir,
         scan_results_dir,
         vulnerabilities_dir) = self._ensure_network_dirs(slug)
        db_filename = f"{slug}.db"
        context = {
            'ssid': ssid,
            'slug': slug,
            'network_dir': network_dir,
            'db_path': os.path.join(db_dir, db_filename),
            'intelligence_dir': intelligence_dir,
            'threat_intelligence_dir': threat_dir,
            'data_stolen_dir': data_stolen_dir,
            'credentials_dir': credentials_dir,
            'scan_results_dir': scan_results_dir,
            'vulnerabilities_dir': vulnerabilities_dir,
        }
        # Persist SSID so the file browser can display human-readable names
        if ssid:
            ssid_file = os.path.join(network_dir, 'ssid.txt')
            if not os.path.exists(ssid_file):
                try:
                    with open(ssid_file, 'w', encoding='utf-8') as _f:
                        _f.write(ssid)
                except IOError:
                    pass
        return context

    def _ensure_network_dirs(self, slug: str):
        network_dir = os.path.join(self.networks_dir, slug)
        db_dir = os.path.join(network_dir, 'db')
        intelligence_dir = os.path.join(network_dir, 'intelligence')
        threat_dir = os.path.join(network_dir, 'threat_intelligence')
        loot_dir = os.path.join(network_dir, 'loot')
        data_stolen_dir = os.path.join(loot_dir, 'data_stolen')
        credentials_dir = os.path.join(loot_dir, 'credentials')
        output_dir = os.path.join(network_dir, 'output')
        scan_results_dir = os.path.join(output_dir, 'scan_results')
        vulnerabilities_dir = os.path.join(output_dir, 'vulnerabilities')

        os.makedirs(db_dir, exist_ok=True)
        os.makedirs(intelligence_dir, exist_ok=True)
        os.makedirs(threat_dir, exist_ok=True)
        os.makedirs(data_stolen_dir, exist_ok=True)
        os.makedirs(credentials_dir, exist_ok=True)
        os.makedirs(scan_results_dir, exist_ok=True)
        os.makedirs(vulnerabilities_dir, exist_ok=True)

        return (network_dir,
                db_dir,
                intelligence_dir,
                threat_dir,
                data_stolen_dir,
                credentials_dir,
                scan_results_dir,
                vulnerabilities_dir)

    def _slugify(self, ssid: Optional[str]) -> str:
        source = ssid.strip().lower() if ssid else self.default_ssid
        source = source.encode('ascii', errors='ignore').decode() or self.default_ssid
        slug = re.sub(r'[^a-z0-9]+', '_', source).strip('_')
        return slug or self.default_ssid

    # ------------------------------------------------------------------
    # Legacy migration
    # ------------------------------------------------------------------
    def _bootstrap_legacy_layout(self):
        """Move legacy global files into the default network folder once."""
        default_dirs = self._ensure_network_dirs(self._slugify(self.default_ssid))
        (default_network_dir,
         default_db_dir,
         default_intel_dir,
         default_threat_dir,
         default_data_stolen_dir,
         default_credentials_dir,
         _default_scan_results,
         _default_vulnerabilities) = default_dirs
        default_db_path = os.path.join(default_db_dir, f"{self._slugify(self.default_ssid)}.db")

        legacy_db = os.path.join(self.base_data_dir, 'ragnar.db')
        if os.path.exists(legacy_db) and not os.path.exists(default_db_path):
            shutil.move(legacy_db, default_db_path)

        legacy_intel = os.path.join(self.base_data_dir, 'intelligence')
        self._migrate_directory_contents(legacy_intel, default_intel_dir)

        legacy_threat = os.path.join(self.base_data_dir, 'threat_intelligence')
        self._migrate_directory_contents(legacy_threat, default_threat_dir)

        legacy_data_stolen = os.path.join(self.base_data_dir, 'output', 'data_stolen')
        self._migrate_directory_contents(legacy_data_stolen, default_data_stolen_dir)

        legacy_credentials = os.path.join(self.base_data_dir, 'output', 'crackedpwd')
        self._migrate_directory_contents(legacy_credentials, default_credentials_dir)

    def _migrate_directory_contents(self, src: str, dest: str):
        if not os.path.isdir(src):
            return
        src_entries = os.listdir(src)
        if not src_entries:
            return
        os.makedirs(dest, exist_ok=True)
        dest_entries = os.listdir(dest)
        if dest_entries:
            return
        for entry in src_entries:
            shutil.move(os.path.join(src, entry), os.path.join(dest, entry))
        # Leave an empty directory to avoid breaking scripts expecting it
        for leftover in os.listdir(src):
            break
        else:
            try:
                os.rmdir(src)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Persistence of last SSID
    # ------------------------------------------------------------------
    def _load_last_ssid(self) -> Optional[str]:
        try:
            if os.path.exists(self.last_ssid_file):
                with open(self.last_ssid_file, 'r', encoding='utf-8') as handle:
                    return handle.read().strip() or None
        except IOError:
            pass
        return None

    def _write_last_ssid(self, ssid: Optional[str]):
        try:
            with open(self.last_ssid_file, 'w', encoding='utf-8') as handle:
                handle.write((ssid or self.default_ssid) + '\n')
        except IOError:
            pass
