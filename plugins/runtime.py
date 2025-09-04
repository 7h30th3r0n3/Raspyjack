"""Runtime helper functions for RaspyJack plugin management.

This module centralizes all logic related to discovering plugins, loading
configuration, auto-populating defaults based on each plugin's config schema,
reloading plugins, and running the periodic plugin tick loop.

Having this logic here keeps `raspyjack.py` slimmer and focused on UI/core.
"""
from __future__ import annotations

import json
import os
import time
import importlib
from typing import Dict, Any, Optional
import shutil
import zipfile
import tarfile


from .base import PluginManager, Plugin  # Re-use existing abstractions

# ----------------------------------------------------------------------------
# Configuration helpers
# ----------------------------------------------------------------------------

def _plugins_config_path(install_path: str) -> str:
    return os.path.join(install_path, 'plugins', 'plugins_conf.json')


def load_plugins_conf(install_path: str) -> Dict[str, Any]:
    """Load plugins configuration and auto-discover new plugins.

    Any new plugin package (directory with `__init__.py` under `plugins/`)
    not present in the config file will be imported so its schema can be
    read and a default entry created (disabled by default).
    """
    cfg_path = _plugins_config_path(install_path)
    try:
        with open(cfg_path, 'r') as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

    plugins_root = os.path.join(install_path, 'plugins')
    if not os.path.isdir(plugins_root):  # No plugins directory yet
        return cfg

    updated = False
    for name in os.listdir(plugins_root):
        plugin_path = os.path.join(plugins_root, name)
        if not os.path.isdir(plugin_path):
            continue
        if name.startswith('_'):
            continue  # Skip hidden/private
        if name == 'base':
            continue  # Skip core base module
        init_file = os.path.join(plugin_path, '__init__.py')
        if not os.path.isfile(init_file):
            continue  # Not a Python package
        if name in cfg:
            continue  # Already configured
        # Read manifest (if present) first to capture config_schema, priority
        manifest_path = os.path.join(plugin_path, 'plugin.json')
        manifest = {}
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, 'r', encoding='utf-8') as mf:
                    manifest = json.load(mf)
            except Exception as e:
                print(f"[PLUGIN] Failed reading manifest for '{name}': {e}")
                manifest = {}
        # Attempt import to let plugin code run minimal init
        try:
            mod = importlib.import_module(f'plugins.{name}')
        except Exception as e:
            print(f"[PLUGIN] Auto-discovery import failed for '{name}': {e}")
            continue
        instance = getattr(mod, 'plugin', None)
        if instance is None:
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and issubclass(obj, Plugin) and obj is not Plugin:
                    try:
                        instance = obj()
                    except Exception:
                        instance = None
                    break
        if instance is None:
            print(f"[PLUGIN] Auto-discovery could not locate plugin object in '{name}'")
            continue
        # Inject manifest-declared schema onto instance for uniform access
        if isinstance(manifest.get('config_schema'), dict):
            try:
                setattr(instance, '_manifest_config_schema', manifest['config_schema'])
            except Exception:
                pass
        # Build default options from schema (manifest-driven now)
        options = {}
        try:
            schema = getattr(instance, '_manifest_config_schema', {}) or {}
            if isinstance(schema, dict):
                for key, meta in schema.items():
                    if isinstance(meta, dict):
                        options[key] = meta.get('default')
        except Exception as e:
            print(f"[PLUGIN] Failed reading manifest schema for '{name}': {e}")
        entry = {
            "enabled": False,
            "priority": manifest.get('priority', getattr(instance, 'priority', 100))
        }
        if options:
            entry['options'] = options
        cfg[name] = entry
        updated = True
        print(f"[PLUGIN] Added new plugin '{name}' to config with defaults (enabled = False)")
    if updated:
        save_plugins_conf(cfg, install_path)
    return cfg

# ----------------------------------------------------------------------------
# Archive installation (auto-install new plugin packages)
# ----------------------------------------------------------------------------

SUPPORTED_ARCHIVES = ('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2')

def _safe_extract_tar(tar: tarfile.TarFile, path: str) -> None:
    """Extract tar file safely, preventing path traversal."""
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        abs_target = os.path.abspath(member_path)
        abs_base = os.path.abspath(path)
        if not abs_target.startswith(abs_base):
            raise RuntimeError(f"Unsafe path in archive: {member.name}")
    tar.extractall(path)

def _safe_extract_zip(zf: zipfile.ZipFile, path: str) -> None:
    for member in zf.infolist():
        member_path = os.path.join(path, member.filename)
        abs_target = os.path.abspath(member_path)
        abs_base = os.path.abspath(path)
        if not abs_target.startswith(abs_base):
            raise RuntimeError(f"Unsafe path in archive: {member.filename}")
    zf.extractall(path)

def install_pending_plugin_archives(install_path: str, move_processed: bool = True) -> list[str]:
    """Install any plugin archives dropped into plugins/install.

    Process:
      1. Look in <install_path>/plugins/install for supported archive files.
      2. Extract each archive into a temporary directory.
      3. Detect the top-level plugin folder (must contain __init__.py or _impl.py and not be 'base').
      4. Move the folder into plugins/ (skip if already exists -> rename with _new or skip).
      5. Move or rename processed archive to 'processed' subfolder or append .done.
      6. Return list of installed plugin names.

    Supports .zip and common tar formats.
    """
    install_root = os.path.join(install_path, 'plugins', 'install')
    if not os.path.isdir(install_root):
        return []

    processed_dir = os.path.join(install_root, 'processed')
    os.makedirs(processed_dir, exist_ok=True)

    installed: list[str] = []
    for fname in os.listdir(install_root):
        if fname.startswith('.'):
            continue
        full = os.path.join(install_root, fname)
        if os.path.isdir(full):
            continue
        lower = fname.lower()
        if not lower.endswith(SUPPORTED_ARCHIVES):
            continue
        try:
            tmp_extract_base = os.path.join(install_root, '_tmp_extract')
            if os.path.isdir(tmp_extract_base):
                shutil.rmtree(tmp_extract_base, ignore_errors=True)
            os.makedirs(tmp_extract_base, exist_ok=True)

            # Extract
            if lower.endswith('.zip'):
                with zipfile.ZipFile(full, 'r') as zf:
                    _safe_extract_zip(zf, tmp_extract_base)
            else:
                # Tar variants
                with tarfile.open(full, 'r:*') as tf:
                    _safe_extract_tar(tf, tmp_extract_base)

            # Determine plugin directory: find first dir containing __init__.py
            plugin_dir_name = None
            for root, dirs, files in os.walk(tmp_extract_base):
                if '__init__.py' in files:
                    cand = os.path.basename(root)
                    if cand not in ('base', '__pycache__'):
                        plugin_dir_name = cand
                        source_dir = root
                        break
            if not plugin_dir_name:
                print(f"[PLUGIN] Archive '{fname}' skipped: no plugin package found")
                # Archive processed anyway to avoid infinite loop
                dest_final = os.path.join(processed_dir, fname + '.invalid')
                shutil.move(full, dest_final)
                continue

            dest_dir = os.path.join(install_path, 'plugins', plugin_dir_name)
            if os.path.exists(dest_dir):
                # Decide rename strategy
                alt_dir = dest_dir + '_new'
                counter = 1
                while os.path.exists(alt_dir):
                    counter += 1
                    alt_dir = f"{dest_dir}_new{counter}"
                dest_dir = alt_dir
            shutil.move(source_dir, dest_dir)
            print(f"[PLUGIN] Installed plugin '{plugin_dir_name}' from '{fname}' -> {os.path.basename(dest_dir)}")
            installed.append(os.path.basename(dest_dir))

            # Mark archive as processed
            if move_processed:
                dest_final = os.path.join(processed_dir, fname + '.done')
                try:
                    shutil.move(full, dest_final)
                except Exception:
                    os.rename(full, full + '.done')
            else:
                os.rename(full, full + '.done')
        except Exception as e:
            print(f"[PLUGIN] Failed installing archive '{fname}': {e}")
            try:
                os.rename(full, full + '.error')
            except Exception:
                pass
        finally:
            try:
                if os.path.isdir(os.path.join(install_root, '_tmp_extract')):
                    shutil.rmtree(os.path.join(install_root, '_tmp_extract'), ignore_errors=True)
            except Exception:
                pass
    return installed


def save_plugins_conf(cfg: Dict[str, Any], install_path: str) -> None:
    """Persist plugin configuration to disk."""
    try:
        path = _plugins_config_path(install_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[PLUGIN] Failed saving plugins_conf: {e}")

# ----------------------------------------------------------------------------
# Manifest discovery
# ----------------------------------------------------------------------------

def discover_plugin_manifests(install_path: str) -> dict:
    """Discover plugin.json manifest files in plugin packages.

    Manifest schema (initial minimal version):
        {
          "name": "Human Name",              # optional (fallback to package)
          "version": "0.1.0",                # optional
          "description": "...",              # optional
          "priority": 50,                    # optional override
          "requires": ["other_plugin"],      # dependencies by package name
          "permissions": {                   # free-form future use
              "network": true,
              "filesystem": true
          },
          "events": {                        # optional declared events published/subscribed
              "emits": ["battery.updated"],
              "listens": ["system.*"]
          }
        }
    Returns mapping: package_name -> manifest_dict
    """
    manifests: dict[str, dict] = {}
    plugins_root = os.path.join(install_path, 'plugins')
    if not os.path.isdir(plugins_root):
        return manifests
    for name in os.listdir(plugins_root):
        pdir = os.path.join(plugins_root, name)
        if not os.path.isdir(pdir):
            continue
        if name in ('base', '__pycache__') or name.startswith('_'):
            continue
        manifest_path = os.path.join(pdir, 'plugin.json')
        if not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                manifests[name] = data
        except Exception as e:
            print(f"[PLUGIN] Failed reading manifest for {name}: {e}")
    return manifests

# ----------------------------------------------------------------------------
# Loading / reloading
# ----------------------------------------------------------------------------

def reload_plugins(current_manager: Optional[PluginManager], install_path: str, context: dict) -> PluginManager:
    """Reload all enabled plugins based on config.

    Returns a (possibly new) PluginManager instance with plugins loaded.
    """
    cfg = load_plugins_conf(install_path)
    manager = current_manager or PluginManager()
    try:
        if current_manager is not None:
            manager.unload_all()
    except Exception:
        pass
    # Ensure plugin_manager reference is present in context for inter-plugin communication
    context = dict(context)
    context['plugin_manager'] = manager
    # Attach manifests & event bus helpers (manager already owns bus)
    manifests = discover_plugin_manifests(install_path)
    context['plugin_manifests'] = manifests  # accessible to plugins for metadata or dependency checks
    # Shortcuts (populated after manager loads) will be added later in process
    if hasattr(manager, 'load_from_config'):
        manager.load_from_config(cfg, context)
    else:
        names = [k for k, v in cfg.items() if isinstance(v, dict) and v.get('enabled')]
        manager.load_all(names, context)
    # After load, expose bus API via context if available
    return manager

# ----------------------------------------------------------------------------
# Tick loop
# ----------------------------------------------------------------------------

def plugin_tick_loop(manager_ref_provider, stop_event, interval: float = 0.5) -> None:
    """Continuously dispatch plugin ticks.

    manager_ref_provider can be either a PluginManager instance or a callable
    returning one (so we can see newly set globals). This keeps the loop alive
    even if the manager changes at runtime.
    """
    last_overlay = 0.0
    OVERLAY_REFRESH = 1.0  # seconds
    while not stop_event.is_set():
        try:
            manager = manager_ref_provider() if callable(manager_ref_provider) else manager_ref_provider
            if manager is not None:
                manager.dispatch_tick()
                now = time.time()
                if now - last_overlay >= OVERLAY_REFRESH:
                    last_overlay = now
                    try:
                        manager.rebuild_overlay()
                    except Exception:
                        pass
        except Exception:
            pass
        time.sleep(interval)

__all__ = [
    'load_plugins_conf', 'save_plugins_conf', 'reload_plugins', 'plugin_tick_loop', 'install_pending_plugin_archives'
]
