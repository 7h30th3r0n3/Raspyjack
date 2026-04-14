#webapp_modern.py
"""
Modern Flask-based web application for Ragnar
Features:
- Fast Flask backend with proper routing
- RESTful API endpoints
- WebSocket support for real-time updates
- Static file caching
- Better performance than SimpleHTTPRequestHandler
"""

import os
import sys
import json
import csv
import glob
import signal
import logging
import threading
import time
import subprocess
import re
import io
import base64
import shutil
import importlib
import hashlib
import ipaddress
import socket
import traceback
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Tuple
from contextlib import contextmanager
from email.utils import format_datetime
from flask import Flask, render_template, jsonify, request, send_from_directory, Response, make_response, g, session, redirect
from flask_socketio import SocketIO, emit, disconnect
try:
    from flask_cors import CORS  # type: ignore
    flask_cors_available = True
except ImportError:
    flask_cors_available = False
try:
    import psutil
    psutil_available = True
except ImportError:
    psutil_available = False
try:
    import pandas as pd
    pandas_available = True
except ImportError:
    pandas_available = False
from init_shared import shared_data
from wifi_interfaces import gather_wifi_interfaces, gather_ethernet_interfaces, is_ethernet_available, get_active_ethernet_interface
from utils import WebUtils
from logger import Logger
from threat_intelligence import ThreatIntelligenceFusion
from lynis_parser import parse_lynis_dat
from actions.lynis_pentest_ssh import LynisPentestSSH
from actions.connector_utils import CredentialChecker
from db_manager import get_db, DatabaseManager
from auth_manager import AuthManager

# Initialize logger
logger = Logger(name="webapp_modern.py", level=logging.DEBUG)

# Initialize auth manager
auth_mgr = AuthManager(shared_data)

# Initialize Flask app
app = Flask(__name__,
            static_folder='web',
            template_folder='web')
app.config['SECRET_KEY'] = auth_mgr.get_or_create_secret_key()
app.config['JSON_SORT_KEYS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Set up CORS if available
if flask_cors_available:
    CORS(app)

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ============================================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================================

@app.before_request
def check_authentication():
    """Enforce authentication on all endpoints when auth is configured."""
    if not auth_mgr.is_configured():
        return  # No auth set up yet, allow everything

    # Whitelist: paths that must be accessible without authentication
    path = request.path
    whitelist_prefixes = ['/login', '/api/auth/', '/api/kill']
    if any(path.startswith(p) for p in whitelist_prefixes):
        return

    # Static assets needed for login page (CSS, JS, images, fonts)
    static_prefixes = ['/css/', '/images/', '/scripts/', '/fonts/']
    if any(path.startswith(p) for p in static_prefixes):
        return

    # Check if user is authenticated via Flask session
    if not session.get('authenticated'):
        if path.startswith('/api/'):
            return jsonify({'error': 'Unauthorized', 'auth_required': True}), 401
        return redirect('/login')

# Initialize web utilities
web_utils = WebUtils(shared_data, logger)

# Initialize threat intelligence system
try:
    threat_intelligence = ThreatIntelligenceFusion(shared_data)
    shared_data.threat_intelligence = threat_intelligence  # type: ignore
    logger.info("Threat intelligence system initialized")
except Exception as exc:
    logger.error(f"Failed to initialize threat intelligence: {exc}")
    threat_intelligence = None
    shared_data.threat_intelligence = None  # type: ignore

# Global state
clients_connected = 0

# Synchronization helpers for keeping dashboard and e-paper data fresh
sync_lock = threading.Lock()
last_sync_time = 0.0
SYNC_BACKGROUND_INTERVAL = 15  # seconds between automatic synchronizations (increased from 5s to reduce CPU load)

# Scan results caching to avoid reprocessing files every sync
scan_results_cache = {}
processed_scan_files = {}  # Track which files we've already processed: {filename: mtime}

DEFAULT_ARP_SCAN_INTERFACE = 'wlan0'
SEP_SCAN_COMMAND = ['sudo', 'sep-scan']
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
PWN_INSTALL_SCRIPT = os.path.join(shared_data.currentdir, 'scripts', 'install_pwnagotchi.sh')
PWN_SERVICE_FILE = '/etc/systemd/system/pwnagotchi.service'
PWN_CONFIG_FILE = '/etc/pwnagotchi/config.toml'
PWN_SWAP_DELAY_SECONDS = 1
PWN_INSTALL_STALE_SECONDS = 600  # Treat installer as stale after 10 minutes
PWN_SWITCH_STALE_SECONDS = 60  # Consider switch stuck after 60 seconds
RELEASE_GATE_DEFAULT_MESSAGE = (
    "A controlled release is rolling out. Proceeding with a manual update may cause instability."
)


def _normalize_value(value, default='Unknown'):
    """Normalize a value, handling nan, None, empty strings, etc."""
    if value is None:
        return default

    str_value = str(value).strip()
    if not str_value or str_value.lower() in ['nan', 'none', 'null', '']:
        return default

    return str_value


def _is_valid_ipv4(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_mac(mac):
    return mac.lower() if mac else ''


def _parse_attack_timestamp(value):
    if value is None:
        return None

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OSError):
            return None

    if isinstance(value, str):
        cleaned = value.strip()

        if cleaned.endswith('Z') and '+' not in cleaned:
            cleaned = cleaned[:-1] + '+00:00'

        parsers = (
            lambda v: datetime.fromisoformat(v),
            lambda v: datetime.strptime(v, '%Y-%m-%d %H:%M:%S'),
            lambda v: datetime.strptime(v, '%Y-%m-%dT%H:%M:%S'),
        )

        for parser in parsers:
            try:
                return parser(cleaned)
            except ValueError:
                continue

    return None


def _parse_arp_scan_output(output):
    hosts = {}
    if not output:
        return hosts

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('Interface:') or line.startswith('Starting') or line.startswith('Ending'):
            continue

        parts = re.split(r'\s+', line)
        if len(parts) < 2:
            continue

        ip_candidate, mac_candidate = parts[0], parts[1]
        if not (_is_valid_ipv4(ip_candidate) and MAC_REGEX.match(mac_candidate)):
            continue

        vendor = ' '.join(parts[2:]).strip() if len(parts) > 2 else ''
        hosts[ip_candidate] = {
            'mac': _normalize_mac(mac_candidate),
            'vendor': vendor
        }

    return hosts


def build_pseudo_mac_from_ip(ip):
    try:
        octets = [int(part) for part in ip.split('.')]
        if len(octets) == 4:
            return f"00:00:{octets[0]:02x}:{octets[1]:02x}:{octets[2]:02x}:{octets[3]:02x}"
    except Exception:
        pass
    return "00:00:00:00:00:00"


def _extract_requested_network_identifier() -> Optional[str]:
    """Read a requested network identifier from common query params."""
    if not request:
        return None
    for key in ('network', 'ssid', 'slug'):
        value = request.args.get(key)
        if value:
            value = value.strip()
            if value:
                return value
    return None


def _normalize_network_slug(identifier: Optional[str]) -> Optional[str]:
    """Normalize a requested network identifier to a storage slug."""
    if not identifier:
        return None
    candidate = identifier.strip()
    if not candidate:
        return None

    manager = getattr(shared_data, 'storage_manager', None)
    slugify = getattr(manager, '_slugify', None) if manager else None
    if callable(slugify):
        try:
            return slugify(candidate)
        except Exception as exc:
            logger.debug(f"Failed to slugify network identifier '{candidate}': {exc}")

    simplified = re.sub(r'[^a-z0-9]+', '_', candidate.lower()).strip('_')
    return simplified or candidate.lower()


@contextmanager
def _network_context_from_request():
    """Temporarily switch shared data to the network requested by the client."""
    identifier = _extract_requested_network_identifier()
    slug = _normalize_network_slug(identifier)
    registry = getattr(shared_data, 'context_registry', None)

    if slug and registry:
        try:
            with registry.activate(slug):
                g.requested_network_slug = slug
                yield slug
                return
        except Exception as exc:
            logger.warning(f"Unable to activate network context '{slug}': {exc}")
        finally:
            try:
                g.pop('requested_network_slug', None)
            except Exception:
                pass

    yield None


def run_targeted_arp_scan(ip, interface=DEFAULT_ARP_SCAN_INTERFACE):
    command = ['sudo', 'arp-scan', f'--interface={interface}', ip]
    logger.info(f"Running targeted arp-scan for {ip}: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
        hosts = _parse_arp_scan_output(result.stdout)
        entry = hosts.get(ip)
        return entry.get('mac', '') if entry else ''
    except FileNotFoundError:
        logger.warning(f"arp-scan command not found when resolving MAC for {ip}")
        return ''
    except subprocess.TimeoutExpired as e:
        logger.warning(f"arp-scan timed out for {ip}: {e}")
        hosts = _parse_arp_scan_output(e.stdout or '')
        entry = hosts.get(ip)
        return entry.get('mac', '') if entry else ''
    except Exception as e:
        logger.error(f"Error running targeted arp-scan for {ip}: {e}")
        return ''


def _update_pwn_config(updates: dict) -> None:
    if not updates:
        return

    changed = False
    for key, value in updates.items():
        if shared_data.config.get(key) != value:
            shared_data.config[key] = value
            setattr(shared_data, key, value)
            changed = True

    if changed:
        try:
            shared_data.save_config()
        except Exception as exc:
            logger.error(f"Failed to persist Pwnagotchi config updates: {exc}")


def _read_pwn_status_file() -> dict:
    status_path = getattr(shared_data, 'pwnagotchi_status_file', os.path.join(shared_data.datadir, 'pwnagotchi_status.json'))
    if not os.path.exists(status_path):
        return {}

    try:
        with open(status_path, 'r', encoding='utf-8') as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        logger.warning(f"Malformed Pwnagotchi status file: {exc}")
    except Exception as exc:
        logger.debug(f"Unable to read Pwnagotchi status file: {exc}")
    return {}


def _parse_iso_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        normalized = value.replace('Z', '+00:00')
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception as exc:
        logger.debug(f"Failed to parse Pwnagotchi status timestamp '{value}': {exc}")
    return None


def _write_pwn_status_file(state: str, message: str, phase: str = 'dashboard', extra: Optional[dict] = None) -> dict:
    payload = _read_pwn_status_file()
    payload.update(extra or {})
    payload.update({
        'state': state,
        'message': message,
        'phase': phase,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })

    status_path = getattr(shared_data, 'pwnagotchi_status_file', os.path.join(shared_data.datadir, 'pwnagotchi_status.json'))
    os.makedirs(os.path.dirname(status_path), exist_ok=True)

    try:
        with open(status_path, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, indent=2)
    except Exception as exc:
        logger.error(f"Failed to update Pwnagotchi status file: {exc}")

    return payload


def _systemctl_check(command: list[str]) -> bool:
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        logger.warning(f"systemctl not available when running: {' '.join(command)}")
    except Exception as exc:
        logger.debug(f"systemctl check failed for {' '.join(command)}: {exc}")
    return False


def _systemctl_state_label(service_name: str) -> str:
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True,
            text=True
        )
        label = result.stdout.strip() or result.stderr.strip() or 'unknown'
        return label
    except FileNotFoundError:
        logger.warning(f"systemctl not available while querying {service_name}")
    except Exception as exc:
        logger.debug(f"systemctl state query failed for {service_name}: {exc}")
    return 'unknown'


_pwn_discovery_cache: Dict = {'data': None, 'timestamp': 0.0, 'dir_mtimes': {}}
_PWN_DISCOVERY_CACHE_TTL = 30


def _parse_pwnagotchi_filename(basename: str) -> Tuple[Optional[str], Optional[str], str]:
    """Parse a Pwnagotchi capture filename into (ssid, bssid, extension).

    Pwnagotchi names files as SSID_BSSID.ext where BSSID may use hex-only,
    underscores, or colons.  Returns (ssid, bssid_colon_format, ext).
    """
    ext = ''
    name = basename
    for compound in ('.gps.json', '.hc22000', '.pcapng', '.netjson'):
        if name.lower().endswith(compound):
            ext = compound
            name = name[:-len(compound)]
            break
    if not ext:
        dot_pos = name.rfind('.')
        if dot_pos > 0:
            ext = name[dot_pos:]
            name = name[:dot_pos]

    if not name:
        return None, None, ext

    # Case 1: BSSID with colons  e.g. SSID_aa:bb:cc:dd:ee:ff
    m = re.search(r'_([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})$', name)
    if m:
        return name[:m.start()] or None, m.group(1).lower(), ext

    # Case 2: BSSID as 12 contiguous hex chars  e.g. SSID_aabbccddeeff
    m = re.search(r'_([0-9a-fA-F]{12})$', name)
    if m:
        raw = m.group(1).lower()
        bssid = ':'.join(raw[i:i + 2] for i in range(0, 12, 2))
        return name[:m.start()] or None, bssid, ext

    # Case 3: BSSID with underscores  e.g. SSID_aa_bb_cc_dd_ee_ff
    m = re.search(
        r'_([0-9a-fA-F]{2})_([0-9a-fA-F]{2})_([0-9a-fA-F]{2})'
        r'_([0-9a-fA-F]{2})_([0-9a-fA-F]{2})_([0-9a-fA-F]{2})$', name)
    if m:
        bssid = ':'.join(m.group(i).lower() for i in range(1, 7))
        return name[:m.start()] or None, bssid, ext

    return name, None, ext


def _read_gps_json_safe(filepath: str) -> Optional[dict]:
    """Read a Pwnagotchi .gps.json file.  Returns dict with lat/lng or None."""
    try:
        with open(filepath, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        lat = data.get('Latitude') or data.get('latitude')
        lng = data.get('Longitude') or data.get('longitude')
        if lat is None or lng is None:
            return None
        lat, lng = float(lat), float(lng)
        if lat == 0.0 and lng == 0.0:
            return None
        return {
            'latitude': lat,
            'longitude': lng,
            'altitude': data.get('Altitude') or data.get('altitude'),
            'accuracy': data.get('Accuracy') or data.get('accuracy'),
            'updated': data.get('Updated') or data.get('updated'),
        }
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return None


def _collect_pwnagotchi_discovery_summary() -> dict:
    """Parse Pwnagotchi handshake/discovery files into grouped network data."""
    global _pwn_discovery_cache

    handshake_dirs = ['/root/handshakes', '/home/pi/handshakes']

    current_mtimes: Dict[str, float] = {}
    for d in handshake_dirs:
        try:
            current_mtimes[d] = os.path.getmtime(d)
        except OSError:
            pass

    now = time.time()
    if (_pwn_discovery_cache['data'] is not None
            and (now - _pwn_discovery_cache['timestamp']) < _PWN_DISCOVERY_CACHE_TTL
            and current_mtimes == _pwn_discovery_cache['dir_mtimes']):
        return _pwn_discovery_cache['data']

    handshake_exts = ('*.pcap', '*.pcapng', '*.22000', '*.hc22000')
    discovery_exts = ('*.gps.json', '*.netjson', '*.json')

    handshake_files: List[str] = []
    discovery_files: List[str] = []
    for d in handshake_dirs:
        for ext in handshake_exts:
            handshake_files.extend(glob.glob(os.path.join(d, ext)))
        for ext in discovery_exts:
            discovery_files.extend(glob.glob(os.path.join(d, ext)))

    handshake_files = sorted(set(p for p in handshake_files if os.path.isfile(p)))
    discovery_files = sorted(set(p for p in discovery_files if os.path.isfile(p)))

    networks: Dict[Tuple[str, str], dict] = {}

    def _get_or_create(ssid: Optional[str], bssid: Optional[str]) -> dict:
        key = (ssid or 'Unknown', bssid or 'unknown')
        if key not in networks:
            networks[key] = {
                'ssid': key[0], 'bssid': key[1],
                'has_handshake': False, 'handshake_types': [],
                'has_gps': False, 'gps': None, 'has_netjson': False,
                'first_seen': None, 'last_seen': None,
                'files': [],
            }
        return networks[key]

    def _touch_ts(net: dict, fpath: str) -> None:
        try:
            ts = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc).isoformat()
        except OSError:
            return
        if net['first_seen'] is None or ts < net['first_seen']:
            net['first_seen'] = ts
        if net['last_seen'] is None or ts > net['last_seen']:
            net['last_seen'] = ts

    def _file_entry(fpath: str) -> dict:
        basename = os.path.basename(fpath)
        try:
            size = os.path.getsize(fpath)
        except OSError:
            size = 0
        return {'name': basename, 'path': fpath, 'size': size}

    for fpath in handshake_files:
        ssid, bssid, ext = _parse_pwnagotchi_filename(os.path.basename(fpath))
        net = _get_or_create(ssid, bssid)
        net['has_handshake'] = True
        label = ext.lstrip('.').upper() if ext else 'UNKNOWN'
        if label not in net['handshake_types']:
            net['handshake_types'].append(label)
        net['files'].append(_file_entry(fpath))
        _touch_ts(net, fpath)

    for fpath in discovery_files:
        ssid, bssid, ext = _parse_pwnagotchi_filename(os.path.basename(fpath))
        net = _get_or_create(ssid, bssid)
        net['files'].append(_file_entry(fpath))
        _touch_ts(net, fpath)
        if os.path.basename(fpath).lower().endswith('.gps.json'):
            gps = _read_gps_json_safe(fpath)
            if gps:
                net['has_gps'] = True
                net['gps'] = gps
        elif os.path.basename(fpath).lower().endswith('.netjson'):
            net['has_netjson'] = True

    network_list = sorted(networks.values(), key=lambda n: n['last_seen'] or '', reverse=True)

    combined = handshake_files + discovery_files
    last_discovery = None
    if combined:
        try:
            newest = max(combined, key=os.path.getmtime)
            last_discovery = datetime.fromtimestamp(os.path.getmtime(newest), tz=timezone.utc).isoformat()
        except OSError:
            pass

    def _recent_items(paths: List[str], limit: int = 5) -> List[dict]:
        items: List[dict] = []
        for fp in sorted(paths, key=lambda p: os.path.getmtime(p), reverse=True)[:limit]:
            try:
                items.append({
                    'name': os.path.basename(fp),
                    'modified': datetime.fromtimestamp(os.path.getmtime(fp), tz=timezone.utc).isoformat(),
                })
            except OSError:
                continue
        return items

    result = {
        'handshake_count': len(handshake_files),
        'discovery_count': len(discovery_files),
        'last_discovery': last_discovery,
        'recent_handshakes': _recent_items(handshake_files),
        'recent_discoveries': _recent_items(discovery_files),
        'networks': network_list,
        'network_count': len(network_list),
        'networks_with_handshake': sum(1 for n in network_list if n['has_handshake']),
        'networks_with_gps': sum(1 for n in network_list if n['has_gps']),
    }

    _pwn_discovery_cache = {'data': result, 'timestamp': now, 'dir_mtimes': current_mtimes}
    return result


def _build_pwnagotchi_status(persist: bool = True) -> dict:
    status = {
        'state': 'not_installed',
        'message': 'Pwnagotchi is not installed',
        'phase': 'idle',
        'installed': os.path.isdir('/opt/pwnagotchi') and os.path.exists(PWN_SERVICE_FILE),
        'installing': False,
        'mode': shared_data.config.get('pwnagotchi_mode', 'ragnar'),
        'last_switch': shared_data.config.get('pwnagotchi_last_switch', ''),
        'service_active': False,
        'service_enabled': False,
        'log_file': None,
        'config_file': None,
        'target_mode': shared_data.config.get('pwnagotchi_mode', 'ragnar'),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'discoveries': {
            'handshake_count': 0,
            'discovery_count': 0,
            'last_discovery': None,
            'recent_handshakes': [],
            'recent_discoveries': []
        }
    }

    file_data = _read_pwn_status_file()
    if file_data:
        for key, value in file_data.items():
            # Only update known keys to avoid leaking arbitrary data
            if key in {'state', 'message', 'phase', 'log_file', 'config_file', 'repo_dir', 'target_mode', 'timestamp'}:
                status[key] = value

    state = status.get('state', 'not_installed')
    status['installing'] = state in {'preflight', 'dependencies', 'python', 'installing'}

    if status['installing'] and not _pwn_install_process_running() and _is_pwn_install_stale(file_data):
        stale_message = 'Pwnagotchi installer stopped unexpectedly. Press Install again to retry.'
        status['installing'] = False
        status['state'] = 'error'
        status['phase'] = 'error'
        status['message'] = stale_message
        _write_pwn_status_file('error', stale_message, 'error', {
            'log_file': status.get('log_file'),
            'target_mode': status.get('target_mode', 'ragnar')
        })

    pwn_service_state = _systemctl_state_label('pwnagotchi')
    status['service_state'] = pwn_service_state
    status['service_active'] = pwn_service_state == 'active'
    status['service_enabled'] = _systemctl_check(['systemctl', 'is-enabled', 'pwnagotchi'])

    ragnar_service_state = _systemctl_state_label('ragnar')
    status['ragnar_service_state'] = ragnar_service_state
    ragnar_service_active = ragnar_service_state == 'active'

    service_file_exists = os.path.exists(PWN_SERVICE_FILE)
    status['service_file_exists'] = service_file_exists
    if service_file_exists and not status.get('service_file'):
        status['service_file'] = PWN_SERVICE_FILE

    if status['service_active']:
        status['state'] = 'running'
        status['message'] = 'Pwnagotchi service is running'
        status['mode'] = 'pwnagotchi'
    elif ragnar_service_active:
        status['mode'] = 'ragnar'
        if status['state'] not in {'error', 'installing'}:
            status['state'] = 'running'
            status['message'] = 'Ragnar service is running'
    else:
        status['mode'] = status.get('mode', shared_data.config.get('pwnagotchi_mode', 'ragnar'))

    state = status.get('state', state)

    stale_switch = False
    if state == 'switching' and not status['installing']:
        timestamp_obj = _parse_iso_timestamp(status.get('timestamp'))
        if not timestamp_obj:
            stale_switch = True
        else:
            age = datetime.now(timezone.utc) - timestamp_obj
            stale_switch = age.total_seconds() >= PWN_SWITCH_STALE_SECONDS

    if stale_switch:
        target_mode = (status.get('target_mode') or shared_data.config.get('pwnagotchi_mode', 'ragnar')).lower()
        if target_mode not in {'pwnagotchi', 'ragnar'}:
            target_mode = 'ragnar'

        if target_mode == 'pwnagotchi':
            if status['service_active']:
                status['state'] = 'running'
                status['phase'] = 'active'
                status['message'] = 'Pwnagotchi service is running'
                status['mode'] = 'pwnagotchi'
                status['target_mode'] = 'pwnagotchi'
            else:
                status['state'] = 'error'
                status['phase'] = 'error'
                status['mode'] = 'ragnar' if ragnar_service_active else 'ragnar'
                status['target_mode'] = 'ragnar'
                status['message'] = (
                    f"Switch to Pwnagotchi failed: pwnagotchi.service is {pwn_service_state}. "
                    f"Ragnar service is {ragnar_service_state}."
                )
        else:  # target_mode == 'ragnar'
            if ragnar_service_active:
                status['state'] = 'running'
                status['phase'] = 'idle'
                status['message'] = 'Ragnar service is running'
                status['mode'] = 'ragnar'
                status['target_mode'] = 'ragnar'
            else:
                status['state'] = 'error'
                status['phase'] = 'error'
                status['mode'] = 'pwnagotchi' if status['service_active'] else 'ragnar'
                status['target_mode'] = 'pwnagotchi'
                status['message'] = (
                    f"Switch to Ragnar failed: ragnar.service is {ragnar_service_state}. "
                    f"Pwnagotchi service is {pwn_service_state}."
                )

        updated_payload = _write_pwn_status_file(
            status['state'],
            status['message'],
            status.get('phase', 'dashboard'),
            {
                'target_mode': status.get('target_mode'),
                'log_file': status.get('log_file'),
                'config_file': status.get('config_file'),
                'service_state': status.get('service_state')
            }
        )
        for key in ('state', 'message', 'phase', 'timestamp', 'target_mode'):
            if key in updated_payload:
                status[key] = updated_payload[key]
        state = status['state']

    status['installed'] = (
        status['installed']
        or state == 'installed'
        or status['service_active']
        or status['service_enabled']
        or service_file_exists
    )

    config_updates = {}
    if status['installed'] != bool(shared_data.config.get('pwnagotchi_installed', False)):
        config_updates['pwnagotchi_installed'] = status['installed']

    if status.get('mode') and status['mode'] != shared_data.config.get('pwnagotchi_mode'):
        config_updates['pwnagotchi_mode'] = status['mode']

    if status.get('message') and status['message'] != shared_data.config.get('pwnagotchi_last_status'):
        config_updates['pwnagotchi_last_status'] = status['message']

    if persist and config_updates:
        _update_pwn_config(config_updates)

    status['discoveries'] = _collect_pwnagotchi_discovery_summary()

    return status


def _emit_pwn_status_update(status: Optional[dict] = None) -> dict:
    payload = status or _build_pwnagotchi_status()
    try:
        socketio.emit('pwnagotchi_status', payload)
    except Exception as exc:
        logger.debug(f"Failed to emit pwnagotchi_status event: {exc}")
    return payload


def _pwn_install_process_running() -> bool:
    script_name = os.path.basename(PWN_INSTALL_SCRIPT)
    try:
        result = subprocess.run(['pgrep', '-f', script_name], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        logger.debug('pgrep not available to verify Pwnagotchi installer state')
    except Exception as exc:
        logger.debug(f"Unable to determine installer process state: {exc}")
    return False


def _is_pwn_install_stale(status: Optional[dict], max_age_seconds: int = PWN_INSTALL_STALE_SECONDS) -> bool:
    if not status:
        return True

    timestamp = status.get('timestamp')
    if not timestamp:
        return True

    normalized = timestamp.replace('Z', '+00:00')
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        logger.debug(f"Unable to parse Pwnagotchi installer timestamp: {timestamp}")
        return True

    age = datetime.now(timezone.utc) - parsed
    return age.total_seconds() > max_age_seconds


def _read_pwn_log_chunk(cursor: Optional[int] = None, tail_bytes: int = 4096, max_bytes: int = 8192):
    """Return a slice of the installer log starting at cursor or tail bytes from end."""
    status = _build_pwnagotchi_status(persist=False)
    log_file = status.get('log_file')

    if not log_file or not os.path.exists(log_file):
        return status, None, 0, []

    try:
        file_size = os.path.getsize(log_file)
    except OSError:
        return status, None, 0, []

    if cursor is None or cursor < 0:
        tail_bytes = max(0, min(tail_bytes, 65536))
        start = max(file_size - tail_bytes, 0)
    else:
        start = max(0, min(cursor, file_size))

    max_bytes = max(1024, min(max_bytes, 65536))

    entries: list[str] = []
    new_cursor = start

    try:
        with open(log_file, 'r', encoding='utf-8', errors='replace') as handle:
            handle.seek(start)
            chunk = handle.read(max_bytes)
            new_cursor = handle.tell()
    except Exception as exc:
        logger.debug(f"Failed reading Pwnagotchi installer log: {exc}")
        return status, log_file, new_cursor, []

    if chunk:
        entries = chunk.splitlines()

    return status, log_file, new_cursor, entries


def _schedule_pwn_mode_switch(target_mode: str) -> None:
    if target_mode not in {'pwnagotchi', 'ragnar'}:
        logger.warning(f"Invalid Pwnagotchi target mode requested: {target_mode}")
        return

    def _thread_target():
        try:
            _execute_pwn_mode_switch(target_mode)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.error(f"Unhandled error during Pwnagotchi handoff to {target_mode}: {exc}")

    thread = threading.Thread(
        target=_thread_target,
        name=f"pwn-switch-{target_mode}",
        daemon=True,
    )
    thread.start()


def _run_systemctl(args: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    """Execute systemctl with sudo and capture output."""
    return subprocess.run(
        ['sudo', 'systemctl', *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _summarize_status_output(output: str, limit: int = 600) -> str:
    """Condense systemctl status output into a single readable line."""
    if not output:
        return ''
    collapsed = ' | '.join(line.strip() for line in output.splitlines() if line.strip())
    return (collapsed[:limit].rstrip() + ('…' if len(collapsed) > limit else ''))


def _collect_service_status(service_name: str) -> str:
    try:
        status_proc = _run_systemctl(['status', service_name, '--no-pager'], timeout=10)
        status_output = status_proc.stdout.strip() or status_proc.stderr.strip()
        return _summarize_status_output(status_output)
    except Exception as exc:  # pragma: no cover - best effort
        return f"Unable to collect status for {service_name}: {exc}"


def _ensure_pwn_launcher() -> None:
    """Ensure /usr/bin/pwnagotchi-launcher exists and is executable."""
    launcher_path = '/usr/bin/pwnagotchi-launcher'
    try:
        if os.path.exists(launcher_path):
            if os.access(launcher_path, os.X_OK):
                return
            os.chmod(launcher_path, 0o755)
            logger.info(f"Repaired permissions for {launcher_path}")
            return

        candidates = [
            shutil.which('pwnagotchi'),
            shutil.which('pwnagotchi-launcher'),
            '/usr/local/bin/pwnagotchi',
            '/usr/local/bin/pwnagotchi-launcher'
        ]
        target = next((c for c in candidates if c and os.path.exists(c)), None)
        if not target:
            logger.warning("Unable to locate pwnagotchi binary; launcher shim not created")
            return

        script = f"#!/bin/bash\nexec {target} \"$@\"\n"
        with open(launcher_path, 'w', encoding='utf-8') as handle:
            handle.write(script)
        os.chmod(launcher_path, 0o755)
        logger.info(f"Created pwnagotchi launcher shim at {launcher_path} → {target}")
    except PermissionError as exc:
        logger.error(f"Permission error while ensuring pwnagotchi launcher: {exc}")
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.error(f"Failed to prepare pwnagotchi launcher: {exc}")


def _unit_name(service_name: str) -> str:
    unit = service_name.strip()
    if unit.endswith('.service'):
        unit = unit[:-8]
    return unit or service_name


def _format_service_failure_message(service_name: str) -> str:
    unit = _unit_name(service_name)
    readable = unit.replace('_', ' ').replace('-', ' ').title()
    return f"Failed to start {readable} service. Review journalctl -u {unit} -f for details."


def _wait_for_service_active(service_name: str, timeout: int = 30, poll_interval: int = 1) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    last_state = ''
    while time.monotonic() < deadline:
        state_proc = _run_systemctl(['is-active', service_name], timeout=10)
        state = state_proc.stdout.strip() or state_proc.stderr.strip()
        last_state = state or last_state or 'unknown'
        if state == 'active':
            return True, 'active'
        if state in {'failed', 'inactive'}:
            return False, _collect_service_status(service_name) or f"{service_name} reported state {state}"
        time.sleep(poll_interval)
    return False, _collect_service_status(service_name) or f"{service_name} did not become active within {timeout}s (last state: {last_state})"


def _start_service_with_monitor(service_name: str, timeout: int = 30) -> tuple[bool, str]:
    start_proc = _run_systemctl(['start', service_name])
    if start_proc.returncode != 0:
        detail = start_proc.stderr.strip() or start_proc.stdout.strip() or f"systemctl start {service_name} failed with {start_proc.returncode}"
        status_excerpt = _collect_service_status(service_name)
        summary = status_excerpt or detail
        return False, summary
    return _wait_for_service_active(service_name, timeout=timeout)


def _stop_service(service_name: str) -> tuple[bool, str]:
    stop_proc = _run_systemctl(['stop', service_name])
    if stop_proc.returncode != 0:
        detail = stop_proc.stderr.strip() or stop_proc.stdout.strip() or f"systemctl stop {service_name} failed with {stop_proc.returncode}"
        logger.warning(detail)
        return False, detail
    return True, 'stopped'


def _deferred_self_stop(delay: int = 1) -> None:
    """Stop the ragnar.service via a systemd-run transient unit.

    Because Ragnar is stopping *itself*, a direct systemctl stop kills the
    thread before status files and config can be persisted.  We use
    systemd-run so the stop command runs in its own cgroup — completely
    outside ragnar.service — and survives ragnar's cgroup teardown.
    subprocess.Popen with start_new_session=True is NOT sufficient: it
    creates a new session but inherits the same cgroup, so systemd kills
    it when tearing down ragnar.service.
    """
    try:
        subprocess.Popen(
            ['systemd-run', '--no-block', '--collect',
             '--unit=ragnar-deferred-stop',
             'bash', '-c', f'sleep {delay} && systemctl stop ragnar.service'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info(f"Scheduled deferred ragnar.service stop in {delay}s (systemd-run)")
    except Exception as exc:
        logger.error(f"Failed to schedule deferred ragnar.service stop: {exc}")
        # Last resort: try direct stop (may be interrupted)
        _stop_service('ragnar.service')


def _show_epaper_transition(message: str) -> None:
    """Write a transition message to the e-paper display before swapping services."""
    try:
        display = getattr(shared_data, 'display_instance', None)
        if not display:
            return
        epd_helper = getattr(shared_data, 'epd_helper', None)
        if not epd_helper:
            return

        from PIL import Image, ImageDraw, ImageFont
        width = shared_data.config.get('ref_width', 122)
        height = shared_data.config.get('ref_height', 250)
        image = Image.new('1', (height, width), 255)  # landscape orientation
        draw = ImageDraw.Draw(image)

        # Use system font or fallback
        try:
            font = ImageFont.truetype(getattr(shared_data, 'font_arial_path', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'), 14)
            font_small = ImageFont.truetype(getattr(shared_data, 'font_arial_path', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'), 10)
        except Exception:
            font = ImageFont.load_default()
            font_small = font

        # Center the message
        draw.text((10, width // 2 - 20), message, font=font, fill=0)
        draw.text((10, width // 2 + 5), "Please wait...", font=font_small, fill=0)

        # Handle screen rotation
        from shared import normalize_rotation
        _rotation = normalize_rotation(shared_data.config.get('screen_reversed', 0))
        if _rotation:
            image = image.rotate(_rotation, expand=True)

        epd_helper.display_full(image)
        logger.info(f"E-paper transition: {message}")
    except Exception as e:
        logger.debug(f"E-paper transition message failed (non-fatal): {e}")


def _execute_pwn_mode_switch(target_mode: str) -> None:
    logger.info(f"Preparing service handoff to {target_mode}")
    time.sleep(PWN_SWAP_DELAY_SECONDS)

    if target_mode == 'pwnagotchi':
        _ensure_pwn_launcher()

        # Stop the display loop FIRST so it doesn't overwrite the transition message.
        # E-paper retains its image without power, so the message stays visible.
        shared_data.display_should_exit = True

        # Show transition message on e-paper before Ragnar stops.
        # Run in a thread with a timeout so a blocked SPI bus never hangs the swap.
        _epd_t = threading.Thread(target=_show_epaper_transition, args=("Switching to Pwnagotchi...",), daemon=True)
        _epd_t.start()
        _epd_t.join(timeout=4)

        # Write status and config BEFORE stopping ourselves
        message = 'Pwnagotchi starting up...'
        _write_pwn_status_file('switching', message, 'swap', {'target_mode': 'pwnagotchi'})
        _update_pwn_config({'pwnagotchi_mode': 'pwnagotchi', 'pwnagotchi_last_status': message})
        _emit_pwn_status_update()

        # Stop Ragnar first so it releases the GPIO/e-paper display, then start
        # pwnagotchi and bettercap.  Starting them before Ragnar stops causes a
        # 'GPIO busy' crash because both processes fight over the display pins.
        #
        # IMPORTANT: subprocess.Popen with start_new_session=True creates a new
        # session but NOT a new cgroup.  When systemd stops ragnar.service it
        # kills every process in the cgroup — including any bash child — so the
        # "&& start pwnagotchi" tail would never execute.  systemd-run launches
        # the sequence in its own transient cgroup, fully outside ragnar.service,
        # so it survives ragnar's cgroup teardown.
        try:
            subprocess.Popen(
                ['systemd-run', '--no-block', '--collect',
                 '--unit=ragnar-to-pwnagotchi-swap',
                 'bash', '-c',
                 'systemctl stop ragnar.service'
                 ' && python3 -OO /home/ragnar/Ragnar/wipe_epd.py 2>/dev/null; true'
                 ' && systemctl start bettercap.service'
                 ' && systemctl start pwnagotchi.service'
                 ' && systemctl start ragnar-swap-button.service'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info("Scheduled systemd-run swap: stop ragnar → start pwnagotchi")
        except Exception as exc:
            logger.error(f"Failed to schedule pwnagotchi start sequence: {exc}")
        return
    else:
        success, detail = _start_service_with_monitor('ragnar.service')
        if success:
            logger.info("Ragnar service reported active; stopping Pwnagotchi and bettercap services")
            _stop_service('pwnagotchi.service')
            _stop_service('bettercap.service')
            message = 'Ragnar service is running'
            _write_pwn_status_file('running', message, 'swap', {'target_mode': 'ragnar'})
            _update_pwn_config({'pwnagotchi_mode': 'ragnar', 'pwnagotchi_last_status': message})
        else:
            logger.error(f"Ragnar service failed to start: {detail}")
            failure_message = _format_service_failure_message('ragnar.service')
            extra = {'target_mode': 'pwnagotchi'}
            if detail:
                extra['service_error_detail'] = detail
            _write_pwn_status_file('error', failure_message, 'error', extra)
            _update_pwn_config({'pwnagotchi_mode': 'pwnagotchi', 'pwnagotchi_last_status': failure_message})
            _start_service_with_monitor('pwnagotchi.service', timeout=30)

    _emit_pwn_status_update()

def resolve_ip_hostname(ip):
    try:
        if _is_valid_ipv4(ip):
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
    except (socket.herror, socket.gaierror):
        return ''
    except Exception as e:
        logger.debug(f"Hostname resolution failed for {ip}: {e}")
    return ''


def update_vulnerability_output(ip, hostname, mac, is_alive):
    """Create or update vulnerability scan results file for discovered host"""
    try:
        # Ensure vulnerabilities output directory exists
        vuln_output_dir = os.path.join('data', 'output', 'vulnerabilities')
        os.makedirs(vuln_output_dir, exist_ok=True)
        
        # Create or update vulnerability scan results file for this IP
        vuln_file = os.path.join(vuln_output_dir, f'scan_{ip.replace(".", "_")}.txt')
        
        with open(vuln_file, 'w') as f:
            f.write(f"# Vulnerability scan results for {ip}\n")
            f.write(f"# Hostname: {hostname}\n")
            f.write(f"# MAC: {mac}\n")
            f.write(f"# Status: {'alive' if is_alive else 'dead'}\n")
            f.write(f"# Last updated: {datetime.now().isoformat()}\n")
            f.write(f"# Discovered via: ARP/Nmap network scanning\n\n")
            
            if is_alive:
                f.write(f"Host {ip} is alive and responding\n")
                f.write(f"MAC Address: {mac}\n")
                f.write(f"Hostname: {hostname}\n")
                f.write(f"Status: ACTIVE\n\n")
                f.write(f"=== NETWORK DISCOVERY RESULTS ===\n")
                f.write(f"Host discovered through network scanning\n")
                f.write(f"Further vulnerability scanning recommended\n")
            else:
                f.write(f"Host {ip} is not responding\n")
                f.write(f"Status: INACTIVE\n")
        
    except Exception as e:
        logger.error(f"Error updating vulnerability output for {ip}: {e}")


def update_netkb_entry(ip, hostname, mac, is_alive):
    try:
        # Update vulnerability output files
        update_vulnerability_output(ip, hostname, mac, is_alive)
        
        netkb_path = shared_data.netkbfile
        os.makedirs(os.path.dirname(netkb_path), exist_ok=True)

        rows = []
        headers: list[str] = []
        updated_row = None

        if os.path.exists(netkb_path) and os.path.getsize(netkb_path) > 0:
            with open(netkb_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                headers = list(reader.fieldnames) if reader.fieldnames else []
                for row in reader:
                    rows.append(row)
        else:
            headers = ['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports']

        for column in ['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports']:
            if column not in headers:
                headers.append(column)

        alive_value = '1' if is_alive else '0'
        mac_to_store = _normalize_mac(mac) if mac else ''

        for row in rows:
            existing_ips = [entry.strip() for entry in row.get('IPs', '').split(';') if entry.strip()]
            if ip in existing_ips:
                if mac_to_store:
                    row['MAC Address'] = mac_to_store
                # Don't generate pseudo MAC - let ARP cache provide real MAC addresses

                if hostname:
                    existing_hostnames = [h.strip() for h in row.get('Hostnames', '').split(';') if h.strip()]
                    existing_hostnames.append(hostname)
                    row['Hostnames'] = ';'.join(sorted(set(existing_hostnames)))

                row['Alive'] = alive_value
                # CRITICAL: NEVER clear the Ports field here!
                # Ports are managed by scanning.py - we only update Alive/MAC/Hostname
                # Preserve existing ports to prevent data loss
                updated_row = row
                break

        if updated_row is None:
            new_row = {header: '' for header in headers}
            new_row['IPs'] = ip
            new_row['Hostnames'] = hostname or ''
            if mac_to_store:
                new_row['MAC Address'] = mac_to_store
            else:
                # Don't generate pseudo MAC - let ARP cache provide real MAC addresses
                new_row['MAC Address'] = ''
            new_row['Alive'] = alive_value
            # CRITICAL: Don't set Ports to '' - preserve existing ports if they exist
            # The Ports field should only be updated by scanning.py during actual port scans
            # Leave it empty for new entries, but scanning.py will populate it
            new_row['Ports'] = new_row.get('Ports', '')  # Preserve if exists, empty if new
            rows.append(new_row)
            updated_row = new_row

        with open(netkb_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

        return updated_row
    except Exception as e:
        logger.error(f"Error updating netkb entry for {ip}: {e}")
        return None

def broadcast_status_update():
    """Immediately broadcast current status to all connected clients"""
    try:
        if clients_connected > 0:
            status_data = get_current_status()
            socketio.emit('status_update', status_data)
            logger.debug(f"Broadcasted status update: {status_data.get('ragnar_status', 'unknown')}")
    except Exception as e:
        logger.error(f"Error broadcasting status update: {e}")


def is_orchestrator_running() -> bool:
    """Determine whether the orchestrator thread is currently alive."""
    try:
        ragnar_instance = getattr(shared_data, 'ragnar_instance', None)
        if not ragnar_instance:
            return False

        orchestrator_thread = getattr(ragnar_instance, 'orchestrator_thread', None)
        if orchestrator_thread and orchestrator_thread.is_alive():
            return not getattr(shared_data, 'orchestrator_should_exit', False)
        return False
    except Exception as exc:
        logger.debug(f"Unable to determine automation state: {exc}")
        return False


def sync_vulnerability_count():
    """Synchronize vulnerability count across all data sources and network intelligence"""
    try:
        vuln_count = 0
        vulnerable_hosts = set()

        def record_host(candidate):
            """Normalize and record a host value for vulnerable host counting"""
            if candidate is None:
                return

            if isinstance(candidate, (list, tuple, set)):
                for item in candidate:
                    record_host(item)
                return

            host_value = str(candidate).strip()
            if not host_value:
                return

            lowered = host_value.lower()
            if lowered in {'unknown', 'none', 'n/a', 'na', 'null'}:
                return

            vulnerable_hosts.add(host_value)

        # Check if network intelligence is enabled
        if (hasattr(shared_data, 'network_intelligence') and
            shared_data.network_intelligence and
            shared_data.config.get('network_intelligence_enabled', True)):

            # Update network context first
            shared_data.network_intelligence.update_network_context()

            # Get active findings count for current network
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            vuln_count = dashboard_findings['counts']['vulnerabilities']

            for vuln_info in dashboard_findings.get('vulnerabilities', {}).values():
                if isinstance(vuln_info, dict):
                    record_host(
                        vuln_info.get('host') or
                        vuln_info.get('ip') or
                        vuln_info.get('target') or
                        vuln_info.get('hostname')
                    )

            logger.debug(f"Network intelligence vulnerability count: {vuln_count}")
        else:
            # Fallback to legacy file-based counting
            vuln_results_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
            
            logger.debug(f"Syncing vulnerabilities from directory: {vuln_results_dir}")
            
            # Create directory if it doesn't exist
            try:
                os.makedirs(vuln_results_dir, exist_ok=True)
                logger.debug(f"Ensured directory exists: {vuln_results_dir}")
            except Exception as e:
                logger.warning(f"Could not create vulnerabilities directory: {e}")
            
            if os.path.exists(vuln_results_dir):
                try:
                    files_found = []
                    for filename in os.listdir(vuln_results_dir):
                        if filename.endswith('.txt') and not filename.startswith('.'):
                            files_found.append(filename)
                            filepath = os.path.join(vuln_results_dir, filename)
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if content.strip():
                                        # Count CVEs or files with vulnerability content
                                        cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
                                        if cve_matches:
                                            vuln_count += len(cve_matches)
                                            logger.debug(f"Found {len(cve_matches)} CVEs in {filename}: {cve_matches}")
                                        elif len(content.strip()) > 50:  # File has significant content
                                            vuln_count += 1
                                            logger.debug(f"Found vulnerability content in {filename} (no CVEs)")
                            except Exception as e:
                                logger.debug(f"Could not read vulnerability file {filepath}: {e}")
                                continue

                    logger.debug(f"Vulnerability files found: {files_found}")
                    logger.debug(f"Total vulnerability count calculated: {vuln_count}")
                except Exception as e:
                    logger.warning(f"Could not list vulnerabilities directory: {e}")
            else:
                logger.warning(f"Vulnerabilities directory does not exist: {vuln_results_dir}")

            vuln_summary_file = getattr(shared_data, 'vuln_summary_file',
                                        os.path.join('data', 'output', 'vulnerabilities', 'vulnerability_summary.csv'))

            if os.path.exists(vuln_summary_file):
                try:
                    if pandas_available:
                        df = pd.read_csv(vuln_summary_file)
                        if not df.empty:
                            for _, row in df.iterrows():
                                vulnerabilities = safe_str(row.get('Vulnerabilities')).strip()
                                if vulnerabilities and vulnerabilities.lower() not in {'none', 'nan', 'na', '0'}:
                                    record_host(row.get('IP') or row.get('Hostname'))
                    else:
                        with open(vuln_summary_file, 'r', encoding='utf-8', errors='ignore') as summary_file:
                            reader = csv.DictReader(summary_file)
                            for row in reader:
                                vulnerabilities = (row.get('Vulnerabilities') or '').strip()
                                if vulnerabilities and vulnerabilities.lower() not in {'none', 'nan', 'na', '0'}:
                                    record_host(row.get('IP') or row.get('Hostname'))
                except Exception as e:
                    logger.debug(f"Could not parse vulnerability summary for host count: {e}")

        # Update shared data with synchronized count
        old_count = shared_data.vulnnbr
        shared_data.vulnnbr = vuln_count
        logger.debug(f"Updated shared_data.vulnnbr: {old_count} -> {vuln_count}")

        # ── Pushover: new vulnerability notification ──
        # Always pass the absolute total; PushoverService tracks its own baseline
        # (loaded from DB at startup) to avoid re-alerting on restart.
        try:
            from pushover_service import PushoverService
            _po = getattr(shared_data, '_pushover_service', None)
            if _po is None:
                _po = PushoverService(shared_data)
                shared_data._pushover_service = _po
            _po.notify_new_vulnerabilities(vuln_count)
        except Exception as _po_err:
            logger.debug(f"Pushover vulnerability notification skipped: {_po_err}")

        old_host_count = getattr(shared_data, 'vulnerable_host_count', 0)
        shared_data.vulnerable_host_count = len(vulnerable_hosts)
        logger.debug(f"Updated vulnerable host count: {old_host_count} -> {shared_data.vulnerable_host_count}")

        # SQLite is the primary source of truth - CSV livestatus file is deprecated
        logger.debug(f"Synchronized vulnerability count: {vuln_count}")
        return vuln_count
        
    except Exception as e:
        logger.error(f"Error synchronizing vulnerability count: {e}")
        return safe_int(shared_data.vulnnbr)


def sync_all_counts():
    """Synchronize all counts (targets, ports, vulnerabilities, credentials) across data sources.
    
    This function reads from SQLite database as the single source of truth and applies the
    30-ping failure rule to determine which hosts are considered active (alive vs degraded).
    """
    global last_sync_time, network_scan_cache

    with sync_lock:
        start_time = time.time()
        try:
            logger.debug("Starting sync_all_counts()")

            # Sync vulnerability count
            sync_vulnerability_count()

            # ==============================================================================
            # PRIMARY DATA SOURCE: Read from SQLite database
            # ==============================================================================
            
            aggregated_targets = 0
            aggregated_ports = 0  # Count total port instances across all hosts
            total_target_count = 0
            inactive_target_count = 0
            current_snapshot = {}
            discovered_macs = set()
            port_debug_info = []  # Track which hosts contribute to port count
            
            # Read from SQLite database
            try:
                db = get_db(currentdir=shared_data.currentdir)
                hosts = db.get_all_hosts()
                
                logger.info(f"[SQLITE SYNC] Reading from SQLite database")
                
                for host in hosts:
                    ip = host.get("ip", "").strip()
                    mac = host.get("mac", "").strip()
                    
                    # Skip standalone entries or entries without IP
                    if mac == "STANDALONE" or not ip:
                        continue
                    
                    # Get status from database (alive or degraded)
                    status = host.get("status", "alive")
                    failed_pings = host.get("failed_ping_count", 0)
                    
                    # Host is active if status is 'alive' (0-29 failed pings)
                    # Host is inactive/degraded if status is 'degraded' (30+ failed pings)
                    is_active = (status == 'alive')
                    
                    if mac:
                        discovered_macs.add(mac)

                    # Count all hosts for total
                    total_target_count += 1
                    
                    # Count active hosts
                    if is_active:
                        aggregated_targets += 1
                        
                        # Count all port instances - support both comma (SQLite) and semicolon (CSV) delimiters
                        ports_str = host.get('ports', '')
                        if ports_str and ports_str != '0':
                            # Check for comma first (SQLite format), else semicolon (CSV format)
                            if ',' in ports_str:
                                port_list = [p.strip() for p in ports_str.split(',') if p.strip() and p.strip() != '0']
                            else:
                                port_list = [p.strip() for p in ports_str.split(';') if p.strip() and p.strip() != '0']
                            
                            # Count valid numeric ports
                            valid_ports = [p for p in port_list if p.isdigit()]
                            aggregated_ports += len(valid_ports)
                            port_list = valid_ports  # Use only valid ports for snapshot
                            
                            # Track for debugging
                            if len(valid_ports) > 0:
                                hostname = host.get('hostname', '')
                                port_debug_info.append(f"{ip} ({hostname}): {len(valid_ports)} ports [{','.join(valid_ports)}]")
                        else:
                            port_list = []
                        
                        # Track in snapshot
                        current_snapshot[ip] = {
                            'alive': True,
                            'ports': set(port_list),
                            'failed_pings': failed_pings,
                            'source': 'sqlite',
                            'mac': mac
                        }
                    else:
                        inactive_target_count += 1
                        current_snapshot[ip] = {
                            'alive': False,
                            'ports': set(),
                            'failed_pings': failed_pings,
                            'source': 'sqlite',
                            'mac': mac
                        }
                
                logger.debug(f"[SYNC] ✅ Read data from SQLite database:")
                logger.debug(f"  - Total unique IPs: {total_target_count}")
                logger.debug(f"  - Active (alive): {aggregated_targets}")
                logger.debug(f"  - Inactive (degraded): {inactive_target_count}")
                logger.debug(f"  - Total open ports: {aggregated_ports}")
                

                if port_debug_info:
                    logger.debug(f"[PORT COUNT BREAKDOWN] Counting ports from {len(port_debug_info)} alive hosts with open ports:")
                    for info in port_debug_info[:10]:
                        logger.debug(f"    {info}")
                    if len(port_debug_info) > 10:
                        logger.debug(f"    ... and {len(port_debug_info) - 10} more hosts with ports")
                
            except Exception as e:
                logger.error(f"[SQLITE SYNC] ❌ Error reading from SQLite database: {e}")
                traceback.print_exc()

            old_targets = shared_data.targetnbr
            old_ports = shared_data.portnbr

            shared_data.targetnbr = aggregated_targets
            shared_data.total_targetnbr = total_target_count
            shared_data.inactive_targetnbr = inactive_target_count
            shared_data.portnbr = aggregated_ports
            shared_data.networkkbnbr = total_target_count
            
            if old_targets != aggregated_targets or old_ports != aggregated_ports:
                logger.info(f"✅ Updated counts from SQLite database:")
                logger.info(f"  - Targets: {old_targets} -> {aggregated_targets}")
                logger.info(f"  - Ports: {old_ports} -> {aggregated_ports}")
                logger.info(f"  - Total hosts: {total_target_count}")
                logger.info(f"  - Inactive hosts: {inactive_target_count}")
            else:
                logger.debug(f"Counts unchanged: targets={aggregated_targets}, ports={aggregated_ports}")

            # Track new and lost hosts
            previous_snapshot = getattr(shared_data, 'network_hosts_snapshot', {}) or {}
            previous_active_hosts = {ip for ip, meta in previous_snapshot.items() if meta.get('alive', True)}
            current_active_hosts = {ip for ip, meta in current_snapshot.items() if meta.get('alive', True)}

            new_active_hosts = current_active_hosts - previous_active_hosts
            lost_active_hosts = previous_active_hosts - current_active_hosts

            shared_data.network_hosts_snapshot = current_snapshot
            shared_data.new_target_ips = sorted(new_active_hosts)
            shared_data.lost_target_ips = sorted(lost_active_hosts)
            shared_data.new_targets = len(shared_data.new_target_ips)
            shared_data.lost_targets = len(shared_data.lost_target_ips)

            # ── Pushover: new / lost device notifications ──
            try:
                from pushover_service import PushoverService
                _po = getattr(shared_data, '_pushover_service', None)
                if _po is None:
                    _po = PushoverService(shared_data)
                    shared_data._pushover_service = _po
                if new_active_hosts:
                    _po.notify_new_devices(new_active_hosts)
                    _po.notify_device_back_online(new_active_hosts)
                if lost_active_hosts:
                    _po.notify_device_lost(lost_active_hosts)
            except Exception as _po_err:
                logger.debug(f"Pushover new/lost device notification skipped: {_po_err}")

            if discovered_macs:
                new_mac_count, points_awarded = shared_data.process_discovered_macs(discovered_macs)
                if new_mac_count:
                    logger.info(
                        f"[GAMIFICATION] Registered {new_mac_count} new MAC(s), awarded {points_awarded} points"
                    )

            # Use network-specific credential directory
            cred_results_dir = getattr(shared_data, 'crackedpwd_dir', os.path.join('data', 'output', 'crackedpwd'))

            logger.debug(f"Syncing credentials from network-specific directory: {cred_results_dir}")

            try:
                os.makedirs(cred_results_dir, exist_ok=True)
                logger.debug(f"Ensured directory exists: {cred_results_dir}")
            except Exception as e:
                logger.warning(f"Could not create crackedpwd directory: {e}")

            if os.path.exists(cred_results_dir):
                cred_count = 0
                try:
                    # Get stable file list (excludes temporary/hidden files) - only CSV files for network storage
                    cred_files_found = []
                    for filename in sorted(os.listdir(cred_results_dir)):
                        if filename.endswith('.csv') and not filename.startswith('.') and not filename.endswith('.tmp'):
                            filepath = os.path.join(cred_results_dir, filename)
                            # Only count files that exist and aren't being written to
                            try:
                                stat_info = os.stat(filepath)
                                if stat_info.st_size > 0:  # Skip empty files
                                    cred_files_found.append(filename)
                            except (OSError, IOError):
                                continue  # Skip files that can't be accessed
                    
                    # Count credentials from stable file list
                    for filename in cred_files_found:
                        filepath = os.path.join(cred_results_dir, filename)
                        try:
                            # Use more robust file reading with retry for locked files
                            max_retries = 2
                            for attempt in range(max_retries):
                                try:
                                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                        lines = f.readlines()
                                        # Skip header row and count data rows only
                                        data_rows = 0
                                        for i, line in enumerate(lines):
                                            line = line.strip()
                                            if line:
                                                # Skip first line if it contains CSV headers
                                                if i == 0 and ('MAC Address' in line or 'IP Address' in line or 'User' in line or 'Password' in line):
                                                    continue
                                                # Count non-empty data rows
                                                data_rows += 1
                                        cred_count += data_rows
                                    break  # Success, exit retry loop
                                except (IOError, OSError) as e:
                                    if attempt == max_retries - 1:  # Last attempt
                                        logger.debug(f"Could not read credential file {filepath} after {max_retries} attempts: {e}")
                                    else:
                                        time.sleep(0.1)  # Brief pause before retry
                        except Exception as e:
                            logger.debug(f"Error processing credential file {filepath}: {e}")
                            continue

                    if cred_count > 0 or len(cred_files_found) > 0:
                        logger.debug(f"Credential count: {cred_count} from {len(cred_files_found)} files")
                except Exception as e:
                    logger.warning(f"Could not list crackedpwd directory: {e}")

                # Only update if we have a stable count (prevent flickering)
                old_creds = shared_data.crednbr
                if old_creds != cred_count:
                    shared_data.crednbr = cred_count
                    logger.info(f"WEBAPP: Updated credentials: {old_creds} -> {cred_count} from {len(cred_files_found)} files")
                    # ── Pushover: new credentials notification ──
                    if cred_count > old_creds:
                        try:
                            _po = getattr(shared_data, '_pushover_service', None)
                            if _po:
                                _po.notify_new_credentials(cred_count - old_creds, cred_count)
                        except Exception as _po_err:
                            logger.debug(f"Pushover credential notification skipped: {_po_err}")
                else:
                    logger.debug(f"WEBAPP: Credentials stable at: {cred_count} from {len(cred_files_found)} files")
            else:
                logger.warning(f"Crackedpwd directory does not exist: {cred_results_dir}")

            data_stolen_dir = getattr(shared_data, 'datastolendir', os.path.join('data', 'output', 'data_stolen'))
            if os.path.exists(data_stolen_dir):
                try:
                    total_data_files = sum([len(files) for r, d, files in os.walk(data_stolen_dir)])
                    old_data = shared_data.datanbr
                    shared_data.datanbr = total_data_files
                    logger.debug(f"Updated data stolen: {old_data} -> {total_data_files}")
                except Exception as e:
                    logger.debug(f"Could not count data stolen files: {e}")
            
            zombies_dir = getattr(shared_data, 'zombiesdir', os.path.join('data', 'output', 'zombies'))
            if os.path.exists(zombies_dir):
                try:
                    total_zombies = sum([len(files) for r, d, files in os.walk(zombies_dir)])
                    old_zombies = shared_data.zombiesnbr
                    shared_data.zombiesnbr = total_zombies
                    logger.debug(f"Updated zombies: {old_zombies} -> {total_zombies}")
                except Exception as e:
                    logger.debug(f"Could not count zombie files: {e}")
            
            actions_dir = getattr(shared_data, 'actions_dir', os.path.join('actions'))
            if os.path.exists(actions_dir):
                try:
                    total_attacks = sum([len(files) for r, d, files in os.walk(actions_dir) if not r.endswith("__pycache__")]) - 2
                    old_attacks = shared_data.attacksnbr
                    shared_data.attacksnbr = max(total_attacks, 0)
                    logger.debug(f"Updated attacks: {old_attacks} -> {shared_data.attacksnbr}")
                except Exception as e:
                    logger.debug(f"Could not count attack modules: {e}")

            
            try:
                shared_data.update_stats()
                logger.debug(f"Updated gamification stats - Level: {shared_data.levelnbr}, Coins: {shared_data.coinnbr}")
                logger.debug(f"Stats breakdown - NetworkKB: {shared_data.networkkbnbr}, Creds: {shared_data.crednbr}, Data: {shared_data.datanbr}, Zombies: {shared_data.zombiesnbr}, Attacks: {shared_data.attacksnbr}, Vulns: {shared_data.vulnnbr}")
            except Exception as e:
                logger.warning(f"Could not update gamification stats: {e}")

            # Cache scanned network count (calculate once per sync cycle)
            try:
                # Recalculate scanned networks count
                scanned_networks = shared_data._calculate_scanned_networks_count()
                shared_data.scanned_networks_count = scanned_networks
                logger.info(f"SYNC: Updated scanned networks count: {scanned_networks}")
            except Exception as e:
                logger.error(f"SYNC: Could not update scanned networks count: {e}")
                import traceback
                logger.error(f"SYNC: Scanned networks error traceback: {traceback.format_exc()}")
                if not hasattr(shared_data, 'scanned_networks_count'):
                    shared_data.scanned_networks_count = 0

            logger.debug(f"Completed sync_all_counts() - Active Targets: {shared_data.targetnbr}, Total Targets: {shared_data.total_targetnbr}, Inactive Targets: {shared_data.inactive_targetnbr}, Ports: {shared_data.portnbr}, Vulns: {shared_data.vulnnbr}, Creds: {shared_data.crednbr}, Networks: {getattr(shared_data, 'scanned_networks_count', 0)}, Level: {shared_data.levelnbr}, Coins: {shared_data.coinnbr}")
            
            if shared_data.targetnbr > shared_data.total_targetnbr:
                logger.warning(f"CONSISTENCY WARNING: Active targets ({shared_data.targetnbr}) > Total targets ({shared_data.total_targetnbr}). Adjusting total.")
                shared_data.total_targetnbr = shared_data.targetnbr
                shared_data.inactive_targetnbr = 0

        except Exception as e:
            logger.error(f"Error synchronizing all counts: {e}")
        finally:
            last_sync_time = time.time()
            shared_data.last_sync_timestamp = last_sync_time
            duration = last_sync_time - start_time
            logger.debug(f"sync_all_counts() finished in {duration:.2f}s")


def _get_network_context_snapshot(target_identifier: Optional[str]) -> Dict[str, str]:
    """Return a storage context for the requested SSID/slug without mutating global state."""
    manager = getattr(shared_data, 'storage_manager', None)
    if not manager:
        raise RuntimeError('Network storage manager unavailable')

    identifier = (target_identifier or '').strip()
    if not identifier or identifier.lower() in {'current', 'active'}:
        return manager.get_context_snapshot(shared_data.active_network_ssid)
    return manager.get_context_snapshot(identifier)


def _split_port_field(port_field: Optional[str]) -> List[str]:
    if not port_field:
        return []
    normalized = str(port_field).replace(';', ',')
    ports = []
    for token in normalized.split(','):
        value = token.strip()
        if not value or value == '0':
            continue
        if value.isdigit():
            ports.append(value)
        else:
            match = re.match(r'^(\d+)', value)
            if match:
                ports.append(match.group(1))
    return ports


def _count_credentials_in_dir(directory: Optional[str]) -> int:
    if not directory or not os.path.isdir(directory):
        return 0
    total = 0
    for filename in os.listdir(directory):
        if not filename.endswith('.csv') or filename.startswith('.'):
            continue
        filepath = os.path.join(directory, filename)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as handle:
                for index, line in enumerate(handle):
                    line = line.strip()
                    if not line:
                        continue
                    if index == 0 and ('mac' in line.lower() or 'user' in line.lower()):
                        continue
                    total += 1
        except (OSError, IOError):
            continue
    return total


def _count_files_in_tree(directory: Optional[str]) -> int:
    if not directory or not os.path.isdir(directory):
        return 0
    total = 0
    for _root, _dirs, files in os.walk(directory):
        total += len(files)
    return total


def _load_intelligence_vulnerability_counts(intelligence_dir: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    # Prefer live, in-memory data from the intelligence engine when available so
    # dashboard cards stay aligned with the Threat Intel tab.
    try:
        network_intel = getattr(shared_data, 'network_intelligence', None)
        intel_enabled = getattr(shared_data, 'config', {}).get('network_intelligence_enabled', True)
        if network_intel and intel_enabled:
            findings = network_intel.get_active_findings_for_dashboard() or {}
            vuln_map = findings.get('vulnerabilities') or {}
            counts = findings.get('counts') or {}
            vuln_total = counts.get('vulnerabilities')
            if vuln_total is None:
                vuln_total = len(vuln_map)

            host_keys = set()
            for vuln in vuln_map.values():
                host_identifier = (vuln.get('host') or vuln.get('ip') or vuln.get('target') or '').strip()
                if host_identifier:
                    host_keys.add(host_identifier)
            host_total = len(host_keys)

            return safe_int(vuln_total, 0), safe_int(host_total, 0)
    except Exception as exc:
        logger.debug(f"Unable to read live network intelligence counts: {exc}")

    if not intelligence_dir:
        return None, None
    findings_file = os.path.join(intelligence_dir, 'active_findings.json')
    if not os.path.exists(findings_file):
        return None, None
    try:
        with open(findings_file, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
        counts = payload.get('counts') or {}
        vulnerabilities = counts.get('vulnerabilities')
        affected = counts.get('affected_hosts') or counts.get('hosts')

        vuln_map = payload.get('vulnerabilities') or {}
        if vulnerabilities is None:
            if isinstance(vuln_map, dict):
                vulnerabilities = len(vuln_map)
            elif isinstance(vuln_map, list):
                vulnerabilities = len(vuln_map)

        if affected is None and isinstance(vuln_map, dict):
            host_keys = { (item.get('host') or item.get('ip') or item.get('target') or '').strip()
                          for item in vuln_map.values()
                          if (item.get('host') or item.get('ip') or item.get('target')) }
            affected = len([key for key in host_keys if key])

        return safe_int(vulnerabilities, None), safe_int(affected, None)
    except Exception as exc:
        logger.debug(f"Unable to read network intelligence findings: {exc}")
        return None, None


def _calculate_dashboard_stats_from_context(context: Dict[str, str]) -> Dict:
    network_dir = context.get('network_dir')
    db_path = context.get('db_path')
    credentials_dir = context.get('credentials_dir')
    intelligence_dir = context.get('intelligence_dir')
    stats = {
        'network_ssid': context.get('ssid') or 'default',
        'network_slug': context.get('slug'),
        'target_count': 0,
        'active_target_count': 0,
        'inactive_target_count': 0,
        'total_target_count': 0,
        'new_target_count': 0,
        'lost_target_count': 0,
        'new_target_ips': [],
        'lost_target_ips': [],
        'port_count': 0,
        'vulnerability_count': 0,
        'vulnerable_hosts_count': 0,
        'credential_count': 0,
        'data_count': 0,
        'level': safe_int(shared_data.levelnbr),
        'points': safe_int(shared_data.coinnbr),
        'scanned_network_count': safe_int(getattr(shared_data, 'scanned_networks_count', shared_data._calculate_scanned_networks_count()), 0),
        'last_sync_timestamp': None,
        'last_sync_iso': None,
        'last_sync_age_seconds': None,
    }

    hosts = []
    if db_path and os.path.exists(db_path):
        try:
            temp_db = DatabaseManager(db_path=db_path, currentdir=shared_data.currentdir, data_root=network_dir)
            hosts = temp_db.get_all_hosts()
        except Exception as exc:
            logger.error(f"Unable to read hosts for network context {context.get('slug')}: {exc}")

    max_failed = safe_int(shared_data.config.get('network_max_failed_pings', 15), 15)
    max_failed = max(1, max_failed)

    vulnerable_hosts = set()
    vuln_count_override, vuln_hosts_override = _load_intelligence_vulnerability_counts(intelligence_dir)

    for host in hosts:
        stats['total_target_count'] += 1
        status = (host.get('status') or '').lower()
        failed = safe_int(host.get('failed_ping_count'), 0)
        is_active = status == 'alive' or failed < max_failed
        if is_active:
            stats['active_target_count'] += 1
            stats['port_count'] += len(_split_port_field(host.get('ports')))
        else:
            stats['inactive_target_count'] += 1

        vuln_field = host.get('vulnerabilities') or host.get('nmap_vuln_scanner') or host.get('scanner_status')
        if vuln_field:
            text = str(vuln_field).strip()
            if text and text.lower() not in {'none', 'clean', 'ok', '0', '[]'}:
                cves = re.findall(r'CVE-\d{4}-\d+', text)
                stats['vulnerability_count'] += len(cves) if cves else 1
                host_label = host.get('ip') or host.get('hostname') or host.get('mac')
                if host_label:
                    vulnerable_hosts.add(host_label)

    if vuln_count_override is not None:
        stats['vulnerability_count'] = vuln_count_override
    if vuln_hosts_override is not None:
        stats['vulnerable_hosts_count'] = vuln_hosts_override
    else:
        stats['vulnerable_hosts_count'] = len(vulnerable_hosts)

    stats['credential_count'] = _count_credentials_in_dir(credentials_dir)
    stats['data_count'] = _count_files_in_tree(context.get('data_stolen_dir'))
    stats['target_count'] = stats['active_target_count']

    # Derive timestamps from DB modification time when available
    timestamp_source = None
    if db_path and os.path.exists(db_path):
        try:
            timestamp_source = os.path.getmtime(db_path)
        except OSError:
            timestamp_source = None
    if timestamp_source is None:
        timestamp_source = time.time()
    stats['last_sync_timestamp'] = timestamp_source
    try:
        stats['last_sync_iso'] = datetime.fromtimestamp(timestamp_source).isoformat()
        stats['last_sync_age_seconds'] = max(time.time() - timestamp_source, 0)
    except Exception:
        stats['last_sync_iso'] = None
        stats['last_sync_age_seconds'] = None

    return stats


def _collect_dashboard_stats_for_network(identifier: Optional[str]) -> Dict:
    context = _get_network_context_snapshot(identifier)
    return _calculate_dashboard_stats_from_context(context)


def safe_int(value, default=0):
    """Safely convert value to int, handling numpy types"""
    try:
        if hasattr(value, 'item'):
            return int(value.item())
        return int(value) if value is not None else default
    except (ValueError, TypeError, AttributeError):
        return default

def safe_str(value, default=""):
    """Safely convert value to string"""
    try:
        return str(value) if value is not None else default
    except (ValueError, TypeError):
        return default

def safe_bool(value, default=False):
    """Safely convert value to boolean, supporting common string inputs."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
        return default
    try:
        return bool(value)
    except (ValueError, TypeError):
        return default


def _build_release_gate_payload():
    enabled = safe_bool(shared_data.config.get('release_gate_enabled', False))
    message = shared_data.config.get('release_gate_message') or RELEASE_GATE_DEFAULT_MESSAGE
    return {
        'enabled': enabled,
        'message': safe_str(message or RELEASE_GATE_DEFAULT_MESSAGE)
    }


def ensure_recent_sync(max_age=SYNC_BACKGROUND_INTERVAL):
    """Ensure counts are synchronized if the last update is older than max_age seconds"""
    global last_sync_time

    if time.time() - last_sync_time > max_age:
        logger.debug("Triggering on-demand sync_all_counts() due to stale data")
        sync_all_counts()


_wifi_ssid_cache = {'ssid': None, 'timestamp': 0}
_WIFI_SSID_CACHE_TTL = 60

def _get_active_ethernet_ip():
    """Get the IP of the active ethernet interface, or empty string."""
    try:
        iface = get_active_ethernet_interface()
        return iface.get('ip_address', '') if iface else ''
    except Exception:
        return ''

def _get_active_ethernet_name():
    """Get the name of the active ethernet interface, or empty string."""
    try:
        iface = get_active_ethernet_interface()
        return iface.get('name', '') if iface else ''
    except Exception:
        return ''

def get_current_wifi_ssid():
    """Get the current WiFi SSID for file naming"""
    global _wifi_ssid_cache
    
    current_timestamp = time.time()
    if _wifi_ssid_cache['ssid'] and (current_timestamp - _wifi_ssid_cache['timestamp']) < _WIFI_SSID_CACHE_TTL:
        return _wifi_ssid_cache['ssid']
    
    try:
        if hasattr(shared_data, 'wifi_manager') and getattr(shared_data, 'wifi_manager', None):
            wifi_manager = getattr(shared_data, 'wifi_manager')
            ssid = wifi_manager.get_current_ssid()
            if ssid:
                # Sanitize SSID for filename
                sanitized = re.sub(r'[^\w\-_]', '_', ssid)
                _wifi_ssid_cache['ssid'] = sanitized
                _wifi_ssid_cache['timestamp'] = current_timestamp
                return sanitized
        
        # Fallback to direct system command
        result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.startswith('yes:'):
                    ssid = line.split(':', 1)[1]
                    if ssid:
                        # Sanitize SSID for filename
                        sanitized = re.sub(r'[^\w\-_]', '_', ssid)
                        _wifi_ssid_cache['ssid'] = sanitized
                        _wifi_ssid_cache['timestamp'] = current_timestamp
                        return sanitized
        
        # Cache the default value too
        _wifi_ssid_cache['ssid'] = "unknown_network"
        _wifi_ssid_cache['timestamp'] = current_timestamp
        return "unknown_network"
    except Exception as e:
        logger.debug(f"Error getting current WiFi SSID: {e}")
        # Cache the error result
        _wifi_ssid_cache['ssid'] = "unknown_network"
        _wifi_ssid_cache['timestamp'] = current_timestamp
        return "unknown_network"


def get_wifi_specific_network_file():
    """Get the WiFi-specific network data file path"""
    current_ssid = get_current_wifi_ssid()
    data_dir = os.path.join('data', 'network_data')
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, f'network_{current_ssid}.csv')


def check_and_handle_network_switch():
    """Check if we've switched networks and clear old data if so"""
    try:
        current_ssid = get_current_wifi_ssid()
        last_ssid_file = os.path.join('data', 'network_data', '.last_ssid')
        
        # Check if we have a record of the last SSID
        last_ssid = None
        if os.path.exists(last_ssid_file):
            try:
                with open(last_ssid_file, 'r', encoding='utf-8') as f:
                    last_ssid = f.read().strip()
            except Exception as e:
                logger.debug(f"Error reading last SSID file: {e}")
        
        # If SSID has changed, clear old network data files
        if last_ssid and last_ssid != current_ssid:
            logger.info(f"Network switch detected: {last_ssid} -> {current_ssid}")
            
            # Clear old network data files
            data_dir = os.path.join('data', 'network_data')
            if os.path.exists(data_dir):
                for filename in os.listdir(data_dir):
                    if filename.startswith('network_') and filename.endswith('.csv'):
                        old_file = os.path.join(data_dir, filename)
                        try:
                            os.remove(old_file)
                            logger.info(f"Removed old network data file: {filename}")
                        except Exception as e:
                            logger.error(f"Error removing old network data file {filename}: {e}")
        
        # Update the last SSID record
        try:
            os.makedirs(os.path.dirname(last_ssid_file), exist_ok=True)
            with open(last_ssid_file, 'w', encoding='utf-8') as f:
                f.write(current_ssid)
        except Exception as e:
            logger.error(f"Error updating last SSID file: {e}")
    
    except Exception as e:
        logger.error(f"Error checking network switch: {e}")


def _is_ip_address(value):
    """Check if a value is a valid IP address"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_port_value(port_entry):
    """Normalize a port entry string for consistent comparisons"""
    try:
        if not port_entry:
            return None

        cleaned = port_entry.strip()
        if not cleaned:
            return None

        # Extract numeric portion if the port entry contains protocol suffixes
        match = re.match(r"^(\d+)", cleaned)
        if match:
            return match.group(1)

        return cleaned
    except Exception:
        return None


def _normalize_alive_value(value):
    """Normalize alive column values to boolean"""
    try:
        if value is None:
            return True

        if isinstance(value, bool):
            return value

        if isinstance(value, (int, float)):
            return value != 0

        text = str(value).strip().lower()
        if text in ('', '1', 'true', 'yes', 'up', 'alive', 'online'):
            return True
        if text in ('0', 'false', 'no', 'down', 'dead', 'offline'):
            return False

        return True
    except Exception:
        return True


def update_wifi_network_data():
    """Update WiFi-specific network data from scan results and provide aggregated counts"""
    try:
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        wifi_network_file = get_wifi_specific_network_file()

        # Load existing data if file exists
        existing_data = {}
        if os.path.exists(wifi_network_file):
            try:
                with open(wifi_network_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    headers = next(reader, None)
                    if headers:
                        for row in reader:
                                if len(row) >= 1 and row[0].strip():
                                    ip = row[0].strip()
                                    ports = set()
                                    if len(row) > 4 and row[4]:
                                        # Parse ports from semicolon-separated list
                                        for port_entry in row[4].split(';'):
                                            normalized = _normalize_port_value(port_entry)
                                            if normalized:
                                                ports.add(normalized)

                                existing_data[ip] = {
                                    'hostname': row[1] if len(row) > 1 else '',
                                    'alive': _normalize_alive_value(row[2] if len(row) > 2 else '1'),
                                    'mac': row[3] if len(row) > 3 else '',
                                    'ports': ports,
                                    'last_seen': row[5] if len(row) > 5 else datetime.now().isoformat(),
                                    # New fields for robust connectivity tracking (with backward compatibility)
                                    'failed_ping_count': int(row[6]) if len(row) > 6 and row[6].isdigit() else 0,
                                    'last_successful_ping': row[7] if len(row) > 7 else '',
                                    'last_ping_attempt': row[8] if len(row) > 8 else ''
                                }
                        
                        # Log loaded data for debugging
                        total_ports_loaded = sum(len(data['ports']) for data in existing_data.values())
                        logger.debug(f"[WIFI DATA LOAD] Loaded {len(existing_data)} hosts with {total_ports_loaded} total ports from {wifi_network_file}")
                        
                        # Log hosts with many ports (likely from deep scans)
                        for ip, data in existing_data.items():
                            if len(data['ports']) > 10:
                                logger.debug(f"[WIFI DATA LOAD] {ip} has {len(data['ports'])} ports (likely from deep scan)")
                                
            except Exception as e:
                logger.debug(f"Could not read existing WiFi network file: {e}")

        # Process new scan results (with caching to avoid reprocessing unchanged files)
        if os.path.exists(scan_results_dir):
            current_time = datetime.now().isoformat()
            global processed_scan_files
            
            files_to_process = []
            for filename in os.listdir(scan_results_dir):
                if filename.startswith('result_') and filename.endswith('.csv'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        # Check if file has been modified since we last processed it
                        file_mtime = os.path.getmtime(filepath)
                        if filename not in processed_scan_files or processed_scan_files[filename] < file_mtime:
                            files_to_process.append((filename, filepath, file_mtime))
                    except Exception as e:
                        logger.debug(f"Could not check mtime for {filepath}: {e}")
                        
            # Log caching efficiency
            if len(files_to_process) == 0:
                logger.debug(f"[SCAN CACHE] All {len(processed_scan_files)} scan files already processed, skipping")
            elif len(files_to_process) < len(os.listdir(scan_results_dir)):
                logger.debug(f"[SCAN CACHE] Processing {len(files_to_process)} new/modified files, skipping {len(processed_scan_files) - len(files_to_process)} cached files")

            for filename, filepath, file_mtime in files_to_process:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.reader(f)
                        for row in reader:
                            if len(row) >= 1 and row[0].strip():
                                ip = row[0].strip()
                                if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                                    hostname = row[1] if len(row) > 1 and row[1] else ''
                                    alive = _normalize_alive_value(row[2] if len(row) > 2 and row[2] else '1')
                                    mac = row[3] if len(row) > 3 and row[3] else ''

                                    # Collect ports from remaining columns
                                    ports = set()
                                    if len(row) > 4:
                                        for port_col in row[4:]:
                                            normalized = _normalize_port_value(port_col)
                                            if normalized:
                                                ports.add(normalized)

                                    # Update or add entry
                                    if ip in existing_data:
                                        # Merge data - PRESERVE ALL EXISTING PORTS (including deep scan results)
                                        existing_ports_before = len(existing_data[ip]['ports'])
                                        
                                        if hostname and hostname != 'Unknown':
                                            existing_data[ip]['hostname'] = hostname
                                        if mac and mac != 'Unknown':
                                            existing_data[ip]['mac'] = mac
                                        existing_data[ip]['alive'] = alive
                                        
                                        # CRITICAL: Add new ports to existing set, don't replace
                                        existing_data[ip]['ports'].update(ports)
                                        
                                        existing_ports_after = len(existing_data[ip]['ports'])
                                        # Only log significant port changes to reduce noise
                                        if existing_ports_after > existing_ports_before and (existing_ports_after - existing_ports_before) >= 3:
                                            logger.info(f"[PORT PRESERVATION] {ip}: Added {existing_ports_after - existing_ports_before} new ports (total: {existing_ports_after})")
                                        
                                        existing_data[ip]['last_seen'] = current_time
                                        # Reset failure counter on successful scan
                                        existing_data[ip]['failed_ping_count'] = 0
                                        existing_data[ip]['last_successful_ping'] = current_time
                                    else:
                                        # New entry
                                        existing_data[ip] = {
                                            'hostname': hostname,
                                            'alive': alive,
                                            'mac': mac,
                                            'ports': ports,
                                            'last_seen': current_time,
                                            'failed_ping_count': 0,
                                            'last_successful_ping': current_time,
                                            'last_ping_attempt': current_time
                                        }
                    
                    # Mark file as processed
                    processed_scan_files[filename] = file_mtime
                    
                except Exception as e:
                    logger.debug(f"Could not read scan result file {filepath}: {e}")
                    continue
        
        # Remove entries that haven't been seen recently
        retention_days = shared_data.config.get('network_device_retention_days', 14)
        try:
            retention_days = int(retention_days)
        except (ValueError, TypeError):
            retention_days = 14

        retention_days = max(retention_days, 1)
        stale_cutoff = datetime.now() - timedelta(days=retention_days)

        stale_hosts = []
        for ip, data in list(existing_data.items()):
            try:
                last_seen_dt = datetime.fromisoformat(data.get('last_seen', datetime.now().isoformat()))
            except Exception:
                last_seen_dt = datetime.now()

            if last_seen_dt < stale_cutoff:
                stale_hosts.append(ip)

        for ip in stale_hosts:
            existing_data.pop(ip, None)

        # Update alive status based on current ARP cache data with robust connectivity tracking
        # IMPORTANT: Only update ping counters when we have fresh ARP data (within last ARP_SCAN_INTERVAL)
        current_time = datetime.now().isoformat()
        current_timestamp = time.time()
        arp_hosts = network_scan_cache.get('arp_hosts', {})
        last_arp_scan_time = network_scan_cache.get('last_arp_scan', 0)
        arp_data_is_fresh = (current_timestamp - last_arp_scan_time) < ARP_SCAN_INTERVAL + 2  # +2 for timing tolerance
        MAX_FAILED_PINGS = shared_data.config.get('network_max_failed_pings', 15)  # Changed to 15 for more stability
        
        for ip, data in existing_data.items():
            # Initialize failure counter if not present
            if 'failed_ping_count' not in data:
                data['failed_ping_count'] = 0
            
            # Update alive status based on ARP cache
            if ip in arp_hosts:
                # Device responded - reset failure counter and mark as alive
                data['failed_ping_count'] = 0
                data['alive'] = True
                data['last_seen'] = current_time
                data['last_successful_ping'] = current_time
                
                # Update MAC if we have a better one from ARP
                arp_mac = arp_hosts[ip].get('mac', '')
                if arp_mac and (not data.get('mac') or data['mac'] in ['', 'Unknown', '00:00:00:00:00:00'] or 
                               data['mac'].startswith('00:00:c0:a8:01:')):  # Replace pseudo MACs
                    data['mac'] = arp_mac
                    # Also update NetKB database with real MAC
                    try:
                        arp_hostname = arp_hosts[ip].get('hostname', data.get('hostname', ''))
                        update_netkb_entry(ip, arp_hostname, arp_mac, True)
                    except Exception as e:
                        logger.debug(f"Could not update NetKB with real MAC for {ip}: {e}")
            else:
                # Device didn't respond - only increment counter if we have fresh ARP data
                if arp_data_is_fresh:
                    data['failed_ping_count'] = data.get('failed_ping_count', 0) + 1
                    data['last_ping_attempt'] = current_time
                
                # Only mark as offline after MAX_FAILED_PINGS consecutive failures
                if data['failed_ping_count'] >= MAX_FAILED_PINGS:
                    data['alive'] = False
                    logger.info(f"Device {ip} marked offline after {data['failed_ping_count']} consecutive failed pings")
                else:
                    # IMPORTANT: Keep device as "alive" until it exceeds the failure limit
                    # This implements the proper 15-ping rule you requested
                    data['alive'] = True  # Don't change to False until 15 failures
                    # Only log devices approaching the failure threshold to reduce noise
                    if data['failed_ping_count'] >= MAX_FAILED_PINGS - 3:
                        logger.debug(f"Device {ip} failed ping {data['failed_ping_count']}/{MAX_FAILED_PINGS} - keeping alive per 15-ping rule")

        # Time-based status transitions (offline/lost)
        offline_hours = shared_data.config.get('network_offline_hours', 3)
        lost_days = shared_data.config.get('network_lost_days', 8)
        try:
            offline_hours = float(offline_hours)
        except (TypeError, ValueError):
            offline_hours = 3
        try:
            lost_days = float(lost_days)
        except (TypeError, ValueError):
            lost_days = 8

        offline_cutoff = datetime.now() - timedelta(hours=offline_hours)
        lost_cutoff = datetime.now() - timedelta(days=lost_days)
        hosts_lost = []
        hosts_offline = []

        for ip, data in existing_data.items():
            status = 'Online'
            last_seen_str = data.get('last_seen') or current_time
            try:
                last_seen_dt = datetime.fromisoformat(last_seen_str)
            except Exception:
                last_seen_dt = datetime.now()

            if last_seen_dt < lost_cutoff:
                status = 'Lost'
                data['alive'] = False
                hosts_lost.append(ip)
            elif last_seen_dt < offline_cutoff:
                status = 'Offline'
                data['alive'] = False
                hosts_offline.append(ip)
            else:
                status = 'Online' if data.get('alive', True) else 'Offline'

            data['status'] = status

        # Resolve findings for lost/offline hosts (network intelligence)
        if hasattr(shared_data, 'network_intelligence') and shared_data.network_intelligence:
            for ip in hosts_lost:
                try:
                    shared_data.network_intelligence.resolve_host_findings(ip, reason="host_lost_timeout")
                except Exception as e:
                    logger.error(f"Failed to resolve findings for lost host {ip}: {e}")
            for ip in hosts_offline:
                try:
                    shared_data.network_intelligence.resolve_host_findings(ip, reason="host_offline_timeout")
                except Exception as e:
                    logger.error(f"Failed to resolve findings for offline host {ip}: {e}")

        # Add new devices discovered via ARP that aren't in our data yet
        for ip, arp_data in arp_hosts.items():
            if ip not in existing_data:
                existing_data[ip] = {
                    'hostname': arp_data.get('hostname', ''),
                    'alive': True,
                    'mac': arp_data.get('mac', ''),
                    'ports': set(),
                    'last_seen': current_time,
                    'last_successful_ping': current_time,
                    'failed_ping_count': 0  # New devices start with 0 failures
                }
                # Add to NetKB database as well
                try:
                    update_netkb_entry(ip, arp_data.get('hostname', ''), arp_data.get('mac', ''), True)
                except Exception as e:
                    logger.debug(f"Could not add new ARP discovery to NetKB for {ip}: {e}")

        # Prepare aggregated counts from persisted data using PROPER 5-ping rule
        aggregated_host_count = 0
        aggregated_active_count = 0
        aggregated_inactive_count = 0
        aggregated_port_count = 0

        for ip, data in existing_data.items():
            aggregated_host_count += 1
            
            # Apply the PROPER 5-ping rule for counting active targets
            failed_ping_count = data.get('failed_ping_count', 0)
            
            # TARGET IS ACTIVE IF:
            # 1. It has fewer than MAX_FAILED_PINGS consecutive failures, OR
            # 2. It's marked as explicitly alive (from ARP response)
            is_explicitly_alive = data.get('alive', True)
            has_not_exceeded_failure_limit = failed_ping_count < MAX_FAILED_PINGS
            
            # A target is active if it hasn't exceeded the failure limit OR if it's currently responding
            is_target_active = has_not_exceeded_failure_limit or is_explicitly_alive
            
            if is_target_active:
                aggregated_active_count += 1
                aggregated_port_count += sum(1 for port in data['ports'] if port)
                # Only log every 10th device or devices approaching failure threshold
                if aggregated_active_count % 10 == 1 or failed_ping_count >= MAX_FAILED_PINGS - 2:
                    logger.debug(f"[15-PING RULE] {ip}: ACTIVE (failures={failed_ping_count}/{MAX_FAILED_PINGS}, alive={is_explicitly_alive})")
            else:
                aggregated_inactive_count += 1
                logger.info(f"[15-PING RULE] {ip}: INACTIVE (failures={failed_ping_count}/{MAX_FAILED_PINGS}, alive={is_explicitly_alive})")

        # Write updated data to WiFi-specific file
        try:
            # Count ports before writing for debugging
            total_ports_to_write = sum(len(data['ports']) for data in existing_data.values())
            hosts_with_many_ports = sum(1 for data in existing_data.values() if len(data['ports']) > 10)
            
            logger.debug(f"[WIFI DATA WRITE] Writing {len(existing_data)} hosts with {total_ports_to_write} total ports ({hosts_with_many_ports} hosts with >10 ports)")
            
            with open(wifi_network_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Hostname', 'Alive', 'MAC', 'Ports', 'LastSeen', 'FailedPingCount', 'LastSuccessfulPing', 'LastPingAttempt'])

                for ip, data in existing_data.items():
                    def port_sort_key(value):
                        if value.isdigit():
                            return int(value)
                        try:
                            match = re.match(r"^(\d+)", value)
                            if match:
                                return int(match.group(1))
                            return value
                        except Exception:
                            return value

                    ports_str = ';'.join(sorted((port for port in data['ports'] if port), key=port_sort_key))
                    
                    # Log hosts with many ports being written
                    if len(data['ports']) > 10:
                        logger.debug(f"[WIFI DATA WRITE] {ip}: Writing {len(data['ports'])} ports to file")
                    
                    writer.writerow([
                        ip,
                        data['hostname'],
                        '1' if data.get('alive', True) else '0',
                        data['mac'],
                        ports_str,
                        data['last_seen'],
                        data.get('failed_ping_count', 0),
                        data.get('last_successful_ping', ''),
                        data.get('last_ping_attempt', '')
                    ])

            logger.info(f"✅ Updated WiFi network data file: {wifi_network_file} with {len(existing_data)} entries (removed {len(stale_hosts)} stale hosts, preserved {total_ports_to_write} ports)")
        except Exception as e:
            logger.error(f"Error writing WiFi network data file: {e}")

        return {
            'host_count': aggregated_active_count,
            'total_host_count': aggregated_host_count,
            'inactive_host_count': aggregated_inactive_count,
            'port_count': aggregated_port_count,
            'stale_hosts_removed': len(stale_hosts),
            'hosts': existing_data
        }

    except Exception as e:
        logger.error(f"Error updating WiFi network data: {e}")
        return None


def read_wifi_network_data():
    """Read network data from WiFi-specific file with automatic cleanup of legacy entries"""
    try:
        wifi_network_file = get_wifi_specific_network_file()
        network_data = []
        cleaned_data = []
        cleanup_needed = False
        
        # Get configuration values for cleanup
        retention_hours = shared_data.config.get('network_device_retention_hours', 8)  # 8 hours by default
        max_failed_pings = shared_data.config.get('network_max_failed_pings', 15)  # Changed to 15 for more stability
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(hours=retention_hours)
        
        if os.path.exists(wifi_network_file):
            with open(wifi_network_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                headers = next(reader, None)  # Read header
                
                # Determine if we have the enhanced format with connectivity tracking
                has_enhanced_format = (headers and len(headers) >= 9 and 
                                     'FailedPingCount' in headers and 
                                     'LastSuccessfulPing' in headers and 
                                     'LastPingAttempt' in headers)
                
                for row in reader:
                    if not row or not row[0].strip():
                        continue
                        
                    ip = row[0].strip()
                    if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                        continue
                    
                    # Handle both old and new CSV formats
                    if has_enhanced_format and len(row) >= 9:
                        # Enhanced format: IP, Hostname, Alive, MAC, Ports, LastSeen, FailedPingCount, LastSuccessfulPing, LastPingAttempt
                        failed_ping_count = int(row[6]) if row[6].isdigit() else 0
                        last_successful_ping = row[7] if len(row) > 7 else ''
                        last_ping_attempt = row[8] if len(row) > 8 else ''
                        last_seen = row[5] if len(row) > 5 else ''
                        
                        # Determine the most recent activity timestamp
                        most_recent_activity = None
                        for timestamp_str in [last_successful_ping, last_ping_attempt, last_seen]:
                            if timestamp_str and timestamp_str.strip():
                                try:
                                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                    if timestamp.tzinfo:
                                        timestamp = timestamp.replace(tzinfo=None)
                                    if most_recent_activity is None or timestamp > most_recent_activity:
                                        most_recent_activity = timestamp
                                except (ValueError, TypeError):
                                    continue
                        
                        # Apply robust 5-ping failure cleanup logic
                        should_keep = True
                        cleanup_reason = None
                        
                        # RULE 1: Remove devices that have failed 5+ consecutive pings (regardless of age)
                        if failed_ping_count >= max_failed_pings:
                            should_keep = False
                            cleanup_reason = f"exceeded max failed pings ({failed_ping_count}>={max_failed_pings})"
                            cleanup_needed = True
                        
                        # RULE 2: Remove very old devices that haven't been seen for 8+ hours (regardless of ping status)
                        elif most_recent_activity and most_recent_activity < cutoff_time:
                            should_keep = False
                            cleanup_reason = f"too old (last activity: {most_recent_activity}, cutoff: {cutoff_time})"
                            cleanup_needed = True
                        
                        # RULE 3: Remove devices with no successful ping record and no recent activity
                        elif not last_successful_ping and most_recent_activity and most_recent_activity < cutoff_time:
                            should_keep = False
                            cleanup_reason = f"no successful pings and old (last activity: {most_recent_activity})"
                            cleanup_needed = True
                        
                        if not should_keep:
                            logger.info(f"[ROBUST CLEANUP] Removing {ip}: {cleanup_reason}")
                        
                        if should_keep:
                            network_entry = {
                                'IPs': ip,
                                'Hostnames': row[1] if row[1] else '',
                                'Alive': int(row[2]) if row[2].isdigit() else 0,
                                'MAC Address': row[3] if row[3] else '',
                                'Ports': row[4] if row[4] else '',
                                'LastSeen': last_seen,
                                'FailedPingCount': failed_ping_count,
                                'LastSuccessfulPing': last_successful_ping,
                                'LastPingAttempt': last_ping_attempt
                            }
                            network_data.append(network_entry)
                            cleaned_data.append(row)
                    
                    elif len(row) >= 6:
                        # Legacy format: IP, Hostname, Alive, MAC, Ports, LastSeen
                        last_seen = row[5] if len(row) > 5 else ''
                        alive_status = int(row[2]) if row[2].isdigit() else 0
                        
                        # For legacy format, remove entries that are old and not alive
                        should_keep = True
                        if last_seen:
                            try:
                                last_seen_time = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                                if last_seen_time.tzinfo:
                                    last_seen_time = last_seen_time.replace(tzinfo=None)
                                
                                if last_seen_time < cutoff_time and alive_status == 0:
                                    logger.debug(f"Removing legacy entry {ip} (old format, not alive, last seen: {last_seen_time})")
                                    should_keep = False
                                    cleanup_needed = True
                            except (ValueError, TypeError):
                                # If we can't parse the timestamp and device is not alive, remove it
                                if alive_status == 0:
                                    logger.debug(f"Removing legacy entry {ip} (unparseable timestamp, not alive)")
                                    should_keep = False
                                    cleanup_needed = True
                        
                        if should_keep:
                            network_entry = {
                                'IPs': ip,
                                'Hostnames': row[1] if row[1] else '',
                                'Alive': alive_status,
                                'MAC Address': row[3] if row[3] else '',
                                'Ports': row[4] if row[4] else '',
                                'LastSeen': last_seen
                            }
                            network_data.append(network_entry)
                            cleaned_data.append(row)
            
            # If we removed any entries, rewrite the file
            if cleanup_needed:
                try:
                    with open(wifi_network_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        if headers:
                            writer.writerow(headers)
                        writer.writerows(cleaned_data)
                    logger.info(f"Cleaned up legacy network data - removed {len(cleaned_data) - len(network_data)} old entries")
                except Exception as e:
                    logger.error(f"Error rewriting cleaned network file: {e}")
            
            logger.debug(f"Read {len(network_data)} entries from WiFi network file: {wifi_network_file}")
        else:
            logger.debug(f"WiFi network file does not exist: {wifi_network_file}")
        
        return network_data
    except Exception as e:
        logger.error(f"Error reading WiFi network data: {e}")
        return []


def is_ap_client_request():
    """Check if the request is coming from an AP client (192.168.4.x)"""
    try:
        client_ip = request.environ.get('REMOTE_ADDR', '')
        # Check if request is from AP network (192.168.4.x)
        return client_ip.startswith('192.168.4.') and client_ip != '192.168.4.1'
    except Exception:
        return False


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/login')
def login_page():
    """Serve the login page."""
    if not auth_mgr.is_configured():
        return redirect('/')
    if session.get('authenticated'):
        return redirect('/')
    return send_from_directory('web', 'login.html')


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Get current authentication status."""
    return jsonify(auth_mgr.get_auth_status(session))


@app.route('/api/auth/setup', methods=['POST'])
def auth_setup():
    """Initial authentication setup - creates user, encrypts DB, generates recovery codes."""
    if auth_mgr.is_configured():
        return jsonify({'success': False, 'error': 'Authentication is already configured'}), 400

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')
    confirm = data.get('confirm_password', '')

    if password != confirm:
        return jsonify({'success': False, 'error': 'Passwords do not match'}), 400

    result = auth_mgr.setup(username, password)
    if result['success']:
        # Auto-login after setup
        session['authenticated'] = True
        session['username'] = username
        session['login_time'] = time.time()
        session.permanent = True
        return jsonify(result)
    else:
        return jsonify(result), 400


@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    """Login with username and password."""
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    result = auth_mgr.login(username, password)
    if result['success']:
        session['authenticated'] = True
        session['username'] = username
        session['login_time'] = time.time()
        session.permanent = True
        return jsonify(result)
    else:
        return jsonify(result), 401


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    """Logout - clear session immediately, encrypt database in background."""
    session.clear()
    # Encrypt DB in background so the response isn't blocked
    threading.Thread(target=auth_mgr.logout, daemon=True).start()
    return jsonify({'success': True})


@app.route('/api/auth/change-password', methods=['POST'])
def auth_change_password():
    """Change the user's password."""
    if not session.get('authenticated'):
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400

    result = auth_mgr.change_password(
        data.get('current_password', ''),
        data.get('new_password', '')
    )
    return jsonify(result) if result['success'] else (jsonify(result), 400)


@app.route('/api/auth/recover', methods=['POST'])
def auth_recover():
    """Use a recovery code to reset password and login."""
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400

    result = auth_mgr.recover(
        data.get('username', '').strip(),
        data.get('recovery_code', '').strip(),
        data.get('new_password', '')
    )
    if result['success']:
        session['authenticated'] = True
        session['username'] = data.get('username', '').strip()
        session['login_time'] = time.time()
        session.permanent = True
    return jsonify(result) if result['success'] else (jsonify(result), 400)


@app.route('/api/auth/regenerate-recovery', methods=['POST'])
def auth_regenerate_recovery():
    """Generate new recovery codes (requires current password)."""
    if not session.get('authenticated'):
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400

    result = auth_mgr.regenerate_recovery_codes(data.get('password', ''))
    return jsonify(result) if result['success'] else (jsonify(result), 400)


# ============================================================================
# STATIC FILE ROUTES
# ============================================================================

@app.route('/')
def index():
    """Serve the main dashboard page or captive portal for AP clients"""
    if is_ap_client_request():
        # Serve captive portal for AP clients
        return send_from_directory('web', 'captive_portal.html')
    else:
        # Serve main dashboard for regular users
        return send_from_directory('web', 'index_modern.html')


# Add explicit captive portal route
@app.route('/portal')
def captive_portal():
    """Explicit captive portal route"""
    return send_from_directory('web', 'captive_portal.html')

# WiFi configuration page route
@app.route('/wifi-config')
def wifi_config_page():
    """Serve the Wi-Fi configuration page for AP clients and regular users"""
    return send_from_directory('web', 'wifi_config.html')

# Alternative routes for WiFi config (for compatibility)
@app.route('/wifi')
@app.route('/setup')
def wifi_config_alt():
    """Alternative routes for Wi-Fi configuration"""
    return send_from_directory('web', 'wifi_config.html')


# Captive portal detection routes for mobile devices
@app.route('/generate_204')
@app.route('/gen_204')
@app.route('/connecttest.txt')
@app.route('/success.txt')
@app.route('/ncsi.txt')
def captive_portal_detection():
    """Handle captive portal detection requests from mobile devices"""
    if is_ap_client_request():
        # Redirect to captive portal for AP clients
        return '''<html><head><meta http-equiv="refresh" content="0; url=/portal"></head><body><a href="/portal">Click here for WiFi setup</a></body></html>''', 302
    else:
        # Return success for non-AP clients
        return "Success", 204


@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files from web directory"""
    return send_from_directory('web', filename)


@app.route('/api/system/headless')
def get_system_headless():
    """Expose headless mode flag for UI to hide display-only features."""
    try:
        is_headless = safe_bool(getattr(shared_data, 'headless_mode', False))
        return jsonify({'success': True, 'headless': is_headless, 'is_headless': is_headless})
    except Exception as exc:
        logger.error(f"Failed to read headless state: {exc}")
        return jsonify({'success': False, 'headless': False, 'error': str(exc)}), 500


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/status')
def get_status():
    """Get current Ragnar status (optimized - uses cached data from background sync)"""
    try:
        # OPTIMIZATION: Don't call sync_all_counts() here - it's expensive!
        # Background thread handles syncing every SYNC_BACKGROUND_INTERVAL seconds
        # This endpoint now returns cached data instantly for fast dashboard loading
        
        status_data = {
            'ragnar_status': safe_str(shared_data.ragnarstatustext),
            'ragnar_status2': safe_str(shared_data.ragnarstatustext2),
            'ragnar_says': safe_str(shared_data.ragnarsays),
            'orchestrator_status': safe_str(shared_data.ragnarorch_status),
            'automation_enabled': is_orchestrator_running(),
            'target_count': safe_int(shared_data.targetnbr),
            'port_count': safe_int(shared_data.portnbr),
            'vulnerability_count': safe_int(shared_data.vulnnbr),
            'credential_count': safe_int(shared_data.crednbr),
            'data_count': safe_int(shared_data.datanbr),
            'level': safe_int(shared_data.levelnbr),
            'points': safe_int(shared_data.coinnbr),
            'coins': safe_int(shared_data.coinnbr),
            'scanned_network_count': safe_int(getattr(shared_data, 'scanned_networks_count', 0)),
            'wifi_connected': safe_bool(shared_data.wifi_connected),
            'current_ssid': safe_str(getattr(shared_data, 'current_wifi_ssid', '') or get_current_wifi_ssid() or ''),
            'ethernet_connected': safe_bool(is_ethernet_available()),
            'ethernet_ip': _get_active_ethernet_ip(),
            'ethernet_interface': _get_active_ethernet_name(),
            'bluetooth_active': safe_bool(shared_data.bluetooth_active),
            'pan_connected': safe_bool(shared_data.pan_connected),
            'usb_active': safe_bool(shared_data.usb_active),
            'manual_mode': safe_bool(shared_data.config.get('manual_mode', False)),
            'headless_mode': safe_bool(getattr(shared_data, 'headless_mode', False)),
            'pwnagotchi_mode': shared_data.config.get('pwnagotchi_mode', 'ragnar'),
            'pwnagotchi_installed': safe_bool(shared_data.config.get('pwnagotchi_installed', False)),
            'release_gate': _build_release_gate_payload(),
            'timestamp': datetime.now().isoformat()
        }
        
        # Add cache headers for quick responses
        response = jsonify(status_data)
        response.headers['Cache-Control'] = 'public, max-age=5'  # Cache for 5 seconds
        return response
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    try:
        return jsonify(shared_data.config)
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        ai_reload_success = None
        ai_reload_error = None
        epd_type_changed = 'epd_type' in data

        # Resolve size keys (from web UI) to actual driver names
        if epd_type_changed:
            from shared import resolve_epd_type
            raw_epd = data['epd_type']
            data['epd_type'] = resolve_epd_type(raw_epd, shared_data.config.get('epd_type'))

        # Update configuration (allow new keys to be added)
        for key, value in data.items():
            # Skip private/internal keys that start with __
            if not key.startswith('__'):
                shared_data.config[key] = value
                # Also set as attribute on shared_data for immediate access
                setattr(shared_data, key, value)

        if epd_type_changed:
            shared_data.apply_display_profile(shared_data.config.get('epd_type'))
        
        # Save configuration
        shared_data.save_config()

        # Reflect orientation changes immediately for both hardware and screenshots
        from shared import normalize_rotation
        shared_data.screen_reversed = normalize_rotation(shared_data.config.get('screen_reversed', 0))
        shared_data.web_screen_reversed = shared_data.screen_reversed
        
        # Reload AI service if ai_enabled was changed
        if 'ai_enabled' in data:
            ai_service = getattr(shared_data, 'ai_service', None)
            
            # If AI service doesn't exist and user enabled it, try to initialize
            if not ai_service and data['ai_enabled']:
                try:
                    shared_data.initialize_ai_service()
                    ai_service = shared_data.ai_service
                    if ai_service and ai_service.is_enabled():
                        ai_reload_success = True
                    else:
                        ai_reload_success = False
                        ai_reload_error = getattr(ai_service, 'initialization_error', 'Failed to initialize AI service') if ai_service else 'AI service creation failed'
                except Exception as e:
                    ai_reload_success = False
                    ai_reload_error = str(e)
            # If AI service exists, reload or disable it
            elif ai_service:
                if data['ai_enabled']:
                    ai_reload_success = ai_service.reload_token()
                    if not ai_reload_success:
                        ai_reload_error = getattr(ai_service, 'initialization_error', None)
                else:
                    ai_service.enabled = False
                    ai_service.client = None
                    ai_service.initialization_error = None
                    ai_reload_success = True
        
        # Emit update to all connected clients
        socketio.emit('config_updated', shared_data.config)

        response = {'success': True, 'message': 'Configuration updated'}
        if ai_reload_success is not None:
            response['ai_reload_success'] = ai_reload_success
            if ai_reload_error:
                response['ai_reload_error'] = ai_reload_error

        # EPD type change requires a full service restart to reinitialize hardware
        if epd_type_changed:
            response['restart_required'] = True
            response['message'] = 'Display type changed - restarting Ragnar service...'
            import threading
            def _delayed_restart():
                import time, os, signal
                time.sleep(2)  # Give the response time to reach the client
                logger.info(f"Restarting Ragnar service for EPD type change to: {shared_data.config.get('epd_type')}")
                os.system('systemctl restart ragnar.service')
            threading.Thread(target=_delayed_restart, daemon=True).start()

        return jsonify(response)
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/scan-subnets', methods=['GET', 'POST', 'DELETE'])
def manage_scan_subnets():
    """Manage the list of extra subnets to scan.

    GET:    Return current list + auto-detected primary subnet.
    POST:   Add a new CIDR (body: {"cidr": "10.0.0.0/24"}).
    DELETE: Remove a CIDR  (body: {"cidr": "10.0.0.0/24"}).
    """
    import ipaddress as _ip
    try:
        subnets = list(shared_data.config.get('scan_subnets', []))

        # Detect primary subnet for reference
        primary = None
        try:
            import netifaces
            gws = netifaces.gateways()
            gw_tuple = gws.get('default', {}).get(netifaces.AF_INET)
            if gw_tuple:
                iface_addrs = netifaces.ifaddresses(gw_tuple[1]).get(netifaces.AF_INET)
                if iface_addrs:
                    my_ip = iface_addrs[0]['addr']
                    mask = iface_addrs[0]['netmask']
                    cidr_bits = sum(bin(int(x)).count('1') for x in mask.split('.'))
                    primary = str(_ip.ip_network(f"{my_ip}/{cidr_bits}", strict=False))
        except Exception:
            pass

        if request.method == 'GET':
            return jsonify({'subnets': subnets, 'primary': primary})

        data = request.get_json() or {}
        raw = str(data.get('cidr', '')).strip()
        if not raw:
            return jsonify({'error': 'Missing cidr field'}), 400

        # Validate
        try:
            net = _ip.ip_network(raw, strict=False)
            normalised = str(net)
        except ValueError:
            return jsonify({'error': f'Invalid CIDR: {raw}'}), 400

        if request.method == 'POST':
            if normalised == primary:
                return jsonify({'error': 'This is already your primary subnet — no need to add it'}), 400
            if normalised not in subnets:
                subnets.append(normalised)
                shared_data.config['scan_subnets'] = subnets
                shared_data.scan_subnets = subnets
                shared_data.save_config()
            return jsonify({'subnets': subnets, 'primary': primary})

        if request.method == 'DELETE':
            subnets = [s for s in subnets if s != normalised]
            shared_data.config['scan_subnets'] = subnets
            shared_data.scan_subnets = subnets
            shared_data.save_config()
            return jsonify({'subnets': subnets, 'primary': primary})

    except Exception as e:
        logger.error(f"Error managing scan subnets: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/scan-subnets/trigger', methods=['POST'])
def trigger_subnet_scan():
    """Trigger an immediate nmap scan of a specific subnet in the background.

    Body: {"cidr": "10.0.0.0/24"}
    Returns immediately — results appear in the subnet scan log.
    """
    import ipaddress as _ip
    try:
        data = request.get_json() or {}
        raw = str(data.get('cidr', '')).strip()
        if not raw:
            return jsonify({'error': 'Missing cidr field'}), 400
        try:
            net = _ip.ip_network(raw, strict=False)
            normalised = str(net)
        except ValueError:
            return jsonify({'error': f'Invalid CIDR: {raw}'}), 400

        def _bg_scan(cidr):
            try:
                from actions.scanning import NetworkScanner
                scanner = NetworkScanner(shared_data)
                portstart = shared_data.portstart
                portend = shared_data.portend
                extra_ports = shared_data.portlist

                shared_data.append_subnet_scan_log(
                    cidr, 'info', f'Scanning {cidr}\u2026',
                )
                results = scanner.run_nmap_network_scan(
                    cidr, portstart, portend, extra_ports,
                )
                found = len(results)
                # Persist discovered hosts into DB
                for host, host_data in results.items():
                    mac = host_data.get('mac', '')
                    if not mac or mac == '00:00:00:00:00:00':
                        ip_parts = host.split('.')
                        if len(ip_parts) == 4:
                            mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                    if mac:
                        scanner.db.upsert_host(
                            mac=mac.lower().strip(),
                            ip=host,
                            hostname=host_data.get('hostname', ''),
                            ports=','.join(map(str, sorted(host_data.get('open_ports', [])))),
                        )
                        scanner.db.update_ping_status(mac.lower().strip(), success=True)

                if found > 0:
                    shared_data.append_subnet_scan_log(
                        cidr, 'ok',
                        f'{found} device(s) found on {cidr}',
                        devices=found,
                    )
                else:
                    shared_data.append_subnet_scan_log(
                        cidr, 'error',
                        f'{cidr} \u2014 no devices responded',
                        devices=0,
                    )
                logger.info(f"Subnet trigger scan complete for {cidr}: {found} hosts")
            except Exception as e:
                logger.error(f"Subnet trigger scan failed for {cidr}: {e}")
                shared_data.append_subnet_scan_log(
                    cidr, 'error', f'Scan failed: {e}',
                )

        import threading
        t = threading.Thread(target=_bg_scan, args=(normalised,), daemon=True)
        t.start()
        return jsonify({'status': 'scan_triggered', 'cidr': normalised})

    except Exception as e:
        logger.error(f"Error triggering subnet scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/scan-subnets/log')
def get_scan_subnets_log():
    """Return the in-memory subnet scan log (newest last)."""
    try:
        log = shared_data.get_subnet_scan_log()
        return jsonify({'log': log})
    except Exception as e:
        logger.error(f"Error fetching subnet scan log: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/hardware-profiles')
def get_hardware_profiles():
    """Get predefined hardware profiles for different Raspberry Pi models"""
    try:
        profiles = {
            'pi_zero_2w': {
                'name': 'Raspberry Pi Zero 2 W',
                'ram': 512,
                'description': '512MB RAM - Minimal resource usage',
                'settings': {
                    'scanner_max_threads': 3,
                    'orchestrator_max_concurrent': 2,
                    'nmap_scan_aggressivity': '-T2',
                    'scan_interval': 400,
                    'scan_vuln_interval': 700,
                    'max_concurrent_scans': 1,
                    'memory_warning_threshold': 90,
                    'memory_critical_threshold': 99,
                    'enable_resource_monitoring': True
                }
            },
            'pi_4_1gb': {
                'name': 'Raspberry Pi 4 (1GB)',
                'ram': 1024,
                'description': '1GB RAM - Light resource usage',
                'settings': {
                    'scanner_max_threads': 5,
                    'orchestrator_max_concurrent': 3,
                    'nmap_scan_aggressivity': '-T3',
                    'scan_interval': 240,
                    'scan_vuln_interval': 480,
                    'max_concurrent_scans': 2,
                    'memory_warning_threshold': 75,
                    'memory_critical_threshold': 90,
                    'enable_resource_monitoring': True
                }
            },
            'pi_4_2gb': {
                'name': 'Raspberry Pi 4 (2GB)',
                'ram': 2048,
                'description': '2GB RAM - Moderate resource usage',
                'settings': {
                    'scanner_max_threads': 10,
                    'orchestrator_max_concurrent': 5,
                    'nmap_scan_aggressivity': '-T3',
                    'scan_interval': 180,
                    'scan_vuln_interval': 360,
                    'max_concurrent_scans': 3,
                    'memory_warning_threshold': 75,
                    'memory_critical_threshold': 90,
                    'enable_resource_monitoring': True
                }
            },
            'pi_4_4gb': {
                'name': 'Raspberry Pi 4 (4GB)',
                'ram': 4096,
                'description': '4GB RAM - Standard resource usage',
                'settings': {
                    'scanner_max_threads': 20,
                    'orchestrator_max_concurrent': 8,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 180,
                    'scan_vuln_interval': 300,
                    'max_concurrent_scans': 4,
                    'memory_warning_threshold': 80,
                    'memory_critical_threshold': 92,
                    'enable_resource_monitoring': True
                }
            },
            'pi_4_8gb': {
                'name': 'Raspberry Pi 4 (8GB)',
                'ram': 8192,
                'description': '8GB RAM - High performance',
                'settings': {
                    'scanner_max_threads': 30,
                    'orchestrator_max_concurrent': 10,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 120,
                    'scan_vuln_interval': 240,
                    'max_concurrent_scans': 6,
                    'memory_warning_threshold': 80,
                    'memory_critical_threshold': 92,
                    'enable_resource_monitoring': True
                }
            },
            'pi_5_2gb': {
                'name': 'Raspberry Pi 5 (2GB)',
                'ram': 2048,
                'description': '2GB RAM - Fast CPU, moderate RAM',
                'settings': {
                    'scanner_max_threads': 15,
                    'orchestrator_max_concurrent': 6,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 150,
                    'scan_vuln_interval': 300,
                    'max_concurrent_scans': 4,
                    'memory_warning_threshold': 75,
                    'memory_critical_threshold': 90,
                    'enable_resource_monitoring': True
                }
            },
            'pi_5_4gb': {
                'name': 'Raspberry Pi 5 (4GB)',
                'ram': 4096,
                'description': '4GB RAM - High performance',
                'settings': {
                    'scanner_max_threads': 30,
                    'orchestrator_max_concurrent': 12,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 120,
                    'scan_vuln_interval': 240,
                    'max_concurrent_scans': 6,
                    'memory_warning_threshold': 80,
                    'memory_critical_threshold': 92,
                    'enable_resource_monitoring': True
                }
            },
            'pi_5_8gb': {
                'name': 'Raspberry Pi 5 (8GB)',
                'ram': 8192,
                'description': '8GB RAM - Maximum performance',
                'settings': {
                    'scanner_max_threads': 40,
                    'orchestrator_max_concurrent': 15,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 90,
                    'scan_vuln_interval': 180,
                    'max_concurrent_scans': 8,
                    'memory_warning_threshold': 82,
                    'memory_critical_threshold': 93,
                    'enable_resource_monitoring': True
                }
            },
            'pi_5_16gb': {
                'name': 'Raspberry Pi 5 (16GB)',
                'ram': 16384,
                'description': '16GB RAM - Extreme performance',
                'settings': {
                    'scanner_max_threads': 50,
                    'orchestrator_max_concurrent': 20,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 60,
                    'scan_vuln_interval': 120,
                    'max_concurrent_scans': 10,
                    'memory_warning_threshold': 85,
                    'memory_critical_threshold': 94,
                    'enable_resource_monitoring': True
                }
            }
        }
        
        return jsonify(profiles)
    except Exception as e:
        logger.error(f"Error getting hardware profiles: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/detect-hardware')
def detect_hardware():
    """Auto-detect current hardware and recommend profile"""
    try:
        import subprocess
        import re
        
        # Detect Raspberry Pi model
        model = 'unknown'
        ram_mb = 0
        recommended_profile = 'pi_zero_2w'  # Default to most conservative
        
        try:
            # Read /proc/cpuinfo for model
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                
            # Detect Pi model
            if 'Raspberry Pi Zero 2' in cpuinfo:
                model = 'Raspberry Pi Zero 2 W'
                recommended_profile = 'pi_zero_2w'
            elif 'Raspberry Pi 5' in cpuinfo:
                model = 'Raspberry Pi 5'
            elif 'Raspberry Pi 4' in cpuinfo:
                model = 'Raspberry Pi 4'
            elif 'Raspberry Pi 3' in cpuinfo:
                model = 'Raspberry Pi 3'
                
        except Exception as e:
            logger.warning(f"Could not read cpuinfo: {e}")
        
        # Detect RAM
        if psutil_available:
            try:
                mem = psutil.virtual_memory()
                ram_mb = int(mem.total / (1024 * 1024))
                
                # Match to closest profile
                if model == 'Raspberry Pi Zero 2 W':
                    recommended_profile = 'pi_zero_2w'
                elif model == 'Raspberry Pi 5':
                    if ram_mb >= 15000:
                        recommended_profile = 'pi_5_16gb'
                    elif ram_mb >= 7000:
                        recommended_profile = 'pi_5_8gb'
                    elif ram_mb >= 3500:
                        recommended_profile = 'pi_5_4gb'
                    else:
                        recommended_profile = 'pi_5_2gb'
                elif model == 'Raspberry Pi 4':
                    if ram_mb >= 7000:
                        recommended_profile = 'pi_4_8gb'
                    elif ram_mb >= 3500:
                        recommended_profile = 'pi_4_4gb'
                    elif ram_mb >= 1800:
                        recommended_profile = 'pi_4_2gb'
                    else:
                        recommended_profile = 'pi_4_1gb'
                        
            except Exception as e:
                logger.warning(f"Could not detect RAM: {e}")
        
        # Get CPU count
        cpu_count = psutil.cpu_count() if psutil_available else 1
        
        return jsonify({
            'model': model,
            'ram_mb': ram_mb,
            'ram_gb': round(ram_mb / 1024, 1),
            'cpu_count': cpu_count,
            'recommended_profile': recommended_profile,
            'detection_method': 'cpuinfo + psutil'
        })
        
    except Exception as e:
        logger.error(f"Error detecting hardware: {e}")
        return jsonify({
            'model': 'unknown',
            'ram_mb': 0,
            'ram_gb': 0,
            'cpu_count': 1,
            'recommended_profile': 'pi_zero_2w',
            'detection_method': 'fallback',
            'error': str(e)
        }), 200

@app.route('/api/config/apply-profile', methods=['POST'])
def apply_hardware_profile():
    """Apply a hardware profile to the system configuration"""
    try:
        data = request.get_json()
        profile_id = data.get('profile_id')
        
        if not profile_id:
            return jsonify({'error': 'No profile_id provided'}), 400
        
        # Get the profile
        profiles_response = get_hardware_profiles()
        if isinstance(profiles_response, tuple):
            return profiles_response
        profiles = profiles_response.get_json()
        
        if profile_id not in profiles:
            return jsonify({'error': f'Unknown profile: {profile_id}'}), 404
        
        profile = profiles[profile_id]
        settings = profile['settings']
        
        # Update configuration with profile settings
        for key, value in settings.items():
            shared_data.config[key] = value
        
        # Also store the applied profile info
        shared_data.config['hardware_profile'] = profile_id
        shared_data.config['hardware_profile_name'] = profile['name']
        shared_data.config['hardware_profile_applied'] = datetime.now().isoformat()
        
        # Save configuration
        shared_data.save_config()
        
        logger.info(f"Applied hardware profile: {profile['name']} ({profile_id})")
        
        # Emit update to all connected clients
        socketio.emit('config_updated', shared_data.config)
        
        return jsonify({
            'success': True,
            'message': f"Applied profile: {profile['name']}",
            'profile': profile,
            'restart_required': True
        })
        
    except Exception as e:
        logger.error(f"Error applying hardware profile: {e}")
        return jsonify({'error': str(e)}), 500


def load_persistent_network_data():
    """Load the WiFi-specific network data with fallbacks."""
    # Check for network switches and clear old data if needed
    check_and_handle_network_switch()
    
    update_wifi_network_data()

    network_data = read_wifi_network_data()

    def _extract_value(entry, keys):
        for key in keys:
            if isinstance(entry, dict) and key in entry:
                value = entry.get(key)
                if isinstance(value, str):
                    value = value.strip()
                if value not in (None, ''):
                    return value
        return ''

    netkb_data = []
    try:
        netkb_data = shared_data.read_data()
    except Exception as e:
        logger.error(f"Could not read netkb data for MAC enrichment: {e}")

    if network_data:
        ip_to_mac = {}
        enrichment_map = {}
        for row in netkb_data:
            ip = _extract_value(row, ("IPs", "IP", "ip"))
            mac = _extract_value(row, ("MAC Address", "MAC", "mac"))
            vuln_summary = _extract_value(row, ("Nmap Vulnerabilities", "nmap_vulnerabilities"))
            vuln_status = _extract_value(row, ("NmapVulnScanner", "nmap_vuln_scanner"))

            enrichment_payload = {
                'Nmap Vulnerabilities': vuln_summary or '',
                'NmapVulnScanner': vuln_status or ''
            }

            if ip and mac and mac.upper() not in {"UNKNOWN", "STANDALONE"}:
                ip_to_mac[ip] = mac

            if mac:
                enrichment_map[("mac", mac.lower())] = enrichment_payload
            if ip:
                enrichment_map[("ip", ip)] = enrichment_payload

        for entry in network_data:
            mac = _extract_value(entry, ("MAC Address", "MAC", "mac"))
            ip = _extract_value(entry, ("IPs", "IP", "ip"))
            if not mac or mac.upper() in {"UNKNOWN", "STANDALONE", "00:00:00:00:00:00"}:
                fallback_mac = ip_to_mac.get(ip)
                if fallback_mac:
                    mac = fallback_mac

            mac = mac or ''
            entry['MAC Address'] = mac
            entry['MAC'] = mac
            entry['mac'] = mac

            enrichment = enrichment_map.get(("mac", mac.lower())) if mac else None
            if not enrichment and ip:
                enrichment = enrichment_map.get(("ip", ip))

            if enrichment:
                entry['Nmap Vulnerabilities'] = enrichment.get('Nmap Vulnerabilities', '')
                entry['nmap_vulnerabilities'] = entry['Nmap Vulnerabilities']
                entry['NmapVulnScanner'] = enrichment.get('NmapVulnScanner', '')
                entry['nmap_vuln_scanner'] = entry['NmapVulnScanner']
            else:
                entry.setdefault('Nmap Vulnerabilities', '')
                entry.setdefault('nmap_vulnerabilities', '')
                entry.setdefault('NmapVulnScanner', '')
                entry.setdefault('nmap_vuln_scanner', '')
    else:
        logger.warning("WiFi-specific network data is empty. Falling back to netkb data.")
        if netkb_data:
            normalized_entries = []
            for row in netkb_data:
                ip = _extract_value(row, ("IPs", "IP", "ip"))
                if not ip:
                    continue
                mac = _extract_value(row, ("MAC Address", "MAC", "mac"))
                hostname = _extract_value(row, ("Hostnames", "Hostname", "hostnames", "hostname"))
                alive = _extract_value(row, ("Alive", "Status", "alive", "status")) or '0'
                ports = _extract_value(row, ("Ports", "Open Ports", "open_ports"))
                last_seen = _extract_value(row, ("LastSeen", "Last Seen", "last_seen"))
                vuln_summary = _extract_value(row, ("Nmap Vulnerabilities", "nmap_vulnerabilities"))
                vuln_status = _extract_value(row, ("NmapVulnScanner", "nmap_vuln_scanner"))

                normalized_entries.append({
                    'IPs': ip,
                    'Hostnames': hostname,
                    'Alive': alive,
                    'MAC Address': mac,
                    'MAC': mac,
                    'mac': mac,
                    'Ports': ports,
                    'LastSeen': last_seen,
                    'Nmap Vulnerabilities': vuln_summary or '',
                    'nmap_vulnerabilities': vuln_summary or '',
                    'NmapVulnScanner': vuln_status or '',
                    'nmap_vuln_scanner': vuln_status or ''
                })

            network_data = normalized_entries
            if network_data:
                logger.debug("Used netkb data as fallback.")
        else:
            network_data = []

    current_ssid = get_current_wifi_ssid()
    logger.info(f"Returning {len(network_data)} network entries for WiFi: {current_ssid}")
    return network_data


@app.route('/api/network/stable')
def get_stable_network_data():
    """Get stable, aggregated network data for the Network tab from SQLite database"""
    with _network_context_from_request():
        try:
            db = get_db(currentdir=shared_data.currentdir)
        
            # Get all hosts from SQLite database
            hosts = db.get_all_hosts()
        
            # Also get any recent ARP scan cache data for real-time enrichment
            recent_arp_data = network_scan_cache.get('arp_hosts', {})
        
            logger.info(f"Loaded {len(hosts)} entries from SQLite database for stable API")
        
            # Merge and enrich the data
            enriched_hosts = []
            processed_ips = set()
        
            # Process SQLite hosts
            for host in hosts:
                ip = host.get('ip', '').strip()
                # Skip if empty, already processed, or is STANDALONE
                if not ip or ip in processed_ips or ip == 'STANDALONE':
                    continue
                
                processed_ips.add(ip)
            
                # Parse ports from semicolon-separated string to list
                ports_str = host.get('ports', '')
                if ports_str:
                    ports = [p.strip() for p in ports_str.split(';') if p.strip()]
                else:
                    ports = []
            
                # Determine status based on SQLite status field
                status = host.get('status', 'unknown')
                if status == 'alive':
                    host_status = 'up'
                elif status == 'degraded':
                    host_status = 'degraded'
                else:
                    host_status = 'unknown'
            
                host_data = {
                    'ip': ip,
                    'hostname': _normalize_value(host.get('hostname'), 'Unknown'),
                    'mac': _normalize_value(host.get('mac'), 'Unknown'),
                    'status': host_status,
                    'ports': ';'.join(ports) if ports else 'Unknown',
                    'vulnerabilities': _normalize_value(host.get('nmap_vuln_scanner'), '0'),
                    'last_scan': _normalize_value(host.get('last_seen'), 'Never'),
                    'first_seen': _normalize_value(host.get('first_seen'), 'Unknown'),
                    'os': 'Unknown',  # TODO: Add OS detection to database
                    'services': 'Unknown',  # TODO: Add services to database
                    'failed_pings': host.get('failed_ping_count', 0),
                    'source': 'sqlite'
                }
            
                # Enhance with recent ARP data if available
                if ip in recent_arp_data:
                    arp_entry = recent_arp_data[ip]
                    if arp_entry.get('mac') and host_data['mac'] in ['Unknown', '00:00:00:00:00:00', '']:
                        host_data['mac'] = arp_entry['mac']
                    if arp_entry.get('hostname') and host_data['hostname'] in ['Unknown', '']:
                        host_data['hostname'] = arp_entry['hostname']
                    if host_status != 'up':  # ARP means it's definitely up
                        host_data['status'] = 'up'
                    host_data['source'] = 'sqlite+arp'
            
                enriched_hosts.append(host_data)
        
            # Add any new ARP discoveries not in database
            for ip, arp_entry in recent_arp_data.items():
                if ip not in processed_ips:
                    host_data = {
                        'ip': ip,
                        'hostname': arp_entry.get('hostname', 'Unknown'),
                        'mac': arp_entry.get('mac', 'Unknown'),
                        'status': 'up',
                        'ports': 'Scanning...',
                        'vulnerabilities': '0',
                        'last_scan': 'Recently discovered',
                        'first_seen': 'Recent',
                        'os': 'Unknown',
                        'services': 'Unknown',
                        'failed_pings': 0,
                        'source': 'arp_discovery'
                    }
                    enriched_hosts.append(host_data)
        
            logger.info(f"Returning {len(enriched_hosts)} enriched hosts from SQLite database")
        
            # Sort by IP address for consistent display
            def safe_ip_sort_key(host):
                ip = host.get('ip', '')
                try:
                    # Try to parse as IP address
                    return (0, tuple(map(int, ip.split('.'))))
                except (ValueError, AttributeError):
                    # Non-IP values sort to the end
                    return (1, ip)
        
            enriched_hosts.sort(key=safe_ip_sort_key)
        
            response = jsonify({
                'success': True,
                'hosts': enriched_hosts,
                'count': len(enriched_hosts),
                'timestamp': datetime.now().isoformat(),
                'source': 'sqlite_database'
            })
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        
        except Exception as e:
            logger.error(f"Error getting stable network data from SQLite: {e}")
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e),
                'hosts': [],
                'count': 0
            }), 500

@app.route('/api/network')
def get_network():
    """Get network scan data from SQLite database - returns ALL hosts (alive and degraded)."""
    with _network_context_from_request():
        try:
            # Get all hosts from SQLite database
            hosts = shared_data.db.get_all_hosts()
        
            logger.debug(f"[API /api/network] Retrieved {len(hosts)} total hosts from database")
        
            # Convert to format expected by frontend
            network_data = []
            alive_count = 0
            degraded_count = 0
        
            for host in hosts:
                # Parse ports from comma-separated string to list
                ports_str = host.get('ports', '')
                ports = [p.strip() for p in ports_str.split(',') if p.strip()] if ports_str else []
            
                status = host.get('status', 'unknown')
                if status == 'alive':
                    alive_count += 1
                elif status == 'degraded':
                    degraded_count += 1
            
                network_data.append({
                    'mac': host.get('mac', ''),
                    'ip': host.get('ip', ''),
                    'hostname': host.get('hostname', ''),
                    'status': status,
                    'ports': ports,
                    'failed_pings': host.get('failed_ping_count', 0),
                    'last_seen': host.get('last_seen', ''),
                    # Action statuses
                    'scanner': host.get('scanner_status', ''),
                    'network_profile': host.get('network_profile', ''),
                    'ssh_connector': host.get('ssh_connector', ''),
                    'rdp_connector': host.get('rdp_connector', ''),
                    'ftp_connector': host.get('ftp_connector', ''),
                    'smb_connector': host.get('smb_connector', ''),
                    'telnet_connector': host.get('telnet_connector', ''),
                    'sql_connector': host.get('sql_connector', ''),
                    'steal_files_ssh': host.get('steal_files_ssh', ''),
                    'steal_files_rdp': host.get('steal_files_rdp', ''),
                    'steal_files_ftp': host.get('steal_files_ftp', ''),
                    'steal_files_smb': host.get('steal_files_smb', ''),
                    'steal_files_telnet': host.get('steal_files_telnet', ''),
                    'steal_data_sql': host.get('steal_data_sql', ''),
                    'nmap_vuln_scanner': host.get('nmap_vuln_scanner', ''),
                    'notes': host.get('notes', '')
                })
        
            logger.info(f"[API /api/network] Returning {len(network_data)} hosts (alive: {alive_count}, degraded: {degraded_count})")
        
            response = jsonify(network_data)
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response

        except Exception as e:
            logger.error(f"Error getting network data from SQLite: {e}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            return jsonify({'error': str(e)}), 500


def _batch_ai_classify(nodes, indices, ai_service, labels, valid_types):
    """Classify multiple low-confidence devices in a SINGLE GPT-5 Nano call.

    Mutates nodes in-place for the given indices.
    """
    if not indices:
        return

    # Build a compact table for the prompt
    lines = []
    for idx in indices:
        n = nodes[idx]
        lines.append(
            f"{idx}|{n.get('vendor','') or '?'}|{n.get('hostname','') or '?'}|"
            f"{n.get('mac','') or '?'}|{','.join(n['ports'][:10]) or 'none'}"
        )

    valid_list = ", ".join(sorted(valid_types - {"ragnar", "unknown"}))

    system = (
        "You are a network device classifier. For each numbered line, reply with "
        "ONLY the line number and device_type, one per line. "
        f"Valid types: {valid_list}. "
        "Format: NUMBER|TYPE\nExample: 0|smart_tv\nIf uncertain reply NUMBER|unknown"
    )

    user = (
        "IDX|VENDOR|HOSTNAME|MAC|PORTS\n" + "\n".join(lines)
    )

    original_model = ai_service.model
    try:
        ai_service.model = "gpt-5-nano"
        answer = ai_service._ask(system, user)
    finally:
        ai_service.model = original_model

    if not answer:
        return

    # Parse response lines
    for line in answer.strip().splitlines():
        line = line.strip().strip('`')
        if '|' not in line:
            continue
        parts = line.split('|', 1)
        try:
            idx = int(parts[0].strip())
            dtype = parts[1].strip().lower().replace(' ', '_').strip('"\'.,')
        except (ValueError, IndexError):
            continue
        if idx in indices and dtype in valid_types:
            nodes[idx]['type'] = dtype
            nodes[idx]['type_label'] = labels.get(dtype, 'Unknown')
            nodes[idx]['confidence'] = 0.7


@app.route('/api/network/topology')
def get_network_topology():
    """Build a topology graph with gateway as center, device types classified, and links inferred."""
    with _network_context_from_request():
        try:
            import hashlib
            from device_classifier import classify_device, classify_device_ai, DEVICE_ICONS, DEVICE_TYPE_LABELS, DEVICE_TYPE_COLORS, VALID_DEVICE_TYPES

            # Client can explicitly request AI classification
            use_ai = request.args.get('use_ai', '0') == '1'

            hosts = shared_data.db.get_all_hosts()
            gw = getattr(shared_data, 'gateway_info', {}) or {}
            gateway_ip = gw.get('gateway_ip')
            ragnar_ip = gw.get('ragnar_ip')
            subnet = gw.get('subnet')
            interface = gw.get('interface')

            # Compute a lightweight fingerprint of the current host list
            # so the client can detect network changes
            _hash_parts = sorted(f"{h.get('ip','')}|{h.get('mac','')}|{h.get('ports','')}" for h in hosts)
            network_hash = hashlib.md5('|'.join(_hash_parts).encode()).hexdigest()[:12]

            # If no gateway info yet, try to detect from netifaces directly
            if not gateway_ip:
                try:
                    import netifaces
                    gws = netifaces.gateways()
                    gw_tuple = gws.get('default', {}).get(netifaces.AF_INET)
                    if gw_tuple:
                        gateway_ip = gw_tuple[0]
                        interface = gw_tuple[1]
                        iface_addrs = netifaces.ifaddresses(gw_tuple[1]).get(netifaces.AF_INET)
                        if iface_addrs:
                            ragnar_ip = iface_addrs[0]['addr']
                except Exception:
                    pass

            # Build credentials set for risk scoring
            cred_ips = set()
            try:
                cred_data = shared_data.db.get_all_credentials() if hasattr(shared_data.db, 'get_all_credentials') else []
                for c in cred_data:
                    ip_val = c.get('ip', '')
                    if ip_val:
                        cred_ips.add(ip_val)
            except Exception:
                pass

            # ----------------------------------------------------------
            # Phase 1: fast rule-based classification (no AI calls)
            # ----------------------------------------------------------
            nodes = []
            node_ids = set()
            low_confidence_indices = []  # indices of nodes needing AI help

            for host in hosts:
                ip = host.get('ip', '')
                if not ip:
                    continue

                ports_str = host.get('ports', '')
                ports = [p.strip() for p in ports_str.split(',') if p.strip()] if ports_str else []
                vendor = host.get('vendor', '') or ''
                status = host.get('status', 'unknown')
                hostname = host.get('hostname', '') or ''
                mac = host.get('mac', '') or ''

                # Rule-based + hostname classification (no AI yet)
                classification = classify_device_ai(
                    vendor, ports,
                    hostname=hostname,
                    mac=mac,
                    ai_service=None,  # skip AI in phase 1
                    gateway_ip=gateway_ip, device_ip=ip,
                )

                # Risk scoring
                port_count = len(ports)
                has_creds = 5 if ip in cred_ips else 0
                degraded = 3 if status == 'degraded' else 0
                risk = port_count + has_creds + degraded

                node = {
                    'id': ip,
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor,
                    'type': classification['device_type'],
                    'type_label': classification['label'],
                    'confidence': classification['confidence'],
                    'ports': ports,
                    'status': status,
                    'risk': risk,
                    'last_seen': host.get('last_seen', ''),
                    'is_gateway': ip == gateway_ip,
                    'is_ragnar': ip == ragnar_ip,
                }
                nodes.append(node)
                node_ids.add(ip)

                # Track low-confidence nodes for batch AI
                if classification['confidence'] < 0.65 and not node['is_gateway']:
                    low_confidence_indices.append(len(nodes) - 1)

            # ----------------------------------------------------------
            # Phase 2: batch AI classification (only when client requests it)
            # ----------------------------------------------------------
            ai_used = False
            ai_service = getattr(shared_data, 'ai_service', None)
            if use_ai and ai_service and low_confidence_indices and ai_service.ensure_ready():
                # Check if we have cached AI results for this exact network state
                _topo_ai_cache = getattr(shared_data, '_topo_ai_cache', {})
                cached = _topo_ai_cache.get(network_hash)
                if cached:
                    # Apply cached classifications
                    for idx, dtype, label in cached:
                        if idx < len(nodes):
                            nodes[idx]['type'] = dtype
                            nodes[idx]['type_label'] = label
                            nodes[idx]['confidence'] = 0.7
                    ai_used = True
                else:
                    try:
                        _batch_ai_classify(nodes, low_confidence_indices, ai_service, DEVICE_TYPE_LABELS, VALID_DEVICE_TYPES)
                        # Store results in cache
                        cache_entries = [(idx, nodes[idx]['type'], nodes[idx]['type_label']) for idx in low_confidence_indices]
                        shared_data._topo_ai_cache = {network_hash: cache_entries}
                        ai_used = True
                    except Exception as e:
                        logger.debug(f"Batch AI classification failed (non-fatal): {e}")

            # ----------------------------------------------------------
            # Phase 3: build topology links
            # ----------------------------------------------------------
            import ipaddress
            potential_aps = []  # Devices that extend the network

            # Ensure gateway is in node list even if not in hosts table
            if gateway_ip and gateway_ip not in node_ids:
                gw_vendor = gw.get('gateway_vendor', '')
                gw_class = classify_device(gw_vendor, ['53', '80', '443'], gateway_ip=gateway_ip, device_ip=gateway_ip)
                nodes.append({
                    'id': gateway_ip,
                    'ip': gateway_ip,
                    'mac': gw.get('gateway_mac', ''),
                    'hostname': 'Gateway',
                    'vendor': gw_vendor,
                    'type': 'router',
                    'type_label': 'Router/Gateway',
                    'confidence': 1.0,
                    'ports': [],
                    'status': 'alive',
                    'risk': 0,
                    'last_seen': '',
                    'is_gateway': True,
                    'is_ragnar': False,
                })
                node_ids.add(gateway_ip)

            # Identify network-extending devices (APs, extenders, secondary routers)
            _NETWORK_EXTENDER_TYPES = {'access_point', 'extender', 'switch'}
            for node in nodes:
                if node['is_gateway'] or node['is_ragnar']:
                    continue
                if node['type'] in _NETWORK_EXTENDER_TYPES:
                    potential_aps.append(node)
                elif node['type'] == 'router' and node['confidence'] >= 0.8:
                    potential_aps.append(node)

            # ── Determine the gateway's /24 subnet ──
            gw_subnet_prefix = None
            if gateway_ip:
                try:
                    gw_subnet_prefix = str(ipaddress.ip_network(f"{gateway_ip}/24", strict=False))
                except Exception:
                    pass

            # ── Build AP subnet map ──
            # If an AP/router is on a DIFFERENT /24 than the gateway,
            # every device on that /24 is assumed to go through that AP.
            ap_subnet_map = {}    # "/24 network string" → AP ip
            ap_macs_prefix = {}   # MAC OUI prefix → AP ip  (fallback for same-subnet)
            for ap in potential_aps:
                ap_ip = ap.get('ip', '')
                if not ap_ip:
                    continue

                # Subnet-based mapping
                try:
                    ap_net = str(ipaddress.ip_network(f"{ap_ip}/24", strict=False))
                    if gw_subnet_prefix and ap_net != gw_subnet_prefix:
                        # This AP serves a different subnet
                        ap_subnet_map[ap_net] = ap_ip
                    elif not gw_subnet_prefix:
                        ap_subnet_map[ap_net] = ap_ip
                except Exception:
                    pass

                # MAC OUI fallback (same-subnet heuristic)
                mac = ap.get('mac', '')
                if mac and len(mac) >= 8:
                    prefix = mac[:8].lower()
                    ap_macs_prefix[prefix] = ap_ip

            # ── Build links ──
            links = []
            for node in nodes:
                if node['is_gateway']:
                    continue
                target = gateway_ip or (nodes[0]['ip'] if nodes else None)
                link_type = 'default'
                node_ip = node.get('ip', '')
                node_type = node.get('type', '')

                # Strategy 1: Subnet-based assignment
                # If this device is on the same /24 as an AP that is NOT
                # on the gateway's subnet, route it through that AP.
                try:
                    node_net = str(ipaddress.ip_network(f"{node_ip}/24", strict=False))
                    if node_net in ap_subnet_map and ap_subnet_map[node_net] != node_ip:
                        target = ap_subnet_map[node_net]
                        link_type = 'subnet_inferred'
                except Exception:
                    node_net = None

                # Strategy 2: MAC OUI prefix (same-subnet fallback)
                if link_type == 'default' and node_type not in ('router', 'access_point', 'extender', 'switch'):
                    mac = node.get('mac', '')
                    if mac and len(mac) >= 8:
                        prefix = mac[:8].lower()
                        if prefix in ap_macs_prefix and ap_macs_prefix[prefix] != node_ip:
                            target = ap_macs_prefix[prefix]
                            link_type = 'ap_inferred'

                if target:
                    links.append({
                        'source': node_ip,
                        'target': target,
                        'type': link_type,
                    })

            # APs / extenders connect upstream to gateway
            for ap in potential_aps:
                if gateway_ip:
                    links.append({
                        'source': ap['ip'],
                        'target': gateway_ip,
                        'type': 'ap_uplink',
                    })

            result = {
                'gateway': {
                    'ip': gateway_ip,
                    'mac': gw.get('gateway_mac', ''),
                    'vendor': gw.get('gateway_vendor', ''),
                },
                'ragnar': {
                    'ip': ragnar_ip,
                    'interface': interface,
                },
                'subnet': subnet,
                'nodes': nodes,
                'links': links,
                'device_icons': DEVICE_ICONS,
                'device_labels': DEVICE_TYPE_LABELS,
                'device_colors': DEVICE_TYPE_COLORS,
                'network_hash': network_hash,
                'ai_used': ai_used,
            }
            return jsonify(result)

        except Exception as e:
            logger.error(f"Error building topology: {e}")
            logger.debug(traceback.format_exc())
            return jsonify({'error': str(e)}), 500


@app.route('/api/host/<path:ip>')
def get_host_detail(ip):
    """Get all aggregated data for a single host"""
    try:
        # Get host base data from DB
        host_data = None
        hosts = shared_data.db.get_all_hosts()
        for h in hosts:
            if h.get('ip') == ip:
                host_data = h
                break

        if not host_data:
            return jsonify({'error': 'Host not found'}), 404

        ports_str = host_data.get('ports', '')
        ports = [p.strip() for p in ports_str.split(',') if p.strip()] if ports_str else []

        # Get credentials for this IP across all services
        all_creds = web_utils.get_all_credentials()
        host_creds = []
        for svc, entries in all_creds.items():
            for e in entries:
                if e.get('ip') == ip:
                    host_creds.append({**e, 'service': svc})

        # Get attack logs for this IP (last 30)
        attack_log_dir = os.path.join(shared_data.logsdir, 'attacks')
        host_attacks = []
        if os.path.exists(attack_log_dir):
            from datetime import datetime, timedelta
            cutoff = datetime.now() - timedelta(days=30)
            for lf in sorted(os.listdir(attack_log_dir), reverse=True)[:30]:
                if not lf.startswith('attacks_') or not lf.endswith('.json'):
                    continue
                try:
                    file_date = datetime.strptime(lf.replace('attacks_','').replace('.json',''), '%Y-%m-%d')
                    if file_date < cutoff:
                        continue
                    with open(os.path.join(attack_log_dir, lf), 'r', encoding='utf-8') as f:
                        for entry in json.load(f):
                            if entry.get('target_ip') == ip:
                                host_attacks.append(entry)
                except Exception:
                    continue
        host_attacks.sort(key=lambda x: x.get('timestamp',''), reverse=True)
        host_attacks = host_attacks[:30]

        # Get vulnerability file for this IP if it exists
        vuln_summary = ''
        vuln_file = os.path.join(shared_data.vulnerabilities_dir, f'vuln_{ip}.txt')
        if os.path.exists(vuln_file):
            try:
                with open(vuln_file, 'r', encoding='utf-8', errors='ignore') as f:
                    vuln_summary = f.read(4000)  # cap at 4KB
            except Exception:
                pass

        return jsonify({
            'ip': ip,
            'hostname': host_data.get('hostname', ''),
            'mac': host_data.get('mac', ''),
            'status': host_data.get('status', 'unknown'),
            'ports': ports,
            'last_seen': host_data.get('last_seen', ''),
            'notes': host_data.get('notes', ''),
            'services': {
                'ssh': host_data.get('ssh_connector', ''),
                'ftp': host_data.get('ftp_connector', ''),
                'smb': host_data.get('smb_connector', ''),
                'telnet': host_data.get('telnet_connector', ''),
                'rdp': host_data.get('rdp_connector', ''),
                'sql': host_data.get('sql_connector', ''),
            },
            'credentials': host_creds,
            'attack_logs': host_attacks,
            'vuln_summary': vuln_summary,
        })
    except Exception as e:
        logger.error(f"Error getting host detail for {ip}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/credentials')
def get_credentials():
    """Get discovered credentials"""
    with _network_context_from_request():
        try:
            credentials = web_utils.get_all_credentials()
            return jsonify(credentials)
        except Exception as e:
            logger.error(f"Error getting credentials: {e}")
            return jsonify({'error': str(e)}), 500


@app.route('/api/loot')
def get_loot():
    """Get stolen data/loot"""
    with _network_context_from_request():
        try:
            loot = web_utils.get_loot_data()
            return jsonify(loot)
        except Exception as e:
            logger.error(f"Error getting loot: {e}")
            return jsonify({'error': str(e)}), 500


@app.route('/api/report/export')
def export_report():
    """Generate and download a self-contained HTML scan report"""
    try:
        from datetime import datetime as _dt
        import html as _html

        # Gather data
        hosts = shared_data.db.get_all_hosts()
        all_creds = web_utils.get_all_credentials()
        flat_creds = []
        for svc, entries in all_creds.items():
            for e in entries:
                flat_creds.append({**e, 'service': svc})

        # Attack logs (last 30 days)
        attack_log_dir = os.path.join(shared_data.logsdir, 'attacks')
        all_attacks = []
        if os.path.exists(attack_log_dir):
            from datetime import timedelta
            cutoff = _dt.now() - timedelta(days=30)
            for lf in sorted(os.listdir(attack_log_dir), reverse=True)[:30]:
                if not lf.startswith('attacks_') or not lf.endswith('.json'):
                    continue
                try:
                    file_date = _dt.strptime(lf.replace('attacks_','').replace('.json',''), '%Y-%m-%d')
                    if file_date < cutoff:
                        continue
                    with open(os.path.join(attack_log_dir, lf), 'r', encoding='utf-8') as f:
                        all_attacks.extend(json.load(f))
                except Exception:
                    continue
        all_attacks.sort(key=lambda x: x.get('timestamp',''), reverse=True)

        # Stats
        alive_hosts = [h for h in hosts if h.get('status') == 'alive']
        total_ports = sum(len([p for p in (h.get('ports','') or '').split(',') if p.strip()]) for h in hosts)
        success_attacks = [a for a in all_attacks if a.get('status') == 'success']

        generated_at = _dt.now().strftime('%Y-%m-%d %H:%M:%S')
        network_ssid = getattr(shared_data, 'active_network_ssid', None) or 'Unknown'

        def e(s): return _html.escape(str(s or ''))

        # Build host rows
        host_rows = ''
        for h in sorted(hosts, key=lambda x: x.get('ip','')):
            ports_str = h.get('ports','') or ''
            ports = [p.strip() for p in ports_str.split(',') if p.strip()]
            status = h.get('status','unknown')
            status_color = '#4ade80' if status == 'alive' else ('#facc15' if status == 'degraded' else '#9ca3af')
            host_rows += f"""<tr>
                <td><span style="color:{status_color}">{e(status)}</span></td>
                <td class="mono">{e(h.get('ip',''))}</td>
                <td>{e(h.get('hostname',''))}</td>
                <td class="mono">{e(h.get('mac',''))}</td>
                <td>{e(len(ports))}</td>
                <td class="mono small">{e(', '.join(ports[:10])) + ('…' if len(ports) > 10 else '')}</td>
                <td>{e(h.get('last_seen',''))}</td>
            </tr>"""

        # Build credential rows
        cred_rows = ''
        svc_colors = {'ssh':'#93c5fd','smb':'#c4b5fd','ftp':'#fde68a','telnet':'#fdba74','rdp':'#f9a8d4','sql':'#86efac'}
        for c in flat_creds:
            color = svc_colors.get(c.get('service',''), '#9ca3af')
            cred_rows += f"""<tr>
                <td class="mono">{e(c.get('ip',''))}</td>
                <td><span style="color:{color};font-weight:600">{e(c.get('service','').upper())}</span></td>
                <td class="mono">{e(c.get('username',''))}</td>
                <td class="mono">{e(c.get('password',''))}</td>
            </tr>"""

        # Build attack rows (top 200)
        attack_rows = ''
        status_colors_atk = {'success':'#4ade80','failed':'#f87171','timeout':'#facc15'}
        for a in all_attacks[:200]:
            color = status_colors_atk.get(a.get('status',''), '#9ca3af')
            attack_rows += f"""<tr>
                <td class="small">{e(a.get('timestamp',''))}</td>
                <td class="mono">{e(a.get('target_ip',''))}</td>
                <td>{e(a.get('attack_type',''))}</td>
                <td>{e(a.get('target_port',''))}</td>
                <td><span style="color:{color};font-weight:600">{e(a.get('status',''))}</span></td>
                <td class="small">{e((a.get('message','') or '')[:80])}</td>
            </tr>"""

        html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ragnar Scan Report — {e(generated_at)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
  h1{{font-size:1.8rem;margin-bottom:0.25rem;color:#f8fafc}}
  .subtitle{{color:#94a3b8;margin-bottom:2rem;font-size:0.9rem}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:2rem}}
  .stat{{background:#1e293b;border:1px solid #334155;border-radius:0.5rem;padding:1rem;text-align:center}}
  .stat-value{{font-size:2rem;font-weight:700;color:#f8fafc}}
  .stat-label{{font-size:0.75rem;color:#94a3b8;margin-top:0.25rem;text-transform:uppercase;letter-spacing:.05em}}
  section{{margin-bottom:2.5rem}}
  h2{{font-size:1.1rem;font-weight:600;color:#cbd5e1;border-bottom:1px solid #334155;padding-bottom:0.5rem;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.05em}}
  .table-wrap{{overflow-x:auto}}
  table{{width:100%;border-collapse:collapse;font-size:0.8rem}}
  th{{background:#1e293b;color:#94a3b8;text-align:left;padding:0.5rem 0.75rem;font-weight:600;white-space:nowrap}}
  td{{padding:0.45rem 0.75rem;border-bottom:1px solid #1e293b}}
  tr:hover td{{background:#1e293b}}
  .mono{{font-family:'SF Mono',monospace}}
  .small{{font-size:0.72rem}}
  .empty{{color:#475569;font-style:italic;padding:1rem 0}}
  .footer{{margin-top:3rem;color:#475569;font-size:0.75rem;text-align:center}}
</style>
</head>
<body>
<h1>Ragnar Scan Report</h1>
<p class="subtitle">Generated: {e(generated_at)} &nbsp;|&nbsp; Network: {e(network_ssid)}</p>

<div class="stats">
  <div class="stat"><div class="stat-value">{len(hosts)}</div><div class="stat-label">Total Hosts</div></div>
  <div class="stat"><div class="stat-value" style="color:#4ade80">{len(alive_hosts)}</div><div class="stat-label">Alive</div></div>
  <div class="stat"><div class="stat-value">{total_ports}</div><div class="stat-label">Open Ports</div></div>
  <div class="stat"><div class="stat-value" style="color:#f87171">{len(flat_creds)}</div><div class="stat-label">Credentials</div></div>
  <div class="stat"><div class="stat-value">{len(all_attacks)}</div><div class="stat-label">Attacks Logged</div></div>
  <div class="stat"><div class="stat-value" style="color:#4ade80">{len(success_attacks)}</div><div class="stat-label">Successful</div></div>
</div>

<section>
  <h2>Discovered Hosts ({len(hosts)})</h2>
  <div class="table-wrap">
  {'<table><thead><tr><th>Status</th><th>IP</th><th>Hostname</th><th>MAC</th><th>Ports #</th><th>Open Ports</th><th>Last Seen</th></tr></thead><tbody>' + host_rows + '</tbody></table>' if host_rows else '<p class="empty">No hosts discovered</p>'}
  </div>
</section>

<section>
  <h2>Discovered Credentials ({len(flat_creds)})</h2>
  <div class="table-wrap">
  {'<table><thead><tr><th>IP</th><th>Service</th><th>Username</th><th>Password</th></tr></thead><tbody>' + cred_rows + '</tbody></table>' if cred_rows else '<p class="empty">No credentials found</p>'}
  </div>
</section>

<section>
  <h2>Attack Log (last 30 days — top 200)</h2>
  <div class="table-wrap">
  {'<table><thead><tr><th>Timestamp</th><th>Target IP</th><th>Attack Type</th><th>Port</th><th>Status</th><th>Message</th></tr></thead><tbody>' + attack_rows + '</tbody></table>' if attack_rows else '<p class="empty">No attacks logged</p>'}
  </div>
</section>

<p class="footer">Ragnar Security Scanner &mdash; For authorized testing only</p>
</body>
</html>"""

        filename = f"ragnar_report_{_dt.now().strftime('%Y%m%d_%H%M%S')}.html"
        response = make_response(html_report)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerability-report/<path:filename>')
def download_vulnerability_report(filename):
    """Stream a vulnerability report file while preventing directory traversal.

    Supports per-network directories via ?network= query param so that download
    URLs returned by /api/vulnerability-intel can be followed directly when a
    network context is active. Falls back to the global vulnerabilities directory
    when no network context is provided.
    """
    with _network_context_from_request():
        try:
            vuln_dir = os.path.abspath(
                getattr(shared_data, 'vulnerabilities_dir',
                        os.path.join('data', 'output', 'vulnerabilities'))
            )
            requested_path = os.path.normpath(os.path.join(vuln_dir, filename))

            if not requested_path.startswith(vuln_dir + os.sep) and requested_path != vuln_dir:
                logger.warning(f"Blocked traversal attempt for report: {filename}")
                return jsonify({'error': 'File not found'}), 404

            if not os.path.isfile(requested_path):
                return jsonify({'error': 'File not found'}), 404

            rel_path = os.path.relpath(requested_path, vuln_dir)
            return send_from_directory(vuln_dir, rel_path, as_attachment=True)
        except Exception as exc:
            logger.error(f"Error serving vulnerability report {filename}: {exc}")
            return jsonify({'error': 'Unable to download report'}), 500


@app.route('/api/vulnerability-intel')
def get_vulnerability_intel():
    """Get interesting intelligence from scan files (not vulnerabilities - those are in threat intel)"""
    with _network_context_from_request():
        try:
            vuln_dir = getattr(shared_data, 'vulnerabilities_dir',
                               os.path.join('data', 'output', 'vulnerabilities'))
            # Embed network context into download links so clicking "View Full Report"
            # resolves the correct per-network directory.
            _net_slug = request.args.get('network') or request.args.get('ssid') or request.args.get('slug')
            _net_qs = f"?network={_net_slug}" if _net_slug else ""

            if not os.path.exists(vuln_dir):
                return jsonify({
                    'scans': [],
                    'statistics': {
                        'total_scanned': 0,
                        'interesting_hosts': 0,
                        'services_with_intel': 0,
                        'script_outputs': 0
                    }
                })

            scans = []
            stats = {
                'total_scanned': 0,
                'interesting_hosts': 0,
                'services_with_intel': 0,
                'script_outputs': 0
            }

            def format_lynis_section(title, entries, limit=25):
                entries = list(entries or [])
                if not entries:
                    return None

                lines = []
                for entry in entries[:limit]:
                    parts = []
                    code = entry.get('code') or entry.get('package') or title.upper()
                    if code:
                        parts.append(f"[{code}]")
                    message = entry.get('message') or entry.get('package') or entry.get('raw') or ''
                    if message:
                        parts.append(message)
                    detail = entry.get('detail') or entry.get('version') or ''
                    if detail:
                        parts.append(detail)
                    remediation = entry.get('remediation') or entry.get('reference') or ''
                    if remediation:
                        parts.append(f"Fix: {remediation}")
                    line = ' | '.join(part for part in parts if part)
                    if line:
                        lines.append(line)

                if len(entries) > limit:
                    lines.append(f"...and {len(entries) - limit} more")

                if not lines:
                    return None

                return {
                    'name': title,
                    'output': '\n'.join(lines)
                }

            vuln_files = os.listdir(vuln_dir)

            # Process all scan files
            for filename in vuln_files:
                if filename.endswith('_vuln_scan.txt'):
                    file_path = os.path.join(vuln_dir, filename)
                    stats['total_scanned'] += 1

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        # Extract host information
                        parts = filename.split('_')
                        ip = parts[1] if len(parts) > 1 else 'Unknown'

                        hostname = 'Unknown'
                        hostname_match = re.search(r'Nmap scan report for ([^\s]+)\s+\(([^\)]+)\)', content)
                        if hostname_match:
                            hostname = hostname_match.group(1)
                            ip = hostname_match.group(2)
                        else:
                            hostname_match = re.search(r'Nmap scan report for ([^\s]+)', content)
                            if hostname_match:
                                potential_host = hostname_match.group(1)
                                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', potential_host):
                                    hostname = potential_host

                        # Extract interesting service information
                        services = []

                        # Parse port/service lines with version info
                        port_lines = re.findall(r'(\d+/tcp)\s+open\s+(\S+)(?:\s+(.+?))?(?=\n|$)', content)

                        for port, service_name, version_info in port_lines:
                            service_data = {
                                'port': port,
                                'service': service_name,
                                'version': version_info.strip() if version_info else '',
                                'scripts': []
                            }

                            # Look for script output after this port
                            # Find the section between this port and the next port or end
                            port_num = port.split('/')[0]
                            pattern = rf'{re.escape(port)}.*?(?=\n\d+/tcp|\nService Info:|\nNmap done:|$)'
                            port_section_match = re.search(pattern, content, re.DOTALL)

                            if port_section_match:
                                port_section = port_section_match.group(0)

                                # Extract script outputs (lines starting with |)
                                script_lines = re.findall(r'^\|(.+)$', port_section, re.MULTILINE)

                                if script_lines:
                                    # Filter out lines with PACKETSTORM, vulners, CVE, exploit references
                                    filtered_lines = []
                                    for line in script_lines:
                                        line_lower = line.lower()
                                        # Skip lines containing vulnerability/exploit references
                                        if any(keyword in line_lower for keyword in ['packetstorm', 'vulners.com', 'cve-', 'exploit', 'https://']):
                                            continue
                                        # Skip lines that look like vulnerability IDs or scores
                                        if re.search(r'\d+\.\d+\s+https?://', line):
                                            continue
                                        # Skip nmap footer messages
                                        if 'service detection performed' in line_lower:
                                            continue
                                        if 'please report any incorrect results' in line_lower:
                                            continue
                                        if 'nmap.org/submit' in line_lower:
                                            continue
                                        filtered_lines.append(line)

                                    script_lines = filtered_lines

                                    # Group script output by script name
                                    current_script = None
                                    script_content = []

                                    for line in script_lines:
                                        line = line.strip()

                                        # Check if this is a script name line (ends with :)
                                        if ':' in line and not line.startswith('_') and not line.startswith(' '):
                                            # Save previous script if exists
                                            if current_script and script_content:
                                                service_data['scripts'].append({
                                                    'name': current_script,
                                                    'output': '\n'.join(script_content)
                                                })
                                                stats['script_outputs'] += 1

                                            # Start new script
                                            script_name_match = re.match(r'^\s*(\S+?):\s*(.*)', line)
                                            if script_name_match:
                                                script_name = script_name_match.group(1)
                                                # Skip vulnerability-related scripts
                                                if script_name.lower() in ['vulners', 'vulns']:
                                                    current_script = None
                                                    script_content = []
                                                    continue
                                                current_script = script_name
                                                first_content = script_name_match.group(2)
                                                script_content = [first_content] if first_content else []
                                        else:
                                            # Add to current script content
                                            if current_script:
                                                script_content.append(line)

                                    # Save last script
                                    if current_script and script_content:
                                        service_data['scripts'].append({
                                            'name': current_script,
                                            'output': '\n'.join(script_content)
                                        })
                                        stats['script_outputs'] += 1

                            # Only add service if it has interesting data (version info or script output)
                            if service_data['version'] or service_data['scripts']:
                                services.append(service_data)
                                stats['services_with_intel'] += 1

                        # Only include hosts with interesting intelligence (not basic scans)
                        if services:
                            mod_time = os.path.getmtime(file_path)
                            scan_date = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')

                            scans.append({
                                'ip': ip,
                                'hostname': hostname,
                                'scan_date': scan_date,
                                'filename': filename,
                                'download_url': f"/api/vulnerability-report/{filename}{_net_qs}",
                                'log_url': f"/api/vulnerability-report/{filename}{_net_qs}",
                                'services': services,
                                'total_services': len(services)
                            })

                            stats['interesting_hosts'] += 1

                    except Exception as e:
                        logger.error(f"Error parsing scan file {filename}: {e}")
                        continue

            # Process Lynis pentest reports
            lynis_pattern = re.compile(r'^lynis_(?P<ip>[^_]+)_(?P<ts>\d{8}_\d{6})_pentest\.txt$')

            for filename in vuln_files:
                match = lynis_pattern.match(filename)
                if not match:
                    continue

                file_path = os.path.join(vuln_dir, filename)
                stats['total_scanned'] += 1

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as handle:
                        content = handle.read()

                    ip = match.group('ip')
                    timestamp_raw = match.group('ts')
                    hostname = f"{ip} (Lynis)"

                    mod_time = os.path.getmtime(file_path)
                    scan_date = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')

                    dat_filename = filename.replace('_pentest.txt', '.dat')
                    dat_path = os.path.join(vuln_dir, dat_filename)
                    parsed_report = {}
                    if os.path.exists(dat_path):
                        with open(dat_path, 'r', encoding='utf-8', errors='ignore') as dat_handle:
                            parsed_report = parse_lynis_dat(dat_handle.read()) or {}

                    findings = []
                    for line in content.splitlines():
                        stripped = line.strip()
                        lowered = stripped.lower()
                        if not stripped:
                            continue
                        if lowered.startswith('warning[') or lowered.startswith('suggestion['):
                            findings.append(stripped)
                        elif 'hardening index' in lowered:
                            findings.append(stripped)

                    if not findings:
                        snippet = content.strip().splitlines()[:40]
                        findings = snippet if snippet else ['No explicit warnings captured; see full report for details.']

                    report_excerpt = '\n'.join(findings)
                    if len(report_excerpt) > 8000:
                        report_excerpt = report_excerpt[:8000] + '\n...[truncated]'

                    scripts = [{
                        'name': 'security_audit',
                        'output': report_excerpt
                    }]

                    warnings_section = format_lynis_section('warnings', parsed_report.get('warnings', []))
                    if warnings_section:
                        scripts.append(warnings_section)

                    suggestions_section = format_lynis_section('suggestions', parsed_report.get('suggestions', []))
                    if suggestions_section:
                        scripts.append(suggestions_section)

                    packages_section = format_lynis_section('packages', parsed_report.get('vulnerable_packages', []))
                    if packages_section:
                        scripts.append(packages_section)

                    hardening_index = None
                    metadata = parsed_report.get('metadata') if isinstance(parsed_report, dict) else {}
                    if isinstance(metadata, dict):
                        hardening_index = metadata.get('hardening_index')

                    service_entry = {
                        'port': 'system',
                        'service': 'lynis pentest',
                        'version': f"Hardening index: {hardening_index} @ {timestamp_raw}" if hardening_index else timestamp_raw,
                        'scripts': scripts
                    }

                    stats['services_with_intel'] += 1
                    stats['script_outputs'] += len(scripts)
                    stats['interesting_hosts'] += 1

                    download_target = dat_filename if os.path.exists(dat_path) else filename

                    scans.append({
                        'ip': ip,
                        'hostname': hostname,
                        'scan_date': scan_date,
                        'filename': filename,
                        'download_url': f"/api/vulnerability-report/{download_target}{_net_qs}",
                        'log_url': f"/api/vulnerability-report/{filename}{_net_qs}",
                        'services': [service_entry],
                        'total_services': 1,
                        'scan_type': 'lynis'
                    })

                except Exception as exc:
                    logger.error(f"Error parsing Lynis report {filename}: {exc}")
                    continue

            # Consolidate scans by IP address to prevent duplicates
            consolidated_scans = {}

            for scan in scans:
                ip = scan['ip']

                if ip not in consolidated_scans:
                    # First scan for this IP - use as base
                    consolidated_scans[ip] = scan.copy()
                else:
                    # Merge services from additional scans for same IP
                    existing_scan = consolidated_scans[ip]

                    # Merge services, avoiding duplicates
                    existing_services = {f"{svc['port']}_{svc['service']}": svc for svc in existing_scan['services']}

                    for new_service in scan['services']:
                        service_key = f"{new_service['port']}_{new_service['service']}"
                        if service_key not in existing_services:
                            existing_scan['services'].append(new_service)
                        else:
                            # Merge scripts if service already exists
                            existing_service = existing_services[service_key]
                            for script in new_service.get('scripts', []):
                                if script not in existing_service.get('scripts', []):
                                    existing_service.setdefault('scripts', []).append(script)

                    # Update totals
                    existing_scan['total_services'] = len(existing_scan['services'])

                    # Use most recent scan date and filename
                    if scan['scan_date'] > existing_scan['scan_date']:
                        existing_scan['scan_date'] = scan['scan_date']
                        existing_scan['filename'] = scan['filename']
                        existing_scan['download_url'] = scan['download_url']
                        existing_scan['log_url'] = scan['log_url']

                    # Combine scan types if different
                    if scan.get('scan_type') != existing_scan.get('scan_type'):
                        existing_types = existing_scan.get('scan_type', 'nmap').split('+')
                        new_type = scan.get('scan_type', 'nmap')
                        if new_type not in existing_types:
                            existing_types.append(new_type)
                            existing_scan['scan_type'] = '+'.join(sorted(existing_types))

            # Convert back to list and sort by interesting content
            final_scans = list(consolidated_scans.values())
            final_scans.sort(key=lambda x: (
                -x['total_services'],  # Most services first
                -sum(len(svc.get('scripts', [])) for svc in x['services']),  # Most scripts first
                x['scan_date']  # Then by date descending
            ), reverse=False)  # reverse=False because we're using negative values

            return jsonify({
                'scans': final_scans,
                'statistics': stats
            })

        except Exception as e:
            logger.error(f"Error getting vulnerability intelligence: {e}")
            return jsonify({'error': str(e)}), 500


@app.route('/api/logs')
def get_logs():
    """Get recent logs - prioritizing orchestrator.py output"""
    try:
        # Enhanced logging - aggregate from multiple sources
        all_logs = []
        
        # Get terminal log level filter from config - default to 'all' to show orchestrator output
        terminal_log_level = shared_data.config.get('terminal_log_level', 'all')
        
        # 1. PRIORITY: Get orchestrator.py logs (main scanning activity)
        orchestrator_log = os.path.join(shared_data.logsdir, 'orchestrator.py.log')
        if os.path.exists(orchestrator_log):
            with open(orchestrator_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Get last 100 lines of orchestrator logs
                orch_logs = [line.strip() for line in lines[-20:] if line.strip()]
                all_logs.extend(orch_logs)
        
        # 2. Get scanning.py logs (network scanning details)
        scanning_log = os.path.join(shared_data.logsdir, 'scanning.py.log')
        if os.path.exists(scanning_log):
            with open(scanning_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Get last 50 lines of scanning logs
                scan_logs = [line.strip() for line in lines[-10:] if line.strip()]
                all_logs.extend(scan_logs)
        
        # 3. Get nmap_vuln_scanner.py logs (vulnerability scanning)
        vuln_scanner_log = os.path.join(shared_data.logsdir, 'nmap_vuln_scanner.py.log')
        if os.path.exists(vuln_scanner_log):
            with open(vuln_scanner_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Get last 50 lines of vuln scanner logs
                vuln_logs = [line.strip() for line in lines[-10:] if line.strip()]
                all_logs.extend(vuln_logs)
        
        # 2. Get Ragnar main activity logs from data/logs directory
        logs_dir = shared_data.logsdir
        if os.path.exists(logs_dir):
            skip_console_logs = {
                'orchestrator.py.log',
                'scanning.py.log',
                'nmap_vuln_scanner.py.log',
                'comment.py.log'
            }
            # Look for recent log files from attack actions
            for log_filename in os.listdir(logs_dir):
                if log_filename.endswith('.log') or log_filename.endswith('.txt'):
                    # Skip files we've already processed or explicitly excluded
                    if log_filename in skip_console_logs:
                        continue
                    
                    log_path = os.path.join(logs_dir, log_filename)
                    try:
                        # Get file modification time to show recent files first
                        mod_time = os.path.getmtime(log_path)
                        # Only show logs from last 24 hours
                        if time.time() - mod_time < 86400:  # 24 hours
                            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                                recent_lines = [line.strip() for line in lines[-10:] if line.strip()]
                                all_logs.extend(recent_lines)
                    except Exception as e:
                        # Skip files that can't be read
                        continue
        
        noise_filters = (
            'comment.py - INFO - Comments loaded successfully from cache',
        )
        if noise_filters:
            all_logs = [
                log for log in all_logs
                if not any(noise in log for noise in noise_filters)
            ]

        # Sort logs chronologically if they have timestamps
        # Logs are in format: YYYY-MM-DD HH:MM:SS - filename - LEVEL - message
        def extract_timestamp(log_line):
            try:
                # Extract timestamp from log line (first 19 characters: YYYY-MM-DD HH:MM:SS)
                if len(log_line) >= 19 and log_line[4] == '-' and log_line[7] == '-':
                    timestamp_str = log_line[:19]
                    from datetime import datetime
                    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except Exception:
                pass
            return datetime.min
        
        # Sort by timestamp
        try:
            from datetime import datetime
            all_logs.sort(key=extract_timestamp)
        except Exception:
            pass  # If sorting fails, keep original order
        
        # Limit to last 200 entries to avoid overwhelming the UI
        recent_logs = all_logs[-200:] if all_logs else []
        
        return jsonify({'logs': recent_logs})
    except Exception as e:
        logger.error(f"Error getting enhanced logs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs/activity')
def get_activity_logs():
    """Get detailed activity logs showing discoveries, attacks, and results"""
    try:
        activity_logs = []
        current_time = datetime.now()
        
        # 1. Recent network discoveries
        if os.path.exists(shared_data.livestatusfile):
            try:
                import pandas as pd
                df = pd.read_csv(shared_data.livestatusfile)
                alive_hosts = df[df['Alive'] == 1] if 'Alive' in df.columns else df
                for _, row in alive_hosts.tail(15).iterrows():
                    ip = row.get('IP', 'Unknown')
                    hostname = row.get('Hostname', ip)
                    ports = row.get('Ports', '')
                    mac = row.get('MAC', 'Unknown')
                    
                    if ports:
                        port_list = ports.split(';')
                        service_summary = f"{len(port_list)} services"
                        if len(port_list) <= 5:
                            service_summary = f"Ports: {', '.join(port_list)}"
                    else:
                        service_summary = "Host responsive"
                    
                    log_entry = {
                        'timestamp': current_time.strftime("%H:%M:%S"),
                        'type': 'discovery',
                        'icon': '🎯',
                        'message': f"Discovered {hostname} ({ip})",
                        'details': f"MAC: {mac} | {service_summary}",
                        'severity': 'info'
                    }
                    activity_logs.append(log_entry)
            except Exception as e:
                activity_logs.append({
                    'timestamp': current_time.strftime("%H:%M:%S"),
                    'type': 'error',
                    'icon': '❌',
                    'message': f"Error reading discoveries: {str(e)}",
                    'details': '',
                    'severity': 'error'
                })
        
        # 2. Recent credential findings
        cred_sources = [
            (shared_data.sshfile, 'SSH', '🔐'),
            (shared_data.smbfile, 'SMB', '📁'),
            (shared_data.ftpfile, 'FTP', '📂'),
            (shared_data.telnetfile, 'Telnet', '💻'),
            (shared_data.sqlfile, 'SQL', '🗄️'),
            (shared_data.rdpfile, 'RDP', '🖥️')
        ]
        
        for cred_file, service, icon in cred_sources:
            if os.path.exists(cred_file):
                try:
                    import pandas as pd
                    df = pd.read_csv(cred_file)
                    if not df.empty:
                        recent_creds = df.tail(5)
                        for _, row in recent_creds.iterrows():
                            ip = row.get('ip', row.get('IP', 'Unknown'))
                            username = row.get('username', row.get('Username', 'Unknown'))
                            password = row.get('password', row.get('Password', '***'))
                            port = row.get('port', row.get('Port', ''))
                            
                            port_info = f":{port}" if port else ""
                            log_entry = {
                                'timestamp': current_time.strftime("%H:%M:%S"),
                                'type': 'credential',
                                'icon': icon,
                                'message': f"{service} access gained on {ip}{port_info}",
                                'details': f"Username: {username} | Password: {'*' * min(len(str(password)), 8)}",
                                'severity': 'success'
                            }
                            activity_logs.append(log_entry)
                except Exception:
                    continue
        
        # 3. Recent vulnerability findings
        vuln_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
        if os.path.exists(vuln_dir):
            vuln_files = [f for f in os.listdir(vuln_dir) if f.endswith('.txt')]
            vuln_files.sort(key=lambda x: os.path.getmtime(os.path.join(vuln_dir, x)), reverse=True)
            
            for vuln_file in vuln_files[:5]:
                try:
                    vuln_path = os.path.join(vuln_dir, vuln_file)
                    with open(vuln_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    ip = vuln_file.replace('.txt', '').replace('vuln_', '')
                    vuln_count = content.upper().count('VULNERABLE')
                    cve_count = content.count('CVE-')
                    
                    if vuln_count > 0 or cve_count > 0:
                        severity_icon = '🚨' if vuln_count > 5 else '⚠️'
                        severity = 'critical' if vuln_count > 5 else 'warning'
                        
                        details = []
                        if vuln_count > 0:
                            details.append(f"{vuln_count} vulnerabilities")
                        if cve_count > 0:
                            details.append(f"{cve_count} CVEs")
                        
                        log_entry = {
                            'timestamp': current_time.strftime("%H:%M:%S"),
                            'type': 'vulnerability',
                            'icon': severity_icon,
                            'message': f"Vulnerabilities found on {ip}",
                            'details': " | ".join(details),
                            'severity': severity
                        }
                        activity_logs.append(log_entry)
                except Exception:
                    continue
        
        # 4. Current system status
        status_entries = []
        if safe_str(shared_data.ragnarstatustext) and safe_str(shared_data.ragnarstatustext) != "Idle":
            status_entries.append({
                'timestamp': current_time.strftime("%H:%M:%S"),
                'type': 'status',
                'icon': '🤖',
                'message': f"Ragnar: {safe_str(shared_data.ragnarstatustext)}",
                'details': safe_str(shared_data.ragnarstatustext2) if safe_str(shared_data.ragnarstatustext2) else '',
                'severity': 'info'
            })
        
        if safe_str(shared_data.ragnarsays) and safe_str(shared_data.ragnarsays).strip():
            status_entries.append({
                'timestamp': current_time.strftime("%H:%M:%S"),
                'type': 'activity',
                'icon': '⚡',
                'message': safe_str(shared_data.ragnarsays),
                'details': '',
                'severity': 'info'
            })
        
        activity_logs.extend(status_entries)
        
        # Sort by timestamp and limit to 50 most recent entries
        activity_logs = activity_logs[-50:]
        
        return jsonify({'activity_logs': activity_logs})
        
    except Exception as e:
        logger.error(f"Error getting activity logs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/attack', methods=['GET', 'POST'])
def attack_logs():
    """
    Attack logs endpoint - Log and retrieve attack action outputs
    
    GET: Retrieve attack logs (optionally filtered by IP, action type, or timeframe)
    POST: Log a new attack output
    """
    if request.method == 'POST':
        try:
            # Log a new attack output
            data = request.get_json()
            
            # Extract attack details
            attack_type = data.get('attack_type', 'Unknown')
            target_ip = data.get('target_ip', 'Unknown')
            target_port = data.get('target_port', '')
            status = data.get('status', 'unknown')  # success, failed, timeout
            message = data.get('message', '')
            details = data.get('details', {})
            timestamp = data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            # Create attack log directory if it doesn't exist
            attack_log_dir = os.path.join(shared_data.logsdir, 'attacks')
            os.makedirs(attack_log_dir, exist_ok=True)
            
            # Create attack log file (one per day)
            log_date = datetime.now().strftime('%Y-%m-%d')
            attack_log_file = os.path.join(attack_log_dir, f'attacks_{log_date}.json')
            
            # Prepare log entry
            log_entry = {
                'timestamp': timestamp,
                'attack_type': attack_type,
                'target_ip': target_ip,
                'target_port': target_port,
                'status': status,
                'message': message,
                'details': details,
                'network_ssid': getattr(shared_data, 'active_network_ssid', None) or 'unknown'
            }
            
            # Load existing logs or create new list
            if os.path.exists(attack_log_file):
                try:
                    with open(attack_log_file, 'r', encoding='utf-8') as f:
                        attack_logs = json.load(f)
                except json.JSONDecodeError:
                    attack_logs = []
            else:
                attack_logs = []
            
            # Append new log entry
            attack_logs.append(log_entry)
            
            # Save updated logs
            with open(attack_log_file, 'w', encoding='utf-8') as f:
                json.dump(attack_logs, f, indent=2)
            
            # Also log to main logger for debugging
            logger.info(f"Attack logged: {attack_type} on {target_ip}:{target_port} - {status}")
            
            return jsonify({
                'success': True,
                'message': 'Attack output logged successfully',
                'log_entry': log_entry
            }), 201
            
        except Exception as e:
            logger.error(f"Error logging attack output: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    else:  # GET request
        try:
            # Retrieve attack logs with optional filtering
            ip_filter = request.args.get('ip', None)
            attack_type_filter = request.args.get('type', None)
            status_filter = request.args.get('status', None)
            network_filter = request.args.get('network', None)
            limit = int(request.args.get('limit', 100))
            days_back = int(request.args.get('days', 7))
            
            attack_log_dir = os.path.join(shared_data.logsdir, 'attacks')

            if not os.path.exists(attack_log_dir):
                return jsonify({
                    'attack_logs': [],
                    'total_count': 0,
                    'message': 'No attack logs found'
                })

            # Collect logs from recent days
            all_logs = []
            latest_log_time_all = None
            cutoff_date = datetime.now() - timedelta(days=days_back)

            for log_file in os.listdir(attack_log_dir):
                if not log_file.startswith('attacks_') or not log_file.endswith('.json'):
                    continue
                
                # Check if log file is within date range
                try:
                    file_date_str = log_file.replace('attacks_', '').replace('.json', '')
                    file_date = datetime.strptime(file_date_str, '%Y-%m-%d')
                    
                    if file_date < cutoff_date:
                        continue
                except Exception:
                    continue
                
                log_path = os.path.join(attack_log_dir, log_file)
                try:
                    with open(log_path, 'r', encoding='utf-8') as f:
                        logs = json.load(f)
                        all_logs.extend(logs)

                        for entry in logs:
                            parsed_time = _parse_attack_timestamp(entry.get('timestamp'))
                            if parsed_time and (latest_log_time_all is None or parsed_time > latest_log_time_all):
                                latest_log_time_all = parsed_time
                except Exception as e:
                    logger.error(f"Error reading attack log file {log_file}: {e}")
                    continue

            # Collect all unique network SSIDs across all logs (before filtering)
            available_networks = sorted(set(
                log.get('network_ssid') or 'unknown'
                for log in all_logs
            ))

            # Apply filters
            filtered_logs = all_logs

            if ip_filter:
                filtered_logs = [log for log in filtered_logs if log.get('target_ip') == ip_filter]

            if attack_type_filter:
                filtered_logs = [log for log in filtered_logs if log.get('attack_type') == attack_type_filter]

            if status_filter:
                filtered_logs = [log for log in filtered_logs if log.get('status') == status_filter]

            if network_filter:
                filtered_logs = [log for log in filtered_logs if (log.get('network_ssid') or 'unknown') == network_filter]

            # Sort by timestamp (most recent first)
            filtered_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

            # Apply limit
            filtered_logs = filtered_logs[:limit]

            # Generate summary statistics
            total_count = len(all_logs)
            filtered_count = len(filtered_logs)
            success_count = len([log for log in filtered_logs if log.get('status') == 'success'])
            failed_count = len([log for log in filtered_logs if log.get('status') == 'failed'])

            filtered_latest = None
            for entry in filtered_logs:
                parsed_time = _parse_attack_timestamp(entry.get('timestamp'))
                if parsed_time and (filtered_latest is None or parsed_time > filtered_latest):
                    filtered_latest = parsed_time

            response_payload = {
                'attack_logs': filtered_logs,
                'total_count': total_count,
                'filtered_count': filtered_count,
                'success_count': success_count,
                'failed_count': failed_count,
                'available_networks': available_networks,
                'filters_applied': {
                    'ip': ip_filter,
                    'type': attack_type_filter,
                    'status': status_filter,
                    'network': network_filter,
                    'days': days_back,
                    'limit': limit
                }
            }

            etag_source = json.dumps({
                'attack_logs': filtered_logs,
                'total_count': total_count,
                'filtered_count': filtered_count,
                'success_count': success_count,
                'failed_count': failed_count
            }, sort_keys=True).encode('utf-8')

            etag_value = f'W/"attack-{hashlib.md5(etag_source).hexdigest()}"'

            last_modified_dt = filtered_latest or latest_log_time_all
            if last_modified_dt and last_modified_dt.tzinfo is None:
                last_modified_dt = last_modified_dt.replace(tzinfo=timezone.utc)

            if_none_match = request.headers.get('If-None-Match', '')
            if if_none_match:
                etag_matches = [tag.strip() for tag in if_none_match.split(',') if tag.strip()]
                if etag_value in etag_matches:
                    response = make_response('', 304)
                    response.headers['ETag'] = etag_value
                    response.headers['Cache-Control'] = 'no-cache'
                    if last_modified_dt:
                        response.headers['Last-Modified'] = format_datetime(last_modified_dt.astimezone(timezone.utc), usegmt=True)
                    return response

            response = jsonify(response_payload)
            response.headers['ETag'] = etag_value
            response.headers['Cache-Control'] = 'no-cache'
            if last_modified_dt:
                response.headers['Last-Modified'] = format_datetime(last_modified_dt.astimezone(timezone.utc), usegmt=True)

            return response

        except Exception as e:
            logger.error(f"Error retrieving attack logs: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


@app.route('/api/debug/verbose-logs')
def get_verbose_debug_logs():
    """Get super verbose debugging logs for tracing data flow issues"""
    try:
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'system_state': {},
            'data_sources': {},
            'cache_state': {},
            'sync_information': {},
            'file_operations': {},
            'api_traces': [],
            'errors_and_warnings': []
        }
        
        # === SYSTEM STATE DEBUGGING ===
        debug_info['system_state'] = {
            'shared_data_targetnbr': getattr(shared_data, 'targetnbr', 'NOT_SET'),
            'shared_data_total_targetnbr': getattr(shared_data, 'total_targetnbr', 'NOT_SET'),
            'shared_data_inactive_targetnbr': getattr(shared_data, 'inactive_targetnbr', 'NOT_SET'),
            'shared_data_portnbr': getattr(shared_data, 'portnbr', 'NOT_SET'),
            'shared_data_vulnnbr': getattr(shared_data, 'vulnnbr', 'NOT_SET'),
            'shared_data_crednbr': getattr(shared_data, 'crednbr', 'NOT_SET'),
            'shared_data_levelnbr': getattr(shared_data, 'levelnbr', 'NOT_SET'),
            'shared_data_coinnbr': getattr(shared_data, 'coinnbr', 'NOT_SET'),
        }
        
        # === DATA SOURCES DEBUGGING ===
        try:
            # WiFi network data
            wifi_network_file = get_wifi_specific_network_file()
            debug_info['data_sources']['wifi_network_file'] = {
                'path': wifi_network_file,
                'exists': os.path.exists(wifi_network_file),
                'size_bytes': os.path.getsize(wifi_network_file) if os.path.exists(wifi_network_file) else 0,
                'modified_time': datetime.fromtimestamp(os.path.getmtime(wifi_network_file)).isoformat() if os.path.exists(wifi_network_file) else 'N/A'
            }
            
            # Read and analyze wifi network data
            network_data = read_wifi_network_data()
            debug_info['data_sources']['wifi_network_data'] = {
                'total_entries': len(network_data),
                'alive_entries': len([entry for entry in network_data if entry.get('Alive') in [True, 'True', '1', 1]]),
                'sample_entries': network_data[:3] if network_data else [],
                'all_alive_values': list(set([str(entry.get('Alive', 'MISSING')) for entry in network_data])),
                'ip_list': [entry.get('IPs', 'NO_IP') for entry in network_data[:10]]
            }
            
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error reading WiFi network data: {str(e)}")
        
        try:
            # NetKB data
            netkb_data = shared_data.read_data()
            netkb_file_path = getattr(shared_data, 'netkbfile', 'NOT_SET')
            debug_info['data_sources']['netkb_data'] = {
                'total_entries': len(netkb_data),
                'alive_entries': len([entry for entry in netkb_data if entry.get('Alive') in ['1', 1]]),
                'sample_entries': netkb_data[:3] if netkb_data else [],
                'all_alive_values': list(set([str(entry.get('Alive', 'MISSING')) for entry in netkb_data])),
                'file_path': netkb_file_path,
                'file_exists': os.path.exists(netkb_file_path) if netkb_file_path != 'NOT_SET' else False
            }
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error reading NetKB data: {str(e)}")
        
        # === CACHE STATE DEBUGGING ===
        debug_info['cache_state'] = {
            'network_scan_cache_keys': list(network_scan_cache.keys()),
            'arp_hosts_count': len(network_scan_cache.get('arp_hosts', {})),
            'arp_hosts_sample': dict(list(network_scan_cache.get('arp_hosts', {}).items())[:5]),
            'last_arp_scan_time': network_scan_cache.get('last_arp_scan', 'NEVER'),
            'cache_size': len(str(network_scan_cache)),
            'network_scan_last_update': network_scan_last_update,
            'arp_scan_interval': ARP_SCAN_INTERVAL,
            'current_time': time.time(),
            'time_since_last_cache_update': time.time() - network_scan_last_update if network_scan_last_update else 'NEVER'
        }
        
        # Test ARP scan directly
        try:
            debug_info['api_traces'].append("=== TESTING ARP SCAN DIRECTLY ===")
            test_arp_result = run_arp_scan_localnet('wlan0')
            debug_info['cache_state']['direct_arp_test'] = {
                'success': bool(test_arp_result),
                'host_count': len(test_arp_result) if test_arp_result else 0,
                'sample_results': dict(list(test_arp_result.items())[:3]) if test_arp_result else {}
            }
            debug_info['api_traces'].append(f"Direct ARP test found {len(test_arp_result) if test_arp_result else 0} hosts")
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error testing ARP scan directly: {str(e)}")
            debug_info['cache_state']['direct_arp_test'] = {'error': str(e)}
        
        # === SYNC INFORMATION ===
        debug_info['sync_information'] = {
            'last_sync_time': getattr(shared_data, 'last_sync_timestamp', 'NOT_SET'),
            'sync_lock_acquired': sync_lock.locked() if sync_lock else 'NO_LOCK',
            'sync_background_interval': SYNC_BACKGROUND_INTERVAL,
            'current_time': time.time(),
            'time_since_last_sync': time.time() - getattr(shared_data, 'last_sync_timestamp', 0) if hasattr(shared_data, 'last_sync_timestamp') else 'UNKNOWN'
        }
        
        # === BACKGROUND THREAD HEALTH ===
        debug_info['background_thread_health'] = {
            'sync_thread': {
                'last_run': background_thread_health.get('sync_last_run', 0),
                'last_run_ago_seconds': time.time() - background_thread_health.get('sync_last_run', 0) if background_thread_health.get('sync_last_run', 0) > 0 else 'NEVER',
                'alive': background_thread_health.get('sync_alive', False),
                'status': '✅ HEALTHY' if background_thread_health.get('sync_alive', False) else '⚠️ POSSIBLY STUCK'
            },
            'arp_thread': {
                'last_run': background_thread_health.get('arp_last_run', 0),
                'last_run_ago_seconds': time.time() - background_thread_health.get('arp_last_run', 0) if background_thread_health.get('arp_last_run', 0) > 0 else 'NEVER',
                'alive': background_thread_health.get('arp_alive', False),
                'status': '✅ HEALTHY' if background_thread_health.get('arp_alive', False) else '⚠️ POSSIBLY STUCK'
            },
            'health_monitor': {
                'enabled': True,
                'check_interval_seconds': 15
            }
        }
        
        # === FILE OPERATIONS DEBUGGING ===
        try:
            # Check key files
            important_files = [
                getattr(shared_data, 'network_file', 'NOT_SET'),
                shared_data.webconsolelog if hasattr(shared_data, 'webconsolelog') else 'NOT_SET',
                get_wifi_specific_network_file()
            ]
            
            debug_info['file_operations'] = {}
            for file_path in important_files:
                if file_path != 'NOT_SET' and file_path:
                    try:
                        debug_info['file_operations'][file_path] = {
                            'exists': os.path.exists(file_path),
                            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                            'readable': os.access(file_path, os.R_OK) if os.path.exists(file_path) else False,
                            'writable': os.access(file_path, os.W_OK) if os.path.exists(file_path) else False,
                            'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat() if os.path.exists(file_path) else 'N/A'
                        }
                    except Exception as e:
                        debug_info['file_operations'][file_path] = {'error': str(e)}
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error checking file operations: {str(e)}")
        
        # === API TRACES ===
        # Simulate the dashboard stats calculation to trace the issue
        try:
            debug_info['api_traces'].append("=== DASHBOARD STATS CALCULATION TRACE ===")
            
            # Step 1: Read network data
            network_data = read_wifi_network_data()
            debug_info['api_traces'].append(f"Step 1: Read {len(network_data)} entries from WiFi network file")
            
            # Step 2: Get ARP cache
            recent_arp_data = network_scan_cache.get('arp_hosts', {})
            debug_info['api_traces'].append(f"Step 2: Found {len(recent_arp_data)} entries in ARP cache")
            
            # Step 3: Process network data
            processed_ips = set()
            active_hosts_count = 0
            
            for i, entry in enumerate(network_data[:5]):  # Trace first 5 entries
                ip = entry.get('IPs', '').strip()
                alive_status = entry.get('Alive')
                is_in_arp = ip in recent_arp_data
                debug_info['api_traces'].append(f"Entry {i}: IP={ip}, Alive={alive_status} (type: {type(alive_status)}), InARP={is_in_arp}")
                
                if ip and ip not in processed_ips:
                    processed_ips.add(ip)
                    is_alive_in_file = alive_status in [True, 'True', '1', 1]
                    is_alive_in_arp = ip in recent_arp_data
                    is_alive = is_alive_in_file or is_alive_in_arp
                    debug_info['api_traces'].append(f"  -> IP {ip} processed, alive_file={is_alive_in_file}, alive_arp={is_alive_in_arp}, final_alive={is_alive}")
                    if is_alive:
                        active_hosts_count += 1
                        debug_info['api_traces'].append(f"  -> Active count increased to {active_hosts_count}")
            
            # Step 4: Process ARP data
            for ip in list(recent_arp_data.keys())[:5]:  # Trace first 5 ARP entries
                if ip not in processed_ips:
                    processed_ips.add(ip)
                    active_hosts_count += 1
                    debug_info['api_traces'].append(f"ARP: Added {ip} as active (count: {active_hosts_count})")
            
            debug_info['api_traces'].append(f"FINAL COUNTS: Active={active_hosts_count}, Total={len(processed_ips)}")
            
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error in API trace: {str(e)}")
        
        # === RECENT LOG ENTRIES ===
        try:
            log_file = shared_data.webconsolelog if hasattr(shared_data, 'webconsolelog') else None
            if log_file and os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    recent_lines = f.readlines()[-20:]  # Last 20 log lines
                    debug_info['recent_logs'] = recent_lines
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error reading recent logs: {str(e)}")
        
        # === THREAT INTELLIGENCE STATUS ===
        try:
            debug_info['threat_intelligence'] = {
                'system_enabled': threat_intelligence is not None,
                'vulnerability_count': safe_int(shared_data.vulnnbr),
                'findings_need_vulnerabilities': 'Threat Intelligence needs discovered vulnerabilities to enrich',
                'manual_scan_available': True,
                'sample_enrichment_test': 'Try: POST /api/threat-intelligence/enrich-target with {"target": "192.168.1.1", "target_type": "ip"}'
            }
            
            if threat_intelligence:
                # Test threat intelligence status
                ti_status = {
                    'cache_entries': len(getattr(threat_intelligence, 'threat_cache', {})),
                    'sources_count': len(getattr(threat_intelligence, 'sources', [])),
                    'last_update': getattr(threat_intelligence, 'last_update', 'Never')
                }
                debug_info['threat_intelligence']['system_status'] = ti_status
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error checking threat intelligence: {str(e)}")
        
        # Force fresh timestamp and prevent caching
        debug_info['timestamp'] = datetime.now().isoformat()
        debug_info['generated_at'] = time.time()
        
        response = jsonify(debug_info)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"Error in verbose debug logs: {e}")
        return jsonify({'error': str(e), 'timestamp': datetime.now().isoformat()}), 500

@app.route('/api/debug/test-robust-tracking')
def test_robust_tracking():
    """Test endpoint to verify robust tracking logic is working"""
    try:
        logger.info("[TEST] Robust tracking test endpoint called")
        
        # Test the network data reading with new logic
        network_data = read_wifi_network_data()
        
        # Count devices by failure status
        max_failed_pings = shared_data.config.get('network_max_failed_pings', 15)  # Changed to 15 for more stability
        results = {
            'total_devices': len(network_data),
            'devices_with_failure_data': 0,
            'devices_exceeding_failure_limit': 0,
            'devices_active_by_robust_rule': 0,
            'max_failed_pings_threshold': max_failed_pings,
            'sample_devices': [],
            'test_timestamp': datetime.now().isoformat()
        }
        
        for entry in network_data[:5]:  # Sample first 5
            ip = entry.get('IPs', '')
            failed_ping_count = entry.get('FailedPingCount', 'N/A')
            alive_status = entry.get('Alive', 'N/A')
            
            if isinstance(failed_ping_count, int):
                results['devices_with_failure_data'] += 1
                if failed_ping_count >= max_failed_pings:
                    results['devices_exceeding_failure_limit'] += 1
                else:
                    results['devices_active_by_robust_rule'] += 1
            
            results['sample_devices'].append({
                'ip': ip,
                'failed_ping_count': failed_ping_count,
                'alive': alive_status,
                'would_be_removed': failed_ping_count >= max_failed_pings if isinstance(failed_ping_count, int) else False
            })
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error in robust tracking test: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/debug/orchestrator-status')
def get_orchestrator_diagnostic():
    """Comprehensive orchestrator diagnostic endpoint"""
    try:
        diagnostic = {
            'timestamp': datetime.now().isoformat(),
            'orchestrator_status': safe_str(shared_data.ragnarorch_status),
            'orchestrator_status2': safe_str(shared_data.ragnarstatustext2),
            'manual_mode': shared_data.config.get('manual_mode', False),
            'manual_mode_reason': 'Manual mode is ENABLED - orchestrator will not run automatic attacks' if shared_data.config.get('manual_mode', False) else 'Manual mode is DISABLED - orchestrator should run attacks',
            'wifi_connected': getattr(shared_data, 'wifi_connected', False),
            'orchestrator_should_exit': getattr(shared_data, 'orchestrator_should_exit', True),
            
            # Configuration checks
            'config': {
                'scan_vuln_running': shared_data.config.get('scan_vuln_running', True),
                'enable_attacks': shared_data.config.get('enable_attacks', True),
                'retry_success_actions': shared_data.config.get('retry_success_actions', True),
                'retry_failed_actions': shared_data.config.get('retry_failed_actions', True),
                'success_retry_delay': shared_data.config.get('success_retry_delay', 300),
                'failed_retry_delay': shared_data.config.get('failed_retry_delay', 180),
                'scan_interval': shared_data.config.get('scan_interval', 180),
                'scan_vuln_interval': shared_data.config.get('scan_vuln_interval', 300),
            },
            
            # Target information
            'targets': {
                'total_count': 0,
                'alive_count': 0,
                'alive_hosts': []
            },
            
            # Actions status
            'actions_available': False,
            'actions_pending': False,
            
            # Diagnosis
            'diagnosis': [],
            'recommendations': []
        }
        
        # Check netkb for targets
        try:
            if os.path.exists(shared_data.netkbfile):
                with open(shared_data.netkbfile, 'r') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                    diagnostic['targets']['total_count'] = len(rows)
                    
                    for row in rows:
                        if row.get('Alive') == '1':
                            diagnostic['targets']['alive_count'] += 1
                            ip = row.get('IPs', '')
                            hostname = row.get('Hostnames', '')
                            ports = row.get('Ports', '')
                            diagnostic['targets']['alive_hosts'].append({
                                'ip': ip,
                                'hostname': hostname,
                                'ports': ports,
                                'mac': row.get('MAC Address', '')
                            })
        except Exception as e:
            diagnostic['targets']['error'] = str(e)
        
        # Diagnose issues
        if diagnostic['manual_mode']:
            diagnostic['diagnosis'].append('🔴 MANUAL MODE IS ENABLED - This is why Ragnar is not performing attacks!')
            diagnostic['recommendations'].append('Disable manual mode in the Config tab to allow automatic attacks')
        
        if not diagnostic['wifi_connected']:
            diagnostic['diagnosis'].append('🔴 Wi-Fi is not connected')
            diagnostic['recommendations'].append('Connect to Wi-Fi to enable network scanning and attacks')
        
        if diagnostic['orchestrator_should_exit']:
            diagnostic['diagnosis'].append('🔴 Orchestrator exit flag is set')
            diagnostic['recommendations'].append('Restart the Ragnar service to clear the exit flag')
        
        if diagnostic['targets']['alive_count'] == 0:
            diagnostic['diagnosis'].append('⚠️ No alive targets found on the network')
            diagnostic['recommendations'].append('Wait for network scan to complete or manually trigger a scan')
            diagnostic['recommendations'].append('Check if you are connected to the correct network')
        else:
            diagnostic['diagnosis'].append(f'✅ Found {diagnostic["targets"]["alive_count"]} alive targets')
        
        if not diagnostic['config']['scan_vuln_running']:
            diagnostic['diagnosis'].append('⚠️ Vulnerability scanning is disabled')
            diagnostic['recommendations'].append('Enable vulnerability scanning in Config tab')
        
        if not diagnostic['config']['enable_attacks']:
            diagnostic['diagnosis'].append('⚠️ Attacks are disabled - Ragnar will only scan, not attack')
            diagnostic['recommendations'].append('Enable attacks in Config tab to allow SSH/FTP/SMB/SQL attacks')
        
        # Check if actions are available
        try:
            if os.path.exists(shared_data.actions_file):
                with open(shared_data.actions_file, 'r') as f:
                    actions_config = json.load(f)
                    diagnostic['actions_available'] = len(actions_config) > 0
                    diagnostic['actions_count'] = len(actions_config)
                    if not diagnostic['actions_available']:
                        diagnostic['diagnosis'].append('🔴 No actions configured in actions.json')
                        diagnostic['recommendations'].append('Check actions.json file for valid action configurations')
            else:
                diagnostic['diagnosis'].append('🔴 actions.json file not found')
                diagnostic['recommendations'].append('Restore actions.json file to enable attacks')
        except Exception as e:
            diagnostic['diagnosis'].append(f'🔴 Error loading actions: {str(e)}')
        
        # Summary
        if not diagnostic['diagnosis']:
            diagnostic['diagnosis'].append('✅ All systems appear normal')
            if diagnostic['targets']['alive_count'] > 0:
                diagnostic['diagnosis'].append(f'⚙️ Orchestrator should be running attacks on {diagnostic["targets"]["alive_count"]} targets')
            else:
                diagnostic['diagnosis'].append('⚙️ Waiting for network scan to discover targets')
        
        return jsonify(diagnostic)
        
    except Exception as e:
        logger.error(f"Error in orchestrator diagnostic: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/debug/connectivity-tracking')
def get_connectivity_tracking():
    """Get detailed connectivity tracking information for all devices"""
    try:
        wifi_network_data = read_wifi_network_data()
        current_time = datetime.now()
        arp_hosts = network_scan_cache.get('arp_hosts', {})
        
        connectivity_info = {
            'timestamp': current_time.isoformat(),
            'summary': {
                'total_devices': len(wifi_network_data),
                'devices_in_arp': len(arp_hosts),
                'max_failed_pings': shared_data.config.get('network_max_failed_pings', 15)  # Changed to 15 for more stability
            },
            'devices': []
        }
        
        for entry in wifi_network_data:
            ip = entry.get('IPs', '').strip()
            if not ip:
                continue
                
            device_info = {
                'ip': ip,
                'hostname': entry.get('Hostnames', ''),
                'mac': entry.get('MAC Address', ''),
                'alive': entry.get('Alive', 0),
                'failed_ping_count': entry.get('failed_ping_count', 0),
                'last_seen': entry.get('LastSeen', ''),
                'last_successful_ping': entry.get('last_successful_ping', ''),
                'last_ping_attempt': entry.get('last_ping_attempt', ''),
                'in_current_arp': ip in arp_hosts,
                'connectivity_status': 'stable' if entry.get('failed_ping_count', 0) == 0 else f"failing ({entry.get('failed_ping_count', 0)}/{shared_data.config.get('network_max_failed_pings', 15)})"  # Changed to 15
            }
            
            # Calculate time since last successful ping
            if device_info['last_successful_ping']:
                try:
                    last_success = datetime.fromisoformat(device_info['last_successful_ping'])
                    time_diff = current_time - last_success
                    device_info['minutes_since_last_success'] = int(time_diff.total_seconds() / 60)
                except Exception:
                    device_info['minutes_since_last_success'] = 'unknown'
            else:
                device_info['minutes_since_last_success'] = 'never'
                
            connectivity_info['devices'].append(device_info)
        
        # Sort by IP address
        connectivity_info['devices'].sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
        
        response = jsonify(connectivity_info)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"Error getting connectivity tracking info: {e}")
        return jsonify({'error': str(e), 'timestamp': datetime.now().isoformat()}), 500

@app.route('/api/debug/ai-service')
def get_ai_service_diagnostic():
    """Detailed AI service diagnostic information"""
    try:
        import traceback
        diagnostic = {
            'timestamp': datetime.now().isoformat(),
            'ai_service_exists': hasattr(shared_data, 'ai_service'),
            'ai_service_is_none': getattr(shared_data, 'ai_service', 'MISSING') is None,
            'config_ai_enabled': shared_data.config.get('ai_enabled', False),
            'env_file_exists': os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')),
        }
        
        # Try to get token from env
        try:
            from env_manager import EnvManager
            env_mgr = EnvManager()
            token = env_mgr.get_token()
            diagnostic['env_token_found'] = bool(token)
            diagnostic['env_token_preview'] = f"{token[:8]}...{token[-4:]}" if token and len(token) > 12 else None
        except Exception as e:
            diagnostic['env_manager_error'] = str(e)
            diagnostic['env_manager_traceback'] = traceback.format_exc()
        
        # Check AI service object
        ai_service = getattr(shared_data, 'ai_service', None)
        if ai_service:
            diagnostic['ai_service_details'] = {
                'enabled': getattr(ai_service, 'enabled', None),
                'model': getattr(ai_service, 'model', None),
                'api_token_set': bool(getattr(ai_service, 'api_token', None)),
                'client_exists': getattr(ai_service, 'client', None) is not None,
                'initialization_error': getattr(ai_service, 'initialization_error', None),
                'is_enabled_result': ai_service.is_enabled() if hasattr(ai_service, 'is_enabled') else 'NO_METHOD'
            }
        else:
            diagnostic['ai_service_details'] = 'SERVICE_IS_NONE'
            
            # Try to initialize it now
            diagnostic['initialization_attempt'] = {}
            try:
                diagnostic['initialization_attempt']['status'] = 'attempting'
                shared_data.initialize_ai_service()
                ai_service = getattr(shared_data, 'ai_service', None)
                if ai_service:
                    diagnostic['initialization_attempt']['status'] = 'success'
                    diagnostic['ai_service_details'] = {
                        'enabled': getattr(ai_service, 'enabled', None),
                        'model': getattr(ai_service, 'model', None),
                        'api_token_set': bool(getattr(ai_service, 'api_token', None)),
                        'client_exists': getattr(ai_service, 'client', None) is not None,
                        'initialization_error': getattr(ai_service, 'initialization_error', None),
                    }
                else:
                    diagnostic['initialization_attempt']['status'] = 'failed_still_none'
            except Exception as e:
                diagnostic['initialization_attempt']['status'] = 'exception'
                diagnostic['initialization_attempt']['error'] = str(e)
                diagnostic['initialization_attempt']['traceback'] = traceback.format_exc()
        
        # Try importing the module directly
        try:
            from ai_service import AIService
            diagnostic['ai_service_import'] = 'success'
        except Exception as e:
            diagnostic['ai_service_import'] = 'failed'
            diagnostic['ai_service_import_error'] = str(e)
            diagnostic['ai_service_import_traceback'] = traceback.format_exc()
        
        return jsonify(diagnostic)
        
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc(),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/debug/force-arp-scan', methods=['POST'])
def force_arp_scan():
    """Force an ARP scan and update the cache manually for debugging"""
    try:
        global network_scan_cache, network_scan_last_update
        
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'force_arp_scan',
            'steps': []
        }
        
        debug_info['steps'].append("Step 1: Running ARP scan...")
        arp_hosts = run_arp_scan_localnet('wlan0')
        debug_info['steps'].append(f"Step 2: Found {len(arp_hosts) if arp_hosts else 0} hosts")
        
        if arp_hosts:
            debug_info['steps'].append("Step 3: Updating cache...")
            current_time = time.time()
            network_scan_cache['arp_hosts'] = arp_hosts
            network_scan_cache['last_arp_scan'] = current_time
            network_scan_last_update = current_time
            debug_info['steps'].append("Step 4: Cache updated successfully")
            
            debug_info['steps'].append("Step 5: Updating NetKB entries...")
            for ip, data in arp_hosts.items():
                update_netkb_entry(ip, data.get('hostname', ''), data.get('mac', ''), True)
            debug_info['steps'].append(f"Step 6: Updated {len(arp_hosts)} NetKB entries")
            
            debug_info['results'] = {
                'cache_updated': True,
                'hosts_found': arp_hosts,
                'cache_state': {
                    'arp_hosts_count': len(network_scan_cache.get('arp_hosts', {})),
                    'last_arp_scan_time': network_scan_cache.get('last_arp_scan', 'NEVER')
                }
            }
        else:
            debug_info['steps'].append("Step 3: No hosts found, cache not updated")
            debug_info['results'] = {
                'cache_updated': False,
                'hosts_found': {},
                'error': 'No hosts discovered'
            }
        
        return jsonify(debug_info)
        
    except Exception as e:
        logger.error(f"Error in force ARP scan: {e}")
        return jsonify({'error': str(e), 'timestamp': datetime.now().isoformat()}), 500

@app.route('/api/threat-intelligence/trigger-vuln-scan', methods=['POST'])
def trigger_vulnerability_scan_for_threat_intel():
    """Trigger vulnerability scanning to generate data for threat intelligence enrichment"""
    with _network_context_from_request():
        try:
            # Get the request data
            data = request.get_json() if request.is_json else {}
            target = data.get('target', 'all')
            
            # Get discovered hosts count for feedback
            network_data = read_wifi_network_data()
            recent_arp_data = network_scan_cache.get('arp_hosts', {})
            total_hosts = len(set([entry.get('IPs', '') for entry in network_data if entry.get('IPs')] + list(recent_arp_data.keys())))
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'action': 'vulnerability_scan_triggered',
                'target': target,
                'discovered_hosts': total_hosts,
                'message': f'Vulnerability scan initiated for {total_hosts} discovered hosts',
                'next_steps': [
                    'Vulnerability scanning is running in the background',
                    'Results will appear in the Network tab when complete',
                    'Threat intelligence will enrich any discovered vulnerabilities',
                    'Check back in 2-5 minutes for results'
                ]
            }
            
            # Trigger the actual vulnerability scan by calling the existing endpoint
            try:
                from urllib.parse import urljoin
                import requests
                base_url = request.host_url
                scan_url = urljoin(base_url, '/api/manual/scan/vulnerability')
                
                scan_response = requests.post(
                    scan_url,
                    json={'target': target},
                    timeout=5
                )
                
                if scan_response.status_code == 200:
                    result['scan_status'] = 'success'
                    result['scan_response'] = scan_response.json()
                else:
                    result['scan_status'] = 'warning'
                    result['scan_response'] = f'Scan request returned status {scan_response.status_code}'
                    
            except Exception as scan_error:
                result['scan_status'] = 'initiated'
                result['scan_note'] = 'Vulnerability scan triggered via orchestrator'
                logger.info(f"Vulnerability scan trigger: {str(scan_error)}")
                
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"Error triggering vulnerability scan for threat intel: {e}")
            return jsonify({
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'suggestion': 'Try using the Manual mode to trigger vulnerability scans'
            }), 500

@app.route('/api/vulnerability-scan/history', methods=['GET'])
def get_vulnerability_scan_history():
    """Get incremental scan history statistics"""
    try:
        # Access the nmap_vuln_scanner from shared_data
        vuln_scanner = getattr(shared_data, 'nmap_vuln_scanner', None)
        
        if not vuln_scanner:
            return jsonify({
                'error': 'Vulnerability scanner not initialized',
                'stats': {
                    'total_macs_tracked': 0,
                    'total_ports_scanned': 0,
                    'average_ports_per_mac': 0,
                    'mac_details': {}
                }
            }), 200
        
        stats = vuln_scanner.get_scan_history_stats()
        
        return jsonify({
            'success': True,
            'stats': stats,
            'message': f"Tracking {stats['total_macs_tracked']} MAC addresses with {stats['total_ports_scanned']} scanned ports"
        })
        
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerability-scan/history/reset', methods=['POST'])
def reset_vulnerability_scan_history():
    """Reset incremental scan history for specific MAC or all"""
    try:
        data = request.get_json() if request.is_json else {}
        mac = data.get('mac', None)
        
        # Access the nmap_vuln_scanner from shared_data
        vuln_scanner = getattr(shared_data, 'nmap_vuln_scanner', None)
        
        if not vuln_scanner:
            return jsonify({
                'error': 'Vulnerability scanner not initialized'
            }), 500
        
        success = vuln_scanner.reset_scan_history(mac)
        
        if mac:
            message = f"Reset scan history for MAC {mac}" if success else f"MAC {mac} not found in history"
        else:
            message = "Reset ALL scan history - next scan will be a full rescan"
        
        return jsonify({
            'success': success,
            'message': message,
            'mac': mac,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error resetting scan history: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# REAL-TIME SCANNING ENDPOINTS
# ============================================================================

def run_arp_scan_localnet(interface='wlan0'):
    """Run arp-scan on local network to discover active hosts"""
    command = ['sudo', 'arp-scan', f'--interface={interface}', '--localnet']
    logger.info(f"Running arp-scan localnet: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return _parse_arp_scan_output(result.stdout)
        else:
            logger.warning(f"arp-scan failed with return code {result.returncode}: {result.stderr}")
            return {}
    except FileNotFoundError:
        logger.warning("arp-scan command not found")
        return {}
    except subprocess.TimeoutExpired as e:
        logger.warning(f"arp-scan timed out: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error running arp-scan: {e}")
        return {}

def run_nmap_ping_scan(network='192.168.1.0/24'):
    """Run nmap ping scan to discover active hosts"""
    command = ['sudo', 'nmap', '-sn', '-PR', network]
    logger.info(f"Running nmap ping scan: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return _parse_nmap_ping_output(result.stdout)
        else:
            logger.warning(f"nmap ping scan failed with return code {result.returncode}: {result.stderr}")
            return {}
    except FileNotFoundError:
        logger.warning("nmap command not found")
        return {}
    except subprocess.TimeoutExpired as e:
        logger.warning(f"nmap ping scan timed out: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error running nmap ping scan: {e}")
        return {}

def _parse_nmap_ping_output(output):
    """Parse nmap ping scan output to extract IP addresses and MAC addresses"""
    hosts = {}
    current_ip = None
    
    for line in output.splitlines():
        line = line.strip()
        
        # Look for "Nmap scan report for" lines to get IP addresses
        if line.startswith('Nmap scan report for'):
            # Extract IP from line like "Nmap scan report for 192.168.1.1"
            parts = line.split()
            if len(parts) >= 5:
                ip_part = parts[-1]
                if '(' in ip_part and ')' in ip_part:
                    # Format: "hostname (192.168.1.1)"
                    current_ip = ip_part.strip('()')
                else:
                    # Format: "192.168.1.1"
                    current_ip = ip_part
                
                if _is_valid_ipv4(current_ip):
                    hosts[current_ip] = {
                        'ip': current_ip,
                        'mac': '',
                        'hostname': '',
                        'status': 'up'
                    }
        
        # Look for MAC address lines
        elif line.startswith('MAC Address:') and current_ip:
            # Extract MAC from line like "MAC Address: 00:11:22:33:44:55 (Vendor)"
            parts = line.split()
            if len(parts) >= 3:
                mac = parts[2]
                if MAC_REGEX.match(mac):
                    hosts[current_ip]['mac'] = _normalize_mac(mac)
                    # Extract vendor info if available
                    if '(' in line and ')' in line:
                        vendor_start = line.find('(')
                        vendor_end = line.find(')')
                        if vendor_start < vendor_end:
                            vendor = line[vendor_start+1:vendor_end]
                            hosts[current_ip]['vendor'] = vendor
    
    return hosts

# Global variables for network scanning
network_scan_cache = {}
network_scan_last_update = 0
ARP_SCAN_INTERVAL = 60  # seconds

@app.route('/api/scan/arp-localnet')
def get_arp_scan_localnet():
    """Get ARP scan results for local network"""
    try:
        interface = request.args.get('interface', 'wlan0')
        hosts = run_arp_scan_localnet(interface)
        
        return jsonify({
            'success': True,
            'hosts': hosts,
            'count': len(hosts),
            'interface': interface,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in ARP scan endpoint: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'hosts': {},
            'count': 0
        }), 500

@app.route('/api/scan/nmap-ping')
def get_nmap_ping_scan():
    """Get nmap ping scan results"""
    try:
        network = request.args.get('network', '192.168.1.0/24')
        hosts = run_nmap_ping_scan(network)
        
        return jsonify({
            'success': True,
            'hosts': hosts,
            'count': len(hosts),
            'network': network,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in nmap ping scan endpoint: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'hosts': {},
            'count': 0
        }), 500

@app.route('/api/scan/combined-network')
def get_combined_network_scan():
    """Get combined results from both ARP and nmap scans"""
    try:
        interface = request.args.get('interface', 'wlan0')
        network = request.args.get('network', '192.168.1.0/24')
        
        # Run both scans
        arp_hosts = run_arp_scan_localnet(interface)
        nmap_hosts = run_nmap_ping_scan(network)
        
        # Combine results, preferring ARP data when available
        combined_hosts = {}
        
        # Start with nmap results
        for ip, data in nmap_hosts.items():
            combined_hosts[ip] = {
                'ip': ip,
                'mac': data.get('mac', ''),
                'hostname': data.get('hostname', ''),
                'status': data.get('status', 'up'),
                'vendor': data.get('vendor', ''),
                'source': 'nmap'
            }
        
        # Overlay ARP results (more reliable for MAC addresses)
        for ip, data in arp_hosts.items():
            if ip in combined_hosts:
                # Update existing entry with ARP data
                combined_hosts[ip]['mac'] = data.get('mac', combined_hosts[ip]['mac'])
                combined_hosts[ip]['hostname'] = data.get('hostname', combined_hosts[ip]['hostname'])
                combined_hosts[ip]['source'] = 'arp+nmap'
            else:
                # Add new entry from ARP
                combined_hosts[ip] = {
                    'ip': ip,
                    'mac': data.get('mac', ''),
                    'hostname': data.get('hostname', ''),
                    'status': 'up',
                    'vendor': data.get('vendor', ''),
                    'source': 'arp'
                }
        
        # Update network knowledge base
        for ip, data in combined_hosts.items():
            update_netkb_entry(ip, data.get('hostname', ''), data.get('mac', ''), True)
        
        return jsonify({
            'success': True,
            'hosts': combined_hosts,
            'count': len(combined_hosts),
            'arp_count': len(arp_hosts),
            'nmap_count': len(nmap_hosts),
            'interface': interface,
            'network': network,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in combined network scan endpoint: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'hosts': {},
            'count': 0
        }), 500

@app.route('/api/scan/start-realtime', methods=['POST'])
def start_realtime_scan():
    """Start real-time vulnerability scanning"""
    try:
        data = request.get_json() or {}
        scan_type = data.get('type', 'all')  # 'all', 'single', 'network'
        target = data.get('target', None)
        
        if scan_type == 'single' and target:
            # Start single host scan
            def scan_callback(event_type, event_data):
                socketio.emit('scan_update', {
                    'type': event_type,
                    'data': event_data
                })
            
            # Run scan in background thread
            def run_single_scan():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner
                    scanner = NmapVulnScanner(shared_data)
                    result = scanner.scan_single_host_realtime(
                        ip=target.get('ip', ''),
                        hostname=target.get('hostname', ''),
                        mac=target.get('mac', ''),
                        ports=target.get('ports', ''),
                        callback=scan_callback
                    )
                except Exception as e:
                    scan_callback('scan_error', {'error': str(e)})
            
            threading.Thread(target=run_single_scan, daemon=True).start()
            
        elif scan_type == 'all':
            # Start full network scan
            def scan_callback(event_type, event_data):
                socketio.emit('scan_update', {
                    'type': event_type,
                    'data': event_data
                })
            
            # Run scan in background thread
            def run_full_scan():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner
                    scanner = NmapVulnScanner(shared_data)
                    scanner.force_scan_all_hosts(real_time_callback=scan_callback)
                except Exception as e:
                    scan_callback('scan_error', {'error': str(e)})
            
            threading.Thread(target=run_full_scan, daemon=True).start()
        
        return jsonify({'status': 'success', 'message': 'Scan started'})
        
    except Exception as e:
        logger.error(f"Error starting real-time scan: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scan/status')
def get_scan_status():
    """Get current scanning status"""
    try:
        # Check if any scans are running by looking at orchestrator status
        scan_status = {
            'scanning': False,
            'current_target': None,
            'progress': 0,
            'total_hosts': 0,
            'completed_hosts': 0
        }
        
        # You can enhance this by checking actual scan status
        # For now, return basic status
        
        return jsonify({'status': 'success', 'data': scan_status})
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scan/host', methods=['POST'])
def scan_single_host():
    """Scan a single host"""
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'status': 'error', 'message': 'IP address is required'}), 400
        
        ip = data['ip']

        # Validate IP address format
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address format'}), 400

        # Start single host scan in background thread
        def scan_host_background():
            def run_nmap_fallback():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner

                    scanner = NmapVulnScanner(shared_data)

                    def callback(event_type, event_data):
                        payload = {'type': event_type}
                        if isinstance(event_data, dict):
                            payload.update(event_data)
                        socketio.emit('scan_host_update', payload)

                    scanner.scan_single_host_realtime(ip, callback=callback)
                except Exception as fallback_error:
                    logger.error(f"Fallback nmap scan failed for {ip}: {fallback_error}")
                    socketio.emit('scan_host_update', {
                        'type': 'sep_scan_error',
                        'ip': ip,
                        'message': f'Nmap fallback failed: {fallback_error}'
                    })

            try:
                logger.info(f"Running sep-scan for {ip}")
                command = SEP_SCAN_COMMAND + [ip]
                result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)

                stdout_lines = result.stdout.splitlines() if result.stdout else []
                stderr_lines = result.stderr.splitlines() if result.stderr else []

                for line in stdout_lines:
                    line = line.strip()
                    if line:
                        socketio.emit('scan_host_update', {
                            'type': 'sep_scan_output',
                            'ip': ip,
                            'message': line
                        })

                for line in stderr_lines:
                    line = line.strip()
                    if line:
                        socketio.emit('scan_host_update', {
                            'type': 'sep_scan_output',
                            'ip': ip,
                            'message': line
                        })

                success = result.returncode == 0
                if not success:
                    error_message = result.stderr.strip() if result.stderr else f"sep-scan exited with code {result.returncode}"
                    socketio.emit('scan_host_update', {
                        'type': 'sep_scan_error',
                        'ip': ip,
                        'message': error_message
                    })

                mac = run_targeted_arp_scan(ip)
                hostname = resolve_ip_hostname(ip)

                updated_row = update_netkb_entry(ip, hostname, mac, success)
                payload = {
                    'type': 'host_updated',
                    'ip': ip,
                    'IPs': ip,
                    'Hostnames': hostname or '',
                    'MAC Address': mac or '',
                    'Alive': '1' if success else '0',
                    'Ports': '',
                    'scan_status': 'sep-scan' if success else 'sep-scan-failed',
                    'last_scan': datetime.now().isoformat(),
                    'vulnerabilities': []
                }

                if updated_row:
                    payload.update({
                        'IPs': updated_row.get('IPs', ip),
                        'Hostnames': updated_row.get('Hostnames', hostname or ''),
                        'MAC Address': updated_row.get('MAC Address', mac or ''),
                        'Ports': updated_row.get('Ports', ''),
                        'Alive': updated_row.get('Alive', '1' if success else '0'),
                        'Nmap Vulnerabilities': updated_row.get('Nmap Vulnerabilities', ''),
                        'NmapVulnScanner': updated_row.get('NmapVulnScanner', '')
                    })

                payload['mac'] = payload.get('MAC Address', '')
                payload['hostname'] = payload.get('Hostnames', '')

                socketio.emit('scan_host_update', payload)
                socketio.emit('scan_host_update', {
                    'type': 'sep_scan_completed',
                    'ip': ip,
                    'status': 'success' if success else 'failed'
                })

            except FileNotFoundError:
                logger.warning(f"sep-scan command not found. Falling back to nmap for {ip}")
                socketio.emit('scan_host_update', {
                    'type': 'sep_scan_error',
                    'ip': ip,
                    'message': 'sep-scan command not found. Falling back to nmap.'
                })
                run_nmap_fallback()
            except subprocess.TimeoutExpired:
                logger.error(f"sep-scan timed out for {ip}")
                socketio.emit('scan_host_update', {
                    'type': 'sep_scan_error',
                    'ip': ip,
                    'message': 'sep-scan timed out'
                })
            except Exception as e:
                logger.error(f"Error running sep-scan for {ip}: {e}")
                socketio.emit('scan_host_update', {
                    'type': 'sep_scan_error',
                    'ip': ip,
                    'message': str(e)
                })
                run_nmap_fallback()

        # Start the scan in a background thread
        import threading
        scan_thread = threading.Thread(target=scan_host_background)
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({'status': 'success', 'message': f'Started scan of {ip}'})
        
    except Exception as e:
        logger.error(f"Error scanning single host: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scan/deep', methods=['POST'])
def deep_scan_host():
    """Perform a deep scan on a single host using TCP connect scan (-sT).

    Defaults to the curated top 3000 ports unless the caller explicitly requests a
    full-range sweep via mode/full flags.
    """
    try:
        # ===== REQUEST INTROSPECTION =====
        logger.info("🎯 DEEP SCAN API ENDPOINT CALLED")
        logger.info(f"   Method={request.method} Content-Type={request.content_type} Content-Length={request.content_length}")
        # Log a safe subset of headers
        try:
            hdr_subset = {k: v for k, v in request.headers.items() if k in ['User-Agent','Content-Type','Origin','Referer']}
            logger.debug(f"   Headers subset: {hdr_subset}")
        except Exception as e_hdr:
            logger.debug(f"   Could not log headers subset: {e_hdr}")

        raw_body = request.get_data(cache=False)  # bytes
        logger.debug(f"   Raw body repr: {raw_body!r}")

        data = {}
        # Robust JSON parsing with fallback to form/query
        if request.content_type and 'application/json' in request.content_type.lower():
            try:
                data = request.get_json(force=True, silent=True) or {}
            except Exception as json_err:
                logger.error(f"   JSON parse error: {json_err}")
                data = {}
        if not data:
            # Fallbacks
            form_dict = request.form.to_dict() if request.form else {}
            args_dict = request.args.to_dict() if request.args else {}
            data = {**args_dict, **form_dict}
        logger.info(f"   Parsed data: {data} (type={type(data).__name__})")

        ip = (data.get('ip') or '').strip()
        portstart_raw = data.get('portstart', 1)
        # ===== SECONDARY RAW BODY PARSING FALLBACK =====
        # If IP is still empty after initial structured parsing, attempt to extract it manually
        if not ip:
            try:
                raw_text = raw_body.decode('utf-8', errors='ignore').strip()
                logger.debug(f"   Fallback raw body text: {raw_text}")
                # Case 1: Proper JSON that get_json() failed to parse (malformed headers / PowerShell curl issues)
                if raw_text.startswith('{') and raw_text.endswith('}'):
                    import json as _json
                    try:
                        manual_json = _json.loads(raw_text)
                        ip = (manual_json.get('ip') or '').strip()
                        logger.debug(f"   Extracted IP from manual JSON fallback: [{ip}]")
                    except Exception as mj_err:
                        logger.debug(f"   Manual JSON decode failed: {mj_err}")
                # Case 2: application/x-www-form-urlencoded style: ip=192.168.1.192
                if not ip and ('=' in raw_text or '&' in raw_text):
                    import urllib.parse as _up
                    parsed_qs = _up.parse_qs(raw_text)
                    if 'ip' in parsed_qs and parsed_qs['ip']:
                        ip = (parsed_qs['ip'][0] or '').strip()
                        logger.debug(f"   Extracted IP from querystring style body: [{ip}]")
                # Case 3: Loose key:value or key=value pattern inside text
                if not ip:
                    import re as _re
                    m = _re.search(r'"?ip"?\s*[:=]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?', raw_text)
                    if m:
                        ip = m.group(1).strip()
                        logger.debug(f"   Extracted IP via regex heuristic: [{ip}]")
            except Exception as fb_err:
                logger.debug(f"   Raw body manual parse error: {fb_err}")
        # Log final IP extraction state before validation
        logger.debug(f"   Final extracted IP after fallbacks: [{ip}]")
        portend_raw = data.get('portend', 65535)
        try:
            portstart = int(portstart_raw)
        except (TypeError, ValueError):
            portstart = 1
        try:
            portend = int(portend_raw)
        except (TypeError, ValueError):
            portend = 65535

        if not ip:
            # Include a small, safe snippet of raw body to aid debugging (truncated to 120 chars)
            try:
                snippet = raw_body.decode('utf-8','ignore')[:120]
            except Exception:
                snippet = '<un-decodable>'
            logger.error(f"❌ Deep scan request missing IP after all parsing attempts. Raw snippet: {snippet!r}")
            return jsonify({'status': 'error', 'message': 'IP address is required', 'raw_snippet': snippet}), 400

        # Decide scan mode early so API response reflects reality
        mode_flag = (data.get('mode') or data.get('scan_mode') or '').lower()
        full_flag = str(data.get('full', '')).lower() in ['1','true','yes']
        use_top_ports = not (mode_flag in ['full','all','65535'] or full_flag)
        logger.info(
            f"🎯 DEEP SCAN PARAMETERS - IP=[{ip}] Ports={portstart}-{portend} mode={'top3000' if use_top_ports else 'full-range'}"
        )

        # Validate IP address format
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address format'}), 400

        # Start deep scan in background thread
        def deep_scan_background():
            try:
                # Import the scanner
                from actions.scanning import NetworkScanner
                
                # Create scanner instance
                scanner = NetworkScanner(shared_data)
                
                # Emit scan started event
                socketio.emit('deep_scan_update', {
                    'type': 'deep_scan_started',
                    'ip': ip,
                    'message': f'Starting deep scan on {ip} (ports {portstart}-{portend})...'
                })
                
                # Define progress callback to emit real-time updates
                def progress_callback(event_type, data):
                    socketio.emit('deep_scan_update', {
                        'type': 'deep_scan_progress',
                        'event': event_type,
                        'ip': ip,
                        'message': data.get('message', ''),
                        'port': data.get('port'),
                        'service': data.get('service')
                    })
                
                socketio.emit('deep_scan_update', {
                    'type': 'deep_scan_progress',
                    'ip': ip,
                    'message': f"Parameters accepted: ip={ip} mode={'top3000' if use_top_ports else 'full-range'} range={portstart}-{portend}"
                })

                # Perform the deep scan with progress callback
                result = scanner.deep_scan_host(ip, portstart, portend, progress_callback=progress_callback, use_top_ports=use_top_ports)
                
                # Emit final result
                if result['success']:
                    socketio.emit('deep_scan_update', {
                        'type': 'deep_scan_completed',
                        'ip': ip,
                        'open_ports': result['open_ports'],
                        'hostname': result['hostname'],
                        'port_details': result['port_details'],
                        'scan_duration': result['scan_duration'],
                        'message': result['message']
                    })
                    
                    # Also emit a network update to refresh the table
                    socketio.emit('network_update', {'refresh': True})
                else:
                    socketio.emit('deep_scan_update', {
                        'type': 'deep_scan_error',
                        'ip': ip,
                        'message': result['message']
                    })
                    
            except Exception as e:
                logger.error(f"Error in deep scan background task for {ip}: {e}")
                socketio.emit('deep_scan_update', {
                    'type': 'deep_scan_error',
                    'ip': ip,
                    'message': f'Deep scan error: {str(e)}'
                })

        # Start the deep scan in a background thread
        import threading
        scan_thread = threading.Thread(target=deep_scan_background)
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({
            'status': 'success',
            'message': f"Started deep scan of {ip} (mode={'top3000' if use_top_ports else 'full-range'})",
            'ip': ip,
            'portstart': portstart,
            'portend': portend,
            'mode': 'top3000' if use_top_ports else 'full-range'
        })
        
    except Exception as e:
        logger.error(f"Error initiating deep scan: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================================================
# SYSTEM MANAGEMENT UTILITIES & ENDPOINTS
# ============================================================================

def _execute_git_update(repo_path: str) -> dict:
    """Run the git pull sequence Ragnar uses, returning status metadata."""
    result = {
        'success': False,
        'output': '',
        'error': '',
        'warnings': []
    }

    # Fix permissions ahead of git pull to avoid ownership issues on devices
    try:
        logger.info("Correcting file permissions before git pull...")
        subprocess.run(
            ['sudo', 'chown', '-R', 'ragnar:ragnar', '/home/ragnar/Ragnar'],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info("Permissions corrected successfully")
    except subprocess.CalledProcessError as e:
        warning = f"Permission correction failed (continuing): {e.stderr.strip() or e.stdout.strip()}"
        logger.warning(warning)
        result['warnings'].append(warning)
    except Exception as e:
        warning = f"Permission correction error (continuing): {e}"
        logger.warning(warning)
        result['warnings'].append(warning)

    # Perform git pull
    try:
        pull_proc = subprocess.run(
            ['git', 'pull'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        result['output'] = pull_proc.stdout.strip()
        logger.info(f"Git pull completed: {result['output']}")
    except subprocess.CalledProcessError as e:
        error_msg = f"Git pull failed: {e.stderr.strip() or e.stdout.strip() or str(e)}"
        logger.error(error_msg)
        result['error'] = error_msg
        return result

    # Ensure executable bits remain in place after pull
    try:
        logger.info("Making scripts executable after git pull...")
        chmod_commands = [
            ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/*.sh'],
            ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/*.py'],
            ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/Ragnar.py'],
            ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/kill_port_8000.sh'],
            ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/webapp_modern.py'],
            ['sudo', 'find', '/home/ragnar/Ragnar', '-name', '*.sh', '-exec', 'chmod', '+x', '{}', ';']
        ]

        for cmd in chmod_commands:
            try:
                subprocess.run(cmd, capture_output=True, text=True, check=False)
            except Exception as chmod_error:
                logger.debug(f"Chmod command failed (continuing): {cmd} - {chmod_error}")

        logger.info("Executable permissions refreshed")
    except subprocess.CalledProcessError as e:
        warning = f"Chmod failed (continuing): {e.stderr.strip() or e.stdout.strip()}"
        logger.warning(warning)
        result['warnings'].append(warning)
    except Exception as e:
        warning = f"Chmod error (continuing): {e}"
        logger.warning(warning)
        result['warnings'].append(warning)

    result['success'] = True
    return result


def _schedule_service_restart(delay_seconds: int = 2) -> None:
    """Restart the Ragnar service after a short delay so HTTP responses return first."""

    def restart_service_delayed():
        time.sleep(delay_seconds)
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', 'ragnar'], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restart service: {e}")

    threading.Thread(target=restart_service_delayed, daemon=True).start()


# ============================================================================
# SYSTEM MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/system/check-updates')
def check_updates():
    """Check for system updates using git"""
    try:
        import subprocess
        import os
        
        # Get current working directory (should be the repo root)
        # Use the directory where the webapp is running from, not the file location
        repo_path = os.getcwd()
        
        logger.info(f"Checking for updates in repository: {repo_path}")
        
        # Fetch latest changes from remote
        try:
            fetch_result = subprocess.run(['git', 'fetch'], cwd=repo_path, check=True, capture_output=True, text=True)
            logger.info(f"Git fetch completed: {fetch_result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git fetch failed: {e.stderr}")
            # Try to fix git safe directory issue and retry
            try:
                subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', repo_path], 
                             cwd=repo_path, check=True, capture_output=True)
                logger.info(f"Added {repo_path} to git safe directories")
                # Retry fetch
                fetch_result = subprocess.run(['git', 'fetch'], cwd=repo_path, check=True, capture_output=True, text=True)
                logger.info(f"Git fetch completed after fixing safe directory: {fetch_result.stdout}")
            except subprocess.CalledProcessError as e2:
                logger.error(f"Git fetch still failed after fixing safe directory: {e2.stderr}")
                return jsonify({
                    'error': 'Failed to fetch from remote repository. Git safe directory issue detected.',
                    'fix_command': f'git config --global --add safe.directory {repo_path}',
                    'detailed_error': str(e2.stderr)
                }), 500
        
        # Get the current branch name
        try:
            branch_result = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=repo_path, check=True, capture_output=True, text=True)
            current_branch = branch_result.stdout.strip()
        except subprocess.CalledProcessError:
            current_branch = 'main' # Fallback
        
        logger.info(f"Current git branch is: {current_branch}")
        remote_branch = f'origin/{current_branch}'

        # Check if local branch is behind remote
        try:
            result = subprocess.run(
                ['git', 'rev-list', '--count', f'HEAD..{remote_branch}'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            commits_behind = int(result.stdout.strip())
            logger.info(f"Commits behind '{remote_branch}': {commits_behind}")
        except (subprocess.CalledProcessError, ValueError) as e:
            logger.error(f"Error checking commits behind '{remote_branch}': {e}")
            commits_behind = 0
        
        # Get current HEAD commit
        try:
            current_result = subprocess.run(
                ['git', 'log', 'HEAD', '--oneline', '-1'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            current_commit = current_result.stdout.strip()
        except Exception:
            current_commit = "Unable to fetch current commit"
        
        # Get latest commit info
        try:
            result = subprocess.run(
                ['git', 'log', remote_branch, '--oneline', '-1'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            latest_commit = result.stdout.strip()
        except Exception:
            latest_commit = "Unable to fetch latest commit"

        # Collect local working tree state so the UI can warn about conflicts/stashes
        git_status = {
            'is_dirty': False,
            'has_conflicts': False,
            'has_stash': False,
            'stash_entries': 0,
            'modified_files': [],
            'conflicted_files': [],
            'status_error': ''
        }

        try:
            status_result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            status_lines = [line for line in status_result.stdout.splitlines() if line.strip()]
            git_status['is_dirty'] = bool(status_lines)

            conflict_codes = {'AA', 'DD', 'AU', 'UA', 'DU', 'UD', 'UU'}
            for raw_line in status_lines:
                code = raw_line[:2]
                path_fragment = raw_line[3:].strip() if len(raw_line) > 3 else raw_line.strip()
                entry = {'code': code, 'path': path_fragment}
                git_status['modified_files'].append(entry)
                if code in conflict_codes or 'U' in code:
                    git_status['conflicted_files'].append(entry)

            git_status['has_conflicts'] = bool(git_status['conflicted_files'])
        except subprocess.CalledProcessError as status_error:
            git_status['status_error'] = status_error.stderr.strip() or str(status_error)
            logger.warning(f"git status failed during update check: {git_status['status_error']}")

        try:
            stash_result = subprocess.run(
                ['git', 'stash', 'list'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            stash_lines = [line for line in stash_result.stdout.splitlines() if line.strip()]
            git_status['stash_entries'] = len(stash_lines)
            git_status['has_stash'] = git_status['stash_entries'] > 0
        except subprocess.CalledProcessError as stash_error:
            stash_msg = stash_error.stderr.strip() or str(stash_error)
            git_status['status_error'] = git_status['status_error'] or stash_msg
            logger.warning(f"git stash list failed during update check: {stash_msg}")
        
        logger.info(f"Update check result - Behind: {commits_behind}, Current: {current_commit}, Latest: {latest_commit}")
        
        return jsonify({
            'updates_available': commits_behind > 0,
            'commits_behind': commits_behind,
            'current_commit': current_commit,
            'latest_commit': latest_commit,
            'repo_path': repo_path,
            'git_status': git_status
        })
        
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/update', methods=['POST'])
def perform_update():
    """Perform system update using git pull"""
    try:
        repo_path = os.getcwd()
        logger.info(f"Performing update in repository: {repo_path}")
        update_result = _execute_git_update(repo_path)

        if not update_result['success']:
            return jsonify({
                'success': False,
                'error': update_result['error'] or 'Unknown error during git pull',
                'warnings': update_result['warnings'],
                'suggestion': 'Please check repository status and resolve any conflicts'
            }), 500

        _schedule_service_restart()

        return jsonify({
            'success': True,
            'message': 'Update completed successfully',
            'output': update_result['output'],
            'warnings': update_result['warnings']
        })
        
    except Exception as e:
        logger.error(f"Error performing update: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/system/stash-update', methods=['POST'])
def stash_and_update():
    """Automatically stash local changes, pull updates, and drop the temporary stash."""
    repo_path = os.getcwd()
    payload = request.get_json(silent=True) or {}
    stash_message = payload.get('message') or f"Ragnar auto stash {datetime.utcnow().isoformat()}"
    include_untracked = payload.get('include_untracked', True)

    stash_cmd = ['git', 'stash', 'push']
    if include_untracked:
        stash_cmd.append('-u')
    stash_cmd.extend(['-m', stash_message])

    logger.info("Auto stash + update requested via UI")

    try:
        stash_proc = subprocess.run(
            stash_cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() or e.stdout.strip() or str(e)
        logger.error(f"Git stash failed: {error_msg}")
        return jsonify({'success': False, 'error': f'Git stash failed: {error_msg}'}), 500

    stash_stdout = stash_proc.stdout.strip() or stash_proc.stderr.strip() or ''
    stash_created = 'No local changes to save' not in stash_stdout
    stash_ref = 'stash@{0}' if stash_created else None

    if stash_created:
        logger.info(f"Local changes stashed as {stash_ref}")
    else:
        logger.info("Auto stash requested but no local changes were found")

    update_result = _execute_git_update(repo_path)
    if not update_result['success']:
        # Preserve the stash so the operator can recover work manually
        logger.error("Auto stash update failed after stashing; stash preserved for manual recovery")
        return jsonify({
            'success': False,
            'error': update_result['error'] or 'Unknown error during git pull',
            'warnings': update_result['warnings'],
            'local_changes_preserved': stash_created
        }), 500

    if stash_created and stash_ref:
        try:
            pop_proc = subprocess.run(
                ['git', 'stash', 'pop', stash_ref],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            pop_msg = pop_proc.stdout.strip() or pop_proc.stderr.strip() or ''
            if pop_msg:
                logger.debug(f"Stash pop output: {pop_msg}")
            logger.info(f"Reapplied local changes from {stash_ref}")
        except subprocess.CalledProcessError as e:
            stash_pop_warning = e.stderr.strip() or e.stdout.strip() or str(e)
            logger.warning(f"Failed to reapply stash {stash_ref}: {stash_pop_warning}")
            update_result['warnings'].append(
                "Local changes were saved but could not be re-applied automatically. Resolve conflicts and run 'git stash pop' manually."
            )

    _schedule_service_restart()

    return jsonify({
        'success': True,
        'message': 'Update applied successfully.',
        'warnings': update_result['warnings'],
        'update_output': update_result['output']
    })

@app.route('/api/system/resolve-conflicts', methods=['POST'])
def resolve_git_conflicts():
    """Resolve git merge conflicts by resetting to HEAD then pulling latest."""
    repo_path = os.getcwd()
    try:
        # Hard reset clears both the index (staged conflicts) and working tree
        subprocess.run(
            ['git', 'reset', '--hard', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        logger.info("Git reset --hard HEAD completed")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() or e.stdout.strip() or str(e)
        logger.error(f"Git reset failed: {error_msg}")
        return jsonify({'success': False, 'error': f'Git reset failed: {error_msg}'}), 500

    update_result = _execute_git_update(repo_path)
    if not update_result['success']:
        return jsonify({
            'success': False,
            'error': update_result['error'] or 'Git pull failed after reset',
            'warnings': update_result['warnings']
        }), 500

    _schedule_service_restart()
    return jsonify({
        'success': True,
        'message': 'Conflicts resolved and update applied successfully.',
        'output': update_result['output'],
        'warnings': update_result['warnings']
    })


@app.route('/api/system/fix-git', methods=['POST'])
def fix_git_safe_directory():
    """Fix git safe directory issue"""
    try:
        import subprocess
        import os
        
        repo_path = os.getcwd()
        
        # Add repo to git safe directories
        result = subprocess.run(
            ['git', 'config', '--global', '--add', 'safe.directory', repo_path], 
            cwd=repo_path, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        logger.info(f"Added {repo_path} to git safe directories")
        
        return jsonify({
            'success': True,
            'message': f'Successfully added {repo_path} to git safe directories'
        })
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fix git safe directory: {e.stderr}")
        return jsonify({
            'success': False, 
            'error': f'Failed to fix git configuration: {e.stderr}'
        }), 500
    except Exception as e:
        logger.error(f"Error fixing git safe directory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# PWNAGOTCHI INTEGRATION ENDPOINTS
# ============================================================================

@app.route('/api/pwnagotchi/status')
def get_pwnagotchi_status():
    try:
        status = _build_pwnagotchi_status()
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        logger.error(f"Error retrieving Pwnagotchi status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pwnagotchi/download')
def download_pwnagotchi_file():
    """Download a Pwnagotchi handshake or discovery file."""
    try:
        filename = request.args.get('file', '')
        if not filename or '/' in filename or '\\' in filename or '..' in filename:
            return jsonify({'error': 'Invalid filename'}), 400

        allowed_dirs = ['/root/handshakes', '/home/pi/handshakes']
        for d in allowed_dirs:
            candidate = os.path.join(d, filename)
            if os.path.isfile(candidate):
                return send_from_directory(d, filename, as_attachment=True)

        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        logger.error(f"Error downloading Pwnagotchi file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pwnagotchi/install', methods=['POST'])
def install_pwnagotchi_from_dashboard():
    try:
        if not os.path.exists(PWN_INSTALL_SCRIPT):
            return jsonify({'success': False, 'error': 'Installer script not found', 'script': PWN_INSTALL_SCRIPT}), 404

        current_status = _build_pwnagotchi_status(persist=False)
        if current_status.get('installing'):
            if _pwn_install_process_running() and not _is_pwn_install_stale(current_status):
                return jsonify({'success': False, 'error': 'Installation already in progress'}), 409
            logger.info('Previous Pwnagotchi install attempt appears stale. Restarting installer.')

        logger.info("Launching Pwnagotchi installer from dashboard request")
        _write_pwn_status_file('installing', 'Launching Pwnagotchi installer…', 'install')

        try:
            subprocess.Popen(
                ['sudo', '/bin/bash', PWN_INSTALL_SCRIPT],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
        except Exception as exc:
            logger.error(f"Failed to spawn installer: {exc}")
            return jsonify({'success': False, 'error': f'Failed to start installer: {exc}'}), 500

        status = _emit_pwn_status_update()
        return jsonify({'success': True, 'message': 'Installer started in background', 'status': status})

    except Exception as e:
        logger.error(f"Error starting Pwnagotchi install: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pwnagotchi/logs')
def stream_pwnagotchi_logs():
    try:
        cursor_arg = request.args.get('cursor', default=None, type=int)
        tail_bytes = request.args.get('tail', default=4096, type=int)
        max_bytes = request.args.get('max_bytes', default=8192, type=int)

        status, log_file, cursor, entries = _read_pwn_log_chunk(cursor=cursor_arg, tail_bytes=tail_bytes, max_bytes=max_bytes)

        response = {
            'success': bool(log_file),
            'entries': entries,
            'cursor': cursor,
            'file': log_file,
            'state': status.get('state'),
            'installing': status.get('installing', False)
        }

        if not log_file:
            response['error'] = 'Installer log not available yet'

        return jsonify(response)

    except Exception as exc:
        logger.error(f"Error streaming Pwnagotchi logs: {exc}")
        return jsonify({'success': False, 'error': 'Failed to read installer logs'}), 500


@app.route('/api/pwnagotchi/swap', methods=['POST'])
def swap_to_pwnagotchi_mode():
    try:
        data = request.get_json(silent=True) or {}
        target_mode = (data.get('target') or 'pwnagotchi').strip().lower()

        if target_mode not in {'pwnagotchi', 'ragnar'}:
            return jsonify({'success': False, 'error': f'Invalid target mode: {target_mode}'}), 400

        status = _build_pwnagotchi_status()
        if not status.get('installed'):
            return jsonify({'success': False, 'error': 'Pwnagotchi is not installed'}), 409

        if target_mode == status.get('mode', 'ragnar') and target_mode == 'pwnagotchi':
            return jsonify({'success': False, 'error': 'Already scheduled for Pwnagotchi mode'}), 409

        if target_mode == 'pwnagotchi':
            message = 'Ragnar service will stop and Pwnagotchi will start. Reboot to return to Ragnar.'
        else:
            message = 'Switching back to Ragnar service. This is typically triggered after reboot.'

        _write_pwn_status_file('switching', message, 'swap', {'target_mode': target_mode})

        timestamp = datetime.utcnow().isoformat() + 'Z'
        _update_pwn_config({
            'pwnagotchi_mode': target_mode,
            'pwnagotchi_last_switch': timestamp,
            'pwnagotchi_last_status': message
        })

        status_payload = _emit_pwn_status_update()
        _schedule_pwn_mode_switch(target_mode)

        return jsonify({'success': True, 'message': message, 'status': status_payload})

    except Exception as e:
        logger.error(f"Error scheduling Pwnagotchi swap: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pwnagotchi/config')
def get_pwnagotchi_config():
    """Read the Pwnagotchi TOML config and return structured settings."""
    try:
        if not os.path.isfile(PWN_CONFIG_FILE):
            return jsonify({'success': False, 'error': 'Pwnagotchi config not found. Install Pwnagotchi first.'}), 404

        try:
            import tomlkit
            with open(PWN_CONFIG_FILE, 'r', encoding='utf-8') as f:
                doc = tomlkit.parse(f.read())
        except ImportError:
            # Fallback: basic TOML parser for simple key=value configs
            doc = _parse_toml_basic(PWN_CONFIG_FILE)
        except Exception as exc:
            logger.error(f"Failed to parse Pwnagotchi config: {exc}")
            return jsonify({'success': False, 'error': f'Failed to parse config: {exc}'}), 500

        # Extract the settings we expose in the UI
        main = doc.get('main', {})
        ui = doc.get('ui', {})
        ui_display = ui.get('display', {})
        ui_web = ui.get('web', {})
        personality = doc.get('personality', {})
        plugins = main.get('plugins', {})

        # Parse whitelist (list of SSIDs/BSSIDs)
        raw_whitelist = main.get('whitelist', [])
        if isinstance(raw_whitelist, list):
            whitelist_str = ', '.join(str(s) for s in raw_whitelist)
        else:
            whitelist_str = str(raw_whitelist)

        # Parse channels (list of ints)
        raw_channels = personality.get('channels', [])
        if isinstance(raw_channels, list):
            channels_str = ', '.join(str(c) for c in raw_channels)
        else:
            channels_str = str(raw_channels)

        config = {
            'main.name': str(main.get('name', 'pwnagotchi')),
            'main.whitelist': whitelist_str,
            'personality.advertise': bool(personality.get('advertise', False)),
            'personality.deauth': bool(personality.get('deauth', True)),
            'personality.associate': bool(personality.get('associate', True)),
            'personality.min_rssi': int(personality.get('min_rssi', -200)),
            'personality.channels': channels_str,
            'ui.invert': bool(ui.get('invert', False)),
            'ui.display.enabled': bool(ui_display.get('enabled', True)),
            'ui.display.type': str(ui_display.get('type', 'waveshare_4')),
            'ui.display.rotation': int(ui_display.get('rotation', 180)),
            'ui.web.enabled': bool(ui_web.get('enabled', True)),
            'ui.web.address': str(ui_web.get('address', '0.0.0.0')),
            'ui.web.username': str(ui_web.get('username', 'ragnar')),
            'ui.web.password': str(ui_web.get('password', 'ragnar')),
            'ui.web.port': int(ui_web.get('port', 8080)),
            'main.plugins.grid.enabled': bool(plugins.get('grid', {}).get('enabled', False)),
            'main.plugins.fix_services.enabled': bool(plugins.get('fix_services', {}).get('enabled', False)),
            'main.plugins.auto-tune.enabled': bool(plugins.get('auto-tune', {}).get('enabled', True)),
            'main.plugins.webcfg.enabled': bool(plugins.get('webcfg', {}).get('enabled', True)),
            'main.plugins.memtemp.enabled': bool(plugins.get('memtemp', {}).get('enabled', False)),
        }

        return jsonify({'success': True, 'config': config})
    except Exception as e:
        logger.error(f"Error reading Pwnagotchi config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pwnagotchi/config', methods=['POST'])
def save_pwnagotchi_config():
    """Update specific settings in the Pwnagotchi TOML config."""
    try:
        if not os.path.isfile(PWN_CONFIG_FILE):
            return jsonify({'success': False, 'error': 'Pwnagotchi config not found. Install Pwnagotchi first.'}), 404

        data = request.get_json(silent=True)
        if not data or 'config' not in data:
            return jsonify({'success': False, 'error': 'Missing config payload'}), 400

        updates = data['config']
        if not isinstance(updates, dict):
            return jsonify({'success': False, 'error': 'Config must be a dict'}), 400

        # Whitelist of allowed settings to prevent arbitrary file writes
        ALLOWED_KEYS = {
            'main.name': str,
            'main.whitelist': str,       # comma-separated → converted to list
            'personality.advertise': bool,
            'personality.deauth': bool,
            'personality.associate': bool,
            'personality.min_rssi': int,
            'personality.channels': str,  # comma-separated → converted to list
            'ui.invert': bool,
            'ui.display.enabled': bool,
            'ui.display.rotation': int,
            'ui.display.type': str,
            'ui.web.username': str,
            'ui.web.password': str,
            'ui.web.port': int,
            'main.plugins.grid.enabled': bool,
            'main.plugins.fix_services.enabled': bool,
            'main.plugins.auto-tune.enabled': bool,
            'main.plugins.webcfg.enabled': bool,
            'main.plugins.memtemp.enabled': bool,
        }

        # Validate keys and types
        validated = {}
        for key, value in updates.items():
            if key not in ALLOWED_KEYS:
                continue  # silently skip unknown keys
            expected_type = ALLOWED_KEYS[key]
            if expected_type == bool:
                validated[key] = bool(value)
            elif expected_type == int:
                validated[key] = int(value)
            else:
                validated[key] = str(value).strip()

        if not validated:
            return jsonify({'success': False, 'error': 'No valid settings in payload'}), 400

        # Validate specific value ranges
        if 'ui.display.rotation' in validated and validated['ui.display.rotation'] not in (0, 90, 180, 270):
            return jsonify({'success': False, 'error': 'Rotation must be 0, 90, 180, or 270'}), 400
        if 'ui.web.port' in validated:
            port = validated['ui.web.port']
            if port < 1024 or port > 65535:
                return jsonify({'success': False, 'error': 'Web port must be between 1024 and 65535'}), 400
        if 'main.name' in validated:
            name = validated['main.name']
            if not name or len(name) > 32 or not re.match(r'^[a-zA-Z0-9_-]+$', name):
                return jsonify({'success': False, 'error': 'Name must be 1-32 alphanumeric characters (plus - and _)'}), 400
        if 'personality.min_rssi' in validated:
            rssi = validated['personality.min_rssi']
            if rssi < -200 or rssi > 0:
                return jsonify({'success': False, 'error': 'Min RSSI must be between -200 and 0'}), 400

        # Convert comma-separated strings to TOML lists
        if 'main.whitelist' in validated:
            raw = validated['main.whitelist']
            validated['main.whitelist'] = [s.strip() for s in raw.split(',') if s.strip()] if raw.strip() else []
        if 'personality.channels' in validated:
            raw = validated['personality.channels']
            if raw.strip():
                try:
                    validated['personality.channels'] = [int(c.strip()) for c in raw.split(',') if c.strip()]
                except ValueError:
                    return jsonify({'success': False, 'error': 'Channels must be comma-separated numbers (e.g. 1, 6, 11)'}), 400
            else:
                validated['personality.channels'] = []

        try:
            import tomlkit
            with open(PWN_CONFIG_FILE, 'r', encoding='utf-8') as f:
                doc = tomlkit.parse(f.read())

            for dotted_key, value in validated.items():
                _set_toml_value(doc, dotted_key, value)

            with open(PWN_CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write(tomlkit.dumps(doc))
        except ImportError:
            # Fallback: use the shell helper from install script
            script_path = os.path.join(shared_data.currentdir, 'scripts', 'install_pwnagotchi.sh')
            for dotted_key, value in validated.items():
                _set_toml_value_fallback(dotted_key, value)

        logger.info(f"Pwnagotchi config updated: {list(validated.keys())}")
        return jsonify({'success': True, 'message': f'Updated {len(validated)} setting(s)', 'updated': list(validated.keys())})

    except Exception as e:
        logger.error(f"Error saving Pwnagotchi config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def _set_toml_value(doc, dotted_key, value):
    """Set a nested value in a tomlkit document using dotted key notation."""
    import tomlkit
    keys = dotted_key.split('.')
    d = doc
    for k in keys[:-1]:
        if k not in d:
            d[k] = tomlkit.table()
        d = d[k]
    d[keys[-1]] = value


def _set_toml_value_fallback(dotted_key, value):
    """Fallback: use Python inline script to update a TOML value when tomlkit is unavailable."""
    if isinstance(value, bool):
        val_str = 'true' if value else 'false'
    elif isinstance(value, int):
        val_str = str(value)
    else:
        val_str = value
    try:
        subprocess.run(
            ['sudo', 'python3', '-c',
             f"import tomlkit; f=open('{PWN_CONFIG_FILE}','r'); d=tomlkit.parse(f.read()); f.close(); "
             f"exec(\"keys='{dotted_key}'.split('.');o=d\\nfor k in keys[:-1]:\\n if k not in o: o[k]=tomlkit.table()\\n o=o[k]\\no[keys[-1]]={repr(value)}\")"
             f"; f=open('{PWN_CONFIG_FILE}','w'); f.write(tomlkit.dumps(d)); f.close()"],
            capture_output=True, text=True, timeout=10
        )
    except Exception as exc:
        logger.error(f"Fallback TOML write failed for {dotted_key}: {exc}")


def _parse_toml_basic(filepath):
    """Minimal TOML parser for reading simple config files when tomlkit is unavailable."""
    result = {}
    current_section = result
    section_path = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Section header
                m = re.match(r'^\[([^\]]+)\]$', line)
                if m:
                    section_path = m.group(1).split('.')
                    current_section = result
                    for part in section_path:
                        if part not in current_section:
                            current_section[part] = {}
                        current_section = current_section[part]
                    continue
                # Key = value
                m = re.match(r'^(\w+)\s*=\s*(.+)$', line)
                if m:
                    key = m.group(1)
                    val = m.group(2).strip()
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    elif val == 'true':
                        val = True
                    elif val == 'false':
                        val = False
                    else:
                        try:
                            val = int(val)
                        except ValueError:
                            pass
                    current_section[key] = val
    except Exception as exc:
        logger.error(f"Basic TOML parse failed: {exc}")
    return result


@app.route('/api/kill', methods=['POST'])
def kill_switch():
    """
    EDUCATIONAL KILL SWITCH - Complete data erasure endpoint
    
    This endpoint provides a secure way to completely wipe all data after educational
    demonstrations. Deletion order:
    1. Delete ragnar.db database file
    2. Delete entire data/ folder
    3. Delete entire Ragnar/ repository
    
    Security: Requires confirmation token to prevent accidental triggering
    """
    try:
        # Get confirmation from request
        data = request.get_json() or {}
        confirmation = data.get('confirmation', '')
        shutdown_after = data.get('shutdown', False)
        
        # Require explicit confirmation to prevent accidental wipes
        if confirmation != 'ERASE_ALL_DATA':
            logger.warning("Kill switch triggered without proper confirmation")
            return jsonify({
                'success': False,
                'error': 'Invalid confirmation token. Use "ERASE_ALL_DATA" to confirm.'
            }), 403
        
        logger.critical("=" * 80)
        logger.critical("KILL SWITCH ACTIVATED - INITIATING COMPLETE DATA ERASURE")
        logger.critical("=" * 80)
        
        results = {
            'database_deleted': False,
            'data_folder_deleted': False,
            'repository_deleted': False,
            'shutdown_scheduled': False,
            'errors': []
        }
        
        # Get the Ragnar directory path
        ragnar_dir = shared_data.currentdir
        home_dir = os.path.expanduser('~')
        ragnar_home_path = os.path.join(home_dir, 'Ragnar')
        
        # Use home path if it exists, otherwise use current directory
        if os.path.exists(ragnar_home_path):
            ragnar_dir = ragnar_home_path
        
        logger.critical(f"Target Ragnar directory: {ragnar_dir}")
        
        # STEP 1: Delete ragnar.db database file
        try:
            db_path = os.path.join(ragnar_dir, 'data', 'ragnar.db')
            logger.critical(f"Step 1/3: Deleting database file: {db_path}")
            
            if os.path.isfile(db_path):
                os.remove(db_path)
                logger.critical(f"✓ Deleted: {db_path}")
                results['database_deleted'] = True
            else:
                logger.warning(f"Database file not found: {db_path}")
                results['database_deleted'] = True  # Consider it success if file doesn't exist
            
        except Exception as e:
            error_msg = f"Error deleting database file: {str(e)}"
            logger.error(error_msg)
            results['errors'].append(error_msg)
        
        # STEP 2: Delete entire data/ folder
        try:
            data_dir = os.path.join(ragnar_dir, 'data')
            logger.critical(f"Step 2/3: Deleting data folder: {data_dir}")
            
            if os.path.exists(data_dir):
                shutil.rmtree(data_dir, ignore_errors=False)
                logger.critical(f"✓ Deleted: {data_dir}")
                results['data_folder_deleted'] = True
            else:
                logger.warning(f"Data folder not found: {data_dir}")
                results['data_folder_deleted'] = True  # Consider it success if folder doesn't exist
            
        except Exception as e:
            error_msg = f"Error deleting data folder: {str(e)}"
            logger.error(error_msg)
            results['errors'].append(error_msg)
        
        # STEP 3: Delete entire Ragnar/ repository
        # Use a background thread to allow response to be sent first
        def delete_repository():
            try:
                time.sleep(3)  # Wait 3 seconds for response to be sent
                logger.critical(f"Step 3/3: Deleting entire repository: {ragnar_dir}")
                
                if os.path.exists(ragnar_dir):
                    # Change to parent directory to avoid issues
                    parent_dir = os.path.dirname(ragnar_dir)
                    os.chdir(parent_dir)
                    
                    # Delete the entire Ragnar directory
                    shutil.rmtree(ragnar_dir, ignore_errors=False)
                    logger.critical(f"✓ Deleted: {ragnar_dir}")
                else:
                    logger.warning(f"Repository not found: {ragnar_dir}")
                    
            except Exception as e:
                logger.error(f"Error deleting repository: {str(e)}")
                logger.error(traceback.format_exc())
        
        # Start deletion thread
        deletion_thread = threading.Thread(target=delete_repository, daemon=True)
        deletion_thread.start()
        results['repository_deleted'] = True  # Marked as scheduled
        logger.critical(f"✓ Repository deletion scheduled in 3 seconds: {ragnar_dir}")
        
        # Optional shutdown
        if shutdown_after:
            try:
                logger.critical("Scheduling system shutdown in 60 seconds...")
                subprocess.Popen(['sudo', 'shutdown', '-h', '+1', 'Ragnar kill switch activated'],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True)
                results['shutdown_scheduled'] = True
            except Exception as e:
                error_msg = f"Error scheduling shutdown: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        logger.critical("=" * 80)
        logger.critical("KILL SWITCH EXECUTION COMPLETE")
        logger.critical(f"1. Database deleted: {results['database_deleted']}")
        logger.critical(f"2. Data folder deleted: {results['data_folder_deleted']}")
        logger.critical(f"3. Repository deletion scheduled: {results['repository_deleted']}")
        if shutdown_after:
            logger.critical(f"4. System shutdown scheduled: {results['shutdown_scheduled']}")
        logger.critical("=" * 80)
        
        # Return success response before repository is deleted
        return jsonify({
            'success': True,
            'message': 'Kill switch executed successfully. Repository will be deleted in 3 seconds.',
            'details': results,
            'ragnar_path': ragnar_dir,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Fatal error in kill switch: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/api/system/restart-service', methods=['POST'])
def restart_service():
    """Restart the Ragnar service"""
    try:
        import subprocess
        
        # Schedule service restart after a short delay to allow response to be sent
        def restart_service_delayed():
            import time
            time.sleep(2)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'systemctl', 'restart', 'ragnar'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to restart service: {e}")
        
        # Start restart in background thread
        import threading
        threading.Thread(target=restart_service_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'Service restart initiated'
        })
        
    except Exception as e:
        logger.error(f"Error restarting service: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/reboot', methods=['POST'])
def reboot_system():
    """Reboot the entire system"""
    try:
        import subprocess
        
        # Schedule reboot after a short delay to allow response to be sent
        def reboot_delayed():
            import time
            time.sleep(3)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'reboot'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to reboot system: {e}")
        
        # Start reboot in background thread
        import threading
        threading.Thread(target=reboot_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'System reboot initiated'
        })
        
    except Exception as e:
        logger.error(f"Error rebooting system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/shutdown', methods=['POST'])
def shutdown_system():
    """Shut down the entire system"""
    try:
        import subprocess
        
        # Schedule shutdown after a short delay to allow response to be sent
        def shutdown_delayed():
            import time
            time.sleep(3)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'shutdown', '-h', 'now'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to shut down system: {e}")
        
        # Start shutdown in background thread
        import threading
        threading.Thread(target=shutdown_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'System shutdown initiated'
        })
        
    except Exception as e:
        logger.error(f"Error shutting down system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# DATA MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/data/reset-vulnerabilities', methods=['POST'])
def reset_vulnerabilities():
    """
    Reset all vulnerability data - removes all discovered vulnerabilities
    
    IMPORTANT: Network Intelligence is the SINGLE SOURCE OF TRUTH for vulnerabilities.
    - Vulnerabilities are cleared from Network Intelligence (in-memory + JSON files)
    - Legacy CSV files are also cleared for backward compatibility
    - If the same vulnerabilities are found in future scans, they will be 
      automatically re-added to Network Intelligence (auto-repopulation)
    """
    try:
        deleted_count = 0
        
        # SINGLE SOURCE OF TRUTH: Clear Network Intelligence vulnerabilities
        if hasattr(shared_data, 'network_intelligence') and shared_data.network_intelligence:
            try:
                # Count all vulnerabilities across all networks
                if hasattr(shared_data.network_intelligence, 'active_vulnerabilities'):
                    deleted_count = sum(len(vulns) for vulns in shared_data.network_intelligence.active_vulnerabilities.values())
                    shared_data.network_intelligence.active_vulnerabilities.clear()
                    
                    # Also clear resolved vulnerabilities
                    if hasattr(shared_data.network_intelligence, 'resolved_vulnerabilities'):
                        shared_data.network_intelligence.resolved_vulnerabilities.clear()
                    
                    shared_data.network_intelligence.save_intelligence_data()
                    logger.info(f"Cleared {deleted_count} vulnerabilities from Network Intelligence (single source of truth)")
            except Exception as e:
                logger.error(f"Error clearing network intelligence vulnerabilities: {e}")
        
        # Legacy CSV cleanup (DEPRECATED - kept for backward compatibility only)
        # TODO: Remove once all systems read from Network Intelligence
        vuln_summary = os.path.join('data', 'output', 'vulnerabilities', 'vulnerability_summary.csv')
        if os.path.exists(vuln_summary):
            try:
                import pandas as pd
                df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                df.to_csv(vuln_summary, index=False)
                logger.debug("Reset legacy vulnerability summary CSV file")
            except Exception as e:
                logger.error(f"Error resetting vulnerability summary: {e}")
        
        # Clear individual vulnerability scan files (raw nmap output - kept for audit/forensics)
        vuln_dir = os.path.join('data', 'output', 'vulnerabilities')
        if os.path.exists(vuln_dir):
            try:
                for filename in os.listdir(vuln_dir):
                    if filename.startswith('scan_') and filename.endswith('.txt'):
                        file_path = os.path.join(vuln_dir, filename)
                        os.remove(file_path)
                logger.debug("Cleared individual vulnerability scan files")
            except Exception as e:
                logger.error(f"Error clearing vulnerability scan files: {e}")
        
        # CRITICAL: Clear scan history cache so all hosts will be rescanned
        scanned_ports_history_file = os.path.join('data', 'output', 'vulnerabilities', 'scanned_ports_history.json')
        if os.path.exists(scanned_ports_history_file):
            try:
                os.remove(scanned_ports_history_file)
                logger.info("✅ Cleared scan history cache - all hosts will be rescanned on next vulnerability scan")
            except Exception as e:
                logger.error(f"Error clearing scan history cache: {e}")
        
        # Reset vulnerability counter
        shared_data.vulnnbr = 0
        
        # Trigger sync
        sync_vulnerability_count()
        
        logger.info(f"Vulnerability reset complete: {deleted_count} entries removed from Network Intelligence")
        
        return jsonify({
            'success': True,
            'message': f'Vulnerabilities reset successfully. {deleted_count} entries removed.',
            'note': 'If the same vulnerabilities are detected in future scans, they will be automatically re-added.',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"Error resetting vulnerabilities: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/data/reset-threat-intel', methods=['POST'])
def reset_threat_intelligence():
    """Reset all threat intelligence data"""
    try:
        if not threat_intelligence:
            return jsonify({'success': False, 'error': 'Threat intelligence system not available'}), 400
        
        # Clear enriched findings
        findings_cleared = len(threat_intelligence.enriched_findings)
        threat_intelligence.enriched_findings.clear()
        
        # Clear threat cache
        cache_cleared = len(threat_intelligence.threat_cache)
        threat_intelligence.threat_cache.clear()
        
        # Save cleared state
        threat_intelligence.save_enriched_findings()
        threat_intelligence.save_threat_cache()
        
        logger.info(f"Threat intelligence reset: {findings_cleared} findings, {cache_cleared} cache entries cleared")
        
        return jsonify({
            'success': True,
            'message': 'Threat intelligence reset successfully',
            'findings_cleared': findings_cleared,
            'cache_cleared': cache_cleared
        })
        
    except Exception as e:
        logger.error(f"Error resetting threat intelligence: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# WI-FI MANAGEMENT ENDPOINTS
# ============================================================================

def _parse_wifi_interface_arg(raw_value):
    """Validate and sanitize a requested Wi-Fi interface name."""
    if raw_value is None:
        return None
    candidate = str(raw_value).strip()
    if not candidate:
        return None
    if not re.match(r'^[A-Za-z0-9_.:-]+$', candidate):
        raise ValueError("Invalid interface name")
    return candidate


def _gather_wifi_interfaces() -> List[Dict]:
    interfaces = gather_wifi_interfaces(shared_data.config.get('wifi_default_interface', 'wlan0'))
    state = getattr(shared_data, 'multi_interface_state', None)
    if state:
        try:
            state.sync_from_interfaces(interfaces)
        except Exception as exc:
            logger.warning(f"Failed to sync multi-interface state: {exc}")
    return interfaces


def _get_multi_interface_state():
    state = getattr(shared_data, 'multi_interface_state', None)
    if not state:
        raise RuntimeError('Multi-interface state unavailable')
    return state

@app.route('/api/wifi/interfaces')
def get_wifi_interfaces():
    """Get available Wi-Fi interfaces"""
    try:
        interfaces = _gather_wifi_interfaces()
        response = {
            'success': True,
            'interfaces': interfaces
        }
        try:
            response['multi_interface'] = _get_multi_interface_state().get_state_payload()
        except Exception:
            pass
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error getting Wi-Fi interfaces: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'interfaces': [{
                'name': 'wlan0',
                'state': 'UNKNOWN',
                'is_default': True,
                'connected_ssid': None,
                'connection': None,
                'connected': False,
                'ip_address': None,
                'mac_address': None,
            }]
        }), 500

@app.route('/api/wifi/status')
def get_wifi_status():
    """Get Wi-Fi manager status"""
    try:
        try:
            requested_interface = _parse_wifi_interface_arg(request.args.get('interface'))
        except ValueError as invalid_iface:
            return jsonify({'error': str(invalid_iface)}), 400

        try:
            interfaces = _gather_wifi_interfaces()
        except Exception as interface_error:
            logger.error(f"Failed to gather Wi-Fi interfaces: {interface_error}")
            interfaces = [{
                'name': 'wlan0',
                'state': 'UNKNOWN',
                'is_default': True,
                'connected_ssid': None,
                'connection': None,
                'connected': False,
                'ip_address': None,
                'mac_address': None,
            }]

        default_interface = next((iface['name'] for iface in interfaces if iface.get('is_default')), interfaces[0]['name'])
        connected_interface = next((iface['name'] for iface in interfaces if iface.get('connected')), None)
        active_interface = requested_interface or connected_interface or default_interface

        wifi_manager_wrapper = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager_wrapper and hasattr(wifi_manager_wrapper, 'wifi_manager'):
            status = wifi_manager_wrapper.wifi_manager.get_status()
            logger.debug(f"Wi-Fi status from manager: {status}")
        else:
            any_connected = any(iface.get('connected') for iface in interfaces)
            current_ssid = next((iface.get('connected_ssid') for iface in interfaces if iface.get('connected')), None)
            status = {
                'wifi_connected': any_connected,
                'ap_mode_active': False,
                'current_ssid': current_ssid,
                'ap_ssid': None,
                'error': 'Wi-Fi manager not available, using fallback'
            }
            logger.debug(f"Wi-Fi status fallback: {status}")

        selected_interface = next((iface for iface in interfaces if iface['name'] == active_interface), None)
        if selected_interface:
            status['connected_ssid'] = selected_interface.get('connected_ssid')
            status['interface_state'] = selected_interface.get('state')
            status['ip_address'] = selected_interface.get('ip_address')
            status['interface_mac'] = selected_interface.get('mac_address')
            status['interface_connected'] = selected_interface.get('connected')
            status.setdefault('current_ssid', selected_interface.get('connected_ssid'))

        status['interface'] = active_interface
        status['interfaces'] = interfaces
        status['default_interface'] = default_interface
        status.setdefault('wifi_connected', any(iface.get('connected') for iface in interfaces))

        try:
            multi_state = _get_multi_interface_state()
            status['multi_interface'] = multi_state.get_state_payload()
        except Exception as exc:
            logger.debug(f"Multi-interface status unavailable: {exc}")

        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting Wi-Fi status: {e}")
        return jsonify({
            'error': str(e),
            'wifi_connected': False,
            'ap_mode_active': False,
            'current_ssid': None,
            'interface': None,
            'interfaces': []
        }), 500


@app.route('/api/wifi/scan-control', methods=['GET'])
def get_wifi_scan_control():
    try:
        interfaces = _gather_wifi_interfaces()
        state = _get_multi_interface_state()
        payload = state.get_state_payload()
        payload['available_interfaces'] = interfaces
        return jsonify({'success': True, **payload})
    except Exception as exc:
        logger.error(f"Failed to read scan control state: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


def _toggle_scan_interface(enable: bool):
    state = _get_multi_interface_state()
    data = request.get_json(silent=True) or {}
    try:
        interface = _parse_wifi_interface_arg(data.get('interface'))
    except ValueError as invalid_iface:
        return jsonify({'success': False, 'error': str(invalid_iface)}), 400
    if not interface:
        return jsonify({'success': False, 'error': 'interface is required'}), 400

    if enable and not state.is_multi_mode_enabled():
        try:
            state.update_scan_mode(mode=state.MODE_MULTI)
        except Exception as exc:
            logger.warning(f"Unable to switch to multi-interface mode automatically: {exc}")

    updated = state.set_scan_enabled(interface, enable)
    if not updated:
        return jsonify({'success': False, 'error': 'interface not managed'}), 404
    return jsonify({'success': True, 'interface': interface, 'scan_enabled': enable, 'state': updated})


@app.route('/api/wifi/scan-control/start', methods=['POST'])
def enable_wifi_scan_control():
    return _toggle_scan_interface(True)


@app.route('/api/wifi/scan-control/stop', methods=['POST'])
def disable_wifi_scan_control():
    return _toggle_scan_interface(False)


@app.route('/api/wifi/scan-control/mode', methods=['POST'])
def update_wifi_scan_mode():
    state = _get_multi_interface_state()
    payload = request.get_json(silent=True) or {}
    mode = payload.get('mode')
    focus_interface = payload.get('focus_interface')
    try:
        updated = state.update_scan_mode(mode=mode, focus_interface=focus_interface)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error(f"Failed to update scan mode: {exc}")
        return jsonify({'success': False, 'error': 'Unable to update scan mode'}), 500
    return jsonify({'success': True, 'state': updated})


# ==============================================================================
# Ethernet/LAN API Endpoints
# ==============================================================================

@app.route('/api/ethernet/status', methods=['GET'])
def get_ethernet_status():
    """Get current Ethernet interface status."""
    try:
        state = _get_multi_interface_state()
        # Refresh Ethernet interfaces
        state.refresh_ethernet_interfaces()
        status = state.get_ethernet_status()
        # Add ethernet preference setting
        status['prefer_ethernet'] = shared_data.config.get('ethernet_prefer_over_wifi', True)
        return jsonify({'success': True, **status})
    except Exception as exc:
        logger.error(f"Failed to get Ethernet status: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/ethernet/interfaces', methods=['GET'])
def get_ethernet_interfaces():
    """Get all Ethernet interfaces."""
    try:
        default_eth = shared_data.config.get('ethernet_default_interface', 'eth0')
        interfaces = gather_ethernet_interfaces(default_eth)
        return jsonify({
            'success': True,
            'interfaces': interfaces,
            'default_interface': default_eth,
        })
    except Exception as exc:
        logger.error(f"Failed to get Ethernet interfaces: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/ethernet/scan-enabled', methods=['GET'])
def get_ethernet_scan_enabled():
    """Get Ethernet scanning enabled status."""
    try:
        state = _get_multi_interface_state()
        state.refresh_ethernet_interfaces()
        status = state.get_ethernet_status()
        return jsonify({
            'success': True,
            'scan_enabled': status.get('scan_enabled', True),
            'active': status.get('active', False),
            'can_toggle': status.get('can_toggle_scan', False),
            'active_interface': status.get('active_interface'),
        })
    except Exception as exc:
        logger.error(f"Failed to get Ethernet scan status: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/ethernet/scan-enabled', methods=['POST'])
def set_ethernet_scan_enabled():
    """Enable or disable scanning over Ethernet/LAN."""
    try:
        payload = request.get_json(silent=True) or {}
        enabled = payload.get('enabled', True)

        # Validate that we have an active Ethernet connection before enabling
        state = _get_multi_interface_state()
        state.refresh_ethernet_interfaces()
        status = state.get_ethernet_status()

        if enabled and not status.get('active'):
            return jsonify({
                'success': False,
                'error': 'No active Ethernet connection. Cannot enable LAN scanning.',
                'can_toggle': False,
            }), 400

        updated_status = state.set_ethernet_scan_enabled(enabled)
        return jsonify({
            'success': True,
            'scan_enabled': updated_status.get('scan_enabled'),
            'active': updated_status.get('active'),
            'can_toggle': updated_status.get('can_toggle_scan'),
            'message': f"Ethernet scanning {'enabled' if enabled else 'disabled'}",
        })
    except Exception as exc:
        logger.error(f"Failed to set Ethernet scan enabled: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/ethernet/prefer', methods=['POST'])
def set_ethernet_preference():
    """Set whether Ethernet should be preferred over WiFi for scanning."""
    try:
        payload = request.get_json(silent=True) or {}
        prefer = payload.get('prefer', True)

        shared_data.config['ethernet_prefer_over_wifi'] = bool(prefer)
        shared_data.save_config()

        state = _get_multi_interface_state()
        preferred = state.get_preferred_scan_interface()

        return jsonify({
            'success': True,
            'prefer_ethernet': bool(prefer),
            'current_preferred': preferred,
            'message': f"Ethernet {'will be' if prefer else 'will not be'} preferred over WiFi",
        })
    except Exception as exc:
        logger.error(f"Failed to set Ethernet preference: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/network/preferred-interface', methods=['GET'])
def get_preferred_scan_interface():
    """Get the preferred interface for network scanning (Ethernet or WiFi)."""
    try:
        state = _get_multi_interface_state()
        state.refresh_from_system()  # Refresh both WiFi and Ethernet
        preferred = state.get_preferred_scan_interface()
        ethernet_status = state.get_ethernet_status()

        return jsonify({
            'success': True,
            'preferred': preferred,
            'ethernet_available': ethernet_status.get('active', False),
            'ethernet_preferred': shared_data.config.get('ethernet_prefer_over_wifi', True),
            'ethernet_scan_enabled': shared_data.config.get('ethernet_scan_enabled', True),
        })
    except Exception as exc:
        logger.error(f"Failed to get preferred interface: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/wifi/scan', methods=['POST'])
def scan_wifi_networks():
    """Scan for available Wi-Fi networks with AP mode considerations for Pi Zero W2"""
    try:
        payload = request.get_json(silent=True) or {}
        try:
            requested_interface = _parse_wifi_interface_arg(payload.get('interface'))
        except ValueError as invalid_iface:
            return jsonify({'success': False, 'error': str(invalid_iface)}), 400
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            manager = wifi_manager.wifi_manager
            effective_interface = requested_interface or getattr(manager, 'default_wifi_interface', 'wlan0')
            known_networks = []
            try:
                known_networks = manager.get_known_networks()
            except Exception as known_err:
                logger.debug(f"Unable to load known networks during scan: {known_err}")
            # Check if we're in AP mode and handle accordingly
            if manager.ap_mode_active:
                logger.info("Scanning networks while in AP mode (Pi Zero W2 compatible)")
                # Use specialized AP mode scanning
                networks = manager.scan_networks_while_ap(interface=requested_interface)
                
                # Check if we got instructional networks (scan failed)
                if networks and any(net.get('instruction') for net in networks):
                    return jsonify({
                        'networks': networks,
                        'known': known_networks,
                        'warning': 'Live scanning limited in AP mode. Manual entry recommended.',
                        'manual_entry_available': True,
                        'ap_mode': True,
                        'interface': effective_interface
                    })
                else:
                    return jsonify({
                        'networks': networks,
                        'known': known_networks,
                        'success': True,
                        'ap_mode': True,
                        'interface': effective_interface
                    })
            else:
                # Regular scanning when not in AP mode
                networks = manager.scan_networks(interface=requested_interface)
                return jsonify({
                    'networks': networks,
                    'known': known_networks,
                    'success': True,
                    'ap_mode': False,
                    'interface': effective_interface
                })
        else:
            return jsonify({
                'error': 'Wi-Fi manager not available',
                'manual_entry_available': True
            }), 503
    except Exception as e:
        logger.error(f"Error scanning Wi-Fi networks: {e}")
        # Fallback to cached networks if scanning fails
        try:
            wifi_manager = getattr(shared_data, 'ragnar_instance', None)
            if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
                known_networks = wifi_manager.wifi_manager.get_known_networks()
                return jsonify({
                    'networks': known_networks,
                    'known': known_networks,
                    'warning': 'Live scan failed, showing known networks only',
                    'manual_entry_available': True
                })
        except Exception:
            pass
        
        return jsonify({
            'networks': [],
            'known': [],
            'error': 'Scanning failed',
            'manual_entry_available': True
        }), 500

@app.route('/api/wifi/networks')
def get_wifi_networks():
    """Get available and known Wi-Fi networks - optimized for Pi Zero W2 AP mode"""
    try:
        try:
            requested_interface = _parse_wifi_interface_arg(request.args.get('interface'))
        except ValueError as invalid_iface:
            return jsonify({'success': False, 'error': str(invalid_iface)}), 400
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            manager = wifi_manager.wifi_manager
            effective_interface = requested_interface or getattr(manager, 'default_wifi_interface', 'wlan0')
            
            # For captive portal/AP clients, use lightweight response
            if is_ap_client_request():
                logger.info("Serving networks to AP client - using optimized response")
                try:
                    if manager.ap_mode_active:
                        available = manager.scan_networks_while_ap(interface=requested_interface)
                    else:
                        available = manager.get_available_networks(interface=requested_interface or '')
                    
                    # Limit to top 10 strongest signals to reduce memory usage on Pi Zero W2
                    if available:
                        # Filter out instructional networks for API response
                        real_networks = [net for net in available if not net.get('instruction')]
                        if real_networks:
                            available = sorted(real_networks, 
                                             key=lambda x: x.get('signal', 0), 
                                             reverse=True)[:10]
                        else:
                            # If only instructional networks, include them
                            available = available[:3]  # Just the top instructions
                    
                    return jsonify({
                        'success': True,
                        'networks': available if available else [],
                        'ap_mode': manager.ap_mode_active,
                        'manual_entry_available': True,
                        'interface': effective_interface
                    })
                except Exception as e:
                    logger.warning(f"Limited scan failed for AP client: {e}")
                    # Fallback to known networks for AP clients
                    known_networks = manager.get_known_networks()
                    return jsonify({
                        'success': True,
                        'networks': known_networks[:5],  # Limit for memory
                        'error': 'Scanning limited in AP mode',
                        'manual_entry_available': True,
                        'ap_mode': True,
                        'interface': effective_interface
                    })
            else:
                # Full response for regular interface
                try:
                    if manager.ap_mode_active:
                        available = manager.scan_networks_while_ap(interface=requested_interface)
                    else:
                        available = manager.get_available_networks(interface=requested_interface or '')
                    
                    known = manager.get_known_networks()
                    
                    return jsonify({
                        'success': True,
                        'available': available,
                        'known': known,
                        'ap_mode': manager.ap_mode_active,
                        'manual_entry_available': True,
                        'interface': effective_interface
                    })
                except Exception as e:
                    logger.warning(f"Network scan failed: {e}")
                    # Fallback to known networks only
                    known = manager.get_known_networks()
                    return jsonify({
                        'success': True,
                        'available': [],
                        'known': known,
                        'error': 'Scanning failed, showing known networks only',
                        'manual_entry_available': True,
                        'interface': effective_interface
                    })
        else:
            return jsonify({
                'success': False,
                'networks': [],
                'available': [], 
                'known': [],
                'manual_entry_available': True,
                'error': 'Wi-Fi manager not available'
            })
    except Exception as e:
        logger.error(f"Error getting Wi-Fi networks: {e}")
        return jsonify({
            'success': False, 
            'error': str(e),
            'manual_entry_available': True,
            'networks': [],
            'available': [],
            'known': []
        }), 500

@app.route('/api/wifi/connect', methods=['POST'])
def connect_wifi():
    """Connect to a Wi-Fi network"""
    try:
        data = request.get_json()
        if not data or 'ssid' not in data:
            return jsonify({'success': False, 'error': 'SSID is required'}), 400
        
        ssid = data['ssid']
        password = data.get('password')
        priority = data.get('priority', 1)
        save_network = data.get('save', True)
        
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'success': False, 'error': 'Wi-Fi manager not available'}), 503
        
        # Log the connection attempt
        logger.info(f"API: Attempting to connect to WiFi network: {ssid}")
        
        # Check if currently in AP mode
        was_in_ap_mode = wifi_manager.wifi_manager.ap_mode_active
        if was_in_ap_mode:
            logger.info(f"API: Currently in AP mode, will stop AP before connecting to {ssid}")
        
        # Try to connect
        success = wifi_manager.wifi_manager.connect_to_network(ssid, password)
        
        if success:
            logger.info(f"API: Successfully connected to {ssid}")
            # Add to known networks if connection successful and save requested
            if save_network:
                wifi_manager.wifi_manager.add_known_network(ssid, password, priority)
            
            message = 'Connected successfully'
            if is_ap_client_request():
                message = 'Connected successfully! Ragnar will now use this network. You can disconnect from this AP.'
        else:
            logger.error(f"API: Failed to connect to {ssid}")
            message = 'Connection failed. Please check the password and try again.'
            if was_in_ap_mode:
                message += ' Note: AP mode was stopped to attempt connection.'
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        logger.error(f"Error connecting to Wi-Fi: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wifi/disconnect', methods=['POST'])
def disconnect_wifi():
    """Disconnect from current Wi-Fi network"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        # Stop any active connection and start AP mode
        result = wifi_manager.wifi_manager.start_ap_mode()
        
        return jsonify({
            'success': result,
            'message': 'Disconnected and started AP mode' if result else 'Failed to start AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error disconnecting Wi-Fi: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/exit-ap', methods=['POST'])
def exit_ap_mode():
    """Exit AP mode and reconnect to WiFi"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'success': False, 'error': 'Wi-Fi manager not available'}), 503
        
        # Use the existing method to exit AP mode from web interface
        result = wifi_manager.wifi_manager.exit_ap_mode_from_web()
        
        return jsonify({
            'success': result,
            'message': 'Exiting AP mode and reconnecting to WiFi' if result else 'Failed to exit AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error exiting AP mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wifi/forget', methods=['POST'])
def forget_wifi_network():
    """Remove a network from known networks"""
    try:
        data = request.get_json()
        if not data or 'ssid' not in data:
            return jsonify({'error': 'SSID is required'}), 400
        
        ssid = data['ssid']
        
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.remove_known_network(ssid)
        
        return jsonify({
            'success': success,
            'message': 'Network forgotten' if success else 'Network not found'
        })
        
    except Exception as e:
        logger.error(f"Error forgetting Wi-Fi network: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/enable', methods=['POST'])
def enable_wifi_ap_mode():
    """Enable Wi-Fi Access Point mode with smart cycling"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        # Use the smart AP mode with cycling
        success = wifi_manager.wifi_manager.enable_ap_mode_from_web()
        
        ap_config = {
            'ssid': wifi_manager.wifi_manager.ap_ssid,
            'timeout': wifi_manager.wifi_manager.ap_timeout,
            'cycling': wifi_manager.wifi_manager.ap_cycle_enabled
        }
        
        return jsonify({
            'success': success,
            'message': 'Smart AP mode enabled with 3-minute cycling' if success else 'Failed to enable AP mode',
            'ap_config': ap_config
        })
        
    except Exception as e:
        logger.error(f"Error enabling Wi-Fi AP mode: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/start', methods=['POST'])
def start_wifi_ap():
    """Start Wi-Fi Access Point mode"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.start_ap_mode()
        
        return jsonify({
            'success': success,
            'message': 'AP mode started' if success else 'Failed to start AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error starting Wi-Fi AP: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/stop', methods=['POST'])
def stop_wifi_ap():
    """Stop Wi-Fi Access Point mode"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.stop_ap_mode()
        
        return jsonify({
            'success': success,
            'message': 'AP mode stopped' if success else 'Failed to stop AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error stopping Wi-Fi AP: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/reconnect', methods=['POST'])
def reconnect_wifi():
    """Force Wi-Fi reconnection attempt"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.force_reconnect()
        
        return jsonify({
            'success': success,
            'message': 'Reconnection attempt initiated' if success else 'Reconnection failed'
        })
        
    except Exception as e:
        logger.error(f"Error reconnecting Wi-Fi: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/exit', methods=['POST'])
def exit_wifi_ap_mode():
    """Exit AP mode and start WiFi search (Endless Loop)"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        # Use the new exit AP mode function for endless loop
        success = wifi_manager.wifi_manager.exit_ap_mode_from_web()
        
        return jsonify({
            'success': success,
            'message': 'Exiting AP mode and starting WiFi search...' if success else 'Failed to exit AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error exiting Wi-Fi AP mode: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/force-recovery', methods=['POST'])
def force_wifi_recovery():
    """Force WiFi recovery - stop AP mode and aggressively search for known networks"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        wm = wifi_manager.wifi_manager
        
        # Stop AP mode if active
        if wm.ap_mode_active:
            logger.info("Force recovery: Stopping AP mode")
            wm.stop_ap_mode()
            time.sleep(2)  # Give time for AP to shut down properly
        
        # Force a WiFi search
        logger.info("Force recovery: Starting aggressive WiFi search")
        wm.wifi_validation_failures = 0
        wm.consecutive_validation_cycles_failed = 0
        
        # Try to connect in a separate thread to avoid blocking
        def attempt_reconnect():
            success = wm._endless_loop_wifi_search()
            if success:
                logger.info("Force recovery: Successfully reconnected to WiFi")
            else:
                logger.warning("Force recovery: Failed to reconnect to WiFi")
        
        recovery_thread = threading.Thread(target=attempt_reconnect, daemon=True)
        recovery_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'WiFi recovery initiated - searching for known networks...'
        })
        
    except Exception as e:
        logger.error(f"Error forcing WiFi recovery: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/log')
def get_wifi_log():
    """Get comprehensive WiFi logs including system status, Ragnar WiFi manager, and e-paper display updates"""
    try:
        wifi_log_data = {
            'timestamp': datetime.now().isoformat(),
            'system_wifi': {},
            'ragnar_wifi_manager': {},
            'epaper_display': {}
        }
        
        # === SYSTEM WIFI STATUS ===
        try:
            wifi_log_data['system_wifi'] = {}
            
            # Get SSID
            try:
                result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True, timeout=3)
                wifi_log_data['system_wifi']['ssid'] = result.stdout.strip() if result.returncode == 0 else None
                wifi_log_data['system_wifi']['connected'] = result.returncode == 0 and result.stdout.strip()
            except Exception as e:
                wifi_log_data['system_wifi']['ssid_error'] = str(e)
            
            # Get IP address
            try:
                result = subprocess.run(['ip', 'addr', 'show', 'wlan0'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    wifi_log_data['system_wifi']['ip_address'] = ip_match.group(1) if ip_match else None
                    wifi_log_data['system_wifi']['interface_up'] = 'state UP' in result.stdout
                else:
                    wifi_log_data['system_wifi']['interface_error'] = f"Exit code: {result.returncode}"
            except Exception as e:
                wifi_log_data['system_wifi']['interface_error'] = str(e)
                
        except Exception as e:
            wifi_log_data['system_wifi']['error'] = str(e)
        
        # === RAGNAR WIFI MANAGER STATUS ===
        try:
            if (hasattr(shared_data, 'ragnar_instance') and 
                shared_data.ragnar_instance and 
                hasattr(shared_data.ragnar_instance, 'wifi_manager')):
                
                wifi_mgr = shared_data.ragnar_instance.wifi_manager
                wifi_log_data['ragnar_wifi_manager'] = {
                    'wifi_connected': getattr(wifi_mgr, 'wifi_connected', False),
                    'ap_mode_active': getattr(wifi_mgr, 'ap_mode_active', False),
                    'cycling_mode': getattr(wifi_mgr, 'cycling_mode', False),
                    'current_ssid': getattr(wifi_mgr, 'current_ssid', None),
                    'connection_attempts': getattr(wifi_mgr, 'connection_attempts', 0),
                    'ap_clients_count': getattr(wifi_mgr, 'ap_clients_count', 0)
                }
            else:
                wifi_log_data['ragnar_wifi_manager']['error'] = "WiFi manager not available"
                
        except Exception as e:
            wifi_log_data['ragnar_wifi_manager']['error'] = str(e)
        
        # === E-PAPER DISPLAY WIFI STATUS ===
        try:
            if (hasattr(shared_data, 'ragnar_instance') and 
                shared_data.ragnar_instance and 
                hasattr(shared_data.ragnar_instance, 'display')):
                
                display = shared_data.ragnar_instance.display
                wifi_log_data['epaper_display'] = {
                    'wifi_status_text': display.get_wifi_status_text(),
                    'is_wifi_connected': display.is_wifi_connected()
                }
            else:
                wifi_log_data['epaper_display']['error'] = "Display not available"
                
        except Exception as e:
            wifi_log_data['epaper_display']['error'] = str(e)
        
        return jsonify(wifi_log_data)
        
    except Exception as e:
        logger.error(f"Error getting WiFi logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/epaper-display')
def get_epaper_display():
    """Get current e-paper display image as base64"""
    try:
        from PIL import Image
        
        # Look for the current display image saved by display.py
        display_image_path = os.path.join(shared_data.webdir, "screen.png")
        
        if os.path.exists(display_image_path):
            # Read and encode the image
            with Image.open(display_image_path) as img:
                orig_w, orig_h = img.size

                # Convert to RGB if needed
                if img.mode != 'RGB':
                    img = img.convert('RGB')

                # Upscale small e-paper images so they aren't pixelated
                # in the browser. Target: shortest side >= 600px.
                MIN_DIM = 600
                if min(orig_w, orig_h) < MIN_DIM:
                    scale = max(MIN_DIM / orig_w, MIN_DIM / orig_h)
                    scale = int(scale) if scale == int(scale) else int(scale) + 1
                    if scale >= 2:
                        img = img.resize(
                            (orig_w * scale, orig_h * scale),
                            Image.NEAREST,
                        )

                # Save to bytes
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='PNG')
                img_byte_arr = img_byte_arr.getvalue()
                
                # Encode to base64
                img_base64 = base64.b64encode(img_byte_arr).decode('utf-8')
                
                return jsonify({
                    'image': f"data:image/png;base64,{img_base64}",
                    'timestamp': int(os.path.getctime(display_image_path)),
                    'width': orig_w,
                    'height': orig_h,
                    'status_text': safe_str(shared_data.ragnarstatustext),
                    'status_text2': safe_str(shared_data.ragnarstatustext2)
                })
        
        # If no image found, return status only
        return jsonify({
            'image': None,
            'message': 'No e-paper display image available',
            'timestamp': int(time.time()),
            'status_text': safe_str(shared_data.ragnarstatustext),
            'status_text2': safe_str(shared_data.ragnarstatustext2)
        })
        
    except Exception as e:
        logger.error(f"Error getting e-paper display: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/display')
def get_display():
    """Get current EPD display image"""
    try:
        # Return the current display status image
        image_path = os.path.join(shared_data.picdir, 'current_display.png')
        if os.path.exists(image_path):
            return send_from_directory(shared_data.picdir, 'current_display.png')
        return jsonify({'error': 'Display image not found'}), 404
    except Exception as e:
        logger.error(f"Error getting display: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# BLUETOOTH MANAGEMENT ENDPOINTS
# ============================================================================

# Import the Bluetooth manager
try:
    from actions.ble import BluetoothManager
    bluetooth_manager = BluetoothManager(logger)
    BLUETOOTH_AVAILABLE = True
    logger.info("Bluetooth manager loaded successfully")
except ImportError as e:
    logger.warning(f"Bluetooth manager not available: {e}")
    bluetooth_manager = None
    BLUETOOTH_AVAILABLE = False
except Exception as e:
    logger.error(f"Error initializing Bluetooth manager: {e}")
    bluetooth_manager = None
    BLUETOOTH_AVAILABLE = False

# Import the Bluetooth pentest module
try:
    from actions.ble_pentest import BluetoothPentest
    bluetooth_pentest = BluetoothPentest(logger)
    BLUETOOTH_PENTEST_AVAILABLE = True
    logger.info("Bluetooth pentest module loaded successfully")
except ImportError as e:
    logger.warning(f"Bluetooth pentest module not available: {e}")
    bluetooth_pentest = None
    BLUETOOTH_PENTEST_AVAILABLE = False
except Exception as e:
    logger.error(f"Error initializing Bluetooth pentest module: {e}")
    bluetooth_pentest = None
    BLUETOOTH_PENTEST_AVAILABLE = False

@app.route('/api/bluetooth/status')
def get_bluetooth_status():
    """Get current Bluetooth status"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'error': 'Bluetooth manager not available', 'enabled': False}), 503
            
        status = bluetooth_manager.get_status()
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting Bluetooth status: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500

@app.route('/api/bluetooth/enable', methods=['POST'])
def enable_bluetooth():
    """Enable Bluetooth"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.power_on()
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error enabling Bluetooth: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/disable', methods=['POST'])
def disable_bluetooth():
    """Disable Bluetooth"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.power_off()
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error disabling Bluetooth: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/discoverable/on', methods=['POST'])
def make_bluetooth_discoverable():
    """Make Bluetooth discoverable"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.set_discoverable(True)
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error making Bluetooth discoverable: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/discoverable/off', methods=['POST'])
def hide_bluetooth_device():
    """Hide Bluetooth device (make non-discoverable)"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.set_discoverable(False)
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error hiding Bluetooth device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/scan/start', methods=['POST'])
def start_bluetooth_scan():
    """Start Bluetooth device scan"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        data = request.get_json() or {}
        duration = data.get('duration', None)
        
        success, message = bluetooth_manager.start_scan(duration)
        
        if success:
            # Update shared data for compatibility
            shared_data.bluetooth_scan_active = True
            shared_data.bluetooth_scan_start_time = time.time()
        
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error starting Bluetooth scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/scan/stop', methods=['POST'])
def stop_bluetooth_scan():
    """Stop Bluetooth device scan"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.stop_scan()
        
        if success:
            # Update shared data for compatibility
            shared_data.bluetooth_scan_active = False
        
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error stopping Bluetooth scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/devices')
def get_bluetooth_devices():
    """Get discovered Bluetooth devices"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'devices': [], 'error': 'Bluetooth manager not available'})
            
        devices = bluetooth_manager.get_discovered_devices()
        
        # Convert to list format for API compatibility
        device_list = list(devices.values())
        
        return jsonify({'devices': device_list})
        
    except Exception as e:
        logger.error(f"Error getting Bluetooth devices: {e}")
        return jsonify({'devices': [], 'error': str(e)})

@app.route('/api/bluetooth/pair', methods=['POST'])
def pair_bluetooth_device():
    """Pair with a Bluetooth device"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        data = request.get_json()
        address = data.get('address') if data else None
        
        if not address:
            return jsonify({'success': False, 'error': 'Device address required'}), 400
        
        success, message = bluetooth_manager.pair_device(address)
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error pairing Bluetooth device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/unpair', methods=['POST'])
def unpair_bluetooth_device():
    """Unpair a Bluetooth device"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        data = request.get_json()
        address = data.get('address') if data else None
        
        if not address:
            return jsonify({'success': False, 'error': 'Device address required'}), 400
        
        success, message = bluetooth_manager.unpair_device(address)
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error unpairing Bluetooth device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/enumerate', methods=['POST'])
def enumerate_bluetooth_services():
    """Enumerate services on a Bluetooth device"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        data = request.get_json()
        address = data.get('address') if data else None
        
        if not address:
            return jsonify({'success': False, 'error': 'Device address required'}), 400
        
        # Get detailed device info which includes services
        device_details = bluetooth_manager._get_device_details(address)
        services = device_details.get('services', [])
        
        return jsonify({'success': True, 'services': services})
        
    except Exception as e:
        logger.error(f"Error enumerating Bluetooth services: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/diagnose', methods=['GET'])
def diagnose_bluetooth():
    """Diagnose Bluetooth scanning issues"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'error': 'Bluetooth manager not available'}), 503
            
        diagnosis = bluetooth_manager.diagnose_scanning()
        return jsonify(diagnosis)
        
    except Exception as e:
        logger.error(f"Error diagnosing Bluetooth: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# BLUETOOTH PENTEST ENDPOINTS
# ============================================================================

@app.route('/api/bluetooth/pentest/beacon-track', methods=['POST'])
def pentest_beacon_track():
    """Start beacon tracking"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        data = request.get_json() or {}
        duration = data.get('duration', 60)
        
        beacons = bluetooth_pentest.start_beacon_tracking(duration)
        
        return jsonify({
            'success': True,
            'beacons_found': len(beacons),
            'beacons': beacons
        })
        
    except Exception as e:
        logger.error(f"Error tracking beacons: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bluetooth/pentest/exfiltrate', methods=['POST'])
def pentest_exfiltrate():
    """Exfiltrate data from target device"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target MAC address required'}), 400
        
        result = bluetooth_pentest.exfiltrate_device_info(target)
        
        if result:
            return jsonify(result)
        else:
            return jsonify({'error': 'Exfiltration failed'}), 500
        
    except Exception as e:
        logger.error(f"Error exfiltrating data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bluetooth/pentest/blueborne-scan', methods=['POST'])
def pentest_blueborne():
    """Scan for BlueBorne vulnerabilities"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target MAC address required'}), 400
        
        result = bluetooth_pentest.blueborne_scan(target)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error scanning for BlueBorne: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bluetooth/pentest/track-movement', methods=['POST'])
def pentest_track_movement():
    """Track device movement via RSSI"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        data = request.get_json() or {}
        target = data.get('target')
        duration = data.get('duration', 300)
        
        if not target:
            return jsonify({'error': 'Target MAC address required'}), 400
        
        readings = bluetooth_pentest.track_device_movement(target, duration)
        
        return jsonify({
            'success': True,
            'target': target,
            'duration': duration,
            'readings': readings
        })
        
    except Exception as e:
        logger.error(f"Error tracking movement: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bluetooth/pentest/report', methods=['GET'])
def pentest_get_report():
    """Get comprehensive pentest report"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        report = bluetooth_pentest.generate_report()
        
        return jsonify(report)
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/actions', methods=['GET'])
def get_actions():
    """Get available actions"""
    try:
        with open(shared_data.actions_file, 'r') as f:
            actions = json.load(f)
        return jsonify(actions)
    except Exception as e:
        logger.error(f"Error getting actions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get vulnerability scan results"""
    try:
        # Check if network intelligence is enabled
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Get network-aware findings for dashboard
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            
            # Convert to legacy format for compatibility
            vuln_data = []
            for vuln_id, vuln_info in dashboard_findings['vulnerabilities'].items():
                vuln_data.append({
                    'id': vuln_id,
                    'host': vuln_info['host'],
                    'port': vuln_info['port'],
                    'service': vuln_info['service'],
                    'vulnerability': vuln_info['vulnerability'],
                    'severity': vuln_info['severity'],
                    'discovered': vuln_info['discovered'],
                    'network_id': vuln_info['network_id'],
                    'status': vuln_info['status']
                })
            
            return jsonify({
                'vulnerabilities': vuln_data,
                'network_context': {
                    'current_network': dashboard_findings['network_id'],
                    'count': dashboard_findings['counts']['vulnerabilities']
                }
            })
        else:
            # Fallback to legacy vulnerability data
            vuln_data = web_utils.get_vulnerability_data()
            return jsonify(vuln_data)
            
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-intelligence')
def get_network_intelligence():
    """Get network intelligence summary and findings"""
    try:
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Update network context
            shared_data.network_intelligence.update_network_context()
            
            # Get network summary
            summary = shared_data.network_intelligence.get_network_summary()
            
            # Get active findings for dashboard
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            
            # Get all findings for NetKB
            netkb_findings = shared_data.network_intelligence.get_all_findings_for_netkb()
            
            return jsonify({
                'enabled': True,
                'network_summary': summary,
                'dashboard_findings': dashboard_findings,
                'netkb_findings': netkb_findings,
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'enabled': False,
                'message': 'Network intelligence is disabled or unavailable'
            })
            
    except Exception as e:
        logger.error(f"Error getting network intelligence: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerabilities/grouped')
def get_vulnerabilities_grouped():
    """Get vulnerabilities grouped by IP address with summary statistics.

    Query param: status=open|resolved|all (default: open)
    """
    try:
        status_filter = request.args.get('status', 'open').lower()
        if status_filter not in ('open', 'resolved', 'all'):
            status_filter = 'open'

        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Get filtered vulnerabilities for dashboard
            vulnerabilities = shared_data.network_intelligence.get_vulnerabilities_for_network(status_filter)
            network_id = shared_data.network_intelligence.get_current_network_id()
            
            # Group vulnerabilities by host IP
            grouped = {}
            for vuln_id, vuln_info in vulnerabilities.items():
                host = vuln_info['host']
                
                if host not in grouped:
                    grouped[host] = {
                        'ip': host,
                        'total_vulnerabilities': 0,
                        'severity_counts': {
                            'critical': 0,
                            'high': 0,
                            'medium': 0,
                            'low': 0
                        },
                        'affected_ports': set(),
                        'affected_services': set(),
                        'vulnerabilities': []
                    }
                
                # Increment counts
                grouped[host]['total_vulnerabilities'] += 1
                severity = vuln_info.get('severity', 'medium')
                if severity in grouped[host]['severity_counts']:
                    grouped[host]['severity_counts'][severity] += 1
                
                # Track ports and services
                grouped[host]['affected_ports'].add(vuln_info['port'])
                grouped[host]['affected_services'].add(vuln_info['service'])
                
                # Add vulnerability detail
                grouped[host]['vulnerabilities'].append({
                    'id': vuln_id,
                    'port': vuln_info['port'],
                    'service': vuln_info['service'],
                    'vulnerability': vuln_info['vulnerability'],
                    'severity': severity,
                    'discovered': vuln_info['discovered'],
                    'status': vuln_info.get('status', 'active'),
                    'resolved': vuln_info.get('resolved')
                })
            
            # Convert sets to lists for JSON serialization
            for host_data in grouped.values():
                host_data['affected_ports'] = sorted(list(host_data['affected_ports']))
                host_data['affected_services'] = sorted(list(host_data['affected_services']))
                # Sort vulnerabilities by severity
                severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                host_data['vulnerabilities'].sort(
                    key=lambda v: severity_order.get(v['severity'], 4)
                )
            
            # Convert to list and sort by total vulnerability count
            grouped_list = sorted(
                grouped.values(),
                key=lambda x: x['total_vulnerabilities'],
                reverse=True
            )
            
            return jsonify({
                'grouped_vulnerabilities': grouped_list,
                'total_hosts': len(grouped_list),
                'total_vulnerabilities': sum(len(h['vulnerabilities']) for h in grouped_list),
                'network_context': {
                    'current_network': network_id,
                    'network_name': 'Unknown',
                    'status_filter': status_filter
                }
            })
        else:
            return jsonify({'error': 'Network intelligence not available'}), 503
            
    except Exception as e:
        logger.error(f"Error getting grouped vulnerabilities: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/credentials')
def get_credentials_api():
    """Get credential data with network intelligence if available"""
    try:
        # Check if network intelligence is enabled
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Get network-aware findings for dashboard
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            
            # Convert to legacy format for compatibility
            cred_data = []
            for cred_id, cred_info in dashboard_findings['credentials'].items():
                cred_data.append({
                    'id': cred_id,
                    'host': cred_info['host'],
                    'service': cred_info['service'],
                    'username': cred_info['username'],
                    'password': cred_info['password'],
                    'protocol': cred_info['protocol'],
                    'discovered': cred_info['discovered'],
                    'network_id': cred_info['network_id'],
                    'status': cred_info['status']
                })
            
            return jsonify({
                'credentials': cred_data,
                'network_context': {
                    'current_network': dashboard_findings['network_id'],
                    'count': dashboard_findings['counts']['credentials']
                }
            })
        else:
            # Fallback to legacy credential data - just return empty structure
            return jsonify({
                'credentials': [],
                'network_context': {
                    'current_network': 'legacy',
                    'count': 0
                }
            })
            
    except Exception as e:
        logger.error(f"Error getting credentials: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-intelligence/add-vulnerability', methods=['POST'])
def add_vulnerability():
    """Add a new vulnerability finding"""
    try:
        if not (hasattr(shared_data, 'network_intelligence') and 
                shared_data.network_intelligence and 
                shared_data.config.get('network_intelligence_enabled', True)):
            return jsonify({'error': 'Network intelligence not available'}), 400
        
        data = request.get_json()
        required_fields = ['host', 'port', 'service', 'vulnerability']
        
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        vuln_id = shared_data.network_intelligence.add_vulnerability(
            host=data['host'],
            port=data['port'],
            service=data['service'],
            vulnerability=data['vulnerability'],
            severity=data.get('severity', 'medium'),
            details=data.get('details', {})
        )
        
        if vuln_id:
            # Trigger sync and broadcast update
            sync_all_counts()
            broadcast_status_update()
            
            return jsonify({
                'success': True,
                'vulnerability_id': vuln_id,
                'message': 'Vulnerability added successfully'
            })
        else:
            return jsonify({'error': 'Failed to add vulnerability'}), 500
            
    except Exception as e:
        logger.error(f"Error adding vulnerability: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-intelligence/add-credential', methods=['POST'])
def add_credential():
    """Add a new credential finding"""
    try:
        if not (hasattr(shared_data, 'network_intelligence') and 
                shared_data.network_intelligence and 
                shared_data.config.get('network_intelligence_enabled', True)):
            return jsonify({'error': 'Network intelligence not available'}), 400
        
        data = request.get_json()
        required_fields = ['host', 'service', 'username', 'password']
        
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        cred_id = shared_data.network_intelligence.add_credential(
            host=data['host'],
            service=data['service'],
            username=data['username'],
            password=data['password'],
            protocol=data.get('protocol', 'unknown'),
            details=data.get('details', {})
        )
        
        if cred_id:
            # Trigger sync and broadcast update
            sync_all_counts()
            broadcast_status_update()
            
            return jsonify({
                'success': True,
                'credential_id': cred_id,
                'message': 'Credential added successfully'
            })
        else:
            return jsonify({'error': 'Failed to add credential'}), 500
            
    except Exception as e:
        logger.error(f"Error adding credential: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
def get_stats():
    """Get aggregated statistics"""
    try:
        # Get database stats
        db_stats = {}
        try:
            db_stats = shared_data.db.get_stats()
        except Exception as e:
            logger.warning(f"Could not get database stats: {e}")
        
        # Build comprehensive stats object with multiple naming conventions for frontend compatibility
        stats = {
            # Target counts (multiple naming conventions for compatibility)
            'active_target_count': safe_int(shared_data.targetnbr),
            'target_count': safe_int(shared_data.targetnbr),
            'total_targets': safe_int(shared_data.targetnbr),
            
            'inactive_target_count': safe_int(shared_data.inactive_targetnbr),
            'offline_target_count': safe_int(shared_data.inactive_targetnbr),
            
            'total_target_count': safe_int(shared_data.total_targetnbr),
            'all_targets': safe_int(shared_data.total_targetnbr),
            
            'new_target_count': safe_int(shared_data.new_targets),
            'new_targets': safe_int(shared_data.new_targets),
            'new_target_ips': shared_data.new_target_ips if hasattr(shared_data, 'new_target_ips') else [],
            
            'lost_target_count': safe_int(shared_data.lost_targets),
            'lost_targets': safe_int(shared_data.lost_targets),
            'lost_target_ips': shared_data.lost_target_ips if hasattr(shared_data, 'lost_target_ips') else [],
            
            # Port counts
            'port_count': safe_int(shared_data.portnbr),
            'open_port_count': safe_int(shared_data.portnbr),
            'total_ports': safe_int(shared_data.portnbr),
            
            # Vulnerability counts
            'vulnerability_count': safe_int(shared_data.vulnnbr),
            'vuln_count': safe_int(shared_data.vulnnbr),
            'total_vulnerabilities': safe_int(shared_data.vulnnbr),
            'vulnerable_hosts_count': safe_int(db_stats.get('vulnerable_hosts', 0)),
            'vulnerable_host_count': safe_int(db_stats.get('vulnerable_hosts', 0)),
            
            # Credential counts
            'credential_count': safe_int(shared_data.crednbr),
            'cred_count': safe_int(shared_data.crednbr),
            'total_credentials': safe_int(shared_data.crednbr),
            
            # Gamification
            'level': safe_int(shared_data.levelnbr),
            'levelnbr': safe_int(shared_data.levelnbr),
            'points': safe_int(shared_data.coinnbr),
            'coins': safe_int(shared_data.coinnbr),
            
            # Other counts
            'total_data_stolen': safe_int(shared_data.datanbr),
            'scan_results_count': safe_int(db_stats.get('alive_count', 0)),
            'services_discovered': {},
            
            # Last sync timestamp
            'last_sync': shared_data.last_sync_timestamp if hasattr(shared_data, 'last_sync_timestamp') else None
        }
        
        # Add threat intelligence stats
        if threat_intelligence:
            ti_stats = threat_intelligence.get_enriched_findings_summary()
            stats.update(ti_stats)
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ============================================================================
# THREAT INTELLIGENCE ENDPOINTS
# ============================================================================

def _serialize_enriched_finding(finding_id, enriched_finding, default_last_update=None):
    """Serialize enriched finding details for the modern web UI."""
    original = enriched_finding.original_finding or {}

    target = (
        original.get('host')
        or original.get('ip')
        or original.get('target')
        or original.get('id')
        or finding_id
    )

    primary_context = enriched_finding.threat_contexts[0] if enriched_finding.threat_contexts else None
    threat_context = 'No additional context available'
    last_seen = None

    if primary_context:
        threat_context = primary_context.description or primary_context.threat_type or threat_context
        last_seen = primary_context.last_seen or primary_context.first_seen

    if not last_seen:
        last_seen = (
            original.get('timestamp')
            or original.get('last_seen')
            or default_last_update
        )

    attribution = None
    if enriched_finding.attribution and enriched_finding.attribution.actor_name:
        confidence = enriched_finding.attribution.confidence
        if confidence:
            attribution = f"{enriched_finding.attribution.actor_name} ({int(round(confidence * 100))}% confidence)"
        else:
            attribution = enriched_finding.attribution.actor_name

    summary = (enriched_finding.executive_summary or '').strip()
    if summary and len(summary) > 160:
        summary = summary[:157] + '...'

    risk_score = int(round(min(enriched_finding.dynamic_risk_score or 0.0, 10.0) * 10))

    return {
        'id': finding_id,
        'target': target,
        'risk_score': risk_score,
        'threat_context': threat_context,
        'attribution': attribution,
        'last_updated': last_seen,
        'summary': summary,
        'last_seen': last_seen
    }


@app.route('/api/threat-intelligence/status')
def get_threat_intelligence_status():
    """Get threat intelligence system status"""
    with _network_context_from_request():
        try:
            if not threat_intelligence:
                return jsonify({'error': 'Threat intelligence system not available'}), 503

            summary = threat_intelligence.get_enriched_findings_summary() or {}
            default_last_update = summary.get('last_intelligence_update')

            serialized_findings = [
                _serialize_enriched_finding(finding_id, enriched_finding, default_last_update)
                for finding_id, enriched_finding in threat_intelligence.enriched_findings.items()
            ]

            risk_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            active_campaigns = set()

            for enriched_finding in threat_intelligence.enriched_findings.values():
                score = enriched_finding.dynamic_risk_score or 0.0
                if score >= 9.0:
                    risk_distribution['critical'] += 1
                elif score >= 7.0:
                    risk_distribution['high'] += 1
                elif score >= 4.0:
                    risk_distribution['medium'] += 1
                else:
                    risk_distribution['low'] += 1

                for campaign in enriched_finding.active_campaigns or []:
                    if campaign:
                        active_campaigns.add(campaign)

            type_to_status_key = {
                'cisa': 'cisa_kev',
                'nvd': 'nvd_cve',
                'otx': 'alienvault_otx',
                'mitre': 'mitre_attack'
            }

            source_status = {key: False for key in type_to_status_key.values()}
            sources = []
            for name, source in threat_intelligence.threat_sources.items():
                sources.append({
                    'name': name,
                    'type': source.type,
                    'enabled': source.enabled,
                    'confidence_weight': source.confidence_weight,
                    'last_updated': source.last_updated
                })

                status_key = type_to_status_key.get(source.type)
                if status_key:
                    source_status[status_key] = source_status.get(status_key, False) or source.enabled

            top_threats = sorted(serialized_findings, key=lambda f: f['risk_score'], reverse=True)[:5]

            total_enriched = summary.get('total_enriched_findings', len(serialized_findings))
            high_risk_total = risk_distribution['critical'] + risk_distribution['high']

            status = {
                'enabled': True,
                'active_sources': summary.get('threat_sources_enabled', 0),
                'enriched_findings_count': total_enriched,
                'high_risk_count': high_risk_total,
                'active_campaigns': len(active_campaigns),
                'risk_distribution': risk_distribution,
                'source_status': source_status,
                'last_update': default_last_update,
                'top_threats': top_threats,
                'sources': sources,
                'cache_entries': len(threat_intelligence.threat_cache),
                'total_enriched_findings': total_enriched
            }

            return jsonify(status)
        except Exception as e:
            logger.error(f"Error getting threat intelligence status: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/enriched-findings')
def get_enriched_findings():
    """Get all enriched findings with threat intelligence"""
    with _network_context_from_request():
        try:
            if not threat_intelligence:
                return jsonify({'error': 'Threat intelligence system not available'}), 503
            
            summary = threat_intelligence.get_enriched_findings_summary() or {}
            default_last_update = summary.get('last_intelligence_update')

            enriched_findings = [
                _serialize_enriched_finding(finding_id, enriched_finding, default_last_update)
                for finding_id, enriched_finding in threat_intelligence.enriched_findings.items()
            ]

            top_threats = sorted(enriched_findings, key=lambda f: f['risk_score'], reverse=True)[:5]

            return jsonify({
                'enriched_findings': enriched_findings,
                'total_count': len(enriched_findings),
                'summary': summary,
                'top_threats': top_threats
            })

        except Exception as e:
            logger.error(f"Error getting enriched findings: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/enrich-finding', methods=['POST'])
def enrich_finding_endpoint():
    """Manually enrich a finding with threat intelligence"""
    with _network_context_from_request():
        try:
            if not threat_intelligence:
                return jsonify({'error': 'Threat intelligence system not available'}), 503
            
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Extract finding data
            finding = {
                'id': data.get('id'),
                'host': data.get('host'),
                'port': data.get('port'),
                'service': data.get('service'),
                'vulnerability': data.get('vulnerability'),
                'severity': data.get('severity', 'medium'),
                'details': data.get('details', {})
            }
            
            # Enrich the finding
            import asyncio
            enriched_finding = asyncio.run(threat_intelligence.enrich_finding_with_threat_intelligence(finding))
            
            return jsonify({
                'success': True,
                'enriched_finding': {
                    'id': finding['id'],
                    'dynamic_risk_score': enriched_finding.dynamic_risk_score,
                    'executive_summary': enriched_finding.executive_summary,
                    'recommended_actions': enriched_finding.recommended_actions,
                    'threat_contexts_count': len(enriched_finding.threat_contexts),
                    'attribution': {
                        'actor_name': enriched_finding.attribution.actor_name if enriched_finding.attribution else None,
                        'confidence': enriched_finding.attribution.confidence if enriched_finding.attribution else 0.0
                    }
                }
            })
            
        except Exception as e:
            logger.error(f"Error enriching finding: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/enrich-target', methods=['POST'])
def enrich_target_endpoint():
    """Enrich a target (IP, domain, or hash) with threat intelligence"""
    with _network_context_from_request():
        try:
            if not threat_intelligence:
                return jsonify({'error': 'Threat intelligence system not available'}), 503
            
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            target = data.get('target', '').strip()
            if not target:
                return jsonify({'error': 'Target is required'}), 400
            
            # Look for actual vulnerability findings for this target
            actual_findings = []
            if hasattr(shared_data, 'network_intelligence') and shared_data.network_intelligence:
                try:
                    # Check active findings
                    active_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
                    
                    # Check for vulnerabilities on this target
                    for vuln_id, vuln_data in active_findings.get('vulnerabilities', {}).items():
                        if vuln_data.get('host') == target:
                            actual_findings.append(vuln_data)
                    
                    # Check for compromised credentials on this target  
                    for cred_id, cred_data in active_findings.get('credentials', {}).items():
                        if cred_data.get('host') == target:
                            actual_findings.append(cred_data)
                            
                except AttributeError as e:
                    logger.warning(f"Network intelligence method not available: {e}")
                    # Fallback: check if we have scan data directly from files
                    try:
                        scan_results_dir = os.path.join(shared_data.datadir, 'output', 'scan_results')
                        if os.path.exists(scan_results_dir):
                            for filename in os.listdir(scan_results_dir):
                                if filename.endswith('.csv') and target in filename:
                                    # Found scan results for this target
                                    actual_findings.append({
                                        'host': target,
                                        'vulnerability': 'Network scan findings available',
                                        'source': 'scan_results',
                                        'details': {'scan_file': filename}
                                    })
                                    break
                    except Exception as scan_e:
                        logger.warning(f"Could not check scan results: {scan_e}")
                        
                except Exception as e:
                    logger.warning(f"Could not retrieve network intelligence findings: {e}")
            
            # If no findings but target looks like it might have vulnerabilities, create a placeholder
            if not actual_findings:
                # For demonstration/testing purposes, allow manual vulnerability analysis
                # This should ideally be replaced with real vulnerability scanner integration
                return jsonify({
                    'error': f'No vulnerability findings detected for target: {target}',
                    'message': 'Ragnar needs to discover vulnerabilities first through network scanning. Try running vulnerability scans on this target.',
                    'target_type': 'no_findings',
                    'suggestion': f'Run network scan on {target} first, then threat intelligence can enrich any discovered vulnerabilities'
                }), 404

            # Use the first real finding for enrichment (or combine multiple findings)
            base_finding = actual_findings[0]
            
            # Create enriched finding object from actual scan data
            finding = {
                'id': base_finding.get('id', hashlib.md5(target.encode()).hexdigest()[:12]),
                'host': target,
                'vulnerability': base_finding.get('vulnerability', base_finding.get('service', 'Unknown')),
                'severity': base_finding.get('severity', 'medium'),
                'port': base_finding.get('port'),
                'service': base_finding.get('service'),
                'details': base_finding.get('details', {}),
                'scan_timestamp': base_finding.get('timestamp', datetime.now().isoformat())
            }
            
            # Enrich the finding
            import asyncio
            enriched_finding = asyncio.run(threat_intelligence.enrich_finding_with_threat_intelligence(finding))
            
            # Convert risk score from 0-10 scale to 0-100 scale for frontend
            risk_score_100 = min(int(enriched_finding.dynamic_risk_score * 10), 100)
            
            return jsonify({
                'success': True,
                'target': target,
                'risk_score': risk_score_100,
                'dynamic_risk_score': enriched_finding.dynamic_risk_score,
                'executive_summary': enriched_finding.executive_summary,
                'recommended_actions': enriched_finding.recommended_actions,
                'threat_contexts_count': len(enriched_finding.threat_contexts),
                'attribution': {
                    'actor_name': enriched_finding.attribution.actor_name if enriched_finding.attribution else None,
                    'confidence': enriched_finding.attribution.confidence if enriched_finding.attribution else 0.0
                },
                'enriched_finding_id': finding['id']
            })
            
        except Exception as e:
            logger.error(f"Error enriching target: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/dashboard')
def get_threat_intelligence_dashboard():
    """Get threat intelligence dashboard data"""
    with _network_context_from_request():
        try:
            if not threat_intelligence:
                return jsonify({'error': 'Threat intelligence system not available'}), 503
            
            dashboard_data = {
                'summary': threat_intelligence.get_enriched_findings_summary(),
                'recent_findings': [],
                'risk_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'threat_sources_status': []
            }
            
            # Get recent enriched findings
            recent_findings = []
            for finding_id, enriched_finding in list(threat_intelligence.enriched_findings.items())[-10:]:
                recent_findings.append({
                    'id': finding_id,
                    'host': enriched_finding.original_finding.get('host', 'Unknown'),
                    'vulnerability': enriched_finding.original_finding.get('vulnerability', 'Unknown'),
                    'risk_score': enriched_finding.dynamic_risk_score,
                    'executive_summary': enriched_finding.executive_summary[:200] + '...'
                })
            
            dashboard_data['recent_findings'] = recent_findings
            
            # Calculate risk distribution
            for enriched_finding in threat_intelligence.enriched_findings.values():
                score = enriched_finding.dynamic_risk_score
                if score >= 9.0:
                    dashboard_data['risk_distribution']['critical'] += 1
                elif score >= 7.0:
                    dashboard_data['risk_distribution']['high'] += 1
                elif score >= 5.0:
                    dashboard_data['risk_distribution']['medium'] += 1
                else:
                    dashboard_data['risk_distribution']['low'] += 1
            
            # Threat sources status
            for name, source in threat_intelligence.threat_sources.items():
                dashboard_data['threat_sources_status'].append({
                    'name': name,
                    'type': source.type,
                    'enabled': source.enabled,
                    'last_updated': source.last_updated
                })
            
            return jsonify(dashboard_data)
            
        except Exception as e:
            logger.error(f"Error getting threat intelligence dashboard: {e}")
            return jsonify({'error': str(e)}), 500

def generate_threat_intelligence_report(target, enriched_finding):
    """Generate threat intelligence report content"""
    try:
        from datetime import datetime
        
        # Check if this is a meaningful finding
        if not enriched_finding.threat_contexts or enriched_finding.dynamic_risk_score < 3.0:
            return {
                'title': f'Threat Intelligence Report - {target}',
                'generated_at': datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
                'target': target,
                'message': 'No significant threat intelligence available for this target',
                'risk_score': enriched_finding.dynamic_risk_score,
                'note': 'This target may be internal or not present in threat intelligence databases'
            }
        
        report_content = {
            'title': f'Threat Intelligence Report - {target}',
            'generated_at': datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
            'target': target,
            'executive_summary': enriched_finding.executive_summary,
            'risk_score': enriched_finding.dynamic_risk_score,
            'threat_contexts': [],
            'attribution': None,
            'active_campaigns': enriched_finding.active_campaigns,
            'exploitation_prediction': enriched_finding.exploitation_prediction,
            'recommended_actions': enriched_finding.recommended_actions
        }
        
        # Process threat contexts
        for context in enriched_finding.threat_contexts:
            report_content['threat_contexts'].append({
                'source': context.source,
                'threat_type': context.threat_type,
                'severity': context.severity,
                'confidence': context.confidence,
                'description': context.description,
                'references': context.references,
                'tags': context.tags
            })
        
        # Process attribution
        if enriched_finding.attribution:
            report_content['attribution'] = {
                'actor_name': enriched_finding.attribution.actor_name,
                'sophistication': enriched_finding.attribution.sophistication,
                'motivation': enriched_finding.attribution.motivation,
                'geographic_origin': enriched_finding.attribution.geographic_origin,
                'confidence': enriched_finding.attribution.confidence
            }
        
        return report_content
        
    except Exception as e:
        logger.error(f"Error generating report content: {e}")
        return {
            'title': f'Threat Intelligence Report - {target}',
            'generated_at': datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
            'target': target,
            'executive_summary': 'Report generation failed - manual review recommended',
            'risk_score': 5.0,
            'error': str(e)
        }

def create_text_report(report_content):
    """Create text report from content"""
    try:
        # Check if this is a low-value report
        if 'message' in report_content:
            return f"""THREAT INTELLIGENCE REPORT
===========================

Target: {report_content['target']}
Generated: {report_content['generated_at']}

STATUS
------
{report_content['message']}

ANALYSIS NOTES
--------------
{report_content.get('note', 'No additional information available')}

Risk Score: {report_content.get('risk_score', 0):.1f}/10

REPORT METADATA
---------------
Generated by: Ragnar Threat Intelligence System
Report ID: {hashlib.md5(report_content['target'].encode()).hexdigest()[:12]}
Timestamp: {report_content['generated_at']}

Note: This target may be internal infrastructure or not present in external threat databases.
""".encode('utf-8')

        report_text = f"""THREAT INTELLIGENCE REPORT
===========================

Target: {report_content['target']}
Generated: {report_content['generated_at']}

EXECUTIVE SUMMARY
-----------------
{report_content['executive_summary']}

RISK ASSESSMENT
---------------
Dynamic Risk Score: {report_content['risk_score']:.1f}/10

"""
        
        if report_content.get('threat_contexts'):
            report_text += "THREAT INTELLIGENCE SOURCES\n"
            report_text += "----------------------------\n"
            for context in report_content['threat_contexts']:
                report_text += f"• {context['source']}: {context['description']}\n"
                report_text += f"  Severity: {context['severity']}, Confidence: {context['confidence']:.1f}\n\n"
        else:
            report_text += "THREAT INTELLIGENCE SOURCES\n"
            report_text += "----------------------------\n"
            report_text += "No external threat intelligence sources matched this target.\n\n"
        
        if report_content.get('attribution'):
            attr = report_content['attribution']
            report_text += "THREAT ATTRIBUTION\n"
            report_text += "------------------\n"
            report_text += f"Actor: {attr.get('actor_name', 'Unknown')}\n"
            report_text += f"Sophistication: {attr.get('sophistication', 'Unknown')}\n"
            report_text += f"Motivation: {attr.get('motivation', 'Unknown')}\n"
            report_text += f"Geographic Origin: {attr.get('geographic_origin', 'Unknown')}\n\n"
        
        if report_content.get('recommended_actions'):
            report_text += "RECOMMENDED ACTIONS\n"
            report_text += "-------------------\n"
            for action in report_content['recommended_actions']:
                report_text += f"• {action}\n"
            report_text += "\n"
        else:
            report_text += "RECOMMENDED ACTIONS\n"
            report_text += "-------------------\n"
            report_text += "• Review target for legitimate business purpose\n"
            report_text += "• Monitor for unusual activity\n"
            report_text += "• Apply standard security controls\n\n"
        
        if report_content.get('exploitation_prediction'):
            pred = report_content['exploitation_prediction']
            report_text += "EXPLOITATION PREDICTION\n"
            report_text += "-----------------------\n"
            report_text += f"Likelihood: {pred.get('exploitation_likelihood', 0) * 100:.1f}%\n"
            report_text += f"Timeline: {pred.get('predicted_timeline_days', 'Unknown')} days\n"
            report_text += f"Confidence: {pred.get('confidence', 0) * 100:.1f}%\n\n"
        
        report_text += f"""REPORT METADATA
---------------
Generated by: Ragnar Threat Intelligence System
Report ID: {hashlib.md5(report_content['target'].encode()).hexdigest()[:12]}
Timestamp: {report_content['generated_at']}

This report contains threat intelligence analysis based on multiple sources.
For questions or additional analysis, contact your security team.
"""
        
        return report_text.encode('utf-8')
        
    except Exception as e:
        logger.error(f"Error creating text report: {e}")
        error_content = f"Error generating report: {e}".encode('utf-8')
        return error_content

@app.route('/api/threat-intelligence/download-report', methods=['POST'])
def download_threat_intelligence_report():
    """Generate and download a comprehensive threat intelligence report"""
    with _network_context_from_request():
        try:
            if not threat_intelligence:
                return jsonify({'error': 'Threat intelligence system not available'}), 503
            
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            target = data.get('target', '').strip()
            if not target:
                return jsonify({'error': 'Target is required'}), 400
            
            # Find enriched finding for the target
            enriched_finding = None
            for finding_id, finding in threat_intelligence.enriched_findings.items():
                original_finding = finding.original_finding
                if (original_finding.get('host') == target or 
                    original_finding.get('domain') == target or
                    original_finding.get('hash') == target or
                    original_finding.get('details', {}).get('target') == target):
                    enriched_finding = finding
                    break
            
            if not enriched_finding:
                # Try to create a new enrichment for the target
                finding = {
                    'id': hashlib.md5(target.encode()).hexdigest()[:12],
                    'host': target if _is_ip_address(target) else None,
                    'domain': target if '.' in target and not _is_ip_address(target) else None,
                    'hash': target if len(target) >= 32 and all(c in '0123456789abcdefABCDEF' for c in target) else None,
                    'vulnerability': f'Threat intelligence analysis for {target}',
                    'severity': 'medium',
                    'details': {'target': target}
                }
                
                import asyncio
                enriched_finding = asyncio.run(threat_intelligence.enrich_finding_with_threat_intelligence(finding))
            
            # Generate report content
            report_content = generate_threat_intelligence_report(target, enriched_finding)
            
            # Create text report
            text_content = create_text_report(report_content)
            
            # Generate filename with current date
            from datetime import datetime
            now = datetime.now()
            date_str = now.strftime("%Y%m%d_%H%M%S")
            safe_target = "".join(c for c in target if c.isalnum() or c in '._-')
            filename = f"Threat_Intelligence_Report_{safe_target}_{date_str}.txt"
            
            # Return text file as download
            response = Response(
                text_content,
                mimetype='text/plain',
                headers={
                    'Content-Disposition': f'attachment; filename="{filename}"',
                    'Content-Type': 'text/plain'
                }
            )
            
            logger.info(f"Generated threat intelligence report for target: {target}")
            return response
            
        except Exception as e:
            logger.error(f"Error generating threat intelligence report: {e}")
            return jsonify({'error': str(e)}), 500


# ============================================================================
# LEGACY ENDPOINTS (for compatibility)
# ============================================================================

@app.route('/network_data')
def legacy_network_data():
    """Network data endpoint with WiFi-specific persistence"""
    try:
        # Update WiFi-specific network data from latest scan results
        update_wifi_network_data()
        
        # Read from WiFi-specific persistent file
        network_data = read_wifi_network_data()
        
        # If no persistent data, build from current scan results
        if not network_data:
            logger.debug("No WiFi-specific network data found, building from scan results")
            
            scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
            current_time = datetime.now().isoformat()
            
            if os.path.exists(scan_results_dir):
                temp_data = {}
                
                for filename in os.listdir(scan_results_dir):
                    if filename.startswith('result_') and filename.endswith('.csv'):
                        filepath = os.path.join(scan_results_dir, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                reader = csv.reader(f)
                                for row in reader:
                                    if len(row) >= 1 and row[0].strip():
                                        ip = row[0].strip()
                                        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                                            hostname = row[1] if len(row) > 1 and row[1] else ''
                                            alive = row[2] if len(row) > 2 and row[2] else '1'
                                            mac = row[3] if len(row) > 3 and row[3] else ''
                                            
                                            # Collect ports from remaining columns
                                            ports = []
                                            if len(row) > 4:
                                                for port_col in row[4:]:
                                                    if port_col and port_col.strip():
                                                        ports.append(port_col.strip())
                                            
                                            # Update or add entry
                                            if ip in temp_data:
                                                # Merge data
                                                if hostname and hostname != 'Unknown':
                                                    temp_data[ip]['Hostnames'] = hostname
                                                if mac and mac != 'Unknown':
                                                    temp_data[ip]['MAC Address'] = mac
                                                temp_data[ip]['Alive'] = int(alive) if alive.isdigit() else 1
                                                existing_ports = set(temp_data[ip]['Ports'].split(';')) if temp_data[ip]['Ports'] else set()
                                                existing_ports.update(ports)
                                                temp_data[ip]['Ports'] = ';'.join(sorted(existing_ports, key=lambda x: int(x) if x.isdigit() else 0))
                                                temp_data[ip]['LastSeen'] = current_time
                                            else:
                                                # New entry
                                                temp_data[ip] = {
                                                    'IPs': ip,
                                                    'Hostnames': hostname,
                                                    'Alive': int(alive) if alive.isdigit() else 1,
                                                    'MAC Address': mac,
                                                    'Ports': ';'.join(ports) if ports else '',
                                                    'LastSeen': current_time
                                                }
                        except Exception as e:
                            logger.debug(f"Could not read scan result file {filepath}: {e}")
                            continue
                
                # Convert to list format
                network_data = list(temp_data.values())
        
        if not network_data:
            current_ssid = get_current_wifi_ssid()
            return f'<div class="error">No network scan results found for WiFi network: {current_ssid}<br>Please run a network scan first.</div>'
        
        current_ssid = get_current_wifi_ssid()
        
        # Generate HTML table
        html = f'''
        <div class="network-header">
            <h3>Network Scan Results for WiFi: {current_ssid}</h3>
            <p>Persistent data - automatically updated when new scans are performed</p>
        </div>
        <table class="network-table">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Status</th>
                    <th>MAC Address</th>
                    <th>Open Ports</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>
        '''
        
        for entry in network_data:
            ip = entry.get('IPs', '')
            hostname = entry.get('Hostnames', '')
            alive = entry.get('Alive', 0)
            mac = entry.get('MAC Address', '')
            ports = entry.get('Ports', '')
            last_seen = entry.get('LastSeen', '')
            
            # Format status
            status = 'Online' if alive == 1 else 'Offline'
            status_class = 'status-online' if alive == 1 else 'status-offline'
            
            # Format ports for display
            if ports:
                port_list = [p for p in ports.split(';') if p]
                ports_display = ', '.join(port_list[:10])  # Show first 10 ports
                if len(port_list) > 10:
                    ports_display += f' ... (+{len(port_list) - 10} more)'
            else:
                ports_display = 'None detected'
            
            # Format last seen time
            try:
                if last_seen:
                    last_seen_dt = datetime.fromisoformat(last_seen)
                    last_seen_display = last_seen_dt.strftime('%m-%d %H:%M')
                else:
                    last_seen_display = 'Unknown'
            except Exception:
                last_seen_display = 'Unknown'
            
            html += f'''
                <tr>
                    <td>{ip}</td>
                    <td>{hostname if hostname else 'Unknown'}</td>
                    <td><span class="{status_class}">{status}</span></td>
                    <td>{mac if mac else 'Unknown'}</td>
                    <td>{ports_display}</td>
                    <td>{last_seen_display}</td>
                </tr>
            '''
        
        html += '''
            </tbody>
        </table>
        '''
        
        # Add some CSS for styling
        html = f'''
        <style>
            .network-header {{
                color: #00ff00;
                font-family: 'Courier New', monospace;
                text-align: center;
                margin-bottom: 20px;
            }}
            .network-header h3 {{
                margin: 0 0 10px 0;
                font-size: 18px;
            }}
            .network-header p {{
                margin: 0;
                font-size: 12px;
                color: #00cc00;
            }}
            .network-table {{
                width: 100%;
                border-collapse: collapse;
                font-family: 'Courier New', monospace;
                background-color: #000;
                color: #00ff00;
            }}
            .network-table th, .network-table td {{
                border: 1px solid #00ff00;
                padding: 8px;
                text-align: left;
                font-size: inherit;
            }}
            .network-table th {{
                background-color: #003300;
                font-weight: bold;
            }}
            .network-table tr:nth-child(even) {{
                background-color: #001100;
            }}
            .status-online {{
                color: #00ff00;
                font-weight: bold;
            }}
            .status-offline {{
                color: #ff6600;
                font-weight: bold;
            }}
            .error {{
                color: #ff0000;
                text-align: center;
                padding: 20px;
                font-family: 'Courier New', monospace;
            }}
        </style>
        {html}
        '''
        
        logger.info(f"Serving network data for WiFi: {current_ssid} with {len(network_data)} entries")
        return html
        
    except Exception as e:
        logger.error(f"Error serving network data: {e}")
        current_ssid = get_current_wifi_ssid()
        return f'<div class="error">Error loading network data for WiFi: {current_ssid}<br>Error: {str(e)}</div>'

@app.route('/list_credentials')
def legacy_credentials():
    """Legacy endpoint for credentials"""
    return get_credentials()

@app.route('/get_logs')
def legacy_logs():
    """Legacy endpoint for logs"""
    return get_logs()

@app.route('/netkb_data_json')
def legacy_netkb_json():
    """Legacy endpoint for network knowledge base JSON - now uses SQLite database"""
    try:
        # Get alive hosts from database
        hosts = shared_data.db.get_all_hosts()
        alive_hosts = [h for h in hosts if h.get('status') == 'alive']
        
        # Get available actions from actions file
        actions = []
        try:
            with open(shared_data.actions_file, 'r') as f:
                actions_config = json.load(f)
                actions = list(actions_config.keys())
        except Exception:
            pass
        
        # Build ports dict (ip -> list of ports)
        ports_dict = {}
        for host in alive_hosts:
            ip = host.get('ip', '')
            if ip:
                port_str = host.get('ports', '')
                ports_dict[ip] = port_str.split(',') if port_str else []
        
        response_data = {
            'ips': [h.get('ip', '') for h in alive_hosts if h.get('ip')],
            'ports': ports_dict,
            'actions': actions
        }
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error getting netkb JSON: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection - reject if auth is configured but not authenticated"""
    if auth_mgr.is_configured() and not session.get('authenticated'):
        logger.warning("Rejected unauthenticated WebSocket connection")
        disconnect()
        return False

    global clients_connected
    clients_connected += 1
    logger.info(f"Client connected. Total clients: {clients_connected}")
    emit('connected', {
        'message': 'Connected to Ragnar',
        'auth_configured': auth_mgr.is_configured()
    })

    # Send initial data to new client
    try:
        ensure_recent_sync()
        status_data = get_current_status()
        emit('status_update', status_data)

        # Send recent logs
        logs = get_recent_logs()
        emit('log_update', logs)
    except Exception as e:
        logger.error(f"Error sending initial data: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    global clients_connected
    clients_connected = max(0, clients_connected - 1)
    logger.info(f"Client disconnected. Total clients: {clients_connected}")


@socketio.on('request_status')
def handle_status_request():
    """Handle status update request"""
    try:
        status_data = get_current_status()
        emit('status_update', status_data)
    except Exception as e:
        logger.error(f"Error handling status request: {e}")


@socketio.on('request_logs')
def handle_log_request():
    """Handle request for recent logs"""
    try:
        logs = get_recent_logs()
        emit('log_update', logs)
    except Exception as e:
        logger.error(f"Error sending logs: {e}")


@socketio.on('request_network')
def handle_network_request():
    """Handle request for network data"""
    try:
        db = get_db(currentdir=shared_data.currentdir)
        data = db.get_all_hosts()
        emit('network_update', data)
    except Exception as e:
        logger.error(f"Error sending network data: {e}")
        traceback.print_exc()


@socketio.on('request_credentials')
def handle_credentials_request():
    """Handle request for credentials data"""
    try:
        credentials = web_utils.get_all_credentials()
        emit('credentials_update', credentials)
    except Exception as e:
        logger.error(f"Error sending credentials: {e}")


@socketio.on('request_loot')
def handle_loot_request():
    """Handle request for loot data"""
    try:
        loot = web_utils.get_loot_data()
        emit('loot_update', loot)
    except Exception as e:
        logger.error(f"Error sending loot data: {e}")


@socketio.on('start_scan')
def handle_start_scan(data):
    """Handle scan start request via WebSocket"""
    try:
        scan_type = data.get('type', 'all')
        target = data.get('target', None)
        
        def scan_callback(event_type, event_data):
            socketio.emit('scan_update', {
                'type': event_type,
                'data': event_data
            })
        
        if scan_type == 'single' and target:
            def run_single_scan():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner
                    scanner = NmapVulnScanner(shared_data)
                    scanner.scan_single_host_realtime(
                        ip=target.get('ip', ''),
                        hostname=target.get('hostname', ''),
                        mac=target.get('mac', ''),
                        ports=target.get('ports', ''),
                        callback=scan_callback
                    )
                except Exception as e:
                    scan_callback('scan_error', {'error': str(e)})
            
            threading.Thread(target=run_single_scan, daemon=True).start()
        
        elif scan_type == 'all':
            def run_full_scan():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner
                    scanner = NmapVulnScanner(shared_data)
                    scanner.force_scan_all_hosts(real_time_callback=scan_callback)
                except Exception as e:
                    scan_callback('scan_error', {'error': str(e)})
            
            threading.Thread(target=run_full_scan, daemon=True).start()
        
        emit('scan_started', {'status': 'success', 'type': scan_type})
        
    except Exception as e:
        logger.error(f"Error handling scan start: {e}")
        emit('scan_error', {'error': str(e)})

@socketio.on('stop_scan')
def handle_stop_scan():
    """Handle scan stop request via WebSocket"""
    try:
        # You can implement scan stopping logic here
        emit('scan_stopped', {'status': 'success'})
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        emit('scan_error', {'error': str(e)})


@socketio.on('request_activity')
def handle_activity_request():
    """Handle request for detailed activity logs"""
    try:
        # Generate activity logs directly
        activity_logs = []
        current_time = datetime.now()
        
        # Recent discoveries
        if os.path.exists(shared_data.livestatusfile):
            try:
                import pandas as pd
                df = pd.read_csv(shared_data.livestatusfile)
                alive_hosts = df[df['Alive'] == 1] if 'Alive' in df.columns else df
                for _, row in alive_hosts.tail(10).iterrows():
                    ip = row.get('IP', 'Unknown')
                    hostname = row.get('Hostname', ip)
                    ports = row.get('Ports', '')
                    
                    log_entry = {
                        'timestamp': current_time.strftime("%H:%M:%S"),
                        'type': 'discovery',
                        'icon': '🎯',
                        'message': f"Discovered {hostname} ({ip})",
                        'details': f"Ports: {ports.split(';')[:3] if ports else []}" if ports else "Host responsive",
                        'severity': 'info'
                    }
                    activity_logs.append(log_entry)
            except Exception:
                pass
        
        # Add current status
        if safe_str(shared_data.ragnarstatustext) and safe_str(shared_data.ragnarstatustext) != "Idle":
            activity_logs.append({
                'timestamp': current_time.strftime("%H:%M:%S"),
                'type': 'status',
                'icon': '🤖',
                'message': f"Ragnar: {safe_str(shared_data.ragnarstatustext)}",
                'details': safe_str(shared_data.ragnarstatustext2) if safe_str(shared_data.ragnarstatustext2) else '',
                'severity': 'info'
            })
        
        if safe_str(shared_data.ragnarsays) and safe_str(shared_data.ragnarsays).strip():
            activity_logs.append({
                'timestamp': current_time.strftime("%H:%M:%S"),
                'type': 'activity',
                'icon': '⚡',
                'message': safe_str(shared_data.ragnarsays),
                'details': '',
                'severity': 'info'
            })
        
        emit('activity_update', activity_logs[-20:])  # Send last 20 entries
    except Exception as e:
        logger.error(f"Error sending activity data: {e}")
        emit('activity_update', [])


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

def get_current_status():
    """Get current status data"""
    try:
        shared_data.update_stats()
    except Exception as e:
        logger.debug(f"Unable to refresh gamification stats: {e}")

    # Get WiFi status details from WiFi manager
    wifi_status = {}
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            wifi_status = wifi_manager.wifi_manager.get_status()
    except Exception as e:
        logger.debug(f"Could not get WiFi status from manager: {e}")

    return {
        'ragnar_status': safe_str(shared_data.ragnarstatustext),
        'ragnar_status2': safe_str(shared_data.ragnarstatustext2),
        'ragnar_says': safe_str(shared_data.ragnarsays),
        'orchestrator_status': safe_str(shared_data.ragnarorch_status),
        'automation_enabled': is_orchestrator_running(),
        'target_count': safe_int(shared_data.targetnbr),
        'port_count': safe_int(shared_data.portnbr),
        'vulnerability_count': safe_int(shared_data.vulnnbr),
        'vulnerable_hosts_count': safe_int(getattr(shared_data, 'vulnerable_host_count', 0)),
        'vulnerable_host_count': safe_int(getattr(shared_data, 'vulnerable_host_count', 0)),
        'credential_count': safe_int(shared_data.crednbr),
        'data_count': safe_int(shared_data.datanbr),
        'level': safe_int(shared_data.levelnbr),
        'points': safe_int(shared_data.coinnbr),
        'coins': safe_int(shared_data.coinnbr),
        'scanned_network_count': safe_int(getattr(shared_data, 'scanned_networks_count', 0)),
        'wifi_connected': wifi_status.get('wifi_connected', safe_bool(shared_data.wifi_connected)),
        'current_ssid': wifi_status.get('current_ssid'),
        'ap_mode_active': wifi_status.get('ap_mode_active', False),
        'ap_ssid': wifi_status.get('ap_ssid'),
        'bluetooth_active': safe_bool(shared_data.bluetooth_active),
        'pan_connected': safe_bool(shared_data.pan_connected),
        'usb_active': safe_bool(shared_data.usb_active),
        'ethernet_connected': safe_bool(is_ethernet_available()),
        'ethernet_ip': _get_active_ethernet_ip(),
        'ethernet_interface': _get_active_ethernet_name(),
        'manual_mode': safe_bool(shared_data.config.get('manual_mode', False)),
        'headless_mode': safe_bool(getattr(shared_data, 'headless_mode', False)),
        'release_gate': _build_release_gate_payload(),
        'timestamp': datetime.now().isoformat()
    }

def get_recent_logs():
    """Get recent log entries with enhanced activity information focused on security scanning"""
    logs = []
    try:
        # Enhanced logging - aggregate from multiple sources for real-time updates
        
        # Function to filter logs for security focus
        def should_include_realtime_log(log_line):
            """Filter real-time logs to focus on security scanning activities"""
            if not log_line:
                return False
            
            log_lower = log_line.lower()
            
            # Exclude comment.py and other non-essential logs
            exclude_sources = [
                'comment.py', 'comments.py', 'comment_', 'comments_',
                'display.py', 'epd_helper.py', 'webapp_', 'flask',
                'socketio', 'werkzeug', 'http.server', 'static'
            ]
            
            if any(source in log_lower for source in exclude_sources):
                return False
            
            # Always include security scanning and vulnerability logs
            high_priority_keywords = [
                'nmap', 'scan', 'scanning', 'port scan', 'host discovery',
                'vulnerability', 'vuln', 'exploit', 'cve-', 'exploit-db',
                'credential', 'cred', 'password', 'login', 'auth',
                'ssh', 'ftp', 'smb', 'telnet', 'rdp', 'sql', 'mysql', 'postgres',
                'attack', 'brute', 'crack', 'penetration', 'pentest',
                'target', 'host found', 'port open', 'service', 'banner',
                'network intelligence', 'threat intelligence', 'orchestrator',
                'error', 'critical', 'warning', 'fail', 'timeout',
                'discovered', 'found'
            ]
            
            return any(keyword in log_lower for keyword in high_priority_keywords)
        
        # 1. Get web console logs (filtered for security content)
        log_file = shared_data.webconsolelog
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                web_logs = [line.strip() for line in lines[-10:] if line.strip()]
                # Filter for security-relevant logs only
                filtered_web_logs = [log for log in web_logs if should_include_realtime_log(log)]
                logs.extend([f"[WEB] {log}" for log in filtered_web_logs[-10:]])  # Last 10 relevant logs
        
        # 2. Add recent activity summary (only if security-related)
        current_time = datetime.now().strftime("%H:%M:%S")
        
        # Add Ragnar status (only if active scanning/attacking)
        ragnar_status = safe_str(shared_data.ragnarstatustext)
        if ragnar_status and ragnar_status != "Idle":
            status_lower = ragnar_status.lower()
            if any(keyword in status_lower for keyword in ['scan', 'attack', 'discovery', 'exploit', 'brute', 'crack']):
                logs.append(f"[{current_time}] [RAGNAR] 🎯 {ragnar_status}")
        
        # Add orchestrator status (only if active)
        orch_status = safe_str(shared_data.ragnarorch_status)
        if orch_status and orch_status != "Idle":
            orch_lower = orch_status.lower()
            if any(keyword in orch_lower for keyword in ['scan', 'attack', 'discovery', 'exploit', 'target', 'running']):
                logs.append(f"[{current_time}] [ORCHESTRATOR] ⚡ {orch_status}")
        
        # Add what Ragnar says (activity description) - only if security-related
        ragnar_says = safe_str(shared_data.ragnarsays)
        if ragnar_says and ragnar_says.strip():
            if should_include_realtime_log(ragnar_says):
                logs.append(f"[{current_time}] [ACTIVITY] 🔍 {ragnar_says}")
        
        # 3. Add concise stats summary (less frequent)
        if safe_int(shared_data.vulnnbr) > 0 or safe_int(shared_data.crednbr) > 0:
            stats_summary = f"Findings: {safe_int(shared_data.vulnnbr)} vulns | {safe_int(shared_data.crednbr)} creds | {safe_int(shared_data.targetnbr)} targets"
            logs.append(f"[{current_time}] [STATS] 📊 {stats_summary}")
        
        # 4. Check for very recent discoveries (last 5 minutes)
        if os.path.exists(shared_data.livestatusfile):
            try:
                # Check file modification time
                mod_time = os.path.getmtime(shared_data.livestatusfile)
                if time.time() - mod_time < 300:  # 5 minutes
                    logs.append(f"[{current_time}] [DISCOVERY] 🎯 Recent network activity detected")
            except Exception:
                pass
        
        # 5. Only show connectivity if there are security implications
        # Skip general connectivity status to focus on security logs
        
        # Limit to last 20 entries for focused real-time updates
        recent_logs = logs[-20:] if logs else []
        
    except Exception as e:
        logger.error(f"Error reading enhanced logs: {e}")
        logs = [f"[ERROR] Error reading logs: {e}"]
    
    return recent_logs

def broadcast_status_updates():
    """Broadcast status updates to all connected clients"""
    log_counter = 0
    activity_counter = 0
    while not shared_data.webapp_should_exit:
        try:
            if clients_connected > 0:
                ensure_recent_sync()

                # Send status update
                status_data = get_current_status()
                socketio.emit('status_update', status_data)
                
                # Send logs every 5 cycles (10 seconds)
                log_counter += 1
                if log_counter % 5 == 0:
                    logs = get_recent_logs()
                    socketio.emit('log_update', logs)
                
                # Send activity updates every 3 cycles (6 seconds)
                activity_counter += 1
                if activity_counter % 3 == 0:
                    # Generate simplified activity update for real-time broadcast
                    activity_update = []
                    current_time = datetime.now().strftime("%H:%M:%S")
                    
                    # Add current Ragnar activity
                    ragnar_says = safe_str(shared_data.ragnarsays)
                    if ragnar_says and ragnar_says.strip():
                        activity_update.append({
                            'timestamp': current_time,
                            'type': 'activity',
                            'icon': '⚡',
                            'message': ragnar_says,
                            'severity': 'info'
                        })
                    
                    # Add status if something is happening
                    ragnar_status = safe_str(shared_data.ragnarstatustext)
                    if ragnar_status and ragnar_status not in ["Idle", ""]:
                        activity_update.append({
                            'timestamp': current_time,
                            'type': 'status',
                            'icon': '🤖',
                            'message': f"Status: {ragnar_status}",
                            'severity': 'info'
                        })
                    
                    if activity_update:
                        socketio.emit('activity_update', activity_update)
            
            socketio.sleep(2)  # Update every 2 seconds
        except Exception as e:
            logger.error(f"Error broadcasting status: {e}")
            socketio.sleep(5)


def background_sync_loop(interval=SYNC_BACKGROUND_INTERVAL):
    """Continuously synchronize counts so displays remain fresh even without web clients"""
    global background_thread_health
    consecutive_errors = 0
    max_consecutive_errors = 10
    
    while not shared_data.webapp_should_exit:
        try:
            # Use a timeout thread to prevent infinite blocking
            import threading
            sync_thread = threading.Thread(target=sync_all_counts, daemon=True)
            sync_thread.start()
            sync_thread.join(timeout=60)  # 60 second timeout (reduced from 120s)
            
            if sync_thread.is_alive():
                logger.error("Background sync thread timed out after 60 seconds! Skipping this cycle.")
                consecutive_errors += 1
            else:
                consecutive_errors = 0  # Reset on success
                background_thread_health['sync_last_run'] = time.time()
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Background sync error (attempt {consecutive_errors}/{max_consecutive_errors}): {e}")
            
            if consecutive_errors >= max_consecutive_errors:
                logger.critical(f"Background sync failed {max_consecutive_errors} times consecutively! Resetting error counter but continuing...")
                consecutive_errors = 0  # Reset to prevent thread death
                time.sleep(30)  # Wait longer after multiple failures
        
        time.sleep(max(1, interval))

def background_arp_scan_loop():
    """Continuously run ARP scans to keep network data fresh"""
    global network_scan_cache, network_scan_last_update, background_thread_health
    consecutive_errors = 0
    max_consecutive_errors = 10
    
    while not shared_data.webapp_should_exit:
        try:
            current_time = time.time()
            
            # Run ARP scan every ARP_SCAN_INTERVAL seconds
            if current_time - network_scan_last_update >= ARP_SCAN_INTERVAL:
                logger.debug("Running background ARP scan...")
                
                # Run ARP scan with timeout protection
                import threading
                arp_hosts = {}
                
                def run_arp():
                    nonlocal arp_hosts
                    arp_hosts = run_arp_scan_localnet('wlan0')
                
                arp_thread = threading.Thread(target=run_arp, daemon=True)
                arp_thread.start()
                arp_thread.join(timeout=25)  # 25 second timeout (less than ARP_SCAN_INTERVAL)
                
                if arp_thread.is_alive():
                    logger.error("Background ARP scan timed out after 25 seconds! Skipping this cycle.")
                    consecutive_errors += 1
                    time.sleep(ARP_SCAN_INTERVAL)
                    continue
                
                # Update cache
                network_scan_cache['arp_hosts'] = arp_hosts
                network_scan_cache['last_arp_scan'] = current_time
                network_scan_last_update = current_time
                background_thread_health['arp_last_run'] = current_time
                
                # Update network knowledge base
                for ip, data in arp_hosts.items():
                    try:
                        update_netkb_entry(ip, data.get('hostname', ''), data.get('mac', ''), True)
                    except Exception as e:
                        logger.error(f"Error updating netkb for {ip}: {e}")
                
                # Update WiFi network data to sync ARP discoveries
                try:
                    update_wifi_network_data()
                except Exception as e:
                    logger.error(f"Error updating WiFi network data from ARP scan: {e}")
                
                # Emit real-time update to connected clients
                if clients_connected > 0:
                    try:
                        socketio.emit('network_update', {
                            'hosts': arp_hosts,
                            'count': len(arp_hosts),
                            'source': 'arp_background',
                            'timestamp': datetime.now().isoformat()
                        })
                    except Exception as e:
                        logger.error(f"Error emitting network update: {e}")
                
                logger.debug(f"Background ARP scan completed, found {len(arp_hosts)} hosts")
                consecutive_errors = 0  # Reset on success
            
            time.sleep(2)  # Check every 2 seconds, but only scan based on interval
            
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Error in background ARP scan loop (attempt {consecutive_errors}/{max_consecutive_errors}): {e}")
            
            if consecutive_errors >= max_consecutive_errors:
                logger.critical(f"Background ARP scan failed {max_consecutive_errors} times consecutively! Resetting error counter but continuing...")
                consecutive_errors = 0  # Reset to prevent thread death
                time.sleep(30)  # Wait longer after multiple failures
            else:
                time.sleep(5)  # Wait a bit before retry
            time.sleep(ARP_SCAN_INTERVAL)


# Health monitoring for background threads
background_thread_health = {
    'sync_last_run': 0,
    'arp_last_run': 0,
    'sync_alive': False,
    'arp_alive': False
}

def background_health_monitor():
    """Monitor background threads and log warnings if they stop responding"""
    global background_thread_health
    
    while not shared_data.webapp_should_exit:
        try:
            current_time = time.time()
            
            # Check sync thread - should run every 15 seconds but may take up to 60s for large networks
            if background_thread_health['sync_last_run'] > 0:
                time_since_sync = current_time - background_thread_health['sync_last_run']
                if time_since_sync > 90:  # 60s timeout + 30s buffer
                    logger.warning(f"⚠️ Background sync thread appears stuck! Last run was {time_since_sync:.0f}s ago")
                    background_thread_health['sync_alive'] = False
                else:
                    background_thread_health['sync_alive'] = True
            
            # Check ARP thread - should run every 10 seconds  
            if background_thread_health['arp_last_run'] > 0:
                time_since_arp = current_time - background_thread_health['arp_last_run']
                if time_since_arp > 60:  # No ARP scan for 60 seconds
                    logger.warning(f"⚠️ Background ARP scan thread appears stuck! Last run was {time_since_arp:.0f}s ago")
                    background_thread_health['arp_alive'] = False
                else:
                    background_thread_health['arp_alive'] = True
            
            time.sleep(15)  # Check every 15 seconds
            
        except Exception as e:
            logger.error(f"Error in health monitor: {e}")
            time.sleep(15)


# ============================================================================
# MANUAL MODE ENDPOINTS
# ============================================================================

@app.route('/api/manual/status')
def get_manual_mode_status():
    """Get current manual mode status"""
    try:
        return jsonify({
            'manual_mode': shared_data.config.get('manual_mode', False),
            'orchestrator_status': shared_data.ragnarorch_status
        })
    except Exception as e:
        logger.error(f"Error getting manual mode status: {e}")
        return jsonify({'error': str(e)}), 500

MANUAL_ATTACK_MATRIX = {
    'ssh': {'label': 'SSH Brute Force', 'ports': [22]},
    'ftp': {'label': 'FTP Brute Force', 'ports': [21]},
    'telnet': {'label': 'Telnet Brute Force', 'ports': [23]},
    'smb': {'label': 'SMB Brute Force', 'ports': [139, 445]},
    'rdp': {'label': 'RDP Brute Force', 'ports': [3389]},
    'sql': {'label': 'SQL Brute Force', 'ports': [3306]}
}

MANUAL_ATTACK_CREDENTIAL_ATTR = {
    'ssh': 'sshfile',
    'ftp': 'ftpfile',
    'telnet': 'telnetfile',
    'smb': 'smbfile',
    'rdp': 'rdpfile',
    'sql': 'sqlfile'
}


def _collect_manual_targets():
    """Collect targets available for manual operations."""
    targets = []
    target_ips = set()  # Track unique IPs to avoid duplicates

    # Read from SQLite database (primary source)
    try:
        db = get_db(currentdir=shared_data.currentdir)
        all_hosts = db.get_all_hosts()
        
        for host in all_hosts:
            # Only include alive/up hosts
            if host.get('status') in ['alive', 'up']:
                ip = host.get('ip') or host.get('ip_address', '')
                hostname = host.get('hostname', ip) or ip
                
                # Parse ports from comma or semicolon-separated string
                ports_str = host.get('ports', '')
                ports = []
                if ports_str:
                    if ',' in ports_str:
                        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
                    else:
                        ports = [p.strip() for p in ports_str.split(';') if p.strip()]
                
                if ip and ip not in target_ips:
                    targets.append({
                        'ip': ip,
                        'hostname': hostname,
                        'ports': ports,
                        'mac': host.get('mac', '00:00:00:00:00:00'),
                        'source': 'Database'
                    })
                    target_ips.add(ip)
        
        logger.debug(f"Loaded {len(targets)} targets from SQLite database for manual attacks")
    except Exception as e:
        logger.error(f"Error reading targets from database: {e}")
    
    # Fallback: Read from CSV livestatus file if database is empty
    if not targets and os.path.exists(shared_data.livestatusfile):
        try:
            with open(shared_data.livestatusfile, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if row.get('Alive') == '1':  # Only alive targets
                        ip = row.get('IP', '')
                        hostname = row.get('Hostname', ip)

                        # Get open ports
                        ports = []
                        for key, value in row.items():
                            if key.isdigit() and value:  # Port columns with values
                                ports.append(key)

                        if ip and ip not in target_ips:
                            targets.append({
                                'ip': ip,
                                'hostname': hostname,
                                'ports': ports,
                                'mac': row.get('MAC', row.get('MAC Address', '00:00:00:00:00:00')),
                                'source': 'CSV Fallback'
                            })
                            target_ips.add(ip)
            logger.debug(f"Loaded {len(targets)} targets from CSV fallback for manual attacks")
        except Exception as e:
            logger.error(f"Error reading CSV fallback: {e}")

    # Also include hosts from NetKB data
    try:
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        if os.path.exists(scan_results_dir):
            for filename in os.listdir(scan_results_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                # Extract IP from filename or content
                                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                host_ip = ip_match.group() if ip_match else 'Unknown'

                                if host_ip and host_ip not in target_ips:
                                    # Parse port/service info from content
                                    ports = []
                                    for line in content.split('\n'):
                                        if '/tcp' in line or '/udp' in line:
                                            parts = line.split()
                                            if len(parts) >= 1:
                                                port = parts[0].split('/')[0]  # Extract port number only
                                                if port.isdigit() and port not in ports:
                                                    ports.append(port)

                                    targets.append({
                                        'ip': host_ip,
                                        'hostname': host_ip,  # Use IP as hostname if no other info
                                        'ports': ports,
                                        'mac': '00:00:00:00:00:00',  # Default MAC for NetKB entries
                                        'source': 'NetKB'
                                    })
                                    target_ips.add(host_ip)
                    except Exception:
                        continue

        # Add example targets if no real data exists
        if not targets:
            targets = [
                {
                    'ip': '192.168.1.1',
                    'hostname': '192.168.1.1',
                    'ports': ['22', '80', '443'],
                    'source': 'Example'
                },
                {
                    'ip': '192.168.1.100',
                    'hostname': '192.168.1.100',
                    'ports': ['80', '443'],
                    'source': 'Example'
                }
            ]
    except Exception as e:
        logger.error(f"Error processing NetKB data for targets: {e}")

    return targets


def _emit_manual_attack_update(action, ip, port, stage, message, status='info'):
    try:
        socketio.emit('manual_attack_update', {
            'action': action,
            'ip': ip,
            'port': port,
            'stage': stage,
            'status': status,
            'message': message,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    except Exception as exc:
        logger.warning(f"Failed to emit manual attack update: {exc}")


def _get_existing_credentials_snapshot(action, ip):
    attr = MANUAL_ATTACK_CREDENTIAL_ATTR.get(action)
    if not attr:
        return []

    credential_file = getattr(shared_data, attr, None)
    if not credential_file or not os.path.exists(credential_file):
        return []

    try:
        return CredentialChecker.check_existing_credentials(credential_file, ip) or []
    except Exception as exc:
        logger.warning(f"Unable to read credential cache for {action} on {ip}: {exc}")
        return []





def _is_port_allowed_for_action(action, port_value):
    normalized_port = _normalize_port_value(port_value)
    if not normalized_port:
        return False

    action_config = MANUAL_ATTACK_MATRIX.get(action)
    if not action_config:
        return False

    allowed_ports = {str(port) for port in action_config.get('ports', [])}
    return normalized_port in allowed_ports


def _manual_attack_matrix_payload():
    payload = {}
    for action, config in MANUAL_ATTACK_MATRIX.items():
        payload[action] = {
            'label': config.get('label', action.upper()),
            'ports': config.get('ports', [])
        }
    return payload


@app.route('/api/manual/targets')
def get_manual_targets():
    """Get available targets for manual attacks"""
    try:
        targets = _collect_manual_targets()
        return jsonify({'targets': targets, 'attack_matrix': _manual_attack_matrix_payload()})

    except Exception as e:
        logger.error(f"Error getting manual targets: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/manual/execute-attack', methods=['POST'])
def execute_manual_attack():
    """Execute a manual attack on a specific target"""
    try:
        data = request.get_json()
        target_ip = data.get('ip')
        target_port = data.get('port')
        attack_type = data.get('action')

        if not target_ip or not attack_type or not target_port:
            return jsonify({'success': False, 'error': 'Missing IP, attack type, or port'}), 400
        
        # Update status to show attack is active
        attack_display_names = {
            'ssh': 'SSHBruteforce',
            'ftp': 'FTPBruteforce',
            'telnet': 'TelnetBruteforce',
            'smb': 'SMBBruteforce',
            'rdp': 'RDPBruteforce',
            'sql': 'SQLBruteforce'
        }
        
        # Map attack types to module imports and execution
        attack_modules = {
            'ssh': 'actions.ssh_connector',
            'ftp': 'actions.ftp_connector', 
            'telnet': 'actions.telnet_connector',
            'smb': 'actions.smb_connector',
            'rdp': 'actions.rdp_connector',
            'sql': 'actions.sql_connector'
        }
        
        if attack_type not in attack_modules:
            shared_data.ragnarstatustext = "IDLE"
            shared_data.ragnarstatustext2 = "Invalid attack type"
            return jsonify({'success': False, 'error': 'Invalid attack type'}), 400

        normalized_port = _normalize_port_value(target_port)
        if not normalized_port:
            shared_data.ragnarstatustext = "IDLE"
            shared_data.ragnarstatustext2 = "Invalid port provided"
            return jsonify({'success': False, 'error': 'Invalid port supplied'}), 400

        if not _is_port_allowed_for_action(attack_type, normalized_port):
            allowed_ports = ', '.join(str(port) for port in MANUAL_ATTACK_MATRIX.get(attack_type, {}).get('ports', []))
            shared_data.ragnarstatustext = "IDLE"
            shared_data.ragnarstatustext2 = "Port/action mismatch"
            return jsonify({
                'success': False,
                'error': f"{attack_type.upper()} attacks are only permitted on port(s): {allowed_ports or 'restricted'}."
            }), 400

        target_port = normalized_port
        cached_credentials = _get_existing_credentials_snapshot(attack_type, target_ip)
        cached_count = len(cached_credentials)

        _emit_manual_attack_update(
            attack_type,
            target_ip,
            target_port,
            stage='queued',
            message=f"{attack_type.upper()} attack queued for {target_ip}:{target_port}",
            status='info'
        )

        status_name = attack_display_names.get(attack_type, f"{attack_type.upper()}Bruteforce")
        shared_data.ragnarstatustext = status_name
        shared_data.ragnarstatustext2 = f"Attacking: {target_ip}:{target_port}"

        # Immediately broadcast the status change
        broadcast_status_update()
        
        # Execute attack in background
        def execute_attack():
            try:
                _emit_manual_attack_update(
                    attack_type,
                    target_ip,
                    target_port,
                    stage='running',
                    message=f"{attack_type.upper()} module running on {target_ip}:{target_port}",
                    status='info'
                )
                # Import the attack module dynamically
                import importlib
                module = importlib.import_module(attack_modules[attack_type])
                
                # Create attack instance
                attack_class_name = attack_type.upper() + 'Bruteforce' if attack_type != 'sql' else 'SQLBruteforce'
                attack_class = getattr(module, attack_class_name, None)
                result_message = "Attack module unavailable"
                emit_status = 'error'
                
                if attack_class:
                    attack_instance = attack_class(shared_data)
                    # Execute with appropriate parameters
                    execution_result = None
                    if hasattr(attack_instance, 'execute'):
                        row = {'ip': target_ip, 'hostname': target_ip, 'mac': '00:00:00:00:00:00'}
                        execution_result = attack_instance.execute(target_ip, target_port, row, f"manual_{attack_type}")

                    updated_credentials = _get_existing_credentials_snapshot(attack_type, target_ip)
                    updated_count = len(updated_credentials)
                    delta = max(0, updated_count - cached_count)

                    if execution_result == 'success':
                        if delta > 0:
                            result_message = f"Captured {delta} new credential(s). Total stored: {updated_count}."
                        elif updated_count > 0:
                            result_message = f"Existing credentials verified ({updated_count} account(s))."
                        else:
                            result_message = "Module completed without discovering credentials."
                        emit_status = 'success'
                    else:
                        result_message = "Attack completed without valid credentials."
                        emit_status = 'warning'
                else:
                    result_message = f"{attack_type.upper()} module is unavailable on this build."
                    
                # Update status when attack completes
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"{attack_type.upper()} attack completed"
                
                # Broadcast completion status
                broadcast_status_update()
                _emit_manual_attack_update(
                    attack_type,
                    target_ip,
                    target_port,
                    stage='completed',
                    message=result_message,
                    status=emit_status
                )
                
                logger.info(f"Manual attack completed: {attack_type} on {target_ip}:{target_port}")
                    
            except Exception as e:
                logger.error(f"Error executing manual attack: {e}")
                # Reset status on error
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"Attack error: {str(e)[:40]}"
                # Broadcast error status
                broadcast_status_update()
                _emit_manual_attack_update(
                    attack_type,
                    target_ip,
                    target_port,
                    stage='error',
                    message=f"Manual {attack_type.upper()} attack failed: {str(e)[:80]}",
                    status='error'
                )
        
        # Start attack in background thread
        import threading
        threading.Thread(target=execute_attack, daemon=True).start()
        
        logger.info(f"Manual attack initiated: {attack_type} on {target_ip}:{target_port}")
        
        return jsonify({
            'success': True,
            'message': f'Manual {attack_type} attack initiated on {target_ip}' + (f':{target_port}' if target_port else '')
        })
        
    except Exception as e:
        logger.error(f"Error executing manual attack: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/orchestrator/start', methods=['POST'])
def start_orchestrator_automation():
    """Start the orchestrator thread to enable automation."""
    try:
        ragnar_instance = getattr(shared_data, 'ragnar_instance', None)
        if not ragnar_instance:
            return jsonify({'success': False, 'error': 'Core Ragnar instance is not initialized yet'}), 503

        if is_orchestrator_running():
            return jsonify({
                'success': True,
                'message': 'Automation already running',
                'automation_enabled': True
            })

        ragnar_instance.start_orchestrator()
        automation_enabled = is_orchestrator_running()

        broadcast_status_update()

        message = 'Automation enabled - orchestrator awake' if automation_enabled else 'Automation start requested - waiting for Wi-Fi'
        return jsonify({
            'success': True,
            'message': message,
            'automation_enabled': automation_enabled
        })

    except Exception as e:
        logger.error(f"Error enabling automation: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/automation/orchestrator/stop', methods=['POST'])
def stop_orchestrator_automation():
    """Stop the orchestrator thread so automation sleeps."""
    try:
        ragnar_instance = getattr(shared_data, 'ragnar_instance', None)
        if not ragnar_instance:
            return jsonify({'success': False, 'error': 'Core Ragnar instance is not initialized yet'}), 503

        if not is_orchestrator_running():
            broadcast_status_update()
            return jsonify({
                'success': True,
                'message': 'Automation already sleeping',
                'automation_enabled': False
            })

        ragnar_instance.stop_orchestrator()
        automation_enabled = is_orchestrator_running()
        broadcast_status_update()

        return jsonify({
            'success': True,
            'message': 'Automation disabled - orchestrator sleeping',
            'automation_enabled': automation_enabled
        })

    except Exception as e:
        logger.error(f"Error disabling automation: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/manual/orchestrator/start', methods=['POST'])
def start_orchestrator_manual():
    """Start the orchestrator in manual mode"""
    try:
        # Update shared data to indicate manual mode
        shared_data.config['manual_mode'] = True
        shared_data.save_config()  # Save the configuration
        
        logger.info("Manual mode enabled")
        
        return jsonify({
            'success': True,
            'message': 'Manual mode enabled - use individual triggers for actions'
        })
        
    except Exception as e:
        logger.error(f"Error enabling manual mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/manual/orchestrator/stop', methods=['POST'])
def stop_orchestrator_manual():
    """Disable manual mode"""
    try:
        # Update shared data to disable manual mode
        shared_data.config['manual_mode'] = False
        shared_data.save_config()  # Save the configuration
        
        logger.info("Manual mode disabled")
        
        return jsonify({
            'success': True,
            'message': 'Manual mode disabled'
        })
        
    except Exception as e:
        logger.error(f"Error disabling manual mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/scan/network', methods=['POST'])
def trigger_network_scan():
    """Trigger a manual network scan"""
    try:
        data = request.get_json()
        target_range = data.get('range', '192.168.1.0/24')  # Default range
        
        # Update status to show scanning is active
        shared_data.ragnarstatustext = "NetworkScanner"
        shared_data.ragnarstatustext2 = f"Manual scan: {target_range}"
        
        # Immediately broadcast the status change
        broadcast_status_update()
        
        # Execute scan in background
        def execute_scan():
            try:
                # Import and create scanner
                from actions.scanning import NetworkScanner
                scanner = NetworkScanner(shared_data)
                
                # Run the scan
                scanner.scan()
                
                # Update status when scan completes
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = "Manual scan completed"
                
                # Broadcast completion status
                broadcast_status_update()
                
                logger.info(f"Manual network scan completed for range: {target_range}")
                
            except Exception as e:
                logger.error(f"Error executing network scan: {e}")
                # Reset status on error
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"Scan error: {str(e)[:50]}"
                # Broadcast error status
                broadcast_status_update()
        
        # Start scan in background thread
        import threading
        threading.Thread(target=execute_scan, daemon=True).start()
        
        logger.info(f"Manual network scan initiated for range: {target_range}")
        
        return jsonify({
            'success': True,
            'message': f'Network scan initiated for {target_range}'
        })
        
    except Exception as e:
        logger.error(f"Error triggering network scan: {e}")
        # Reset status on error
        shared_data.ragnarstatustext = "IDLE"
        shared_data.ragnarstatustext2 = f"Failed to start scan"
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/scan/vulnerability', methods=['POST'])
def trigger_vulnerability_scan():
    """Trigger a manual vulnerability scan using the proper NmapVulnScanner method"""
    try:
        data = request.get_json(silent=True) or {}
        target_ip = (data.get('ip') or '').strip()

        available_targets = _collect_manual_targets()
        if not available_targets:
            return jsonify({'success': False, 'error': 'No targets available for vulnerability scan'}), 400

        is_all_targets = not target_ip or target_ip.lower() == 'all'

        if not is_all_targets:
            # Check if specific target exists
            target_found = any(t.get('ip') == target_ip for t in available_targets)
            if not target_found:
                return jsonify({'success': False, 'error': f'Target {target_ip} not found'}), 404

        status_target = 'All Targets' if is_all_targets else target_ip

        # Update status to show vulnerability scanning is active
        shared_data.ragnarstatustext = "NmapVulnScanner"
        shared_data.ragnarstatustext2 = f"Starting scan: {status_target}"

        # Immediately broadcast the status change
        broadcast_status_update()

        # Execute vulnerability scan in background using proper method
        def execute_vuln_scan():
            try:
                # Import and create vulnerability scanner
                from actions.nmap_vuln_scanner import NmapVulnScanner
                vuln_scanner = NmapVulnScanner(shared_data)

                def progress_callback(event_type, data):
                    """Real-time callback for vulnerability scan progress"""
                    try:
                        if event_type == "scan_started":
                            shared_data.ragnarstatustext2 = f"Scanning {data.get('total_hosts', 0)} hosts"
                            broadcast_status_update()
                        elif event_type == "scan_progress":
                            current_ip = data.get('current_ip', '')
                            scanned = data.get('scanned', 0)
                            total = data.get('total_hosts', 0)
                            progress = data.get('progress_percent', 0)
                            shared_data.ragnarstatustext2 = f"Scanning {current_ip} ({scanned}/{total}) - {progress}%"
                            broadcast_status_update()
                        elif event_type == "scan_completed":
                            scanned_count = data.get('scanned', 0)
                            shared_data.ragnarstatustext2 = f"Completed: {scanned_count} hosts scanned"
                            broadcast_status_update()
                        elif event_type == "scan_error":
                            error_ip = data.get('ip', 'unknown')
                            shared_data.ragnarstatustext2 = f"Error scanning {error_ip}"
                            broadcast_status_update()
                    except Exception as callback_error:
                        logger.error(f"Error in vulnerability scan callback: {callback_error}")

                if is_all_targets:
                    # Use force_scan_all_hosts for all targets - this is the proper method
                    scanned_count = vuln_scanner.force_scan_all_hosts(real_time_callback=progress_callback)
                    logger.info(f"Manual vulnerability scan completed: {scanned_count} hosts scanned")
                else:
                    # For single target, use scan_single_host_realtime method
                    target = next((t for t in available_targets if t.get('ip') == target_ip), None)
                    if target:
                        hostname = target.get('hostname', target_ip)
                        mac = target.get('mac', '00:00:00:00:00:00')
                        ports = target.get('ports', [])
                        ports_str = ';'.join([str(p) for p in ports]) if ports else ''
                        
                        result = vuln_scanner.scan_single_host_realtime(
                            ip=target_ip,
                            hostname=hostname,
                            mac=mac,
                            ports=ports_str,
                            callback=progress_callback
                        )
                        logger.info(f"Single host vulnerability scan completed for {target_ip}: {result}")

                # Update status when scan completes
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = "Vulnerability scan completed"
                broadcast_status_update()
                
            except Exception as e:
                logger.error(f"Error executing vulnerability scan: {e}")
                # Reset status on error
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"Vuln scan error: {str(e)[:40]}"
                broadcast_status_update()
        
        # Start scan in background thread
        import threading
        threading.Thread(target=execute_vuln_scan, daemon=True).start()
        
        logger.info(f"Manual vulnerability scan initiated for: {status_target}")

        return jsonify({
            'success': True,
            'message': 'Vulnerability scan initiated for all targets' if is_all_targets else f'Vulnerability scan initiated for {target_ip}'
        })
        
    except Exception as e:
        logger.error(f"Error triggering vulnerability scan: {e}")
        # Reset status on error
        shared_data.ragnarstatustext = "IDLE"
        shared_data.ragnarstatustext2 = f"Failed to start vuln scan"
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/manual/pentest/lynis', methods=['POST'])
def run_manual_lynis_pentest():
    """Manually trigger a Lynis pentest for a specific host."""
    try:
        if not shared_data.config.get('manual_mode', False):
            return jsonify({'success': False, 'error': 'Enable Pentest Mode to run manual pentests'}), 400

        data = request.get_json(silent=True) or {}
        target_ip = (data.get('ip') or '').strip()
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''

        if not target_ip or not username or not password:
            return jsonify({'success': False, 'error': 'IP, username, and password are required'}), 400

        shared_data.ragnarstatustext = "LynisPentest"
        shared_data.ragnarstatustext2 = f"Manual pentest: {target_ip}"
        broadcast_status_update()

        def execute_manual_lynis():
            try:
                # Emit scan started event
                socketio.emit('lynis_update', {
                    'type': 'lynis_started',
                    'ip': target_ip,
                    'message': f'Starting Lynis security audit on {target_ip}...'
                })
                
                # Define progress callback to emit real-time updates
                def progress_callback(event_type, data):
                    socketio.emit('lynis_update', {
                        'type': 'lynis_progress',
                        'event': event_type,
                        'ip': target_ip,
                        'message': data.get('message', ''),
                        'stage': data.get('stage'),
                        'details': data.get('details')
                    })
                
                action = LynisPentestSSH(shared_data)
                status = action.run_manual(target_ip, username, password, progress_callback=progress_callback)
                success = status == 'success'
                
                # Emit final result
                if success:
                    socketio.emit('lynis_update', {
                        'type': 'lynis_completed',
                        'ip': target_ip,
                        'message': f'Lynis audit completed successfully for {target_ip}'
                    })
                else:
                    socketio.emit('lynis_update', {
                        'type': 'lynis_error',
                        'ip': target_ip,
                        'message': f'Lynis audit failed for {target_ip}'
                    })
                
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = (
                    "Lynis pentest completed" if success else "Lynis pentest failed"
                )
                broadcast_status_update()
                logger.info(f"Manual Lynis pentest finished for {target_ip} with status: {status}")
            except Exception as exc:
                logger.error(f"Error during manual Lynis pentest for {target_ip}: {exc}")
                socketio.emit('lynis_update', {
                    'type': 'lynis_error',
                    'ip': target_ip,
                    'message': f'Lynis audit error: {str(exc)}'
                })
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = "Lynis pentest error"
                broadcast_status_update()

        threading.Thread(target=execute_manual_lynis, daemon=True).start()

        return jsonify({'success': True, 'message': f'Lynis pentest initiated for {target_ip}'})

    except Exception as e:
        logger.error(f"Error starting manual Lynis pentest: {e}")
        shared_data.ragnarstatustext = "IDLE"
        shared_data.ragnarstatustext2 = "Lynis pentest error"
        broadcast_status_update()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# FILE MANAGEMENT ENDPOINTS
# ============================================================================

def _get_networks_dir():
    """Return the filesystem path to the per-network storage root."""
    manager = getattr(shared_data, 'storage_manager', None)
    if manager:
        return getattr(manager, 'networks_dir', os.path.join(shared_data.datadir, 'networks'))
    return os.path.join(shared_data.datadir, 'networks')


def _list_all_networks():
    """Return [{slug, ssid, network_dir}] for every known network directory."""
    networks_dir = _get_networks_dir()
    result = []
    if not os.path.isdir(networks_dir):
        return result
    for slug in sorted(os.listdir(networks_dir)):
        if slug.startswith('.'):
            continue
        network_dir = os.path.join(networks_dir, slug)
        if not os.path.isdir(network_dir):
            continue
        ssid = slug
        ssid_file = os.path.join(network_dir, 'ssid.txt')
        if os.path.exists(ssid_file):
            try:
                with open(ssid_file, 'r', encoding='utf-8') as _f:
                    ssid = _f.read().strip() or slug
            except IOError:
                pass
        result.append({'slug': slug, 'ssid': ssid, 'network_dir': network_dir})
    return result


def _resolve_loot_path(virtual_root, network_rel_path, path):
    """
    Resolve a virtual per-network path to a real filesystem path.

    network_rel_path is the subdirectory relative to the network root, e.g.:
      'loot/data_stolen', 'loot/credentials',
      'output/scan_results', 'output/vulnerabilities'

    Returns None when the caller should show the network list (path == virtual_root).
    Raises ValueError on path traversal or invalid slug.
    """
    remainder = path[len(virtual_root):].lstrip('/')
    if not remainder:
        return None  # show network list

    parts = remainder.split('/', 1)
    slug = parts[0]
    subpath = parts[1] if len(parts) > 1 else ''

    # Validate slug: must be alphanumeric + underscores only (mirrors slugify output)
    if not slug or not all(c.isalnum() or c == '_' for c in slug):
        raise ValueError(f'Invalid network slug: {slug}')

    networks_dir = _get_networks_dir()
    category_dir = os.path.join(networks_dir, slug, *network_rel_path.split('/'))
    actual = os.path.join(category_dir, subpath) if subpath else category_dir

    # Security: path must stay within networks_dir
    real_actual = os.path.realpath(actual)
    real_networks = os.path.realpath(networks_dir)
    if not real_actual.startswith(real_networks + os.sep) and real_actual != real_networks:
        raise ValueError('Path traversal detected')

    return actual


def _network_loot_dirs(network_rel_path, virtual_root):
    """Return a list-API response listing all networks as virtual directories."""
    networks = _list_all_networks()
    dirs = []
    for n in networks:
        category_dir = os.path.join(n['network_dir'], *network_rel_path.split('/'))
        mtime = 0
        if os.path.isdir(category_dir):
            try:
                mtime = os.path.getmtime(category_dir)
            except OSError:
                pass
        dirs.append({
            'name': n['ssid'],
            'is_directory': True,
            'path': f"{virtual_root}/{n['slug']}",
            'size': 0,
            'modified': mtime,
        })
    return dirs


# ---------------------------------------------------------------------------
# PR 3 — Scanned Networks Tab endpoints
# ---------------------------------------------------------------------------

@app.route('/api/networks/all')
def get_all_scanned_networks():
    """Return summary info for every network Ragnar has ever scanned."""
    try:
        networks = _list_all_networks()
        result = []
        for net in networks:
            nd = net['network_dir']
            stats = _network_dir_stats(nd)
            result.append({
                'slug': net['slug'],
                'ssid': net['ssid'],
                'last_seen': stats['last_seen'],
                'file_count': stats['file_count'],
                'has_loot': stats['has_loot'],
                'has_creds': stats['has_creds'],
                'has_vulns': stats['has_vulns'],
                'has_scans': stats['has_scans'],
            })
        return jsonify({'success': True, 'networks': result, 'total': len(result)})
    except Exception as exc:
        logger.error(f"Error listing all networks: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


def _network_dir_stats(network_dir):
    """Compute lightweight stats for a single network directory."""
    import time as _time

    category_paths = {
        'has_loot':  os.path.join(network_dir, 'loot', 'data_stolen'),
        'has_creds': os.path.join(network_dir, 'loot', 'credentials'),
        'has_vulns': os.path.join(network_dir, 'output', 'vulnerabilities'),
        'has_scans': os.path.join(network_dir, 'output', 'scan_results'),
    }

    flags = {}
    file_count = 0
    latest_mtime = 0.0

    for flag, path in category_paths.items():
        if not os.path.isdir(path):
            flags[flag] = False
            continue
        entries = []
        for root, _, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    mtime = os.path.getmtime(fp)
                    if mtime > latest_mtime:
                        latest_mtime = mtime
                    file_count += 1
                    entries.append(fp)
                except OSError:
                    pass
        flags[flag] = bool(entries)

    if latest_mtime:
        import datetime as _dt
        last_seen = _dt.datetime.fromtimestamp(latest_mtime).strftime('%Y-%m-%d %H:%M')
    else:
        last_seen = ''

    return {**flags, 'file_count': file_count, 'last_seen': last_seen}


@app.route('/api/networks/<slug>/files')
def get_network_files(slug):
    """Return a flat list of files stored under a specific network's directory."""
    try:
        # Validate slug
        if not slug or not all(c.isalnum() or c == '_' for c in slug):
            return jsonify({'success': False, 'error': 'Invalid network slug'}), 400

        networks_dir = _get_networks_dir()
        network_dir = os.path.join(networks_dir, slug)

        if not os.path.isdir(network_dir):
            return jsonify({'success': False, 'error': 'Network not found'}), 404

        # Read human-readable SSID
        ssid = slug
        ssid_file = os.path.join(network_dir, 'ssid.txt')
        if os.path.exists(ssid_file):
            try:
                with open(ssid_file, 'r', encoding='utf-8') as _f:
                    ssid = _f.read().strip() or slug
            except IOError:
                pass

        # Categories to expose and their virtual path prefixes
        categories = {
            'data_stolen':    os.path.join(network_dir, 'loot', 'data_stolen'),
            'credentials':    os.path.join(network_dir, 'loot', 'credentials'),
            'vulnerabilities': os.path.join(network_dir, 'output', 'vulnerabilities'),
            'scan_results':   os.path.join(network_dir, 'output', 'scan_results'),
        }

        files = []
        for category, cat_dir in categories.items():
            if not os.path.isdir(cat_dir):
                continue
            for root, _, filenames in os.walk(cat_dir):
                for fname in sorted(filenames):
                    fp = os.path.join(root, fname)
                    try:
                        stat = os.stat(fp)
                        # Build a virtual path reachable via /api/files/download
                        rel = os.path.relpath(fp, os.path.join(networks_dir))
                        # Map back to the virtual file-browser namespace
                        virtual_map = {
                            'data_stolen':    '/data_stolen',
                            'credentials':    '/crackedpwd',
                            'vulnerabilities': '/vulnerabilities',
                            'scan_results':   '/scan_results',
                        }
                        vroot = virtual_map[category]
                        inner = os.path.relpath(fp, cat_dir).replace('\\', '/')
                        virtual_path = f"{vroot}/{slug}/{inner}"

                        files.append({
                            'filename': fname,
                            'category': category,
                            'size': _format_bytes_simple(stat.st_size),
                            'modified': _format_timestamp_simple(stat.st_mtime),
                            'virtual_path': virtual_path,
                        })
                    except OSError:
                        pass

        return jsonify({
            'success': True,
            'slug': slug,
            'ssid': ssid,
            'files': files,
            'total': len(files),
        })
    except Exception as exc:
        logger.error(f"Error listing files for network '{slug}': {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


def _format_bytes_simple(size):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != 'B' else f"{size} B"
        size /= 1024
    return f"{size:.1f} TB"


def _format_timestamp_simple(ts):
    import datetime as _dt
    try:
        return _dt.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
    except Exception:
        return ''


@app.route('/api/files/list')
def list_files_api():
    """List files in a directory for file management"""
    try:
        path = request.args.get('path', '/')
        
        # Map root paths to actual directories
        if path == '/' or path == '':
            # List main directories
            return jsonify([
                {'name': 'data_stolen', 'is_directory': True, 'path': '/data_stolen'},
                {'name': 'scan_results', 'is_directory': True, 'path': '/scan_results'},
                {'name': 'crackedpwd', 'is_directory': True, 'path': '/crackedpwd'},
                {'name': 'vulnerabilities', 'is_directory': True, 'path': '/vulnerabilities'},
                {'name': 'logs', 'is_directory': True, 'path': '/logs'},
                {'name': 'backups', 'is_directory': True, 'path': '/backups'},
                {'name': 'uploads', 'is_directory': True, 'path': '/uploads'}
            ])
        
        # Map paths to actual directories
        actual_path = ""
        if path.startswith('/data_stolen'):
            actual_path = _resolve_loot_path('/data_stolen', 'loot/data_stolen', path)
            if actual_path is None:
                return jsonify(_network_loot_dirs('loot/data_stolen', '/data_stolen'))
        elif path.startswith('/scan_results'):
            actual_path = _resolve_loot_path('/scan_results', 'output/scan_results', path)
            if actual_path is None:
                return jsonify(_network_loot_dirs('output/scan_results', '/scan_results'))
        elif path.startswith('/crackedpwd'):
            actual_path = _resolve_loot_path('/crackedpwd', 'loot/credentials', path)
            if actual_path is None:
                return jsonify(_network_loot_dirs('loot/credentials', '/crackedpwd'))
        elif path.startswith('/vulnerabilities'):
            actual_path = _resolve_loot_path('/vulnerabilities', 'output/vulnerabilities', path)
            if actual_path is None:
                return jsonify(_network_loot_dirs('output/vulnerabilities', '/vulnerabilities'))
        elif path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs'
            if len(path) > 5:  # More than just '/logs'
                actual_path = os.path.join(actual_path, path[6:])
        elif path.startswith('/backups'):
            actual_path = shared_data.backupdir
            if len(path) > 8:  # More than just '/backups'
                actual_path = os.path.join(actual_path, path[9:])
        elif path.startswith('/uploads'):
            actual_path = shared_data.upload_dir
            if len(path) > 8:  # More than just '/uploads'
                actual_path = os.path.join(actual_path, path[9:])
        else:
            return jsonify({'error': 'Invalid path'}), 400
        
        # Check if directory exists
        if not os.path.exists(actual_path):
            return jsonify([])
        
        # List files in directory
        files = []
        for entry in os.scandir(actual_path):
            files.append({
                'name': entry.name,
                'is_directory': entry.is_dir(),
                'path': os.path.join(path, entry.name),
                'size': entry.stat().st_size if entry.is_file() else 0,
                'modified': entry.stat().st_mtime
            })
        
        # Sort files - directories first, then by name
        files.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))
        
        return jsonify(files)
        
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/preview')
def preview_file_api():
    """Preview file contents inline — text, CSV, images"""
    import mimetypes, base64
    try:
        file_path = request.args.get('path')
        if not file_path:
            return jsonify({'error': 'File path required'}), 400

        # Map virtual path to actual path
        actual_path = ''
        if file_path.startswith('/data_stolen'):
            resolved = _resolve_loot_path('/data_stolen', 'loot/data_stolen', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid path'}), 400
            actual_path = resolved
        elif file_path.startswith('/scan_results'):
            resolved = _resolve_loot_path('/scan_results', 'output/scan_results', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid path'}), 400
            actual_path = resolved
        elif file_path.startswith('/crackedpwd'):
            resolved = _resolve_loot_path('/crackedpwd', 'loot/credentials', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid path'}), 400
            actual_path = resolved
        elif file_path.startswith('/vulnerabilities'):
            resolved = _resolve_loot_path('/vulnerabilities', 'output/vulnerabilities', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid path'}), 400
            actual_path = resolved
        elif file_path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs' + file_path[5:]
        elif file_path.startswith('/backups'):
            actual_path = shared_data.backupdir + file_path[8:]
        elif file_path.startswith('/uploads'):
            actual_path = shared_data.upload_dir + file_path[8:]
        else:
            return jsonify({'error': 'Invalid path'}), 400

        if not os.path.isfile(actual_path):
            return jsonify({'error': 'File not found'}), 404

        # Security: ensure path doesn't escape allowed dirs
        actual_path = os.path.realpath(actual_path)

        mime_type, _ = mimetypes.guess_type(actual_path)
        mime_type = mime_type or 'application/octet-stream'
        file_size = os.path.getsize(actual_path)
        ext = os.path.splitext(actual_path)[1].lower()

        TEXT_EXTENSIONS = {'.txt', '.log', '.csv', '.json', '.xml', '.yaml', '.yml',
                           '.md', '.conf', '.cfg', '.ini', '.nmap', '.gnmap', '.sh', '.py'}
        IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg'}

        if ext in IMAGE_EXTENSIONS:
            if file_size > 5 * 1024 * 1024:  # 5MB limit for images
                return jsonify({'type': 'too_large', 'size': file_size, 'name': os.path.basename(actual_path)})
            with open(actual_path, 'rb') as f:
                data = base64.b64encode(f.read()).decode('ascii')
            return jsonify({'type': 'image', 'mime': mime_type, 'data': data, 'name': os.path.basename(actual_path)})

        elif ext in TEXT_EXTENSIONS or (mime_type and mime_type.startswith('text/')):
            if file_size > 512 * 1024:  # 512KB limit for text
                # Return first 512KB with truncation notice
                with open(actual_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read(512 * 1024)
                return jsonify({'type': 'text', 'content': content, 'truncated': True,
                                'size': file_size, 'name': os.path.basename(actual_path)})
            with open(actual_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            return jsonify({'type': 'text', 'content': content, 'truncated': False,
                            'size': file_size, 'name': os.path.basename(actual_path)})
        else:
            return jsonify({'type': 'binary', 'mime': mime_type,
                            'size': file_size, 'name': os.path.basename(actual_path)})

    except Exception as e:
        logger.error(f"Error previewing file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/download')
def download_file_api():
    """Download a file"""
    try:
        file_path = request.args.get('path')
        if not file_path:
            return jsonify({'error': 'File path required'}), 400

        # Map virtual path to actual path
        actual_path = ""
        if file_path.startswith('/data_stolen'):
            resolved = _resolve_loot_path('/data_stolen', 'loot/data_stolen', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid file path'}), 400
            actual_path = resolved
        elif file_path.startswith('/scan_results'):
            resolved = _resolve_loot_path('/scan_results', 'output/scan_results', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid file path'}), 400
            actual_path = resolved
        elif file_path.startswith('/crackedpwd'):
            resolved = _resolve_loot_path('/crackedpwd', 'loot/credentials', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid file path'}), 400
            actual_path = resolved
        elif file_path.startswith('/vulnerabilities'):
            resolved = _resolve_loot_path('/vulnerabilities', 'output/vulnerabilities', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid file path'}), 400
            actual_path = resolved
        elif file_path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs' + file_path[5:]
        elif file_path.startswith('/backups'):
            actual_path = shared_data.backupdir + file_path[8:]
        elif file_path.startswith('/uploads'):
            actual_path = shared_data.upload_dir + file_path[8:]
        else:
            return jsonify({'error': 'Invalid file path'}), 400

        if not os.path.isfile(actual_path):
            return jsonify({'error': 'File not found'}), 404

        return send_from_directory(
            os.path.dirname(actual_path),
            os.path.basename(actual_path),
            as_attachment=True
        )
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/delete', methods=['POST'])
def delete_file_api():
    """Delete a file or directory"""
    try:
        data = request.get_json()
        file_path = data.get('path')
        
        if not file_path:
            return jsonify({'error': 'File path required'}), 400
        
        # Map virtual path to actual path
        actual_path = ""
        if file_path.startswith('/data_stolen'):
            resolved = _resolve_loot_path('/data_stolen', 'loot/data_stolen', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid file path'}), 400
            actual_path = resolved
        elif file_path.startswith('/scan_results'):
            resolved = _resolve_loot_path('/scan_results', 'output/scan_results', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid file path'}), 400
            actual_path = resolved
        elif file_path.startswith('/crackedpwd'):
            resolved = _resolve_loot_path('/crackedpwd', 'loot/credentials', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid file path'}), 400
            actual_path = resolved
        elif file_path.startswith('/vulnerabilities'):
            resolved = _resolve_loot_path('/vulnerabilities', 'output/vulnerabilities', file_path)
            if resolved is None:
                return jsonify({'error': 'Invalid file path'}), 400
            actual_path = resolved
        elif file_path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs' + file_path[5:]
        elif file_path.startswith('/backups'):
            actual_path = shared_data.backupdir + file_path[8:]
        elif file_path.startswith('/uploads'):
            actual_path = shared_data.upload_dir + file_path[8:]
        else:
            return jsonify({'error': 'Invalid file path'}), 400

        if not os.path.exists(actual_path):
            return jsonify({'error': 'File not found'}), 404

        # Delete file or directory
        if os.path.isdir(actual_path):
            import shutil
            shutil.rmtree(actual_path)
            logger.info(f"Deleted directory: {actual_path}")
        else:
            os.remove(actual_path)
            logger.info(f"Deleted file: {actual_path}")
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/upload', methods=['POST'])
def upload_file_api():
    """Upload a file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        target_path = request.form.get('path', '/uploads')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Map virtual path to actual path
        actual_dir = ""
        if target_path.startswith('/uploads'):
            actual_dir = shared_data.upload_dir
        elif target_path.startswith('/backups'):
            actual_dir = shared_data.backupdir
        else:
            return jsonify({'error': 'Invalid upload path'}), 400
        
        # Create directory if it doesn't exist
        os.makedirs(actual_dir, exist_ok=True)
        
        # Save file
        filename = file.filename
        if not filename:
            return jsonify({'error': 'Invalid filename'}), 400
            
        actual_path = os.path.join(actual_dir, filename)
        file.save(actual_path)
        
        logger.info(f"File uploaded: {actual_path}")
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'filename': filename
        })
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/clear', methods=['POST'])
def clear_files_api():
    """Clear files from specified directories"""
    try:
        data = request.get_json()
        clear_type = data.get('type', 'light')  # 'light' or 'full'
        
        if clear_type == 'light':
            # Clear only logs and temporary files (like clear_files_light)
            command = f"""
            rm -rf {shared_data.datadir}/*.log && 
            rm -rf {shared_data.datastolendir}/* && 
            rm -rf {shared_data.crackedpwddir}/* && 
            rm -rf {shared_data.scan_results_dir}/* && 
            rm -rf {shared_data.datadir}/logs/* && 
            rm -rf {shared_data.vulnerabilities_dir}/*
            """
        else:
            # Full clear (like clear_files)
            command = f"""
            rm -rf {shared_data.configdir}/*.json && 
            rm -rf {shared_data.datadir}/*.csv && 
            rm -rf {shared_data.datadir}/*.log && 
            rm -rf {shared_data.backupdir}/* && 
            rm -rf {shared_data.upload_dir}/* && 
            rm -rf {shared_data.datastolendir}/* && 
            rm -rf {shared_data.crackedpwddir}/* && 
            rm -rf {shared_data.scan_results_dir}/* && 
            rm -rf {shared_data.datadir}/logs/* && 
            rm -rf {shared_data.vulnerabilities_dir}/*
            """
        
        import subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Files cleared successfully ({clear_type} clear)")
            return jsonify({
                'success': True,
                'message': f'Files cleared successfully ({clear_type} clear)'
            })
        else:
            logger.error(f"Error clearing files: {result.stderr}")
            return jsonify({'error': result.stderr}), 500
        
    except Exception as e:
        logger.error(f"Error clearing files: {e}")
        return jsonify({'error': str(e)}), 500

# Legacy endpoint compatibility
@app.route('/list_files')
def legacy_list_files():
    """Legacy endpoint for file listing"""
    try:
        path = request.args.get('path', '/')
        
        # Use the same logic as list_files_api but return legacy format
        if path == '/' or path == '':
            return jsonify([
                {'name': 'data_stolen', 'is_directory': True, 'children': []},
                {'name': 'scan_results', 'is_directory': True, 'children': []},
                {'name': 'crackedpwd', 'is_directory': True, 'children': []},
                {'name': 'vulnerabilities', 'is_directory': True, 'children': []},
                {'name': 'logs', 'is_directory': True, 'children': []},
                {'name': 'backups', 'is_directory': True, 'children': []},
                {'name': 'uploads', 'is_directory': True, 'children': []}
            ])
        
        # For other paths, use the web_utils function
        actual_path = ""
        if path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir
        elif path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir
        elif path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir
        elif path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir
        elif path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs'
        elif path.startswith('/backups'):
            actual_path = shared_data.backupdir
        elif path.startswith('/uploads'):
            actual_path = shared_data.upload_dir
        
        if actual_path and os.path.exists(actual_path):
            return jsonify(web_utils.list_files(actual_path))
        else:
            return jsonify([])
        
    except Exception as e:
        logger.error(f"Error in legacy file listing: {e}")
        return jsonify([])

@app.route('/download_file')
def legacy_download_file():
    """Legacy endpoint for file download"""
    try:
        file_path = request.args.get('path')
        if not file_path:
            return "File path required", 400
            
        # Check if file exists in data_stolen directory
        actual_path = os.path.join(shared_data.datastolendir, file_path)
        if os.path.isfile(actual_path):
            return send_from_directory(
                os.path.dirname(actual_path),
                os.path.basename(actual_path),
                as_attachment=True
            )
        else:
            return "File not found", 404
    except Exception as e:
        logger.error(f"Error in legacy file download: {e}")
        return str(e), 500

# ============================================================================
# (Image gallery endpoints removed)
# ============================================================================

def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    if bytes_value == 0:
        return '0 B'
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"

# ============================================================================
# SYSTEM MONITORING ENDPOINTS
# ============================================================================

@app.route('/api/system/status')
def get_system_status_api():
    """Get comprehensive system status"""
    try:
        if not psutil_available:
            return jsonify({'error': 'System monitoring not available'}), 503
            
        # CPU Information
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        # Memory Information
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk Information
        disk = psutil.disk_usage('/')
        
        # Network Interfaces
        net_if = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()
        
        # System Information
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        # Process Information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': pinfo['cpu_percent'],
                    'memory_percent': pinfo['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort processes by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        processes = processes[:10]  # Top 10 processes
        
        # Temperature (if available)
        try:
            if hasattr(psutil, 'sensors_temperatures'):
                temps_func = getattr(psutil, 'sensors_temperatures')
                temps = temps_func()
                temperature_data = {}
                for name, entries in temps.items():
                    for entry in entries:
                        temperature_data[f"{name}_{entry.label}"] = entry.current
            else:
                temperature_data = {}
        except Exception:
            temperature_data = {}
        
        # Battery (PiSugar UPS - only if connected)
        battery_data = None
        try:
            ragnar_inst = getattr(shared_data, 'ragnar_instance', None)
            pisugar = getattr(ragnar_inst, 'pisugar_listener', None) if ragnar_inst else None
            if pisugar and pisugar.available:
                level = pisugar.get_battery_level()
                if level is not None:
                    voltage = pisugar.get_battery_voltage()
                    battery_data = {
                        'level': round(level, 1),
                        'charging': bool(pisugar.is_charging()),
                        'voltage': round(voltage, 2) if voltage is not None else None,
                        'model': pisugar.get_model(),
                    }
        except Exception:
            pass

        # Network interface details
        network_interfaces = []
        for interface, addrs in net_if.items():
            if interface in net_stats:
                stats = net_stats[interface]
                interface_info = {
                    'name': interface,
                    'is_up': stats.isup,
                    'speed': stats.speed,
                    'addresses': []
                }
                
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                
                network_interfaces.append(interface_info)
        
        system_status = {
            'cpu': {
                'percent': round(cpu_percent, 1),
                'count': cpu_count,
                'frequency': {
                    'current': round(cpu_freq.current, 2) if cpu_freq else None,
                    'min': round(cpu_freq.min, 2) if cpu_freq else None,
                    'max': round(cpu_freq.max, 2) if cpu_freq else None
                }
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percent': round(memory.percent, 1),
                'total_formatted': format_bytes(memory.total),
                'available_formatted': format_bytes(memory.available),
                'used_formatted': format_bytes(memory.used)
            },
            'swap': {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': round(swap.percent, 1) if swap.total > 0 else 0,
                'total_formatted': format_bytes(swap.total),
                'used_formatted': format_bytes(swap.used),
                'free_formatted': format_bytes(swap.free)
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': round((disk.used / disk.total) * 100, 1),
                'total_formatted': format_bytes(disk.total),
                'used_formatted': format_bytes(disk.used),
                'free_formatted': format_bytes(disk.free)
            },
            'uptime': {
                'seconds': round(uptime),
                'formatted': format_uptime(uptime)
            },
            'processes': processes,
            'network_interfaces': network_interfaces,
            'temperatures': temperature_data,
            'battery': battery_data
        }
        
        return jsonify(system_status)
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/processes')
def get_processes_api():
    """Get detailed process information"""
    try:
        if not psutil_available:
            return jsonify({'error': 'Process monitoring not available'}), 503
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': round(pinfo['cpu_percent'] or 0, 2),
                    'memory_percent': round(pinfo['memory_percent'] or 0, 2),
                    'status': pinfo['status'],
                    'create_time': pinfo['create_time']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        sort_by = request.args.get('sort', 'cpu')
        if sort_by == 'memory':
            processes.sort(key=lambda x: x['memory_percent'], reverse=True)
        else:
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        return jsonify(processes)
        
    except Exception as e:
        logger.error(f"Error getting processes: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/network-stats')
def get_network_stats_api():
    """Get network interface statistics"""
    try:
        if not psutil_available:
            return jsonify({'error': 'Network monitoring not available'}), 503
        
        net_io = psutil.net_io_counters(pernic=True)
        net_connections = psutil.net_connections()
        
        # Count connections by status
        connection_stats = {}
        for conn in net_connections:
            status = conn.status
            connection_stats[status] = connection_stats.get(status, 0) + 1
        
        network_stats = {
            'interfaces': {},
            'connections': connection_stats,
            'total_connections': len(net_connections)
        }
        
        for interface, stats in net_io.items():
            network_stats['interfaces'][interface] = {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout,
                'bytes_sent_formatted': format_bytes(stats.bytes_sent),
                'bytes_recv_formatted': format_bytes(stats.bytes_recv)
            }
        
        return jsonify(network_stats)
        
    except Exception as e:
        logger.error(f"Error getting network stats: {e}")
        return jsonify({'error': str(e)}), 500

def format_uptime(seconds):
    """Format uptime in human readable format"""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"


# ============================================================================
# SERVER MODE & ADVANCED FEATURES API ENDPOINTS
# ============================================================================

@app.route('/api/server/capabilities')
def get_server_capabilities_api():
    """Get server capabilities and feature availability"""
    try:
        from server_capabilities import get_server_capabilities
        caps = get_server_capabilities(shared_data)
        return jsonify({
            'success': True,
            'capabilities': caps.get_capabilities(),
            'features': caps.get_feature_status()
        })
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'Server capabilities module not available',
            'capabilities': {},
            'features': {
                'server_mode': False,
                'traffic_analysis': False,
                'advanced_vuln_assessment': False,
                'parallel_scanning': False,
                'local_ai': False,
                'large_dictionaries': False
            }
        })
    except Exception as e:
        logger.error(f"Error getting server capabilities: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/server/debug')
def debug_server_capabilities():
    """Debug endpoint to see raw capability detection values"""
    import platform
    import os
    
    debug_info = {
        'platform': {
            'machine': platform.machine(),
            'architecture': platform.architecture(),
            'system': platform.system(),
            'node': platform.node(),
            'release': platform.release(),
        },
        'cpu_count': os.cpu_count(),
    }
    
    # Try to get RAM info
    try:
        import psutil
        mem = psutil.virtual_memory()
        debug_info['ram'] = {
            'total_bytes': mem.total,
            'total_gb': mem.total / (1024**3),
            'available_gb': mem.available / (1024**3),
        }
    except ImportError:
        debug_info['ram'] = {'error': 'psutil not installed'}
    
    # Check device model on Linux
    try:
        model_path = '/sys/firmware/devicetree/base/model'
        if os.path.exists(model_path):
            with open(model_path, 'r') as f:
                debug_info['device_model'] = f.read().strip('\\x00').strip()
    except Exception as e:
        debug_info['device_model_error'] = str(e)
    
    # Get actual capabilities
    try:
        from server_capabilities import get_server_capabilities
        caps = get_server_capabilities(shared_data)
        debug_info['capabilities'] = caps.get_capabilities()
        debug_info['features'] = caps.get_feature_status()
    except Exception as e:
        debug_info['caps_error'] = str(e)
    
    return jsonify(debug_info)


@app.route('/api/server/install-tools', methods=['POST'])
def install_server_tools():
    """Install missing tools for a feature"""
    try:
        from server_capabilities import get_server_capabilities
        caps = get_server_capabilities(shared_data)
        
        if not caps.is_server_mode():
            return jsonify({
                'success': False,
                'error': 'Server mode not available on this system'
            }), 400
        
        data = request.get_json(silent=True) or {}
        feature = data.get('feature', '')
        
        if feature not in ['traffic_analysis', 'advanced_vuln']:
            return jsonify({
                'success': False,
                'error': 'Invalid feature specified'
            }), 400
        
        success, message = caps.install_missing_tools(feature)
        return jsonify({
            'success': success,
            'message': message,
            'missing_tools': caps.get_missing_tools(feature)
        })
        
    except ImportError:
        return jsonify({'success': False, 'error': 'Server capabilities module not available'}), 503
    except Exception as e:
        logger.error(f"Error installing tools: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# TRAFFIC ANALYSIS API ENDPOINTS
# ============================================================================

# Global traffic analyzer instance
_traffic_analyzer_instance = None

def get_traffic_analyzer():
    """Get or create traffic analyzer instance"""
    global _traffic_analyzer_instance
    if _traffic_analyzer_instance is None:
        try:
            from traffic_analyzer import TrafficAnalyzer
            _traffic_analyzer_instance = TrafficAnalyzer(shared_data)
            shared_data._traffic_analyzer = _traffic_analyzer_instance
        except ImportError:
            return None
    return _traffic_analyzer_instance


@app.route('/api/traffic/status')
def get_traffic_status():
    """Get traffic analyzer status and summary"""
    try:
        analyzer = get_traffic_analyzer()
        if not analyzer:
            return jsonify({
                'success': False,
                'available': False,
                'error': 'Traffic analysis module not available'
            })
        
        return jsonify({
            'success': True,
            'available': analyzer.is_available(),
            'summary': analyzer.get_summary()
        })
    except Exception as e:
        logger.error(f"Error getting traffic status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/traffic/debug')
def get_traffic_debug():
    """Debug endpoint for traffic analyzer"""
    import shutil
    import subprocess
    
    debug_info = {
        'tcpdump_path': shutil.which('tcpdump'),
        'tcpdump_available': shutil.which('tcpdump') is not None,
    }
    
    # Check if tcpdump can run with sudo
    try:
        result = subprocess.run(
            ['sudo', '-n', 'tcpdump', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        debug_info['tcpdump_sudo_works'] = result.returncode == 0
        debug_info['tcpdump_version'] = result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except Exception as e:
        debug_info['tcpdump_sudo_works'] = False
        debug_info['tcpdump_sudo_error'] = str(e)
    
    # Check analyzer state
    try:
        analyzer = get_traffic_analyzer()
        if analyzer:
            debug_info['analyzer_exists'] = True
            debug_info['analyzer_running'] = analyzer._running
            debug_info['analyzer_interface'] = analyzer.interface
            debug_info['packet_queue_size'] = analyzer._packet_queue.qsize()
            debug_info['total_packets_raw'] = getattr(analyzer, '_raw_packet_count', 0)
            debug_info['total_packets_parsed'] = analyzer.total_packets
            debug_info['total_bytes'] = analyzer.total_bytes
            debug_info['host_count'] = len(analyzer.host_stats)
            debug_info['connection_count'] = len(analyzer.connections)
            debug_info['capture_process_alive'] = analyzer._capture_process is not None and analyzer._capture_process.poll() is None
            if analyzer._capture_process:
                debug_info['capture_process_pid'] = analyzer._capture_process.pid
                debug_info['capture_process_returncode'] = analyzer._capture_process.poll()
        else:
            debug_info['analyzer_exists'] = False
    except Exception as e:
        debug_info['analyzer_error'] = str(e)
    
    # List network interfaces
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and '@' not in line:
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        interfaces.append(parts[1].split('@')[0])
            debug_info['interfaces'] = interfaces
    except Exception as e:
        debug_info['interfaces_error'] = str(e)
    
    return jsonify(debug_info)


@app.route('/api/traffic/start', methods=['POST'])
def start_traffic_capture():
    """Start traffic capture"""
    try:
        analyzer = get_traffic_analyzer()
        if not analyzer:
            return jsonify({'success': False, 'error': 'Traffic analysis not available'}), 503
        
        if not analyzer.is_available():
            return jsonify({
                'success': False,
                'error': 'Traffic analysis not available - check system requirements'
            }), 400
        
        data = request.get_json(silent=True) or {}
        interface = data.get('interface')
        
        if interface:
            analyzer.interface = interface
        
        success = analyzer.start()
        return jsonify({
            'success': success,
            'message': 'Traffic capture started' if success else 'Failed to start capture',
            'interface': analyzer.interface
        })
        
    except Exception as e:
        logger.error(f"Error starting traffic capture: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/traffic/stop', methods=['POST'])
def stop_traffic_capture():
    """Stop traffic capture"""
    try:
        analyzer = get_traffic_analyzer()
        if analyzer:
            analyzer.stop()
        return jsonify({'success': True, 'message': 'Traffic capture stopped'})
    except Exception as e:
        logger.error(f"Error stopping traffic capture: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/traffic/summary')
def get_traffic_summary():
    """Get traffic analysis summary"""
    try:
        analyzer = get_traffic_analyzer()
        if not analyzer:
            return jsonify({'success': False, 'error': 'Traffic analysis not available'}), 503
        
        return jsonify({
            'success': True,
            'summary': analyzer.get_summary(),
            'protocols': analyzer.get_protocol_distribution()
        })
    except Exception as e:
        logger.error(f"Error getting traffic summary: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/traffic/hosts')
def get_traffic_hosts():
    """Get top hosts by traffic"""
    try:
        analyzer = get_traffic_analyzer()
        if not analyzer:
            return jsonify({'success': False, 'error': 'Traffic analysis not available'}), 503
        
        limit = request.args.get('limit', 20, type=int)
        sort_by = request.args.get('sort', 'bytes')
        
        return jsonify({
            'success': True,
            'hosts': analyzer.get_top_hosts(limit=limit, sort_by=sort_by)
        })
    except Exception as e:
        logger.error(f"Error getting traffic hosts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/traffic/connections')
def get_traffic_connections():
    """Get active connections"""
    try:
        analyzer = get_traffic_analyzer()
        if not analyzer:
            return jsonify({'success': False, 'error': 'Traffic analysis not available'}), 503
        
        limit = request.args.get('limit', 50, type=int)
        
        return jsonify({
            'success': True,
            'connections': analyzer.get_active_connections(limit=limit)
        })
    except Exception as e:
        logger.error(f"Error getting connections: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/traffic/alerts')
def get_traffic_alerts():
    """Get traffic alerts"""
    try:
        analyzer = get_traffic_analyzer()
        if not analyzer:
            return jsonify({'success': False, 'error': 'Traffic analysis not available'}), 503
        
        limit = request.args.get('limit', 100, type=int)
        level = request.args.get('level')
        
        return jsonify({
            'success': True,
            'alerts': analyzer.get_alerts(limit=limit, level=level)
        })
    except Exception as e:
        logger.error(f"Error getting traffic alerts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/traffic/host/<ip>')
def get_traffic_host_details(ip):
    """Get detailed traffic stats for a specific host"""
    try:
        analyzer = get_traffic_analyzer()
        if not analyzer:
            return jsonify({'success': False, 'error': 'Traffic analysis not available'}), 503
        
        details = analyzer.get_host_details(ip)
        if details:
            return jsonify({'success': True, 'host': details})
        else:
            return jsonify({'success': False, 'error': 'Host not found'}), 404
    except Exception as e:
        logger.error(f"Error getting host details: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# ADVANCED VULNERABILITY SCANNING API ENDPOINTS
# ============================================================================

# Global advanced vuln scanner instance (thread-safe singleton)
_advanced_vuln_scanner_instance = None
_advanced_vuln_scanner_lock = threading.Lock()

def get_advanced_vuln_scanner():
    """Get or create advanced vuln scanner instance (thread-safe)"""
    global _advanced_vuln_scanner_instance
    if _advanced_vuln_scanner_instance is not None:
        return _advanced_vuln_scanner_instance
    with _advanced_vuln_scanner_lock:
        # Double-check after acquiring lock
        if _advanced_vuln_scanner_instance is not None:
            return _advanced_vuln_scanner_instance
        try:
            from advanced_vuln_scanner import AdvancedVulnScanner
            _advanced_vuln_scanner_instance = AdvancedVulnScanner(shared_data)
            shared_data._advanced_vuln_scanner = _advanced_vuln_scanner_instance
        except ImportError:
            return None
    return _advanced_vuln_scanner_instance


@app.route('/api/vuln-advanced/status')
def get_advanced_vuln_status():
    """Get advanced vulnerability scanner status"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'available': False,
                'error': 'Advanced vulnerability scanner not available'
            })

        return jsonify({
            'success': True,
            'available': scanner.is_available(),
            'scanners': scanner.get_available_scanners(),
            'summary': scanner.get_summary(),
            'active_scans': scanner.get_active_scans_list()
        })
    except Exception as e:
        logger.error(f"Error getting advanced vuln status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/debug')
def get_advanced_vuln_debug():
    """Debug endpoint for vulnerability scanner"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'error': 'Scanner not available'})
        
        # ZAP diagnostic info
        zap_info = {
            'zap_base_url': scanner._zap_base_url,
            'zap_port': scanner._zap_port,
            'zap_api_key_set': bool(scanner._zap_api_key),
            'zap_running': scanner._is_zap_running(),
        }
        # Try to get ZAP version
        try:
            version_resp = scanner._zap_api_call('JSON/core/view/version')
            zap_info['zap_version'] = version_resp.get('version', 'unknown')
            zap_info['zap_api_key_valid'] = True
        except Exception as e:
            zap_info['zap_api_key_valid'] = False
            zap_info['zap_api_error'] = str(e)

        debug_info = {
            'tool_paths': scanner._tool_paths,
            'total_scans': len(scanner.scan_history),
            'active_scans': len(scanner.active_scans),
            'scan_results_keys': list(scanner.scan_results.keys()),
            'scan_results_counts': {k: len(v) for k, v in scanner.scan_results.items()},
            'zap': zap_info,
            'scan_history': [
                {
                    'scan_id': s.scan_id,
                    'scan_type': s.scan_type.value,
                    'target': s.target,
                    'status': s.status,
                    'current_check': s.current_check,
                    'error_message': s.error_message,
                    'findings_count': s.findings_count
                }
                for s in list(scanner.scan_history)[-10:]  # Last 10 scans
            ]
        }
        
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vuln-advanced/scan', methods=['POST'])
def start_advanced_vuln_scan():
    """Start an advanced vulnerability scan"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Advanced vuln scanner not available'}), 503

        if not scanner.is_available():
            return jsonify({
                'success': False,
                'error': 'Advanced vulnerability scanning not available - check system requirements'
            }), 400

        data = request.get_json(silent=True) or {}
        target = data.get('target')
        scan_type = data.get('scan_type', 'nuclei')
        options = data.get('options', {})

        # Pass scan strength to options (default: standard)
        scan_strength = data.get('scan_strength') or options.get('scan_strength', 'standard')
        if scan_strength not in ('standard', 'thorough', 'insane'):
            scan_strength = 'standard'
        options['scan_strength'] = scan_strength

        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400

        # Extract auth from options.auth_params if provided (inline auth for this scan)
        auth_type = options.get('auth_type')
        auth_params = options.get('auth_params', {})
        
        if auth_type and auth_params:
            # Map auth_params to options format expected by scanner
            if auth_type == 'http_basic' and auth_params.get('http_basic_auth'):
                options['http_basic_auth'] = auth_params['http_basic_auth']
            elif auth_type == 'bearer_token' and auth_params.get('bearer_token'):
                options['bearer_token'] = auth_params['bearer_token']
            elif auth_type == 'api_key' and auth_params.get('api_key'):
                options['api_key'] = auth_params['api_key']
                options['api_key_header'] = auth_params.get('api_key_header', 'X-API-Key')
            elif auth_type == 'cookie' and auth_params.get('cookie_value'):
                options['cookie_value'] = auth_params['cookie_value']
            elif auth_type == 'oauth2_client_creds' and auth_params.get('client_id'):
                options['oauth2_client_creds'] = auth_params
            elif auth_type == 'form' and auth_params.get('username'):
                options['form_auth'] = auth_params
            elif auth_type == 'oauth2_bba' and auth_params.get('username'):
                options['oauth2_bba'] = auth_params
            elif auth_type == 'script_auth' and auth_params.get('username'):
                options['script_auth'] = auth_params
            
            logger.info(f"Using inline {auth_type} auth for scan target: {target}")

        # Log API scan mode if used
        if options.get('scan_mode') == 'api':
            logger.info(f"API scan mode: method={options.get('http_method', 'GET')}, "
                       f"has_headers={bool(options.get('custom_headers'))}, "
                       f"has_body={bool(options.get('request_body'))}, "
                       f"openapi_url={options.get('openapi_url', 'none')}")

        # Map string to enum
        from advanced_vuln_scanner import ScanType
        try:
            scan_type_enum = ScanType(scan_type)
        except ValueError:
            return jsonify({'success': False, 'error': f'Invalid scan type: {scan_type}'}), 400

        scan_id = scanner.start_scan(target, scan_type_enum, options)

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': f'Started {scan_type} scan against {target}'
        })

    except Exception as e:
        logger.error(f"Error starting advanced vuln scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/scan/<scan_id>')
def get_advanced_vuln_scan_status(scan_id):
    """Get status of a specific scan"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503
        
        status = scanner.get_scan_status(scan_id)
        if status:
            return jsonify({
                'success': True,
                'scan': status,
                'results': scanner.get_scan_results(scan_id)
            })
        else:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/scan/<scan_id>/cancel', methods=['POST'])
def cancel_advanced_vuln_scan(scan_id):
    """Cancel a running scan"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503

        success = scanner.cancel_scan(scan_id)
        return jsonify({
            'success': success,
            'message': 'Scan cancelled' if success else 'Could not cancel scan'
        })
    except Exception as e:
        logger.error(f"Error cancelling scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/scan/<scan_id>/logs')
def get_advanced_vuln_scan_logs(scan_id):
    """Get live log entries for a specific scan"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503

        since_index = request.args.get('since', 0, type=int)
        logs = scanner.get_scan_logs(scan_id, since_index)

        return jsonify({
            'success': True,
            'logs': logs,
            'total': since_index + len(logs)
        })
    except Exception as e:
        logger.error(f"Error getting scan logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/scan/<scan_id>', methods=['DELETE'])
def delete_advanced_vuln_scan(scan_id):
    """Delete a scan and its findings"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503

        success = scanner.delete_scan(scan_id)
        return jsonify({
            'success': success,
            'message': 'Scan deleted' if success else 'Could not delete scan'
        })
    except Exception as e:
        logger.error(f"Error deleting scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/scans', methods=['DELETE'])
def delete_all_advanced_vuln_scans():
    """Delete all scans and findings"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503

        count = scanner.delete_all_scans()
        return jsonify({
            'success': True,
            'message': f'Deleted {count} scans'
        })
    except Exception as e:
        logger.error(f"Error deleting all scans: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/scan/<scan_id>/report')
def download_scan_report(scan_id):
    """Download report for a specific scan"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503

        report_format = request.args.get('format', 'html')

        # Get scan info and findings
        scan_info = scanner.get_scan_status(scan_id)
        if not scan_info:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404

        findings = scanner.get_scan_results(scan_id)

        # Generate HTML report
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        severity_colors = {
            'critical': '#ef4444',
            'high': '#f97316',
            'medium': '#facc15',
            'low': '#3b82f6',
            'info': '#9ca3af'
        }

        findings_html = ''
        severity_badge_bg = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#ca8a04',
            'low': '#2563eb',
            'info': '#4b5563'
        }
        for f in findings:
            sev = f.get('severity', 'info')
            color = severity_colors.get(sev, '#6b7280')
            badge_bg = severity_badge_bg.get(sev, '#4b5563')
            badge_text = '#000000' if sev == 'medium' else '#ffffff'
            findings_html += f'''
            <div style="border-left: 4px solid {color}; padding: 15px; margin: 10px 0; background: #1e293b; border-radius: 4px; border: 1px solid #334155; border-left: 4px solid {color};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="background: {badge_bg}; color: {badge_text}; padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase;">{sev}</span>
                    <span style="color: #cbd5e1; font-size: 12px;">{f.get('scanner', 'unknown')}</span>
                </div>
                <h3 style="color: #ffffff; margin: 10px 0 5px 0; font-size: 16px;">{f.get('title', 'Unknown')}</h3>
                <p style="color: #e2e8f0; font-size: 14px;">Host: <span style="color: #ffffff; font-family: monospace;">{f.get('host', 'N/A')}{':' + str(f.get('port')) if f.get('port') else ''}</span></p>
                <p style="color: #e2e8f0; font-size: 14px; margin-top: 10px; line-height: 1.6;">{f.get('description', '')}</p>
                {f'<div style="margin-top: 10px;"><strong style="color: #22d3ee;">Evidence:</strong><pre style="background: #0f172a; padding: 10px; border-radius: 4px; overflow-x: auto; color: #4ade80; font-size: 12px; border: 1px solid #1e293b;">{f.get("evidence", "")}</pre></div>' if f.get('evidence') else ''}
                {f'<p style="color: #fde68a; margin-top: 10px; line-height: 1.6;"><strong>Remediation:</strong> {f.get("remediation", "")}</p>' if f.get('remediation') else ''}
            </div>
            '''

        if not findings_html:
            findings_html = '<p style="color: #94a3b8; text-align: center; padding: 40px;">No findings for this scan.</p>'

        # Count severities
        sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        html_report = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Ragnar Security Scan Report - {scan_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f1f5f9; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1e293b 0%, #334155 100%); padding: 30px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }}
        .header h1 {{ margin: 0; color: #22d3ee; font-size: 28px; }}
        .header p {{ color: #cbd5e1; margin: 8px 0 0 0; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 20px; }}
        .summary-card {{ background: #1e293b; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
        .summary-card .count {{ font-size: 32px; font-weight: bold; }}
        .summary-card .label {{ color: #cbd5e1; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}
        .critical .count {{ color: #f87171; }}
        .high .count {{ color: #fb923c; }}
        .medium .count {{ color: #facc15; }}
        .low .count {{ color: #60a5fa; }}
        .info .count {{ color: #9ca3af; }}
        .scan-info {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }}
        .scan-info h2 {{ color: #22d3ee; margin-top: 0; font-size: 20px; }}
        .scan-info table {{ width: 100%; border-collapse: collapse; }}
        .scan-info td {{ padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 14px; }}
        .scan-info td:first-child {{ color: #cbd5e1; width: 160px; font-weight: 500; }}
        .scan-info td:last-child {{ color: #ffffff; word-break: break-all; }}
        .findings {{ background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }}
        .findings h2 {{ color: #22d3ee; margin-top: 0; font-size: 20px; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Ragnar Security Scan Report</h1>
            <p>Generated: {timestamp}</p>
        </div>

        <div class="summary">
            <div class="summary-card critical"><div class="count">{sev_counts['critical']}</div><div class="label">Critical</div></div>
            <div class="summary-card high"><div class="count">{sev_counts['high']}</div><div class="label">High</div></div>
            <div class="summary-card medium"><div class="count">{sev_counts['medium']}</div><div class="label">Medium</div></div>
            <div class="summary-card low"><div class="count">{sev_counts['low']}</div><div class="label">Low</div></div>
            <div class="summary-card info"><div class="count">{sev_counts['info']}</div><div class="label">Info</div></div>
        </div>

        <div class="scan-info">
            <h2>Scan Information</h2>
            <table>
                <tr><td>Scan ID</td><td>{scan_id}</td></tr>
                <tr><td>Target</td><td>{scan_info.get('target', 'N/A')}</td></tr>
                <tr><td>Scan Type</td><td>{scan_info.get('scan_type', 'N/A')}</td></tr>
                <tr><td>Status</td><td>{scan_info.get('status', 'N/A')}</td></tr>
                <tr><td>Started</td><td>{scan_info.get('started_at', 'N/A')}</td></tr>
                <tr><td>Completed</td><td>{scan_info.get('completed_at', 'N/A')}</td></tr>
                <tr><td>Total Findings</td><td>{len(findings)}</td></tr>
            </table>
        </div>

        <div class="findings">
            <h2>Findings ({len(findings)})</h2>
            {findings_html}
        </div>
    </div>
</body>
</html>'''

        filename = f'ragnar_scan_report_{scan_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        response = Response(html_report, content_type='text/html')
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error(f"Error generating scan report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/report')
def download_zap_report():
    """Download ZAP scan report"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503

        report_format = request.args.get('format', 'html')
        if report_format not in ('html', 'xml', 'json', 'md'):
            return jsonify({'success': False, 'error': 'Invalid format. Use: html, xml, json, md'}), 400

        report_data = scanner.generate_zap_report(report_format)
        if not report_data:
            return jsonify({'success': False, 'error': 'Failed to generate report. Is ZAP running?'}), 500

        # Set content type based on format
        content_types = {
            'html': 'text/html',
            'xml': 'application/xml',
            'json': 'application/json',
            'md': 'text/markdown'
        }

        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'ragnar_zap_report_{timestamp}.{report_format}'

        response = Response(report_data, content_type=content_types.get(report_format, 'text/plain'))
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error(f"Error generating ZAP report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/findings')
def get_advanced_vuln_findings():
    """Get all vulnerability findings"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503
        
        limit = request.args.get('limit', 100, type=int)
        severity = request.args.get('severity')
        
        return jsonify({
            'success': True,
            'findings': scanner.get_all_findings(severity=severity, limit=limit),
            'summary': scanner.get_summary()
        })
    except Exception as e:
        logger.error(f"Error getting findings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vuln-advanced/summary')
def get_advanced_vuln_summary():
    """Get vulnerability summary"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Scanner not available',
                'summary': {
                    'total_findings': 0,
                    'severity_counts': {},
                    'available_scanners': {}
                }
            })
        
        return jsonify({
            'success': True,
            'summary': scanner.get_summary()
        })
    except Exception as e:
        logger.error(f"Error getting vuln summary: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# OWASP ZAP API ENDPOINTS
# ============================================================================

@app.route('/api/zap/status')
def get_zap_status():
    """Get OWASP ZAP daemon status"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available'
            }), 503

        return jsonify({
            'success': True,
            'status': scanner.get_zap_status()
        })
    except Exception as e:
        logger.error(f"Error getting ZAP status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/logs')
def get_zap_logs():
    """Get ZAP-related log entries from the advanced_vuln_scanner log file.
    
    Filters for [ZAP-START], [ZAP-CLEANUP] and other ZAP-related lines 
    to help diagnose startup/crash issues.
    
    Query params:
        lines: max lines to return (default 200)
        filter: additional keyword filter (optional)
    """
    try:
        max_lines = min(int(request.args.get('lines', 200)), 2000)
        extra_filter = request.args.get('filter', '').strip()
        
        log_path = os.path.join(shared_data.logsdir, 'advanced_vuln_scanner.log')
        if not os.path.exists(log_path):
            return jsonify({
                'success': True,
                'logs': [],
                'message': 'No advanced_vuln_scanner.log file found'
            })
        
        # ZAP-related keywords to match
        zap_keywords = [
            '[ZAP-START]', '[ZAP-CLEANUP]', 'ZAP', 'zap_full', 'zap_spider',
            'zap_active', 'start_zap', 'stop_zap', '_zap_', 'zap daemon',
            'port 8090'
        ]
        
        matched_lines = []
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                line_lower = line.lower()
                if any(kw.lower() in line_lower for kw in zap_keywords):
                    if extra_filter and extra_filter.lower() not in line_lower:
                        continue
                    matched_lines.append(line)
        
        # Return the most recent entries
        recent = matched_lines[-max_lines:]
        
        return jsonify({
            'success': True,
            'logs': recent,
            'total_matched': len(matched_lines),
            'returned': len(recent),
            'log_file': log_path
        })
    except Exception as e:
        logger.error(f"Error reading ZAP logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/alerts')
def get_zap_alerts():
    """Get raw ZAP alerts for debugging"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({'success': False, 'error': 'Scanner not available'}), 503

        if not scanner._is_zap_running():
            return jsonify({'success': False, 'error': 'ZAP not running'}), 503

        baseurl = request.args.get('baseurl', '')
        limit = request.args.get('limit', '100')

        params = {'start': '0', 'count': limit}
        if baseurl:
            params['baseurl'] = baseurl

        alerts_resp = scanner._zap_api_call('JSON/core/view/alerts', params)
        alerts = alerts_resp.get('alerts', [])

        return jsonify({
            'success': True,
            'count': len(alerts),
            'alerts': alerts
        })
    except Exception as e:
        logger.error(f"Error getting ZAP alerts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/start', methods=['POST'])
def start_zap_daemon():
    """Start OWASP ZAP daemon"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available'
            }), 503

        data = request.get_json(silent=True) or {}
        port = data.get('port')

        success = scanner.start_zap_daemon(port)
        return jsonify({
            'success': success,
            'message': 'ZAP daemon started' if success else 'Failed to start ZAP daemon',
            'status': scanner.get_zap_status()
        })
    except Exception as e:
        logger.error(f"Error starting ZAP: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/stop', methods=['POST'])
def stop_zap_daemon():
    """Stop OWASP ZAP daemon"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available'
            }), 503

        success = scanner.stop_zap_daemon()
        return jsonify({
            'success': success,
            'message': 'ZAP daemon stopped' if success else 'Failed to stop ZAP daemon'
        })
    except Exception as e:
        logger.error(f"Error stopping ZAP: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/scan', methods=['POST'])
def start_zap_scan():
    """Start a ZAP vulnerability scan"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available'
            }), 503

        data = request.get_json(silent=True) or {}
        target = data.get('target')
        if not target:
            return jsonify({'success': False, 'error': 'Target URL required'}), 400

        # Validate target is a URL
        if not target.startswith('http://') and not target.startswith('https://'):
            target = f"http://{target}"

        # Check if saved credentials exist for this target
        auth_applied = False
        auth_info = None
        skip_auth = data.get('skip_auth', False)  # Allow explicit skip

        if not skip_auth:
            try:
                from db_manager import get_db
                db = get_db()
                saved_creds = db.get_zap_credentials_for_url(target)

                if saved_creds and saved_creds.get('auth_type') != 'none':
                    # Apply saved credentials to ZAP
                    logger.info(f"Found saved credentials for {target}, applying to ZAP...")
                    cred_auth_type = saved_creds.get('auth_type')

                    auth_params = {
                        'login_url': saved_creds.get('login_url') or target,
                        'username': saved_creds.get('username'),
                        'password': saved_creds.get('password'),
                        'login_request_data': saved_creds.get('login_request_data'),
                        'username_field': saved_creds.get('username_field', 'username'),
                        'password_field': saved_creds.get('password_field', 'password'),
                    }

                    if cred_auth_type == 'http_basic':
                        auth_params['hostname'] = saved_creds.get('target_host')
                        auth_params['realm'] = saved_creds.get('http_realm')
                    elif cred_auth_type == 'bearer_token':
                        auth_params['bearer_token'] = saved_creds.get('bearer_token', '')
                    elif cred_auth_type == 'api_key':
                        auth_params['api_key'] = saved_creds.get('api_key', '')
                        auth_params['api_key_header'] = saved_creds.get('api_key_header', 'X-API-Key')
                    elif cred_auth_type == 'cookie':
                        auth_params['cookie_value'] = saved_creds.get('cookie_value', '')

                    success, error = scanner.zap_set_authentication(
                        'default',
                        saved_creds.get('auth_type'),
                        auth_params
                    )

                    if success:
                        auth_applied = True
                        auth_info = {
                            'type': saved_creds.get('auth_type'),
                            'username': saved_creds.get('username'),
                            'message': f"Using saved {saved_creds.get('auth_type')} auth for {saved_creds.get('target_host')}"
                        }
                        logger.info(f"Applied saved auth: {auth_info['message']}")
                    else:
                        logger.warning(f"Failed to apply saved auth: {error}")
            except Exception as auth_err:
                logger.warning(f"Error checking/applying saved credentials: {auth_err}")

        # Determine scan type
        from advanced_vuln_scanner import ScanType
        scan_type_str = data.get('scan_type', 'zap_full')
        scan_type_map = {
            'spider': ScanType.ZAP_SPIDER,
            'zap_spider': ScanType.ZAP_SPIDER,
            'active': ScanType.ZAP_ACTIVE,
            'zap_active': ScanType.ZAP_ACTIVE,
            'full': ScanType.ZAP_FULL,
            'zap_full': ScanType.ZAP_FULL,
        }

        scan_type = scan_type_map.get(scan_type_str, ScanType.ZAP_FULL)

        options = {
            'ajax_spider': data.get('ajax_spider', True),
            'max_children': data.get('max_children', 10),
            'scan_policy': data.get('scan_policy', 'Default Policy'),
            'recurse': data.get('recurse', True),
            'in_scope_only': data.get('in_scope_only', True),
        }

        scan_id = scanner.start_scan(target, scan_type, options)

        response = {
            'success': True,
            'scan_id': scan_id,
            'message': f'ZAP {scan_type.value} scan started',
            'target': target,
            'auth_applied': auth_applied
        }

        if auth_info:
            response['auth_info'] = auth_info

        return jsonify(response)

    except Exception as e:
        logger.error(f"Error starting ZAP scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/clear-session', methods=['POST'])
def zap_clear_session():
    """Clear ZAP session data"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available'
            }), 503

        success = scanner.zap_clear_session()
        return jsonify({
            'success': success,
            'message': 'ZAP session cleared' if success else 'Failed to clear session'
        })
    except Exception as e:
        logger.error(f"Error clearing ZAP session: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/import-openapi', methods=['POST'])
def zap_import_openapi():
    """Import OpenAPI/Swagger specification for API scanning"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available'
            }), 503

        data = request.get_json(silent=True) or {}
        spec_url = data.get('spec_url')
        target_url = data.get('target_url')

        if not spec_url:
            return jsonify({'success': False, 'error': 'spec_url required'}), 400

        success = scanner.zap_import_openapi(spec_url, target_url)
        return jsonify({
            'success': success,
            'message': 'OpenAPI spec imported' if success else 'Failed to import spec'
        })
    except Exception as e:
        logger.error(f"Error importing OpenAPI spec: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/set-auth', methods=['POST'])
def zap_set_authentication():
    """Configure authentication for ZAP scanning"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available'
            }), 503

        data = request.get_json(silent=True) or {}
        context_name = data.get('context_name', 'default')
        auth_type = data.get('auth_type')
        auth_params = data.get('auth_params', {})

        if not auth_type:
            return jsonify({'success': False, 'error': 'auth_type required (form, http_basic, oauth2_bba, script_auth, bearer_token, api_key, cookie)'}), 400

        success, error_message = scanner.zap_set_authentication(context_name, auth_type, auth_params)

        if success:
            return jsonify({
                'success': True,
                'message': f'{auth_type} authentication configured successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': error_message or 'Failed to configure authentication'
            }), 400

    except Exception as e:
        logger.error(f"Error setting ZAP auth: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/auth-status')
def zap_get_auth_status():
    """Get current ZAP authentication configuration status"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available',
                'has_auth': False
            }), 503

        auth_status = scanner.zap_get_auth_status()
        auth_status['success'] = True
        return jsonify(auth_status)

    except Exception as e:
        logger.error(f"Error getting ZAP auth status: {e}")
        return jsonify({'success': False, 'error': str(e), 'has_auth': False}), 500


@app.route('/api/zap/clear-auth', methods=['POST'])
def zap_clear_auth():
    """Clear all ZAP authentication configurations"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Advanced scanner not available'
            }), 503

        success, message = scanner.zap_clear_auth()

        if success:
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400

    except Exception as e:
        logger.error(f"Error clearing ZAP auth: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/diagnose')
def zap_diagnose():
    """Diagnose ZAP connectivity and configuration issues"""
    try:
        scanner = get_advanced_vuln_scanner()
        diagnosis = {
            'scanner_available': scanner is not None,
            'zap_running': False,
            'zap_reachable': False,
            'contexts': [],
            'auth_status': None,
            'recent_errors': [],
            'recommendations': []
        }

        if not scanner:
            diagnosis['recommendations'].append("Advanced scanner not available - restart server")
            return jsonify(diagnosis)

        # Check if ZAP is running
        diagnosis['zap_running'] = scanner._is_zap_running()

        if not diagnosis['zap_running']:
            diagnosis['recommendations'].append("ZAP daemon is not running. Click 'Start ZAP' to start it.")
            return jsonify(diagnosis)

        # Try to reach ZAP API
        try:
            status = scanner.get_zap_status()
            diagnosis['zap_reachable'] = True
            diagnosis['zap_status'] = status
        except Exception as e:
            diagnosis['zap_reachable'] = False
            diagnosis['recent_errors'].append(f"Cannot reach ZAP API: {str(e)}")
            diagnosis['recommendations'].append("ZAP process may be running but API is not responding. Try restarting ZAP.")
            return jsonify(diagnosis)

        # Check auth status
        try:
            auth_status = scanner.zap_get_auth_status()
            diagnosis['auth_status'] = auth_status

            if auth_status.get('has_auth'):
                diagnosis['recommendations'].append(
                    f"Authentication is configured ({auth_status.get('auth_type')}). "
                    "If scanning unauthenticated targets, click 'Clear Auth' first."
                )
        except Exception as e:
            diagnosis['recent_errors'].append(f"Error checking auth: {str(e)}")

        # Check contexts
        try:
            contexts_resp = scanner._zap_api_call('JSON/context/view/contextList', {})
            context_list = contexts_resp.get('contextList', [])
            if isinstance(context_list, str):
                context_list = [c.strip() for c in context_list.split(',') if c.strip()]
            diagnosis['contexts'] = context_list

            if len(context_list) > 5:
                diagnosis['recommendations'].append(
                    f"Many contexts configured ({len(context_list)}). Consider clearing ZAP session."
                )
        except Exception as e:
            diagnosis['recent_errors'].append(f"Error listing contexts: {str(e)}")

        # General recommendations
        if not diagnosis['recent_errors'] and not diagnosis['recommendations']:
            diagnosis['recommendations'].append("ZAP appears to be configured correctly. If scans still fail, check target accessibility.")

        return jsonify(diagnosis)

    except Exception as e:
        logger.error(f"Error in ZAP diagnosis: {e}")
        return jsonify({
            'error': str(e),
            'recommendations': ['An error occurred during diagnosis. Check server logs.']
        }), 500


@app.route('/api/zap/diagnose-target', methods=['POST'])
def zap_diagnose_target():
    """Diagnose a target URL before scanning - check accessibility, DNS, connectivity"""
    try:
        scanner = get_advanced_vuln_scanner()
        if not scanner:
            return jsonify({
                'valid': False,
                'errors': ['Advanced scanner not available'],
                'recommendations': ['Restart server or check server capabilities']
            }), 503

        data = request.get_json(silent=True) or {}
        target = data.get('target', '')

        if not target:
            return jsonify({
                'valid': False,
                'errors': ['No target URL provided'],
                'recommendations': ['Provide a target URL to diagnose']
            }), 400

        # Ensure URL has scheme
        if not target.startswith('http://') and not target.startswith('https://'):
            target = f"http://{target}"

        result = scanner.zap_diagnose_target(target)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error diagnosing target: {e}")
        return jsonify({
            'valid': False,
            'errors': [str(e)],
            'recommendations': ['An error occurred. Check server logs.']
        }), 500


# ============================================================================
# ZAP TARGET CREDENTIALS API ENDPOINTS
# ============================================================================

@app.route('/api/zap/credentials', methods=['GET'])
def list_zap_credentials():
    """List all saved ZAP target credentials (without passwords)"""
    try:
        from db_manager import get_db
        db = get_db()
        credentials = db.list_zap_credentials()
        return jsonify({
            'success': True,
            'credentials': credentials,
            'count': len(credentials)
        })
    except Exception as e:
        logger.error(f"Error listing ZAP credentials: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/credentials', methods=['POST'])
def save_zap_credentials():
    """Save ZAP authentication credentials for a target"""
    try:
        from db_manager import get_db
        db = get_db()

        data = request.get_json(silent=True) or {}
        target_host = data.get('target_host') or data.get('target')

        if not target_host:
            return jsonify({'success': False, 'error': 'target_host required'}), 400

        auth_type = data.get('auth_type', 'form')
        valid_auth_types = ('form', 'http_basic', 'bearer_token', 'api_key', 'cookie', 'none')
        if auth_type not in valid_auth_types:
            return jsonify({'success': False, 'error': f'auth_type must be one of: {", ".join(valid_auth_types)}'}), 400

        success = db.save_zap_credentials(
            target_host=target_host,
            auth_type=auth_type,
            login_url=data.get('login_url'),
            username=data.get('username'),
            password=data.get('password'),
            login_request_data=data.get('login_request_data'),
            username_field=data.get('username_field', 'username'),
            password_field=data.get('password_field', 'password'),
            http_realm=data.get('http_realm'),
            notes=data.get('notes'),
            bearer_token=data.get('bearer_token'),
            api_key=data.get('api_key'),
            api_key_header=data.get('api_key_header', 'X-API-Key'),
            cookie_value=data.get('cookie_value')
        )

        if success:
            return jsonify({
                'success': True,
                'message': f'Credentials saved for {target_host}'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to save credentials'
            }), 500

    except Exception as e:
        logger.error(f"Error saving ZAP credentials: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/credentials/check', methods=['GET', 'POST'])
def check_zap_credentials():
    """Check if credentials exist for a target (used by scan form)"""
    try:
        from db_manager import get_db
        db = get_db()

        # Support both GET with query param and POST with JSON
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            target = data.get('target') or data.get('target_host')
        else:
            target = request.args.get('target') or request.args.get('target_host')

        if not target:
            return jsonify({'exists': False, 'error': 'target required'}), 400

        result = db.check_zap_credentials_exist(target)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error checking ZAP credentials: {e}")
        return jsonify({'exists': False, 'error': str(e)}), 500


@app.route('/api/zap/credentials/<path:target_host>', methods=['GET'])
def get_zap_credentials(target_host):
    """Get full credentials for a target (including password - use carefully)"""
    try:
        from db_manager import get_db
        db = get_db()

        credentials = db.get_zap_credentials(target_host)
        if credentials:
            return jsonify({
                'success': True,
                'credentials': credentials
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No credentials found for this target'
            }), 404

    except Exception as e:
        logger.error(f"Error getting ZAP credentials: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/zap/credentials/<path:target_host>', methods=['DELETE'])
def delete_zap_credentials(target_host):
    """Delete credentials for a target"""
    try:
        from db_manager import get_db
        db = get_db()

        success = db.delete_zap_credentials(target_host)
        if success:
            return jsonify({
                'success': True,
                'message': f'Credentials deleted for {target_host}'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to delete credentials'
            }), 500

    except Exception as e:
        logger.error(f"Error deleting ZAP credentials: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# DASHBOARD API ENDPOINTS
# ============================================================================

def _count_scanned_networks() -> int:
    """Return the number of distinct Wi-Fi networks Ragnar has stored (excluding default)."""
    try:
        return shared_data._calculate_scanned_networks_count()
    except Exception as exc:
        logger.error(f"SCANNED_NETWORKS: Failed to calculate via shared_data: {exc}")
        return 0

@app.route('/api/debug/scanned-networks')
def debug_scanned_networks():
    """DEBUG: Test endpoint to check scanned networks counting"""
    try:
        manager = getattr(shared_data, 'storage_manager', None)
        networks_dir = getattr(manager, 'networks_dir', None) if manager else None
        default_slug = 'default'

        if manager is not None:
            default_ssid = getattr(manager, 'default_ssid', None)
            slugify = getattr(manager, '_slugify', None)
            if callable(slugify) and default_ssid is not None:
                try:
                    default_slug = slugify(default_ssid)
                except Exception:
                    default_slug = 'default'

        if not networks_dir:
            networks_dir = os.path.join(shared_data.datadir, 'networks')

        debug_info = {
            'networks_dir': networks_dir,
            'dir_exists': os.path.exists(networks_dir),
            'entries': [],
            'count': 0,
            'cached_count': getattr(shared_data, 'scanned_networks_count', 0),
            'default_slug': default_slug,
        }

        if os.path.exists(networks_dir):
            try:
                entries = os.listdir(networks_dir)
                debug_info['raw_entries'] = entries
                count = 0
                for entry in entries:
                    entry_info = {
                        'name': entry,
                        'is_hidden': entry.startswith('.'),
                        'is_dir': os.path.isdir(os.path.join(networks_dir, entry)),
                        'is_default': entry in ('default', default_slug),
                        'counted': False
                    }
                    if (not entry.startswith('.')
                            and os.path.isdir(os.path.join(networks_dir, entry))
                            and entry not in ('default', default_slug)):
                        count += 1
                        entry_info['counted'] = True
                    debug_info['entries'].append(entry_info)
                debug_info['count'] = count
                debug_info['recalculated_count'] = shared_data._calculate_scanned_networks_count()
            except OSError as e:
                debug_info['error'] = str(e)
        
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()})

@app.route('/api/dashboard/quick')
def get_dashboard_quick():
    """OPTIMIZED: Combined fast endpoint that returns all essential dashboard data in one call.
    This eliminates multiple round-trips and significantly speeds up dashboard loading on Pi Zero."""
    try:
        requested_identifier = _extract_requested_network_identifier()
        stats_payload = None

        if requested_identifier:
            try:
                stats_payload = _collect_dashboard_stats_for_network(requested_identifier)
            except Exception as exc:
                logger.error(f"Unable to collect dashboard stats for '{requested_identifier}': {exc}")
                stats_payload = None

        current_time = time.time()
        last_sync_ts = getattr(shared_data, 'last_sync_timestamp', last_sync_time)
        last_sync_iso = None
        last_sync_age = None

        if last_sync_ts:
            try:
                last_sync_iso = datetime.fromtimestamp(last_sync_ts).isoformat()
                last_sync_age = max(current_time - last_sync_ts, 0.0)
            except Exception:
                last_sync_iso = None

        if stats_payload:
            ts_override = stats_payload.get('last_sync_timestamp')
            if ts_override:
                last_sync_ts = ts_override
                last_sync_iso = stats_payload.get('last_sync_iso', last_sync_iso)
                last_sync_age = stats_payload.get('last_sync_age_seconds', last_sync_age)

        if stats_payload:
            active_target_count = safe_int(stats_payload.get('active_target_count', stats_payload.get('target_count', 0)))
            total_target_count = safe_int(stats_payload.get('total_target_count', active_target_count))
            inactive_target_count = safe_int(stats_payload.get('inactive_target_count', total_target_count - active_target_count))
            port_count = safe_int(stats_payload.get('port_count', shared_data.portnbr))
            vulnerability_count = safe_int(stats_payload.get('vulnerability_count', shared_data.vulnnbr))
            vulnerable_hosts_count = safe_int(stats_payload.get('vulnerable_hosts_count', stats_payload.get('vulnerable_host_count', 0)))
            credential_count = safe_int(stats_payload.get('credential_count', shared_data.crednbr))
            data_count = safe_int(stats_payload.get('data_count', shared_data.datanbr))
            scanned_network_count = safe_int(stats_payload.get('scanned_network_count', getattr(shared_data, 'scanned_networks_count', 0)))
            new_target_ips = stats_payload.get('new_target_ips', []) or []
            lost_target_ips = stats_payload.get('lost_target_ips', []) or []
            new_target_count = safe_int(stats_payload.get('new_target_count', len(new_target_ips)))
            lost_target_count = safe_int(stats_payload.get('lost_target_count', len(lost_target_ips)))
            level = safe_int(stats_payload.get('level', shared_data.levelnbr))
            points = safe_int(stats_payload.get('points', shared_data.coinnbr))
            network_ssid = stats_payload.get('network_ssid') or shared_data.active_network_ssid or 'default'
            network_slug = stats_payload.get('network_slug') or getattr(shared_data, 'active_network_slug', None)
        else:
            active_target_count = safe_int(shared_data.targetnbr)
            total_target_count = safe_int(shared_data.total_targetnbr)
            inactive_target_count = safe_int(shared_data.inactive_targetnbr)
            port_count = safe_int(shared_data.portnbr)
            vulnerability_count = safe_int(shared_data.vulnnbr)
            vulnerable_hosts_count = safe_int(getattr(shared_data, 'vulnerable_host_count', 0))
            credential_count = safe_int(shared_data.crednbr)
            data_count = safe_int(shared_data.datanbr)
            scanned_network_count = safe_int(getattr(shared_data, 'scanned_networks_count', 0))
            new_target_ips = getattr(shared_data, 'new_target_ips', [])
            lost_target_ips = getattr(shared_data, 'lost_target_ips', [])
            new_target_count = safe_int(getattr(shared_data, 'new_targets', len(new_target_ips)))
            lost_target_count = safe_int(getattr(shared_data, 'lost_targets', len(lost_target_ips)))
            level = safe_int(shared_data.levelnbr)
            points = safe_int(shared_data.coinnbr)
            network_ssid = shared_data.active_network_ssid or 'default'
            network_slug = getattr(shared_data, 'active_network_slug', None)

        if total_target_count == 0 and active_target_count > 0:
            total_target_count = active_target_count
            inactive_target_count = 0
        elif inactive_target_count == 0 and total_target_count > active_target_count:
            inactive_target_count = total_target_count - active_target_count

        wifi_status = {}
        try:
            wifi_manager = getattr(shared_data, 'ragnar_instance', None)
            if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
                wifi_status = wifi_manager.wifi_manager.get_status()
        except Exception:
            pass  # Silently fail - non-critical for dashboard

        combined_data = {
            'network_ssid': network_ssid,
            'network_slug': network_slug,
            'requested_network': requested_identifier,
            'target_count': active_target_count,
            'active_target_count': active_target_count,
            'inactive_target_count': inactive_target_count,
            'total_target_count': total_target_count,
            'new_target_count': new_target_count,
            'lost_target_count': lost_target_count,
            'new_target_ips': new_target_ips,
            'lost_target_ips': lost_target_ips,
            'port_count': port_count,
            'vulnerability_count': vulnerability_count,
            'vulnerable_hosts_count': vulnerable_hosts_count,
            'vulnerable_host_count': vulnerable_hosts_count,
            'credential_count': credential_count,
            'level': level,
            'points': points,
            'coins': points,
            'data_count': data_count,
            'scanned_network_count': scanned_network_count,
            'last_sync_timestamp': last_sync_ts,
            'last_sync_iso': last_sync_iso,
            'last_sync_age_seconds': last_sync_age,
            'ragnar_status': safe_str(shared_data.ragnarstatustext),
            'ragnar_status2': safe_str(shared_data.ragnarstatustext2),
            'ragnar_says': safe_str(shared_data.ragnarsays),
            'orchestrator_status': safe_str(shared_data.ragnarorch_status),
            'automation_enabled': is_orchestrator_running(),
            'wifi_connected': wifi_status.get('wifi_connected', safe_bool(shared_data.wifi_connected)),
            'current_ssid': wifi_status.get('current_ssid'),
            'ap_mode_active': wifi_status.get('ap_mode_active', False),
            'ap_ssid': wifi_status.get('ap_ssid'),
            'bluetooth_active': safe_bool(shared_data.bluetooth_active),
            'pan_connected': safe_bool(shared_data.pan_connected),
            'usb_active': safe_bool(shared_data.usb_active),
            'ethernet_connected': safe_bool(is_ethernet_available()),
            'ethernet_ip': _get_active_ethernet_ip(),
            'ethernet_interface': _get_active_ethernet_name(),
            'manual_mode': safe_bool(shared_data.config.get('manual_mode', False)),
            'release_gate': _build_release_gate_payload(),
            'timestamp': datetime.now().isoformat()
        }

        response = jsonify(combined_data)
        response.headers['Cache-Control'] = 'public, max-age=3'
        return response
    except Exception as e:
        logger.error(f"Error getting dashboard quick data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get dashboard statistics using synchronized data from shared_data to ensure consistency.
    DEPRECATED: Use /api/dashboard/quick for faster loading."""
    try:
        requested_network = request.args.get('network') or request.args.get('ssid') or request.args.get('slug')
        identifier = requested_network if requested_network else None
        stats = _collect_dashboard_stats_for_network(identifier)
        response = jsonify(stats)
        response.headers['Cache-Control'] = 'public, max-age=3'
        return response
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# NETKB (Network Knowledge Base) API ENDPOINTS
# ============================================================================

@app.route('/api/netkb/data')
def get_netkb_data():
    """Get network knowledge base data"""
    try:
        netkb_entries = []
        
        # Process network scan results
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        
        # Create directory if it doesn't exist
        try:
            os.makedirs(scan_results_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create scan_results directory: {e}")
        
        if os.path.exists(scan_results_dir):
            try:
                for filename in os.listdir(scan_results_dir):
                    if filename.endswith('.txt') and not filename.startswith('.'):
                        filepath = os.path.join(scan_results_dir, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if content.strip():
                                    # Extract IP from filename or content
                                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                    host_ip = ip_match.group() if ip_match else 'Unknown'
                                    
                                    # Parse port/service info from content
                                    for line in content.split('\n'):
                                        if '/tcp' in line or '/udp' in line:
                                            parts = line.split()
                                            if len(parts) >= 3:
                                                port = parts[0]
                                                service = parts[2] if len(parts) > 2 else 'unknown'
                                                
                                                netkb_entries.append({
                                                    'id': f"scan_{host_ip}_{port}",
                                                    'type': 'service',
                                                    'host': host_ip,
                                                    'port': port,
                                                    'service': service,
                                                    'description': f"Service {service} running on {port}",
                                                    'severity': 'info',
                                                    'discovered': os.path.getmtime(filepath),
                                                    'source': 'Network Scan'
                                                })
                        except Exception as e:
                            logger.debug(f"Could not read scan result file {filepath}: {e}")
                            continue
            except Exception as e:
                logger.warning(f"Could not list scan_results directory: {e}")
        
        # Process vulnerability scan results
        vuln_results_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
        
        # Create directory if it doesn't exist
        try:
            os.makedirs(vuln_results_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create vulnerabilities directory: {e}")
        
        if os.path.exists(vuln_results_dir):
            try:
                for filename in os.listdir(vuln_results_dir):
                    if filename.endswith('.txt') and not filename.startswith('.'):
                        filepath = os.path.join(vuln_results_dir, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if content.strip():
                                    # Extract vulnerability information
                                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                    host_ip = ip_match.group() if ip_match else 'Unknown'
                                    
                                    # Look for CVE patterns
                                    cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
                                    for cve in cve_matches:
                                        netkb_entries.append({
                                            'id': f"vuln_{host_ip}_{cve}",
                                            'type': 'vulnerability',
                                            'host': host_ip,
                                            'port': '',
                                            'service': '',
                                            'description': f"Vulnerability {cve} detected",
                                            'severity': 'high',
                                            'discovered': os.path.getmtime(filepath),
                                            'source': 'Vulnerability Scan',
                                            'cve': cve
                                        })
                                    
                                    # Generic vulnerability entries for files without CVEs
                                    if not cve_matches and len(content.strip()) > 50:
                                        netkb_entries.append({
                                            'id': f"vuln_{host_ip}_{os.path.basename(filename)}",
                                            'type': 'vulnerability',
                                            'host': host_ip,
                                            'port': '',
                                            'service': '',
                                            'description': f"Vulnerability scan results for {host_ip}",
                                            'severity': 'medium',
                                            'discovered': os.path.getmtime(filepath),
                                            'source': 'Vulnerability Scan'
                                        })
                        except Exception as e:
                            logger.debug(f"Could not read vulnerability file {filepath}: {e}")
                            continue
            except Exception as e:
                logger.warning(f"Could not list vulnerabilities directory: {e}")
        
        # Add some example entries if no real data exists
        if not netkb_entries:
            netkb_entries = [
                {
                    'id': 'example_1',
                    'type': 'service',
                    'host': '192.168.1.1',
                    'port': '22/tcp',
                    'service': 'ssh',
                    'description': 'SSH service detected',
                    'severity': 'info',
                    'discovered': time.time(),
                    'source': 'Network Scan'
                },
                {
                    'id': 'example_2',
                    'type': 'vulnerability',
                    'host': '192.168.1.100',
                    'port': '80/tcp',
                    'service': 'http',
                    'description': 'Outdated web server version detected',
                    'severity': 'medium',
                    'discovered': time.time(),
                    'source': 'Vulnerability Scan'
                }
            ]
        
        # Calculate statistics using synchronized vulnerability count
        sync_all_counts()  # Ensure all counts are up to date
        total_entries = len(netkb_entries)
        vulnerabilities = safe_int(shared_data.vulnnbr)  # Use synchronized count from shared_data
        services = len([e for e in netkb_entries if e['type'] == 'service'])
        unique_hosts = len(set([e['host'] for e in netkb_entries]))
        
        return jsonify({
            'entries': netkb_entries,
            'statistics': {
                'total_entries': total_entries,
                'vulnerabilities': vulnerabilities,
                'services': services,
                'unique_hosts': unique_hosts
            }
        })
    except Exception as e:
        logger.error(f"Error getting NetKB data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/netkb/entry/<entry_id>')
def get_netkb_entry(entry_id):
    """Get detailed information for a specific NetKB entry"""
    try:
        # This would normally fetch detailed information about a specific entry
        # For now, return a placeholder response
        return jsonify({
            'id': entry_id,
            'detailed_info': f"Detailed information for entry {entry_id}",
            'recommendations': [
                "Monitor this service regularly",
                "Consider updating to latest version",
                "Implement proper access controls"
            ],
            'references': [
                "https://nvd.nist.gov/",
                "https://cve.mitre.org/",
                "https://www.exploit-db.com/"
            ]
        })
    except Exception as e:
        logger.error(f"Error getting NetKB entry: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/netkb/export')
def export_netkb_data():
    """Export NetKB data in various formats"""
    try:
        format_type = request.args.get('format', 'json')
        
        # Get NetKB data directly
        netkb_entries = []
        
        # Process scan results for host/service information
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        if os.path.exists(scan_results_dir):
            for filename in os.listdir(scan_results_dir):
                if filename.endswith('.txt') and not filename.startswith('.'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                host_ip = ip_match.group() if ip_match else 'Unknown'
                                
                                for line in content.split('\n'):
                                    if '/tcp' in line or '/udp' in line:
                                        parts = line.split()
                                        if len(parts) >= 3:
                                            port = parts[0]
                                            service = parts[2] if len(parts) > 2 else 'unknown'
                                            
                                            netkb_entries.append({
                                                'id': f"scan_{host_ip}_{port}",
                                                'type': 'service',
                                                'host': host_ip,
                                                'port': port,
                                                'service': service,
                                                'description': f"Service {service} running on {port}",
                                                'severity': 'info',
                                                'discovered': os.path.getmtime(filepath),
                                                'source': 'Network Scan'
                                            })
                    except Exception as e:
                        continue
        
        # Add example data if no real data
        if not netkb_entries:
            netkb_entries = [
                {
                    'type': 'service',
                    'host': '192.168.1.1',
                    'port': '22/tcp',
                    'service': 'ssh',
                    'description': 'SSH service detected',
                    'severity': 'info',
                    'source': 'Network Scan'
                }
            ]
        
        if format_type == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Type', 'Host', 'Port', 'Service', 'Description', 'Severity', 'Source'])
            
            # Write data
            for entry in netkb_entries:
                writer.writerow([
                    entry['type'],
                    entry['host'],
                    entry['port'],
                    entry['service'],
                    entry['description'],
                    entry['severity'],
                    entry['source']
                ])
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=netkb_export.csv'}
            )
        else:
            # Default to JSON export
            export_data = {
                'entries': netkb_entries,
                'exported_at': datetime.now().isoformat(),
                'total_entries': len(netkb_entries)
            }
            return Response(
                json.dumps(export_data, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=netkb_export.json'}
            )
    except Exception as e:
        logger.error(f"Error exporting NetKB data: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# AI INSIGHTS ENDPOINTS
# ============================================================================

@app.route('/api/ai/status')
def get_ai_status():
    """Get AI service status and configuration"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        config_enabled = shared_data.config.get('ai_enabled', False)
        
        # If the AI service object isn't present but config says it should be enabled, try to initialize it
        if not ai_service and config_enabled:
            try:
                logger.info("AI service not found but config_enabled=true, attempting initialization...")
                shared_data.initialize_ai_service()
                ai_service = getattr(shared_data, 'ai_service', None)
            except Exception as e:
                logger.error(f"Failed to auto-initialize AI service: {e}")
        
        # If the AI service object still isn't present, report not available
        if not ai_service:
            return jsonify({
                'enabled': False,
                'available': True,  # Always assume SDK is installed
                'config_enabled': config_enabled,
                'configured': False,
                'message': 'AI service not initialized'
            })
        
        status = {
            'enabled': ai_service.is_enabled(),  # Runtime state - is it actually working?
            'config_enabled': config_enabled,  # User's intent from config
            'available': True,  # Always assume SDK is installed
            'model': getattr(ai_service, 'model', None),
            'capabilities': {
                'network_insights': getattr(ai_service, 'network_insights', False),
                'vulnerability_summaries': getattr(ai_service, 'vulnerability_summaries', False)
            },
            'configured': bool(getattr(ai_service, 'api_token', None) or getattr(ai_service, 'client', None))
        }
        
        # Include initialization error if present (but skip SDK-related ones)
        init_error = getattr(ai_service, 'initialization_error', None)
        if init_error and 'OpenAI SDK' not in str(init_error):
            status['error'] = init_error
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting AI status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/insights')
def get_ai_insights():
    """Get comprehensive AI-generated insights about the network"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service or not ai_service.is_enabled():
            return jsonify({
                'enabled': False,
                'message': 'AI service is not enabled. Configure OpenAI API token in settings.'
            })
        
        # Generate insights
        insights = ai_service.generate_insights()
        
        return jsonify(insights)
        
    except Exception as e:
        logger.error(f"Error getting AI insights: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/network-summary')
def get_ai_network_summary():
    """Get AI-generated network security summary"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service or not ai_service.is_enabled():
            return jsonify({
                'enabled': False,
                'message': 'AI service is not enabled'
            })
        
        # Get current network data
        network_data = {
            'target_count': safe_int(shared_data.targetnbr),
            'port_count': safe_int(shared_data.portnbr),
            'vulnerability_count': safe_int(shared_data.vulnnbr),
            'credential_count': safe_int(shared_data.crednbr)
        }
        
        # Get AI summary
        summary = ai_service.analyze_network_summary(network_data)
        
        return jsonify({
            'enabled': True,
            'summary': summary,
            'network_data': network_data
        })
        
    except Exception as e:
        logger.error(f"Error getting AI network summary: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/vulnerabilities')
def get_ai_vulnerability_analysis():
    """Get AI-generated vulnerability analysis"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service or not ai_service.is_enabled():
            return jsonify({
                'enabled': False,
                'message': 'AI service is not enabled'
            })
        
        # Get vulnerabilities from network intelligence
        vulnerabilities = []
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence):
            findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            vulnerabilities = list(findings.get('vulnerabilities', {}).values())
        
        if not vulnerabilities:
            return jsonify({
                'enabled': True,
                'analysis': None,
                'message': 'No vulnerabilities found to analyze'
            })
        
        # Get AI analysis
        analysis = ai_service.analyze_vulnerabilities(vulnerabilities)
        
        return jsonify({
            'enabled': True,
            'analysis': analysis,
            'vulnerability_count': len(vulnerabilities)
        })
        
    except Exception as e:
        logger.error(f"Error getting AI vulnerability analysis: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/weaknesses')
def get_ai_weakness_analysis():
    """Get AI-identified network weaknesses"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service or not ai_service.is_enabled():
            return jsonify({
                'enabled': False,
                'message': 'AI service is not enabled'
            })
        
        # Get network data
        network_data = {
            'target_count': safe_int(shared_data.targetnbr),
            'port_count': safe_int(shared_data.portnbr),
            'vulnerability_count': safe_int(shared_data.vulnnbr)
        }
        
        # Get findings
        findings = []
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence):
            findings_data = shared_data.network_intelligence.get_active_findings_for_dashboard()
            vulnerabilities = list(findings_data.get('vulnerabilities', {}).values())
            credentials = list(findings_data.get('credentials', {}).values())
            findings = vulnerabilities + credentials
        
        # Get AI analysis
        analysis = ai_service.identify_network_weaknesses(network_data, findings)
        
        return jsonify({
            'enabled': True,
            'analysis': analysis,
            'findings_count': len(findings)
        })
        
    except Exception as e:
        logger.error(f"Error getting AI weakness analysis: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/clear-cache', methods=['POST'])
def clear_ai_cache():
    """Clear AI response cache"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service:
            return jsonify({
                'success': False,
                'message': 'AI service not available'
            })
        
        ai_service.clear_cache()
        
        return jsonify({
            'success': True,
            'message': 'AI cache cleared successfully'
        })
        
    except Exception as e:
        logger.error(f"Error clearing AI cache: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/token', methods=['GET'])
def get_ai_token():
    """Get OpenAI API token status (without revealing the actual token)"""
    try:
        from env_manager import EnvManager
        env_manager = EnvManager()
        
        token = env_manager.get_token()
        
        return jsonify({
            'configured': bool(token),
            'token_preview': f"{token[:8]}...{token[-4:]}" if token and len(token) > 12 else None
        })
        
    except Exception as e:
        logger.error(f"Error getting AI token status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/token', methods=['POST'])
def save_ai_token():
    """Save OpenAI API token to .env file"""
    try:
        from env_manager import EnvManager
        env_manager = EnvManager()
        
        data = request.get_json()
        if not data or 'token' not in data:
            return jsonify({'error': 'No token provided'}), 400
        
        token = data['token'].strip()
        
        # Log save attempt
        logger.info(f"Attempting to save AI token to {env_manager.env_file_path}")
        
        # Save token to .env file
        result = env_manager.save_token(token)
        
        if result['success']:
            auto_enabled = False
            if not shared_data.config.get('ai_enabled', False):
                shared_data.config['ai_enabled'] = True
                setattr(shared_data, 'ai_enabled', True)
                shared_data.save_config()
                socketio.emit('config_updated', shared_data.config)
                auto_enabled = True
                logger.info("AI Insights automatically enabled after saving API token")
            
            # Reinitialize AI service with new token
            ai_service = getattr(shared_data, 'ai_service', None)
            if ai_service:
                if ai_service.reload_token():
                    logger.info("AI service reloaded with new token")
                else:
                    logger.warning("AI service failed to reload with new token")
            
            return jsonify({
                'success': True,
                'message': result['message'],
                'configured': True,
                'ai_enabled': shared_data.config.get('ai_enabled', False),
                'auto_enabled': auto_enabled,
                'env_file': str(env_manager.env_file_path)
            })
        else:
            logger.error(f"Failed to save token to {env_manager.env_file_path}")
            return jsonify({
                'success': False,
                'message': result.get('message', 'Failed to save token. Check server logs for details.'),
                'env_file': str(env_manager.env_file_path)
            }), 500
        
    except Exception as e:
        logger.error(f"Error saving AI token: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/token', methods=['DELETE'])
def remove_ai_token():
    """Remove OpenAI API token from .env file"""
    try:
        from env_manager import EnvManager
        import os
        env_manager = EnvManager()
        
        # Remove the .env file
        if os.path.exists(env_manager.env_file_path):
            os.remove(env_manager.env_file_path)
            
            # Disable AI service
            ai_service = getattr(shared_data, 'ai_service', None)
            if ai_service:
                ai_service.api_token = ''
                ai_service.enabled = False
            
            return jsonify({
                'success': True,
                'message': 'Token removed from .env successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No token file found'
            }), 404
        
    except Exception as e:
        logger.error(f"Error removing AI token: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# PUSHOVER NOTIFICATION ENDPOINTS
# ============================================================================

@app.route('/api/pushover/keys', methods=['GET'])
def get_pushover_keys():
    """Get Pushover key status (without revealing full keys)."""
    try:
        from env_manager import EnvManager
        em = EnvManager()
        user_key = em.get_env_key("RAGNAR_PUSHOVER_USER_KEY")
        api_token = em.get_env_key("RAGNAR_PUSHOVER_API_TOKEN")
        return jsonify({
            'user_key_configured': bool(user_key),
            'api_token_configured': bool(api_token),
            'user_key_preview': f"{user_key[:6]}...{user_key[-4:]}" if user_key and len(user_key) > 10 else None,
            'api_token_preview': f"{api_token[:6]}...{api_token[-4:]}" if api_token and len(api_token) > 10 else None,
        })
    except Exception as e:
        logger.error(f"Error getting Pushover key status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pushover/keys', methods=['POST'])
def save_pushover_keys():
    """Save Pushover user key and/or API token to .env file."""
    try:
        from env_manager import EnvManager
        em = EnvManager()
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        saved = []
        user_key = data.get('user_key', '').strip()
        api_token = data.get('api_token', '').strip()

        if user_key:
            em.set_env_key("RAGNAR_PUSHOVER_USER_KEY", user_key)
            saved.append("User Key")
        if api_token:
            em.set_env_key("RAGNAR_PUSHOVER_API_TOKEN", api_token)
            saved.append("API Token")

        if not saved:
            return jsonify({'error': 'No keys provided'}), 400

        # Auto-enable Pushover if both keys are now set
        uk = em.get_env_key("RAGNAR_PUSHOVER_USER_KEY")
        at = em.get_env_key("RAGNAR_PUSHOVER_API_TOKEN")
        auto_enabled = False
        if uk and at and not shared_data.config.get('pushover_enabled', False):
            shared_data.config['pushover_enabled'] = True
            shared_data.save_config()
            auto_enabled = True

        return jsonify({
            'success': True,
            'message': f"✓ Saved: {', '.join(saved)}",
            'auto_enabled': auto_enabled,
            'both_configured': bool(uk and at),
        })
    except Exception as e:
        logger.error(f"Error saving Pushover keys: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pushover/keys', methods=['DELETE'])
def remove_pushover_keys():
    """Remove Pushover keys from .env file."""
    try:
        from env_manager import EnvManager
        em = EnvManager()
        em.delete_env_key("RAGNAR_PUSHOVER_USER_KEY")
        em.delete_env_key("RAGNAR_PUSHOVER_API_TOKEN")
        shared_data.config['pushover_enabled'] = False
        shared_data.save_config()
        return jsonify({'success': True, 'message': 'Pushover keys removed'})
    except Exception as e:
        logger.error(f"Error removing Pushover keys: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pushover/test', methods=['POST'])
def test_pushover():
    """Send a test Pushover notification."""
    try:
        pushover = getattr(shared_data, '_pushover_service', None)
        if not pushover:
            from pushover_service import PushoverService
            pushover = PushoverService(shared_data)
            shared_data._pushover_service = pushover

        if not pushover.is_configured():
            return jsonify({'success': False, 'message': 'Pushover keys not configured. Please save your User Key and API Token first.'}), 400

        result = pushover.send(
            message="Hello there Viking, are you ready for adventures?",
            title="Ragnar says",
            sound="bugle"
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error testing Pushover: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ============================================================================
# AIRSNITCH – Wi-Fi Client Isolation Testing
# ============================================================================

def _get_airsnitch_instance():
    """Return (or lazily create) a shared AirSnitch instance."""
    if not hasattr(shared_data, '_airsnitch'):
        from actions.airsnitch import AirSnitch
        shared_data._airsnitch = AirSnitch(shared_data)
    return shared_data._airsnitch


@app.route('/api/airsnitch/status', methods=['GET'])
def airsnitch_status():
    """Return AirSnitch installation status and latest results."""
    try:
        airsnitch = _get_airsnitch_instance()
        installed = airsnitch.runner.is_installed()
        latest = airsnitch.get_latest_results()
        return jsonify({
            'success': True,
            'installed': installed,
            'latest_results': latest,
        })
    except Exception as exc:
        logger.error(f"airsnitch_status error: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/airsnitch/run', methods=['POST'])
def airsnitch_run():
    """
    Trigger an AirSnitch client isolation test.

    Optional JSON body:
      iface_victim   (str)   – victim wireless interface   (default: wlan1)
      iface_attacker (str)   – attacker wireless interface (default: wlan2)
      tests          (list)  – subset of ["gtk","gateway","port_steal_down","port_steal_up"]
      same_bss       (bool)  – test same-BSS scenario      (default: false)
      server         (str)   – pingable server for port-steal tests (default: "8.8.8.8")
    """
    try:
        data = request.get_json(silent=True) or {}

        # Temporarily override config values for this run
        cfg_overrides = {k: v for k, v in {
            'airsnitch_iface_victim':   data.get('iface_victim'),
            'airsnitch_iface_attacker': data.get('iface_attacker'),
            'airsnitch_tests':          data.get('tests'),
            'airsnitch_same_bss':       data.get('same_bss'),
            'airsnitch_server':         data.get('server'),
            'airsnitch_victim_ssid':    data.get('victim_ssid'),
            'airsnitch_victim_psk':     data.get('victim_psk'),
            'airsnitch_attacker_ssid':  data.get('attacker_ssid'),
            'airsnitch_attacker_psk':   data.get('attacker_psk'),
        }.items() if v is not None}

        original_cfg = {}
        cfg = getattr(shared_data, 'config', {})
        for k, v in cfg_overrides.items():
            original_cfg[k] = cfg.get(k)
            cfg[k] = v

        airsnitch = _get_airsnitch_instance()

        def run_in_background():
            try:
                airsnitch.execute()
            finally:
                for k, v in original_cfg.items():
                    if v is None:
                        cfg.pop(k, None)
                    else:
                        cfg[k] = v

        thread = threading.Thread(target=run_in_background, daemon=True, name="airsnitch-run")
        thread.start()

        return jsonify({'success': True, 'message': 'AirSnitch test started in background'})

    except Exception as exc:
        logger.error(f"airsnitch_run error: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/airsnitch/results', methods=['GET'])
def airsnitch_results():
    """Return the most recent AirSnitch test results."""
    try:
        airsnitch = _get_airsnitch_instance()
        results = airsnitch.get_latest_results()
        if results is None:
            return jsonify({'success': True, 'results': None, 'message': 'No results yet'})
        return jsonify({'success': True, 'results': results})
    except Exception as exc:
        logger.error(f"airsnitch_results error: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/airsnitch/install', methods=['POST'])
def airsnitch_install():
    """Install AirSnitch from GitHub (runs in background, streams output to install log)."""
    try:
        airsnitch = _get_airsnitch_instance()
        if airsnitch.runner.is_installed():
            return jsonify({'success': True, 'message': 'AirSnitch is already installed', 'installing': False})

        if airsnitch.is_installing():
            return jsonify({'success': True, 'message': 'Installation already in progress', 'installing': True})

        def do_install():
            airsnitch._installing = True
            try:
                airsnitch.runner.install()
            finally:
                airsnitch._installing = False

        thread = threading.Thread(target=do_install, daemon=True, name="airsnitch-install")
        thread.start()
        return jsonify({'success': True, 'message': 'AirSnitch installation started', 'installing': True})
    except Exception as exc:
        logger.error(f"airsnitch_install error: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


@app.route('/api/airsnitch/install-log', methods=['GET'])
def airsnitch_install_log():
    """Return the live install log and current install state."""
    try:
        airsnitch = _get_airsnitch_instance()
        return jsonify({
            'success': True,
            'log': airsnitch.get_install_log(),
            'installing': airsnitch.is_installing(),
            'installed': airsnitch.runner.is_installed(),
        })
    except Exception as exc:
        logger.error(f"airsnitch_install_log error: {exc}")
        return jsonify({'success': False, 'error': str(exc)}), 500


# ============================================================================
# SIGNAL HANDLERS
# ============================================================================

def handle_exit(signum, frame):
    """Handle exit signals with proper cleanup"""
    logger.info("Shutting down web server...")
    shared_data.webapp_should_exit = True
    
    # Stop all background tasks first
    try:
        socketio.stop()
    except Exception as e:
        logger.warning(f"Error stopping socketio: {e}")
    
    # Kill any running subprocesses
    try:
        if psutil_available:
            current_process = psutil.Process()
            children = current_process.children(recursive=True)
            
            if children:
                logger.info(f"Terminating {len(children)} child processes...")
                for child in children:
                    try:
                        child.terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Wait up to 3 seconds for graceful termination
                gone, alive = psutil.wait_procs(children, timeout=3)
                
                # Force kill any remaining processes
                for p in alive:
                    try:
                        logger.warning(f"Force killing process {p.pid} ({p.name()})")
                        p.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        else:
            # Fallback: try to kill common subprocess patterns
            logger.info("Attempting to clean up subprocesses (psutil not available)...")
            try:
                subprocess.run(['pkill', '-P', str(os.getpid())], timeout=2)
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Error cleaning up subprocesses: {e}")
    
    logger.info("Shutdown complete")
    sys.exit(0)



# ============================================================================
# MAIN
# ============================================================================

def generate_self_signed_cert(cert_path: str, key_path: str):
    """Generate a self-signed SSL certificate"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Security"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Ragnar"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ragnar Security Scanner"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ragnar.local"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("ragnar.local"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

        # Write key
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Write certificate
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info(f"Generated self-signed SSL certificate: {cert_path}")
        return True

    except ImportError:
        logger.warning("cryptography library not installed. Cannot generate SSL certificate.")
        logger.warning("Install with: pip install cryptography")
        return False
    except Exception as e:
        logger.error(f"Error generating SSL certificate: {e}")
        return False


def _resolve_bind_address(interface_name: str) -> str:
    """Resolve a network interface name (e.g. 'wlan0') to its IPv4 address.
    Returns '0.0.0.0' if the interface has no IP or doesn't exist."""
    if not interface_name:
        return '0.0.0.0'
    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface_name)
        ipv4_list = addrs.get(netifaces.AF_INET, [])
        if ipv4_list:
            return ipv4_list[0].get('addr', '0.0.0.0')
    except Exception:
        pass
    # Fallback: parse ip addr output
    try:
        import subprocess
        result = subprocess.run(
            ['ip', '-4', '-o', 'addr', 'show', interface_name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            # Format: "4: wlan0    inet 192.168.1.211/24 ..."
            for part in result.stdout.split():
                if '.' in part and '/' in part:
                    return part.split('/')[0]
    except Exception:
        pass
    logger.warning(f"Could not resolve IP for interface '{interface_name}', falling back to 0.0.0.0")
    return '0.0.0.0'


def run_server(host='0.0.0.0', port=8000, ssl_cert=None, ssl_key=None, https_port=None):
    """
    Run the Flask server with optional HTTPS support.

    Args:
        host: Host to bind to (default: 0.0.0.0)
        port: HTTP port (default: 8000)
        ssl_cert: Path to SSL certificate file (optional)
        ssl_key: Path to SSL key file (optional)
        https_port: HTTPS port (default: None, uses port+443-80 if SSL enabled)
    """
    try:
        # Bind to a specific interface if configured
        bind_iface = shared_data.config.get('web_bind_interface', '')
        if bind_iface:
            resolved = _resolve_bind_address(bind_iface)
            if resolved != '0.0.0.0':
                host = resolved
                logger.info(f"Binding web server to interface {bind_iface} ({host})")
            else:
                logger.warning(f"Interface '{bind_iface}' has no IP, binding to all interfaces")
        # Determine SSL configuration
        ssl_context = None
        use_https = False

        if ssl_cert and ssl_key:
            if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
                ssl_context = (ssl_cert, ssl_key)
                use_https = True
                logger.info(f"SSL enabled with certificate: {ssl_cert}")
            else:
                logger.warning(f"SSL cert/key not found. Running HTTP only.")
        elif ssl_cert == 'adhoc' or os.environ.get('RAGNAR_HTTPS', '').lower() == 'true':
            # Generate self-signed certificate
            cert_dir = os.path.join(os.path.dirname(__file__), 'certs')
            os.makedirs(cert_dir, exist_ok=True)
            cert_path = os.path.join(cert_dir, 'ragnar.crt')
            key_path = os.path.join(cert_dir, 'ragnar.key')

            if os.path.exists(cert_path) and os.path.exists(key_path):
                ssl_context = (cert_path, key_path)
                use_https = True
                logger.info(f"Using existing SSL certificate: {cert_path}")
            elif generate_self_signed_cert(cert_path, key_path):
                ssl_context = (cert_path, key_path)
                use_https = True
            else:
                logger.warning("Could not generate SSL certificate. Running HTTP only.")

        # Determine effective port
        effective_port = https_port if (use_https and https_port) else port

        protocol = "https" if use_https else "http"
        logger.info(f"Starting Ragnar web server on {host}:{effective_port}")
        logger.info(f"Access the interface at {protocol}://{host}:{effective_port}")

        if use_https:
            logger.info("⚠️  Using self-signed certificate - browser will show security warning")

        # Synchronize counts in the background so the web server binds
        # immediately instead of waiting for a full DB scan first.
        def _deferred_sync():
            try:
                sync_all_counts()
                logger.info("Initial sync_all_counts completed")
            except Exception as e:
                logger.error(f"Deferred sync_all_counts error: {e}")
        socketio.start_background_task(_deferred_sync)

        # Start background status broadcaster
        socketio.start_background_task(broadcast_status_updates)
        socketio.start_background_task(background_sync_loop)
        socketio.start_background_task(background_arp_scan_loop)
        socketio.start_background_task(background_health_monitor)

        logger.info("✅ All background threads started successfully")

        # Run the server
        if use_https and ssl_context:
            socketio.run(app, host=host, port=effective_port, debug=False,
                        allow_unsafe_werkzeug=True, ssl_context=ssl_context)
        else:
            socketio.run(app, host=host, port=effective_port, debug=False,
                        allow_unsafe_werkzeug=True)

    except Exception as e:
        logger.error(f"Error running server: {e}")
        raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Ragnar Security Scanner Web Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='HTTP port (default: 8000)')
    parser.add_argument('--ssl-cert', help='Path to SSL certificate file')
    parser.add_argument('--ssl-key', help='Path to SSL key file')
    parser.add_argument('--https', action='store_true', help='Enable HTTPS with self-signed certificate')
    parser.add_argument('--https-port', type=int, help='HTTPS port (default: same as --port)')

    args = parser.parse_args()

    # Set up signal handling
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # Determine SSL settings
    ssl_cert = args.ssl_cert
    ssl_key = args.ssl_key

    if args.https and not ssl_cert:
        ssl_cert = 'adhoc'  # Will trigger self-signed cert generation

    # Run the server
    run_server(
        host=args.host,
        port=args.port,
        ssl_cert=ssl_cert,
        ssl_key=ssl_key,
        https_port=args.https_port
    )
