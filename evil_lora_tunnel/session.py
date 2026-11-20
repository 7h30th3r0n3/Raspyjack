"""Bounded local capture with durable raw observations and explicit GPS freshness."""
import json
import math
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import socket
import sqlite3
import tempfile
import threading
import time
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone

from . import RadioError
from .gnss import read_cap_uart, share_gps

SCHEMA_VERSION = 1
LOCK_PATH = Path('/run/lock/evil-lora-tunnel.lock')
MIN_FREE_BYTES = 16 * 1024 * 1024


def atomic_json(path, data, *, durable=True):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '-')
    try:
        with os.fdopen(fd, 'w', encoding='utf8') as stream:
            json.dump(data, stream, ensure_ascii=True, allow_nan=False)
            stream.write('\n')
            if durable:
                stream.flush()
                os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)
    if durable and os.name == 'posix':
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def create_session(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if shutil.disk_usage(root).free < MIN_FREE_BYTES:
        raise RuntimeError('Storage has less than 16 MiB free')
    directory = root / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
    directory.mkdir(mode=0o700)
    atomic_json(directory / 'session.json', {
        'schema_version': SCHEMA_VERSION, 'status': 'created',
        'created_at': time.time(), 'native_files': {},
        'time_source': 'system clock; receiver UTC recorded separately',
    })
    return directory.resolve()


def _metadata(directory):
    path = Path(directory) / 'session.json'
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('Missing or invalid Evil-LORA-Tunnel session metadata')
    data = json.loads(path.read_text(encoding='utf8'))
    if data.get('schema_version') != SCHEMA_VERSION:
        raise ValueError('Unsupported session schema')
    return data


def interrupt_start(directory, reason):
    """Persist an early launch failure after the launcher knows its child is gone."""
    data = _metadata(directory)
    if data['status'] == 'created':
        data.update(status='interrupted', ended_at=time.time(), errors=[reason])
        atomic_json(Path(directory) / 'session.json', data)


def attach(directory, kind, path):
    if kind not in ('wifi_csv', 'wifi_pcap'):
        raise ValueError('Unknown native capture type')
    source = Path(path)
    if not source.is_absolute() or not source.is_file():
        raise ValueError('Native capture must be an existing absolute file path')
    data = _metadata(directory)
    if data['status'] in ('starting', 'capturing'):
        raise ValueError('Attach native files after stopping LoRa capture')
    data['native_files'][kind] = str(source)
    data.setdefault('retained_files', {}).pop(kind, None)
    atomic_json(Path(directory) / 'session.json', data)


def finalize(directory):
    """Snapshot explicitly attached native logs; originals always remain in place."""
    directory = Path(directory)
    data = _metadata(directory)
    if data['status'] != 'closed':
        raise ValueError('Only cleanly closed sessions can be finalized')
    for kind, source in data.get('native_files', {}).items():
        target = directory / {'wifi_csv': 'wifi.csv', 'wifi_pcap': 'wifi.pcap'}[kind]
        if data.get('retained_files', {}).get(kind) == source and target.is_file():
            continue
        source = Path(source)
        if source.resolve() == target.resolve():
            continue
        before = source.stat()
        if before.st_size + MIN_FREE_BYTES > shutil.disk_usage(directory).free:
            raise RuntimeError('Not enough storage to retain native capture')
        tmp = target.with_suffix(target.suffix + '.partial')
        try:
            shutil.copyfile(source, tmp)
            with tmp.open('r+b') as snapshot:
                os.fsync(snapshot.fileno())
            after = source.stat()
            if (not os.path.samestat(before, after) or
                    (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
                raise RuntimeError('Native recording is still changing; stop it before export')
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
            data.setdefault('retained_files', {})[kind] = str(source)
            atomic_json(directory / 'session.json', data)
        finally:
            tmp.unlink(missing_ok=True)


class GPS:
    """Use a shared gpsd feed, or an idle cap UART when no gpsd receiver exists."""
    def __init__(self, cap_directory=None):
        self.cap_directory = cap_directory
        self._fix = {}
        self._updated = 0.0
        self._lock = threading.Lock()

    def update(self, value, now=None):
        if value.get('class') != 'TPV':
            return
        now = time.monotonic() if now is None else now
        mode = value.get('mode', 0)
        # gpsd can split an epoch into partial TPVs. Do not discard an actual
        # fix or renew its age merely because a later report has no position.
        if type(mode) is int and mode in (2, 3) and not {'lat', 'lon'} <= value.keys():
            return
        fix = {'mode': mode if type(mode) is int and mode in (0, 1, 2, 3) else 0, 'valid': False}
        if isinstance(value.get('time'), str):
            fix['utc'] = value['time'][:64]
        lat, lon = value.get('lat'), value.get('lon')
        if (fix['mode'] in (2, 3) and type(lat) in (float, int)
                and type(lon) in (float, int) and math.isfinite(lat)
                and math.isfinite(lon) and -90 <= lat <= 90 and -180 <= lon <= 180):
            fix.update(valid=True, latitude=lat, longitude=lon)
            for key in ('time', 'altHAE', 'altMSL', 'epx', 'epy', 'epv', 'speed'):
                item = value.get(key)
                if isinstance(item, (int, float)) and math.isfinite(item):
                    fix[key] = item
                elif key == 'time' and isinstance(item, str):
                    fix['utc'] = item[:64]
        with self._lock:
            self._fix, self._updated = fix, now

    def snapshot(self, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            fix = dict(self._fix)
            age = max(0.0, now - self._updated) if self._updated else None
        fix['age_seconds'] = age
        fix['valid'] = bool(fix.get('valid') and age is not None and age <= 10)
        fix['status'] = 'fix' if fix['valid'] else ('stale' if age is not None and age > 10 else 'no_fix')
        if not fix['valid']:
            for key in ('latitude', 'longitude', 'utc', 'altHAE', 'altMSL', 'speed'):
                fix.pop(key, None)
        return fix

    def run(self, stopped):
        while not stopped.is_set():
            try:
                with socket.create_connection(('127.0.0.1', 2947), 2) as sock:
                    sock.settimeout(1)
                    sock.sendall(b'?WATCH={"enable":true,"json":true};\n')
                    buffer = b''
                    first_report = time.monotonic() + 5
                    while not stopped.is_set():
                        try:
                            part = sock.recv(8192)
                        except socket.timeout:
                            if first_report and time.monotonic() >= first_report:
                                break
                            continue
                        if not part:
                            break
                        buffer += part
                        if len(buffer) > 65536:
                            raise ValueError('gpsd line exceeded limit')
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            try:
                                message = json.loads(line)
                                if isinstance(message, dict):
                                    if message.get('class') == 'DEVICES' and message.get('devices') == []:
                                        raise ConnectionError('gpsd has no receiver')
                                    if message.get('class') in ('TPV', 'SKY', 'DEVICE', 'DEVICES'):
                                        first_report = None
                                    self.update(message)
                            except (ValueError, TypeError):
                                continue
            except (OSError, ValueError):
                pass
            if self.cap_directory is not None and not stopped.is_set():
                read_cap_uart(stopped, self.update, self.cap_directory)
            stopped.wait(2)


class Store:
    def __init__(self, directory):
        from .loratap import PCAPWriter
        self.directory = Path(directory)
        self.pcap = PCAPWriter(self.directory / 'lora.pcap')
        self.db = sqlite3.connect(self.directory / 'capture.sqlite3')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY, received_at REAL NOT NULL,
                protocol TEXT, node_id TEXT, raw BLOB NOT NULL, record_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS devices (
                protocol TEXT NOT NULL, node_id TEXT NOT NULL,
                first_seen REAL NOT NULL, last_seen REAL NOT NULL, sightings INTEGER NOT NULL,
                latest_json TEXT NOT NULL, PRIMARY KEY(protocol, node_id));
            CREATE INDEX IF NOT EXISTS devices_last_seen ON devices(last_seen DESC);
            PRAGMA user_version=1;
        ''')
        self.stream = (self.directory / 'observations.jsonl').open('a', encoding='utf8', buffering=65536)
        self.count = 0

    def append(self, record):
        raw = bytes.fromhex(record['raw_hex'])
        if not 1 <= len(raw) <= 255:
            raise ValueError('Invalid radio packet length')
        record = dict(record, schema_version=SCHEMA_VERSION)
        text = json.dumps(record, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        if len(text) > 32768:
            raise ValueError('Observation exceeded size limit')
        decoded = record.get('decoded', {})
        protocol = decoded.get('protocol', 'unknown')
        node = decoded.get('node_id') or decoded.get('source_id') or decoded.get('from_id')
        if isinstance(node, int):
            node = '%08x' % node
        if not isinstance(node, str) or len(node) > 128:
            node = None
        stamp = record['timestamp']
        self.db.execute('INSERT INTO observations(received_at,protocol,node_id,raw,record_json) VALUES(?,?,?,?,?)',
                        (stamp, protocol, node, raw, text))
        if node:
            previous = self.db.execute('SELECT latest_json FROM devices WHERE protocol=? AND node_id=?',
                                       (protocol, node)).fetchone()
            summary = dict(record)
            if previous:
                prior = json.loads(previous[0])
                known = prior.get('decoded', {})
                summary['decoded'] = dict(known, **decoded)
                summary['field_times'] = prior.get('field_times', {})
            else:
                summary['field_times'] = {}
            for field in decoded:
                summary['field_times'][field] = stamp
            summary_text = json.dumps(summary, ensure_ascii=True, allow_nan=False)
            self.db.execute('''INSERT INTO devices VALUES(?,?,?,?,?,?)
                ON CONFLICT(protocol,node_id) DO UPDATE SET
                last_seen=excluded.last_seen,sightings=devices.sightings+1,latest_json=excluded.latest_json''',
                (protocol, node, stamp, stamp, 1, summary_text))
        self.stream.write(text + '\n')
        self.pcap.append(record)
        self.count += 1

    def flush(self):
        self.db.commit()
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.pcap.flush()

    def close(self):
        failure = None
        try:
            self.flush()
            self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        except Exception as exc:
            failure = exc
        finally:
            # A buffered write can fail again during close. Still close every
            # other sink so its successfully received records can be retained.
            for resource in (self.db, self.stream, self.pcap):
                try:
                    resource.close()
                except Exception as exc:
                    if failure is None:
                        failure = exc
        if failure is not None:
            raise failure


def status(directory):
    result = _metadata(directory)
    if result['status'] in ('starting', 'capturing') and result.get('worker_identity'):
        try:
            current = process_identity(result['pid'])
        except (FileNotFoundError, ProcessLookupError):
            current = None
        if current != result['worker_identity']:
            # Re-read in case shutdown committed a final manifest before exit.
            result = _metadata(directory)
            if result['status'] in ('starting', 'capturing'):
                result.update(status='interrupted', errors=['Collector ended before closing the session'])
                # The observation timestamp is the last trustworthy end-time bound.
                atomic_json(Path(directory) / 'session.json', result)
    path = Path(directory) / 'status.json'
    if path.exists() and path.stat().st_size < 65536:
        result.update(json.loads(path.read_text(encoding='utf8')))
    return result


def process_identity(pid):
    """Linux boot ID and per-process start tick identify a worker across PID reuse."""
    stat = (Path('/proc') / str(pid) / 'stat').read_text()
    tick = stat.rsplit(')', 1)[1].split()[19]
    return {'pid': pid, 'start_tick': tick,
            'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


@contextmanager
def session_lock():
    """Serialize capture and export/upload ownership between RaspyJack processes."""
    import fcntl
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    with os.fdopen(os.open(LOCK_PATH, flags, 0o600), 'r+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RadioError("Another Evil-LORA-Tunnel operation is in progress") from exc
        yield


def capture(directory, config, duration=None):
    directory = Path(directory)
    stop = threading.Event()
    previous = {}
    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[sig] = signal.signal(sig, lambda *_: stop.set())
        with session_lock():
            # The common lock guarantees that only its current collector can
            # publish or clear this hint. Identity lives in the session manifest.
            active = directory.parent / '.active-session.json'
            atomic_json(active, directory.name, durable=False)
            try:
                return _collect(directory, config, stop, duration)
            finally:
                active.unlink(missing_ok=True)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _collect(directory, config, stop, duration):
    from .profiles import select_profiles
    from .decode import decode_packet

    directory = Path(directory)
    metadata = _metadata(directory)
    if metadata['status'] != 'created':
        raise ValueError('Start a new session; completed logs cannot be overwritten')
    profiles = select_profiles(config.get('region'), config.get('mode', 'meshtastic'))
    backend = config['backend']
    gps = GPS(cap_directory=directory if backend == 'cap' else None)
    packets = queue.Queue(maxsize=256)
    counters = {'received': 0, 'saved': 0, 'queue_drops': 0, 'decode_errors': 0, 'write_errors': 0}
    failure = []
    active = [profiles[0]]
    radio = None
    store = None
    worker = None
    gps_thread = None
    start = time.monotonic()
    producer_done = threading.Event()
    metadata.update(status='starting', started_at=time.time(), pid=os.getpid(), profiles=[p.to_dict() for p in profiles],
                    backend=config.get('backend', 'cap'))
    if os.name == 'posix':
        metadata['worker_identity'] = process_identity(os.getpid())

    def receive():
        index, deadline = 0, time.monotonic() + profiles[0].dwell_seconds
        try:
            while not stop.is_set():
                record = radio.receive(timeout=0.25)
                if record:
                    record['receiver_gps'] = gps.snapshot()
                    counters['received'] += 1
                    try:
                        packets.put_nowait(record)
                    except queue.Full:
                        counters['queue_drops'] += 1
                if len(profiles) > 1 and time.monotonic() >= deadline:
                    index = (index + 1) % len(profiles)
                    radio.tune(profiles[index])
                    active[0] = profiles[index]
                    deadline = time.monotonic() + profiles[index].dwell_seconds
        except Exception as exc:
            failure.append(str(exc) if isinstance(exc, RadioError) else type(exc).__name__)
            stop.set()
        finally:
            producer_done.set()

    try:
        atomic_json(directory / 'session.json', metadata)
        if backend == 'lorapipe':
            from .lorapipe import LoRaPipeSerial
            if not config['serial_device']:
                raise RadioError("Select the LoRaPipe serial device")
            radio = LoRaPipeSerial(profiles[0], config['serial_device'])
        elif backend == 'cap':
            from .cap import CapRadio
            radio = CapRadio(profiles[0])
        else:
            raise RadioError("Select a supported receiver")
        radio.open()
        store = Store(directory)
        metadata['status'] = 'capturing'
        atomic_json(directory / 'session.json', metadata)
        gps_thread = threading.Thread(target=gps.run, args=(stop,), daemon=True)
        worker = threading.Thread(target=receive, daemon=True)
        gps_thread.start()
        worker.start()
        last_flush = time.monotonic()
        flushed_count = -1
        while not producer_done.is_set() or not packets.empty():
            if duration is not None and time.monotonic() - start >= duration:
                stop.set()
            try:
                record = packets.get(timeout=0.25)
            except queue.Empty:
                record = None
            if record:
                if record.get('crc_ok') is False:
                    record['decoded'] = {'protocol': 'unknown', 'decode_status': 'crc_error'}
                elif 'decoded' not in record:
                    try:
                        profile = next(p for p in profiles if p.id == record['profile']['id'])
                        record['decoded'] = decode_packet(bytes.fromhex(record['raw_hex']), profile)
                    except Exception:
                        counters['decode_errors'] += 1
                        record['decoded'] = {'protocol': 'unknown', 'decode_status': 'decoder_error'}
                try:
                    store.append(record)
                except (OSError, sqlite3.Error):
                    counters['write_errors'] += 1
                    raise
                counters['saved'] += 1
            if time.monotonic() - last_flush >= 1:
                if flushed_count != store.count:
                    try:
                        store.flush()
                    except (OSError, sqlite3.Error):
                        counters['write_errors'] += 1
                        raise
                    flushed_count = store.count
                atomic_json(directory / 'status.json', dict(counters, profile=active[0].id,
                            gps=gps.snapshot(), radio=radio.diagnostics, elapsed_seconds=round(time.monotonic()-start)),
                            durable=False)
                if shutil.disk_usage(directory).free < MIN_FREE_BYTES:
                    failure.append('Storage reserve reached')
                    stop.set()
                last_flush = time.monotonic()
        worker.join(2)
        if worker.is_alive():
            failure.append('Radio shutdown timeout')
    except Exception as exc:
        failure.append(str(exc) if isinstance(exc, RadioError) else type(exc).__name__)
    finally:
        stop.set()
        if worker and worker.is_alive():
            worker.join(2)
            if worker.is_alive():
                failure.append('Radio shutdown timeout')
        if gps_thread and gps_thread.is_alive():
            gps_thread.join(3)
        if radio:
            try:
                radio.close()
            except Exception:
                failure.append('RadioCloseError')
        if store:
            try:
                store.close()
            except Exception:
                counters['write_errors'] += 1
                failure.append('StorageCloseError')
        metadata.update(status='interrupted' if failure else 'closed', ended_at=time.time(),
                        counters=counters, errors=failure)
        atomic_json(directory / 'session.json', metadata)
        atomic_json(directory / 'status.json', dict(counters, profile=active[0].id,
                    gps=gps.snapshot(), radio=radio.diagnostics if radio else {},
                    elapsed_seconds=round(time.monotonic()-start)))
    return 1 if failure else 0


def _display_text(value, limit=44):
    if not isinstance(value, str):
        return ""
    printable = "".join(character if 32 <= ord(character) <= 126 else " " for character in value)
    printable = " ".join(printable.split())
    return printable[:limit - 3] + "..." if len(printable) > limit else printable


def _source_identity(decoded):
    source = decoded.get("source_id")
    if decoded.get("protocol") == "meshtastic" and isinstance(source, str):
        if re.fullmatch(r"![0-9a-fA-F]{8}", source) and source.lower() not in {"!00000000", "!ffffffff"}:
            return "MT", source.lower(), "claimed"
    if decoded.get("protocol") == "meshcore" and decoded.get("signature_valid") is True:
        if isinstance(source, str) and re.fullmatch(r"[0-9a-fA-F]{64}", source) and source == decoded.get("public_key"):
            return "MC", source[:10].lower() + "..", "signed"
    protocol = {"meshtastic": "MT", "meshcore": "MC"}.get(decoded.get("protocol"), "Unknown")
    return protocol, "unknown", ""


def _observation_lines(timestamp, record, devices=False):
    decoded = record.get("decoded", {})
    if not isinstance(decoded, dict):
        decoded = {}
    protocol, source, identity = _source_identity(decoded)
    if devices and not identity:
        return []
    try:
        when = datetime.fromtimestamp(float(timestamp), timezone.utc).strftime("%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        when = "time unavailable"

    def measurement(field, prefix):
        value = record.get(field)
        return prefix + ("%g" % value if type(value) in (int, float) and math.isfinite(value) else "?")

    profile = record.get("profile", {})
    profile_id = profile.get("id", "") if isinstance(profile, dict) else ""
    if not isinstance(profile_id, str):
        profile_id = ""
    short_profile = "LF" if profile_id.endswith("LONG_FAST") else "Narrow" if profile_id.endswith("NARROW") else _display_text(profile_id, 10)
    first = "%s %s %s" % (protocol, source, when)
    fields = [measurement("rssi_dbm", "R"), measurement("snr_db", "S")]
    if short_profile:
        fields.append(short_profile)
    if devices:
        fields.append(identity)
    label = decoded.get("name") or decoded.get("short_name")
    detail = _display_text(label, 12)
    text = _display_text(decoded.get("text"), 24)
    state = _display_text(decoded.get("decode_status"), 18)
    if detail:
        fields.append(detail)
    if text:
        fields.append(text)
    elif state:
        fields.append(state)
    return [first, _display_text(" | ".join(fields), 60)]


def recent_records(directory, devices=False):
    """Read a small committed snapshot without creating or modifying a database."""
    path = (Path(directory) / "capture.sqlite3").resolve()
    if not path.is_file():
        return ["No saved observations in this session yet."]
    deadline = time.monotonic() + 0.5
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.2)) as database:
        database.execute("PRAGMA query_only=ON")
        database.execute("PRAGMA trusted_schema=OFF")
        database.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        if database.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise ValueError("Unsupported capture database")
        if devices:
            rows = database.execute("SELECT last_seen, substr(latest_json,1,32769) FROM devices ORDER BY last_seen DESC LIMIT 8").fetchall()
        else:
            rows = database.execute("SELECT received_at, substr(record_json,1,32769) FROM observations ORDER BY id DESC LIMIT 8").fetchall()
    lines = []
    for timestamp, raw in rows:
        try:
            if not isinstance(raw, str) or len(raw) > 32768:
                continue
            record = json.loads(raw)
            if isinstance(record, dict):
                lines.extend(_observation_lines(timestamp, record, devices))
        except (ValueError, TypeError, OverflowError):
            continue
    return lines or ["No identified device summaries yet." if devices else "No saved observations yet."]
