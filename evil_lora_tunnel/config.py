"""Private, validated configuration for Evil-LORA-Tunnel."""

import copy
import json
import os
from pathlib import Path
import stat
import tempfile


MAX_CONFIG_BYTES = 32768
DEFAULTS = {
    "region": "", "mode": "meshtastic", "backend": "cap",
    "serial_device": "", "last_session": "",
    "uploads": {
        "wigle": {"enabled": False, "auto": False, "donate": False,
                  "api_name": "", "api_token": ""},
        "wardrift": {"enabled": False, "auto": False, "api_key": ""},
        "wdgwars": {"enabled": False, "auto": False, "api_key": ""},
    },
}
SECRET_KEYS = frozenset({
    "uploads.wigle.api_name", "uploads.wigle.api_token",
    "uploads.wardrift.api_key", "uploads.wdgwars.api_key",
})


class ConfigError(ValueError):
    """An error message that does not contain configuration values."""


def config_path():
    override = os.environ.get("EVIL_LORA_TUNNEL_CONFIG")
    return Path(override).expanduser() if override else Path.home().resolve() / ".config/evil-lora-tunnel/config.json"


def _leaves(value, prefix=""):
    for key, item in value.items():
        name = prefix + key
        if isinstance(item, dict):
            yield from _leaves(item, name + ".")
        else:
            yield name, item


ALLOWED = dict(_leaves(DEFAULTS))


def _validate_value(key, value):
    if key not in ALLOWED:
        raise ConfigError("Unknown configuration field")
    if type(ALLOWED[key]) is bool:
        if type(value) is not bool:
            raise ConfigError("This configuration field requires true or false")
        return value
    if not isinstance(value, str):
        raise ConfigError("This configuration field requires text")
    if len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConfigError("Configuration text contains unsupported characters or is too long")
    if key in SECRET_KEYS and (len(value) > 512 or any(ord(char) < 33 or ord(char) > 126 for char in value)):
        raise ConfigError("Credentials must be at most 512 printable ASCII characters without spaces")
    choices = {"region": {"", "US", "EU_868", "ANZ"},
               "mode": {"meshtastic", "meshcore", "both"},
               "backend": {"cap", "lorapipe"}}
    if key in choices and value not in choices[key]:
        raise ConfigError("Unsupported configuration choice")
    if key == "serial_device" and value:
        if not value.startswith("/dev/") or ".." in Path(value).parts:
            raise ConfigError("Serial device must be an absolute path under /dev")
    if key == "last_session" and value and not Path(value).is_absolute():
        raise ConfigError("Session path must be absolute")
    return value


def _put(config, key, value):
    parts = key.split(".")
    node = config
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value


def _safe_path(path):
    path = Path(path).expanduser().absolute()
    if any(candidate.is_symlink() for candidate in (path, *path.parents)):
        raise ConfigError("Configuration paths must not contain symbolic links")
    return path


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("Duplicate configuration field")
        result[key] = value
    return result


def load(path=None):
    """Load a private file without printing or returning a shared mutable default."""
    path = _safe_path(path if path is not None else config_path())
    result = copy.deepcopy(DEFAULTS)
    if not path.exists():
        return result
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ConfigError("Configuration must be a regular file")
            if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
                raise ConfigError("Configuration permissions must be 0600")
            raw = source.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ConfigError("Configuration file is too large")
        stored = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError("Cannot read valid private configuration") from exc
    if not isinstance(stored, dict):
        raise ConfigError("Configuration must contain an object")

    def merge(node, expected, prefix=""):
        for key, value in node.items():
            if key not in expected:
                raise ConfigError("Unknown configuration field")
            name = prefix + key
            if isinstance(expected[key], dict):
                if not isinstance(value, dict):
                    raise ConfigError("Invalid configuration section")
                merge(value, expected[key], name + ".")
            else:
                _put(result, name, _validate_value(name, value))
    merge(stored, DEFAULTS)
    return result


def get_value(key, path=None):
    if key not in ALLOWED:
        raise ConfigError("Unknown configuration field")
    if key in SECRET_KEYS:
        raise ConfigError("Credential values cannot be displayed")
    node = load(path)
    for part in key.split("."):
        node = node[part]
    return node


def parse_value(key, text):
    """Parse CLI booleans explicitly rather than treating nonempty text as true."""
    if key not in ALLOWED:
        raise ConfigError("Unknown configuration field")
    if type(ALLOWED[key]) is bool:
        if text not in {"true", "false"}:
            raise ConfigError("This configuration field requires true or false")
        return text == "true"
    return _validate_value(key, text)


def set_value(key, value, path=None):
    value = _validate_value(key, value)
    path = _safe_path(path if path is not None else config_path())
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            import fcntl
            # Lock the stable directory inode, since the JSON file is replaced.
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fcntl.flock(directory, fcntl.LOCK_EX)
                _save_value(key, value, path)
            finally:
                os.close(directory)
        else:
            _save_value(key, value, path)
    except OSError as exc:
        raise ConfigError("Cannot save private configuration") from exc


def _save_value(key, value, path):
    data = load(path)
    _put(data, key, value)
    encoded = (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ConfigError("Configuration file is too large")
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=str(path.parent))
        with os.fdopen(fd, "wb") as target:
            if os.name != "nt":
                os.fchmod(target.fileno(), 0o600)
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
        _safe_path(path)
        os.replace(temporary, path)
        temporary = None
        if os.name != "nt":
            directory = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as exc:
        raise ConfigError("Cannot save private configuration") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
