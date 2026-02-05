#!/usr/bin/env python3
"""
RaspyJack input bridge
----------------------
Listens on a Unix datagram socket for JSON input events coming from the
WebSocket server and exposes a tiny queue API so the main UI can treat them
like real button presses.

Environment:
  RJ_INPUT_SOCK  Path to AF_UNIX datagram socket (default: /dev/shm/rj_input.sock)

Protocol (JSON, one datagram per message):
  {"type":"input","button":"UP|DOWN|LEFT|RIGHT|OK|KEY1|KEY2|KEY3","state":"press|release"}

Only "press" events are queued; "release" is ignored for simple navigation.
"""

import os, json, threading, socket, queue, atexit
from typing import Optional

_SOCK_PATH = os.environ.get("RJ_INPUT_SOCK", "/dev/shm/rj_input.sock")

# Map frontend button names to RaspyJack getButton() return values
_BTN_MAP = {
    "UP": "KEY_UP_PIN",
    "DOWN": "KEY_DOWN_PIN",
    "LEFT": "KEY_LEFT_PIN",
    "RIGHT": "KEY_RIGHT_PIN",
    "OK": "KEY_PRESS_PIN",
    "KEY1": "KEY1_PIN",
    "KEY2": "KEY2_PIN",
    "KEY3": "KEY3_PIN",
}

_q: "queue.Queue[str]" = queue.Queue()
_sock: Optional[socket.socket] = None
_listener_thread: Optional[threading.Thread] = None


def _cleanup():
    global _sock
    try:
        if _sock is not None:
            _sock.close()
    except Exception:
        pass
    try:
        if os.path.exists(_SOCK_PATH):
            os.unlink(_SOCK_PATH)
    except Exception:
        pass
    _sock = None


def _listen():
    global _sock
    # Ensure no stale socket file remains
    try:
        if os.path.exists(_SOCK_PATH):
            os.unlink(_SOCK_PATH)
    except Exception:
        pass

    _sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    # Allow other processes to send without special perms
    _sock.bind(_SOCK_PATH)
    try:
        os.chmod(_SOCK_PATH, 0o666)
    except Exception:
        pass

    while True:
        try:
            data, _addr = _sock.recvfrom(4096)
        except Exception:
            # Socket closed or transient error → exit thread
            break
        try:
            msg = json.loads(data.decode("utf-8", "ignore"))
        except Exception:
            continue
        if msg.get("type") != "input":
            continue
        button = str(msg.get("button", ""))
        state = str(msg.get("state", ""))
        if state != "press":
            continue
        mapped = _BTN_MAP.get(button)
        if mapped:
            try:
                _q.put_nowait(mapped)
            except Exception:
                pass


def get_virtual_button() -> Optional[str]:
    """Return next virtual button name (e.g. 'KEY_LEFT_PIN') or None."""
    try:
        return _q.get_nowait()
    except queue.Empty:
        return None


def _ensure_started():
    global _listener_thread
    if _listener_thread is None or not _listener_thread.is_alive():
        _listener_thread = threading.Thread(target=_listen, daemon=True)
        _listener_thread.start()


def restart_listener():
    """
    Recreate the Unix socket listener.
    Call this after external processes may have removed the socket file.
    """
    global _listener_thread
    _cleanup()
    _listener_thread = None
    _ensure_started()


# Start on import and register cleanup
_ensure_started()
atexit.register(_cleanup)
