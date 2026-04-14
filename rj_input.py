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
    {"type":"text_key","session_id":"...","key":"a"}
    {"type":"text_key","session_id":"...","special":"BACKSPACE|ENTER|ESCAPE"}

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
_text_q: "queue.Queue[dict]" = queue.Queue()
_held: set = set()  # currently held buttons (for continuous input like games)
_held_lock = threading.Lock()
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
        msg_type = str(msg.get("type", ""))
        if msg_type == "input":
            button = str(msg.get("button", ""))
            state = str(msg.get("state", ""))
            mapped = _BTN_MAP.get(button)
            if not mapped:
                continue
            print(f"[rj_input] {button} {state} -> {mapped}")
            if state == "press":
                try:
                    _q.put_nowait(mapped)
                except Exception:
                    pass
                with _held_lock:
                    _held.add(mapped)
            elif state == "release":
                with _held_lock:
                    _held.discard(mapped)
            continue
        if msg_type == "text_key":
            event = {
                "type": "text_key",
                "session_id": str(msg.get("session_id", "")),
            }
            if msg.get("special"):
                event["special"] = str(msg.get("special", ""))
            else:
                event["key"] = str(msg.get("key", ""))
            print(f"[rj_input:text] session={event.get('session_id','')} key={event.get('key','')} special={event.get('special','')}")
            try:
                _text_q.put_nowait(event)
            except Exception:
                pass
            continue


def get_virtual_button() -> Optional[str]:
    """Return next virtual button name (e.g. 'KEY_LEFT_PIN') or None."""
    try:
        return _q.get_nowait()
    except queue.Empty:
        return None


def get_held_buttons() -> set:
    """Return set of currently held button names (for continuous input)."""
    with _held_lock:
        return set(_held)


def get_text_event() -> Optional[dict]:
    """Return next queued remote text event or None."""
    try:
        return _text_q.get_nowait()
    except queue.Empty:
        return None


def flush_text_events():
    """Clear queued remote text events."""
    try:
        while not _text_q.empty():
            _text_q.get_nowait()
    except Exception:
        pass


def flush():
    """Clear all queued and held button state."""
    with _held_lock:
        _held.clear()
    try:
        while not _q.empty():
            _q.get_nowait()
    except Exception:
        pass
    flush_text_events()


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
