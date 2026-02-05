"""High-level button event manager.

Quick usage:
    from input_events import init_button_events, get_button_event
    mgr = init_button_events(gpio_config.pins, _stop_evt, plugin_dispatch=_plugin_manager.dispatch_button_event)
    # In a loop or thread:
    evt = get_button_event(timeout=0.1)
    if evt:
        print(evt['type'], evt['button'])

Plugins:
    Implement optional on_button_event(self, event: dict) to receive:
        event = { 'type': 'LONG_PRESS', 'button': 'KEY_UP_PIN', 'ts': 123.45, 'count': 2 (optional) }

Event types:
    PRESS, RELEASE, CLICK, DOUBLE_CLICK, LONG_PRESS, REPEAT
"""

import time
import threading
from collections import deque
from typing import Deque, Dict, Optional, Callable, Any

try:
    import RPi.GPIO as GPIO  # type: ignore
except Exception:
    class GPIO:  # type: ignore
        BCM = None
        PUD_UP = None
        @staticmethod
        def setmode(mode):
            pass
        @staticmethod
        def setup(pin, mode, pull_up_down=None):
            pass
        @staticmethod
        def input(pin):
            return 1

# Event type constants
PRESS = "PRESS"
RELEASE = "RELEASE"
CLICK = "CLICK"
DOUBLE_CLICK = "DOUBLE_CLICK"
LONG_PRESS = "LONG_PRESS"
REPEAT = "REPEAT"

# Timing configuration (seconds)
DEBOUNCE = 0.04
LONG_PRESS_TIME = 0.80
MULTI_PRESS_WINDOW = 0.30
REPEAT_INITIAL_DELAY = 0.50
REPEAT_INTERVAL = 0.15

class ButtonEventManager:
    """Polls GPIO buttons and produces high-level events.

    Events generated (dict):
        {"type": TYPE, "button": NAME, "ts": monotonic_timestamp, "count": N(optional)}

    Types:
        PRESS, RELEASE, CLICK, DOUBLE_CLICK, LONG_PRESS, REPEAT

    Design:
      - PRESS emitted immediately on edge down.
      - RELEASE emitted on edge up.
      - CLICK/DOUBLE/TRIPLE consolidated after MULTI_PRESS_WINDOW expires while button is released.
      - LONG_PRESS emitted once when held LONG_PRESS_TIME (suppresses later CLICK aggregation).
      - REPEAT emitted periodically after REPEAT_INITIAL_DELAY while held (even after LONG_PRESS by default).
    """
    def __init__(self, gpio_pins: Dict[str, int], stop_event: threading.Event, plugin_dispatch: Optional[Callable[[dict], None]] = None):
        self.pins = gpio_pins
        self.stop_event = stop_event
        self.plugin_dispatch = plugin_dispatch
        self.events: Deque[dict] = deque(maxlen=256)
        self._data: Dict[str, Dict[str, Any]] = {}
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        now = time.monotonic()
        for name, pin in self.pins.items():
            try:
                lvl = GPIO.input(pin)
            except Exception:
                lvl = 1
            self._data[name] = {
                "level": lvl,
                "last_change": now,
                "press_time": None,
                "long_emitted": False,
                "repeat_next": None,
                "click_count": 0,
                "multi_deadline": None,
            }
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def get_event(self, timeout: Optional[float] = None) -> Optional[dict]:
        """Blocking (with timeout) or non-blocking retrieval of next event."""
        end = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                if self.events:
                    return self.events.popleft()
            if timeout is not None and time.monotonic() >= end:
                return None
            time.sleep(0.01)

    def poll(self) -> Optional[dict]:
        """Non-blocking poll."""
        with self._lock:
            if self.events:
                return self.events.popleft()
        return None

    def _emit(self, etype: str, button: str, **extra) -> None:
        evt = {"type": etype, "button": button, "ts": time.monotonic()}
        if extra:
            evt.update(extra)
        with self._lock:
            self.events.append(evt)
        if self.plugin_dispatch:
            try:
                self.plugin_dispatch(evt)
            except Exception:
                pass

    def _run(self) -> None:
        SLEEP = 0.005
        while not self.stop_event.is_set():
            now = time.monotonic()
            for name, pin in self.pins.items():
                data = self._data[name]
                try:
                    lvl = GPIO.input(pin)
                except Exception:
                    lvl = data["level"]
                prev = data["level"]
                if lvl != prev:  # edge
                    data["level"] = lvl
                    data["last_change"] = now
                    if lvl == 0:  # pressed (active low)
                        # debounce edge
                        if now - prev >= 0:  # redundant guard
                            data["press_time"] = now
                            data["long_emitted"] = False
                            data["click_count"] += 1
                            if data["click_count"] == 1:
                                data["multi_deadline"] = now + MULTI_PRESS_WINDOW
                            self._emit(PRESS, name)
                            data["repeat_next"] = now + REPEAT_INITIAL_DELAY
                    else:  # released
                        self._emit(RELEASE, name)
                        if data["long_emitted"]:
                            # Long press cancels click classification
                            data["click_count"] = 0
                            data["multi_deadline"] = None
                else:
                    if lvl == 0:  # still pressed
                        pt = data["press_time"]
                        if pt and not data["long_emitted"] and (now - pt) >= LONG_PRESS_TIME:
                            data["long_emitted"] = True
                            self._emit(LONG_PRESS, name)
                        rn = data["repeat_next"]
                        if rn and now >= rn:
                            self._emit(REPEAT, name)
                            data["repeat_next"] = now + REPEAT_INTERVAL
                    else:  # released state, check multi-click window
                        md = data["multi_deadline"]
                        if md and now >= md and data["click_count"] > 0:
                            cc = data["click_count"]
                            if cc == 1:
                                self._emit(CLICK, name, count=1)
                            elif cc == 2:
                                self._emit(DOUBLE_CLICK, name, count=2)
                            data["click_count"] = 0
                            data["multi_deadline"] = None
            time.sleep(SLEEP)

# Convenience singleton pattern (optional usage):
_manager: Optional[ButtonEventManager] = None

def init_button_events(gpio_pins: Dict[str, int], stop_event: threading.Event, plugin_dispatch: Optional[Callable[[dict], None]] = None):
    global _manager
    if _manager is None:
        _manager = ButtonEventManager(gpio_pins, stop_event, plugin_dispatch)
        _manager.start()
    return _manager

def get_button_event(timeout: Optional[float] = None) -> Optional[dict]:
    if _manager is None:
        return None
    return _manager.get_event(timeout=timeout)

def poll_button_event() -> Optional[dict]:
    if _manager is None:
        return None
    return _manager.poll()

def clear_button_events() -> None:
    """Drain all pending button events from the queue."""
    while True:
        evt = poll_button_event()
        if not evt:
            break
