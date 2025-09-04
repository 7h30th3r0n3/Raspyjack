"""Lightweight topic-based event bus for plugins.

Features:
  - subscribe(pattern, handler, *, once=False) where pattern supports fnmatch wildcards (*, ?, [seq]).
  - emit(topic, **data) dispatches to all matching handlers.
  - unsubscribe(handler) or unsubscribe_pattern(pattern).
  - Thread-safe (RLock) and minimal overhead.
  - Handlers signature: handler(topic: str, data: dict)
  - Wildcard examples:
       system.* matches system.start, system.shutdown
       *.updated matches battery.updated, wifi.updated
       battery.*.warn matches battery.low.warn (multi-segment)

Ordering: subscription order.

Errors in handlers are caught and logged (print) so they do not break emit chain.
"""
from __future__ import annotations
import fnmatch
import threading
import time
from collections import deque
from typing import Callable, List, Tuple, Deque, Dict, Any

Handler = Callable[[str, dict], None]

class EventBus:
    def __init__(self):
        self._lock = threading.RLock()
        # list of tuples (pattern, handler, once)
        self._subs: List[Tuple[str, Handler, bool]] = []
        # Keep a bounded history of recent emitted events for diagnostics
        self._history: Deque[Dict[str, Any]] = deque(maxlen=200)

    # ------------------------------------------------------------------
    def subscribe(self, pattern: str, handler: Handler, *, once: bool = False) -> None:
        with self._lock:
            self._subs.append((pattern, handler, once))

    def once(self, pattern: str, handler: Handler) -> None:
        self.subscribe(pattern, handler, once=True)

    def unsubscribe(self, handler: Handler) -> None:
        with self._lock:
            self._subs = [s for s in self._subs if s[1] is not handler]

    def unsubscribe_pattern(self, pattern: str) -> None:
        with self._lock:
            self._subs = [s for s in self._subs if s[0] != pattern]

    # ------------------------------------------------------------------
    def emit(self, topic: str, **data) -> None:
        # Snapshot first for minimal lock time
        with self._lock:
            matches = [(idx, s) for idx, s in enumerate(self._subs) if fnmatch.fnmatch(topic, s[0])]
            # Record history entry (store shallow data summary to keep size small)
            try:
                self._history.append({
                    'ts': time.time(),
                    'topic': topic,
                    'keys': list(data.keys()),
                    'match_count': len(matches)
                })
            except Exception:
                pass
        # Call outside lock to avoid deadlocks / reentrancy problems
        to_remove_indices: List[int] = []
        for idx, (pattern, handler, once) in matches:
            try:
                handler(topic, data)
            except Exception as e:
                print(f"[EventBus] handler error for '{topic}' ({pattern}): {e}")
            if once:
                to_remove_indices.append(idx)
        if to_remove_indices:
            with self._lock:
                # Remove from the end backwards to keep indices valid
                for idx in sorted(to_remove_indices, reverse=True):
                    if 0 <= idx < len(self._subs):
                        self._subs.pop(idx)

    # ------------------------------------------------------------------
    def clear(self) -> None:
        with self._lock:
            self._subs.clear()
            self._history.clear()

    # Introspection helpers --------------------------------------
    def list_subscriptions(self) -> List[Tuple[str, bool]]:
        """Return list of (pattern, once_flag) for current subscriptions."""
        with self._lock:
            return [(p, once) for (p, _h, once) in self._subs]

    def get_history(self) -> List[Dict[str, Any]]:
        """Return a snapshot list of recent emit history entries (most recent last)."""
        with self._lock:
            return list(self._history)

__all__ = ["EventBus"]
