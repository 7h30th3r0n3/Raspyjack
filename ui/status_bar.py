#!/usr/bin/env python3
"""Status bar utilities for Raspyjack UI.

Provides the `StatusBar` class which manages a short activity text and a
temporary (TTL-based) message rendered in the top 12px band of the display.
Thread-safe: internal state is protected by a lock so background update and
render threads can interact safely.
"""
from __future__ import annotations

import time
import threading
from typing import Optional, Any

class StatusBar:
    """Activity and temporary status management.

    Responsibilities:
    - Maintain a persistent activity string (e.g. current operation)
    - Maintain an optional temporary message with TTL (overrides activity)
    - Provide a simple `render` method to draw on a Pillow `ImageDraw` object
    - Offer `is_busy` to let plugins decide whether to display extra adornments
    """
    __slots__ = ("_activity", "_temp_msg", "_temp_expires", "_lock", "_hidden")

    def __init__(self) -> None:
        self._activity: str = ""
        self._temp_msg: str = ""
        self._temp_expires: float = 0.0
        self._lock = threading.Lock()
        self._hidden = False

    # ---- Activity status -------------------------------------------------
    def set_activity(self, new_value: Optional[str]) -> None:
        if new_value is None:
            return
        with self._lock:
            if new_value != self._activity:
                self._activity = new_value

    def get_activity(self) -> str:
        with self._lock:
            return self._activity

    # ---- Temporary status ------------------------------------------------
    def set_temp_status(self, message: str, ttl: float = 3.0) -> None:
        if not message:
            return
        ttl = max(0.5, ttl)
        expires = time.time() + ttl
        with self._lock:
            self._temp_msg = message
            self._temp_expires = expires

    # ---- Composition -----------------------------------------------------
    def get_status_msg(self) -> str:
        now = time.time()
        with self._lock:
            if self._hidden:
                return ""
            if self._temp_msg and now < self._temp_expires:
                return self._temp_msg
            if self._temp_msg and now >= self._temp_expires:
                # Clear expired temporary message
                self._temp_msg = ""
            return self._activity

    # ---- Rendering -------------------------------------------------------
    def render(self, draw_obj: Any, font_obj: Any) -> None:
        """Render the top status bar onto the provided draw object.

        draw_obj: PIL.ImageDraw.Draw
        font_obj: PIL.ImageFont.FreeTypeFont (or any object with getbbox / getsize)
        """
        try:
            # Always draw bar background if not hidden (get_status_msg handles hidden state)
            if self.is_hidden():
                return
            draw_obj.rectangle((0, 0, 128, 12), fill="#000000")
            status_txt = self.get_status_msg()  # Will be empty string if no message
            if status_txt:
                try:
                    status_width = font_obj.getbbox(status_txt)[2]
                except AttributeError:
                    status_width = font_obj.getsize(status_txt)[0]
                draw_obj.text(((128 - status_width) / 2, 0), status_txt, fill="WHITE", font=font_obj)
        except Exception:
            # Silently ignore rendering issues to avoid crashing render loop
            pass

    # ---- Introspection ---------------------------------------------------
    def is_busy(self) -> bool:
        """True if any (temp or activity) message is currently displayed."""
        return bool(self.get_status_msg())

    # ---- Visibility control ---------------------------------------------
    def hide(self):
        with self._lock:
            self._hidden = True

    def show(self):
        with self._lock:
            self._hidden = False

    def is_hidden(self) -> bool:
        with self._lock:
            return self._hidden

__all__ = ["StatusBar"]
