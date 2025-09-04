#!/usr/bin/env python3
"""Unified frame buffer abstraction to hide locking and image persistence.

Menus and widgets obtain a working frame (copy or in-place) and then commit,
without dealing with explicit locks or manual image copies.
"""
from __future__ import annotations
from typing import Tuple
from threading import RLock
from PIL import Image, ImageDraw

class FrameBuffer:
    def __init__(self):
        self._lock = RLock()
        self._base: Image.Image | None = None

    def init(self, base: Image.Image):
        """Initialize with the base image allocated by the main application."""
        self._base = base

    def begin(self, clone: bool = True) -> Tuple[Image.Image, ImageDraw.ImageDraw]:
        """Acquire a working frame.
        If clone=True, returns a copy to draw; commit will merge it.
        The lock remains held until commit() is called.
        """
        self._lock.acquire()
        if self._base is None:
            # Create empty fallback
            self._base = Image.new("RGB", (128, 128), "BLACK")
        working = self._base.copy() if clone else self._base
        return working, ImageDraw.Draw(working)

    def commit(self, working: Image.Image, persist: bool = True):
        """Persist changes (optionally) and release the lock."""
        try:
            if persist and working is not self._base and self._base is not None:
                # Copy whole working content onto base
                self._base.paste(working)
        finally:
            self._lock.release()

    def snapshot(self) -> Image.Image:
        """Thread-safe copy of the current base frame for the render loop."""
        with self._lock:
            if self._base is None:
                self._base = Image.new("RGB", (128, 128), "BLACK")
            return self._base.copy()

    def lock(self):
        return self._lock

# Simple singleton instance
fb = FrameBuffer()
