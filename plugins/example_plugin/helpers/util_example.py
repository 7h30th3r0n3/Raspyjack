"""Helper utilities for Example Plugin.

You can put any support functions or classes here. The plugin implementation
can import them with:

    from .helpers.util_example import some_helper

Keeping helpers separate avoids cluttering the main plugin logic.
"""
from __future__ import annotations


def format_status(flag: bool) -> str:
    """Return a human-friendly ON/OFF string."""
    return "ON" if flag else "OFF"
