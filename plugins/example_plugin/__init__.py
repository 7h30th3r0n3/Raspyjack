"""Example plugin package initializer.

Expose the plugin instance (named `plugin`) so the PluginManager can find it.
You can also expose a subclass of Plugin instead, but using an instance keeps
state predictable.
"""
from ._impl import plugin  # noqa: F401
