"""RaspyJack plugin package.

Drop Python modules in this directory (or subpackages) and list their module
names in gui_conf.json under the "plugins" key to have them auto‑loaded at
startup.

Each plugin should expose either:
  - a global variable `plugin` containing an instance of a subclass of Plugin
  - OR at least one subclass of Plugin (the first found will be instantiated)

See `example_plugin.py` for a minimal reference implementation.
"""

from .base import Plugin, PluginManager  # convenience re‑exports
