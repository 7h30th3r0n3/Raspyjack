# 🧩 Plugin System - RaspyJack

Modular plugin system for RaspyJack that allows adding functionality without modifying the main code.

## 📋 Table of Contents
- [Plugin Structure](#-plugin-structure)
- [Installation](#-installation)
- [Plugin Template](#-plugin-template)
- [Configuration](#-configuration)
- [Event Bus](#-event-bus)
- [Plugin Dependencies](#-plugin-dependencies)
- [Plugin Menu Actions](#-plugin-menu-actions)
- [Persisting Configuration Changes](#-persisting-configuration-changes)
- [Available Callbacks](#-available-callbacks)
- [Context Helpers](#-context-helpers)
- [Bin Commands](#-bin-commands)
- [Complete Examples](#-complete-examples)
- [Development](#-development)
- [Included Plugins](#-included-plugins)

---

## 📁 Plugin Structure

Each plugin is a **Python package** with standardized structure (manifest‑driven configuration):

```
plugins/
    my_plugin/
        __init__.py        # Entry point (required) – must expose `plugin`
        _impl.py           # Implementation (recommended) – logic & hooks
        plugin.json        # Manifest: name, description, priority, requires,
                                             #           events.emits/listens, config_schema, etc.
        bin/               # (Optional) Executables auto‑exposed globally
            MY_COMMAND
            OTHER_CMD
        helpers/           # (Optional) Support modules
            utils.py
            constants.py
        README.md          # (Optional) Plugin-specific docs
```

### `__init__.py` File (Required)
```python
from ._impl import plugin
```

### `_impl.py` File (Implementation)
```python
from plugins.base import Plugin

class MyPlugin(Plugin):
    def on_load(self, context):
        print(f"[{self.name}] Plugin loaded! context keys: {list(context.keys())[:5]} ...")

    def get_info(self):
        return "My custom plugin"

plugin = MyPlugin()
```

---

## 📥 Installation

There are **two ways** to add new plugins:

### 1. Manual (development) install
Place your plugin folder under `plugins/` (e.g. `plugins/my_plugin/`) with an `__init__.py` that exposes a `plugin` instance. Restart RaspyJack.

### 2. Archive auto‑install (recommended for deployment)
Drop a compressed archive into the installer directory:

```
plugins/install/
    my_plugin.zip
    toolpack.tar.gz
```

Supported archive types: `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`

On startup RaspyJack will:
1. Scan `plugins/install/` for supported archives
2. Safely extract each into a temp directory (path traversal protected)
3. Detect the first package directory containing `__init__.py`
4. Move it into `plugins/<plugin_name>/` (appends `_new`, `_new2`, etc. if name already exists)
5. Add a default config entry (disabled) to `plugins_conf.json`
6. Rename/move the archive:
     - `<name>.done` in `plugins/install/processed/` if successful
     - `<name>.invalid` if no plugin package found
     - `<name>.error` if extraction failed

Example session log excerpt:
```
[PLUGIN] Installed plugin 'status_plugin' from 'status_plugin.zip' -> status_plugin
[PLUGIN] Added new plugin 'status_plugin' to config with defaults (enabled = False)
```

After installation: enable via UI → `Plugins` → select plugin → `Enable Plugin` → `Save & Restart`.

### Packaging a plugin
From inside `plugins/` run (examples):
```bash
zip -r my_plugin.zip my_plugin
tar czf my_plugin.tar.gz my_plugin
```
Copy the archive to `plugins/install/` and restart.

---

## 🧪 Plugin Template

A fully documented reference implementation is provided in `plugins/example_plugin/`.

Template contents:
```
example_plugin/
    __init__.py          # Exposes plugin instance
    _impl.py             # All hook examples + config schema
    helpers/             # (Optional) support modules
        util_example.py
    bin/                 # (Optional) executable tools (auto-exposed to top-level bin/)
        EXAMPLE_CMD
    README.md            # Local docs (optional)
```

### Creating a new plugin from the template
1. Copy the folder:
     ```bash
     cp -r plugins/example_plugin plugins/my_new_plugin
     ```
2. Rename class `ExamplePlugin` → `MyNewPlugin` inside `_impl.py`
3. Edit `plugin.json` (fields: name, description, priority, requires, events, config_schema)
4. Define options under `config_schema` inside `plugin.json` (no Python method)
5. Remove hooks you don't need to keep it lean
6. (Optional) Add commands under `bin/` and helpers under `helpers/`
7. Restart RaspyJack → plugin auto‑discovered (disabled by default)
8. Enable in UI → `Plugins` menu

### Exposed features in template
- All lifecycle + event hooks implemented
- Example configuration schema with two boolean flags
- Demonstrates overlay drawing, tick updates, button handling
- `get_info()` output for info viewer
- Sample bin command (`EXAMPLE_CMD`)

### Recommendations when adapting
- Keep overlay output short to avoid conflicts
- Use `on_config_changed()` for recalculating cache/state
- Avoid blocking operations in hooks; spawn threads if needed
- Prefix print logs with `[YourPlugin]` for clarity

---

## ⚙️ Configuration

Configure plugins in `plugins/plugins_conf.json` (runtime merges manifest + state):

```json
{
    "my_plugin": {
        "enabled": true,
        "priority": 50,  // Optional override; manifest defines default
    "options": {
      "interval": 5,
      "text_color": "white",
      "show_details": false
    }
  },
  "discord_notifier_plugin": {
    "enabled": true,
    "priority": 200,
    "options": {
      "nmap_notifications": true
    }
  }
}
```

### Configuration Fields:
- **`enabled`**: `true/false` - Enable/disable plugin
- **`priority`**: `number` - Execution order (lower = first)
- **`options`**: `object` - Plugin-specific settings

### Plugin Configuration Schema

Plugins declare configuration options in their `plugin.json` under `config_schema`. Each option has:

```
{
    "type": "boolean" | "string" | "list" | "number",
    "label": "Short label",
    "description": "Longer help text",
    "default": <value matching type>
}
```

CURRENT UI LIMITATION:
    Only `boolean` options are rendered as toggleable items in the on-device menu.
    Non-boolean types (`string`, `list`) are still fully supported in the schema,
    auto-added to `plugins_conf.json`, and retrievable through
    `get_config_value()`, but must be edited manually in the JSON file until the
    menu gains editors for those types.

Type semantics:
    - `boolean`: True/False toggle (visible in UI)
    - `string`: Arbitrary text (edit JSON manually)
    - `list`: Typically list of strings (edit JSON manually). Example: payload names.
    - `number`: JSON number (int ou float). Ajuste via arquivo JSON.

Example manifest (multi-type config_schema):
```jsonc
{
    "name": "net_tools",
    "description": "Network helper tools",
    "priority": 120,
    "events": {
        "emits": ["net_tools.scan.started", "net_tools.scan.finished"],
        "listens": ["ethernet.connected", "wifi.connected"]
    },
    "config_schema": {
        "enable_feature": {
            "type": "boolean",
            "label": "Enable Feature",
            "description": "Turn feature on/off",
            "default": true
        },
        "interface": {
            "type": "string",
            "label": "Interface",
            "description": "Network interface to monitor (edit JSON)",
            "default": "eth0"
        },
        "connect_payloads": {
            "type": "list",
            "label": "Connect Payloads",
            "description": "Payloads to run on connect (edit JSON)",
            "default": []
        },
        "interval_secs": {
            "type": "number",
            "label": "Interval Seconds",
            "description": "Polling interval (edit JSON)",
            "default": 5
        }
    }
}
```

Legacy Python method `get_config_schema()` was removed. Define schemas only in the manifest.

### UI Integration

Configuration options automatically appear in the plugin submenu as interactive checkboxes:

- **✅ Menu Integration**: Boolean configs become CheckboxMenuItem instances
- **🔄 Real-time Updates**: Changes are immediately saved and applied
- **💾 Persistent Storage**: Settings saved to `plugins_conf.json`
- **🔔 Callbacks**: `on_config_changed()` called when values change

### Accessing Configuration in Plugin:
```python
def on_load(self, context):
    # Use get_config_value() with defaults
    self.interval = self.get_config_value("interval", 10)
    self.enabled = self.get_config_value("enable_feature", True)
    print(f"Configured interval: {self.interval}")

def on_tick(self, dt):
    # Check configuration before actions
    if not self.get_config_value("enable_feature", True):
        return  # Feature disabled
    
    # Your plugin logic here
    pass
```

---

## 🚦 Event Bus

Decoupled publish/subscribe system for intra‑plugin communication. Event names
use dotted identifiers (`domain.action`) and support wildcard subscription.

### Recommended Convenience API (inside a Plugin subclass)
```python
def on_load(self, ctx):
    # Subscribe
    self.on('ethernet.connected', self._on_eth)
    # One‑shot subscription
    self.once('wifi.connected', lambda evt, data: print('WiFi once:', data))
    # Emit custom event
    self.emit('example.started', ts=time.time())

def _on_eth(self, event_name, data):
    print('Ethernet up:', data['interface'], data.get('ip'))
```

### Wildcards
```python
self.on('ethernet.*', handler)         # all ethernet events
self.on('*.connected', handler)        # any <domain>.connected
self.on('battery.*.warn', handler)     # multi‑segment match
```

### Handler Signature
`handler(event_name: str, data: dict)` — return value ignored, exceptions logged.

### Core Example Events
- `ethernet.connected` { interface, ip }
- `ethernet.disconnected` { interface, ip=None }

Define any additional events you need; document them in your plugin manifest under `events.emits` for clarity.

---

## 🔗 Plugin Dependencies

A plugin declares dependencies in its `plugin.json` manifest (`requires` array):

```jsonc
{
    "name": "net_action_plugin",
    "priority": 210,
    "requires": ["ethernet_hook"],
    "events": { "emits": ["net.action"], "listens": ["ethernet.connected"] },
    "config_schema": {}
}
```

Dependency loading behavior:
 1. Loader makes multiple passes attempting to load enabled plugins.
 2. A plugin is only instantiated once all entries in `requires` are loaded.
 3. If after passes some dependencies remain unmet, the plugin is skipped and a log line is printed.

Best Practices:
    - Keep dependency list short and focused.
    - Emit events from dependency plugins instead of exposing internal attributes.
    - Use `get_plugin_instance(name)` only if you need direct API access.

---

## 🧷 Plugin Menu Actions

Plugins can inject custom actions into their own submenu without modifying core code.

### API
Implement `provide_menu_items(self) -> list` in your plugin class.

Return a list whose entries are any of:
1. `MenuItem` instances (preferred)
2. Tuples `(label, callable)`
3. Tuples `(label, callable, icon)` where `icon` is a Font Awesome glyph string
4. Tuples `(label, callable, icon, description)` adding a short help text

If at least one valid item is returned a separator `─ Actions ─` is inserted before them.

Called every time the Plugins menu is rebuilt, so keep it fast and side‑effect free.

### Example
```python
from plugins.base import Plugin

class NetToolsPlugin(Plugin):

    def provide_menu_items(self):
        return [
            ("Run Quick Scan", lambda: self.ctx['exec_payload']('auto_nmap_scan.py'), '\\uf002', "Shortcut to payload"),
            ("Show Status", self._show_status, '\\uf05a'),
            # Or explicit MenuItem if you need advanced args
            # MenuItem("Custom Action", lambda: ... , icon='\\uf0ad', description="Does something")
        ]

    def _show_status(self):
        sb = self.ctx.get('status_bar') if self.ctx else None
        if sb:
            sb.set_temp_status("NetTools OK", ttl=2)
```

### Notes
* Icons use the same Font Awesome font already loaded (pass raw unicode string, eg: `"\uf05a"`).
* Invalid tuple shapes are ignored safely.
* When disabled, a plugin's custom actions are not shown.

---

## 💾 Persisting Configuration Changes

Plugins sometimes need to update their configuration (e.g. after an interactive
picker). You can modify the in-memory value with `set_config_value()` but to
save it permanently to `plugins_conf.json` use the helper:

```python
self.persist_option('icon_horizontal_pos', 42)
```

### API
```python
persist_option(key: str, value: Any, create_if_missing: bool = True) -> bool
```

Behavior:
- Tries to load + update the central `plugins_conf.json` using runtime helpers.
- Returns `True` on apparent success, `False` otherwise.
- Creates the plugin entry if missing and `create_if_missing=True`.

This is preferred over re‑implementing JSON writes inside each plugin.

### Example (excerpt from Ethernet plugin)
```python
new_val = numeric_picker(wctx, label="ETH X", min_value=0, max_value=120, initial_value=current_int, step=1)
self.set_config_value('icon_horizontal_pos', new_val)      # update in memory
self.persist_option('icon_horizontal_pos', new_val)         # persist to disk
```

If you need to update multiple keys atomically, consider reading the current
config via runtime helpers and writing back once. A future helper may provide
batch persistence if needed.

---

## 🔄 Available Callbacks

All callbacks are **optional**. Implement only what you need:

### Lifecycle
```python
def on_load(self, context: dict) -> None:
    """Called once when loading the plugin"""
    self.context = context
    print("Plugin initialized!")

def on_unload(self) -> None:
    """Called when unloading (shutdown)"""
    print("Plugin finalized!")
```

### Periodic Events
```python
def on_tick(self, dt: float) -> None:
    """Called periodically (~1x per second)"""
    # IMPORTANT: Keep fast and non-blocking!
    self.counter += dt
```

### Hardware Interaction
```python
def on_button_event(self, event: dict) -> None:
    """High-level button event.
    event keys: type ('PRESS','LONG_PRESS','REPEAT','CLICK',etc.), button, ts, count(optional)
    """
    if event['type'] == 'PRESS' and event['button'] == 'KEY_UP_PIN':
        print("UP pressed (PRESS)")
    if event['type'] == 'LONG_PRESS' and event['button'] == 'KEY_UP_PIN':
        print("UP long press!")
    if event['type'] == 'DOUBLE_CLICK' and event['button'] == 'KEY_PRESS_PIN':
        print("Select double click")
```

### Rendering
```python
def on_render_overlay(self, image, draw) -> None:
    """Draw overlay on HUD"""
    # Draw only small elements (HUD)
    draw.text((100, 10), "Status: OK", fill='green')
```

### Runtime Events

Subscribe via the event bus instead of overriding methods:

| Event                | Data Keys                               | Description                         |
|----------------------|------------------------------------------|-------------------------------------|
| `payload.before_exec`| `payload_name`                           | Before a payload script runs        |
| `payload.after_exec` | `payload_name`, `success`                | After payload wrapper completes     |
| `scan.before`        | `label`, `args`                          | Before starting a scan (e.g. Nmap)  |
| `scan.after`         | `label`, `args`, `result_path`           | After scan finishes (file saved)    |

Example subscription:
```python
def on_load(self, ctx):
    self.on('payload.before_exec', self._log_before)
    self.on('scan.after', self._after_scan)

def _log_before(self, topic, data):
    print('About to run payload:', data['payload_name'])

def _after_scan(self, topic, data):
    print('Scan finished ->', data['result_path'])
```

### Information
```python
def get_info(self) -> str:
    """Return plugin status/info for UI"""
    return "Plugin working perfectly!"

def provide_menu_items(self) -> list:
    """Return optional custom menu items for this plugin's submenu.

    Return [] (or omit) for no extra actions. Accepts MenuItem objects or
    tuples (label, callable[, icon[, description]]). Called whenever plugin
    menus are rebuilt. Keep it lightweight (no blocking work)."""
    return []
```

---

## 🛠 Context Helpers

The `context` parameter in `on_load()` provides access to system functionality:

```python
def on_load(self, context):
    self.context = context
    
    # Execute payload
    self.context['exec_payload']('my_script.py')
    
    # Check system state
    if self.context['is_responder_running']():
        print("Responder is active")
    
    # Access graphical interface
    menu = self.context['get_menu']()
    status_bar = self.context['status_bar']
    status_bar.set_temp_status("Plugin active", 3)
    
    # Draw on screen
    image = self.context['draw_image']()  # PIL base Image
    draw = self.context['draw_obj']()     # PIL ImageDraw
```

### Available Context Keys:
- `exec_payload(name)` - Execute payload script
- `get_menu()` - Get current menu
- `is_responder_running()` - Responder status
- `is_mitm_running()` - MITM status
- `draw_image()` - PIL base image
- `draw_obj()` - PIL ImageDraw object
- `status_bar` - StatusBar instance
- `widget_context` - The active `WidgetContext` (pass to pickers/dialogs)

---

## 📦 Bin Commands

Plugins can expose globally executable commands:

### 1. Create Executable
```bash
# plugins/my_plugin/bin/MY_CMD
#!/usr/bin/env python3
"""My custom command"""

from plugins.my_plugin.helpers.utils import do_something

def main():
    print("Running my command!")
    do_something()

if __name__ == "__main__":
    main()
```

### 2. Automatic Exposure
When plugin is loaded, `MY_CMD` becomes available at:
- `bin/MY_CMD` (symlink or copy)
- Can be used by other payloads

### 3. Exposure Logs
```
[PLUGIN] Created symlink: bin/MY_CMD -> /path/to/plugins/my_plugin/bin/MY_CMD
```

### 4. Automatic PYTHONPATH
Scripts executed via `payload_executor.py` have automatic access to modules:
```python
# Works automatically in payloads
from plugins.my_plugin.helpers.utils import function
```

---

## 🎯 Complete Examples

### Example 1: Simple Status Plugin
```
plugins/
  status_plugin/
    __init__.py
    _impl.py
```

**`__init__.py`:**
```python
from ._impl import plugin
```

**`_impl.py`:**
```python
from plugins.base import Plugin
import time

class StatusPlugin(Plugin):  # metadata provided by plugin.json
    
    def on_load(self, context):
        self.start_time = time.time()
    
    def on_render_overlay(self, image, draw):
        uptime = int(time.time() - self.start_time)
        draw.text((0, 0), f"Uptime: {uptime}s", fill='white')
    
    def get_info(self):
        return f"Active for {int(time.time() - self.start_time)} seconds"

plugin = StatusPlugin()
```

### Example 2: Plugin with Bin Commands
```
plugins/
  tools_plugin/
    __init__.py
    _impl.py
    bin/
      SCAN_PORTS
      CHECK_HOST
    helpers/
      scanner.py
```

**`bin/SCAN_PORTS`:**
```python
#!/usr/bin/env python3
import sys
from plugins.tools_plugin.helpers.scanner import scan_host

def main():
    if len(sys.argv) < 2:
        print("Usage: SCAN_PORTS <host>")
        sys.exit(1)
    
    host = sys.argv[1]
    ports = scan_host(host)
    print(f"Open ports on {host}: {ports}")

if __name__ == "__main__":
    main()
```

**`helpers/scanner.py`:**
```python
import socket

def scan_host(host, ports=[22, 80, 443]):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports
```

### Example 3: Plugin with UI Configuration System
```
plugins/
  configurable_plugin/
    __init__.py
    _impl.py
```

**`plugin.json`:**
```jsonc
{
  "name": "ConfigurablePlugin",
  "description": "Shows how runtime reacts to manifest config_schema toggles",
  "priority": 50,
  "config_schema": {
    "enable_monitoring": {
      "type": "boolean",
      "label": "Enable Monitoring",
      "description": "Enable background monitoring",
      "default": true
    },
    "show_overlay": {
      "type": "boolean",
      "label": "Show HUD Overlay",
      "description": "Display information on screen",
      "default": true
    },
    "enable_notifications": {
      "type": "boolean",
      "label": "Enable Notifications",
      "description": "Show status notifications",
      "default": false
    }
  }
}
```

**`_impl.py`:**
```python
from plugins.base import Plugin
import time

class ConfigurablePlugin(Plugin):

    def __init__(self):
        self.counter = 0
        self.last_notify = 0
        self.context = None

    def on_load(self, context):
        self.context = context
        print(f"[{self.name}] Loaded with manifest config schema")

    def on_tick(self, dt):
        if not self.get_config_value("enable_monitoring", True):
            return
        self.counter += dt
        if self.get_config_value("enable_notifications", False):
            if time.time() - self.last_notify > 10:
                print(f"[{self.name}] Monitoring active: {self.counter:.1f}s")
                self.last_notify = time.time()

    def on_render_overlay(self, image, draw):
        if not self.get_config_value("show_overlay", True):
            return
        if self.get_config_value("enable_monitoring", True):
            draw.text((100, 20), f"Monitor: {self.counter:.1f}s", fill='yellow')

    def on_config_changed(self, key: str, old_value, new_value):
        print(f"[{self.name}] Config changed: {key} = {new_value}")
        if key == "enable_monitoring" and new_value:
            self.counter = 0

    def get_info(self):
        monitoring = self.get_config_value("enable_monitoring", True)
        overlay = self.get_config_value("show_overlay", True)
        notifications = self.get_config_value("enable_notifications", False)
        return "\n".join([
            f"Counter: {self.counter:.1f}s",
            "",
            "Configuration:",
            f"• Monitoring: {'ON' if monitoring else 'OFF'}",
            f"• HUD Overlay: {'ON' if overlay else 'OFF'}",
            f"• Notifications: {'ON' if notifications else 'OFF'}",
        ])

plugin = ConfigurablePlugin()
```

**Configuration appears automatically in menu:**
```
Plugins → ConfigurablePlugin →
  ✓ Enable Plugin
  Show Information
  ─ Configuration ─
  [X] Enable Monitoring      ← CheckboxMenuItem
  [X] Show HUD Overlay       ← CheckboxMenuItem  
  [ ] Enable Notifications   ← CheckboxMenuItem
```

### Example 4: Simplified Plugin Configurations

Current included plugins use simplified, focused configurations:

**Discord Plugin (excerpt plugin.json)**
```jsonc
{
    "name": "discord_notifier_plugin",
    "config_schema": {
        "nmap_notifications": {
            "type": "boolean",
            "label": "Nmap Notifications",
            "description": "Send Discord notifications when Nmap scans complete",
            "default": true
        }
    }
}
```

**Temperature Plugin (excerpt plugin.json)**
```jsonc
{
    "name": "temperature_plugin",
    "config_schema": {
        "enable_display": {
            "type": "boolean",
            "label": "Show Temperature HUD",
            "description": "Display temperature in corner of screen",
            "default": true
        },
        "show_unit": {
            "type": "boolean",
            "label": "Show Temperature Unit",
            "description": "Display °C unit with temperature value",
            "default": true
        }
    }
}
```

**Battery Plugin (excerpt plugin.json)**
```jsonc
{
    "name": "battery_status_plugin",
    "config_schema": {
        "show_percentage": {
            "type": "boolean",
            "label": "Show Battery Percentage",
            "description": "Display battery percentage in overlay",
            "default": true
        },
        "show_icon": {
            "type": "boolean",
            "label": "Show Battery Icon",
            "description": "Display battery status icon",
            "default": true
        },
        "enable_monitoring": {
            "type": "boolean",
            "label": "Enable Battery Monitoring",
            "description": "Monitor battery status via I2C",
            "default": true
        }
    }
}
```

---

## 🚀 Development

### Recommended Structure
1. **Separate logic**: Use `_impl.py` for implementation
2. **Organized helpers**: Group utilities in `helpers/`
3. **Useful commands**: Expose tools via `bin/`
4. **Flexible configuration**: Use `options` for customizations

### Best Practices
- ✅ **Fast callbacks**: `on_tick()` should be non-blocking
- ✅ **Error handling**: Always use try/except
- ✅ **Informative logs**: Use `print()` for debugging
- ✅ **Spaced priorities**: Use 10, 20, 30... for easy insertions
- ✅ **Default configuration**: Always provide default values
- ✅ **Configuration schema**: Define clear config schemas for UI integration
- ✅ **Boolean configs**: Use boolean types for checkbox integration
- ✅ **Descriptive labels**: Provide user-friendly labels for config options
- ✅ **Config validation**: Check config values before using them
- ✅ **Change notifications**: Implement `on_config_changed()` for immediate updates

### Configuration Guidelines
- **Use clear labels**: "Enable Feature" not "feature_enabled"
- **Provide descriptions**: Help users understand each option
- **Sensible defaults**: Plugins should work out-of-the-box
- **Check before use**: Always validate config values in callbacks
- **Handle changes**: Implement `on_config_changed()` for real-time updates

### Plugin Lifecycle with Configuration
```python
1. Plugin loaded → on_load() called
2. Config schema retrieved from plugin.json manifest
3. UI menu built with checkboxes
4. User toggles checkbox → on_toggle callback
5. Config updated and saved → set_config_value()
6. Plugin notified → on_config_changed()
7. Plugin behavior adapts immediately
```

---

## 📝 Included Plugins

Below are the bundled plugins with quick links to their dedicated documentation pages (each plugin folder contains a `README.md` with full details, events, configuration, and usage examples):

| Plugin | Description | Docs |
|--------|-------------|------|
| Battery Status | INA219 based battery monitoring (percentage, icon, thresholds, adaptive polling) | [README](./battery_status_plugin/README.md) |
| Temperature | CPU temperature overlay with thresholds, colorize, alignment & offset | [README](./temperature_plugin/README.md) |
| Screenshot | Manual + periodic framebuffer capture with event hooks | [README](./screenshot_plugin/README.md) |
| Discord Notifier | Event-driven Discord webhook notifications & automation hooks | [README](./discord_notifier_plugin/README.md) |
| Ethernet Hook | Ethernet link state detection + payload triggers + status icon | [README](./ethernet_hook/README.md) |
| Example Plugin | Fully documented reference / template implementation | [README](./example_plugin/README.md) |

### Plugin Menu Navigation

Access plugin configurations through the main menu:

1. **Main Menu** → **Plugins**
2. Select plugin (shows ✓ if enabled, ✗ if disabled)
3. **Plugin Submenu** options:
   - `Enable/Disable Plugin` - Toggle plugin activation
   - `Show Information` - View plugin status and details
   - `─ Configuration ─` - Separator for config options
   - **Checkbox Options** - Interactive boolean settings
4. **Save & Restart** - Apply changes and reload plugins

### Configuration Management

- **Real-time Updates**: Checkbox changes immediately update plugin behavior
- **Persistent Storage**: All settings saved to `plugins_conf.json`
- **Plugin Reload**: Use "Save & Restart" to apply enable/disable changes
- **Default Values**: Plugins provide sensible defaults for all options

---

**💡 Tip**: Study existing plugins in `plugins/` to see practical implementation examples!

---

*Developed for RaspyJack - Educational offensive security toolkit*