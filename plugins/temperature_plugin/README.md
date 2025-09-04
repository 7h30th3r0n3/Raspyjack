# Temperature Plugin

Displays the CPU temperature as a lightweight HUD overlay and emits structured events for automation or alerting. Supports configurable polling interval, colorized thresholds, alignment & horizontal offset, and interactive menu helpers to adjust positioning at runtime.

## Features
- Periodic CPU temperature polling (configurable interval)
- Overlay rendering with optional unit display (°C)
- Colorized output (white / yellow / red) based on warn & critical thresholds
- Alignment options: left / center / right + pixel offset
- Threshold events with hysteresis to reduce flapping
- Interactive menu actions: cycle alignment, set offset
- Persistent option storage (alignment / offset retained across restarts)
- Structured event emissions for automation (Discord hooks, logging, etc.)

## Emitted Events
| Event | When | Payload Fields |
|-------|------|----------------|
| `temperature.updated` | Every successful polling cycle | `value`, `ts` |
| `temperature.sensor.error` | Sensor file not found at startup | `path` |
| `temperature.read.failed` | Read exception after successful init | `error`, `ts` |
| `temperature.threshold.warn` | Crossed warn threshold (enter) | `value`, `threshold` |
| `temperature.threshold.critical` | Crossed critical threshold (enter) | `value`, `threshold` |
| `temperature.threshold.warn.cleared` | Fell back below warn (with hysteresis) | `value`, `threshold` |
| `temperature.threshold.critical.cleared` | Fell back below critical (with hysteresis) | `value`, `threshold` |

### Notes on Threshold Logic
- `warn_threshold` < `critical_threshold` (plugin auto-adjusts if misconfigured).
- Hysteresis: warn clears at `(warn_threshold - 2)`, critical clears at `(critical_threshold - 2)`.
- Warn event suppressed if temperature jumps directly into critical range (avoids double notification).

## Configuration Schema (plugin.json)
```jsonc
{
  "enable_display": { "type": "boolean", "default": true },
  "refresh_interval": { "type": "number", "default": 2.0 },
  "colorize": { "type": "boolean", "default": true },
  "show_unit": { "type": "boolean", "default": true },
  "warn_threshold": { "type": "number", "default": 55.0 },
  "critical_threshold": { "type": "number", "default": 70.0 },
  "temp_align": { "type": "string", "default": "left" },
  "temp_offset": { "type": "number", "default": 0 }
}
```

## Overlay Behavior
| Option | Effect |
|--------|--------|
| `enable_display` | Master switch for rendering |
| `show_unit` | Append °C to value |
| `colorize` | Apply color based on thresholds |
| `temp_align` | Horizontal anchor (left / center / right) |
| `temp_offset` | Pixel shift applied after alignment (can be negative) |

Color mapping when `colorize=true`:
- Normal (< warn): white
- Warn (≥ warn & < critical): yellow
- Critical (≥ critical): red

## Menu Actions
| Label | Action |
|-------|--------|
| `Temp Align` | Cycles alignment (left → center → right) and persists selection |
| `Temp Offset` | Opens numeric picker to set horizontal offset (-40 .. 40) |

## Example Event Subscription
```python
pm = context['plugin_manager']
pm.subscribe_event('temperature.*', lambda evt, data: print(evt, data))
```

## Automation Ideas
| Goal | Approach |
|------|----------|
| Discord alert on critical | Add an event hook rule for `temperature.threshold.critical` |
| Adaptive cooling script | Subscribe to `temperature.updated` and drive a GPIO fan |
| Logging | Append events to a CSV in a lightweight background task |

## Failure Handling
| Scenario | Behavior |
|----------|----------|
| Sensor file missing | Emits `temperature.sensor.error` and disables overlay |
| Read error mid-run | Emits `temperature.read.failed`, temperature resets to 0.0 for that cycle |

## Info Panel Output
Selecting the plugin in the UI shows current temperature, configuration, thresholds, alignment, offset, and last poll timestamp.

## Performance Notes
- Polling is lightweight (single file read under `/sys/class/thermal/`)
- Rendering draws a single short text string; negligible impact on frame time

---
Log prefix: `[Temperature]`
Events prefix: `temperature.`
