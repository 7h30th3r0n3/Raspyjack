# Battery Status Plugin

Provides real‑time battery monitoring and an overlay (icon + percentage) using an INA219 current/voltage sensor. Implements adaptive polling, dynamic voltage→percentage mapping and emits structured events for automation or UI integration.

## Features
- INA219 sensor integration (bus voltage, current, power, shunt voltage)
- Smart voltage→percentage curve built from configurable `voltage_min` / `voltage_max`
- Exponential smoothing + stability tracking
- Adaptive polling rate (slows when battery stable/high, speeds up when low/critical)
- Overlay rendering:
  - Optional percentage text
  - Optional battery icon (with fill proportional to charge)
  - Color + blink logic for warning / critical (if `colorize` enabled)
- Configurable alignment (left / center / right) + pixel offset
- Emits lifecycle & threshold events
- Graceful degradation if I2C / sensor not present

## Requirements
| Component | Purpose |
|-----------|---------|
| INA219 sensor | Measures bus & shunt voltage, current, power |
| I2C enabled on system | Required to communicate with INA219 |
| `smbus` / `smbus2` Python lib | Access I2C bus (plugin tolerates absence) |

If the sensor cannot be initialized, the plugin disables itself and emits `battery.sensor_error`.

## Emitted Events
| Event | Trigger | Payload Fields |
|-------|---------|----------------|
| `battery.updated` | Percentage changed (≥1% delta) | `percent`, `voltage`, `current`, `power`, `samples_ok`, `errors` |
| `battery.low` | First time percent ≤ `warn_threshold` (and > `crit_threshold`) | `percent`, `threshold` |
| `battery.critical` | First time percent ≤ `crit_threshold` | `percent`, `threshold` |
| `battery.recovered` | Percent rises back above `warn_threshold` after low/critical | `percent`, `from_state` ("low"|"critical") |
| `battery.charging` | Transition to charging (current > ~5mA) | `percent`, `voltage`, `current` |
| `battery.discharging` | Transition to discharging (current ≤ ~5mA) | `percent`, `voltage`, `current` |
| `battery.sensor_error` | I2C init or read error (first or periodic) | `error` |

> Threshold events are only emitted on state transitions to avoid spam.

## Configuration Schema
(Defined in `plugin.json`)
```jsonc
{
  "show_percentage": { "type": "boolean", "default": true },
  "show_icon": { "type": "boolean", "default": true },
  "enable_monitoring": { "type": "boolean", "default": true },
  "i2c_bus": { "type": "number", "default": 1 },
  "address": { "type": "number", "default": 67 },           // 67 decimal = 0x43
  "refresh_interval": { "type": "number", "default": 2.0 },
  "voltage_min": { "type": "number", "default": 3.0 },       // 0% reference
  "voltage_max": { "type": "number", "default": 4.2 },       // 100% reference
  "warn_threshold": { "type": "number", "default": 25 },
  "crit_threshold": { "type": "number", "default": 10 },
  "colorize": { "type": "boolean", "default": true },
  "battery_align": { "type": "string", "default": "right" },
  "battery_offset": { "type": "number", "default": 0 }
}
```

## Voltage → Percentage Mapping
A dynamic table is constructed at startup:
- Top voltage = `voltage_max` (≥ `voltage_min + 0.25` enforced)
- Key plateau points (100, 90, 80, ... 10%) shaped with a mild curve to approximate Li‑ion discharge
- Tail (7, 5, 4, 3, 2, 1, 0%) interpolated down to `voltage_min`
- Linear interpolation is applied between adjacent table points at runtime

If table generation fails, a minimal fallback is used: `(4.20→100, 3.90→70, 3.74→20, voltage_min→0)`.

## Adaptive Polling Strategy
| Condition | Interval Multiplicator |
|-----------|------------------------|
| Stable ≥80% (≥5 stable cycles) | ×4 base interval |
| Stable ≥60% (≥3 stable cycles) | ×2 base interval |
| ≤ critical threshold | ×0.5 (min 0.5s) |
| ≤ warn threshold | ×0.75 (min 1.0s) |
| Default | ×1 |

A cycle is considered "stable" if the rounded percentage changes < 0.5% between emissions.

## Overlay Rendering
Elements are drawn only if monitoring enabled and either icon or percentage are active.

| Option | Effect |
|--------|--------|
| `show_percentage` | Draw XX% text (monospaced layout assumption) |
| `show_icon` | Draw battery outline + terminal nub + fill |
| `colorize` | Changes color based on thresholds; may blink when critical |
| `battery_align` | Horizontal positioning (left / center / right) |
| `battery_offset` | Horizontal pixel shift after alignment |

## Failure & Degradation Handling
| Situation | Behavior |
|-----------|----------|
| Missing sensor / smbus | Plugin disables monitoring, emits `battery.sensor_error` |
| Repeated read errors | Printed every 10th occurrence (rate-limited) |
| Invalid voltage range | Top adjusted to ensure span ≥0.25V |

## Example Event Subscription
```python
pm = context['plugin_manager']  # if accessible
pm.subscribe_event('battery.*', lambda evt, data: print(evt, data))
```

## Troubleshooting
| Symptom | Cause | Resolution |
|---------|-------|-----------|
| Always 0% | `voltage_min` too high | Lower `voltage_min` (e.g. 3.0) |
| Rapid flicker | Very small span or unstable sensor | Increase `refresh_interval` or smooth externally |
| No icon displayed | `show_icon` disabled or overlay blocked | Enable, ensure no UI conflicts |
| No updates | `enable_monitoring` false or sensor error | Re-enable / check I2C wiring |

---
Log prefix: `[BatteryStatus]`
Module path: `plugins.battery_status_plugin`
