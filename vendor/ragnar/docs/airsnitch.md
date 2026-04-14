# AirSnitch — Wi-Fi Client Isolation Testing

> [!IMPORTANT]
> Only run against networks you own or have **explicit written permission** to test.

AirSnitch is a Ragnar module that verifies whether a Wi-Fi network properly enforces **client isolation** — the security feature that prevents devices on the same network from communicating directly with each other.

Based on the research tool by [Mathy Vanhoef](https://github.com/vanhoefm/airsnitch).

---

## How It Works

AirSnitch uses **two wireless interfaces** simultaneously:

- **Victim interface** (`wlan1`) — connects to the target AP as a normal client
- **Attacker interface** (`wlan2`) — connects to the same AP as a separate client and attempts to intercept or reach the victim

It then runs up to four attack tests to detect isolation bypass vulnerabilities.

---

## Requirements

### Hardware

| Component | Requirement |
|---|---|
| Victim interface | Any Wi-Fi adapter (onboard `wlan0` works) |
| Attacker interface | USB Wi-Fi adapter with **monitor mode + packet injection** support |

> The Raspberry Pi onboard Wi-Fi alone is **not** sufficient — two separate physical adapters are required.

**Recommended USB adapters:**
- Alfa AWUS036ACS (RTL8811AU)
- Alfa AWUS036ACM (MT7612U)
- TP-Link TL-WN722N v1 (AR9271)
- Any adapter with Ralink MT7601U, RT2800, or Atheros AR9271 chipset

### Software

AirSnitch is installed automatically on first use (cloned from GitHub). Build dependencies installed automatically:
- `git`, `build-essential`
- `libnl-3-dev`, `libnl-genl-3-dev`, `libnl-route-3-dev`
- `libssl-dev`, `libdbus-1-dev`

---

## Tests

### GTK Abuse
Checks whether the victim and attacker receive the **same Group Transient Key (GTK)**. If shared, the attacker can decrypt all broadcast/multicast traffic sent to the victim.

- Vulnerable if output contains: `gtk is shared`

### Gateway Bouncing
Tests whether **IP-layer client isolation** is enforced. Sends traffic from the attacker to the victim via the gateway (router) to check if the AP forwards it.

- Vulnerable if output contains: `client to client traffic at ip layer is allowed`

### Port Steal — Downlink
Tests whether the attacker can **intercept incoming (downlink) TCP traffic** destined for the victim by stealing its TCP port mapping at the AP.

- Vulnerable if output contains: `success` or `intercepted`

### Port Steal — Uplink
Tests whether the attacker can **intercept outgoing (uplink) TCP traffic** from the victim by stealing its source port before the AP forwards it.

- Vulnerable if output contains: `success` or `intercepted`

---

## Configuration

Settings are stored in `config/actions.json`:

| Key | Default | Description |
|---|---|---|
| `airsnitch_iface_victim` | `wlan1` | Wireless interface for the victim role |
| `airsnitch_iface_attacker` | `wlan2` | Wireless interface for the attacker role |
| `airsnitch_tests` | all four | Which tests to run: `gtk`, `gateway`, `port_steal_down`, `port_steal_up` |
| `airsnitch_same_bss` | `false` | Test same-BSS scenarios (victim and attacker on same AP radio) |
| `airsnitch_server` | `8.8.8.8` | Pingable server IP used by port-steal tests |

---

## Results & Output

### Web UI
After a test run, the AirSnitch panel in the Ragnar dashboard (`http://<ragnar-ip>:8000`) shows:

- Overall **PASS ✓** (green) or **FAIL ✗** (red) verdict
- Per-test pass/fail status with color coding
- Timestamp and interface names used
- Summary line in the global pentest summary at the top of the UI

### Saved JSON
All results are saved to:
```
/tmp/ragnar_logs/airsnitch/airsnitch_<timestamp>.json
```

Example result structure:
```json
{
  "timestamp": "2025-01-01T12:00:00",
  "iface_victim": "wlan1",
  "iface_attacker": "wlan2",
  "tests": {
    "gtk_shared":        { "vulnerable": false, ... },
    "gateway_bouncing":  { "vulnerable": true,  ... },
    "port_steal_downlink": { "vulnerable": false, ... },
    "port_steal_uplink": { "vulnerable": false, ... }
  },
  "summary": {
    "total_tests": 4,
    "vulnerable_count": 1,
    "vulnerable_tests": ["gateway_bouncing"],
    "network_isolated": false
  }
}
```

### Log Files
- Install log: `/tmp/ragnar_logs/airsnitch/install.log`
- Ragnar system log: messages prefixed with `AirSnitch:`

---

## Installation

AirSnitch installs automatically when first triggered. To install manually via the web UI:

1. Open `http://<ragnar-ip>:8000`
2. Navigate to the **AirSnitch** panel
3. Click **Install from GitHub** if the tool is not yet installed
4. Watch the live installation log stream in the UI

The tool is cloned to `tools/airsnitch/` inside the Ragnar directory.

---

## Running a Test

### Via Web UI
1. Open `http://<ragnar-ip>:8000`
2. Navigate to the **AirSnitch** panel
3. Configure interfaces, tests, and server IP
4. Click **Run AirSnitch**
5. Results appear automatically when the test completes

### Via Ragnar Orchestrator
AirSnitch runs as a standard Ragnar action and can be triggered programmatically via the API:

```bash
POST /api/airsnitch/run
{
  "iface_victim": "wlan1",
  "iface_attacker": "wlan2",
  "tests": ["gtk", "gateway", "port_steal_down", "port_steal_up"],
  "same_bss": false,
  "server": "8.8.8.8"
}
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/airsnitch/status` | Installation status and latest results |
| `POST` | `/api/airsnitch/run` | Trigger a test run |
| `GET` | `/api/airsnitch/results` | Most recent test results |
| `POST` | `/api/airsnitch/install` | Start background installation |
| `GET` | `/api/airsnitch/install-log` | Live installation log |

---

## Understanding Results

| Result | Meaning |
|---|---|
| All tests pass | Network correctly isolates clients — nearby devices cannot intercept each other's traffic |
| GTK Abuse vulnerable | Broadcast/multicast traffic can be decrypted by other clients |
| Gateway Bouncing vulnerable | Direct client-to-client traffic is possible via the router |
| Port Steal vulnerable | TCP sessions can be hijacked by another client on the same network |

Even WPA2/WPA3 protected networks can fail client isolation — encryption protects traffic from outsiders but not necessarily from other authenticated clients on the same network.

---

## Credits & Source

The underlying test tool is **AirSnitch**, developed by **Mathy Vanhoef** and collaborators as part of academic research into Wi-Fi client isolation vulnerabilities.

- **Source repository**: [https://github.com/vanhoefm/airsnitch](https://github.com/vanhoefm/airsnitch)
- **Author**: [Mathy Vanhoef](https://github.com/vanhoefm) — researcher at KU Leuven, known for discovering KRACK, FragAttacks, and other Wi-Fi protocol vulnerabilities
- **Research context**: The attacks implemented in AirSnitch were documented and disclosed responsibly as part of ongoing Wi-Fi security research

The Ragnar integration wraps the AirSnitch CLI, automates installation, and surfaces results through the Ragnar web dashboard. All credit for the underlying attack implementations belongs to the original authors.
