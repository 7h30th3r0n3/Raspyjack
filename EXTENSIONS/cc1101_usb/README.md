# CC1101-over-USB bridge for RaspyJack

Make the RaspyJack sub-GHz payloads work on **any** Raspberry Pi by moving the
CC1101 off the Pi's SPI/GPIO (which the LCD + Ethernet HAT already use) and onto
a tiny **ESP32-S3** USB dongle. The Pi talks to the dongle over USB-CDC; all the
timing-critical OOK work (replay + edge capture) happens on the ESP32.

```
  Raspberry Pi ──USB──► ESP32-S3 ──SPI──► CC1101 ──► antenna
   (RaspyJack)   CDC     (bridge fw)        (radio)
```

No change to the Pi's wiring, and the existing CardputerZero Cap HAT keeps
working: the driver auto-detects USB first, then falls back to the SPI HAT.

---

## 1. Bill of materials

| Qty | Part | Notes |
|-----|------|-------|
| 1 | **ESP32-S3** dev board with **native USB** | e.g. ESP32-S3-DevKitC-1, or an S3 "SuperMini". Must be S3/S2/C3 (native USB-CDC), *not* a classic ESP32. |
| 1 | **CC1101 SPI module** | generic 8-pin 433/868 MHz board, or E07-M1101D. 3.3 V part. |
| 1 | Antenna | 433 MHz (and/or 868 MHz) helical or SMA whip to match your module. |
| — | 1× 100 nF + 1× 10 µF cap | decoupling across the CC1101 VCC/GND, close to the module. |
| — | Short dupont wires | keep SCK/MISO/MOSI short (< 10 cm). |

Budget: ~6–10 €.

## 2. Wiring  (ESP32-S3 ↔ CC1101)

Pins are the defaults in `firmware/platformio.ini` — change the `build_flags`
there if your board differs.

| CC1101 pin | ESP32-S3 GPIO | Purpose |
|------------|---------------|---------|
| VCC        | **3V3**       | power — **never 5 V** |
| GND        | GND           | ground |
| CSN        | GPIO10        | SPI chip-select |
| SCK        | GPIO12        | SPI clock |
| MOSI / SI  | GPIO11        | SPI MOSI |
| MISO / SO  | GPIO13        | SPI MISO (also CHIP_RDYn) |
| GDO0       | GPIO4         | OOK data in (TX) / out (RX) — **required** |
| GDO2       | GPIO5         | optional status/IRQ |

> The firmware drives GDO0 as an output for TX (CC1101 `IOCFG0=0x2E`, Hi-Z) and
> reads it as an input for RX (`IOCFG0=0x0D`). One wire, direction per mode —
> same scheme the Pi HAT used on GPIO15.

If your CC1101 board has an RF antenna switch on a control pin, wire it to a
free GPIO and set `-D PIN_RF_SW=<gpio>` in `platformio.ini` (default `-1` = none).

## 3. Flash the firmware

PlatformIO:

```bash
cd EXTENSIONS/cc1101_usb/firmware
pio run -t upload          # build + flash
pio device monitor         # optional, 115200
```

Arduino IDE: open `firmware/src/main.cpp`, select an ESP32-S3 board, set
**USB CDC On Boot = Enabled** and **USB Mode = Hardware CDC and JTAG**, then
upload. (Those two settings = the `ARDUINO_USB_*` build flags.)

## 4. Pi-side setup

```bash
sudo apt install python3-serial        # or: pip install pyserial
sudo usermod -aG dialout $USER         # then re-login, for /dev/ttyACM* access
```

That's it. The dongle enumerates as `/dev/ttyACM0` (Espressif VID `303A`). The
driver probes it automatically.

### Transport selection

`payloads/_cc1101_driver.py` honours one environment variable:

| `RJ_CC1101_TRANSPORT` | behaviour |
|-----------------------|-----------|
| *(unset)* / `auto`    | try USB bridge, else SPI HAT (default) |
| `usb`                 | USB bridge only |
| `spi`                 | SPI HAT only (ignore USB) |

Force a specific port with `RJ_CC1101_USB=/dev/ttyACM0` if auto-detect picks the
wrong one.

## 5. Bring-up (staged — do this on first build)

The firmware is a v0.1 first cut; validate in order:

1. **Link** — `python3 EXTENSIONS/cc1101_usb/selftest.py` → expect `PING ok`,
   proto 1, and a plausible CC1101 `VERSION` (commonly `0x14`). A `0x00`/`0xFF`
   version = SPI wiring problem.
2. **Config/RX packet** — run the normal `Sub-GHz` payload, *Freq Analyzer* /
   *Read* — this exercises SPI_XFER + RSSI only.
3. **Capture** — *Read RAW* on a live remote; confirm pulses come back.
4. **Replay** — transmit a capture; confirm the target reacts.

If capture/replay timing looks off, the two tunables are the ISR filter window
(`50 µs .. 200000 µs` in `doTxRaw`/`gdoISR`) and the `delayMicroseconds` TX loop.

## 6. How it hangs together

* **PROTOCOL.md** — the COBS-framed wire protocol (keep `PROTO_VER` in sync).
* **firmware/** — ESP32-S3 bridge. `SPI_XFER` is a transparent passthrough, so
  the entire Python register layer runs unchanged; only `TX_RAW` (bit-banged
  GDO0) and `RX_RAW` (GDO0 edge timestamps) run device-side because USB latency
  makes host-side µs timing impossible.
* **../../payloads/_cc1101_usb.py** — host transport; a `spidev`-compatible
  object (`xfer2`) plus `tx_raw` / `rx_raw` / `rf_switch`.
* **../../payloads/_cc1101_driver.py** — `CC1101` now auto-selects USB or HAT in
  `open()`, and `send_raw_pulses()` / `capture_raw()` route to whichever
  transport is active. HAT behaviour is byte-for-byte unchanged.
```
