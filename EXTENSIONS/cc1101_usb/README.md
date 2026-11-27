# CC1101-over-USB bridge for RaspyJack

Give the RaspyJack sub-GHz payloads a CC1101 over USB — on a PC, a CardputerZero,
or any host with no free SPI bus. A tiny **ESP32-C3/S3** does the timing-critical
OOK work (replay + edge capture); the host talks to it over USB-CDC.

```
  host (Pi / PC) ──USB──► ESP32-C3/S3 ──SPI──► CC1101 ──► antenna
                   CDC      (bridge fw)         (radio)
```

The driver auto-detects the USB bridge first, then falls back to a local SPI
CC1101 (CardputerZero Cap HAT, or a bare module on the Pi's SPI0.1 / CE1 — the
native path needs no dongle and gives better RAW timing).

> **Responsible use.** This is a TX-capable sub-GHz tool. Transmit (replay /
> brute) **only** on frequencies you are allowed to use in your jurisdiction
> (EU: 433.05–434.79 MHz 10 mW; 868 MHz with duty-cycle limits — 315/915 are
> US) and **only** against targets you are explicitly authorised to test
> (pentest / CTF / research). **No jamming** — no continuous carrier, no
> RollJam/RollBack; the firmware hard-caps TX-on time to enforce this. The
> operator is responsible for legal compliance.

---

## 1. Bill of materials

| Qty | Part | Notes |
|-----|------|-------|
| 1 | **ESP32-C3 SuperMini** (carrier PCB default) | or any S3/S2/C3 board with **native USB-CDC** for a bare-wire build. **Not** a classic ESP32 (no native USB). |
| 1 | **CC1101 SPI module** | the carrier PCB expects a **2×4 (nRF24 footprint)** module; a bare-wire build takes any 433/868 MHz CC1101. 3.3 V part. |
| 1 | **Antenna matched to the band** | a real 433 MHz (≈16.4 cm ¼-wave) or 868 MHz (≈8.2 cm) antenna. ⚠️ A spring from an actual *nRF24* module is 2.4 GHz and gives ~metres only. Never TX without an antenna. |
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

**On an ESP32-C3** use the `esp32-c3` env (`pio run -e esp32-c3 -t upload`) and
this map instead — the C3 cannot use GPIO12–17 (SPI flash) or 18/19 (USB):

| CC1101 | CSN | SCK | MOSI | MISO | GDO0 | GDO2 |
|--------|-----|-----|------|------|------|------|
| **C3 GPIO** | 7 | 4 | 6 | 5 | 10 | 3 |

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
