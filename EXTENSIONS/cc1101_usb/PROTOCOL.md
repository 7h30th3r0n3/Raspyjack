# RaspyJack CC1101-over-USB — serial protocol

Contract between the ESP32-S3/C3 bridge firmware (`firmware/`) and the Python
host transport (`payloads/_cc1101_usb.py`). Keep both sides in sync with the
`PROTO_VER` constant below (a mismatch is rejected at `detect()`).

```
PROTO_VER = 2          # v2: RX_RAW idle_us widened u16->u32; TX safety limits
MAGIC     = "RJC1"     # returned by PING, used for auto-detection
```

## Physical / link layer

* Transport: USB-CDC (native USB of the ESP32-S3). Baud rate is irrelevant on
  native USB; the host opens the port at 115200 by convention.
* The host is always the initiator: one request → one response. Only one
  command is outstanding at a time (no pipelining). `RX_RAW` is a *blocking*
  command: the device captures for the requested window, then replies.

## Framing — COBS

Every frame is `COBS(body) + 0x00`. COBS guarantees the body contains no `0x00`,
so the trailing `0x00` is an unambiguous delimiter and resynchronisation is
trivial (drop everything up to the next `0x00`).

* Request `body`  = `[cmd:u8][args...]`
* Response `body` = `[status:u8][data...]`

`status`: `0x00` = OK, anything else = error (see codes). Multi-byte integers
are **little-endian**. Signed pulse durations are `int16` LE (µs): a positive
value is carrier-ON (GDO0 high), a negative value is carrier-OFF (GDO0 low),
matching the existing driver / Flipper `.sub` convention.

Max body length each way: `MAX_BODY = 2048` bytes.

## Commands

| cmd  | name       | args                                                   | response data                                  |
|------|------------|--------------------------------------------------------|------------------------------------------------|
| 0x01 | PING       | —                                                      | `MAGIC[4] proto:u8 fw_major:u8 fw_minor:u8`    |
| 0x02 | INFO       | —                                                      | `cc_version:u8 cc_partnum:u8 gdo0:u8 gdo2:u8`  |
| 0x10 | SPI_XFER   | `mosi[n]`  (**1 ≤ n ≤ 70**)                             | `miso[n]` (same length, full-duplex)           |
| 0x11 | RF_SWITCH  | `val:u8`                                                | —                                              |
| 0x12 | POWER      | `on:u8`  (no-op; module powered from the 3V3 rail)      | —                                              |
| 0x13 | GDO_READ   | `which:u8` (0=GDO0, 2=GDO2)                             | `level:u8`                                     |
| 0x20 | TX_RAW     | `repeat:u8 flags:u8 n:u16 dur[n]:int16`                 | —                                              |
| 0x21 | RX_RAW     | `dur_ms:u16 idle_us:u32 max_sym:u16 flags:u8`           | `n:u16 dur[n]:int16`                           |

`SPI_XFER` carries one CC1101 SPI transaction (header + up to a 64-byte FIFO
burst), hence the 70-byte cap — it is not a bulk pipe. `dur[]` are signed-µs,
`|dur| ≤ 32767`.

### 0x10 SPI_XFER — the universal passthrough

The device asserts CSn, waits for MISO (CHIP_RDYn) low, performs a full-duplex
SPI transfer of the `mosi` bytes against the CC1101, deasserts CSn, and returns
the MISO bytes. Semantics are byte-for-byte identical to `spidev.xfer2()`, so
the entire Python register layer (header bit `0x80` read, `0x40` burst,
`0xC0` status) works unchanged. Everything that is *not* timing-critical
(config, `set_frequency`, packet TX/RX, RSSI, spectrum, chat) uses only this.

### 0x20 TX_RAW — device-side OOK replay

The firmware is self-contained: it saves the OOK-relevant registers
(`MDMCFG2`, `PKTCTRL0`, `FREND0`, `IOCFG0`), switches the CC1101 to
asynchronous-serial OOK (`IOCFG0=0x2E` → GDO0 Hi-Z so the ESP32 drives it),
strobes `STX`, then clocks the `dur[]` waveform out on GDO0 by **bit-banging**
the GPIO (`digitalWrite` + `delayMicroseconds` — no RMT, so it builds on both
arduino-esp32 2.x and 3.x). The frame is emitted `repeat` times. On completion
it releases GDO0, strobes `SIDLE` and restores the saved registers.

`flags` bit0 = append a short inter-frame gap between repeats (default on).

**Safety (no-jamming) guard — enforced in firmware, not just by the host:**
`repeat ≤ 32`, no single carrier-ON pulse > 100 ms, and cumulative carrier-ON
time (× repeat) ≤ 5 s; otherwise the device replies `ST_TXLIMIT` and transmits
nothing. The host chunks waveforms longer than ~1000 pulses into several frames.

### 0x21 RX_RAW — device-side edge capture

Pre-condition: the host has already put the CC1101 into async-serial RX
(`set_raw_rx()` → `IOCFG0=0x0D` serial-data-out on GDO0) via SPI_XFER. The
firmware sets GDO0 as input, timestamps both edges with a GPIO ISR + `micros()`,
and returns the signed-µs pulse list. Capture ends after `dur_ms`, or after
`idle_us` of silence once at least one edge was seen (now u32 — e.g. 500000 for
500 ms), or at `max_sym` symbols (capped to 1000 device-side). Durations outside
`50 µs .. 32767 µs` are dropped (int16 transport; a longer gap already ends the
frame).

## Error codes (status)

| code | meaning                       |
|------|-------------------------------|
| 0x00 | OK                            |
| 0x01 | bad/unknown command           |
| 0x02 | bad length / malformed args   |
| 0x03 | busy                          |
| 0x04 | CC1101 not responding         |
| 0x05 | capture error                 |
| 0x06 | TX refused (no-jamming limit) |
```
