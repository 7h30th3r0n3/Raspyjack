#!/usr/bin/env python3
"""Bring-up self-test for the CC1101-over-USB bridge.

Run on the Pi after flashing the ESP32-S3:

    python3 EXTENSIONS/cc1101_usb/selftest.py [--port /dev/ttyACM0]

Checks the USB link (PING), reads the CC1101 VERSION/PARTNUM via SPI passthrough,
then programs a frequency through the full driver to prove the register layer
works over USB.
"""
import argparse
import os
import sys

# make payloads/ importable regardless of CWD
_REPO = os.path.abspath(os.path.join(__file__, "..", "..", ".."))
sys.path.insert(0, _REPO)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", help="force serial port (e.g. /dev/ttyACM0)")
    args = ap.parse_args()

    from payloads import _cc1101_usb as usb

    link = usb.detect(port=args.port)
    if link is None:
        print("FAIL: no CC1101 USB bridge found.")
        print("  - is the ESP32-C3/S3 flashed (pio run -e esp32-c3 -t upload) and plugged in?")
        print("  - try: RJ_CC1101_USB=/dev/ttyACM0, and check the `dialout` group")
        return 1

    from payloads import _cc1101_usb as usb
    proto, fw = link.ping()
    print("PING ok  | proto=%d fw=%d.%d" % (proto, fw[0], fw[1]))
    if proto != usb.PROTO_VER:
        print("FAIL: protocol mismatch (host %d vs device %d) — reflash firmware."
              % (usb.PROTO_VER, proto))
        link.close()
        return 5

    info = link.info()
    ver = info[0] if len(info) > 0 else 0
    part = info[1] if len(info) > 1 else 0
    print("CC1101   | VERSION=0x%02X PARTNUM=0x%02X (PARTNUM=0x00 is normal)" % (ver, part))
    if ver in (0x00, 0xFF):
        print("FAIL: CC1101 not responding — check SPI wiring or VCC=3V3 (module reversed?).")
        link.close()
        return 2

    # Real SPI write/readback: proves MOSI+MISO+SCK+CS in both polarities.
    # SYNC1 (0x04) is a free R/W register; restore with SRES afterwards.
    ok_spi = True
    for pat in (0xAA, 0x55):
        link.xfer2([0x04, pat])                 # write SYNC1 = pat
        rd = link.xfer2([0x04 | 0x80, 0x00])    # read  SYNC1
        got = rd[1] if len(rd) > 1 else None
        if got != pat:
            ok_spi = False
            print("SPI R/W  | FAIL: wrote 0x%02X read 0x%02X" % (pat, got if got is not None else -1))
    link.xfer2([0x30])                          # SRES, back to defaults
    if not ok_spi:
        print("FAIL: SPI data lines bad — check MOSI/MISO/SCK/CSN solder joints.")
        link.close()
        return 3
    print("SPI R/W  | OK (0xAA/0x55 readback) — SPI lines good")

    link.close()

    # Full driver round-trip over USB.
    os.environ["RJ_CC1101_TRANSPORT"] = "usb"
    from payloads._cc1101_driver import CC1101
    radio = CC1101()
    if not radio.open():
        print("FAIL: CC1101.open() over USB failed.")
        return 4
    radio.set_frequency(433.92)
    print("DRIVER   | open ok, is_usb=%s, freq=%.2f MHz, rssi=%.0f dBm"
          % (radio.is_usb, radio.get_frequency(), radio.get_rssi()))
    radio.close()
    print("\nLINK + SPI OK.  NOT tested here: GDO0 wiring, TX, RX capture, antenna.")
    print("Next: fit a matched antenna, then run 'Read RAW' + a short replay to")
    print("validate the RF chain (the only parts the self-test cannot reach).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
