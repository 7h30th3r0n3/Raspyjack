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
        print("  - is the ESP32-S3 flashed and plugged in?")
        print("  - try: RJ_CC1101_USB=/dev/ttyACM0, and check `dialout` group")
        return 1

    proto, fw = link.ping()
    print("PING ok  | proto=%d fw=%d.%d" % (proto, fw[0], fw[1]))

    info = link.info()
    ver = info[0] if len(info) > 0 else 0
    part = info[1] if len(info) > 1 else 0
    print("CC1101   | VERSION=0x%02X PARTNUM=0x%02X" % (ver, part))
    if ver in (0x00, 0xFF):
        print("FAIL: CC1101 not responding — check SPI wiring (SCK/MOSI/MISO/CSN).")
        link.close()
        return 2
    print("         | version looks valid (common value: 0x14)")

    link.close()

    # Full driver round-trip over USB.
    os.environ["RJ_CC1101_TRANSPORT"] = "usb"
    from payloads._cc1101_driver import CC1101
    radio = CC1101()
    if not radio.open():
        print("FAIL: CC1101.open() over USB failed.")
        return 3
    radio.set_frequency(433.92)
    print("DRIVER   | open ok, is_usb=%s, freq=%.2f MHz, rssi=%.0f dBm"
          % (radio.is_usb, radio.get_frequency(), radio.get_rssi()))
    radio.close()
    print("\nALL CHECKS PASSED — sub-GHz payloads can now use the USB bridge.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
