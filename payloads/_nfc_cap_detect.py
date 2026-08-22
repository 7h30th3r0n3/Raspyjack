"""
NFC auto-detect wrapper that adds Cap HAT (ST25R3916) support.

Drop-in replacement for _nfc_driver.auto_detect().  Tries the
built-in Cap NFC HAT first, then falls back to the original
detection chain (Chameleon Ultra → Proxmark3 → nfcpy → PN532).

Usage in a payload (change one import line):
    # Before:
    from payloads.nfc_rfid._nfc_driver import auto_detect
    # After:
    from payloads._nfc_cap_detect import auto_detect
"""

from payloads.nfc_rfid._nfc_driver import auto_detect as _original_detect


def auto_detect():
    """Try Cap HAT ST25R3916 first, fall back to original auto_detect."""
    try:
        from payloads._st25r_driver import ST25R3916Driver
        drv = ST25R3916Driver()
        if drv.open():
            return drv, "Cap NFC (ST25R3916)"
    except Exception:
        pass
    return _original_detect()
