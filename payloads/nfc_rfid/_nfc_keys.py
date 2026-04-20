"""
MIFARE Classic key dictionary and sector cracking utilities.
"""

import os
import json
from typing import Optional, List, Tuple

KEYS_DIR = "/root/Raspyjack/loot/NFC/keys"

# Extended dictionary of known MIFARE Classic keys (~100 most common)
KNOWN_KEYS = [
    bytes.fromhex(k) for k in [
        "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7", "000000000000",
        "B0B1B2B3B4B5", "AABBCCDDEEFF", "1A2B3C4D5E6F", "010203040506",
        "123456789ABC", "4D3A99C351DD", "1A982C7E459A", "714C5C886E97",
        "587EE5F9350F", "A0478CC39091", "533CB6C723F6", "8FD0A4F256E9",
        "A22AE129C013", "49FAE4E3849F", "FC00018778F7", "2612FEE7F4CE",
        "484558414354", "564C505249CB", "000000000001", "000000000002",
        "A0B0C0D0E0F0", "A1B1C1D1E1F1", "A0A1A2A3A4A5", "B0B1B2B3B4B5",
        "4B0B20107CCB", "D4F7D4F7D4F7", "FF078069D003", "A0478CC39091",
        "62D0C424ED8E", "E64A986A5D94", "8829DA9DAF76", "8A1F424104D3",
        "314B49474956", "564C505249CB", "0604DF988000", "1234567890AB",
        "AB0000000000", "ABCDEF012345", "CDEF89ABCDEF", "111111111111",
        "222222222222", "333333333333", "444444444444", "555555555555",
        "666666666666", "777777777777", "888888888888", "999999999999",
        "AAAAAAAAAAAA", "BBBBBBBBBBBB", "CCCCCCCCCCCC", "DDDDDDDDDDDD",
        "EEEEEEEEEEEE", "A0B0C0D0E0F0", "A1B1C1D1E1F1", "A0A1A2A3A4A5",
        "100910111213", "535455564142", "55495320DEAD", "474F4F444F4F",
        "0A0B0C0D0E0F", "010101010101", "656B4E4F545C", "09125A2589E5",
        "F4A9EF2ADB96", "19821982BB93", "6A1987C40A21", "7F33625BC129",
        "0AA11F3AC596", "E2F1321AB09F", "FC95DB3AEB92", "E9920A7A82C0",
        "1100AAB00011", "434F4D4D4F41", "4AC1273CE3A0", "505249565431",
        "47524F555041", "434F4D4D4F42", "505249565432", "47524F555042",
        "0FC3A0222243", "505249565433", "47524F555043", "434F4D4D4F43",
        "AC100722A0B4", "A12B34C56D78", "BA1234567890", "AB1234567890",
        "DEADBEEF0000", "CAFEBABE0000", "1337BEEF1337", "DEFACED00000",
        "F1F2F3F4F5F6", "E0E1E2E3E4E5", "000102030405", "050403020100",
        "D1D2D3D4D5D6", "C1C2C3C4C5C6", "B1B2B3B4B5B6", "A1A2A3A4A5A6",
    ]
]

# Deduplicate
_seen = set()
KNOWN_KEYS_UNIQUE = []
for k in KNOWN_KEYS:
    h = k.hex()
    if h not in _seen:
        _seen.add(h)
        KNOWN_KEYS_UNIQUE.append(k)
KNOWN_KEYS = KNOWN_KEYS_UNIQUE


def try_key(drv, block: int, key: bytes, uid: bytes) -> Optional[int]:
    """Try a key on a block. Returns key_type (0x60=A, 0x61=B) or None."""
    if drv.mifare_auth(block, key, uid, 0x60):
        return 0x60
    if drv.mifare_auth(block, key, uid, 0x61):
        return 0x61
    return None


def try_all_keys(drv, sector: int, uid: bytes, progress_cb=None) -> Tuple[Optional[bytes], Optional[int]]:
    """Try all known keys on a sector. Returns (key, key_type) or (None, None)."""
    block = sector * 4
    for i, key in enumerate(KNOWN_KEYS):
        if progress_cb:
            progress_cb(i, len(KNOWN_KEYS))
        kt = try_key(drv, block, key, uid)
        if kt is not None:
            return key, kt
    return None, None


def crack_all_sectors(drv, uid: bytes, n_sectors: int = 16, progress_cb=None):
    """Crack all sectors. Returns list of {sector, key, key_type, key_hex}."""
    results = []
    for sec in range(n_sectors):
        if progress_cb:
            progress_cb(sec, n_sectors, results)
        key, kt = try_all_keys(drv, sec, uid)
        results.append({
            "sector": sec,
            "key": key.hex().upper() if key else "",
            "key_type": "A" if kt == 0x60 else "B" if kt == 0x61 else "",
            "cracked": key is not None,
        })
    return results


def save_keymap(uid_hex: str, keymap: list):
    """Save discovered keys for a UID."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    path = os.path.join(KEYS_DIR, f"{uid_hex}.json")
    with open(path, "w") as f:
        json.dump({"uid": uid_hex, "keys": keymap}, f, indent=2)


def load_keymap(uid_hex: str) -> Optional[list]:
    """Load saved keys for a UID."""
    path = os.path.join(KEYS_DIR, f"{uid_hex}.json")
    if os.path.isfile(path):
        try:
            with open(path) as f:
                return json.load(f).get("keys", [])
        except Exception:
            pass
    return None


def get_sector_key(keymap: list, sector: int) -> Tuple[Optional[bytes], int]:
    """Get key for a sector from keymap. Returns (key_bytes, key_type)."""
    for entry in keymap:
        if entry.get("sector") == sector and entry.get("cracked"):
            key_hex = entry.get("key", "")
            kt = 0x60 if entry.get("key_type") == "A" else 0x61
            if key_hex:
                return bytes.fromhex(key_hex), kt
    return None, 0x60
