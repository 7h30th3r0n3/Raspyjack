#!/usr/bin/env python3
"""MIFARE DESFire EV1/EV2/EV3 reader for RaspyJack (Cap NFC, ST25R3916).

Enumerates a DESFire card (GET_VERSION, applications, files, file settings),
authenticates with DES (D40 legacy 0x0A), ISO 2K3DES (0x1A as DES path) and
AES-128 (EV1 0xAA) using the RndA/RndB CBC challenge, and reads data / value /
record files.

Native DESFire commands ride on the existing ISO-DEP (ISO14443-4) transport:
each native command is the INF of an I-block; the response is a status byte
(0x00 = OK, 0xAF = additional frame) followed by the payload. This mirrors the
EMV reader's use of ``payloads._iso14443_4.ISO14443_4``.

Logic ported faithfully from Evil-Cardputer ``src/nfc_desfire.h`` (df_cmd,
df_get_version, df_get_app_ids, df_auth_des, df_auth_aes, df_read_data, 0xAF
chaining). Crypto convention preserved:
  * AES : CBC, decrypt enc_rndb (iv=0), encrypt token (iv=enc_rndb).
  * DES legacy (D40): the PCD *deciphers* in both directions (libfreefare
    MCD_SEND/RECEIVE convention), i.e. everything is CBC-DECRYPT.

Session setup (done by the caller, as in cap_flipper_nfc._mode_emv):
    drv  = _open_driver()                 # ST25R3916Driver, opened
    drv.read_passive_target(timeout=3.0)  # anticollision + SELECT
    from payloads._iso14443_4 import ISO14443_4
    iso = ISO14443_4(drv); iso.activate() # RATS/ATS
    from payloads.nfc_rfid.nfc_desfire import DESFireReader, enumerate_card
    info = enumerate_card(iso)

Crypto backend: python3-cryptography (already a declared RaspyJack dependency).
"""

import os
from typing import Optional, List, Dict, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
try:  # TripleDES moved to the "decrepit" module in cryptography 43+/48
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
except Exception:  # older cryptography: still on the main algorithms module
    _TripleDES = algorithms.TripleDES

# ── Status codes ──────────────────────────────────────────────────────
DF_ST_OK           = 0x00
DF_ST_ADDITIONAL   = 0xAF
DF_ST_AUTH_ERROR   = 0xAE
DF_ST_LENGTH_ERROR = 0x7E
DF_ST_PERMISSION   = 0x9D

# ── Native commands ───────────────────────────────────────────────────
DF_CMD_GET_VERSION       = 0x60
DF_CMD_ADDITIONAL_FRAME  = 0xAF
DF_CMD_GET_APP_IDS       = 0x6A
DF_CMD_GET_DF_NAMES      = 0x6D
DF_CMD_GET_FREE_MEM      = 0x6E
DF_CMD_SELECT_APP        = 0x5A
DF_CMD_GET_FILE_IDS      = 0x6F
DF_CMD_GET_FILE_SETTINGS = 0xF5
DF_CMD_GET_KEY_SETTINGS  = 0x45
DF_CMD_AUTH_DES          = 0x0A   # D40 legacy DES / 2K3DES
DF_CMD_AUTH_ISO          = 0x1A   # ISO 3DES / 3K3DES
DF_CMD_AUTH_AES          = 0xAA   # AES-128
DF_CMD_READ_DATA         = 0xBD
DF_CMD_GET_VALUE         = 0x6C
DF_CMD_READ_RECORDS      = 0xBB

# Key types
DF_KEY_DES    = "des"      # single DES, 8-byte key
DF_KEY_2K3DES = "2k3des"   # 16-byte key via the legacy 0x0A path
DF_KEY_AES    = "aes"      # AES-128, 16-byte key

# Factory default keys
DF_KEY_ZERO8  = bytes(8)
DF_KEY_ZERO16 = bytes(16)

_FTYPE_NAMES = {0: "StandardData", 1: "BackupData", 2: "Value",
                3: "LinearRecord", 4: "CyclicRecord"}
_COMM_NAMES  = {0: "plain", 1: "MACed", 2: "plain", 3: "enciphered"}


# ── Crypto helpers (cryptography backend) ─────────────────────────────

def _aes_cbc(encrypt: bool, key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def _des_cbc(encrypt: bool, key: bytes, iv: bytes, data: bytes) -> bytes:
    """CBC with TripleDES: an 8-byte key is single DES, a 16-byte key is
    2-key EDE (K1 K2 K1) — matching Evil's df_des_block_decrypt."""
    c = Cipher(_TripleDES(key), modes.CBC(iv), backend=default_backend())
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def _rotl1(b: bytes) -> bytes:
    return b[1:] + b[:1]


def _rand(n: int) -> bytes:
    return os.urandom(n)


# ── DESFire reader ────────────────────────────────────────────────────

class DESFireReader:
    """DESFire reader over an activated ISO14443-4 transport.

    Args:
        iso: a payloads._iso14443_4.ISO14443_4 instance whose .activate()
             already succeeded (RATS/ATS done). Must expose send_apdu(bytes).
    """

    def __init__(self, iso, timeout_ms: int = 400):
        self._iso = iso
        self._to = timeout_ms
        self.session_key: Optional[bytes] = None
        self.authenticated: bool = False

    # ---- low-level framing --------------------------------------------
    def _raw(self, frame: bytes) -> Tuple[int, bytes]:
        """Transceive one native frame. Returns (status, payload)."""
        resp = self._iso.send_apdu(bytes(frame))
        if not resp:
            return (-1, b"")
        return (resp[0], bytes(resp[1:]))

    def _cmd(self, cmd: int, data: bytes = b"") -> Tuple[int, bytes]:
        """Command + data, following 0xAF additional-frame chaining.
        Returns (final_status, assembled_payload)."""
        data = bytes(data)[:60]
        st, payload = self._raw(bytes([cmd]) + data)
        if st < 0:
            return (-1, b"")
        out = bytearray(payload)
        guard = 0
        while st == DF_ST_ADDITIONAL and guard < 16:
            guard += 1
            st, payload = self._raw(bytes([DF_CMD_ADDITIONAL_FRAME]))
            if st < 0:
                break
            if len(out) + len(payload) <= 2048:
                out.extend(payload)
        return (st, bytes(out))

    # ---- enumeration --------------------------------------------------
    def get_version(self) -> Optional[Dict]:
        st, v = self._cmd(DF_CMD_GET_VERSION)
        if st != DF_ST_OK or len(v) < 28:
            return None
        return parse_version(v)

    def get_free_memory(self) -> Optional[int]:
        st, v = self._cmd(DF_CMD_GET_FREE_MEM)
        if st != DF_ST_OK or len(v) < 3:
            return None
        return v[0] | (v[1] << 8) | (v[2] << 16)

    def get_application_ids(self) -> List[int]:
        st, v = self._cmd(DF_CMD_GET_APP_IDS)
        if st != DF_ST_OK:
            return []
        aids = []
        for i in range(0, len(v) - 2, 3):
            aids.append(v[i] | (v[i + 1] << 8) | (v[i + 2] << 16))
        return aids

    def select_application(self, aid: int) -> bool:
        a = bytes([aid & 0xFF, (aid >> 8) & 0xFF, (aid >> 16) & 0xFF])
        st, _ = self._cmd(DF_CMD_SELECT_APP, a)
        ok = st == DF_ST_OK
        if ok:  # selecting an app drops any prior authentication
            self.authenticated = False
            self.session_key = None
        return ok

    def get_file_ids(self) -> List[int]:
        st, v = self._cmd(DF_CMD_GET_FILE_IDS)
        if st != DF_ST_OK:
            return []
        return list(v)

    def get_file_settings(self, fid: int) -> Optional[Dict]:
        st, v = self._cmd(DF_CMD_GET_FILE_SETTINGS, bytes([fid & 0xFF]))
        if st != DF_ST_OK or not v:
            return None
        return parse_file_settings(v)

    def get_key_settings(self) -> Optional[bytes]:
        st, v = self._cmd(DF_CMD_GET_KEY_SETTINGS)
        return v if st == DF_ST_OK else None

    # ---- file content -------------------------------------------------
    def read_data(self, fid: int, offset: int = 0, length: int = 0) -> Optional[bytes]:
        p = bytes([fid & 0xFF,
                   offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
                   length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF])
        st, v = self._cmd(DF_CMD_READ_DATA, p)
        return v if st == DF_ST_OK else None

    def get_value(self, fid: int) -> Optional[int]:
        st, v = self._cmd(DF_CMD_GET_VALUE, bytes([fid & 0xFF]))
        if st != DF_ST_OK or len(v) < 4:
            return None
        val = v[0] | (v[1] << 8) | (v[2] << 16) | (v[3] << 24)
        if val & 0x80000000:
            val -= 1 << 32
        return val

    def read_records(self, fid: int, offset: int = 0, num: int = 0) -> Optional[bytes]:
        p = bytes([fid & 0xFF,
                   offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
                   num & 0xFF, (num >> 8) & 0xFF, (num >> 16) & 0xFF])
        st, v = self._cmd(DF_CMD_READ_RECORDS, p)
        return v if st == DF_ST_OK else None

    # ---- authentication ----------------------------------------------
    def authenticate(self, keyno: int, key: bytes, keytype: str = DF_KEY_AES) -> bool:
        """Mutually authenticate. keytype: 'aes' (16B), 'des' (8B) or
        '2k3des' (16B, via the legacy 0x0A path). Returns True on success."""
        key = bytes(key)
        if keytype == DF_KEY_AES:
            return self._auth_aes(keyno, key)
        return self._auth_des(keyno, key)  # des / 2k3des share the 0x0A flow

    def _auth_aes(self, keyno: int, key: bytes) -> bool:
        if len(key) != 16:
            return False
        st, buf = self._raw(bytes([DF_CMD_AUTH_AES, keyno & 0xFF]))
        if st != DF_ST_ADDITIONAL or len(buf) < 16:
            return False
        enc_rndb = buf[:16]
        rndb = _aes_cbc(False, key, bytes(16), enc_rndb)       # decrypt, iv=0
        rnda = _rand(16)
        plain = rnda + _rotl1(rndb)
        token = _aes_cbc(True, key, enc_rndb, plain)           # encrypt, iv=enc_rndb
        st, resp = self._raw(bytes([DF_CMD_ADDITIONAL_FRAME]) + token)
        if st != DF_ST_OK or len(resp) < 16:
            return False
        iv = token[16:32]
        rnda_rot_card = _aes_cbc(False, key, iv, resp[:16])
        if rnda_rot_card != _rotl1(rnda):
            return False
        # AES session key = RndA[0:4] | RndB[0:4] | RndA[12:16] | RndB[12:16]
        self.session_key = rnda[0:4] + rndb[0:4] + rnda[12:16] + rndb[12:16]
        self.authenticated = True
        return True

    def _auth_des(self, keyno: int, key: bytes) -> bool:
        if len(key) not in (8, 16):
            return False
        bs = 8
        st, buf = self._raw(bytes([DF_CMD_AUTH_DES, keyno & 0xFF]))
        if st != DF_ST_ADDITIONAL or len(buf) < bs:
            return False
        enc_rndb = buf[:bs]
        rndb = _des_cbc(False, key, bytes(bs), enc_rndb)       # decrypt, iv=0
        rnda = _rand(bs)
        plain = rnda + _rotl1(rndb)
        token = _des_cbc(False, key, enc_rndb, plain)          # legacy: decrypt, iv=enc_rndb
        st, resp = self._raw(bytes([DF_CMD_ADDITIONAL_FRAME]) + token)
        if st != DF_ST_OK or len(resp) < bs:
            return False
        iv2 = token[bs:2 * bs]
        rnda_rot_card = _des_cbc(False, key, iv2, resp[:bs])
        if rnda_rot_card != _rotl1(rnda):
            return False
        self.session_key = rnda[0:4] + rndb[0:4]  # DES session key (first 8 bytes)
        self.authenticated = True
        return True

    def try_key_dictionary(self, keyno: int, keys: List[Tuple[str, bytes, str]]) -> Optional[Tuple[str, bytes, str]]:
        """Try (name, key, keytype) tuples; return the first that authenticates.
        Re-selection may be needed between failed auths on some cards; callers
        that see persistent failures should re-select the application."""
        for name, key, ktype in keys:
            try:
                if self.authenticate(keyno, key, ktype):
                    return (name, key, ktype)
            except Exception:
                pass
        return None


# ── Parsers ───────────────────────────────────────────────────────────

def parse_version(v: bytes) -> Dict:
    """Parse the 28-byte GET_VERSION response (7 HW + 7 SW + 14 UID/batch)."""
    def _hw(o):
        return {
            "vendor": v[o], "type": v[o + 1], "subtype": v[o + 2],
            "major": v[o + 3], "minor": v[o + 4],
            "storage_code": v[o + 5], "protocol": v[o + 6],
            "storage_bytes": 1 << (v[o + 5] >> 1),
        }
    uid = v[14:21]
    return {
        "hw": _hw(0),
        "sw": _hw(7),
        "uid": uid.hex().upper(),
        "batch": v[21:26].hex().upper(),
        "prod_week": v[26], "prod_year": v[27],
        "vendor_name": "NXP" if v[0] == 0x04 else "0x%02X" % v[0],
        "raw": v[:28].hex().upper(),
    }


def parse_file_settings(s: bytes) -> Dict:
    """Parse a GET_FILE_SETTINGS response."""
    ftype = s[0]
    comm = s[1] if len(s) > 1 else 0
    ar = (s[2] | (s[3] << 8)) if len(s) > 3 else 0
    out = {
        "type": ftype,
        "type_name": _FTYPE_NAMES.get(ftype, "0x%02X" % ftype),
        "comm": comm,
        "comm_name": _COMM_NAMES.get(comm, "0x%02X" % comm),
        "access": {
            "read": (ar >> 12) & 0xF,
            "write": (ar >> 8) & 0xF,
            "read_write": (ar >> 4) & 0xF,
            "change": ar & 0xF,
        },
        "free_read": ((ar >> 12) & 0xF) == 0x0E,
        "raw": s.hex().upper(),
    }
    if ftype in (0, 1) and len(s) >= 7:  # standard / backup data
        out["size"] = s[4] | (s[5] << 8) | (s[6] << 16)
    elif ftype == 2 and len(s) >= 17:    # value
        def i32(o):
            x = s[o] | (s[o + 1] << 8) | (s[o + 2] << 16) | (s[o + 3] << 24)
            return x - (1 << 32) if x & 0x80000000 else x
        out["lower_limit"] = i32(4)
        out["upper_limit"] = i32(8)
        out["limited_credit"] = i32(12)
        out["limited_credit_enabled"] = s[16]
    elif ftype in (3, 4) and len(s) >= 13:  # record
        out["record_size"] = s[4] | (s[5] << 8) | (s[6] << 16)
        out["max_records"] = s[7] | (s[8] << 8) | (s[9] << 16)
        out["cur_records"] = s[10] | (s[11] << 8) | (s[12] << 16)
    return out


# ── Key dictionary ────────────────────────────────────────────────────

def default_key_dictionary() -> List[Tuple[str, bytes, str]]:
    """Factory keys tried first: all-zero DES and all-zero AES."""
    return [
        ("factory DES (0x00*8)", DF_KEY_ZERO8, DF_KEY_DES),
        ("factory AES (0x00*16)", DF_KEY_ZERO16, DF_KEY_AES),
    ]


def load_key_dictionary(path: str) -> List[Tuple[str, bytes, str]]:
    """Load extra keys from a text file: 'HEX[,type]' per line (type =
    des|2k3des|aes; inferred from length when omitted). '#' comments allowed.
    Missing/unreadable file -> factory keys only."""
    keys = default_key_dictionary()
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(",")]
                hexk = parts[0].replace(" ", "")
                try:
                    kb = bytes.fromhex(hexk)
                except ValueError:
                    continue
                ktype = parts[1].lower() if len(parts) > 1 else (
                    DF_KEY_AES if len(kb) == 16 else DF_KEY_DES)
                if ktype not in (DF_KEY_DES, DF_KEY_2K3DES, DF_KEY_AES):
                    continue
                keys.append(("file:" + hexk[:12], kb, ktype))
    except OSError:
        pass
    return keys


# ── High-level enumeration for UI ─────────────────────────────────────

def enumerate_card(iso, read_free_files: bool = True, key_dict_path: Optional[str] = None) -> Dict:
    """Walk the whole card and return a display-ready dict:
        {version, free_mem, picc_key_settings, apps: [{aid, key_settings,
         files: [{fid, settings, data?}], auth?}], error?}
    `auth` records a factory-key hit (free-read files need no auth)."""
    r = DESFireReader(iso)
    result: Dict = {"version": None, "free_mem": None, "apps": []}
    result["version"] = r.get_version()
    result["free_mem"] = r.get_free_memory()

    # PICC level (AID 0): select, read key settings, list apps.
    r.select_application(0x000000)
    result["picc_key_settings"] = _hexn(r.get_key_settings())
    keys = load_key_dictionary(key_dict_path) if key_dict_path else default_key_dictionary()

    for aid in r.get_application_ids():
        app: Dict = {"aid": "%06X" % aid, "files": [], "key_settings": None, "auth": None}
        if not r.select_application(aid):
            app["error"] = "select failed"
            result["apps"].append(app)
            continue
        app["key_settings"] = _hexn(r.get_key_settings())
        # Opportunistic factory-key auth (key 0) so enciphered files can be read.
        hit = r.try_key_dictionary(0, keys)
        if hit:
            app["auth"] = {"key": hit[0], "type": hit[2]}
        for fid in r.get_file_ids():
            fentry: Dict = {"fid": fid}
            settings = r.get_file_settings(fid)
            fentry["settings"] = settings
            if read_free_files and settings and settings["type"] in (0, 1):
                size = min(settings.get("size", 0), 256)
                data = r.read_data(fid, 0, size)
                if data is not None:
                    fentry["data"] = data.hex().upper()
            elif read_free_files and settings and settings["type"] == 2:
                val = r.get_value(fid)
                if val is not None:
                    fentry["value"] = val
            app["files"].append(fentry)
        result["apps"].append(app)
    return result


def _hexn(b: Optional[bytes]) -> Optional[str]:
    return b.hex().upper() if b else None


if __name__ == "__main__":  # pragma: no cover
    print("nfc_desfire.py — DESFire EV1/2/3 reader module (import and pass an "
          "activated ISO14443_4 transport to DESFireReader / enumerate_card).")
