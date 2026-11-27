#!/usr/bin/env python3
"""NTAG / Ultralight info decode + NXP originality-signature verification.

Pure-Python helpers for the Cap-NFC HAT Read path. No external deps:
- decode_version(): GET_VERSION bytes -> human model / storage / vendor.
- decode_config(): interpret the configuration + lock pages (AUTH0, PROT,
  CFGLCK, AUTHLIM, PWD set, static/dynamic lock bits).
- verify_originality(): ECDSA verification of the 32-byte READ_SIG signature
  against NXP's public key on curve secp128r1. Returns True (genuine NXP),
  False (bad signature / clone), or None (could not check). Mirrors the
  method used by proxmark3 / libnfc for NTAG21x.
"""

# ── secp128r1 domain parameters ───────────────────────────────────────
_P  = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
_A  = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC
_B  = 0xE87579C11079F43DD824993C2CEE5ED3
_N  = 0xFFFFFFFE0000000075A30D1B9038A115
_GX = 0x161FF7528B899B2D0C28607CA52C5B86
_GY = 0xCF5AC8395BAFEB13C02DA292DDED7A83

# NXP NTAG21x originality public key (uncompressed: 0x04 || X || Y), 33 bytes.
_NXP_PUB_HEX = "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61"


# ── EC point arithmetic over GF(p) (affine, None = point at infinity) ──
def _inv(x, m):
    return pow(x % m, -1, m)


def _pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if x1 == x2 and y1 == y2:
        m = (3 * x1 * x1 + _A) * _inv(2 * y1, _P) % _P
    else:
        m = (y2 - y1) * _inv((x2 - x1) % _P, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return (x3, y3)


def _pt_mul(k, pt):
    r = None
    k %= _N
    while k:
        if k & 1:
            r = _pt_add(r, pt)
        pt = _pt_add(pt, pt)
        k >>= 1
    return r


def _pubkey_point():
    raw = bytes.fromhex(_NXP_PUB_HEX)
    if len(raw) != 33 or raw[0] != 0x04:
        return None
    return (int.from_bytes(raw[1:17], "big"), int.from_bytes(raw[17:33], "big"))


def verify_originality(uid, signature):
    """ECDSA-verify the NTAG21x originality signature over secp128r1.

    uid: 7-byte tag UID (bytes). signature: 32-byte READ_SIG response.
    Returns True / False / None (None = malformed input or math error).
    """
    try:
        if not uid or not signature or len(signature) < 32:
            return None
        sig = bytes(signature[:32])
        r = int.from_bytes(sig[:16], "big")
        s = int.from_bytes(sig[16:32], "big")
        if not (1 <= r < _N and 1 <= s < _N):
            return False
        # Message scalar: the raw UID as an integer (leftmost bits), no SHA.
        e = int.from_bytes(bytes(uid), "big")
        q = _pubkey_point()
        if q is None:
            return None
        w = _inv(s, _N)
        u1 = (e * w) % _N
        u2 = (r * w) % _N
        pt = _pt_add(_pt_mul(u1, (_GX, _GY)), _pt_mul(u2, q))
        if pt is None:
            return False
        return (pt[0] % _N) == (r % _N)
    except Exception:
        return None


# ── GET_VERSION decode ────────────────────────────────────────────────
_VENDORS = {0x04: "NXP", 0x02: "STMicro", 0x05: "Infineon"}


def decode_version(ver):
    """GET_VERSION dict (from driver.ntag_get_version) -> display dict."""
    if not ver:
        return {"model": "Ultralight (no GET_VERSION)", "vendor": "?",
                "storage_bytes": None, "protocol": "?"}
    vendor = _VENDORS.get(ver.get("vendor"), "0x%02X" % ver.get("vendor", 0))
    typ = ver.get("type")
    sto = ver.get("storage", 0)
    sto_bytes = (1 << (sto >> 1)) if sto else None  # 2^(n>>1), approx user mem
    model = "Unknown"
    s = sto & 0xFF
    if typ == 0x03:  # NTAG (storage byte: 213=0x0F, 215=0x11, 216=0x13)
        model = {0x0F: "NTAG213", 0x11: "NTAG215", 0x13: "NTAG216"}.get(s, "NTAG21x")
    elif typ == 0x04:  # Ultralight EV1 (48B=0x0B, 128B=0x0E)
        model = {0x0B: "UL EV1 (48B)", 0x0E: "UL EV1 (128B)"}.get(s,
                "MIFARE Ultralight EV1")
    elif typ == 0x05:
        model = "NTAG I2C"
    proto = "ISO14443-3" if ver.get("protocol") == 0x03 else "0x%02X" % ver.get("protocol", 0)
    return {"model": model, "vendor": vendor, "storage_bytes": sto_bytes,
            "protocol": proto,
            "fw": "%d.%d" % (ver.get("major", 0), ver.get("minor", 0))}


# ── Configuration + lock pages decode (NTAG21x) ───────────────────────
def decode_config(pages, total_pages):
    """Interpret NTAG21x config/lock pages. `pages` maps int page -> 4 bytes.

    Returns a dict with the security-relevant fields, or {} if the config
    pages were not read (e.g. locked before reading them).
    """
    if not pages or total_pages < 10:
        return {}
    cfg0 = total_pages - 4          # CFG0: MIRROR .. AUTH0
    cfg1 = total_pages - 3          # CFG1: ACCESS ..
    dynlock = total_pages - 5       # dynamic lock bytes (NTAG21x)
    out = {}

    p2 = pages.get(2)
    if p2 and len(p2) >= 4:
        out["lock_static"] = "%02X%02X" % (p2[2], p2[3])

    c0 = pages.get(cfg0)
    if c0 and len(c0) >= 4:
        out["auth0"] = c0[3]        # first page requiring PWD_AUTH (0xFF = off)
        out["prot_from"] = ("page %d" % c0[3]) if c0[3] <= total_pages else "disabled"

    c1 = pages.get(cfg1)
    if c1 and len(c1) >= 1:
        acc = c1[0]
        out["prot"] = "R/W" if (acc & 0x80) else "write-only"
        out["cfglck"] = bool(acc & 0x40)
        out["nfc_cnt_en"] = bool(acc & 0x10)
        out["authlim"] = acc & 0x07

    dl = pages.get(dynlock)
    if dl and len(dl) >= 3:
        out["lock_dyn"] = "%02X%02X%02X" % (dl[0], dl[1], dl[2])

    pwd = pages.get(total_pages - 2)
    if pwd and len(pwd) >= 4:
        out["pwd_set"] = (bytes(pwd[:4]) != b"\xFF\xFF\xFF\xFF"
                          and bytes(pwd[:4]) != b"\x00\x00\x00\x00")
    return out


def info_lines(version_info, config, counter, signature, genuine):
    """Build human-readable lines for the card-info view."""
    lines = []
    if version_info:
        vi = version_info
        sb = ("%dB" % vi["storage_bytes"]) if vi.get("storage_bytes") else "?"
        lines.append("%s  (%s)" % (vi.get("model", "?"), vi.get("vendor", "?")))
        lines.append("Mem~%s  %s fw%s" % (sb, vi.get("protocol", ""), vi.get("fw", "")))
    if genuine is True:
        lines.append("Originality: GENUINE NXP")
    elif genuine is False:
        lines.append("Originality: FAIL (clone?)")
    elif signature:
        lines.append("Sig: %s.. (unchecked)" % signature[:12])
    if counter is not None:
        lines.append("NFC counter: %d" % counter)
    if config:
        if "auth0" in config:
            a0 = config["auth0"]
            lines.append("AUTH0: 0x%02X (%s)" % (
                a0, "off" if a0 == 0xFF else "prot from p%d" % a0))
        if "authlim" in config:
            lines.append("PROT:%s CFGLCK:%s AUTHLIM:%d" % (
                config.get("prot", "?"),
                "Y" if config.get("cfglck") else "N",
                config.get("authlim", 0)))
        if "pwd_set" in config:
            lines.append("PWD set: %s" % ("YES" if config["pwd_set"] else "no"))
        if config.get("lock_static"):
            lines.append("Lock: s=%s d=%s" % (
                config.get("lock_static", "?"), config.get("lock_dyn", "?")))
    return lines
