"""
NFC card type detection, NDEF parsing, and dump management.
"""

import os
import json
from datetime import datetime
from typing import Optional, List

LOOT_DIR = "/root/Raspyjack/loot/NFC"

# NDEF URL prefixes (TNF=0x01, type="U")
NDEF_URL_PREFIXES = {
    0x00: "", 0x01: "http://www.", 0x02: "https://www.", 0x03: "http://",
    0x04: "https://", 0x05: "tel:", 0x06: "mailto:",
    0x07: "ftp://anonymous:anonymous@", 0x08: "ftp://ftp.",
    0x09: "ftps://", 0x0A: "sftp://", 0x0B: "smb://",
    0x0C: "nfs://", 0x0D: "ftp://", 0x0E: "dav://",
    0x0F: "news:", 0x10: "telnet://", 0x11: "imap:",
    0x12: "rtsp://", 0x13: "urn:", 0x14: "pop:",
    0x15: "sip:", 0x16: "sips:", 0x17: "tftp:",
    0x18: "btspp://", 0x19: "btl2cap://", 0x1A: "btgoep://",
    0x1B: "tcpobex://", 0x1C: "irdaobex://", 0x1D: "file://",
}


def parse_ndef(raw_bytes: bytes) -> List[dict]:
    """Parse NDEF TLV data from Ultralight/NTAG pages. Returns list of records."""
    records = []
    i = 0
    while i < len(raw_bytes):
        tlv_type = raw_bytes[i]
        i += 1
        if tlv_type == 0xFE:
            break
        if tlv_type == 0x00:
            continue
        if i >= len(raw_bytes):
            break
        length = raw_bytes[i]
        i += 1
        if length == 0xFF:
            if i + 1 >= len(raw_bytes):
                break
            length = (raw_bytes[i] << 8) | raw_bytes[i + 1]
            i += 2
        if tlv_type != 0x03:
            i += length
            continue
        # NDEF message
        end = i + length
        while i < end and i < len(raw_bytes):
            if i >= len(raw_bytes):
                break
            header = raw_bytes[i]
            i += 1
            tnf = header & 0x07
            sr = bool(header & 0x10)
            il = bool(header & 0x08)
            if i >= len(raw_bytes):
                break
            type_len = raw_bytes[i]
            i += 1
            if sr:
                if i >= len(raw_bytes):
                    break
                payload_len = raw_bytes[i]
                i += 1
            else:
                if i + 3 >= len(raw_bytes):
                    break
                payload_len = (raw_bytes[i] << 24) | (raw_bytes[i+1] << 16) | (raw_bytes[i+2] << 8) | raw_bytes[i+3]
                i += 4
            id_len = 0
            if il:
                if i >= len(raw_bytes):
                    break
                id_len = raw_bytes[i]
                i += 1
            rec_type = raw_bytes[i:i + type_len]
            i += type_len
            rec_id = raw_bytes[i:i + id_len]
            i += id_len
            payload = raw_bytes[i:i + payload_len]
            i += payload_len

            record = {"tnf": tnf, "type": rec_type, "payload": payload, "parsed": ""}
            if tnf == 0x01 and rec_type == b"U":
                prefix_idx = payload[0] if payload else 0
                prefix = NDEF_URL_PREFIXES.get(prefix_idx, "")
                url = prefix + payload[1:].decode("utf-8", errors="replace")
                record["parsed"] = url
                record["kind"] = "URL"
            elif tnf == 0x01 and rec_type == b"T":
                lang_len = payload[0] & 0x3F if payload else 0
                text = payload[1 + lang_len:].decode("utf-8", errors="replace")
                record["parsed"] = text
                record["kind"] = "Text"
            elif tnf == 0x02:
                record["kind"] = "MIME"
                record["parsed"] = rec_type.decode("ascii", errors="replace")
            else:
                record["kind"] = f"TNF{tnf}"
                record["parsed"] = payload.hex()[:30]
            records.append(record)
    return records


def read_ultralight_pages(drv, max_pages=45) -> List[Optional[bytes]]:
    """Read all pages from Ultralight/NTAG. Returns list of 4-byte pages."""
    pages = []
    for start in range(0, max_pages, 4):
        data = drv.mifare_ul_read(start)
        if data is None:
            for _ in range(min(4, max_pages - start)):
                pages.append(None)
        else:
            for j in range(min(4, max_pages - start)):
                pages.append(data[j*4:(j+1)*4])
    return pages


def detect_ntag_type(pages: List[Optional[bytes]]) -> str:
    """Detect NTAG variant from capability container (page 3)."""
    if len(pages) < 4 or pages[3] is None:
        return "Ultralight"
    cc = pages[3]
    size_byte = cc[2] if len(cc) > 2 else 0
    if size_byte == 0x12:
        return "NTAG213 (144B)"
    if size_byte == 0x3E:
        return "NTAG215 (504B)"
    if size_byte == 0x6D:
        return "NTAG216 (888B)"
    if size_byte == 0x06:
        return "Ultralight (64B)"
    if size_byte == 0x24:
        return "Ultralight C (192B)"
    return f"UL/NTAG ({size_byte * 8}B)"


def ntag_user_pages(pages: List[Optional[bytes]]) -> int:
    """Return number of user-writable pages based on NTAG type."""
    if len(pages) < 4 or pages[3] is None:
        return 16
    cc = pages[3]
    size_byte = cc[2] if len(cc) > 2 else 0
    if size_byte == 0x12:
        return 39   # NTAG213: pages 4-39
    if size_byte == 0x3E:
        return 130  # NTAG215: pages 4-130
    if size_byte == 0x6D:
        return 226  # NTAG216: pages 4-226
    return 12       # Ultralight: pages 4-15


# --- Dump management ---

def save_dump(uid: bytes, card_type: str, data: dict) -> str:
    """Save card dump. Returns filename."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    uid_hex = uid.hex().upper()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"nfc_{uid_hex}_{ts}.json"
    dump = {
        "uid": uid_hex,
        "uid_bytes": list(uid),
        "type": card_type,
        "timestamp": ts,
    }
    dump.update(data)
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump(dump, f, indent=2)
    return fname


def list_dumps() -> List[dict]:
    """List all saved card dumps."""
    if not os.path.isdir(LOOT_DIR):
        return []
    result = []
    for f in sorted(os.listdir(LOOT_DIR), reverse=True):
        if f.startswith("nfc_") and f.endswith(".json"):
            path = os.path.join(LOOT_DIR, f)
            try:
                with open(path) as fh:
                    d = json.load(fh)
                result.append({
                    "file": f, "path": path,
                    "uid": d.get("uid", "?"),
                    "type": d.get("type", "?"),
                    "timestamp": d.get("timestamp", ""),
                    "sectors": len(d.get("sectors", [])),
                    "pages": len(d.get("pages", [])),
                })
            except Exception:
                pass
    return result


def load_dump(path: str) -> Optional[dict]:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def export_flipper_nfc(dump: dict) -> Optional[str]:
    """Export dump in Flipper Zero .nfc format. Returns filepath or None."""
    uid = dump.get("uid", "")
    card_type = dump.get("type", "")
    if not uid:
        return None
    os.makedirs(LOOT_DIR, exist_ok=True)
    fname = f"{uid}.nfc"
    path = os.path.join(LOOT_DIR, fname)

    lines = [
        "Filetype: Flipper NFC device",
        "Version: 4",
        f"Device type: {'MIFARE Classic' if 'Classic' in card_type else 'NTAG/Ultralight'}",
        f"UID: {' '.join(uid[i:i+2] for i in range(0, len(uid), 2))}",
    ]

    sectors = dump.get("sectors", [])
    if sectors:
        lines.append(f"Mifare Classic type: {'1K' if len(sectors) <= 16 else '4K'}")
        for sec in sectors:
            sec_num = sec.get("sector", 0)
            blocks = sec.get("blocks", [])
            for i, blk in enumerate(blocks):
                block_num = sec_num * 4 + i
                if isinstance(blk, str) and len(blk) == 32:
                    hex_spaced = " ".join(blk[j:j+2] for j in range(0, 32, 2))
                    lines.append(f"Block {block_num}: {hex_spaced}")

    pages = dump.get("pages", [])
    if pages:
        for i, page in enumerate(pages):
            if page:
                hex_spaced = " ".join(page[j:j+2] for j in range(0, len(page), 2))
                lines.append(f"Page {i}: {hex_spaced}")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path
