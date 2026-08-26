"""EMV contactless card reader for ST25R3916.

Ported from Flipper Zero Momentum firmware:
  lib/nfc/protocols/emv/emv_poller_i.c
  lib/nfc/protocols/emv/emv.h

Reads payment card data via ISO14443-4: card number (PAN), expiry,
cardholder name, AID, application label, transaction logs.
"""

from typing import Optional, List, Dict, Any


# ── Known AIDs ───────────────────────────────────────────────────────────

KNOWN_AIDS = {
    bytes.fromhex("A0000000041010"): "Mastercard",
    bytes.fromhex("A0000000042010"): "Mastercard (Maestro)",
    bytes.fromhex("A0000000043060"): "Mastercard (Maestro)",
    bytes.fromhex("A0000000044010"): "Mastercard (Maestro UK)",
    bytes.fromhex("A0000000031010"): "Visa",
    bytes.fromhex("A0000000032010"): "Visa Electron",
    bytes.fromhex("A0000000032020"): "Visa V Pay",
    bytes.fromhex("A0000000033010"): "Visa Interlink",
    bytes.fromhex("A0000000034010"): "Visa Specific",
    bytes.fromhex("A0000000035010"): "Visa Specific",
    bytes.fromhex("A0000000036010"): "Visa Specific",
    bytes.fromhex("A0000000036020"): "Visa Specific",
    bytes.fromhex("A0000000038010"): "Visa Plus",
    bytes.fromhex("A00000002501"): "Amex",
    bytes.fromhex("A000000025010104"): "Amex",
    bytes.fromhex("A000000025010701"): "Amex (Expresspay)",
    bytes.fromhex("A000000065"): "JCB",
    bytes.fromhex("A0000000651010"): "JCB",
    bytes.fromhex("A0000001523010"): "Discover",
    bytes.fromhex("A0000001524010"): "Discover",
    bytes.fromhex("A0000003241010"): "Discover",
    bytes.fromhex("A0000003710001"): "Interac (Debit)",
    bytes.fromhex("D27600002545500100"): "NDEF",
    bytes.fromhex("D276000085010100"): "Transport",
    bytes.fromhex("A00000000401"): "Mastercard (short)",
    bytes.fromhex("A00000000301"): "Visa (short)",
    bytes.fromhex("A000000042"): "CB (Cartes Bancaires)",
    bytes.fromhex("A0000000421010"): "CB (Cartes Bancaires)",
    bytes.fromhex("A0000000422010"): "CB (Cartes Bancaires Debit)",
    bytes.fromhex("A0000000423010"): "CB (Cartes Bancaires)",
    bytes.fromhex("A0000000424010"): "CB (Cartes Bancaires)",
    bytes.fromhex("A0000001141010"): "Bancontact",
    bytes.fromhex("A0000003591010"): "Euro Alliance (EAPS)",
    bytes.fromhex("A0000000043010"): "Mastercard (Debit)",
    bytes.fromhex("A0000000046000"): "Mastercard (Cirrus)",
    bytes.fromhex("A0000001211010"): "Dankort",
    bytes.fromhex("A0000000040010"): "Mastercard (Specific)",
    bytes.fromhex("315041592E5359532E4444463031"): "PPSE (2PAY.SYS.DDF01)",
}


# ── EMV TLV Tags ─────────────────────────────────────────────────────────

TAG_AID = 0x4F
TAG_PRIORITY = 0x87
TAG_APPL_LABEL = 0x50
TAG_APPL_NAME = 0x9F12
TAG_PDOL = 0x9F38
TAG_AFL = 0x94
TAG_GPO_FMT1 = 0x80
TAG_PAN = 0x5A
TAG_EXP_DATE = 0x5F24
TAG_EFFECTIVE = 0x5F25
TAG_CARDHOLDER_NAME = 0x5F20
TAG_CARDHOLDER_NAME_EXT = 0x9F0B
TAG_COUNTRY_CODE = 0x5F28
TAG_CURRENCY_CODE = 0x9F42
TAG_TRACK2_EQUIV = 0x57
TAG_TRACK2_DATA = 0x9F6B
TAG_TRACK1_EQUIV = 0x56
TAG_LOG_ENTRY = 0x9F4D
TAG_LOG_FMT = 0x9F4F
TAG_PIN_TRY = 0x9F17
TAG_ATC = 0x9F36
TAG_LAST_ONLINE_ATC = 0x9F13
TAG_AIP = 0x82
TAG_LOG_AMOUNT = 0x9F02
TAG_LOG_COUNTRY = 0x9F1A
TAG_LOG_CURRENCY = 0x5F2A
TAG_LOG_DATE = 0x9A
TAG_LOG_TIME = 0x9F21
TAG_LANG_PREF = 0x5F2D

COUNTRY_NAMES = {
    0x0036: "Australia", 0x0056: "Belgium", 0x0076: "Brazil", 0x0124: "Canada",
    0x0156: "China", 0x0203: "Czech Rep.", 0x0208: "Denmark", 0x0246: "Finland",
    0x0250: "France", 0x0276: "Germany", 0x0300: "Greece", 0x0344: "Hong Kong",
    0x0348: "Hungary", 0x0356: "India", 0x0372: "Ireland", 0x0376: "Israel",
    0x0380: "Italy", 0x0392: "Japan", 0x0410: "South Korea", 0x0442: "Luxembourg",
    0x0458: "Malaysia", 0x0484: "Mexico", 0x0528: "Netherlands", 0x0554: "New Zealand",
    0x0578: "Norway", 0x0616: "Poland", 0x0620: "Portugal", 0x0642: "Romania",
    0x0643: "Russia", 0x0702: "Singapore", 0x0710: "South Africa", 0x0724: "Spain",
    0x0752: "Sweden", 0x0756: "Switzerland", 0x0764: "Thailand", 0x0792: "Turkey",
    0x0804: "Ukraine", 0x0826: "UK", 0x0840: "USA", 0x0978: "EU",
}

CURRENCY_NAMES = {
    0x0036: "AUD", 0x0124: "CAD", 0x0156: "CNY", 0x0203: "CZK",
    0x0208: "DKK", 0x0348: "HUF", 0x0356: "INR", 0x0376: "ILS",
    0x0392: "JPY", 0x0410: "KRW", 0x0458: "MYR", 0x0484: "MXN",
    0x0554: "NZD", 0x0578: "NOK", 0x0616: "PLN", 0x0643: "RUB",
    0x0702: "SGD", 0x0710: "ZAR", 0x0752: "SEK", 0x0756: "CHF",
    0x0764: "THB", 0x0792: "TRY", 0x0826: "GBP", 0x0840: "USD",
    0x0978: "EUR", 0x0985: "PLN", 0x0986: "BRL",
}

def country_name(code):
    return COUNTRY_NAMES.get(code, "%04X" % code)

def currency_name(code):
    return CURRENCY_NAMES.get(code, "%04X" % code)


# ── PDOL terminal values ─────────────────────────────────────────────────

PDOL_VALUES = {
    0x9F59: bytes([0xC8, 0x80, 0x00]),
    0x9F5A: bytes([0x00]),
    0x9F58: bytes([0x01]),
    0x9F66: bytes([0x79, 0x00, 0x40, 0x80]),
    0x9F40: bytes([0x79, 0x00, 0x40, 0x80]),
    0x9F02: bytes([0x00, 0x00, 0x00, 0x10, 0x00, 0x00]),
    0x9F03: bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    0x9F1A: bytes([0x01, 0x24]),
    0x5F2A: bytes([0x01, 0x24]),
    0x95:   bytes([0x00, 0x00, 0x00, 0x00, 0x00]),
    0x9A:   bytes([0x19, 0x01, 0x01]),
    0x9C:   bytes([0x00]),
    0x98:   bytes(20),
    0x9F37: bytes([0x82, 0x3D, 0xDE, 0x7A]),
}


# ── TLV parser ────────────────────────────────────────────────────────────

def parse_tlv(data: bytes) -> List[Dict[str, Any]]:
    """Parse BER-TLV encoded data. Returns list of {tag, length, value}."""
    result = []
    i = 0
    while i < len(data):
        if data[i] == 0x00 or data[i] == 0xFF:
            i += 1
            continue
        tag = data[i]
        i += 1
        if (tag & 0x1F) == 0x1F:
            if i >= len(data):
                break
            tag = (tag << 8) | data[i]
            i += 1
            while i < len(data) and data[i - 1] & 0x80:
                tag = (tag << 8) | data[i]
                i += 1
        if i >= len(data):
            break
        length = data[i]
        i += 1
        if length & 0x80:
            n_bytes = length & 0x7F
            length = 0
            for _ in range(n_bytes):
                if i >= len(data):
                    break
                length = (length << 8) | data[i]
                i += 1
        if i + length > len(data):
            length = len(data) - i
        value = data[i:i + length]
        i += length
        entry = {"tag": tag, "length": len(value), "value": value}
        if tag & 0x20 if tag < 0x100 else (tag >> 8) & 0x20:
            entry["children"] = parse_tlv(value)
        result.append(entry)
    return result


def find_tag(tlv_list: List[Dict], tag: int) -> Optional[bytes]:
    """Recursively find a tag value in parsed TLV."""
    for entry in tlv_list:
        if entry["tag"] == tag:
            return entry["value"]
        if "children" in entry:
            found = find_tag(entry["children"], tag)
            if found is not None:
                return found
    return None


def find_all_tags(tlv_list: List[Dict], tag: int) -> List[bytes]:
    """Find all occurrences of a tag."""
    results = []
    for entry in tlv_list:
        if entry["tag"] == tag:
            results.append(entry["value"])
        if "children" in entry:
            results.extend(find_all_tags(entry["children"], tag))
    return results


# ── EMV Data class ────────────────────────────────────────────────────────

class EMVData:
    """Holds parsed EMV card data."""

    def __init__(self):
        self.aid = b""
        self.aid_name = ""
        self.app_label = ""
        self.app_name = ""
        self.pan = ""
        self.pan_raw = b""
        self.exp_month = 0
        self.exp_year = 0
        self.cardholder_name = ""
        self.country_code = 0
        self.currency_code = 0
        self.effective_month = 0
        self.effective_year = 0
        self.language = ""
        self.pin_try_counter = -1
        self.atc = 0
        self.last_online_atc = 0
        self.pdol_raw = b""
        self.afl_raw = b""
        self.transactions = []
        self.raw_tlv = []

    def _decode_pan(self, raw: bytes) -> str:
        """Decode BCD-encoded PAN."""
        digits = ""
        for b in raw:
            hi = (b >> 4) & 0x0F
            lo = b & 0x0F
            if hi <= 9:
                digits += str(hi)
            if lo <= 9:
                digits += str(lo)
        return digits.rstrip("F").rstrip("f")

    def parse_response(self, data: bytes):
        """Parse an EMV TLV response and extract known fields."""
        tlv = parse_tlv(data)
        self.raw_tlv.extend(tlv)
        self._extract_fields(tlv)

    def _extract_fields(self, tlv: List[Dict]):
        aid = find_tag(tlv, TAG_AID)
        if aid:
            self.aid = bytes(aid)
            self.aid_name = KNOWN_AIDS.get(self.aid, self.aid.hex().upper())

        label = find_tag(tlv, TAG_APPL_LABEL)
        if label:
            self.app_label = label.decode("ascii", errors="replace").rstrip("\x00")

        name = find_tag(tlv, TAG_APPL_NAME)
        if name:
            self.app_name = name.decode("ascii", errors="replace").rstrip("\x00")

        pan = find_tag(tlv, TAG_PAN)
        if pan:
            self.pan_raw = bytes(pan)
            self.pan = self._decode_pan(pan)

        for track_tag in (TAG_TRACK2_EQUIV, TAG_TRACK2_DATA):
            track = find_tag(tlv, track_tag)
            if track and not self.pan:
                self._parse_track2(track)

        exp = find_tag(tlv, TAG_EXP_DATE)
        if exp and len(exp) >= 2:
            self.exp_year = exp[0]
            self.exp_month = exp[1]

        holder = find_tag(tlv, TAG_CARDHOLDER_NAME) or find_tag(tlv, TAG_CARDHOLDER_NAME_EXT)
        if holder:
            self.cardholder_name = holder.decode("ascii", errors="replace").split("/")[0].strip()

        effective = find_tag(tlv, TAG_EFFECTIVE)
        if effective and len(effective) >= 2:
            self.effective_year = effective[0]
            self.effective_month = effective[1]

        country = find_tag(tlv, TAG_COUNTRY_CODE)
        if country and len(country) >= 2:
            self.country_code = (country[0] << 8) | country[1]

        currency = find_tag(tlv, TAG_CURRENCY_CODE)
        if currency and len(currency) >= 2:
            self.currency_code = (currency[0] << 8) | currency[1]

        lang = find_tag(tlv, 0x5F2D)
        if lang:
            self.language = lang.decode("ascii", errors="replace").strip()

        pdol = find_tag(tlv, TAG_PDOL)
        if pdol:
            self.pdol_raw = bytes(pdol)

        afl = find_tag(tlv, TAG_AFL)
        if afl:
            self.afl_raw = bytes(afl)

        gpo_fmt1 = find_tag(tlv, TAG_GPO_FMT1)
        if gpo_fmt1 and len(gpo_fmt1) > 2 and not self.afl_raw:
            self.afl_raw = bytes(gpo_fmt1[2:])

        pin = find_tag(tlv, TAG_PIN_TRY)
        if pin:
            self.pin_try_counter = pin[0]

        atc = find_tag(tlv, TAG_ATC)
        if atc and len(atc) >= 2:
            self.atc = (atc[0] << 8) | atc[1]

        latc = find_tag(tlv, TAG_LAST_ONLINE_ATC)
        if latc and len(latc) >= 2:
            self.last_online_atc = (latc[0] << 8) | latc[1]

        log = find_tag(tlv, TAG_LOG_ENTRY)
        if log and len(log) >= 2:
            self._log_sfi = log[0]
            self._log_records = log[1]

    def _parse_track2(self, track: bytes):
        digits = ""
        for b in track:
            hi = (b >> 4) & 0x0F
            lo = b & 0x0F
            c_hi = str(hi) if hi <= 9 else chr(ord("A") + hi - 10)
            c_lo = str(lo) if lo <= 9 else chr(ord("A") + lo - 10)
            digits += c_hi + c_lo
        sep = digits.find("D")
        if sep > 0:
            self.pan = digits[:sep].rstrip("F")
            if sep + 4 < len(digits):
                try:
                    self.exp_year = int(digits[sep+1:sep+3])
                    self.exp_month = int(digits[sep+3:sep+5])
                except ValueError:
                    pass

    def __repr__(self):
        parts = []
        if self.pan:
            parts.append(f"PAN={self.pan}")
        if self.exp_month:
            parts.append(f"Exp={self.exp_month:02d}/{self.exp_year:02d}")
        if self.cardholder_name:
            parts.append(f"Name={self.cardholder_name}")
        if self.app_label:
            parts.append(f"App={self.app_label}")
        if self.aid_name:
            parts.append(f"AID={self.aid_name}")
        return f"EMVData({', '.join(parts)})"


# ── EMV Reader ────────────────────────────────────────────────────────────

class EMVReader:
    """EMV contactless card reader using ISO14443-4."""

    def __init__(self, iso_layer):
        """iso_layer: ISO14443_4 instance (already activated with ATS)."""
        self._iso = iso_layer
        self.data = EMVData()

    def _apdu(self, cla, ins, p1, p2, data=b"", le=0x00) -> Optional[bytes]:
        cmd = bytes([cla, ins, p1, p2])
        if data:
            cmd += bytes([len(data)]) + data
        cmd += bytes([le])
        resp = self._iso.send_apdu(cmd)
        if resp is None:
            return None
        if len(resp) >= 2:
            sw1, sw2 = resp[-2], resp[-1]
            if sw1 == 0x90 and sw2 == 0x00:
                return resp[:-2]
            if sw1 == 0x61:
                return resp[:-2]
            if sw1 == 0x6C:
                cmd2 = bytes([cla, ins, p1, p2, sw2])
                resp2 = self._iso.send_apdu(cmd2)
                if resp2 and len(resp2) >= 2:
                    return resp2[:-2]
            return resp[:-2] if len(resp) > 2 else None
        return resp

    def select_ppse(self) -> bool:
        """Select PPSE (2PAY.SYS.DDF01)."""
        ppse = b"2PAY.SYS.DDF01"
        resp = self._apdu(0x00, 0xA4, 0x04, 0x00, ppse)
        if resp is None:
            return False
        self.data.parse_response(resp)
        return bool(self.data.aid)

    def select_application(self, aid: bytes = None) -> bool:
        """Select EMV application by AID."""
        if aid is None:
            aid = self.data.aid
        if not aid:
            return False
        resp = self._apdu(0x00, 0xA4, 0x04, 0x00, aid)
        if resp is None:
            return False
        self.data.parse_response(resp)
        return True

    def get_processing_options(self) -> bool:
        """Send GET PROCESSING OPTIONS with PDOL data."""
        pdol_data = self._prepare_pdol()
        gpo_data = bytes([0x83, len(pdol_data)]) + pdol_data
        resp = self._apdu(0x80, 0xA8, 0x00, 0x00, gpo_data)
        if resp is None:
            return False
        self.data.parse_response(resp)
        return True

    def _prepare_pdol(self) -> bytes:
        """Build PDOL data from card's requested tags."""
        if not self.data.pdol_raw:
            return b""
        result = bytearray()
        i = 0
        raw = self.data.pdol_raw
        while i < len(raw):
            tag = raw[i]
            i += 1
            if (tag & 0x1F) == 0x1F and i < len(raw):
                tag = (tag << 8) | raw[i]
                i += 1
            if i >= len(raw):
                break
            tlen = raw[i]
            i += 1
            known = PDOL_VALUES.get(tag)
            if known:
                result.extend(known[:tlen])
                if len(known) < tlen:
                    result.extend(bytes(tlen - len(known)))
            else:
                result.extend(bytes(tlen))
        return bytes(result)

    def read_records(self) -> bool:
        """Read all SFI records from AFL."""
        if not self.data.afl_raw:
            return False
        afl = self.data.afl_raw
        for i in range(0, len(afl), 4):
            if i + 3 >= len(afl):
                break
            sfi = afl[i] >> 3
            rec_start = afl[i + 1]
            rec_end = afl[i + 2]
            for rec in range(rec_start, rec_end + 1):
                resp = self._read_record(sfi, rec)
                if resp:
                    self.data.parse_response(resp)
        return bool(self.data.pan)

    def _read_record(self, sfi: int, record: int) -> Optional[bytes]:
        sfi_param = (sfi << 3) | 0x04
        return self._apdu(0x00, 0xB2, record, sfi_param)

    def get_pin_try_counter(self) -> int:
        resp = self._apdu(0x80, 0xCA, 0x9F, 0x17)
        if resp:
            self.data.parse_response(resp)
            if self.data.pin_try_counter < 0 and len(resp) >= 1:
                self.data.pin_try_counter = resp[-1]
        return self.data.pin_try_counter

    def get_last_online_atc(self) -> int:
        resp = self._apdu(0x80, 0xCA, 0x9F, 0x13)
        if resp:
            self.data.parse_response(resp)
        return self.data.last_online_atc

    def get_atc(self) -> int:
        resp = self._apdu(0x80, 0xCA, 0x9F, 0x36)
        if resp:
            self.data.parse_response(resp)
        return self.data.atc

    def read_card(self) -> Optional[EMVData]:
        """Full card read sequence: PPSE → SELECT → GPO → READ RECORDS.

        Returns EMVData with all extracted fields, or None on failure.
        """
        if not self.select_ppse():
            return None
        if not self.select_application():
            return None
        self.get_processing_options()
        self.read_records()
        self.get_pin_try_counter()
        self.get_atc()
        self.get_last_online_atc()
        return self.data
