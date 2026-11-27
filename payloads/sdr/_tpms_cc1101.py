"""
Multi-brand TPMS decoders for the RaspyJack CC1101 Cap — faithful Python port of
Evil-Cardputer's src/tpms_multi.h (itself ported from rtl_433 / Flipper / Bruce
PR #2675).

Pipeline (identical to the C source):
    signed-µs pulse list  ->  oversampled half-bit bitmap (@ te)
    ->  seek preamble/sync  ->  line-code / differential-Manchester
    ->  CRC / checksum  ->  plausibility bounds  ->  fields.

The CC1101 driver's capture_raw() already returns the exact signed-int duration
convention this expects (+ = carrier/high, - = low), so the dispatcher consumes
a RaspyJack capture directly:

    from payloads.sdr._tpms_cc1101 import tpms_multi_decode
    hit = tpms_multi_decode(radio.capture_raw(duration_s=2.0))
    if hit: print(hit["model"], hit["id_hex"], hit["pressure_kpa"], hit["temp_c"])

Each decoder returns a dict or None:
    {model, protocol, id, id_hex, pressure_kpa, pressure_bar, temp_c,
     battery, flags, cnt, fix, bits, te, preset, raw}

OOK protocols use preset "Ook270Async"; FSK ones "2FSKDev238Async" / "...476Async"
— capture them with the matching modulation (2-FSK for BMW/Mercedes/Porsche/… and
the FSK TRW/Ford/Renault families, OOK for Schrader/GM/TRW-OOK/TyreGuard/…).

This module is self-contained: it reuses nothing from _cc1101_protocols.py and
does not touch RaspyJack's existing feed-based "Schrader GG4" decoder.
"""

# ──────────────────────────────── Helpers ──────────────────────────────────

_BITS_CAP = 8192
_COUNT_CAP = 64


def _durations_to_bitmap(durations, te):
    """Signed-µs pulse list -> oversampled half-bit bitmap (list of 0/1)."""
    bits = []
    half = te // 2
    for raw in durations:
        level = 1 if raw > 0 else 0
        dur = raw if raw > 0 else -raw
        count = (dur + half) // te
        if count == 0:
            count = 1
        if count > _COUNT_CAP:
            count = _COUNT_CAP
        for _ in range(count):
            if len(bits) >= _BITS_CAP:
                break
            bits.append(level)
        if len(bits) >= _BITS_CAP:
            break
    return bits


def _seek(bits, start, maxbits, pattern):
    pat = [1 if c == '1' else 0 for c in pattern]
    patlen = len(pat)
    if patlen == 0 or start + patlen > maxbits:
        return None
    end = maxbits - patlen
    i = start
    while i <= end:
        if bits[i:i + patlen] == pat:
            return i
        i += 1
    return None


def _line_code(buflen, bits, offset, maxbits, zero_pat, one_pat):
    """Manchester line-code decode. Returns (bytearray(buflen), nbits)."""
    zp = [1 if c == '1' else 0 for c in zero_pat]
    op = [1 if c == '1' else 0 for c in one_pat]
    if len(zp) != len(op):
        return bytearray(buflen), 0
    symlen = len(zp)
    bitpos = 0
    byte_pos = 0
    buf = bytearray(buflen)
    while offset + symlen <= maxbits and byte_pos < buflen:
        seg = bits[offset:offset + symlen]
        if seg == zp:
            buf[byte_pos] = ((buf[byte_pos] << 1) | 0) & 0xFF
        elif seg == op:
            buf[byte_pos] = ((buf[byte_pos] << 1) | 1) & 0xFF
        else:
            break
        bitpos += 1
        offset += symlen
        if bitpos == 8:
            bitpos = 0
            byte_pos += 1
    return buf, byte_pos * 8 + bitpos


def _diff_manch(buflen, bits, offset, maxbits, previous):
    """Differential-Manchester decode. Returns (bytearray(buflen), nbits)."""
    prev = 1 if previous else 0
    bitpos = 0
    byte_pos = 0
    buf = bytearray(buflen)
    while offset + 2 <= maxbits and byte_pos < buflen:
        start_level = bits[offset]
        mid_level = bits[offset + 1]
        bit_val = 0 if (start_level != prev) else 1
        prev = mid_level
        buf[byte_pos] = ((buf[byte_pos] << 1) | bit_val) & 0xFF
        bitpos += 1
        offset += 2
        if bitpos == 8:
            bitpos = 0
            byte_pos += 1
    return buf, byte_pos * 8 + bitpos


def _crc8(data, length, init, poly):
    crc = init & 0xFF
    for i in range(length):
        crc ^= data[i]
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if (crc & 0x80) else (crc << 1) & 0xFF
    return crc


def _crc16_1021(data, length, init):
    """CRC-16/CCITT MSB-first, poly 0x1021 (BMW G3, Porsche, Sefis M3)."""
    rem = init & 0xFFFF
    for i in range(length):
        rem ^= (data[i] << 8) & 0xFFFF
        for _ in range(8):
            rem = ((rem << 1) ^ 0x1021) & 0xFFFF if (rem & 0x8000) else (rem << 1) & 0xFFFF
    return rem


def _abarth_crc16_ccitt(data, length):
    """CRC-16/CCITT-FALSE poly 0x1021 init 0xffff (Abarth Q85)."""
    return _crc16_1021(data, length, 0xFFFF)


def _jansite_crc16_buypass(data, length):
    """CRC-16/BUYPASS poly 0x8005 init 0x0000 (Jansite Solar)."""
    rem = 0x0000
    for i in range(length):
        rem ^= (data[i] << 8) & 0xFFFF
        for _ in range(8):
            rem = ((rem << 1) ^ 0x8005) & 0xFFFF if (rem & 0x8000) else (rem << 1) & 0xFFFF
    return rem


def _reverse8(x):
    x = ((x & 0xF0) >> 4) | ((x & 0x0F) << 4)
    x = ((x & 0xCC) >> 2) | ((x & 0x33) << 2)
    x = ((x & 0xAA) >> 1) | ((x & 0x55) << 1)
    return x & 0xFF


def _crc7(msg, nbytes, poly, init):
    """rtl_433 crc7 (7-bit register, >>1 result)."""
    remainder = (init << 1) & 0xFFFF
    p = (poly << 1) & 0xFFFF
    for byte in range(nbytes):
        remainder ^= msg[byte]
        for _ in range(8):
            remainder = ((remainder << 1) ^ p) & 0xFFFF if (remainder & 0x80) else (remainder << 1) & 0xFFFF
    return (remainder >> 1) & 0x7F


def _sane_a(kpa, temp):
    return 0.0 <= kpa <= 800.0 and -50 <= temp <= 110


def _sane_b(kpa, temp):
    return 0.0 <= kpa <= 900.0 and -50 <= temp <= 150


def _result(protocol, serial, kpa, temp, bit, te, preset, raw, raw_len,
            btn=0, cnt=0, fix=0, battery=None, key=0):
    serial &= 0xFFFFFFFF
    return {
        "model": protocol,
        "protocol": protocol,
        "id": serial,
        "id_hex": "%08X" % serial,
        "key": key,
        "pressure_kpa": round(float(kpa), 1),
        "pressure_bar": round(float(kpa) / 100.0, 2),
        "temp_c": int(temp),
        "battery": battery,
        "flags": btn,
        "cnt": cnt,
        "fix": fix,
        "bits": bit,
        "te": te,
        "preset": preset,
        "raw": bytes(raw[:raw_len]),
    }


# ───────────────────────── Batch 0 : originals ──────────────────────────────

def rf_decode_schrader(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 120)
    if len(bits) < 64:
        return None
    off = _seek(bits, 0, len(bits), "1111010101" "01011010")
    if off is None:
        return None
    off += 10
    raw, nb = _line_code(8, bits, off, len(bits), "01", "10")
    if nb < 64:
        return None
    raw[0] |= 0xF0
    if _crc8(raw, 7, 0xF0, 0x07) != raw[7]:
        return None
    kpa = raw[5] * 2.5
    temp = raw[6] - 50
    id_val = ((raw[1] & 0x0F) << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    return _result("Schrader", id_val, kpa, temp, 64, 120, "Ook270Async", raw, 8)


def rf_decode_ford(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 64:
        return None
    off = _seek(bits, 0, len(bits), "010101010101" "0110")
    if off is None:
        return None
    off += 16
    raw, nb = _line_code(8, bits, off, len(bits), "01", "10")
    if nb < 64:
        return None
    crc = 0
    for j in range(7):
        crc = (crc + raw[j]) & 0xFF
    if crc != raw[7]:
        return None
    st = raw[6] & 0x4C
    if st != 0x08 and st != 0x04 and st != 0x44:
        return None
    if raw[6] & 0x90:
        return None
    psi = 0.25 * (((raw[6] & 0x20) << 3) | raw[4])
    temp = 0 if (raw[5] & 0x80) else raw[5] - 56
    flags = raw[5] & 0x7F
    id_val = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    return _result("Ford", id_val, psi * 6.89476, temp, 64, 52, "2FSKDev238Async",
                   raw, 8, btn=flags & 0x7F)


def rf_decode_renault(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 80:
        return None
    off = _seek(bits, 0, len(bits), "01010101010101010110")
    if off is None:
        return None
    off += 20
    raw, nb = _line_code(9, bits, off, len(bits), "01", "10")
    if nb < 72:
        return None
    if _crc8(raw, 8, 0, 7) != raw[8]:
        return None
    flags = raw[0] >> 2
    kpa = 0.75 * (((raw[0] & 3) << 8) | raw[1])
    temp = raw[2] - 30
    id_val = (raw[5] << 16) | (raw[4] << 8) | raw[3]
    return _result("Renault", id_val, kpa, temp, 72, 52, "2FSKDev238Async",
                   raw, 9, btn=flags)


def rf_decode_citroen(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 80:
        return None
    off = _seek(bits, 0, len(bits), "01010101010101010")
    if off is None:
        return None
    off += 17
    raw, nb = _line_code(10, bits, off, len(bits), "01", "10")
    if nb < 80:
        return None
    crc = 0
    for j in range(1, 10):
        crc ^= raw[j]
    if crc != 0:
        return None
    if raw[6] == 0 or raw[7] == 0:
        return None
    repeat = raw[5] & 0xF
    kpa = raw[6] * 1.364
    temp = raw[7] - 50
    battery = raw[8]
    id_val = (raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    return _result("Citroen", id_val, kpa, temp, 80, 52, "2FSKDev238Async",
                   raw, 10, cnt=repeat, fix=battery, battery=battery)


def rf_decode_toyota(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 128:
        return None
    sync = ["00111100", "001111100", "00111101", "001111101"]
    off = None
    chosen = None
    for s in sync:
        off = _seek(bits, 0, len(bits), s)
        if off is not None:
            off += len(s) - 2
            chosen = s
            break
    if off is None:
        return None
    raw, nb = _diff_manch(9, bits, off, len(bits), True)
    if nb < 72:
        return None
    if _crc8(raw, 8, 0x80, 7) != raw[8]:
        return None
    pressure1 = ((raw[4] & 0x7F) << 1) | (raw[5] >> 7)
    pressure2 = raw[7] ^ 0xFF
    if pressure1 != pressure2:
        return None
    psi = pressure1 * 0.25 - 7.0
    temp = (((raw[5] & 0x7F) << 1) | (raw[6] >> 7)) - 40
    id_val = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    return _result("Toyota", id_val, psi * 6.89476, temp, 72, 52, "2FSKDev238Async",
                   raw, 9)


# ──────────────────── Batch A : German / Continental ────────────────────────

def rf_decode_bmw(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 25)
    if len(bits) < 64:
        return None
    off = _seek(bits, 0, len(bits), "1010101001011001")
    if off is None:
        return None
    off += 16
    raw, nb = _line_code(11, bits, off, len(bits), "01", "10")
    if nb >= 88:
        len_msg = 11
    elif nb >= 64:
        len_msg = 8
    else:
        return None
    if _crc8(raw, len_msg - 1, 0xAA, 0x2F) != raw[len_msg - 1]:
        return None
    brand = raw[0]
    if brand not in (0x00, 0x03, 0x23, 0x80, 0x88):
        return None
    kpa = raw[5] * 2.45
    temp = raw[6] - 52
    if not _sane_a(kpa, temp):
        return None
    idv = (raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    if idv == 0:
        return None
    cp = min(len_msg, 10)
    return _result("BMW" if len_msg == 11 else "Audi", idv, kpa, temp,
                   len_msg * 8, 25, "2FSKDev476Async", raw, cp,
                   btn=(raw[7] if len_msg == 11 else 0),
                   cnt=(raw[8] if len_msg == 11 else 0), fix=brand)


def rf_decode_bmw_g3(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 160:
        return None
    off = _seek(bits, 0, len(bits), "1100110011001101")
    if off is None:
        return None
    data_start = off + 16
    if data_start + 2 >= len(bits):
        return None
    prev = bits[data_start]
    raw, nb = _diff_manch(11, bits, data_start + 1, len(bits), prev)
    if nb >= 88:
        msg_len = 11
    elif nb >= 80:
        msg_len = 10
    else:
        return None
    if _crc16_1021(raw, msg_len, 0x0000) != 0:
        return None
    kpa = (raw[4] - 43) * 2.5
    temp = raw[5] - 40
    if not _sane_a(kpa, temp):
        return None
    idv = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    if idv == 0:
        return None
    cp = min(msg_len, 10)
    return _result("BMW", idv, kpa, temp, msg_len * 8, 52, "2FSKDev476Async",
                   raw, cp, btn=raw[6], cnt=raw[7])


def rf_decode_mercedes_benz(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 25)
    if len(bits) < 160:
        return None
    off = _seek(bits, 0, len(bits), "0101010101011001")
    if off is None:
        return None
    off += 16
    raw, nb = _line_code(10, bits, off, len(bits), "01", "10")
    if nb < 80:
        return None
    if _crc8(raw, 9, 0xAA, 0x2F) != raw[9]:
        return None
    if raw[0] != 0x83 and raw[0] != 0xA3:
        return None
    psi = raw[5] / 2.75
    kpa = psi * 6.89476
    temp = raw[6] - 51
    if not _sane_a(kpa, temp):
        return None
    idv = (raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    if idv == 0:
        return None
    return _result("Mercedes", idv, kpa, temp, 80, 25, "2FSKDev476Async",
                   raw, 10, cnt=(raw[7] & 0x1F), btn=raw[8])


def rf_decode_porsche(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 160:
        return None
    bsz = len(bits)
    anchor = _seek(bits, 0, bsz, "0011001100110011")
    if anchor is None:
        return None
    scan_end = anchor + 56
    if scan_end + 2 >= bsz:
        scan_end = bsz - 2 if bsz >= 2 else 0
    raw = None
    for ds in range(anchor, scan_end + 1):
        prev = bits[ds]
        cand, nb = _diff_manch(10, bits, ds + 1, bsz, prev)
        if nb < 80:
            continue
        if _crc16_1021(cand, 10, 0xFFFF) == 0:
            raw = cand
            break
    if raw is None:
        return None
    kpa_i = raw[4] * 5 // 2 - 100
    temp = raw[5] - 40
    kpa = float(kpa_i)
    if not _sane_a(kpa, temp):
        return None
    idv = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    if idv == 0:
        return None
    return _result("Porsche", idv, kpa, temp, 80, 52, "2FSKDev476Async",
                   raw, 10, cnt=((raw[6] << 8) | raw[7]))


def rf_decode_hyundai_vdo(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 160:
        return None
    off = _seek(bits, 0, len(bits), "01010101010101010101010101010110")
    if off is None:
        return None
    off += 32
    raw, nb = _line_code(10, bits, off, len(bits), "01", "10")
    if nb < 80:
        return None
    if _crc8(raw, 9, 0xAA, 0x07) != raw[9]:
        return None
    if raw[6] == 0:
        return None
    kpa = raw[6] * 1.375
    temp = raw[7] - 50
    if not _sane_a(kpa, temp):
        return None
    idv = (raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    if idv == 0:
        return None
    return _result("Hyundai", idv, kpa, temp, 80, 52, "2FSKDev476Async",
                   raw, 10, btn=raw[0], cnt=(raw[5] & 0x0F), fix=raw[8], battery=raw[8])


def rf_decode_sefis_m3(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 160:
        return None
    off = _seek(bits, 0, len(bits), "01100110" "10011001" "10010110" "10100110")
    if off is None:
        return None
    off += 32
    raw, nb = _line_code(9, bits, off, len(bits), "01", "10")
    if nb < 72:
        return None
    crc = _crc16_1021(raw, 7, 0x0000)
    if crc != (((raw[7] << 8) | raw[8]) & 0xFFFF):
        return None
    page = {7: 0, 4: 1, 5: 2, 2: 3}.get(raw[4] >> 5, -1)
    kpa = 0.0
    if page >= 0:
        code = (page << 13) | ((raw[4] & 0x1F) << 8) | raw[5]
        kpa = (code - 0x0E00) / 102.4
        if kpa < 0.0:
            kpa = 0.0
    temp = 14 + (((raw[2] + raw[5]) & 0xFF) & 0x0F)
    if not _sane_a(kpa, temp):
        return None
    if not any(raw[i] for i in range(7)):
        return None
    pseudo_id = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    return _result("Sefis", pseudo_id, kpa, temp, 72, 52, "2FSKDev476Async",
                   raw, 9, cnt=(page if page >= 0 else 0))


# ──────────────────────── Batch B : US OEM / JDM ────────────────────────────

def rf_decode_gm(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 120)
    if len(bits) < 260:
        return None
    off = _seek(bits, 0, len(bits), "010101010101010101010101")
    if off is None:
        return None
    raw, nb = _line_code(17, bits, off, len(bits), "01", "10")
    if nb < 128:
        return None
    for i in range(6):
        if raw[i] != 0:
            return None
    s = 0
    all_zero = 1
    for i in range(6, 15):
        s = (s + raw[i]) & 0xFF
        all_zero &= (raw[i] == 0)
    if s != raw[15]:
        return None
    if all_zero and raw[15] == 0:
        return None
    flags = (raw[6] << 8) | raw[7]
    kpa = raw[13] * 2.75
    temp = raw[14] - 60
    if not _sane_b(kpa, temp):
        return None
    id64 = ((raw[8] << 32) | (raw[9] << 24) | (raw[10] << 16) | (raw[11] << 8) | raw[12])
    serial = (raw[9] << 24) | (raw[10] << 16) | (raw[11] << 8) | raw[12]
    battery_ok = 0 if ((flags >> 5) & 1) else 1
    return _result("GM", serial, kpa, temp, 130, 120, "Ook270Async",
                   raw[6:16], 10, fix=battery_ok, battery=battery_ok, key=id64)


def rf_decode_honda(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 50)
    if len(bits) < 151:
        return None
    off = _seek(bits, 0, len(bits), "11011010" "11100011" "0101010")
    if off is None:
        return None
    off += 23
    raw, nb = _line_code(8, bits, off, len(bits), "10", "01")
    if nb < 64:
        return None
    if _crc8(raw, 7, 0x00, 0x07) != raw[7]:
        return None
    pressure_raw = raw[0]
    if 0 < pressure_raw < 50:
        return None
    kpa = pressure_raw * 0.2 * 6.89476
    temp = raw[1] - 50
    if not _sane_b(kpa, temp):
        return None
    if not any(raw[i] for i in range(8)):
        return None
    idv = (raw[2] << 24) | (raw[3] << 16) | (raw[4] << 8) | raw[5]
    return _result("Honda", idv, kpa, temp, 64, 50, "2FSKDev238Async",
                   raw, 8, btn=raw[6])


def rf_decode_kia(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 50)
    if len(bits) < 154:
        return None
    off = _seek(bits, 0, len(bits), "11101101" "01110001")
    if off is None:
        return None
    off += 16
    raw, nb = _line_code(9, bits, off, len(bits), "10", "01")
    if nb < 69:
        return None
    kbits = nb - 64
    if kbits > 8:
        kbits = 8
    b8 = (raw[8] << (8 - kbits)) & 0xF8
    if _crc8(raw, 8, 0x76, 0x07) != b8:
        return None
    pressure = ((raw[0] << 4) | (raw[1] >> 4)) & 0xFF
    temperature = ((raw[1] << 4) | (raw[2] >> 4)) & 0xFF
    kpa = pressure / 5.0 * 6.89476
    temp = temperature - 50
    if not _sane_b(kpa, temp):
        return None
    if not any(raw[i] for i in range(9)):
        return None
    idv = ((raw[2] << 28) | (raw[3] << 20) | (raw[4] << 12) | (raw[5] << 4) | (raw[6] >> 4))
    return _result("Kia", idv, kpa, temp, 69, 50, "2FSKDev238Async", raw, 9)


def _nissan_chk(b):
    chk = 0
    for i in range(4):
        chk = (chk + (b[i] >> 7)) & 0xFF
        chk = (chk + (b[i] >> 5)) & 0xFF
        chk = (chk + (b[i] >> 3)) & 0xFF
        chk = (chk + (b[i] >> 1)) & 0xFF
        chk = (chk + ((b[i] << 1) & 0xFF)) & 0xFF
    chk = (chk + (b[4] >> 7)) & 0xFF
    chk = (chk + (b[4] >> 5)) & 0xFF
    chk = (chk + (b[4] >> 3)) & 0xFF
    return (~chk) & 0x03


def rf_decode_nissan(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 120)
    if len(bits) < 110:
        return None
    off = _seek(bits, 0, len(bits),
                "11110101" "01010101" "01010101" "01010101" "1110")
    if off is None:
        return None
    off += 36
    raw, nb = _line_code(5, bits, off, len(bits), "01", "10")
    if nb < 37:
        return None
    lb = nb - 32
    if 0 < lb < 8:
        raw[4] = (raw[4] << (8 - lb)) & 0xFF
    if _nissan_chk(raw) != 0:
        return None
    mode = raw[0] >> 5
    idv = ((raw[0] & 0x1F) << 19) | (raw[1] << 11) | (raw[2] << 3) | (raw[3] >> 5)
    pressure_raw = ((raw[3] & 0x1F) << 3) | (raw[4] >> 5)
    psi = pressure_raw / 4.0 - 3.0
    kpa = psi * 6.89476
    if idv == 0:
        return None
    if kpa < 0.0 or kpa > 700.0:
        return None
    if all(raw[i] == raw[0] for i in range(1, 5)):
        return None
    return _result("Nissan", idv, kpa, 0, 37, 120, "2FSKDev238Async",
                   raw, 5, btn=mode)


def rf_decode_jeep(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 80:
        return None
    off = _seek(bits, 0, len(bits), "01010101010101010")
    if off is None:
        return None
    off += 17
    raw, nb = _line_code(10, bits, off, len(bits), "01", "10")
    if nb < 80:
        return None
    crc = 0
    for j in range(1, 10):
        crc ^= raw[j]
    if crc != 0:
        return None
    if raw[6] == 0 or raw[7] == 0:
        return None
    repeat = raw[5] & 0xF
    kpa = raw[6] * 2.728
    temp = raw[7] - 50
    battery = raw[8]
    if not _sane_b(kpa, temp):
        return None
    idv = (raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    return _result("Jeep", idv, kpa, temp, 80, 52, "2FSKDev238Async",
                   raw, 10, cnt=repeat, fix=battery, battery=battery, btn=(raw[5] >> 4))


def _trw_common(durations, preamble_raw, preset):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 190:
        return None
    off = _seek(bits, 0, len(bits), preamble_raw)
    if off is None:
        return None
    off += 32
    raw, nb = _line_code(11, bits, off, len(bits), "01", "10")
    if nb < 80:
        return None
    if _crc8(raw, 10, 0x00, 0x07) != 0:
        return None
    kpa = raw[6] * 0.4 * 6.89476
    temp = raw[7] - 50
    if not _sane_b(kpa, temp):
        return None
    if not any(raw[i] for i in range(10)):
        return None
    idv = (raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]
    return _result("TRW", idv, kpa, temp, 88, 52, preset, raw, 10,
                   btn=(raw[5] >> 4), cnt=(raw[5] & 0x0F), fix=raw[8])


def rf_decode_trw_ook(durations):
    return _trw_common(durations, "01010101010101010101010101010110", "Ook270Async")


def rf_decode_trw_fsk(durations):
    return _trw_common(durations, "01101010101010101010101010101010", "2FSKDev238Async")


# ─────────────────── Batch C : EU / PSA / misc OEM ──────────────────────────

def rf_decode_renault_0435r(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 160:
        return None
    off = _seek(bits, 0, len(bits), "0101010101010110")
    if off is None:
        return None
    off += 16
    raw, nb = _line_code(9, bits, off, len(bits), "01", "10")
    if nb < 72:
        return None
    x = 0
    for j in range(9):
        x ^= raw[j]
    if x != 0:
        return None
    has_tick = raw[8] >> 7
    tick = raw[8] & 0x7F
    if raw[8] and (not has_tick or tick > 30):
        return None
    if not raw[0] and not raw[1] and not raw[2]:
        return None
    temp = raw[5] - 50
    if temp < -50 or temp > 125:
        return None
    kpa = raw[4] / 0.75
    idv = (raw[0] << 16) | (raw[1] << 8) | raw[2]
    return _result("Renault-0435R", idv, kpa, temp, 72, 52, "2FSKDev238Async",
                   raw, 9, btn=raw[3], cnt=tick)


def rf_decode_abarth124(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 168:
        return None
    off = _seek(bits, 0, len(bits), "010101010101010101010110")
    if off is None:
        return None
    off += 24
    raw, nb = _line_code(12, bits, off, len(bits), "01", "10")
    if nb < 72:
        return None
    x = 0
    for j in range(9):
        x ^= raw[j]
    if x != 0:
        return None
    if not raw[0] and not raw[1] and not raw[2] and not raw[3]:
        return None
    press_raw = raw[5]
    temp_raw = raw[6]
    is_q85 = False
    if nb >= 96:
        crc_le = ((raw[11] << 8) | raw[10]) & 0xFFFF
        if _abarth_crc16_ccitt(raw, 10) == crc_le:
            is_q85 = True
    if is_q85:
        temp = temp_raw - 55
        if temp < -20 or temp > 80:
            return None
        kpa = press_raw * 3.0
        bit = 96
        proto = "Abarth-Q85"
    else:
        temp = temp_raw - 50
        if temp < -50 or temp > 125:
            return None
        kpa = press_raw * 1.38
        bit = 72
        proto = "Abarth-124"
    serial = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    n = 10 if is_q85 else 9
    return _result(proto, serial, kpa, temp, bit, 52, "2FSKDev238Async",
                   raw, n, btn=raw[7])


def rf_decode_elantra2012(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 49)
    if len(bits) < 144:
        return None
    off = _seek(bits, 0, len(bits), "0111000101010101")
    if off is None:
        return None
    off += 16
    raw, nb = _line_code(8, bits, off, len(bits), "10", "01")
    if nb < 64:
        return None
    if _crc8(raw, 8, 0x00, 0x07) != 0:
        return None
    if not raw[2] and not raw[3] and not raw[4] and not raw[5]:
        return None
    pressure = raw[0] + 60
    temp = raw[1] - 50
    if temp < -50 or temp > 125:
        return None
    serial = (raw[2] << 24) | (raw[3] << 16) | (raw[4] << 8) | raw[5]
    battery_ok = 0 if ((raw[6] & 0x02) >> 1) else 1
    return _result("Elantra2012", serial, float(pressure), temp, 64, 49,
                   "2FSKDev238Async", raw, 8, btn=raw[6], cnt=(raw[6] & 0x01),
                   fix=battery_ok, battery=battery_ok)


def rf_decode_pmv107j(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 100)
    if len(bits) < 139:
        return None
    base = _seek(bits, 0, len(bits), "111110")
    if base is None:
        return None
    off0 = base + 6
    if off0 + 1 >= len(bits):
        return None
    previous = bits[off0]
    dec, nb = _diff_manch(9, bits, off0 + 1, len(bits), previous)
    if nb < 66:
        return None
    d = [0] * 66
    fb = nb & ~7
    for i in range(66):
        if i < fb:
            d[i] = (dec[i >> 3] >> (7 - (i & 7))) & 1
        else:
            j = i - fb
            d[i] = (dec[nb >> 3] >> ((nb & 7) - 1 - j)) & 1
    b = [0] * 9
    b[0] = ((d[0] << 1) | d[1]) & 0xFF
    for k in range(8):
        v = 0
        for j in range(8):
            v = ((v << 1) | d[2 + k * 8 + j]) & 0xFF
        b[k + 1] = v
    if _crc8(b, 8, 0x00, 0x13) != b[8]:
        return None
    pressure1 = b[5]
    pressure2 = b[6] ^ 0xFF
    if pressure1 != pressure2:
        return None
    kpa = (pressure1 - 40.0) * 2.48
    temp = b[7] - 40
    idv = (b[0] << 26) | (b[1] << 18) | (b[2] << 10) | (b[3] << 2) | (b[4] >> 6)
    battery_ok = 0 if ((b[4] & 0x20) >> 5) else 1
    return _result("PMV-107J", idv, kpa, temp, 66, 100, "2FSKDev238Async",
                   b, 9, btn=(b[4] & 0x3F), cnt=((b[4] & 0x18) >> 3),
                   fix=battery_ok, battery=battery_ok)


def rf_decode_ave(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 100)
    if len(bits) < 161:
        return None
    base = _seek(bits, 0, len(bits), "11001100110011001100110011001101")
    if base is None:
        return None
    off0 = base + 32
    if off0 + 1 >= len(bits):
        return None
    previous = bits[off0]
    raw, nb = _diff_manch(8, bits, off0 + 1, len(bits), previous)
    if nb < 64:
        return None
    if _crc8(raw, 8, 0xFF, 0x31) != 0:
        return None
    if not raw[0] and not raw[1] and not raw[2] and not raw[3]:
        return None
    pressure_raw = raw[4]
    mode = (raw[6] >> 6) & 0x3
    battery_raw = (raw[6] >> 3) & 0x7
    if mode == 0:
        ratio, offset = 2.352, 47.0
    elif mode == 2:
        ratio, offset = 5.491, 18.2
    elif mode == 3:
        ratio, offset = 5.491, 0.0
    else:
        ratio, offset = 2.352, 0.0
    kpa = (pressure_raw - offset) * ratio
    temp = raw[5] - 50
    battery_pct = 100
    if battery_raw == 6:
        battery_pct = 75
    elif battery_raw == 7:
        battery_pct = 25
    serial = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    return _result("AVE", serial, kpa, temp, 64, 100, "2FSKDev238Async",
                   raw, 8, btn=(raw[6] & 0x7), cnt=mode, fix=battery_pct,
                   battery=battery_pct)


def rf_decode_truck(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 176:
        return None
    off = _seek(bits, 0, len(bits), "010101010101010101010110")
    if off is None:
        return None
    off += 24 + 8
    raw, nb = _line_code(9, bits, off, len(bits), "01", "10")
    if nb < 72:
        return None
    if not raw[0] and not raw[1] and not raw[2] and not raw[3]:
        return None
    x = 0
    for j in range(9):
        x ^= raw[j]
    if x != 0:
        return None
    pressure = ((raw[5] & 0x0F) << 8) | raw[6]
    if pressure > 1300:
        return None
    temp = raw[7] if raw[7] < 128 else raw[7] - 256
    wheel = raw[4]
    flags = raw[5] >> 4
    serial = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    battery_ok = 1 if ((flags & 0x3) == 0x3) else 0
    return _result("Truck", serial, float(pressure), temp, 72, 52,
                   "2FSKDev238Async", raw, 9, btn=wheel, cnt=flags,
                   fix=battery_ok, battery=battery_ok)


# ───────────────────── Batch D : Jansite family + aftermarket ────────────────

def rf_decode_jansite(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 112:
        return None
    off = _seek(bits, 0, len(bits), "010101010101010101010110")
    if off is None:
        return None
    off += 24
    raw, nb = _line_code(7, bits, off, len(bits), "01", "10")
    if nb < 56:
        return None
    idv = (raw[0] << 20) | (raw[1] << 12) | (raw[2] << 4) | (raw[3] >> 4)
    flags = raw[3] & 0x0F
    kpa = raw[4] * 1.7
    temp = raw[5] - 50
    if raw[4] == 0:
        return None
    if kpa <= 0.0 or kpa > 400.0:
        return None
    if temp < -40 or temp > 125:
        return None
    if idv == 0:
        return None
    return _result("Jansite", idv, kpa, temp, 56, 52, "2FSKDev238Async",
                   raw, 7, btn=flags)


def rf_decode_jansite_solar(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 51)
    if len(bits) < 176:
        return None
    off = _seek(bits, 0, len(bits), "101001101010011001011010")
    if off is None:
        return None
    raw, nb = _line_code(11, bits, off, len(bits), "01", "10")
    if nb < 88:
        return None
    if raw[0] != 0xDD or raw[1] != 0x33:
        return None
    crc = _jansite_crc16_buypass(raw[2:9], 7)
    if (((raw[9] << 8) | raw[10]) & 0xFFFF) != crc:
        return None
    idv = (raw[2] << 16) | (raw[3] << 8) | raw[4]
    flags = raw[5]
    temp = raw[6] - 55
    kpa = raw[7] * 1.6
    if temp < -50 or temp > 125:
        return None
    if kpa < 0.0 or kpa > 700.0:
        return None
    return _result("Jansite-Solar", idv, kpa, temp, 88, 51, "2FSKDev238Async",
                   raw, 10, btn=flags)


def rf_decode_jansite_ty468(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 50)
    if len(bits) < 128:
        return None
    off = _seek(bits, 0, len(bits), "101010101010101010101010")
    if off is None:
        return None
    off += 32
    raw, nb = _line_code(8, bits, off, len(bits), "01", "10")
    if nb < 64:
        return None
    if raw[7] != raw[0]:
        return None
    if (raw[0] & 0x0F) != (raw[1] & 0x0F):
        return None
    checksum = (raw[3] + raw[4]) & 0xFF
    if checksum == 0xFB:
        temp_off, pres_off = 224, 273
    elif checksum == 0x64:
        temp_off, pres_off = 153, 201
    else:
        return None
    temp = temp_off - ((raw[2] + raw[5]) & 0xFF)
    kpa = (pres_off - ((raw[5] + raw[6]) & 0xFF)) * 2.5
    if temp < -50 or temp > 125:
        return None
    if kpa < 0.0 or kpa > 700.0:
        return None
    serial = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    return _result("Jansite-TY468", serial, kpa, temp, 64, 50, "Ook270Async", raw, 8)


def rf_decode_jansite_ty588(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 51)
    if len(bits) < 128:
        return None
    off = _seek(bits, 0, len(bits), "100110011010101001011010")
    if off is None:
        return None
    off += 44
    raw, nb = _line_code(8, bits, off, len(bits), "10", "01")
    if nb < 64:
        return None
    if raw[7] != raw[0]:
        return None
    if ((raw[3] + raw[4]) & 0xFF) != 0x30:
        return None
    if (raw[0] & 0x0F) != (raw[1] & 0x0F):
        return None
    raw_temp = (raw[2] + raw[5]) & 0xFF
    raw_pres = (raw[5] + raw[6]) & 0xFF
    temp = raw_temp - 139
    pres_raw = raw_pres - 90
    if pres_raw < 0 or temp < -40 or temp > 120:
        return None
    kpa = pres_raw * 2.5
    serial = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    return _result("Jansite-TY588", serial, kpa, temp, 64, 51, "2FSKDev238Async", raw, 8)


def rf_decode_steelmate(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 50)
    if len(bits) < 112:
        return None
    off = _seek(bits, 0, len(bits), "01010110101010101010")
    if off is None:
        return None
    off += 4
    r, nb = _line_code(7, bits, off, len(bits), "01", "10")
    if nb < 56:
        return None
    b = [_reverse8((~r[i]) & 0xFF) for i in range(7)]
    if b[0] != 0x01:
        return None
    s = b[0] + b[1] + b[2] + b[3] + b[4] + b[5]
    if (s & 0xFF) != b[6]:
        return None
    idv = (b[1] << 8) | b[2]
    kpa = b[3] * 3.125
    temp = b[4] - 50
    if idv == 0 and b[3] == 0:
        return None
    if kpa < 0.0 or kpa > 900.0:
        return None
    if temp < -50 or temp > 125:
        return None
    return _result("Steelmate", idv, kpa, temp, 72, 50, "2FSKDev238Async",
                   b, 7, fix=b[5], battery=b[5])


def rf_decode_tyreguard400(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 100)
    if len(bits) < 176:
        return None
    off = _seek(bits, 0, len(bits),
                "10101010101001100110011010101010101001100110011010101010")
    if off is None:
        return None
    b, nb = _line_code(11, bits, off, len(bits), "01", "10")
    if nb < 88:
        return None
    if _crc8(b, 11, 0xDD, 0x31) != 0:
        return None
    flags = b[9]
    idv = ((b[3] & 0x0F) << 24) | (b[4] << 16) | (b[5] << 8) | b[6]
    pressure_kpa = b[7] | ((flags & 0x70) << 4)
    temp = b[8] - 40
    if temp < -50 or temp > 125:
        return None
    if pressure_kpa < 0 or pressure_kpa > 1200:
        return None
    if idv == 0:
        return None
    return _result("TyreGuard400", idv, float(pressure_kpa), temp, 88, 100,
                   "Ook270Async", b, 10, btn=flags)


# ──────────────────── Batch E : niche / aftermarket ─────────────────────────

def rf_decode_airpuxem(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 52)
    if len(bits) < 192:
        return None
    off = _seek(bits, 0, len(bits), "01010101010101010101" "0110")
    if off is None:
        return None
    off += 24
    buf, nb = _line_code(11, bits, off, len(bits), "01", "10")
    if nb < 84:
        return None
    if (buf[0] >> 4) != 0x5:
        return None
    payload = bytearray(8)
    for i in range(8):
        payload[i] = ((buf[i] << 4) | (buf[i + 1] >> 4)) & 0xFF
    crcbyte = ((buf[8] << 4) | (buf[9] >> 4)) & 0xFF
    if _crc8(payload, 8, 0xAA, 0x2F) != crcbyte:
        return None
    idv = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]
    flags = (payload[4] >> 4) & 0x07
    position = payload[4] & 0x07
    pressure = (payload[5] | (((payload[4] >> 7) & 1) << 8) | (((payload[4] >> 3) & 1) << 9)) - 100
    temp = payload[6] if payload[6] < 128 else payload[6] - 256
    if idv == 0:
        return None
    if pressure <= 0 or pressure > 1000:
        return None
    if temp < -40 or temp > 125:
        return None
    out_raw = bytearray(payload) + bytes([crcbyte])
    return _result("Airpuxem", idv, float(pressure), temp, 84, 52, "2FSKDev238Async",
                   out_raw, 9, btn=position, cnt=flags, fix=payload[7], battery=payload[7])


def rf_decode_eezrv(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 50)
    if len(bits) < 96:
        return None
    off = _seek(bits, 0, len(bits), "01010101010101010101010101010101")
    if off is None:
        return None
    off += 32
    raw, nb = _line_code(8, bits, off, len(bits), "10", "01")
    if nb < 64:
        return None
    cs = raw[1] + raw[2] + raw[3] + raw[4] + raw[5] + raw[6] + raw[7]
    if cs > 0xFF:
        cs |= 0x80
    if (cs & 0xFF) != raw[0]:
        return None
    idv = (raw[1] << 16) | (raw[2] << 8) | raw[3]
    temp = raw[5] - 50
    kpa = (((raw[7] & 0x01) << 8) + raw[4]) * 2.5
    low_batt = raw[6] >> 7
    if idv == 0:
        return None
    if kpa <= 0.0 or kpa > 1000.0:
        return None
    if temp < -40 or temp > 125:
        return None
    return _result("EezTire", idv, kpa, temp, 64, 50, "Ook270Async",
                   raw, 8, fix=low_batt, battery=(0 if low_batt else 1),
                   btn=(raw[6] & 0x7F))


def rf_decode_gear_hive(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 120)
    if len(bits) < 176:
        return None
    off = _seek(bits, 0, len(bits), "01011001011001101001011001100101")
    if off is None:
        return None
    off += 32
    raw, nb = _line_code(9, bits, off, len(bits), "01", "10")
    if nb < 72:
        return None
    p = [0] * 9
    p[0] = raw[0] ^ 0x94
    for i in range(1, 9):
        p[i] = raw[i] ^ raw[i - 1]
    if (p[6] & 0x3C) != 0x20:
        return None
    if (p[7] & 0x3F) != 0x35:
        return None
    sensor_class = p[1] & 0x0F
    counter = ((p[1] >> 4) << 8) | p[0]
    idv = (p[2] << 16) | (p[3] << 8) | p[4]
    base = (80 + sensor_class * 64) & 0xFF
    kpa = ((p[5] - base + 256) & 0xFF) * 6.25
    temp_bits = (p[7] >> 6) | ((p[6] & 0x03) << 2)
    temp = temp_bits + 21
    if idv == 0:
        return None
    if kpa <= 0.0 or kpa > 1000.0:
        return None
    if temp < -40 or temp > 125:
        return None
    return _result("GearHive", idv, kpa, temp, 72, 120, "Ook270Async",
                   p, 9, cnt=counter, btn=sensor_class)


def rf_decode_smartire(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 167)
    if len(bits) < 112:
        return None
    sync = _seek(bits, 0, len(bits), "0011001010110100")
    if sync is None:
        return None
    dm_start = sync + 16
    if dm_start + 1 >= len(bits):
        return None
    previous = bits[dm_start]
    b, nb = _diff_manch(6, bits, dm_start + 1, len(bits), previous)
    if nb < 47:
        return None
    if _crc7(b, 6, 0x45, 0x6F) != 0:
        return None
    idv = ((b[1] & 0x3F) << 16) | (b[2] << 8) | b[3]
    msg_type = (b[1] & 0xC0) >> 6
    value = b[0] - 40
    if idv == 0:
        return None
    kpa = 0.0
    temp = 0
    if msg_type == 0:
        kpa = value * 2.5
        if kpa <= 0.0 or kpa > 1000.0:
            return None
    elif msg_type == 1:
        temp = value
        if temp < -40 or temp > 125:
            return None
    else:
        return None
    return _result("SmarTire", idv, kpa, temp, 48, 167, "Ook270Async",
                   b, 6, btn=(b[4] & 0x7F))


def rf_decode_schrader_motorcycle(durations):
    if len(durations) < 32:
        return None
    bits = _durations_to_bitmap(durations, 122)
    if len(bits) < 140:
        return None
    off = _seek(bits, 0, len(bits), "01" "101010101010101010101010")
    if off is None:
        return None
    off += 26
    b, nb = _line_code(7, bits, off, len(bits), "01", "10")
    if nb < 56:
        return None
    if _crc8(b, 7, 0xE0, 0x07) != 0:
        return None
    idv = ((b[0] & 0x03) << 22) | (b[1] << 14) | (b[2] << 6) | (b[3] >> 2)
    pressure_raw = ((b[3] & 0x03) << 8) | b[4]
    kpa = pressure_raw * 0.5
    temp = b[5] - 50
    if idv == 0:
        return None
    if kpa < 0.0 or kpa > 1000.0:
        return None
    if temp < -40 or temp > 125:
        return None
    return _result("SchraderMoto", idv, kpa, temp, 56, 122, "Ook270Async", b, 7)


# ──────────────────────────────── Dispatcher ───────────────────────────────

# Same order as Evil's tpms_multi_decode: strong CRCs first (self-rejecting),
# then weak checksums (bounded by plausibility), Jansite TY02S last (no MIC).
_DECODERS = [
    # strong CRC
    rf_decode_schrader,
    rf_decode_renault,
    rf_decode_toyota,
    rf_decode_bmw,
    rf_decode_bmw_g3,
    rf_decode_mercedes_benz,
    rf_decode_porsche,
    rf_decode_hyundai_vdo,
    rf_decode_sefis_m3,
    rf_decode_honda,
    rf_decode_kia,
    rf_decode_trw_ook,
    rf_decode_trw_fsk,
    rf_decode_elantra2012,
    rf_decode_pmv107j,
    rf_decode_ave,
    rf_decode_abarth124,
    rf_decode_jansite_solar,
    rf_decode_tyreguard400,
    rf_decode_smartire,
    rf_decode_schrader_motorcycle,
    rf_decode_airpuxem,
    # weak checksum (bounded)
    rf_decode_citroen,
    rf_decode_ford,
    rf_decode_gm,
    rf_decode_nissan,
    rf_decode_jeep,
    rf_decode_renault_0435r,
    rf_decode_truck,
    rf_decode_eezrv,
    rf_decode_gear_hive,
    rf_decode_jansite_ty468,
    rf_decode_jansite_ty588,
    rf_decode_steelmate,
    # no checksum (last resort)
    rf_decode_jansite,
]

# Protocol names this module can emit (for UI / stats).
PROTOCOLS = [
    "Schrader", "Renault", "Toyota", "BMW", "Audi", "Mercedes", "Porsche",
    "Hyundai", "Sefis", "Honda", "Kia", "TRW", "Elantra2012", "PMV-107J",
    "AVE", "Abarth-124", "Abarth-Q85", "Jansite-Solar", "TyreGuard400",
    "SmarTire", "SchraderMoto", "Airpuxem", "Citroen", "Ford", "GM", "Nissan",
    "Jeep", "Renault-0435R", "Truck", "EezTire", "GearHive", "Jansite-TY468",
    "Jansite-TY588", "Steelmate", "Jansite",
]


def tpms_multi_decode(durations):
    """Try every TPMS decoder on a signed-µs pulse list (radio.capture_raw()).

    Returns the first decoded sensor dict, or None if nothing matched.
    """
    if not durations:
        return None
    for dec in _DECODERS:
        try:
            r = dec(durations)
        except Exception:
            r = None
        if r:
            return r
    return None


def tpms_decode_all(durations):
    """Like tpms_multi_decode but returns the list of ALL decoders that matched
    (diagnostics / ambiguity inspection)."""
    out = []
    if not durations:
        return out
    for dec in _DECODERS:
        try:
            r = dec(durations)
        except Exception:
            r = None
        if r:
            out.append(r)
    return out
