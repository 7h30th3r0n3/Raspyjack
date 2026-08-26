"""
MIFARE Classic Crypto1 cipher — ported from Flipper Zero Momentum firmware.

Implements the proprietary Crypto1 stream cipher used by MIFARE Classic cards.
Based on https://github.com/RfidResearchGroup/proxmark3 and Flipper's crypto1.c.

MIFARE Classic authentication flow:
  1. Reader sends AUTH_KEY_A (0x60) or AUTH_KEY_B (0x61) + block_number
  2. Tag responds with 4-byte NT (nonce from tag's PRNG)
  3. Reader initializes Crypto1 LFSR with: key XOR (uid XOR nt)
  4. Reader generates NR (random), computes AR = suc²(nt) encrypted
  5. Reader sends {NR}{AR} (8 bytes) with custom parity bits
  6. Tag responds with AT = suc³(nt) encrypted (4 bytes)
  7. All subsequent communication is encrypted with Crypto1 keystream
"""
import os
import struct

_LF_POLY_ODD = 0x29CE5C
_LF_POLY_EVEN = 0x870804
_FILTER_LUT = 0xEC57E80A

_ODD_PARITY_LUT = bytes([
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
])


def odd_parity8(b):
    return _ODD_PARITY_LUT[b & 0xFF]


def even_parity8(b):
    return 1 - _ODD_PARITY_LUT[b & 0xFF]


def even_parity32(v):
    v &= 0xFFFFFFFF
    v ^= v >> 16
    v ^= v >> 8
    return even_parity8(v & 0xFF)


def _swapendian32(x):
    x &= 0xFFFFFFFF
    x = ((x >> 8) & 0x00FF00FF) | ((x & 0x00FF00FF) << 8)
    x = (x >> 16) | ((x << 16) & 0xFFFFFFFF)
    return x


def _bebit(x, n):
    return (x >> (n ^ 24)) & 1


def _filter(x):
    out = 0
    out = (0xF22C0 >> (x & 0xF)) & 16
    out |= (0x6C9C0 >> ((x >> 4) & 0xF)) & 8
    out |= (0x3C8B0 >> ((x >> 8) & 0xF)) & 4
    out |= (0x1E458 >> ((x >> 12) & 0xF)) & 2
    out |= (0x0D938 >> ((x >> 16) & 0xF)) & 1
    return (_FILTER_LUT >> out) & 1


class Crypto1:
    def __init__(self):
        self.odd = 0
        self.even = 0

    def reset(self):
        self.odd = 0
        self.even = 0

    def init(self, key):
        self.odd = 0
        self.even = 0
        for i in range(47, 0, -2):
            self.odd = ((self.odd << 1) | ((key >> ((i - 1) ^ 7)) & 1)) & 0xFFFFFF
            self.even = ((self.even << 1) | ((key >> (i ^ 7)) & 1)) & 0xFFFFFF

    def bit(self, inp, is_encrypted):
        out = _filter(self.odd)
        feed = out & (1 if is_encrypted else 0)
        feed ^= (1 if inp else 0)
        feed ^= _LF_POLY_ODD & self.odd
        feed ^= _LF_POLY_EVEN & self.even
        self.even = ((self.even << 1) | even_parity32(feed)) & 0xFFFFFF
        self.odd, self.even = self.even, self.odd
        return out

    def byte(self, inp, is_encrypted):
        out = 0
        for i in range(8):
            out |= self.bit((inp >> i) & 1, is_encrypted) << i
        return out

    def word(self, inp, is_encrypted):
        out = 0
        for i in range(32):
            out |= self.bit(_bebit(inp, i), is_encrypted) << (24 ^ i)
        return out & 0xFFFFFFFF

    def lfsr_rollback_bit(self, inp, fb):
        self.odd &= 0xFFFFFF
        self.odd, self.even = self.even, self.odd
        out = self.even & 1
        val = _LF_POLY_EVEN & (self.even >> 1)
        self.even >>= 1
        val ^= out
        val ^= _LF_POLY_ODD & self.odd
        val ^= (1 if inp else 0)
        ret = _filter(self.odd)
        val ^= ret & (1 if fb else 0)
        self.even |= even_parity32(val) << 23
        return ret

    def lfsr_rollback_word(self, inp, fb):
        ret = 0
        for i in range(31, -1, -1):
            ret |= self.lfsr_rollback_bit(_bebit(inp, i), fb) << (24 ^ i)
        return ret & 0xFFFFFFFF

    def decrypt_bytes(self, data):
        return bytes(self.byte(0, 0) ^ b for b in data)

    def decrypt_4bit(self, enc_byte):
        out = 0
        for i in range(4):
            out |= (self.bit(0, 0) ^ ((enc_byte >> i) & 1)) << i
        return out

    def encrypt_bytes(self, data):
        result = bytearray(len(data))
        parity = bytearray(len(data))
        for i, b in enumerate(data):
            result[i] = self.byte(0, 0) ^ b
            parity[i] = (_filter(self.odd) ^ odd_parity8(b)) & 1
        return bytes(result), bytes(parity)


def prng_successor(x, n):
    x = _swapendian32(x)
    for _ in range(n):
        x = ((x >> 1) | (((x >> 16) ^ (x >> 18) ^ (x >> 19) ^ (x >> 21)) & 1) << 31) & 0xFFFFFFFF
    return _swapendian32(x)


def is_weak_prng_nonce(nonce):
    if nonce == 0:
        return False
    x = (nonce >> 16) & 0xFFFF
    x = ((x & 0xFF) << 8) | (x >> 8)
    for _ in range(16):
        x = ((x >> 1) | (((x ^ (x >> 2) ^ (x >> 3) ^ (x >> 5)) & 1) << 15)) & 0xFFFF
    x = ((x & 0xFF) << 8) | (x >> 8)
    return x == (nonce & 0xFFFF)


def encrypt_reader_nonce(key, cuid, nt_bytes, nr_bytes, is_nested=False):
    """Encrypt the reader nonce (NR) and answer (AR) for MIFARE auth.

    Returns (encrypted_data_9byte, parity_bits) where encrypted_data_9byte
    contains 8 data bytes packed with parity into 9 bytes (72 bits) for
    custom parity TX on the ST25R3916.
    """
    crypto = Crypto1()
    nt_num = int.from_bytes(nt_bytes[:4], 'big')

    crypto.init(key)
    if is_nested:
        nt_num = crypto.word(nt_num ^ cuid, 1) ^ nt_num
    else:
        crypto.word(nt_num ^ cuid, 0)

    nr = bytearray(nr_bytes[:4])
    enc_nr = bytearray(4)
    par_nr = bytearray(4)
    for i in range(4):
        enc_nr[i] = crypto.byte(nr[i], 0) ^ nr[i]
        par_nr[i] = (_filter(crypto.odd) ^ odd_parity8(nr[i])) & 1

    nt_succ = prng_successor(nt_num, 32)
    enc_ar = bytearray(4)
    par_ar = bytearray(4)
    for i in range(4):
        nt_succ = prng_successor(nt_succ, 8)
        enc_ar[i] = crypto.byte(0, 0) ^ (nt_succ & 0xFF)
        par_ar[i] = (_filter(crypto.odd) ^ odd_parity8(nt_succ & 0xFF)) & 1

    data = bytes(enc_nr) + bytes(enc_ar)
    parity = bytes(par_nr) + bytes(par_ar)
    packed = pack_with_parity(data, parity)
    return crypto, packed, data, parity


def pack_with_parity(data, parity):
    """Pack 8 data bytes + 8 parity bits into 9 bytes (72 bits).

    The ST25R3916 with no_tx_par sends raw bits including parity.
    Format: [D0b7..D0b0][P0][D1b7..D1b0][P1]...[D7b7..D7b0][P7]
    """
    bits = 0
    total = 0
    for i, b in enumerate(data):
        bits |= b << total
        total += 8
        bits |= (parity[i] & 1) << total
        total += 1
    nbytes = (total + 7) // 8
    return bits.to_bytes(nbytes, 'little'), total


def iso14443a_crc(data):
    crc = 0x6363
    for b in data:
        bt = b ^ (crc & 0xFF)
        bt ^= (bt << 4) & 0xFF
        crc = ((crc >> 8) ^ (bt << 8) ^ (bt << 3) ^ (bt >> 4)) & 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def append_crc(data):
    return bytes(data) + iso14443a_crc(data)


def check_crc(data):
    if len(data) < 3:
        return False
    crc = iso14443a_crc(data[:-2])
    return crc == data[-2:]
