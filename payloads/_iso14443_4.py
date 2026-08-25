"""ISO14443-4 (T=CL) protocol layer for ST25R3916.

Ported from Flipper Zero Momentum firmware:
  lib/nfc/helpers/iso14443_4_layer.c
  lib/nfc/protocols/iso14443_4a/iso14443_4a_poller_i.c

Provides RATS/ATS exchange, I/R/S-block framing with block numbering,
chaining support for large APDUs, and S(WTX) handling.
"""

from typing import Optional, Tuple

RATS_CMD = 0xE0
FSDI_256 = 0x08
MAX_RETRIES = 20

# PCB byte masks
_PCB_I = 0x02
_PCB_I_CHAIN = 1 << 4
_PCB_I_CID = 1 << 3
_PCB_R_MASK = 0xA0
_PCB_R_ACK = 0xA2
_PCB_R_NAK = 0xB2
_PCB_S_MASK = 0xC0
_PCB_S_WTX = 0xF2
_PCB_S_DESELECT = 0xC2
_BLOCK_NUM_MASK = 0x01


def _is_i_block(pcb):
    return (pcb & 0xE2) == 0x02

def _is_r_block(pcb):
    return (pcb & 0xE0) == 0xA0

def _is_s_block(pcb):
    return (pcb & 0xC0) == 0xC0

def _is_s_wtx(pcb):
    return pcb == _PCB_S_WTX or (pcb & 0xF0) == 0xF0


class ATS:
    """Parsed Answer To Select."""
    def __init__(self, raw: bytes):
        self.raw = raw
        self.tl = raw[0] if raw else 0
        self.t0 = raw[1] if len(raw) > 1 else 0
        self.fsci = self.t0 & 0x0F
        self.fsc = [16, 24, 32, 40, 48, 64, 96, 128, 256][min(self.fsci, 8)]
        self.ta1 = None
        self.tb1 = None
        self.tc1 = None
        idx = 2
        if self.t0 & 0x10 and idx < len(raw):
            self.ta1 = raw[idx]; idx += 1
        if self.t0 & 0x20 and idx < len(raw):
            self.tb1 = raw[idx]; idx += 1
        if self.t0 & 0x40 and idx < len(raw):
            self.tc1 = raw[idx]; idx += 1
        self.historical = raw[idx:self.tl] if idx < self.tl and self.tl <= len(raw) else b""
        self.fwt_fc = self._calc_fwt()

    def _calc_fwt(self):
        if self.tb1 is not None:
            fwi = (self.tb1 >> 4) & 0x0F
            return (4096 << fwi)
        return 4096 << 4  # default FWI=4

    @property
    def cid_supported(self):
        return bool(self.tc1 is not None and self.tc1 & 0x02)

    @property
    def nad_supported(self):
        return bool(self.tc1 is not None and self.tc1 & 0x01)


class ISO14443_4Layer:
    """ISO14443-4 block protocol with I/R/S framing."""

    def __init__(self):
        self.reset()

    def reset(self):
        self._block_num = 0
        self._cid = None

    def _next_block_num(self):
        self._block_num ^= 1

    def encode_i_block(self, data: bytes, chaining: bool = False) -> bytes:
        """Build an I-block with optional chaining."""
        pcb = _PCB_I | (self._block_num & _BLOCK_NUM_MASK)
        if chaining:
            pcb |= _PCB_I_CHAIN
        frame = bytes([pcb]) + data
        self._next_block_num()
        return frame

    def encode_r_ack(self) -> bytes:
        return bytes([_PCB_R_ACK | (self._block_num & _BLOCK_NUM_MASK)])

    def encode_r_nak(self) -> bytes:
        return bytes([_PCB_R_NAK | (self._block_num & _BLOCK_NUM_MASK)])

    def encode_s_wtx_response(self, wtxm: int) -> bytes:
        return bytes([_PCB_S_WTX, wtxm & 0x3F])

    def encode_s_deselect(self) -> bytes:
        return bytes([_PCB_S_DESELECT])

    def decode_response(self, data: bytes) -> Tuple[str, bytes]:
        """Decode a response block. Returns (block_type, payload).

        block_type: 'I', 'I_CHAIN', 'R_ACK', 'R_NAK', 'S_WTX', 'S_DESELECT', 'UNKNOWN'
        """
        if not data:
            return ("UNKNOWN", b"")
        pcb = data[0]
        payload = data[1:] if len(data) > 1 else b""

        if _is_i_block(pcb):
            if pcb & _PCB_I_CHAIN:
                return ("I_CHAIN", payload)
            return ("I", payload)
        elif _is_r_block(pcb):
            if pcb & 0x10:
                return ("R_NAK", payload)
            return ("R_ACK", payload)
        elif _is_s_block(pcb):
            if _is_s_wtx(pcb):
                return ("S_WTX", payload)
            return ("S_DESELECT", payload)
        return ("UNKNOWN", data)


class ISO14443_4:
    """High-level ISO14443-4 poller using the ST25R3916 driver."""

    def __init__(self, driver):
        """driver: ST25R3916Driver instance (must be opened with card activated)."""
        self._drv = driver
        self._layer = ISO14443_4Layer()
        self.ats = None

    def activate(self) -> Optional[ATS]:
        """Send RATS and parse ATS. Returns ATS on success."""
        rats_cmd = bytes([RATS_CMD, FSDI_256 << 4])
        resp = self._drv._transceive(rats_cmd, timeout_ms=50, min_rx=2)
        if resp is None:
            return None
        self.ats = ATS(resp)
        self._layer.reset()
        return self.ats

    def send_apdu(self, apdu: bytes) -> Optional[bytes]:
        """Send an APDU command and receive the full response.

        Handles I-block framing, chaining, and S(WTX) extensions.
        """
        i_block = self._layer.encode_i_block(apdu)
        resp = self._drv._transceive(i_block, timeout_ms=500, min_rx=1)
        if resp is None:
            return None

        result = bytearray()
        attempts = MAX_RETRIES

        while attempts > 0:
            attempts -= 1
            btype, payload = self._layer.decode_response(resp)

            if btype == "I":
                result.extend(payload)
                return bytes(result)

            elif btype == "I_CHAIN":
                result.extend(payload)
                r_ack = self._layer.encode_r_ack()
                resp = self._drv._transceive(r_ack, timeout_ms=500, min_rx=1)
                if resp is None:
                    return bytes(result) if result else None

            elif btype == "S_WTX":
                wtxm = payload[0] & 0x3F if payload else 1
                wtx_resp = self._layer.encode_s_wtx_response(wtxm)
                resp = self._drv._transceive(wtx_resp, timeout_ms=2000, min_rx=1)
                if resp is None:
                    return None

            elif btype == "R_ACK":
                return bytes(result) if result else None

            else:
                return bytes(result) if result else None

        return bytes(result) if result else None

    def deselect(self):
        """Send S(DESELECT) to end the session."""
        s_block = self._layer.encode_s_deselect()
        self._drv._transceive(s_block, timeout_ms=50, min_rx=0)
