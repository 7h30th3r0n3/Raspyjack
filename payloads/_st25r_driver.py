"""
ST25R3916 NFC reader driver for CardputerZero Cap HAT.

Pure-Python SPI driver using spidev.  Implements the same public API
as _PN532Base from _nfc_driver.py so it can be used as a drop-in
replacement with all existing NFC payloads.

Usage:
    from payloads._st25r_driver import ST25R3916Driver

    drv = ST25R3916Driver()
    if drv.open():
        card = drv.read_passive_target()
        ...
    drv.close()
"""

import os
import subprocess
import time
from typing import Optional, Tuple

try:
    import spidev
    _SPIDEV_OK = True
except ImportError:
    spidev = None
    _SPIDEV_OK = False

from payloads._nfc_driver import CardInfo, MIFARE_AUTH_A, MIFARE_AUTH_B

# ---------------------------------------------------------------------------
# ST25R3916 register map (selected)
# ---------------------------------------------------------------------------
_REG_IO_CFG1        = 0x00
_REG_IO_CFG2        = 0x01
_REG_OP_CTRL        = 0x02
_REG_MODE_DEF       = 0x03
_REG_BIT_RATE       = 0x04
_REG_ISO14443A_NFC  = 0x05
_REG_NUM_TX_BYTES_1 = 0x0A
_REG_NUM_TX_BYTES_2 = 0x0B
_REG_MASK_IRQ_MAIN  = 0x16
_REG_MASK_IRQ_TIMER = 0x17
_REG_MASK_IRQ_ERR   = 0x18
_REG_MASK_IRQ_TGT   = 0x19
_REG_IRQ_MAIN       = 0x1A
_REG_IRQ_TIMER      = 0x1B
_REG_IRQ_ERR_WUP    = 0x1C
_REG_IRQ_TARGET     = 0x1D
_REG_FIFO_STATUS_1  = 0x1E
_REG_FIFO_STATUS_2  = 0x1F
_REG_IC_ID           = 0x3F

# Direct commands
_CMD_SET_DEFAULT      = 0x01
_CMD_CLEAR            = 0x02
_CMD_TX_WITH_CRC      = 0x04
_CMD_TX_WITHOUT_CRC   = 0x05
_CMD_CALIBRATE_ANT    = 0x11
_CMD_ADJUST_REGS      = 0x15

# IRQ bits
_IRQ_TXE  = 0x40
_IRQ_RXE  = 0x10
_IRQ_COL  = 0x08
_IRQ_ERR  = 0x01
_IRQ_NRT  = 0x01

# FIFO
_FIFO_WRITE = 0x80
_FIFO_READ  = 0x9F

# ISO 14443-A
_REQA      = 0x26
_SEL_CL1   = 0x93
_SEL_CL2   = 0x95
_SEL_CL3   = 0x97
_HLTA      = 0x50
_MIFARE_READ     = 0x30
_MIFARE_WRITE    = 0xA0
_MIFARE_UL_WRITE = 0xA2

_SPI_BUS   = 0
_SPI_CS    = 2
_SPI_SPEED = 4000000


class ST25R3916Driver:
    """ST25R3916 NFC driver with _PN532Base-compatible interface."""

    can_write = True
    can_emulate = False

    def __init__(self, spi_bus=_SPI_BUS, spi_cs=_SPI_CS, speed=_SPI_SPEED):
        self._bus = spi_bus
        self._cs = spi_cs
        self._speed = speed
        self._spi = None
        self._opened = False
        self._authed = False

    # ── SPI primitives ────────────────────────────────────────────────

    def _rr(self, reg):
        return self._spi.xfer2([0x40 | (reg & 0x3F), 0x00])[1]

    def _wr(self, reg, val):
        self._spi.xfer2([0x00 | (reg & 0x3F), val & 0xFF])

    def _cmd(self, c):
        self._spi.xfer2([0xC0 | (c & 0x3F)])

    def _fifo_w(self, data):
        for i in range(0, len(data), 32):
            self._spi.xfer2([_FIFO_WRITE] + list(data[i:i + 32]))

    def _fifo_r(self, n):
        out = []
        while n > 0:
            chunk = min(n, 32)
            r = self._spi.xfer2([_FIFO_READ] + [0x00] * chunk)
            out.extend(r[1:])
            n -= chunk
        return bytes(out)

    def _fifo_len(self):
        return self._rr(_REG_FIFO_STATUS_1) | ((self._rr(_REG_FIFO_STATUS_2) & 0x01) << 8)

    def _clear_irqs(self):
        self._rr(_REG_IRQ_MAIN)
        self._rr(_REG_IRQ_TIMER)
        self._rr(_REG_IRQ_ERR_WUP)
        self._rr(_REG_IRQ_TARGET)

    def _wait_irq(self, mask, timeout=0.1):
        deadline = time.time() + timeout
        while time.time() < deadline:
            v = self._rr(_REG_IRQ_MAIN)
            if v & mask:
                return v
            time.sleep(0.001)
        return 0

    # ── Lifecycle ─────────────────────────────────────────────────────

    def open(self) -> bool:
        if not _SPIDEV_OK:
            return False
        try:
            with open("/sys/class/leds/ext_5v_out/brightness", "w") as f:
                f.write("1")
        except OSError:
            pass
        time.sleep(0.1)

        dev = f"/dev/spidev{self._bus}.{self._cs}"
        if not os.path.exists(dev):
            try:
                subprocess.run(
                    ["sudo", "dtoverlay", "spi0-spidev2-gpio22-overlay"],
                    capture_output=True, timeout=5)
                time.sleep(0.5)
            except Exception:
                pass
        if not os.path.exists(dev):
            return False

        try:
            self._spi = spidev.SpiDev()
            self._spi.open(self._bus, self._cs)
            self._spi.max_speed_hz = self._speed
            self._spi.mode = 0
        except OSError:
            return False

        self._cmd(_CMD_SET_DEFAULT)
        time.sleep(0.01)

        ic_id = self._rr(_REG_IC_ID)
        if ic_id in (0x00, 0xFF):
            self._spi.close()
            self._spi = None
            return False

        self._init_hw()
        self._opened = True
        return True

    def close(self):
        if self._opened:
            self._wr(_REG_OP_CTRL, self._rr(_REG_OP_CTRL) & ~0x08)
        if self._spi:
            try:
                self._spi.close()
            except Exception:
                pass
            self._spi = None
        self._opened = False

    def _init_hw(self):
        self._cmd(_CMD_SET_DEFAULT)
        time.sleep(0.01)
        self._wr(_REG_OP_CTRL, 0xC0)
        time.sleep(0.01)
        self._wr(_REG_IO_CFG1, 0x00)
        self._wr(_REG_IO_CFG2, 0x00)
        self._wr(_REG_MODE_DEF, 0x08)
        self._wr(_REG_BIT_RATE, 0x00)
        self._wr(_REG_ISO14443A_NFC, 0x01)
        self._wr(_REG_MASK_IRQ_MAIN, 0x00)
        self._wr(_REG_MASK_IRQ_TIMER, 0x00)
        self._wr(_REG_MASK_IRQ_ERR, 0x00)
        self._wr(_REG_MASK_IRQ_TGT, 0x00)
        self._cmd(_CMD_CALIBRATE_ANT)
        time.sleep(0.05)
        self._cmd(_CMD_ADJUST_REGS)
        time.sleep(0.01)
        self._clear_irqs()

    def _field_on(self):
        self._wr(_REG_OP_CTRL, self._rr(_REG_OP_CTRL) | 0x08)
        time.sleep(0.005)

    def _field_off(self):
        self._wr(_REG_OP_CTRL, self._rr(_REG_OP_CTRL) & ~0x08)

    def _field_reset(self):
        self._field_off()
        time.sleep(0.025)
        self._field_on()

    # ── Low-level transceive ──────────────────────────────────────────

    def _transceive(self, tx, crc=True, bits=0, timeout=0.1):
        self._cmd(_CMD_CLEAR)
        self._clear_irqs()
        tx_bits = len(tx) * 8 + bits
        self._wr(_REG_NUM_TX_BYTES_2, (tx_bits >> 8) & 0xFF)
        self._wr(_REG_NUM_TX_BYTES_1, tx_bits & 0xFF)
        self._fifo_w(tx)
        self._cmd(_CMD_TX_WITH_CRC if crc else _CMD_TX_WITHOUT_CRC)

        m = self._wait_irq(_IRQ_RXE | _IRQ_TXE | _IRQ_ERR | _IRQ_COL, timeout)
        if m & _IRQ_ERR:
            return None
        if (m & _IRQ_TXE) and not (m & _IRQ_RXE):
            m |= self._wait_irq(_IRQ_RXE | _IRQ_ERR | _IRQ_COL, timeout)
        n = self._fifo_len()
        return self._fifo_r(n) if n > 0 else None

    def _send_short(self, cmd_byte, timeout=0.05):
        self._cmd(_CMD_CLEAR)
        self._clear_irqs()
        self._wr(_REG_NUM_TX_BYTES_2, 0x00)
        self._wr(_REG_NUM_TX_BYTES_1, 7)
        self._fifo_w([cmd_byte])
        self._cmd(_CMD_TX_WITHOUT_CRC)

        m = self._wait_irq(_IRQ_RXE | _IRQ_TXE | _IRQ_ERR, timeout)
        if (m & _IRQ_TXE) and not (m & _IRQ_RXE):
            m |= self._wait_irq(_IRQ_RXE | _IRQ_ERR, timeout)
        n = self._fifo_len()
        return self._fifo_r(n) if n > 0 else None

    # ── ISO 14443-A activation ────────────────────────────────────────

    def _anticoll(self, cascade):
        self._cmd(_CMD_CLEAR)
        self._clear_irqs()
        self._wr(_REG_NUM_TX_BYTES_2, 0x00)
        self._wr(_REG_NUM_TX_BYTES_1, 16)
        self._fifo_w([cascade, 0x20])
        self._cmd(_CMD_TX_WITHOUT_CRC)
        m = self._wait_irq(_IRQ_RXE | _IRQ_COL | _IRQ_ERR, 0.05)
        if m & _IRQ_ERR:
            return None
        n = self._fifo_len()
        return self._fifo_r(n) if n >= 5 else None

    def _select(self, cascade, nfcid, bcc):
        return self._transceive([cascade, 0x70] + list(nfcid) + [bcc], crc=True, timeout=0.05)

    def _activate_nfca(self):
        atqa = self._send_short(_REQA)
        if atqa is None or len(atqa) < 2:
            return None
        atqa_val = atqa[0] | (atqa[1] << 8)
        uid = bytearray()
        sak = 0
        for cl in [_SEL_CL1, _SEL_CL2, _SEL_CL3]:
            resp = self._anticoll(cl)
            if resp is None or len(resp) < 5:
                return None
            nfcid = resp[:4]
            bcc = resp[4]
            check = 0
            for b in nfcid:
                check ^= b
            if check != bcc:
                return None
            sel = self._select(cl, nfcid, bcc)
            if sel is None or len(sel) < 1:
                return None
            sak = sel[0]
            if nfcid[0] == 0x88:
                uid.extend(nfcid[1:4])
            else:
                uid.extend(nfcid)
            if not (sak & 0x04):
                break
        return CardInfo(uid=bytes(uid), atqa=atqa_val, sak=sak)

    # ── _PN532Base-compatible public API ──────────────────────────────

    def get_firmware(self) -> Optional[Tuple[int, int, int, int]]:
        if not self._opened:
            return None
        ic = self._rr(_REG_IC_ID)
        return (0x25, ic, 0, 0)

    def sam_config(self):
        pass

    def read_passive_target(self, card_type=0x00, timeout=2.0) -> Optional[CardInfo]:
        if not self._opened:
            return None
        self._authed = False
        self._field_on()
        time.sleep(0.005)
        deadline = time.time() + timeout
        while time.time() < deadline:
            card = self._activate_nfca()
            if card is not None:
                return card
            time.sleep(0.05)
            self._field_reset()
        return None

    def mifare_auth(self, block: int, key: bytes, uid: bytes,
                    key_type: int = MIFARE_AUTH_A) -> bool:
        tx = [key_type, block] + list(key[:6]) + list(uid[:4])
        self._cmd(_CMD_CLEAR)
        self._clear_irqs()
        self._wr(_REG_NUM_TX_BYTES_2, 0x00)
        self._wr(_REG_NUM_TX_BYTES_1, len(tx) * 8)
        self._fifo_w(tx)
        self._cmd(_CMD_TX_WITHOUT_CRC)
        m = self._wait_irq(_IRQ_RXE | _IRQ_TXE | _IRQ_ERR, 0.2)
        if m & _IRQ_ERR:
            self._authed = False
            return False
        if m & _IRQ_TXE:
            m |= self._wait_irq(_IRQ_RXE | _IRQ_ERR, 0.2)
        self._authed = bool(m & _IRQ_RXE) and not bool(m & _IRQ_ERR)
        return self._authed

    def mifare_read(self, block: int) -> Optional[bytes]:
        resp = self._transceive([_MIFARE_READ, block], crc=True, timeout=0.1)
        if resp and len(resp) >= 16:
            return bytes(resp[:16])
        return None

    def mifare_write(self, block: int, data: bytes) -> bool:
        resp = self._transceive([_MIFARE_WRITE, block], crc=True, timeout=0.1)
        if resp is None or len(resp) < 1 or resp[0] != 0x0A:
            return False
        time.sleep(0.001)
        resp2 = self._transceive(list(data[:16]), crc=True, timeout=0.1)
        return resp2 is not None and len(resp2) >= 1 and resp2[0] == 0x0A

    def mifare_ul_read(self, page: int) -> Optional[bytes]:
        resp = self._transceive([_MIFARE_READ, page], crc=True, timeout=0.1)
        if resp and len(resp) >= 16:
            return bytes(resp[:16])
        return None

    def mifare_ul_write(self, page: int, data: bytes) -> bool:
        tx = [_MIFARE_UL_WRITE, page] + list(data[:4])
        resp = self._transceive(tx, crc=True, timeout=0.1)
        return resp is not None and len(resp) >= 1 and resp[0] == 0x0A

    def communicate_thru(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        resp = self._transceive(list(data), crc=True, timeout=timeout)
        if resp and len(resp) >= 2:
            return bytes(resp)
        return None

    def data_exchange(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        return self.communicate_thru(data, timeout=timeout)

    def in_communicate_thru_raw(self, data: bytes, timeout=0.5) -> Optional[bytes]:
        resp = self._transceive(list(data), crc=False, timeout=timeout)
        if resp:
            return bytes(resp)
        return None

    def init_as_target(self, uid, atqa=b"\x04\x00", sak=0x08, timeout=1.0):
        return None

    def tg_get_data(self):
        return None

    def tg_set_data(self, data):
        return False

    @staticmethod
    def detect() -> bool:
        """Quick check: is a Cap NFC HAT available?"""
        if not _SPIDEV_OK:
            return False
        try:
            with open("/sys/class/leds/ext_5v_out/brightness", "w") as f:
                f.write("1")
        except OSError:
            pass
        time.sleep(0.05)
        dev = f"/dev/spidev{_SPI_BUS}.{_SPI_CS}"
        if not os.path.exists(dev):
            try:
                subprocess.run(
                    ["sudo", "dtoverlay", "spi0-spidev2-gpio22-overlay"],
                    capture_output=True, timeout=5)
                time.sleep(0.3)
            except Exception:
                pass
        if not os.path.exists(dev):
            return False
        try:
            spi = spidev.SpiDev()
            spi.open(_SPI_BUS, _SPI_CS)
            spi.max_speed_hz = _SPI_SPEED
            spi.mode = 0
            spi.xfer2([0xC0 | _CMD_SET_DEFAULT])
            time.sleep(0.01)
            ic = spi.xfer2([0x40 | _REG_IC_ID, 0x00])[1]
            spi.close()
            return ic not in (0x00, 0xFF)
        except Exception:
            return False
