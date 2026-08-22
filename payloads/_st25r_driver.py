"""
ST25R3916 NFC reader driver for CardputerZero Cap HAT.

Pure-Python SPI driver using spidev.  Implements the same public API
as _PN532Base from _nfc_driver.py so it can be used as a drop-in
replacement with all existing NFC payloads.

Based on M5Stack M5Unit-NFC library (MIT license).

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

from payloads.nfc_rfid._nfc_driver import CardInfo, MIFARE_AUTH_A, MIFARE_AUTH_B

# ---------------------------------------------------------------------------
# Register map — Space-A (from ST25R3916_definition.hpp)
# ---------------------------------------------------------------------------
_IO_CFG1         = 0x00
_IO_CFG2         = 0x01
_OP_CTRL         = 0x02
_MODE_DEF        = 0x03
_BIT_RATE        = 0x04
_ISO14443A       = 0x05
_ISO14443B       = 0x06
_FELICA          = 0x07
_NFCIP1_PT_DEF   = 0x08
_STREAM_MODE     = 0x09
_AUX_DEF         = 0x0A
_RX_CONF1        = 0x0B
_RX_CONF2        = 0x0C
_RX_CONF3        = 0x0D
_RX_CONF4        = 0x0E
_MASK_RX_TIMER   = 0x0F
_NRT1            = 0x10
_NRT2            = 0x11
_TIMER_EMV       = 0x12
_GPT1            = 0x13
_GPT2            = 0x14
_PPON2           = 0x15
_MASK_IRQ_MAIN   = 0x16
_MASK_IRQ_TIMER  = 0x17
_MASK_IRQ_ERR    = 0x18
_MASK_IRQ_TGT    = 0x19
_IRQ_MAIN        = 0x1A
_IRQ_TIMER       = 0x1B
_IRQ_ERR         = 0x1C
_IRQ_TGT         = 0x1D
_FIFO_STA1       = 0x1E
_FIFO_STA2       = 0x1F
_COLL_DISP       = 0x20
_PT_DISP         = 0x21
_NUM_TX1         = 0x22
_NUM_TX2         = 0x23
_BR_DETECT       = 0x24
_AD_OUT          = 0x25
_ANT_TUNE1       = 0x26
_ANT_TUNE2       = 0x27
_TX_DRIVER       = 0x28
_PT_MOD          = 0x29
_EFD_ACT         = 0x2A
_EFD_DEACT       = 0x2B
_REG_VOLT        = 0x2C
_RSSI            = 0x2D
_GAIN_RED        = 0x2E
_CAP_SENS_CTRL   = 0x2F
_CAP_SENS_DISP   = 0x30
_AUX_DISP        = 0x31
_IC_ID           = 0x3F

# Register map — Space-B (prefixed with CMD_SPACE_B_ACCESS in SPI)
_B_EMD_SUPP      = 0x05
_B_CORR_CFG1     = 0x0C
_B_CORR_CFG2     = 0x0D
_B_SQUELCH       = 0x0F
_B_FIELD_GUARD   = 0x15
_B_AUX_MOD       = 0x28
_B_TX_TIMING     = 0x29
_B_RES_AM_MOD    = 0x2A
_B_REG_DISP      = 0x2C
_B_OVERSHOOT1    = 0x30
_B_OVERSHOOT2    = 0x31
_B_UNDERSHOOT1   = 0x32
_B_UNDERSHOOT2   = 0x33

# Direct commands
_CMD_SET_DEFAULT       = 0xC1
_CMD_STOP_ALL          = 0xC2
_CMD_TX_CRC            = 0xC4
_CMD_TX_NO_CRC         = 0xC5
_CMD_TX_REQA           = 0xC6
_CMD_TX_WUPA           = 0xC7
_CMD_FIELD_ON          = 0xC8
_CMD_FIELD_RESP        = 0xC9
_CMD_MASK_RX           = 0xD0
_CMD_UNMASK_RX         = 0xD1
_CMD_MEASURE_AMP       = 0xD3
_CMD_RESET_RX_GAIN     = 0xD5
_CMD_ADJUST_REG        = 0xD6
_CMD_CLEAR_RSSI        = 0xDA
_CMD_CLEAR_FIFO        = 0xDB
_CMD_MEASURE_PWR       = 0xDF
_CMD_START_NRT         = 0xE3
_CMD_SPACE_B           = 0xFB
_CMD_TEST_ACCESS       = 0xFC

# SPI opcodes
_OP_WRITE     = 0x00
_OP_READ      = 0x40
_OP_LOAD_FIFO = 0x80
_OP_READ_FIFO = 0x9F

# OP_CTRL bits
_EN    = 0x80
_RX_EN = 0x40
_TX_EN = 0x08
_WU    = 0x04
_FD_MASK = 0x03

# AUX_DISP bits
_TX_ON  = 0x20
_OSC_OK = 0x10
_RX_ON  = 0x08

# IRQ_MAIN bits
_I_OSC  = 0x80
_I_WL   = 0x40
_I_RXS  = 0x20
_I_RXE  = 0x10
_I_TXE  = 0x08
_I_COL  = 0x04

# IRQ_TIMER bits
_I_NRE  = 0x40

# IO_CFG2 bits
_SUP3V     = 0x80
_AAT_EN    = 0x20
_MISO_PD2  = 0x10
_MISO_PD1  = 0x08
_IO_DRV    = 0x04

# AUX_DEF bits
_NO_CRC_RX = 0x80
_DIS_CORR  = 0x04
_ANTCL     = 0x01

# ISO14443A
_REQA      = 0x26
_SEL_CL1   = 0x93
_SEL_CL2   = 0x95
_SEL_CL3   = 0x97
_HLTA      = 0x50
_MF_READ   = 0x30
_MF_WRITE  = 0xA0
_MF_UL_WR  = 0xA2
_ACK       = 0x0A

_SPI_BUS   = 0
_SPI_CS    = 2
_SPI_SPEED = 4000000
_SPI_MODE  = 1


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

    # ── SPI primitives ────────────────────────────────────────────────

    def _rr(self, reg):
        return self._spi.xfer2([_OP_READ | (reg & 0x3F), 0x00])[1]

    def _wr(self, reg, val):
        self._spi.xfer2([_OP_WRITE | (reg & 0x3F), val & 0xFF])

    def _rr_b(self, reg):
        self._spi.xfer2([_CMD_SPACE_B])
        return self._spi.xfer2([_OP_READ | (reg & 0x3F), 0x00])[1]

    def _wr_b(self, reg, val):
        self._spi.xfer2([_CMD_SPACE_B])
        self._spi.xfer2([_OP_WRITE | (reg & 0x3F), val & 0xFF])

    def _cmd(self, c):
        self._spi.xfer2([c])

    def _cmd_data(self, c, data):
        self._spi.xfer2([c] + list(data))

    def _fifo_w(self, data):
        self._spi.xfer2([_OP_LOAD_FIFO] + list(data))

    def _fifo_r(self, n):
        if n <= 0:
            return b""
        return bytes(self._spi.xfer2([_OP_READ_FIFO] + [0x00] * n)[1:])

    def _fifo_len(self):
        s1 = self._rr(_FIFO_STA1)
        s2 = self._rr(_FIFO_STA2)
        return s1 | ((s2 & 0xC0) << 2)

    def _clear_irqs(self):
        self._rr(_IRQ_MAIN)
        self._rr(_IRQ_TIMER)
        self._rr(_IRQ_ERR)
        self._rr(_IRQ_TGT)

    def _read_irq32(self):
        e = self._rr(_IRQ_ERR)
        mt = self._spi.xfer2([_OP_READ | _IRQ_MAIN, 0x00, 0x00])
        p = self._rr(_IRQ_TGT)
        return (mt[1] << 24) | (mt[2] << 16) | (e << 8) | p

    def _wait_irq(self, mask_main=0xFF, timeout=0.05):
        deadline = time.time() + timeout
        while time.time() < deadline:
            v = self._rr(_IRQ_MAIN)
            if v & mask_main:
                return v
            time.sleep(0.0005)
        return self._rr(_IRQ_MAIN)

    def _set_bits(self, reg, bits):
        v = self._rr(reg)
        self._wr(reg, v | bits)

    def _clr_bits(self, reg, bits):
        v = self._rr(reg)
        self._wr(reg, v & ~bits)

    def _mod_bits(self, reg, set_mask, clr_mask):
        v = self._rr(reg)
        self._wr(reg, (v & ~clr_mask) | set_mask)

    # ── Lifecycle ─────────────────────────────────────────────────────

    def open(self) -> bool:
        if not _SPIDEV_OK:
            return False
        try:
            with open("/sys/class/leds/ext_5v_out/brightness", "w") as f:
                f.write("1")
        except OSError:
            pass
        time.sleep(0.2)

        dev = f"/dev/spidev{self._bus}.{self._cs}"
        if not os.path.exists(dev):
            try:
                subprocess.run(
                    ["dtoverlay", "spi0-spidev2-gpio22-overlay"],
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
            self._spi.mode = _SPI_MODE
        except OSError:
            return False

        time.sleep(0.05)

        self._cmd(_CMD_SET_DEFAULT)
        time.sleep(0.02)

        ic = self._rr(_IC_ID)
        ic_type = (ic >> 3) & 0x1F
        if ic_type != 0x05:
            self._spi.close()
            self._spi = None
            return False

        if not self._init_hw():
            self._spi.close()
            self._spi = None
            return False

        self._opened = True
        return True

    def close(self):
        if self._opened and self._spi:
            try:
                self._cmd(_CMD_STOP_ALL)
                self._mod_bits(_OP_CTRL, 0x00, _TX_EN | _RX_EN)
            except Exception:
                pass
        if self._spi:
            try:
                self._spi.close()
            except Exception:
                pass
            self._spi = None
        self._opened = False

    def _init_hw(self) -> bool:
        # 1. Defensive reset
        self._cmd(_CMD_STOP_ALL)
        self._mod_bits(_OP_CTRL, 0x00, _TX_EN | _RX_EN)
        time.sleep(0.002)

        # 2. Set default
        self._cmd(_CMD_SET_DEFAULT)
        time.sleep(0.02)

        # 3. Overheat protection (mandatory after power-on)
        self._cmd_data(_CMD_TEST_ACCESS, [0x04, 0x10])

        # 4. IO configuration for SPI, 5V VDD
        # IO_CFG1: 0x07 = MCU_CLK disabled, no LF clock
        # IO_CFG2: miso_pd1|miso_pd2|io_drv_lvl|aat_en = 0x3C, sup3V=0 for 5V
        self._wr(_IO_CFG1, 0x07)
        self._wr(_IO_CFG2, _MISO_PD1 | _MISO_PD2 | _IO_DRV | _AAT_EN)  # 0x3C

        # 5. TX driver: AM modulation depth 13 -> (13 << 4) = 0xD0
        self._wr(_TX_DRIVER, 0xD0)

        # 6. Resistive AM modulation sequence (from M5Stack lib)
        self._wr_b(_B_RES_AM_MOD, 0x80)
        self._set_bits(_IO_CFG2, _AAT_EN)
        self._wr_b(_B_RES_AM_MOD, 0x00)

        # 7. External field detector thresholds
        self._wr(_EFD_ACT, 0x13)
        self._wr(_EFD_DEACT, 0x02)

        # 8. Passive target settings
        self._mod_bits(_NFCIP1_PT_DEF, 0x50, 0xF0)  # FDT
        self._wr(_PT_MOD, 0x5F)

        # 9. EMD suppression
        self._wr_b(_B_EMD_SUPP, 0x40)

        # 10. Antenna tuning
        self._wr(_ANT_TUNE1, 0x82)
        self._wr(_ANT_TUNE2, 0x82)

        # 11. Enable external field detector auto
        self._set_bits(_OP_CTRL, _FD_MASK)  # en_fd = auto (0x03)

        # 12. Clear FIFO
        self._cmd(_CMD_CLEAR_FIFO)

        # 13. Unmask all interrupts, then mask all except errors for regulator adjust
        self._wr(_MASK_IRQ_MAIN, 0x00)
        self._wr(_MASK_IRQ_TIMER, 0x00)
        self._wr(_MASK_IRQ_ERR, 0x00)
        self._wr(_MASK_IRQ_TGT, 0x00)

        # 14. Enable oscillator
        if not self._enable_osc():
            return False

        # 15. Adjust regulators
        self._cmd(_CMD_ADJUST_REG)
        time.sleep(0.005)

        # 16. Configure NFC-A
        return self._configure_nfc_a()

    def _enable_osc(self) -> bool:
        v = self._rr(_OP_CTRL)
        if not (v & _EN):
            self._clear_irqs()
            self._set_bits(_OP_CTRL, _EN)
            # Wait for osc_ok (typical 700us, allow 50ms)
            for _ in range(100):
                aux = self._rr(_AUX_DISP)
                if aux & _OSC_OK:
                    return True
                time.sleep(0.001)
            return False
        aux = self._rr(_AUX_DISP)
        return bool(aux & _OSC_OK)

    def _configure_nfc_a(self) -> bool:
        # Mode: initiator, ISO14443A, nfc_ar8_auto
        self._wr(_MODE_DEF, 0x08 | 0x01)  # ISO14443A + nfc_ar_auto
        # Bitrate 106/106
        self._wr(_BIT_RATE, 0x00)
        # ISO14443A settings: standard
        self._wr(_ISO14443A, 0x00)

        # Clear dis_corr
        self._clr_bits(_AUX_DEF, _DIS_CORR)

        # Overshoot/undershoot protection
        self._wr_b(_B_OVERSHOOT1, 0x40)
        self._wr_b(_B_OVERSHOOT2, 0x03)
        self._wr_b(_B_UNDERSHOOT1, 0x40)
        self._wr_b(_B_UNDERSHOOT2, 0x03)

        # Correlator
        self._wr_b(_B_CORR_CFG1, 0x47)
        self._wr_b(_B_CORR_CFG2, 0x00)

        # Receiver config (stability-focused from M5Stack lib)
        self._wr(_RX_CONF1, 0x08)   # z_600k
        self._wr(_RX_CONF2, 0x2D)   # sqm_dyn|agc_en|agc_m|agc6_3
        self._wr(_RX_CONF3, 0xD8)   # stability
        self._wr(_RX_CONF4, 0x22)   # stability

        # Reset RX gain
        self._cmd(_CMD_RESET_RX_GAIN)

        # Unmask interrupts
        self._wr(_MASK_IRQ_MAIN, 0x00)
        self._wr(_MASK_IRQ_TIMER, 0x00)
        self._wr(_MASK_IRQ_ERR, 0x00)
        self._wr(_MASK_IRQ_TGT, 0x00)

        # Field ON
        return self._field_on()

    def _field_on(self) -> bool:
        v = self._rr(_OP_CTRL)
        if v & _TX_EN:
            return True

        self._cmd(_CMD_FIELD_ON)
        time.sleep(0.005)
        self._mod_bits(_OP_CTRL, _TX_EN | _RX_EN, 0x00)
        time.sleep(0.05)

        # tx_on bit in AUX_DISP may not read True on this variant
        # but TX works if OP_CTRL has tx_en set — verify with REQA
        op = self._rr(_OP_CTRL)
        return bool(op & _TX_EN)

    def _field_off(self):
        self._cmd(_CMD_STOP_ALL)
        self._mod_bits(_OP_CTRL, 0x00, _TX_EN | _RX_EN)

    def _field_reset(self):
        self._field_off()
        time.sleep(0.025)
        self._field_on()

    # ── NFC-A no-response timer ───────────────────────────────────────

    def _set_nrt(self, ms):
        step = self._rr(_TIMER_EMV) & 0x01  # nrt_step
        fc = 13560000
        if step:
            nrt = (ms * fc + 4095999) // 4096000
        else:
            nrt = (ms * fc + 63999) // 64000
        nrt = max(1, min(nrt, 0xFFFF))
        self._wr(_NRT1, (nrt >> 8) & 0xFF)
        self._wr(_NRT2, nrt & 0xFF)

    # ── Low-level transceive ──────────────────────────────────────────

    def _transceive(self, tx, crc=True, timeout=0.1):
        self._set_nrt(max(1, int(timeout * 1000)))
        self._wr(_ISO14443A, 0x00)
        self._clr_bits(_AUX_DEF, _NO_CRC_RX)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w(tx)
        self._wr(_NUM_TX1, len(tx))
        self._wr(_NUM_TX2, 0x00)
        self._cmd(_CMD_TX_CRC if crc else _CMD_TX_NO_CRC)

        # Wait for RX end
        deadline = time.time() + timeout + 0.05
        while time.time() < deadline:
            m = self._rr(_IRQ_MAIN)
            if m & _I_RXE:
                n = self._fifo_len()
                return self._fifo_r(n) if n > 0 else None
            if m & (_I_TXE):
                time.sleep(0.001)
                continue
            time.sleep(0.0005)
        return None

    # ── ISO 14443-A activation ────────────────────────────────────────

    def _send_reqa(self):
        self._set_nrt(5)
        self._wr(_ISO14443A, _ANTCL)
        self._set_bits(_AUX_DEF, _NO_CRC_RX)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._cmd(_CMD_TX_REQA)

        deadline = time.time() + 0.02
        while time.time() < deadline:
            m = self._rr(_IRQ_MAIN)
            if m & _I_RXE:
                n = self._fifo_len()
                if n >= 2:
                    d = self._fifo_r(n)
                    return d[0] | (d[1] << 8)
            if m & _I_RXS:
                time.sleep(0.001)
                n = self._fifo_len()
                if n >= 2:
                    d = self._fifo_r(n)
                    return d[0] | (d[1] << 8)
            time.sleep(0.0005)
        return None

    def _anticoll(self, cascade):
        self._set_nrt(5)
        self._wr(_ISO14443A, _ANTCL)
        self._clr_bits(_AUX_DEF, _NO_CRC_RX)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w([cascade, 0x20])
        self._wr(_NUM_TX1, 2)
        self._wr(_NUM_TX2, 0x00)
        self._cmd(_CMD_TX_NO_CRC)

        deadline = time.time() + 0.02
        while time.time() < deadline:
            m = self._rr(_IRQ_MAIN)
            if m & _I_RXE:
                n = self._fifo_len()
                if n >= 5:
                    return self._fifo_r(n)
                return None
            if m & _I_COL:
                n = self._fifo_len()
                if n >= 5:
                    return self._fifo_r(n)
                return None
            time.sleep(0.0005)
        return None

    def _select(self, cascade, nfcid, bcc):
        self._wr(_ISO14443A, 0x00)
        self._clr_bits(_AUX_DEF, _NO_CRC_RX)
        return self._transceive([cascade, 0x70] + list(nfcid) + [bcc],
                                crc=True, timeout=0.05)

    def _activate_nfca(self):
        atqa = self._send_reqa()
        if atqa is None:
            return None

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
        return CardInfo(uid=bytes(uid), atqa=atqa, sak=sak)

    # ── _PN532Base-compatible public API ──────────────────────────────

    def get_firmware(self) -> Optional[Tuple[int, int, int, int]]:
        if not self._opened:
            return None
        ic = self._rr(_IC_ID)
        return (0x25, ic, 0, 0)

    def sam_config(self):
        pass

    def read_passive_target(self, card_type=0x00, timeout=2.0) -> Optional[CardInfo]:
        if not self._opened:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            card = self._activate_nfca()
            if card is not None:
                return card
            time.sleep(0.05)
        return None

    def mifare_auth(self, block: int, key: bytes, uid: bytes,
                    key_type: int = MIFARE_AUTH_A) -> bool:
        tx = [key_type, block] + list(key[:6]) + list(uid[:4])
        resp = self._transceive(tx, crc=False, timeout=0.2)
        return resp is not None

    def mifare_read(self, block: int) -> Optional[bytes]:
        resp = self._transceive([_MF_READ, block], crc=True, timeout=0.1)
        if resp and len(resp) >= 16:
            return bytes(resp[:16])
        return None

    def mifare_write(self, block: int, data: bytes) -> bool:
        resp = self._transceive([_MF_WRITE, block], crc=True, timeout=0.1)
        if resp is None or len(resp) < 1 or resp[0] != _ACK:
            return False
        time.sleep(0.001)
        resp2 = self._transceive(list(data[:16]), crc=True, timeout=0.1)
        return resp2 is not None and len(resp2) >= 1 and resp2[0] == _ACK

    def mifare_ul_read(self, page: int) -> Optional[bytes]:
        resp = self._transceive([_MF_READ, page], crc=True, timeout=0.1)
        if resp and len(resp) >= 16:
            return bytes(resp[:16])
        return None

    def mifare_ul_write(self, page: int, data: bytes) -> bool:
        tx = [_MF_UL_WR, page] + list(data[:4])
        resp = self._transceive(tx, crc=True, timeout=0.1)
        return resp is not None and len(resp) >= 1 and resp[0] == _ACK

    def communicate_thru(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        resp = self._transceive(list(data), crc=True, timeout=timeout)
        return bytes(resp) if resp and len(resp) >= 2 else None

    def data_exchange(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        return self.communicate_thru(data, timeout=timeout)

    def in_communicate_thru_raw(self, data: bytes, timeout=0.5) -> Optional[bytes]:
        resp = self._transceive(list(data), crc=False, timeout=timeout)
        return bytes(resp) if resp else None

    def init_as_target(self, uid, atqa=b"\x04\x00", sak=0x08, timeout=1.0):
        return None

    def tg_get_data(self):
        return None

    def tg_set_data(self, data):
        return False

    @staticmethod
    def detect() -> bool:
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
                    ["dtoverlay", "spi0-spidev2-gpio22-overlay"],
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
            spi.mode = _SPI_MODE
            spi.xfer2([_CMD_SET_DEFAULT])
            time.sleep(0.02)
            ic = spi.xfer2([_OP_READ | _IC_ID, 0x00])[1]
            spi.close()
            ic_type = (ic >> 3) & 0x1F
            return ic_type == 0x05
        except Exception:
            return False
