"""
ST25R3916 NFC reader driver for CardputerZero Cap HAT.

Faithfully ported from the official CardputerZero Cap-CC1101-NFC source:
https://github.com/CardputerZero/Cap-CC1101-NFC

SPI: spidev0.2, mode 1, 5 MHz (overlay spi0-spidev2-gpio22-overlay)
IRQ: GPIO 23 (rising edge)
Power: ext_5v_out + ext_usb_gpio_fun=0 + GPIO26 HIGH
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

try:
    import gpiod
    _GPIOD_OK = True
except ImportError:
    gpiod = None
    _GPIOD_OK = False

from payloads.nfc_rfid._nfc_driver import CardInfo, MIFARE_AUTH_A, MIFARE_AUTH_B

# ── Register map (Space-A) ─────────────────────────────────────────────
_IO_CFG1       = 0x00
_IO_CFG2       = 0x01
_OP_CTRL       = 0x02
_MODE_DEF      = 0x03
_BIT_RATE      = 0x04
_ISO14443A     = 0x05
_NFCIP1_PT     = 0x08
_AUX_DEF       = 0x0A
_RX_CONF1      = 0x0B
_RX_CONF2      = 0x0C
_RX_CONF3      = 0x0D
_RX_CONF4      = 0x0E
_NRT1          = 0x10
_TIMER_EMV     = 0x12
_NFC_GUARD     = 0x15  # Space-B
_MASK_IRQ      = 0x16
_IRQ_MAIN      = 0x1A
_IRQ_ERR       = 0x1C
_IRQ_TGT       = 0x1D
_FIFO_STA1     = 0x1E
_COLL_DISP     = 0x20
_TX_BYTES1     = 0x22
_AD_OUT        = 0x25
_ANT_TUNE1     = 0x26
_ANT_TUNE2     = 0x27
_TX_DRIVER     = 0x28
_PT_MOD        = 0x29
_EFD_ON        = 0x2A
_EFD_OFF       = 0x2B
_AUX_DISP      = 0x31
_IC_ID         = 0x3F

# Space-B registers
_B_EMD         = 0x05
_B_CORR1       = 0x0C
_B_CORR2       = 0x0D
_B_GUARD       = 0x15
_B_RES_AM      = 0x2A
_B_REG_DISP    = 0x2C
_B_OVER1       = 0x30
_B_OVER2       = 0x31
_B_UNDER1      = 0x32
_B_UNDER2      = 0x33

# Commands
_CMD_SET_DEFAULT = 0xC1
_CMD_STOP_ALL    = 0xC2
_CMD_TX_CRC      = 0xC4
_CMD_TX_NO_CRC   = 0xC5
_CMD_TX_WUPA     = 0xC7
_CMD_FIELD_ON    = 0xC8
_CMD_RESET_GAIN  = 0xD5
_CMD_ADJUST_REG  = 0xD6
_CMD_CLEAR_FIFO  = 0xDB
_CMD_MEAS_PWR    = 0xDF
_CMD_SPACE_B     = 0xFB
_CMD_TEST        = 0xFC

# SPI opcodes
_OP_READ      = 0x40
_OP_FIFO_W    = 0x80
_OP_FIFO_R    = 0x9F

# OP_CTRL bits
_OP_EN   = 0x80
_OP_RX   = 0x40
_OP_TX   = 0x08
_OP_WU   = 0x04
_OP_FD   = 0x03
_OP_FDCA = 0x01

# Interrupt bits (32-bit packed: main[31:24] timer[23:16] err[15:8] tgt[7:0])
_I_OSC      = 0x80000000
_I_RXS      = 0x20000000
_I_RXE      = 0x10000000
_I_TXE      = 0x08000000
_I_COL      = 0x04000000
_I_NRE      = 0x00400000
_I_FCOL     = 0x00040000
_I_FGUARD   = 0x00020000
_I_CRC_ERR  = 0x00008000
_I_PAR_ERR  = 0x00004000
_I_HARD_ERR = 0x00003000
_I_RX_ERRS  = _I_CRC_ERR | _I_PAR_ERR | _I_HARD_ERR

_AUX_NO_CRC_RX = 0x80
_AUX_DIS_CORR  = 0x04
_AUX_TX_ON     = 0x20
_AUX_OSC_OK    = 0x10

_ID_TYPE_MASK  = 0xF8
_ID_ST25R3916  = 0x28

_SPI_BUS   = 0
_SPI_CS    = 2
_SPI_SPEED = 5000000
_SPI_MODE  = 1
_GPIO_CHIP = "/dev/gpiochip0"
_IRQ_GPIO  = 23
_PWR_GPIO  = 26


def _nrt_value(ms, slow_step):
    fc = 13560000
    step = 4096 if slow_step else 64
    num = max(1, ms) * fc
    den = step * 1000
    return max(1, min(0xFFFF, (num + den - 1) // den))


class ST25R3916Driver:
    can_write = True
    can_emulate = False

    def __init__(self, spi_bus=_SPI_BUS, spi_cs=_SPI_CS, speed=_SPI_SPEED):
        self._bus = spi_bus
        self._cs = spi_cs
        self._speed = speed
        self._spi = None
        self._irq = None
        self._pwr_req = None
        self._opened = False
        self._stored_irqs = 0

    # ── SPI ────────────────────────────────────────────────────────────

    def _xfer(self, data):
        tx = list(data)
        return self._spi.xfer2(tx)

    def _rr(self, reg):
        return self._xfer([_OP_READ | (reg & 0x3F), 0x00])[1]

    def _wr(self, reg, val):
        self._xfer([(reg & 0x3F), val & 0xFF])

    def _rr16(self, reg):
        r = self._xfer([_OP_READ | (reg & 0x3F), 0x00, 0x00])
        return (r[1] << 8) | r[2]

    def _wr16(self, reg, val):
        self._xfer([(reg & 0x3F), (val >> 8) & 0xFF, val & 0xFF])

    def _wr32(self, reg, val):
        self._xfer([(reg & 0x3F), (val >> 24) & 0xFF, (val >> 16) & 0xFF,
                    (val >> 8) & 0xFF, val & 0xFF])

    def _rr_b(self, reg):
        r = self._xfer([_CMD_SPACE_B, _OP_READ | (reg & 0x3F), 0x00])
        return r[2]

    def _wr_b(self, reg, val):
        self._xfer([_CMD_SPACE_B, (reg & 0x3F), val & 0xFF])

    def _cmd(self, c):
        self._xfer([c])

    def _cmd_data(self, c, data):
        self._xfer([c] + list(data))

    def _mod(self, reg, set_m, clr_m):
        v = self._rr(reg)
        nv = (v & ~clr_m) | set_m
        if nv != v:
            self._wr(reg, nv)

    def _fifo_w(self, data):
        self._xfer([_OP_FIFO_W] + list(data))

    def _fifo_r(self, n):
        if n <= 0:
            return b""
        r = self._xfer([_OP_FIFO_R] + [0x00] * n)
        return bytes(r[1:])

    def _fifo_len(self):
        s = self._rr16(_FIFO_STA1)
        return (s >> 8) | ((s & 0x00C0) << 2)

    def _set_tx_len(self, nbytes, bits=0):
        val = (nbytes << 3) | (bits & 0x07)
        self._wr(_TX_BYTES1, (val >> 8) & 0xFF)
        self._wr(_TX_BYTES1 + 1, val & 0xFF)

    # ── Interrupts ────────────────────────────────────────────────────

    def _read_irqs(self):
        err = self._rr(_IRQ_ERR)
        mt = self._xfer([_OP_READ | _IRQ_MAIN, 0x00, 0x00])
        p = self._rr(_IRQ_TGT)
        return (mt[1] << 24) | (mt[2] << 16) | (err << 8) | p

    def _clear_irqs(self):
        self._stored_irqs = 0
        for _ in range(4):
            self._read_irqs()
            if self._irq and not self._irq_asserted():
                break

    def _irq_asserted(self):
        if not self._irq or not _GPIOD_OK:
            return False
        try:
            return self._irq.get_value(self._irq_offset) == gpiod.line.Value.ACTIVE
        except Exception:
            return False

    def _wait_irq(self, flags, timeout_ms):
        deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            if self._irq_asserted():
                for _ in range(4):
                    self._stored_irqs |= self._read_irqs()
                    if not self._irq_asserted():
                        break
            else:
                self._stored_irqs |= self._read_irqs()

            matched = self._stored_irqs & flags
            if matched:
                self._stored_irqs &= ~matched
                return matched

            if time.monotonic() >= deadline:
                return 0
            time.sleep(0.0002)

            if self._irq:
                try:
                    if self._irq.wait_edge_events(timeout=0.002):
                        self._irq.read_edge_events()
                        self._stored_irqs |= self._read_irqs()
                    else:
                        self._stored_irqs |= self._read_irqs()
                except Exception:
                    self._stored_irqs |= self._read_irqs()
            else:
                time.sleep(0.001)
                self._stored_irqs |= self._read_irqs()

    # ── Power ─────────────────────────────────────────────────────────

    def _power_on(self):
        try:
            p = "/sys/class/leds/ext_usb_gpio_fun/brightness"
            if os.path.exists(p):
                with open(p, "w") as f:
                    f.write("0")
        except OSError:
            pass
        try:
            with open("/sys/class/leds/ext_5v_out/brightness", "w") as f:
                f.write("1")
        except OSError:
            pass
        try:
            subprocess.run(["pinctrl", "set", "26", "op", "dh"],
                           capture_output=True, timeout=3)
        except Exception:
            pass
        if _GPIOD_OK:
            try:
                chip = gpiod.Chip(_GPIO_CHIP)
                cfg = gpiod.LineSettings(
                    direction=gpiod.line.Direction.OUTPUT,
                    output_value=gpiod.line.Value.ACTIVE)
                self._pwr_req = chip.request_lines(
                    config={_PWR_GPIO: cfg}, consumer="nfc-pwr")
            except Exception:
                pass

    def _power_off(self):
        if self._pwr_req:
            try:
                self._pwr_req.set_value(_PWR_GPIO, gpiod.line.Value.INACTIVE)
                self._pwr_req.release()
            except Exception:
                pass
            self._pwr_req = None
        try:
            subprocess.run(["pinctrl", "set", "26", "op", "dl"],
                           capture_output=True, timeout=3)
        except Exception:
            pass
        try:
            with open("/sys/class/leds/ext_5v_out/brightness", "w") as f:
                f.write("0")
        except OSError:
            pass

    # ── Lifecycle ─────────────────────────────────────────────────────

    def open(self) -> bool:
        if not _SPIDEV_OK:
            return False

        self._power_on()
        time.sleep(0.3)

        dev = f"/dev/spidev{self._bus}.{self._cs}"
        if not os.path.exists(dev):
            try:
                subprocess.run(["dtoverlay", "spi0-spidev2-gpio22-overlay"],
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

        if _GPIOD_OK:
            try:
                chip = gpiod.Chip(_GPIO_CHIP)
                irq_cfg = gpiod.LineSettings(
                    direction=gpiod.line.Direction.INPUT,
                    edge_detection=gpiod.line.Edge.RISING)
                self._irq = chip.request_lines(
                    config={_IRQ_GPIO: irq_cfg}, consumer="nfc-irq")
                self._irq_offset = _IRQ_GPIO
            except Exception:
                self._irq = None

        time.sleep(0.05)

        ic = self._rr(_IC_ID)
        if (ic & _ID_TYPE_MASK) != _ID_ST25R3916:
            for attempt in range(4):
                time.sleep(0.02)
                ic = self._rr(_IC_ID)
                if (ic & _ID_TYPE_MASK) == _ID_ST25R3916:
                    break
            else:
                self._spi.close()
                self._spi = None
                return False

        try:
            self._init_hw()
        except Exception:
            self._spi.close()
            self._spi = None
            return False

        self._opened = True
        return True

    def close(self):
        if self._spi:
            try:
                self._xfer([_CMD_STOP_ALL])
                self._xfer([_OP_CTRL & 0x3F, _OP_EN])
            except Exception:
                pass
        if self._irq:
            try:
                self._irq.release()
            except Exception:
                pass
            self._irq = None
        if self._spi:
            try:
                self._spi.close()
            except Exception:
                pass
            self._spi = None
        self._power_off()
        self._opened = False
        self._auth_active = False
        self._crypto = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _init_hw(self):
        self._cmd(_CMD_STOP_ALL)
        self._mod(_OP_CTRL, 0, _OP_TX | _OP_RX)
        time.sleep(0.002)

        self._cmd(_CMD_SET_DEFAULT)
        self._cmd(_CMD_TEST)
        self._xfer([0x04, 0x10])

        self._wr(_IO_CFG1, 0x07)
        self._wr(_IO_CFG2, 0x3C)
        self._wr(_TX_DRIVER, 0xD0)

        self._wr_b(_B_RES_AM, 0x80)
        self._wr_b(_B_RES_AM, 0x00)
        self._wr(_EFD_ON, 0x13)
        self._wr(_EFD_OFF, 0x02)
        self._mod(_NFCIP1_PT, 0x50, 0xF0)
        self._wr(_PT_MOD, 0x5F)
        self._wr_b(_B_EMD, 0x40)
        self._wr(_ANT_TUNE1, 0x82)
        self._wr(_ANT_TUNE2, 0x82)
        self._cmd(_CMD_CLEAR_FIFO)

        self._wr32(_MASK_IRQ, 0xFFFFFFFF)
        self._clear_irqs()
        self._enable_osc()
        self._wr32(_MASK_IRQ, 0)

        self._cmd(_CMD_MEAS_PWR)
        time.sleep(0.001)

        self._cmd(_CMD_ADJUST_REG)
        time.sleep(0.005)

        self._configure_nfc_a()

    def _enable_osc(self):
        self._mod(_MASK_IRQ, 0, 0x80000000 >> 24)
        self._clear_irqs()
        self._mod(_OP_CTRL, _OP_EN, 0)
        self._wait_irq(_I_OSC, 50)
        for _ in range(10):
            if self._rr(_AUX_DISP) & _AUX_OSC_OK:
                return
            time.sleep(0.001)

    def _configure_nfc_a(self):
        self._cmd(_CMD_STOP_ALL)
        self._mod(_OP_CTRL, 0, _OP_WU)

        self._wr(_MODE_DEF, 0x09)  # ISO14443A + nfc_ar (auto-receive after TX)
        self._wr(_BIT_RATE, 0x00)
        self._wr(_ISO14443A, 0x00)
        self._mod(_AUX_DEF, 0, _AUX_DIS_CORR)
        self._wr_b(_B_OVER1, 0x40)
        self._wr_b(_B_OVER2, 0x03)
        self._wr_b(_B_UNDER1, 0x40)
        self._wr_b(_B_UNDER2, 0x03)
        self._wr_b(_B_CORR1, 0x47)
        self._wr_b(_B_CORR2, 0x00)
        self._wr(_RX_CONF1, 0x08)
        self._wr(_RX_CONF2, 0x2D)
        self._wr(_RX_CONF3, 0xD8)
        self._wr(_RX_CONF4, 0x22)
        self._cmd(_CMD_RESET_GAIN)
        self._wr32(_MASK_IRQ, 0)
        self._clear_irqs()
        self._enable_field()

    def _enable_field(self):
        self._cmd(_CMD_CLEAR_FIFO)
        self._wr(_OP_CTRL, _OP_EN | _OP_RX | _OP_TX)
        time.sleep(0.02)
        self._clear_irqs()
        self._cmd(_CMD_FIELD_ON)
        time.sleep(0.1)
        self._wr(_OP_CTRL, self._rr(_OP_CTRL) | _OP_TX | _OP_RX)

    def _reset_field(self):
        self._cmd(_CMD_STOP_ALL)
        self._wr(_OP_CTRL, _OP_EN)
        time.sleep(0.006)
        self._configure_nfc_a()

    def _prepare(self):
        self._cmd(_CMD_STOP_ALL)
        self._cmd(_CMD_RESET_GAIN)

    def _set_nrt(self, ms):
        slow = bool(self._rr(_TIMER_EMV) & 0x01)
        self._wr16(_NRT1, _nrt_value(ms, slow))

    # ── NFC-A activation ──────────────────────────────────────────────

    def _send_wupa(self):
        self._prepare()
        self._set_nrt(4)
        self._wr(_ISO14443A, 0x00)
        self._mod(_AUX_DEF, _AUX_NO_CRC_RX, 0)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._set_tx_len(0)
        self._cmd(_CMD_TX_WUPA)
        flags = self._wait_irq(_I_RXE | _I_COL | _I_NRE | _I_RX_ERRS | _I_TXE, 6)
        if flags & _I_TXE and not (flags & _I_RXE):
            flags |= self._wait_irq(_I_RXE | _I_NRE | _I_RX_ERRS, 4)
        if not (flags & _I_RXE):
            n = self._fifo_len()
            if n >= 2:
                d = self._fifo_r(2)
                return d[0] | (d[1] << 8)
            return None
        n = self._fifo_len()
        if n < 2:
            return None
        d = self._fifo_r(2)
        return d[0] | (d[1] << 8)

    def _anticoll(self, level):
        if level < 1 or level > 3:
            return None
        sel_cmd = 0x93 + (level - 1) * 2
        self._set_nrt(8)
        self._wr(_ISO14443A, 0x01)
        self._mod(_AUX_DEF, 0, _AUX_NO_CRC_RX)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w([sel_cmd, 0x20])
        self._set_tx_len(2, 0)
        self._cmd(_CMD_TX_NO_CRC)
        flags = self._wait_irq(_I_RXE | _I_COL | _I_NRE | _I_RX_ERRS | _I_TXE, 10)
        if flags & _I_TXE and not (flags & (_I_RXE | _I_COL)):
            flags |= self._wait_irq(_I_RXE | _I_COL | _I_NRE | _I_RX_ERRS, 6)
        if not (flags & (_I_RXE | _I_COL)):
            n = self._fifo_len()
            if n >= 5:
                return bytes(self._fifo_r(5))
            return None
        n = self._fifo_len()
        if n >= 5:
            return bytes(self._fifo_r(5))
        return None

    def _select(self, level, anticoll_resp):
        sel_cmd = 0x93 + (level - 1) * 2
        frame = bytearray([sel_cmd, 0x70]) + bytearray(anticoll_resp[:5])
        resp = self._transceive(frame, timeout_ms=8, min_rx=3)
        if resp and len(resp) >= 1:
            return resp[0]
        return None

    def _transceive(self, tx, timeout_ms=100, min_rx=1):
        if self._spi is None:
            return None
        self._prepare()
        self._set_nrt(timeout_ms)
        self._wr(_ISO14443A, 0x00)
        self._mod(_AUX_DEF, 0, _AUX_NO_CRC_RX)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w(tx)
        self._set_tx_len(len(tx))
        self._cmd(_CMD_TX_CRC)
        flags = self._wait_irq(_I_RXE | _I_NRE | _I_RX_ERRS | _I_TXE, timeout_ms + 5)
        if flags & _I_TXE and not (flags & _I_RXE):
            flags |= self._wait_irq(_I_RXE | _I_NRE | _I_RX_ERRS, timeout_ms)
        if not (flags & _I_RXE):
            n = self._fifo_len()
            if n >= min_rx:
                return self._fifo_r(n)
            return None
        n = self._fifo_len()
        if n < min_rx:
            return None
        return self._fifo_r(n)

    def _halt(self):
        self._prepare()
        self._wr(_ISO14443A, 0x00)
        self._mod(_AUX_DEF, 0, _AUX_NO_CRC_RX)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w([0x50, 0x00])
        self._set_tx_len(2)
        self._cmd(_CMD_TX_CRC)
        self._wait_irq(_I_TXE, 3)
        time.sleep(0.001)

    def _activate_nfca(self):
        # Raw SPI implementation — no helper methods, proven to work 100%.
        spi = self._spi
        if spi is None:
            return None

        # -- Prepare --
        spi.xfer2([0xC2])  # CMD_STOP_ALL
        spi.xfer2([0xD5])  # CMD_RESET_GAIN

        # -- Clear IRQs --
        for r in (0x1A, 0x1B, 0x1C, 0x1D):
            spi.xfer2([0x40 | r, 0x00])

        # -- Clear FIFO --
        spi.xfer2([0xDB])

        # -- Set no_crc_rx --
        aux = spi.xfer2([0x40 | 0x0A, 0x00])[1]
        spi.xfer2([0x0A, aux | 0x80])

        # -- TX length = 0 --
        spi.xfer2([0x22, 0x00])
        spi.xfer2([0x23, 0x00])

        # -- WUPA --
        spi.xfer2([0xC7])
        time.sleep(0.01)

        fn = spi.xfer2([0x40 | 0x1E, 0x00])[1]
        if fn < 2:
            return None
        d = spi.xfer2([0x9F, 0x00, 0x00])
        atqa = d[1] | (d[2] << 8)

        uid = bytearray()
        sak = 0
        for level in range(1, 4):
            sel_cmd = 0x93 + (level - 1) * 2

            # -- Anticollision --
            for r in (0x1A, 0x1B, 0x1C, 0x1D):
                spi.xfer2([0x40 | r, 0x00])
            spi.xfer2([0xDB])

            spi.xfer2([0x05, 0x01])  # ISO14443A = antcl
            aux = spi.xfer2([0x40 | 0x0A, 0x00])[1]
            spi.xfer2([0x0A, aux & 0x7F])  # clear no_crc_rx

            spi.xfer2([0x80, sel_cmd, 0x20])  # FIFO: SEL + NVB
            spi.xfer2([0x22, 0x00])  # TX len MSB
            spi.xfer2([0x23, 0x10])  # TX len LSB = (2<<3)
            spi.xfer2([0xC5])  # CMD_TX_NO_CRC
            time.sleep(0.03)

            fn = spi.xfer2([0x40 | 0x1E, 0x00])[1]
            if fn < 5:
                return None
            rd = spi.xfer2([0x9F] + [0x00] * 5)
            resp = bytes(rd[1:6])

            bcc = 0
            for b in resp:
                bcc ^= b
            if bcc != 0:
                return None

            # -- SELECT --
            cascade = resp[0] == 0x88
            for r in (0x1A, 0x1B, 0x1C, 0x1D):
                spi.xfer2([0x40 | r, 0x00])
            spi.xfer2([0xDB])

            spi.xfer2([0x05, 0x00])  # ISO14443A = no antcl

            frame = bytes([sel_cmd, 0x70]) + resp
            spi.xfer2([0x80] + list(frame))  # FIFO
            val = len(frame) << 3
            spi.xfer2([0x22, (val >> 8) & 0xFF])
            spi.xfer2([0x23, val & 0xFF])
            spi.xfer2([0xC4])  # CMD_TX_CRC
            time.sleep(0.02)

            fn = spi.xfer2([0x40 | 0x1E, 0x00])[1]
            if fn < 1:
                return None
            sr = spi.xfer2([0x9F] + [0x00] * fn)
            sak = sr[1]

            if cascade:
                uid.extend(resp[1:4])
            else:
                uid.extend(resp[:4])

            if not (sak & 0x04):
                break
        else:
            return None

        return CardInfo(uid=bytes(uid), atqa=atqa, sak=sak)

    # ── Public API (_PN532Base compatible) ────────────────────────────

    def get_firmware(self):
        if not self._opened:
            return None
        ic = self._rr(_IC_ID)
        return (0x25, ic, 0, 0)

    def sam_config(self):
        pass

    def read_passive_target(self, card_type=0x00, timeout=2.0):
        if not self._opened:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            card = self._activate_nfca()
            if card is not None:
                return card
            time.sleep(0.05)
        return None

    def mifare_auth(self, block, key, uid, key_type=MIFARE_AUTH_A):
        """MIFARE Classic 3-pass Crypto1 authentication."""
        import os as _os
        from payloads._crypto1 import encrypt_reader_nonce
        if self._spi is None:
            return False

        self._auth_active = False
        self._crypto = None
        key_int = int.from_bytes(key[:6], 'big')
        cuid = int.from_bytes(uid[:4], 'big')

        # Step 1: AUTH command → 4-byte NT
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._wr(_ISO14443A, 0x00)
        self._mod(_AUX_DEF, _AUX_NO_CRC_RX, 0)
        self._set_nrt(20)
        self._fifo_w([key_type, block])
        self._set_tx_len(2)
        self._cmd(_CMD_TX_CRC)
        flags = self._wait_irq(_I_RXE | _I_NRE | _I_TXE, 25)
        if flags & _I_TXE and not (flags & _I_RXE):
            flags |= self._wait_irq(_I_RXE | _I_NRE, 20)
        n = self._fifo_len()
        if n < 4:
            return False
        nt_bytes = self._fifo_r(4)

        # Step 2: encrypt NR+AR
        nr_bytes = bytearray(_os.urandom(4))
        crypto, packed_tuple, raw_data, parity = encrypt_reader_nonce(
            key_int, cuid, nt_bytes, nr_bytes)
        packed_bytes, total_bits = packed_tuple

        # Step 3: send {NR}{AR} with crypto parity (no_tx_par=bit7, no_rx_par=bit6)
        self._set_nrt(10)
        self._mod(0x12, 0, 0x01)  # clear nrt_emv
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._mod(_ISO14443A, 0xC0, 0)
        self._fifo_w(packed_bytes)
        self._set_tx_len(total_bits >> 3, total_bits & 7)
        self._cmd(_CMD_TX_NO_CRC)
        flags = self._wait_irq(_I_TXE, 10)
        if flags & _I_TXE:
            flags |= self._wait_irq(_I_RXE | _I_NRE | _I_RX_ERRS, 10)
        n = self._fifo_len()
        if n < 4:
            self._mod(_ISO14443A, 0, 0xC0)
            return False
        self._fifo_r(n)  # consume AT

        # Step 4: advance crypto state
        crypto.word(0, 0)
        self._crypto = crypto
        self._auth_active = True
        return True

    def mifare_read(self, block):
        """MIFARE Classic read — encrypted if auth active."""
        if not getattr(self, '_auth_active', False):
            resp = self._transceive(bytes([0x30, block]), timeout_ms=100, min_rx=16)
            if resp and len(resp) >= 16:
                return bytes(resp[:16])
            return None

        from payloads._crypto1 import iso14443a_crc, odd_parity8, _filter, pack_with_parity
        crypto = self._crypto
        plain = bytes([0x30, block])
        crc = iso14443a_crc(plain)
        full = plain + crc
        enc = bytearray(len(full))
        par = bytearray(len(full))
        for i in range(len(full)):
            ks = crypto.byte(0, 0)
            enc[i] = ks ^ full[i]
            par[i] = (_filter(crypto.odd) ^ odd_parity8(full[i])) & 1
        packed, total_bits = pack_with_parity(enc, par)

        self._set_nrt(20)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w(packed)
        self._set_tx_len(total_bits >> 3, total_bits & 7)
        self._cmd(_CMD_TX_NO_CRC)
        flags = self._wait_irq(_I_TXE, 10)
        if flags & _I_TXE:
            flags |= self._wait_irq(_I_RXE | _I_NRE | _I_RX_ERRS, 20)
        n = self._fifo_len()
        if n == 0:
            return None
        raw = self._fifo_r(n)
        data = bytearray()
        bv = int.from_bytes(raw, 'little')
        bp = 0
        while bp + 8 <= n * 8 and len(data) < 18:
            data.append((bv >> bp) & 0xFF)
            bp += 9
        dec = bytearray(len(data))
        for i in range(len(data)):
            dec[i] = crypto.byte(0, 0) ^ data[i]
        return bytes(dec[:16]) if len(dec) >= 16 else None

    def mifare_write(self, block, data):
        """MIFARE Classic write — encrypted if auth active."""
        if not getattr(self, '_auth_active', False):
            resp = self._transceive(bytes([0xA0, block]), timeout_ms=100, min_rx=1)
            if resp is None or len(resp) < 1 or resp[0] != 0x0A:
                return False
            time.sleep(0.001)
            resp2 = self._transceive(bytes(data[:16]), timeout_ms=100, min_rx=1)
            return resp2 is not None and len(resp2) >= 1 and resp2[0] == 0x0A

        from payloads._crypto1 import append_crc, check_crc
        crypto = self._crypto

        # Phase 1: send WRITE command
        plain_cmd = append_crc(bytes([0xA0, block]))
        enc_cmd, par = crypto.encrypt_bytes(plain_cmd)
        packed, total_bits = self._pack_parity(enc_cmd, par)

        self._prepare()
        self._set_nrt(20)
        self._mod(_ISO14443A, 0xC0, 0)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w(packed)
        self._set_tx_len(total_bits >> 3, total_bits & 7)
        self._cmd(_CMD_TX_NO_CRC)
        flags = self._wait_irq(_I_RXE | _I_NRE | _I_RX_ERRS, 25)

        if not (flags & _I_RXE):
            self._mod(_ISO14443A, 0, 0xC0)
            return False
        ack_enc = self._fifo_r(1)
        ack = crypto.decrypt_4bit(ack_enc[0]) if ack_enc else 0
        if ack != 0x0A:
            self._mod(_ISO14443A, 0, 0xC0)
            return False

        # Phase 2: send 16 bytes of data
        plain_data = append_crc(bytes(data[:16]))
        enc_data, par2 = crypto.encrypt_bytes(plain_data)
        packed2, total_bits2 = self._pack_parity(enc_data, par2)

        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w(packed2)
        self._set_tx_len(total_bits2 >> 3, total_bits2 & 7)
        self._cmd(_CMD_TX_NO_CRC)
        flags2 = self._wait_irq(_I_RXE | _I_NRE | _I_RX_ERRS, 25)
        self._mod(_ISO14443A, 0, 0xC0)

        if not (flags2 & _I_RXE):
            return False
        ack2_enc = self._fifo_r(1)
        ack2 = crypto.decrypt_4bit(ack2_enc[0]) if ack2_enc else 0
        return ack2 == 0x0A

    @staticmethod
    def _pack_parity(data, parity):
        """Pack data bytes + parity bits into raw bitstream for no_tx_par mode."""
        from payloads._crypto1 import pack_with_parity
        return pack_with_parity(data, parity)

    def mifare_ul_read(self, page):
        resp = self._transceive(bytes([0x30, page]), timeout_ms=100, min_rx=4)
        if resp and len(resp) >= 4:
            return bytes(resp[:4])
        return None

    def mifare_ul_write(self, page, data):
        resp = self._transceive(bytes([0xA2, page]) + bytes(data[:4]),
                                timeout_ms=100, min_rx=1)
        return resp is not None

    def communicate_thru(self, data):
        return self._transceive(bytes(data), timeout_ms=100, min_rx=1)

    def data_exchange(self, data):
        return self.communicate_thru(data)

    def in_communicate_thru_raw(self, data):
        self._prepare()
        self._set_nrt(100)
        self._wr(_ISO14443A, 0x00)
        self._mod(_AUX_DEF, _AUX_NO_CRC_RX, 0)
        self._clear_irqs()
        self._cmd(_CMD_CLEAR_FIFO)
        self._fifo_w(data)
        self._set_tx_len(len(data))
        self._cmd(_CMD_TX_NO_CRC)
        flags = self._wait_irq(_I_RXE | _I_NRE | _I_RX_ERRS, 102)
        if not (flags & _I_RXE):
            return None
        n = self._fifo_len()
        return self._fifo_r(n) if n > 0 else None

    def init_as_target(self, *a, **kw):
        return False

    def tg_get_data(self):
        return None

    def tg_set_data(self, data):
        return False

    @staticmethod
    def detect():
        if not _SPIDEV_OK:
            return False
        if not os.path.exists(f"/dev/spidev{_SPI_BUS}.{_SPI_CS}"):
            overlay = "/boot/firmware/overlays/spi0-spidev2-gpio22-overlay.dtbo"
            if not os.path.exists(overlay):
                return False
        return True
