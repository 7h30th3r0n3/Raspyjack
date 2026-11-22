"""Hardware-free checks for the CardputerZero CE1 / SX1262 receive backend."""

import errno
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evil_lora_tunnel import RadioError, cap
from evil_lora_tunnel.profiles import select_profiles


class CapTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.power = Path(tmp.name) / "power"
        self.mux = Path(tmp.name) / "mux"
        self.power.write_text("0")
        self.mux.write_text("1")
        self.start_patch(patch.object(cap, "_EXT_POWER", self.power))
        self.start_patch(patch.object(cap, "_EXT_MUX", self.mux))
        self.start_patch(patch.object(cap.time, "sleep"))
        self.spi = Mock()
        self.bus = Mock()
        self.lines = Mock()
        self.gpiod = Mock()
        self.gpiod.request_lines.return_value = self.lines
        self.start_patch(patch.dict(sys.modules, {
            "gpiod": self.gpiod, "gpiod.line": self.gpiod.line,
            "smbus": None,
            "smbus2": Mock(SMBus=Mock(return_value=self.bus)),
            "spidev": Mock(SpiDev=Mock(return_value=self.spi)),
        }))
        self.expander = {0x01: 0xA2, 0x03: 0x40, 0x05: 0xC0, 0x07: 0x0F}
        self.bus.read_byte_data.side_effect = lambda addr, reg: self.expander[reg]
        self.bus.write_byte_data.side_effect = self.write_expander
        self.registers = {}
        self.irq = 0
        self.packet = b""
        self.spi.xfer2.side_effect = self.transfer
        self.lines.get_value.side_effect = self.line_value
        self.profiles = select_profiles("US", "both")
        self.radio = cap.CapRadio(self.profiles[0])
        self.addCleanup(self.radio.close)

    def start_patch(self, patcher):
        patcher.start()
        self.addCleanup(patcher.stop)

    def line_value(self, pin):
        return (self.gpiod.line.Value.ACTIVE if pin == 23 and self.irq
                else self.gpiod.line.Value.INACTIVE)

    def write_expander(self, address, register, value):
        self.assertEqual(address, 0x43)
        self.assertIn(register, (0x03, 0x05, 0x07))
        self.expander[register] = value

    def transfer(self, data):
        opcode = data[0]
        out = bytearray(len(data))
        if opcode in (0x0D, 0x1D):
            address = int.from_bytes(data[1:3], "big")
            if opcode == 0x0D:
                self.registers[address] = bytes(data[3:])
            else:
                out[4:] = self.registers.get(address, bytes(len(data) - 4))
        elif opcode == 0x11:
            out[2] = 1
        elif opcode == 0x12:
            out[2:] = self.irq.to_bytes(2, "big")
        elif opcode == 0x02:
            self.irq &= ~int.from_bytes(data[1:], "big")
        elif opcode == 0x13:
            out[2:] = bytes((len(self.packet), 42))
        elif opcode == 0x1E:
            self.assertEqual(data[1], 42)
            out[3:] = self.packet
        elif opcode == 0x14:
            out[2:] = bytes((177, 246, 155))
        return list(out)

    def test_open_retune_and_close(self):
        self.assertIs(self.radio.open(), self.radio)
        self.radio.open()
        self.spi.open.assert_called_once_with(0, 1)
        self.assertEqual(self.spi.mode, 0)
        self.assertEqual(self.spi.max_speed_hz, 1_000_000)
        self.lines.set_value.assert_called_once_with(26, self.gpiod.line.Value.ACTIVE)
        self.spi.xfer2.assert_any_call([0x97, 6, 0, 1, 0x40])
        self.spi.xfer2.assert_any_call([0x9D, 1])
        self.assertEqual(self.expander, {1: 0xA2, 3: 0x41, 5: 0xC1, 7: 0x0E})
        self.assertEqual((self.power.read_text(), self.mux.read_text()), ("1", "0"))
        self.assertEqual(self.registers[0x740], b"\x24\xb4")
        self.radio.tune(self.profiles[1])
        self.assertEqual(self.registers[0x740], b"\x14\x24")
        self.assertEqual(self.radio.diagnostics["retunes"], 2)
        self.assertIsNone(self.radio.receive(0))
        # Another I2C client changed P5 during the capture.
        self.expander[5] |= 0x20
        self.radio.close()
        self.radio.close()
        self.assertEqual(self.expander, {1: 0xA2, 3: 0x40, 5: 0xE0, 7: 0x0F})
        self.assertEqual((self.power.read_text(), self.mux.read_text()), ("0", "1"))
        self.spi.xfer2.assert_called_with([0x80, 0])
        self.lines.release.assert_called_once()
        self.bus.close.assert_called_once()
        self.spi.close.assert_called_once()
        with self.assertRaises(RadioError):
            self.radio.receive(0)

    def test_max_length_packet_with_bad_crc_and_signed_snr(self):
        self.radio.open()
        self.packet = bytes(range(255))
        self.irq = 0x42
        frame = self.radio.receive(0)
        self.assertEqual(bytes.fromhex(frame["raw_hex"]), self.packet)
        self.assertEqual(frame["profile"], self.profiles[0].to_dict())
        self.assertEqual((frame["rssi_dbm"], frame["snr_db"], frame["crc_ok"]),
                         (-88.5, -2.5, False))
        self.assertEqual(self.radio.diagnostics["crc_errors"], 1)
        self.assertIsNone(self.radio.receive(0))

    def test_header_error_without_rx_done_never_reads_fifo(self):
        self.radio.open()
        self.irq = 0x20
        self.assertIsNone(self.radio.receive(0))
        self.assertEqual(self.radio.diagnostics["header_errors"], 1)
        self.assertEqual(self.radio.diagnostics["received"], 0)
        self.assertFalse(any(call.args[0][0] == 0x1E for call in self.spi.xfer2.call_args_list))

    def test_partial_antenna_failure_restores_shared_bits_and_rail(self):
        def write(address, register, value):
            if register == 3:
                raise OSError("I2C transfer failed")
            self.write_expander(address, register, value)
        self.bus.write_byte_data.side_effect = write
        with self.assertRaisesRegex(RadioError, "0x43"):
            self.radio.open()
        self.assertEqual(self.expander[5], 0xC0)
        self.assertEqual(self.power.read_text(), "0")
        self.lines.reconfigure_lines.assert_not_called()
        self.lines.release.assert_called_once()
        self.spi.xfer2.assert_not_called()

    def test_wrong_cap_is_left_alone(self):
        self.expander[1] = 0
        self.power.write_text("1")
        with self.assertRaisesRegex(RadioError, "0x43"):
            self.radio.open()
        self.bus.write_byte_data.assert_not_called()
        self.spi.xfer2.assert_not_called()
        self.assertEqual(self.power.read_text(), "1")
        self.assertEqual(self.mux.read_text(), "1")

    def test_nfc_overlay_or_radio_owner_rejected_before_power(self):
        self.gpiod.request_lines.side_effect = OSError(errno.EBUSY, "in use")
        with self.assertRaisesRegex(RadioError, "GPIO22"):
            self.radio.open()
        self.assertEqual(self.power.read_text(), "0")
        self.spi.open.assert_not_called()
        self.bus.read_byte_data.assert_not_called()

    def test_other_pi_models_do_not_touch_foreground_gpio(self):
        self.power.unlink()
        with self.assertRaisesRegex(RadioError, "CardputerZero"):
            self.radio.open()
        self.gpiod.request_lines.assert_not_called()
        self.spi.open.assert_not_called()

    def test_transmit_commands_rejected_before_spi(self):
        for opcode in (0x83, 0xD1, 0xD2):
            with self.assertRaises(RadioError):
                self.radio._command(opcode)
        self.spi.xfer2.assert_not_called()

    def test_bookworm_gpio_and_system_smbus_bindings(self):
        chip = Mock()
        pins = {pin: Mock() for pin in (22, 23, 26)}
        chip.get_line.side_effect = pins.__getitem__
        pins[22].get_value.return_value = 0
        pins[23].get_value.side_effect = lambda: bool(self.irq)
        gpiod = types.SimpleNamespace(Chip=Mock(return_value=chip), LINE_REQ_DIR_IN=1)
        with patch.dict(sys.modules, {"gpiod": gpiod, "smbus2": None,
                                     "smbus": Mock(SMBus=Mock(return_value=self.bus))}):
            with self.radio:
                pins[26].set_direction_output.assert_called_once_with(0)
                pins[26].set_value.assert_called_once_with(1)
                self.irq = 2
                self.packet = b"\x00\xff"
                self.assertEqual(self.radio.receive(0)["raw_hex"], "00ff")
            for pin in pins.values():
                pin.request.assert_called_once_with(consumer="raspyjack-lora", type=1)
                pin.release.assert_called_once()
            pins[26].set_direction_input.assert_called_once()
            chip.close.assert_called_once()

    def test_bookworm_partial_gpio_acquisition_releases_prior_lines(self):
        chip = Mock()
        free, busy = Mock(), Mock()
        busy.request.side_effect = OSError(errno.EBUSY, "in use")
        chip.get_line.side_effect = [free, busy]
        gpiod = types.SimpleNamespace(Chip=Mock(return_value=chip), LINE_REQ_DIR_IN=1)
        with patch.dict(sys.modules, {"gpiod": gpiod}):
            with self.assertRaisesRegex(RadioError, "GPIO22"):
                self.radio.open()
        free.release.assert_called_once()
        busy.release.assert_not_called()
        chip.close.assert_called_once()
        self.assertEqual(self.power.read_text(), "0")
        self.spi.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
