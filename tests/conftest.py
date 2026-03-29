"""
Pytest configuration for the RaspyJack test suite.

Hardware mocks are installed into ``sys.modules`` BEFORE any payload or core
module is imported.  This is essential because modules like ``LCD_Config`` and
``LCD_1in44`` perform ``import RPi.GPIO`` and ``import spidev`` at the
top-level -- if the real packages are absent the import fails immediately.

The session-scoped ``_hardware_mocks`` fixture runs automatically (autouse)
and patches every hardware-dependent module once per test session.
"""

import sys
import os
from pathlib import Path
from typing import Iterator, List, Optional
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so ``import LCD_Config`` etc. work.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Also add the payloads directory so ``from payloads._input_helper import ...``
# resolves correctly.
_PAYLOADS_DIR = os.path.join(_PROJECT_ROOT, "payloads")
if _PAYLOADS_DIR not in sys.path:
    sys.path.insert(0, _PAYLOADS_DIR)

# ---------------------------------------------------------------------------
# Install hardware mocks BEFORE anything else can trigger a real import.
# ---------------------------------------------------------------------------
from tests.mocks.hardware import (  # noqa: E402
    MockGPIO,
    MockLCD,
    MockLCDConfig,
    MockSpiDev,
    MockSMBus,
    MockSerial,
    MockRjInput,
    install_all_mocks,
)

# Run the install once at module-load time so even top-level imports in
# conftest or early-collected test files find the mocks in sys.modules.
_INJECTED = install_all_mocks()


# ---------------------------------------------------------------------------
# Session-scoped fixture (autouse) -- ensures mocks survive the full session
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _hardware_mocks():
    """
    Guarantee that hardware mocks remain installed for the entire session.

    The actual patching already happened at module-load time (see above).
    This fixture simply holds the reference so nothing can garbage-collect
    the mock modules.
    """
    yield _INJECTED


# ---------------------------------------------------------------------------
# Per-test cleanup: reset GPIO state between tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_gpio():
    """Reset MockGPIO internal state before each test."""
    MockGPIO.reset()
    yield
    MockGPIO.reset()


# ---------------------------------------------------------------------------
# Convenience fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_gpio():
    """Provide the MockGPIO class for direct assertions in tests."""
    return MockGPIO


@pytest.fixture()
def mock_lcd():
    """Return a fresh MockLCD instance."""
    return MockLCD()


@pytest.fixture()
def mock_lcd_config():
    """Provide the MockLCDConfig namespace."""
    return MockLCDConfig


@pytest.fixture()
def mock_spi():
    """Return a fresh MockSpiDev instance."""
    return MockSpiDev()


@pytest.fixture()
def mock_smbus():
    """Return a fresh MockSMBus instance."""
    return MockSMBus()


@pytest.fixture()
def mock_serial():
    """Return a fresh MockSerial instance."""
    return MockSerial()


@pytest.fixture()
def mock_rj_input():
    """Provide the rj_input mock module from sys.modules."""
    return sys.modules["rj_input"]


# ---------------------------------------------------------------------------
# Configurable button-press sequence fixture
# ---------------------------------------------------------------------------

class ButtonSequencer:
    """
    Simulate a sequence of button presses.

    Usage in a test::

        def test_payload_exits_on_key3(mock_get_button):
            # Simulate: no press, no press, KEY3
            seq = mock_get_button(["UP", "DOWN", "KEY3"])
            # Each call to seq() returns the next button; after exhaustion
            # returns None.
    """

    def __init__(self, sequence: List[Optional[str]]):
        self._sequence = list(sequence)
        self._index = 0

    def __call__(self) -> Optional[str]:
        if self._index < len(self._sequence):
            value = self._sequence[self._index]
            self._index = self._index + 1
            return value
        return None

    @property
    def remaining(self) -> int:
        return max(0, len(self._sequence) - self._index)

    def reset(self):
        self._index = 0


@pytest.fixture()
def mock_get_button():
    """
    Factory fixture that returns a ``ButtonSequencer``.

    Pass a list of button names (matching ``_input_helper.get_button`` return
    values) -- ``None`` entries represent "no button pressed".

    Example::

        def test_something(mock_get_button):
            buttons = mock_get_button([None, None, "KEY3"])
            assert buttons() is None
            assert buttons() is None
            assert buttons() == "KEY3"
            assert buttons() is None  # exhausted
    """

    def _factory(sequence: List[Optional[str]]) -> ButtonSequencer:
        return ButtonSequencer(sequence)

    return _factory


# ---------------------------------------------------------------------------
# Fixture for patching get_button in _input_helper
# ---------------------------------------------------------------------------

@pytest.fixture()
def patch_get_button(monkeypatch, mock_get_button):
    """
    Patch ``payloads._input_helper.get_button`` to use a ``ButtonSequencer``.

    Returns a helper that accepts a button sequence and installs it::

        def test_payload(patch_get_button):
            sequencer = patch_get_button([None, "UP", "KEY3"])
            # Now any code calling get_button(pins, gpio) will get the
            # sequenced values instead of reading real GPIO.
    """

    def _install(sequence: List[Optional[str]]) -> ButtonSequencer:
        sequencer = mock_get_button(sequence)

        def _fake_get_button(pins=None, gpio=None):
            return sequencer()

        try:
            import payloads._input_helper as helper_mod
            monkeypatch.setattr(helper_mod, "get_button", _fake_get_button)
        except ImportError:
            pass

        return sequencer

    return _install


# ---------------------------------------------------------------------------
# Project root path fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def project_root() -> str:
    """Return the absolute path to the project root."""
    return _PROJECT_ROOT
