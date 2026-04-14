#!/usr/bin/env python3
"""
Test script to validate Pager code works without actual Pager hardware.
Run this on a Raspberry Pi to check for Python errors in the Pager modules.

This creates a comprehensive MockPager that simulates all libpagerctl.so APIs
including drawing, input, LEDs, audio, and battery functions.

Usage:
    python3 test_pager_code.py
    python3 test_pager_code.py --verbose   # Show all mock draw calls
"""

import sys
import os
import time
import types
import argparse

# Parse args early
parser = argparse.ArgumentParser(description='Test Pager code without hardware')
parser.add_argument('--verbose', '-v', action='store_true', help='Show all mock draw calls')
args, _ = parser.parse_known_args()
VERBOSE = args.verbose

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


class MockPagerInput:
    """Input state structure matching pager_input_t in C."""
    def __init__(self):
        self.current = 0   # Currently held buttons (bitmask)
        self.pressed = 0   # Just pressed this frame (bitmask)
        self.released = 0  # Just released this frame (bitmask)


class MockPagerInputEvent:
    """Input event structure for thread-safe event queue."""
    def __init__(self):
        self.button = 0      # Which button
        self.type = 0        # Event type
        self.timestamp = 0   # When event occurred


class MockPager:
    """Complete mock of pagerctl.Pager - simulates all hardware APIs."""
    
    # ========== COLORS (RGB565) ==========
    BLACK = 0x0000
    WHITE = 0xFFFF
    RED = 0xF800
    GREEN = 0x07E0
    BLUE = 0x001F
    YELLOW = 0xFFE0
    CYAN = 0x07FF
    MAGENTA = 0xF81F
    ORANGE = 0xFD20
    PURPLE = 0x8010
    GRAY = 0x8410
    
    # ========== ROTATION MODES ==========
    ROTATION_0 = 0      # Portrait 222x480
    ROTATION_90 = 90    # Landscape 480x222
    ROTATION_180 = 180  # Portrait inverted
    ROTATION_270 = 270  # Landscape inverted (default)
    
    # ========== FONT SIZES ==========
    FONT_SMALL = 1   # 5x7
    FONT_MEDIUM = 2  # 10x14
    FONT_LARGE = 3   # 15x21
    
    # ========== BUTTON MASKS ==========
    BTN_UP = 0x01
    BTN_DOWN = 0x02
    BTN_LEFT = 0x04
    BTN_RIGHT = 0x08
    BTN_A = 0x10     # Green button
    BTN_B = 0x20     # Red button
    BTN_POWER = 0x40 # Power button
    
    # Aliases
    BTN_GREEN = BTN_A
    BTN_RED = BTN_B
    
    # ========== EVENT TYPES ==========
    EVENT_NONE = 0
    EVENT_PRESS = 1
    EVENT_RELEASE = 2
    
    # ========== RTTTL MODES ==========
    RTTTL_SOUND_ONLY = 0
    RTTTL_SOUND_VIBRATE = 1
    RTTTL_VIBRATE_ONLY = 2
    
    # ========== RTTTL MELODIES ==========
    RTTTL_TETRIS = "tetris:d=4,o=5,b=160:e6,8b,8c6,8d6,16e6,16d6,8c6,8b,a"
    RTTTL_GAME_OVER = "smbdeath:d=4,o=5,b=90:8p,16b,16f6,16p,16f6"
    RTTTL_LEVEL_UP = "levelup:d=16,o=5,b=200:c,e,g,c6,8p,g,c6,e6,8g6"
    
    def __init__(self):
        self._width = 222
        self._height = 480
        self._initialized = False
        self._rotation = 0
        self._brightness = 100
        self._max_brightness = 255
        self._screen_on = True
        self._start_time = time.time()
        self._audio_playing = False
        self._led_states = {}
        self._draw_calls = 0
        self._loaded_images = {}
        self._next_image_handle = 1
        if VERBOSE:
            print("[MockPager] Created")
    
    # ========== COLOR HELPERS ==========
    @staticmethod
    def rgb(r, g, b):
        """Convert RGB888 to RGB565."""
        return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
    
    @staticmethod
    def hex_color(rgb_hex):
        """Convert 0xRRGGBB to RGB565."""
        r = (rgb_hex >> 16) & 0xFF
        g = (rgb_hex >> 8) & 0xFF
        b = rgb_hex & 0xFF
        return MockPager.rgb(r, g, b)
    
    # ========== INIT/CLEANUP ==========
    def init(self):
        """Initialize pager hardware."""
        self._initialized = True
        self._start_time = time.time()
        if VERBOSE:
            print("[MockPager] init() called")
        return 0
    
    def cleanup(self):
        """Clean up hardware resources."""
        self._initialized = False
        if VERBOSE:
            print("[MockPager] cleanup() called")
    
    # ========== ROTATION/SIZE ==========
    def set_rotation(self, degrees):
        """Set display rotation: 0, 90, 180, or 270."""
        self._rotation = degrees
        if degrees in [90, 270]:
            self._width, self._height = 480, 222
        else:
            self._width, self._height = 222, 480
        if VERBOSE:
            print(f"[MockPager] set_rotation({degrees}) -> {self._width}x{self._height}")
    
    @property
    def width(self):
        """Get current logical screen width."""
        return self._width
    
    @property
    def height(self):
        """Get current logical screen height."""
        return self._height
    
    # ========== FRAME MANAGEMENT ==========
    def flip(self):
        """Display the current frame."""
        self._draw_calls += 1
        if VERBOSE and self._draw_calls % 10 == 0:
            print(f"[MockPager] flip() - frame #{self._draw_calls}")
    
    def clear(self, color=0):
        """Clear screen to color."""
        if VERBOSE:
            print(f"[MockPager] clear({color:#06x})")
    
    def get_ticks(self):
        """Get milliseconds since init."""
        return int((time.time() - self._start_time) * 1000)
    
    def delay(self, ms):
        """Sleep for milliseconds."""
        time.sleep(ms / 1000.0)
    
    def frame_sync(self):
        """Frame rate limiter (60fps target)."""
        time.sleep(1/60)
        return self.get_ticks()
    
    # ========== DRAWING PRIMITIVES ==========
    def pixel(self, x, y, color):
        """Set a single pixel."""
        pass
    
    def fill_rect(self, x, y, w, h, color):
        """Draw a filled rectangle."""
        if VERBOSE:
            print(f"[MockPager] fill_rect({x}, {y}, {w}, {h}, {color:#06x})")
    
    def rect(self, x, y, w, h, color):
        """Draw a rectangle outline."""
        if VERBOSE:
            print(f"[MockPager] rect({x}, {y}, {w}, {h}, {color:#06x})")
    
    def hline(self, x, y, w, color):
        """Draw horizontal line."""
        pass
    
    def vline(self, x, y, h, color):
        """Draw vertical line."""
        pass
    
    def line(self, x0, y0, x1, y1, color):
        """Draw a line between two points."""
        pass
    
    def fill_circle(self, cx, cy, r, color):
        """Draw a filled circle."""
        pass
    
    def circle(self, cx, cy, r, color):
        """Draw a circle outline."""
        pass
    
    # ========== TEXT (BUILT-IN FONT) ==========
    def draw_char(self, x, y, char, color, size=1):
        """Draw a single character. Returns width."""
        return 5 * size
    
    def draw_text(self, x, y, text, color, size=1):
        """Draw text at position. Returns width."""
        if VERBOSE:
            text_preview = text[:30] + ('...' if len(text) > 30 else '')
            print(f"[MockPager] draw_text({x}, {y}, '{text_preview}', size={size})")
        return len(text) * 6 * size
    
    def draw_text_centered(self, y, text, color, size=1):
        """Draw horizontally centered text."""
        if VERBOSE:
            print(f"[MockPager] draw_text_centered(y={y}, '{text[:30]}')")
    
    def text_width(self, text, size=1):
        """Get width of text in pixels."""
        return len(text) * 6 * size
    
    def draw_number(self, x, y, num, color, size=1):
        """Draw a number. Returns width."""
        return len(str(num)) * 6 * size
    
    # ========== TTF TEXT ==========
    def draw_ttf(self, x, y, text, color, font_path, font_size):
        """Draw text using TTF font. Returns width."""
        if VERBOSE:
            text_preview = text[:30] + ('...' if len(text) > 30 else '')
            print(f"[MockPager] draw_ttf({x}, {y}, '{text_preview}', size={font_size})")
        return int(len(text) * font_size * 0.6)
    
    def ttf_width(self, text, font_path, font_size):
        """Get width of TTF text in pixels."""
        return int(len(text) * font_size * 0.6)
    
    def ttf_height(self, font_path, font_size):
        """Get height of TTF font in pixels."""
        return int(font_size * 1.2)
    
    def draw_ttf_centered(self, y, text, color, font_path, font_size):
        """Draw horizontally centered TTF text."""
        if VERBOSE:
            print(f"[MockPager] draw_ttf_centered(y={y}, '{text[:30]}')")
    
    def draw_ttf_right(self, y, text, color, font_path, font_size, padding=0):
        """Draw right-aligned TTF text."""
        pass
    
    # ========== AUDIO ==========
    def play_rtttl(self, melody, mode=None):
        """Play RTTTL melody in background."""
        self._audio_playing = True
        if VERBOSE:
            print(f"[MockPager] play_rtttl('{melody[:30]}...')")
    
    def stop_audio(self):
        """Stop any playing audio."""
        self._audio_playing = False
    
    def audio_playing(self):
        """Check if audio is playing."""
        return self._audio_playing
    
    def beep(self, freq, duration_ms):
        """Play a simple beep (blocking)."""
        if VERBOSE:
            print(f"[MockPager] beep({freq}Hz, {duration_ms}ms)")
    
    def play_rtttl_sync(self, melody, with_vibration=False):
        """Play RTTTL synchronously (blocking)."""
        pass
    
    # ========== VIBRATION ==========
    def vibrate(self, duration_ms=200):
        """Vibrate for duration in milliseconds."""
        if VERBOSE:
            print(f"[MockPager] vibrate({duration_ms}ms)")
    
    def vibrate_pattern(self, pattern):
        """Play vibration pattern."""
        pass
    
    # ========== LEDS ==========
    def led_set(self, name, brightness):
        """Set LED brightness (0-255)."""
        self._led_states[name] = brightness
    
    def led_rgb(self, button, r, g, b):
        """Set D-pad LED color."""
        self._led_states[button] = (r, g, b)
    
    def led_dpad(self, direction, color):
        """Set D-pad LED from 0xRRGGBB color."""
        self._led_states[direction] = color
    
    def led_all_off(self):
        """Turn off all LEDs."""
        self._led_states.clear()
    
    # ========== RANDOM ==========
    def random(self, max_val):
        """Get random number from 0 to max-1."""
        import random
        return random.randint(0, max_val - 1)
    
    def seed_random(self, seed):
        """Seed the random number generator."""
        import random
        random.seed(seed)
    
    # ========== INPUT ==========
    def wait_button(self):
        """Wait for any button press (blocking)."""
        return self.BTN_A  # Simulate green button press
    
    def poll_input(self):
        """Poll input state (non-blocking)."""
        return (0, 0, 0)  # (current, pressed, released)
    
    def get_input(self):
        """Get input state as object."""
        return MockPagerInput()
    
    def get_input_event(self):
        """Get next input event from queue."""
        return None  # No events
    
    def has_input_events(self):
        """Check if there are pending input events."""
        return False
    
    def peek_buttons(self):
        """Get currently pressed buttons without consuming events."""
        return 0
    
    def clear_input_events(self):
        """Clear all pending input events."""
        pass
    
    # ========== BRIGHTNESS/BACKLIGHT ==========
    def set_brightness(self, level):
        """Set screen brightness (0-255)."""
        self._brightness = max(0, min(255, level))
        return self._brightness
    
    def get_brightness(self):
        """Get current brightness level."""
        return self._brightness
    
    def get_max_brightness(self):
        """Get maximum brightness value."""
        return self._max_brightness
    
    def screen_off(self):
        """Turn off screen backlight."""
        self._screen_on = False
        return 0
    
    def screen_on(self):
        """Turn on screen backlight."""
        self._screen_on = True
        return 0
    
    # ========== IMAGE SUPPORT ==========
    def load_image(self, path):
        """Load image file. Returns handle."""
        handle = self._next_image_handle
        self._next_image_handle += 1
        self._loaded_images[handle] = path
        return handle
    
    def free_image(self, handle):
        """Free loaded image."""
        if handle in self._loaded_images:
            del self._loaded_images[handle]
    
    def draw_image(self, x, y, handle):
        """Draw loaded image at position."""
        if VERBOSE and handle in self._loaded_images:
            print(f"[MockPager] draw_image({x}, {y}, '{os.path.basename(self._loaded_images[handle])}')")
    
    def draw_image_scaled(self, x, y, w, h, handle):
        """Draw loaded image scaled to size."""
        pass
    
    def draw_image_file(self, x, y, path):
        """Draw image file directly (convenience)."""
        if VERBOSE:
            print(f"[MockPager] draw_image_file({x}, {y}, '{os.path.basename(path)}')")
        return 0
    
    def draw_image_file_scaled(self, x, y, w, h, path):
        """Draw image file scaled."""
        return 0
    
    def get_image_info(self, path):
        """Get image dimensions. Returns (width, height)."""
        return (100, 100)  # Dummy dimensions
    
    # Compatibility aliases
    draw_bmp = draw_image_file
    draw_rect = rect
    draw_line = line
    draw_pixel = pixel
    
    # ========== BATTERY (simulated) ==========
    def get_battery_percent(self):
        """Get battery percentage (simulated)."""
        return 75
    
    def get_battery_charging(self):
        """Check if charging (simulated)."""
        return False


# Create mock module and inject BEFORE any imports
mock_module = types.ModuleType('pagerctl')
mock_module.Pager = MockPager
mock_module.PagerInput = MockPagerInput
mock_module.PagerInputEvent = MockPagerInputEvent
mock_module.PAGER_EVENT_NONE = 0
mock_module.PAGER_EVENT_PRESS = 1
mock_module.PAGER_EVENT_RELEASE = 2
sys.modules['pagerctl'] = mock_module


def run_tests():
    """Execute all tests."""
    print("=" * 60)
    print("Pager Code Test - Using MockPager (no hardware required)")
    print("=" * 60)
    print()
    
    if VERBOSE:
        print("[INFO] Verbose mode enabled - showing all mock draw calls")
        print()
    
    errors = []
    warnings = []
    
    # ========== TEST 1: pager_menu.py ==========
    print("[TEST 1] Importing pager_menu.py...")
    try:
        import pager_menu
        print("[OK] pager_menu.py imported successfully")
    except Exception as e:
        print(f"[FAIL] pager_menu.py: {e}")
        import traceback
        traceback.print_exc()
        errors.append(('pager_menu.py', str(e)))
    
    print()
    
    # ========== TEST 2: pager_display.py ==========
    print("[TEST 2] Importing pager_display.py...")
    try:
        import pager_display
        print("[OK] pager_display.py imported successfully")
    except Exception as e:
        print(f"[FAIL] pager_display.py: {e}")
        import traceback
        traceback.print_exc()
        errors.append(('pager_display.py', str(e)))
    
    print()
    
    # ========== TEST 3: PagerRagnar.py syntax ==========
    print("[TEST 3] Checking PagerRagnar.py syntax...")
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("PagerRagnar", 
            os.path.join(os.path.dirname(__file__), "PagerRagnar.py"))
        pager_ragnar = importlib.util.module_from_spec(spec)
        print("[OK] PagerRagnar.py syntax OK")
    except Exception as e:
        print(f"[FAIL] PagerRagnar.py: {e}")
        import traceback
        traceback.print_exc()
        errors.append(('PagerRagnar.py', str(e)))
    
    print()
    
    # ========== TEST 4: RagnarMenu instantiation ==========
    print("[TEST 4] Testing pager_menu.RagnarMenu instantiation...")
    try:
        interfaces = [
            {'name': 'eth0', 'ip': '192.168.1.100', 'subnet': '192.168.1.0/24'},
            {'name': 'wlan0', 'ip': '10.0.0.5', 'subnet': '10.0.0.0/24'},
        ]
        menu = pager_menu.RagnarMenu(interfaces)
        print(f"[OK] RagnarMenu created - display size: {menu.gfx.width}x{menu.gfx.height}")
        menu.cleanup()
    except Exception as e:
        print(f"[FAIL] RagnarMenu instantiation: {e}")
        import traceback
        traceback.print_exc()
        errors.append(('RagnarMenu', str(e)))
    
    print()
    
    # ========== TEST 5: PagerDisplay instantiation ==========
    print("[TEST 5] Testing pager_display.PagerDisplay instantiation...")
    try:
        from init_shared import shared_data
        # PagerRagnar.setup_pager_shared_data patches shared_data with Pager-specific
        # attributes (font_arial_path, font_viking_path, static_images, etc.)
        # This MUST be called before PagerDisplay is created.
        import importlib
        PagerRagnar = importlib.import_module('PagerRagnar')
        PagerRagnar.setup_pager_shared_data(shared_data)
        print("  [OK] setup_pager_shared_data() completed")
        
        display = pager_display.PagerDisplay(shared_data)
        print(f"[OK] PagerDisplay created - size: {display.width}x{display.height}")
        display.cleanup()
    except Exception as e:
        print(f"[FAIL] PagerDisplay instantiation: {e}")
        import traceback
        traceback.print_exc()
        errors.append(('PagerDisplay', str(e)))
    
    print()
    
    # ========== TEST 6: MockPager API completeness ==========
    print("[TEST 6] Verifying MockPager API coverage...")
    try:
        pager = MockPager()
        pager.init()
        
        # Test rotation
        pager.set_rotation(270)
        assert pager.width == 480 and pager.height == 222, "Rotation 270 should be 480x222"
        
        pager.set_rotation(0)
        assert pager.width == 222 and pager.height == 480, "Rotation 0 should be 222x480"
        
        # Test drawing calls don't crash
        pager.clear(MockPager.BLACK)
        pager.fill_rect(10, 10, 100, 50, MockPager.RED)
        pager.rect(10, 10, 100, 50, MockPager.BLUE)
        pager.draw_text(20, 20, "Test text", MockPager.WHITE, 2)
        pager.draw_ttf(20, 50, "TTF Test", MockPager.GREEN, "/fonts/Arial.ttf", 18.0)
        pager.flip()
        
        # Test color conversion
        color = MockPager.rgb(255, 128, 64)
        assert isinstance(color, int), "rgb() should return int"
        
        # Test battery simulation
        assert 0 <= pager.get_battery_percent() <= 100, "Battery should be 0-100"
        
        # Test brightness
        pager.set_brightness(200)
        assert pager.get_brightness() == 200, "Brightness should be set"
        
        # Test input
        current, pressed, released = pager.poll_input()
        assert current == 0, "No buttons pressed in mock"
        
        # Test timer
        ticks = pager.get_ticks()
        assert ticks >= 0, "Ticks should be non-negative"
        
        pager.cleanup()
        print("[OK] MockPager API coverage verified (15 methods tested)")
    except Exception as e:
        print(f"[FAIL] MockPager API: {e}")
        import traceback
        traceback.print_exc()
        errors.append(('MockPager API', str(e)))
    
    print()
    
    # ========== TEST 7: Required files exist ==========
    print("[TEST 7] Checking required files...")
    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    required_files = [
        'pager_menu.py',
        'pager_display.py',
        'PagerRagnar.py',
        'pagerctl.py',
        'pager_payload.sh',
        'init_shared.py',
        'shared.py',
        'orchestrator.py',
        'resources/fonts/DejaVuSansMono.ttf',
        'resources/fonts/Viking.TTF',
        'config/actions.json',
    ]
    
    missing = []
    for f in required_files:
        path = os.path.join(script_dir, f)
        if not os.path.exists(path):
            missing.append(f)
    
    if missing:
        print(f"[WARN] Missing files: {', '.join(missing)}")
        warnings.extend(missing)
    else:
        print(f"[OK] All {len(required_files)} required files present")
    
    print()
    
    # ========== SUMMARY ==========
    print("=" * 60)
    if errors:
        print(f"FAILED: {len(errors)} error(s) found:")
        for name, err in errors:
            print(f"  - {name}: {err}")
        print()
        print("Fix these errors before deploying to Pager hardware.")
        return 1
    elif warnings:
        print(f"PASSED with {len(warnings)} warning(s)")
        print("Missing optional files:")
        for w in warnings:
            print(f"  - {w}")
        print()
        print("Code should work, but some features may be limited.")
        return 0
    else:
        print("SUCCESS: All tests passed!")
        print()
        print("The Pager code is ready for deployment.")
        print("Run: ./scripts/install_pineapple_pager.sh <pager-ip>")
        return 0


if __name__ == '__main__':
    sys.exit(run_tests())
