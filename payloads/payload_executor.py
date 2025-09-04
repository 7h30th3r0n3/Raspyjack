#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
import os
import sys
# This ensures that imports like 'import LCD_1in44' work correctly from the main project directory.
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

from gpio_config import gpio_config

# ---------------------------- Standard library ----------------------------
import time
import subprocess
import threading
import collections
import select
import socket
import signal

# ----------------------------- Third-party libs ---------------------------
# These are expected to be installed on the Raspyjack system.
import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont

# --- Constants ---
# Communication pipe for payload commands
PIPE_PATH = "/tmp/raspyjack.pipe"
# Directory where standalone command executables are located
COMMANDS_PATH = "/root/Raspyjack/bin"
# Fixed loot directory for Raspyjack
LOOT_PATH = "/root/Raspyjack/loot"
# Base directory where all payload scripts are stored
PAYLOADS_BASE_PATH = "/root/Raspyjack/payloads"

# Additional joystick / button mappings for WAIT_FOR_KEY macro
KEY_NAME_TO_PIN = {
    'UP': gpio_config.key_up_pin,
    'DOWN': gpio_config.key_down_pin,
    'LEFT': gpio_config.key_left_pin,
    'RIGHT': gpio_config.key_right_pin,
    'PRESS': gpio_config.key_press_pin,
    'KEY1': gpio_config.key1_pin,
    'KEY2': gpio_config.key2_pin,
    'KEY3': gpio_config.key3_pin
}

# --- UI Constants ---
WIDTH, HEIGHT = 128, 128
try:
    FONT_BOLD = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    FONT_MONO = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 8)
    FONT_SMALL = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
except IOError:
    FONT_BOLD = FONT_MONO = FONT_SMALL = ImageFont.load_default()

# --- LED Syntax Maps ---
COLOR_MAP = {
    'R': '#FF0000', 'G': '#00FF00', 'B': '#0000FF',
    'Y': '#FFFF00', 'C': '#00FFFF', 'M': '#FF00FF', 'W': '#FFFFFF'
}

STATE_MAP = {
    "SETUP":    {"color": 'M', "pattern": "SOLID"},
    "FAIL":     {"color": 'R', "pattern": "SLOW"},
    "FAIL1":    {"color": 'R', "pattern": "SLOW"},
    "FAIL2":    {"color": 'R', "pattern": "FAST"},
    "FAIL3":    {"color": 'R', "pattern": "VERYFAST"},
    "ATTACK":   {"color": 'Y', "pattern": "SINGLE"},
    "STAGE1":   {"color": 'Y', "pattern": "SINGLE"},
    "STAGE2":   {"color": 'Y', "pattern": "DOUBLE"},
    "STAGE3":   {"color": 'Y', "pattern": "TRIPLE"},
    "STAGE4":   {"color": 'Y', "pattern": "QUAD"},
    "STAGE5":   {"color": 'Y', "pattern": "QUIN"},
    "SPECIAL":  {"color": 'C', "pattern": "ISINGLE"},
    "SPECIAL1": {"color": 'C', "pattern": "ISINGLE"},
    "SPECIAL2": {"color": 'C', "pattern": "IDOUBLE"},
    "SPECIAL3": {"color": 'C', "pattern": "ITRIPLE"},
    "SPECIAL4": {"color": 'C', "pattern": "IQUAD"},
    "SPECIAL5": {"color": 'C', "pattern": "IQUIN"},
    "CLEANUP":  {"color": 'W', "pattern": "FAST"},
    "FINISH":   {"color": 'G', "pattern": "SUCCESS"},
}

class PayloadOrchestrator:
    """
    Manages the execution of a bash payload, providing a real-time
    dashboard on the actual LCD screen.
    """
    def __init__(self, lcd_instance):
        self.lcd = lcd_instance
        self.image_buffer = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")

        # Real-time state variables
        self.payload_indicators = {"ip": "N/A", "runtime": "00:00"}
        self.led_status = {"text": "RUNNING", "color_code": "#333333", "pattern": "SOLID", "state_change_time": 0}
        self.log_buffer = collections.deque(maxlen=7)
        self.log_lock = threading.Lock()
        self.payload_running = False
        self.listener_thread = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def execute_payload(self, full_payload_path: str):
        if not os.path.isfile(full_payload_path):
            print(f"ERROR: Payload script not found: {full_payload_path}")
            return

        print(f"Starting payload: {os.path.basename(full_payload_path)}")
        if os.path.exists(PIPE_PATH): os.remove(PIPE_PATH)
        os.mkfifo(PIPE_PATH)
        
        self.payload_running = True

        try:
            payload_env = os.environ.copy()
            payload_env["PATH"] = f"{COMMANDS_PATH}:{payload_env.get('PATH', '')}"
            payload_env["LOOT_DIR"] = LOOT_PATH
            # Add project root to PYTHONPATH so scripts can import project modules
            project_root = os.path.abspath(os.path.join(__file__, '..', '..'))
            payload_env["PYTHONPATH"] = f"{project_root}:{payload_env.get('PYTHONPATH', '')}"

            # Ensure GPIO for abort + macro keys configured (input w/ pull-up)
            try:
                GPIO.setmode(GPIO.BCM)
                configured = set()
                for pin in KEY_NAME_TO_PIN.values():
                    if pin not in configured:  # avoid duplicate setup
                        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                        configured.add(pin)
            except Exception as e:
                print(f"[Abort Setup] Warning: GPIO setup failed: {e}")

            process = subprocess.Popen(["bash", full_payload_path], env=payload_env)
            self._payload_process = process
            
            self.listener_thread = threading.Thread(target=self._read_pipe_and_update_state, daemon=True)
            self.listener_thread.start()

            # Start abort monitor thread
            self.abort_requested = False
            self.abort_thread = threading.Thread(target=self._abort_monitor, daemon=True)
            self.abort_thread.start()
            
            start_time = time.time()
            
            while process.poll() is None:
                self.payload_indicators["runtime"] = time.strftime("%M:%S", time.gmtime(time.time() - start_time))
                self.payload_indicators["ip"] = self._get_ip_address()
                self._draw_dashboard()
                time.sleep(0.05)
            
            print(f"Payload process finished with exit code: {process.returncode}")

            # ----------------- Post-Execution (Display Final Message & Wait) -----------------
            # Stop background threads cleanly
            self.payload_running = False
            if self.listener_thread:
                self.listener_thread.join(timeout=0.2)
            if hasattr(self, 'abort_thread') and self.abort_thread:
                self.abort_thread.join(timeout=0.2)

            # Append final log lines (do NOT change LED state as requested)
            with self.log_lock:
                if getattr(self, 'abort_requested', False):
                    self.log_buffer.append("PAYLOAD ABORTED")
                else:
                    self.log_buffer.append("PAYLOAD FINISHED")
                self.log_buffer.append("Press KEY3 to return")

            # Remove pipe now (no more incoming messages expected)
            if os.path.exists(PIPE_PATH):
                try:
                    os.remove(PIPE_PATH)
                except Exception:
                    pass

            # Wait for a fresh KEY3 press (falling edge) before returning
            try:
                key3_pin = gpio_config.key3_pin
                last_state = GPIO.input(key3_pin)
                # Continue drawing dashboard while waiting
                while True:
                    self._draw_dashboard()
                    try:
                        state = GPIO.input(key3_pin)
                    except Exception:
                        break
                    if last_state == 1 and state == 0:
                        break
                    last_state = state
                    time.sleep(0.06)
            except Exception:
                pass

        finally:
            print("Cleaning up resources...")
            self.payload_running = False
            if self.listener_thread: self.listener_thread.join(timeout=0.2)
            if hasattr(self, 'abort_thread') and self.abort_thread: self.abort_thread.join(timeout=0.2)
            if os.path.exists(PIPE_PATH): os.remove(PIPE_PATH)
            print("UI restored. Execution finished.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _get_ip_address(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "N/A"

    def _read_pipe_and_update_state(self):
        print("[Orchestrator] Pipe listener thread started.")
        with open(PIPE_PATH, "r") as pipe:
            while self.payload_running:
                r, _, _ = select.select([pipe], [], [], 0.1)
                if not r: continue

                line = pipe.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                raw = line.rstrip('\n')
                line_upper = raw.strip().upper()
                print(f"[Pipe Listener] Received: '{line_upper}'")
                self._process_pipe_line(line_upper, raw)
        print("[Orchestrator] Pipe listener thread finished.")

    def _process_pipe_line(self, line_upper: str, original_line: str):
        """Dispatch a single line from the pipe to the proper handler.
        line_upper: uppercase trimmed version for case-insensitive matching
        original_line: the raw line (without trailing newline) preserving case for log display."""
        if line_upper.startswith("LED:"):
            self._handle_led_command(line_upper)
        elif line_upper.startswith("SERIAL_WRITE:"):
            # Preserve everything after first ':' exactly as payload sent (excluding the prefix)
            message = original_line.split(":", 1)[1]
            self._handle_serial_write(message)
        else:
            # Unknown / pass-through lines could optionally be logged in future
            pass

    def _handle_led_command(self, line_upper: str):
        """Parse and apply an LED: command (state or direct color/pattern)."""
        parts = line_upper.split(":", 1)[1].split()
        if not parts:
            return
        arg1 = parts[0]
        arg2 = parts[1] if len(parts) > 1 else None

        color_char = None
        pattern = None

        if arg1 in STATE_MAP:
            state_info = STATE_MAP[arg1]
            color_char = state_info["color"]
            pattern = state_info["pattern"]
            self.led_status['text'] = arg1
        elif arg1 in COLOR_MAP:
            color_char = arg1
            pattern = arg2 or "SOLID"
            self.led_status['text'] = f"{color_char} {pattern}"

        if color_char:
            self.led_status['color_code'] = COLOR_MAP[color_char]
            self.led_status['pattern'] = pattern
            self.led_status['state_change_time'] = time.time()

    def _handle_serial_write(self, message: str):
        """Append a SERIAL_WRITE payload message to log buffer (thread-safe)."""
        with self.log_lock:
            self.log_buffer.append(message)

    def _abort_monitor(self):
        """Monitor KEY3 button; when pressed, terminate payload process gracefully."""
        print("[Abort] Monitor thread started (press KEY3 to abort).")
        # Debounce + edge detection simple approach
        last_state = 1
        key3_pin = gpio_config.key3_pin
        while self.payload_running and hasattr(self, '_payload_process') and self._payload_process.poll() is None:
            try:
                state = GPIO.input(key3_pin)
            except Exception:
                break
            if last_state == 1 and state == 0:  # falling edge (pressed)
                print("[Abort] KEY3 pressed – terminating payload...")
                with self.log_lock:
                    self.log_buffer.append("ABORT REQUEST")
                self.led_status.update({
                    'text': 'ABORT',
                    'color_code': COLOR_MAP.get('R', '#FF0000'),
                    'pattern': 'VERYFAST',
                    'state_change_time': time.time()
                })
                self.abort_requested = True
                # Try graceful terminate
                try:
                    self._payload_process.terminate()
                except Exception:
                    pass
                # Wait a short grace period
                for _ in range(20):  # ~1s
                    if self._payload_process.poll() is not None:
                        break
                    time.sleep(0.05)
                if self._payload_process.poll() is None:
                    try:
                        self._payload_process.kill()
                        print("[Abort] Forced kill issued.")
                    except Exception:
                        pass
                break
            last_state = state
            time.sleep(0.05)
        print("[Abort] Monitor thread finished.")

    def _draw_dashboard(self):
        draw = ImageDraw.Draw(self.image_buffer)
        draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")

        # --- Top Part (Indicators) ---
        status_text = f"IP: {self.payload_indicators['ip']} | {self.payload_indicators['runtime']}"
        draw.text((2, 1), status_text, fill="white", font=FONT_SMALL)
        draw.line((0, 14, WIDTH, 14), fill="#444444")

        # --- Middle Part (LED Bar) ---
        bar_color = self.led_status['color_code']
        pattern = self.led_status.get('pattern', 'SOLID')
        current_time = time.time()
        
        # --- Pattern Rendering ---
        is_on = self._is_led_on(pattern, current_time, self.led_status['state_change_time'])

        if not is_on:
            bar_color = "black"

        text_color = self._get_contrasting_color(bar_color)
        draw.rectangle((0, 16, WIDTH, 36), fill=bar_color)
        draw.text((4, 18), f"{self.led_status['text']}", fill=text_color, font=FONT_BOLD)
        draw.line((0, 37, WIDTH, 37), fill="#444444")

        # --- Bottom Part (Log Prompt) ---
        y_pos = 40

        # Collect wrapped lines for ALL log entries, then keep only the last that fit.
        line_height = 11
        max_lines = (HEIGHT - 10 - y_pos) // line_height  # number of lines that fit in remaining space

        with self.log_lock:
            log_lines_copy = list(self.log_buffer)

        wrapped_lines = []
        for log_line in log_lines_copy:
            wrapped_lines.extend(self._wrap_line(log_line, FONT_MONO, max_width=WIDTH-8))

        # Keep only the most recent lines that fit
        visible = wrapped_lines[-max_lines:]

        for sub in visible:
            draw.text((4, y_pos), sub, fill="#33FF33", font=FONT_MONO)
            y_pos += line_height

        self.lcd.LCD_ShowImage(self.image_buffer, 0, 0)

    def _get_contrasting_color(self, hex_color):
        """Calculates black or white for best contrast against a given hex color."""
        if hex_color.startswith('#'):
            hex_color = hex_color[1:]
        
        # Handle named colors or invalid formats
        if hex_color == "black":
            return "white"
        
        try:
            # Convert hex to RGB
            r = int(hex_color[0:2], 16)
            g = int(hex_color[2:4], 16)
            b = int(hex_color[4:6], 16)
        except (ValueError, IndexError):
            return "white"  # Default for invalid colors

        # Simple luminance calculation
        luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255

        return "black" if luminance > 0.5 else "white"

    def _is_led_on(self, pattern, current_time, state_change_time):
        """Determines if the LED should be lit based on the pattern and time."""
        is_on = True
        time_in_state = current_time - state_change_time

        if pattern == "SOLID":
            is_on = True
        elif pattern == "SLOW":
            is_on = int(current_time * 0.5) % 2 == 0
        elif pattern == "FAST":
            is_on = int(current_time * 5) % 2 == 0
        elif pattern == "VERYFAST":
            is_on = int(current_time * 50) % 2 == 0
        elif "SINGLE" in pattern or "DOUBLE" in pattern or "TRIPLE" in pattern or "QUAD" in pattern or "QUIN" in pattern:
            is_inverted = pattern.startswith('I')
            base_pattern = pattern[1:] if is_inverted else pattern
            num_blinks = {"SINGLE": 1, "DOUBLE": 2, "TRIPLE": 3, "QUAD": 4, "QUIN": 5}.get(base_pattern, 0)
            
            if num_blinks > 0:
                cycle_len_ms = (num_blinks * 200) + 1000
                time_in_cycle_ms = (current_time * 1000) % cycle_len_ms
                
                if time_in_cycle_ms < (num_blinks * 200):
                    is_on = int(time_in_cycle_ms / 100) % 2 == 0
                else:
                    is_on = True # The long pause period
                if is_inverted: 
                    is_on = not is_on
        elif pattern == "SUCCESS":
            is_on = (time_in_state > 1.0) or (int(current_time * 50) % 2 == 0)
        else:
            try:
                period_ms = int(pattern)
                if 1 <= period_ms <= 10000:
                    period_s = period_ms / 1000.0
                    is_on = (current_time % (2 * period_s)) < period_s
            except (ValueError, TypeError):
                pass  # Keep default is_on=True for unknown patterns
        
        return is_on

    def _wrap_line(self, text, font, max_width):
        """Wrap a single log line to fit within max_width pixels using the provided font."""
        if not text:
            return [""]
        words = text.split(" ")
        lines = []
        current = ""
        for w in words:
            candidate = w if not current else current + " " + w
            if font.getlength(candidate) <= max_width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                # If single word longer than max_width, hard-break
                if font.getlength(w) > max_width:
                    chunk = ""
                    for ch in w:
                        if font.getlength(chunk + ch) <= max_width:
                            chunk += ch
                        else:
                            lines.append(chunk)
                            chunk = ch
                    current = chunk
                else:
                    current = w
        if current:
            lines.append(current)
        return lines


def main():
    """
    Main execution block.
    Usage: python3 this_script.py <payload_name.sh>
    Example: python3 this_script.py my_first_payload/payload.sh
    """
    # --- Check for command-line argument ---
    if len(sys.argv) < 2:
        print("Usage: python3 {} <payload_script_name>".format(sys.argv[0]))
        print("Example: python3 {} my_payload/payload.sh".format(sys.argv[0]))
        sys.exit(1)
        
    full_payload_path = sys.argv[1]

    # ----------------- Hardware Initialization -----------------
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    
    # Setup a signal handler for graceful shutdown on Ctrl+C
    def cleanup_handler(*_):
        # This will be caught by the finally block
        raise KeyboardInterrupt("Signal received, cleaning up.")
    
    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)

    try:
        # ----------------- Execution -----------------
        print(f"--- Starting orchestrator for payload: {full_payload_path} ---")
        orchestrator = PayloadOrchestrator(LCD)
        orchestrator.execute_payload(full_payload_path)

    except (KeyboardInterrupt, Exception) as e:
        if not isinstance(e, KeyboardInterrupt):
            print(f"An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        # ----------------- Hardware Cleanup -----------------
        print("\n--- Cleaning up hardware ---")
        LCD.LCD_Clear()
        GPIO.cleanup()


if __name__ == '__main__':
    main()