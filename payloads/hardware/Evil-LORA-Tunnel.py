#!/usr/bin/env python3
"""Evil-LORA-Tunnel — LoRa/GPS field recorder for RaspyJack."""

import json
import os
import select
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from evil_lora_tunnel import config, session, uploads

TITLE = "Evil-LORA-Tunnel"
LOOT = ROOT / "loot"
SESSIONS = LOOT / "evil-lora-tunnel"
SERVICES = {"WiGLE": "wigle", "Wardrift": "wardrift", "WDGWars": "wdgwars"}
REGIONS = {"US / Canada": "US", "Europe 868 MHz": "EU_868", "Australia / New Zealand": "ANZ"}
MODES = {"Meshtastic": "meshtastic", "MeshCore": "meshcore", "Both (alternating)": "both"}
PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}


class ExitPayload(Exception):
    pass


class Screen:
    """Render using the same logical 128-pixel canvas as RaspyJack payloads."""

    def __init__(self, lcd, get_key, text_input):
        from PIL import Image, ImageColor
        from payloads._display_helper import scaled_font

        self.lcd, self.get_key, self.text_input = lcd, get_key, text_input
        self.font = scaled_font(10)
        self.small = scaled_font(8)
        self.colors = {"BACKGROUND": "#000000", "BORDER": "#05ff00", "TEXT": "#05ff00",
                       "SELECTED_TEXT": "#00ff55", "SELECTED_TEXT_BACKGROUND": "#2d0fff"}
        try:
            configured = json.loads((ROOT / "gui_conf.json").read_text())["COLORS"]
            for key in self.colors:
                if key in configured:
                    self.colors[key] = ImageColor.getrgb(configured[key])
        except (ValueError, OSError, KeyError, TypeError):
            pass
        self.logo = None
        self.wide = lcd.width >= lcd.height * 1.5
        path = ROOT / "img" / "evil_lora_tunnel.png"
        if path.is_file():
            with Image.open(path) as image:
                self.logo = image.convert("RGBA")
            size = round(lcd.height * (.45 if self.wide else .17))
            self.logo.thumbnail((size, size), Image.Resampling.LANCZOS)

    def fit(self, text, width, font=None):
        font = font or self.font
        if font.getlength(text) <= width:
            return text
        lo, hi = 0, len(text)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if font.getlength(text[:mid] + "…") <= width:
                lo = mid
            else:
                hi = mid - 1
        return text[:lo] + "…"

    def frame(self, title, lines, focus=None, footer="LEFT back   K3 exit", logo=False):
        from PIL import Image
        from payloads._display_helper import ScaledDraw

        bg, edge, fg = (self.colors[k] for k in ("BACKGROUND", "BORDER", "TEXT"))
        selected, highlight = (self.colors[k] for k in ("SELECTED_TEXT", "SELECTED_TEXT_BACKGROUND"))
        image = Image.new("RGB", (self.lcd.width, self.lcd.height), bg)
        d = ScaledDraw(image)
        header_x = 4
        menu_right = 126
        if logo and self.logo:
            if self.wide:
                menu_right = 88
                x = round(self.lcd.width * .85 - self.logo.width / 2)
                y = round(self.lcd.height * .52 - self.logo.height / 2)
            else:
                x, y = 2, (round(self.lcd.height * 22 / 128) - self.logo.height) // 2
                header_x = 3 + self.logo.width * 128 / self.lcd.width
            image.paste(self.logo, (x, y), self.logo)
        d.text((header_x, 5), self.fit(title, self.lcd.width * (125 - header_x) / 128),
               font=self.font, fill=selected)
        d.line((0, 22, 127, 22), fill=edge)
        for i, line in enumerate(lines[:6]):
            y = 25 + 14 * i
            if i == focus:
                d.rectangle((1, y, menu_right, y + 13), fill=highlight)
                d.rectangle((1, y, 2, y + 13), fill=selected)
            d.text((5, y + 1), self.fit(str(line), self.lcd.width * (menu_right - 7) / 128), font=self.font,
                   fill=selected if i == focus else fg)
        d.line((0, 112, 127, 112), fill=edge)
        d.text((4, 115), self.fit(footer, self.lcd.width * 120 / 128, self.small),
               font=self.small, fill=fg)
        return image

    def paint(self, *args, **kwargs):
        self.lcd.LCD_ShowImage(self.frame(*args, **kwargs), 0, 0)

    def key(self):
        time.sleep(.04)
        key = self.get_key()
        if key == "KEY3":
            raise ExitPayload
        return key

    def choose(self, title, items, initial=0, logo=False, footer="OK select   LEFT back"):
        items = list(items)
        if not items:
            return None
        i = initial
        while True:
            first = max(0, i - 5)
            hint = f"{i + 1}/{len(items)}   {footer}" if len(items) > 6 else footer
            clipped = self.fit(items[i], self.lcd.width * 119 / 128) != items[i]
            if clipped:
                hint = "K1 full name   OK select"
            self.paint(title, items[first:first + 6], i - first, hint, logo)
            while not (key := self.key()):
                pass
            if key == "LEFT":
                return None
            if key in ("OK", "RIGHT"):
                return items[i]
            if key == "KEY1" and clipped:
                self.report("Full name", [items[i]])
            i = (i + {"DOWN": 1, "UP": -1}.get(key, 0)) % len(items)

    def wrap(self, lines):
        """Wrap details by pixel width, including paths and radio identifiers."""
        result = []
        width = self.lcd.width * 119 / 128
        for line in lines:
            remaining = str(line)
            while remaining and self.font.getlength(remaining) > width:
                n = len(self.fit(remaining, width).removesuffix("…")) or 1
                end = remaining.rfind(" ", 0, n + 1)
                end = end if end > 0 else n
                result.append(remaining[:end])
                remaining = remaining[end:].lstrip()
            result.append(remaining)
        return result

    def report(self, title, lines):
        """Callable reports are live; static reports still support scrolling."""
        top, last, refresh = 0, None, 0
        while True:
            if time.monotonic() >= refresh:
                rows = self.wrap(lines() if callable(lines) else lines)
                top = min(top, max(0, len(rows) - 6))
                page = rows[top:top + 6]
                if last != page:
                    footer = "UP/DN scroll   LEFT back" if len(rows) > 6 else "OK / LEFT back"
                    self.paint(title, page, footer=footer)
                    last = page
                refresh = time.monotonic() + 1
            key = self.key()
            if key in ("OK", "LEFT"):
                return
            if key in ("UP", "DOWN"):
                top = max(0, top + (1 if key == "DOWN" else -1))
                refresh = 0

    def confirm(self, title, action):
        return self.choose(title, ["Cancel", action]) == action


def local_sessions():
    return sorted((file.parent for file in SESSIONS.glob("*/session.json")
                   if not file.parent.is_symlink() and not file.is_symlink()), reverse=True)


def recording_picker(screen, suffix):
    folder = LOOT
    while True:
        files = sorted((p for p in folder.iterdir() if not p.is_symlink() and p != SESSIONS
                        and not p.name.startswith(".") and (p.is_dir() or p.is_file() and p.suffix.lower() == suffix)),
                       key=lambda p: (not p.is_dir(), p.name.casefold()))
        options = {(p.name + "/" if p.is_dir() else p.name): p for p in files}
        if options:
            name = screen.choose("loot/" + folder.relative_to(LOOT).as_posix().strip("."), options)
        else:
            screen.report("Select recording", ["No matching recordings in this folder."])
            name = None
        if name is None:
            if folder == LOOT:
                return None
            folder = folder.parent
        elif options[name].is_dir():
            folder = options[name]
        else:
            return options[name]


def session_action(directory, action, arg=None):
    """Serialize writes with captures and other exports, including concurrent launchers."""
    with session.session_lock():
        if action in ("wifi_csv", "wifi_pcap"):
            session.attach(directory, action, arg)
        session.finalize(directory)
        if action == "export":
            result = uploads.prepare_session(directory)
            return [f"Files prepared: {len(result['artifacts'])}", f"Wi-Fi rows: {result['wifi_rows']}",
                    f"Mesh nodes: {result['mesh_nodes']}", f"Session: {directory.name}"]
        automatic = action in ("auto", "wifi_csv", "wifi_pcap")
        services = SERVICES.values() if automatic else [action]
        result = uploads.advance_uploads(directory, config.load(), list(services), automatic=automatic)
        lines = ["Recording attached."] if action in ("wifi_csv", "wifi_pcap") else []
        for service, data in result["services"].items():
            if not automatic or data["state"] != "disabled":
                lines.append(f"{service}: {data['state'].replace('_', ' ')}")
                for state, count in data.get("states", {}).items():
                    lines.append(f"  {count} {state}")
        return lines


def finish_process(proc):
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise RuntimeError("Recorder timed out while stopping. Check the session status.")


def recorder_id(pid, directory):
    """Identify this particular collector across process exit, PID reuse and reboot."""
    proc = Path("/proc") / str(pid)
    argv = (proc / "cmdline").read_bytes().split(b"\0")
    if argv[1:] != [b"-m", b"evil_lora_tunnel", os.fsencode(directory), b""]:
        raise ValueError("The recorded process is no longer this session's collector.")
    return session.process_identity(pid)


class BackgroundWorker:
    def __init__(self, directory, saved):
        self.pid = int(saved["pid"])
        self.fd = os.pidfd_open(self.pid)
        try:
            if saved != recorder_id(self.pid, directory):
                raise ValueError("Background recording has ended.")
        except BaseException:
            os.close(self.fd)
            raise

    def poll(self):
        return 0 if select.select([self.fd], [], [], 0)[0] else None

    def terminate(self):
        self.send(signal.SIGTERM)

    def kill(self):
        self.send(signal.SIGKILL)

    def send(self, sig):
        # Signal the pinned process even if its numeric PID has since been reused.
        try:
            signal.pidfd_send_signal(self.fd, sig)
        except ProcessLookupError:
            pass

    def wait(self, timeout=None):
        if not select.select([self.fd], [], [], timeout)[0]:
            raise subprocess.TimeoutExpired("background recorder", timeout)


class Recorder:
    def __init__(self, screen):
        self.ui = screen
        self.worker = None
        self.directory = None
        previous = Path(config.load()["last_session"])
        if previous.parent == SESSIONS and not previous.is_symlink() and (previous / "session.json").is_file():
            self.directory = previous
        self.reconnect()

    def reconnect(self):
        if self.worker is not None or not hasattr(os, "pidfd_open"):
            return
        try:
            name = json.loads((SESSIONS / ".active-session.json").read_text())
            if not isinstance(name, str) or name in ("", ".", "..") or Path(name).name != name:
                return
            directory = SESSIONS / name
            if directory.is_symlink():
                return
            state = session.status(directory)
            if state["status"] in ("starting", "capturing"):
                self.worker = BackgroundWorker(directory, state["worker_identity"])
                self.directory = directory
        except (KeyError, ValueError, FileNotFoundError, ProcessLookupError):
            pass

    def running(self):
        return self.worker is not None and self.worker.poll() is None

    def start(self):
        self.reconnect()
        if self.worker is not None:
            if self.running():
                raise ValueError("A capture is already running.")
            self.stop(automatic=False)
        settings = config.load()
        if not settings["region"]:
            region = self.ui.choose("Choose radio region", REGIONS)
            if not region:
                return
            config.set_value("region", REGIONS[region])
        if settings["backend"] == "lorapipe" and not settings["serial_device"]:
            raise ValueError("Set the USB serial device in Radio settings first.")
        self.directory = session.create_session(SESSIONS)
        try:
            config.set_value("last_session", str(self.directory))
            self.worker = subprocess.Popen([sys.executable, "-m", "evil_lora_tunnel", str(self.directory)],
                                           stdin=subprocess.DEVNULL, cwd=ROOT, start_new_session=True)
        except (ValueError, OSError) as error:
            session.interrupt_start(self.directory, f"Could not launch recorder: {error}")
            raise
        self.ui.report("Starting capture", self.status)

    def stop(self, automatic=True):
        if self.worker is None:
            return
        try:
            finish_process(self.worker)
        finally:
            stopped = self.worker.poll() is not None
            if isinstance(self.worker, BackgroundWorker):
                os.close(self.worker.fd)
            self.worker = None
            if stopped:
                session.interrupt_start(self.directory, "Recorder stopped before initialization finished.")
        if automatic and session.status(self.directory)["status"] == "closed":
            if any(x["enabled"] and x["auto"] for x in config.load()["uploads"].values()):
                self.job("Automatic uploads", "auto")

    def background(self):
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise ValueError("Background recording requires Linux process descriptors.")
        action = self.ui.choose("Record in background", ["Cancel", "LoRa only", "LoRa + native Wi-Fi"])
        if action is None or action == "Cancel":
            return
        # Confirm kernel support before leaving a worker for a new UI to control.
        os.close(os.pidfd_open(self.worker.pid))
        if action == "LoRa + native Wi-Fi":
            self.ui.paint("Sharing GPS", ["Releasing the GPS UART for native Wardriving…"])
            session.share_gps(self.directory)
        if session.status(self.directory).get("worker_identity") != recorder_id(self.worker.pid, self.directory):
            raise ValueError("Recorder is starting. Check Status before returning to RaspyJack.")
        if isinstance(self.worker, BackgroundWorker):
            os.close(self.worker.fd)
        self.worker = None
        raise ExitPayload

    def status(self):
        if not self.directory:
            settings = config.load()
            return ["Ready to capture", f"Radio: {settings['backend']}", f"Region: {settings['region'] or 'choose on start'}",
                    f"Mode: {settings['mode']}"]
        if self.worker is not None and self.worker.poll() is not None:
            session.interrupt_start(self.directory, "Recorder exited before initialization finished.")
        data = session.status(self.directory)
        state = data["status"]
        errors = list(data.get("errors") or [])
        if self.worker is not None and self.worker.poll() is not None and state in ("created", "starting", "capturing"):
            state = "interrupted"
            errors.append("Receiver process exited before closing this session.")
        rows = [state.capitalize(), *errors, f"Received {data.get('received', 0)}   Saved {data.get('saved', 0)}",
                f"GPS: {data.get('gps', {}).get('status', 'waiting').replace('_', ' ')}",
                f"Profile: {data.get('profile') or 'waiting'}", f"Queue drops: {data.get('queue_drops', 0)}",
                f"Write errors: {data.get('write_errors', 0)}", self.directory.name]
        return rows

    def job(self, title, action, arg=None):
        """Long exports/network requests run off the UI; LEFT cancels the operation."""
        cmd = [sys.executable, str(Path(__file__).resolve()), "--session-action", str(self.directory), action]
        if arg is not None:
            cmd.append(str(arg))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL, cwd=ROOT)
        try:
            self.ui.paint(title, ["Working…"], footer="LEFT cancel   K3 exit")
            while proc.poll() is None:
                if self.ui.key() == "LEFT":
                    return
            output = proc.communicate()[0].splitlines()
        finally:
            finish_process(proc)
            proc.stdout.close()
        self.ui.report(title, output or ["Operation complete." if proc.returncode == 0 else "Operation failed."])

    def radio(self):
        if self.running():
            raise ValueError("Stop capture before changing radio settings.")
        current = config.load()
        options = [f"Region: {current['region'] or 'unset'}", f"Mode: {current['mode']}",
                   "Radio: " + ("LoRa/GPS cap" if current["backend"] == "cap" else "LoRaPipe USB")]
        choice = self.ui.choose("Radio settings", options)
        if choice == options[0] or choice == options[1]:
            regions = choice == options[0]
            choices = REGIONS if regions else MODES
            value = self.ui.choose("Region" if regions else "Receive mode", choices)
            if value:
                config.set_value("region" if regions else "mode", choices[value])
        elif choice == options[2]:
            value = self.ui.choose("Receive hardware", ["LoRa/GPS cap", "LoRaPipe USB"])
            if value == "LoRaPipe USB":
                port = self.ui.text_input("Serial device", current["serial_device"] or "/dev/ttyUSB0", 256)
                if not port:
                    return
                config.set_value("serial_device", port)
            if value:
                config.set_value("backend", "cap" if value == "LoRa/GPS cap" else "lorapipe")

    def select_session(self):
        if self.running():
            raise ValueError("Stop capture before selecting another session.")
        self.stop(automatic=False)
        choices = {d.name: d for d in local_sessions()}
        if not choices:
            raise ValueError("No recorded sessions yet.")
        value = self.ui.choose("Select session (UTC)", choices)
        if value:
            self.directory = choices[value]
            config.set_value("last_session", str(self.directory))

    def observations(self):
        if not self.directory:
            raise ValueError("Start a capture or select a session.")
        value = self.ui.choose("Observations", ["Recent packets", "Device summaries"])
        if value:
            self.ui.report(value, lambda: session.recent_records(self.directory, devices=value == "Device summaries"))

    def export(self):
        if not self.directory or self.running() or session.status(self.directory)["status"] != "closed":
            raise ValueError("Choose a cleanly stopped session to export.")
        labels = ["Prepare local export", "Attach Wi-Fi CSV", "Attach Wi-Fi PCAP"] + [f"Upload to {s}" for s in SERVICES]
        value = self.ui.choose("Session export", labels)
        if value == labels[0]:
            self.job(value, "export")
        elif value in labels[1:3]:
            csv_file = value == labels[1]
            file = recording_picker(self.ui, ".csv" if csv_file else ".pcap")
            if file is None or not file.resolve().is_relative_to(LOOT.resolve()):
                return
            if self.ui.confirm("Recording stopped?", "Attach this file"):
                self.job(value, "wifi_csv" if csv_file else "wifi_pcap", file)
        elif value:
            display = value.removeprefix("Upload to ")
            service = SERVICES[display]
            if not config.load()["uploads"][service]["enabled"]:
                raise ValueError(f"Enable {display} uploads in Accounts first.")
            if self.ui.confirm(f"Send to {display}?", "Send logs + locations"):
                self.job(value, service)

    def accounts(self):
        name = self.ui.choose("Upload accounts", SERVICES)
        if not name:
            return
        service = SERVICES[name]
        key = f"uploads.{service}."
        current = config.load()["uploads"][service]
        toggles = {"Allow uploads": "enabled", "Automatic after capture": "auto"}
        if service == "wigle":
            toggles["Donate to WiGLE"] = "donate"
        labels = {f"[{'on' if current[field] else 'off'}] {label}": field for label, field in toggles.items()}
        choice = self.ui.choose(name, ["Credentials", *labels])
        if choice == "Credentials":
            fields = [("API name", "api_name"), ("API token", "api_token")] if service == "wigle" else [("API key", "api_key")]
            for title, field in fields:
                value = self.ui.text_input(name + " " + title, "", 512, masked=True)
                if not value:
                    return
                config.set_value(key + field, value)
        elif choice:
            field = labels[choice]
            enabled = not current[field]
            if enabled and not self.ui.confirm(name, {"enabled": "Allow logs + locations", "auto": "Send after capture",
                                                      "donate": "Donate uploads"}[field]):
                return
            if enabled and field == "auto":
                config.set_value(key + "enabled", True)
            if not enabled and field == "enabled":
                config.set_value(key + "auto", False)
            config.set_value(key + field, enabled)

    def run(self):
        pos = 0
        while True:
            try:
                self.reconnect()
                active = self.running()
                actions = ({"Stop capture": self.stop, "Record in background": self.background}
                           if active else {"Start capture": self.start})
                actions.update({"Status": lambda: self.ui.report("Session status", self.status),
                                "Observations": self.observations, "Select session": self.select_session,
                                "Radio settings": self.radio, "Export / upload": self.export, "Accounts": self.accounts})
                pos = min(pos, len(actions) - 1)
                value = self.ui.choose(TITLE, actions, initial=pos, logo=True, footer="OK select   K3 exit")
                if value is None:
                    return
                pos = list(actions).index(value)
                actions[value]()
            except (ValueError, RuntimeError, OSError, sqlite3.Error) as error:
                self.ui.report("Action unavailable", [str(error)])


def main():
    import LCD_1in44
    import RPi.GPIO as GPIO
    from payloads._display_helper import scaled_font
    from payloads._input_helper import get_button
    from payloads._keyboard_helper import lcd_keyboard

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()
    ui = Screen(lcd, lambda: get_button(PINS, GPIO),
                lambda title, value, limit, masked=False: lcd_keyboard(
                    lcd, font, PINS, GPIO, title, value, max_len=limit, masked=masked))
    app = None

    def exit_on_signal(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, exit_on_signal)
    try:
        try:
            app = Recorder(ui)
            try:
                app.run()
            except ExitPayload:
                pass
            app.stop()
        except (RuntimeError, ValueError, OSError) as error:
            ui.report("Recorder unavailable", [str(error)])
    except (ExitPayload, KeyboardInterrupt):
        pass
    finally:
        try:
            if app:
                app.stop(automatic=False)
        finally:
            lcd.LCD_Clear()
            GPIO.cleanup()


if __name__ == "__main__":
    if sys.argv[1:2] == ["--session-action"]:
        try:
            print("\n".join(session_action(Path(sys.argv[2]), *sys.argv[3:])))
        except (ValueError, RuntimeError, OSError, sqlite3.Error) as exc:
            print(str(exc))
            sys.exit(1)
    else:
        main()
