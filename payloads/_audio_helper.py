"""
Audio helper - auto-detect playback and capture ALSA devices.
Usage:
    from payloads._audio_helper import get_audio_card, get_alsa_dev
    from payloads._audio_helper import get_capture_card, get_capture_dev
    from payloads._audio_helper import enable_capture, disable_capture
    from payloads._audio_helper import open_capture_stream, get_capture_label

USB microphones are preferred over the built-in ES838x codec when present.
Set RASPYJACK_CAPTURE_DEV to force a device (e.g. "plughw:3,0").
"""

import os
import subprocess

_card = None
_dev = None
_capture_card = None
_capture_dev = None
_capture_desc = ""


def _card_num_from_line(line):
    try:
        return line.split(":")[0].replace("card", "").strip()
    except Exception:
        return None


def get_audio_card():
    """Return playback card number as string. Cached."""
    global _card
    if _card is not None:
        return _card
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if "card" in line.lower() and ":" in line:
                num = line.split(":")[0].replace("card", "").strip()
                if any(k in line.upper() for k in ["ES8388", "ES8389", "ES8390"]):
                    _card = num
                    return _card
                elif "HDMI" not in line.upper():
                    _card = num
    except Exception:
        pass
    if _card is None:
        _card = "0"
    return _card


def get_alsa_dev():
    """Return playback ALSA device string like 'plughw:0,0'. Cached."""
    global _dev
    if _dev is not None:
        return _dev
    _dev = f"plughw:{get_audio_card()},0"
    return _dev


def get_capture_card():
    """Return capture card number as string, preferring USB microphones."""
    global _capture_card, _capture_desc
    if _capture_card is not None:
        return _capture_card
    try:
        r = subprocess.run(["arecord", "-l"], capture_output=True, text=True, timeout=3)
        usb_candidate = None
        mic_candidate = None
        fallback = None
        for line in r.stdout.split("\n"):
            if "card" not in line.lower() or ":" not in line:
                continue
            num = _card_num_from_line(line)
            if not num:
                continue
            upper = line.upper()
            if "USB" in upper:
                usb_candidate = usb_candidate or (num, line)
            elif any(k in upper for k in ["MIC", "MICROPHONE"]):
                mic_candidate = mic_candidate or (num, line)
            elif any(k in upper for k in ["ES8388", "ES8389", "ES8390"]):
                fallback = fallback or (num, line)
            elif "HDMI" not in upper:
                fallback = fallback or (num, line)
        for candidate in (usb_candidate, mic_candidate, fallback):
            if candidate is not None:
                _capture_card, _capture_desc = candidate
                return _capture_card
    except Exception:
        pass
    _capture_card = get_audio_card()
    return _capture_card


def get_capture_dev():
    """Return capture ALSA device string like 'plughw:2,0'. Cached.

    RASPYJACK_CAPTURE_DEV overrides auto-detection.
    """
    global _capture_dev
    if _capture_dev is not None:
        return _capture_dev
    override = os.environ.get("RASPYJACK_CAPTURE_DEV", "").strip()
    if override:
        _capture_dev = override
        return _capture_dev
    _capture_dev = f"plughw:{get_capture_card()},0"
    return _capture_dev


def _selected_capture_desc():
    """Return the `arecord -l` line describing the selected capture card."""
    override = os.environ.get("RASPYJACK_CAPTURE_DEV", "").strip()
    if not override:
        get_capture_card()
        return _capture_desc
    card = override.split(":")[-1].split(",")[0]
    try:
        r = subprocess.run(["arecord", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if ":" in line and _card_num_from_line(line) == card:
                return line
    except Exception:
        pass
    return ""


def is_usb_capture():
    """True when the selected capture device is a USB microphone."""
    return "USB" in _selected_capture_desc().upper()


def is_builtin_codec_capture():
    """True when the selected capture device is the on-board ES838x codec.

    Only this codec needs the AU_EN i2c poke and the ADC MUX/PGA controls;
    everything else is driven through plain ALSA mixer controls.
    """
    upper = _selected_capture_desc().upper()
    return any(k in upper for k in ("ES8388", "ES8389", "ES8390"))


def get_capture_label():
    """Short human-readable name of the capture device, for on-screen display."""
    desc = _selected_capture_desc()
    name = desc.split("[", 1)[1].split("]", 1)[0].strip() if "[" in desc else ""
    if is_builtin_codec_capture():
        return "Built-in Mic"
    if is_usb_capture():
        return name or "USB Mic"
    return name or f"Capture {get_capture_card()}"


def _amixer(card, *args):
    try:
        r = subprocess.run(["amixer", "-c", card] + list(args),
                           capture_output=True, timeout=2)
        return r.returncode == 0
    except Exception:
        return False


def enable_capture(gain_percent=80):
    """Power up and unmute the selected microphone.

    USB mics only need their capture control unmuted and turned up. The built-in
    ES838x codec additionally needs AU_EN asserted over i2c and its ADC path set.
    """
    card = get_capture_card()
    if not is_builtin_codec_capture():
        for control in ("Mic", "Capture", "Microphone", "Digital"):
            _amixer(card, "sset", control, f"{gain_percent}%", "cap")
        return
    subprocess.run(["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x01"],
                   capture_output=True, timeout=2)
    pga = str(int(12 * gain_percent / 80))
    adc = str(int(220 * gain_percent / 80))
    for control, value in (
        ("ADC MUX", "0"),
        ("ADCL PGA Volume", pga),
        ("ADCR PGA Volume", pga),
        ("ADCL Capture Volume", adc),
        ("ADCR Capture Volume", adc),
    ):
        _amixer(card, "cset", f"name={control}", value)


def disable_capture():
    """Release the microphone. No-op for USB mics, which have nothing to power down."""
    if not is_builtin_codec_capture():
        return
    subprocess.run(["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x03"],
                   capture_output=True, timeout=2)


def open_capture_stream(rate=16000, channels=1, fmt="S16_LE"):
    """Enable the mic and return a Popen streaming raw PCM on stdout.

    Caller owns the process and must terminate it, then call disable_capture().
    plughw handles rate/channel conversion for USB mics that cannot do 16k mono.
    """
    enable_capture()
    return subprocess.Popen(
        ["arecord", "-D", get_capture_dev(), "-f", fmt, "-r", str(rate),
         "-c", str(channels), "-t", "raw"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def list_capture_devices():
    """Return [(card_number, description)] for every capture card ALSA reports."""
    devices = []
    try:
        r = subprocess.run(["arecord", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if "card" not in line.lower() or ":" not in line:
                continue
            num = _card_num_from_line(line)
            if not num:
                continue
            name = line.split("[", 1)[1].split("]", 1)[0].strip() if "[" in line else line.strip()
            devices.append((num, name))
    except Exception:
        pass
    return devices
