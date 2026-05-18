"""
Audio helper — auto-detect ES8389 card number.
Usage:
    from payloads._audio_helper import get_audio_card, get_alsa_dev
"""

import subprocess

_card = None
_dev = None


def get_audio_card():
    """Return ES8389 card number as string. Cached."""
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
    """Return ALSA device string like 'plughw:0,0'. Cached."""
    global _dev
    if _dev is not None:
        return _dev
    _dev = f"plughw:{get_audio_card()},0"
    return _dev
