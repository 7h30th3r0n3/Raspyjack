"""
SDR Radio Suite – Presets and Configuration
"""
import json
import os

BAND_PRESETS = [
    {"name": "FM Broadcast",  "freq": 97_750_000,  "start": 87_500_000,  "end": 108_000_000, "step": 100_000,  "mode": "WFM", "bw": 200_000},
    {"name": "Air Band",      "freq": 127_500_000, "start": 118_000_000, "end": 137_000_000, "step": 25_000,   "mode": "AM",  "bw": 25_000},
    {"name": "2m Amateur",    "freq": 145_000_000, "start": 144_000_000, "end": 146_000_000, "step": 12_500,   "mode": "NFM", "bw": 12_500},
    {"name": "70cm Amateur",  "freq": 435_000_000, "start": 430_000_000, "end": 440_000_000, "step": 25_000,   "mode": "NFM", "bw": 25_000},
    {"name": "NOAA Weather",  "freq": 162_475_000, "start": 162_400_000, "end": 162_550_000, "step": 25_000,   "mode": "NFM", "bw": 25_000},
    {"name": "Marine VHF",    "freq": 156_800_000, "start": 156_000_000, "end": 162_000_000, "step": 25_000,   "mode": "NFM", "bw": 25_000},
    {"name": "PMR446",        "freq": 446_006_250, "start": 446_006_250, "end": 446_193_750, "step": 12_500,   "mode": "NFM", "bw": 12_500},
    {"name": "ISM 433",       "freq": 433_920_000, "start": 433_050_000, "end": 434_790_000, "step": 25_000,   "mode": "NFM", "bw": 25_000},
    {"name": "ISM 868",       "freq": 868_300_000, "start": 868_000_000, "end": 868_600_000, "step": 25_000,   "mode": "NFM", "bw": 25_000},
    {"name": "FRS/GMRS",      "freq": 462_562_500, "start": 462_562_500, "end": 467_712_500, "step": 25_000,   "mode": "NFM", "bw": 12_500},
    {"name": "ACARS",         "freq": 131_550_000, "start": 131_550_000, "end": 136_975_000, "step": 25_000,   "mode": "AM",  "bw": 25_000},
    {"name": "ADS-B 1090",    "freq": 1_090_000_000, "start": 1_089_000_000, "end": 1_091_000_000, "step": 0,  "mode": "RAW", "bw": 2_000_000},
]

NOAA_CHANNELS = [
    (162_550_000, "WX1"), (162_400_000, "WX2"), (162_475_000, "WX3"),
    (162_425_000, "WX4"), (162_450_000, "WX5"), (162_500_000, "WX6"),
    (162_525_000, "WX7"),
]

FM_STATIONS = [
    ("France Inter", 87_700_000), ("France Musique", 91_700_000),
    ("France Culture", 93_500_000), ("RTL", 104_300_000),
    ("Europe 1", 104_700_000), ("France Info", 105_500_000),
    ("NRJ", 100_300_000), ("Fun Radio", 101_900_000),
    ("RFM", 103_900_000), ("Skyrock", 96_000_000),
    ("Nostalgie", 90_400_000), ("Cherie FM", 91_300_000),
    ("Rire et Chansons", 97_400_000), ("Virgin Radio", 103_500_000),
]

DEFAULT_SETTINGS = {
    "center_freq": 100_000_000,
    "sample_rate": 2_048_000,
    "gain": 30,
    "fft_size": 256,
    "colormap": "turbo",
    "db_min": -70,
    "db_max": -10,
    "audio_device": "default",
    "waterfall_fps": 10,
    "scanner_threshold": -45,
    "scanner_dwell": 0.3,
    "last_preset": 0,
}

SETTINGS_PATH = "/root/Raspyjack/loot/SDR/sdr_settings.json"


def load_settings():
    s = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, "r") as f:
            s.update(json.load(f))
    except Exception:
        pass
    return s


def save_settings(s):
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    with open(SETTINGS_PATH, "w") as f:
        json.dump(s, f, indent=2)


def format_freq(hz):
    if hz >= 1_000_000_000:
        return f"{hz / 1e9:.4f} GHz"
    if hz >= 1_000_000:
        return f"{hz / 1e6:.3f} MHz"
    if hz >= 1_000:
        return f"{hz / 1e3:.1f} kHz"
    return f"{hz} Hz"


def format_freq_short(hz):
    if hz >= 1_000_000:
        return f"{hz / 1e6:.1f}"
    return f"{hz / 1e3:.0f}k"
