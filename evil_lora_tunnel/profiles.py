"""Explicit receive profiles; a radio hears one profile at a time."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Profile:
    id: str
    region: str
    protocol: str
    frequency_hz: int
    bandwidth_hz: int
    spreading_factor: int
    coding_rate: int
    sync_word: int
    preamble_symbols: int
    dwell_seconds: float = 30.0

    def to_dict(self):
        return asdict(self)


# Radio parameters cross-checked against Kismet's 2026-11-17 LoRaPipe
# source, Meshtastic radio settings, and the MeshCore regional preset list.
# The modem sync word is the 8-bit convention used by LoRaPipe/RadioLib.
PROFILES = {
    "meshtastic-US-LONG_FAST": Profile("meshtastic-US-LONG_FAST", "US", "meshtastic", 906875000, 250000, 11, 5, 0x2B, 16),
    "meshcore-US-NARROW": Profile("meshcore-US-NARROW", "US", "meshcore", 910525000, 62500, 7, 5, 0x12, 16),
    "meshcore-US-SOCAL": Profile("meshcore-US-SOCAL", "US", "meshcore", 927875000, 62500, 7, 5, 0x12, 16),
    "meshtastic-EU_868-LONG_FAST": Profile("meshtastic-EU_868-LONG_FAST", "EU_868", "meshtastic", 869525000, 250000, 11, 5, 0x2B, 16),
    "meshcore-EU_868-NARROW": Profile("meshcore-EU_868-NARROW", "EU_868", "meshcore", 869618000, 62500, 8, 8, 0x12, 16),
    "meshtastic-ANZ-LONG_FAST": Profile("meshtastic-ANZ-LONG_FAST", "ANZ", "meshtastic", 919875000, 250000, 11, 5, 0x2B, 16),
    "meshcore-ANZ-NARROW": Profile("meshcore-ANZ-NARROW", "ANZ", "meshcore", 916575000, 62500, 7, 7, 0x12, 16),
}


def select_profiles(region, mode="meshtastic"):
    """Return a bounded scan list only after an explicit region selection."""
    if region not in {"US", "EU_868", "ANZ"}:
        raise ValueError("Select a supported LoRa region: US, EU_868, or ANZ")
    if mode not in {"meshtastic", "meshcore", "both"}:
        raise ValueError("LoRa mode must be meshtastic, meshcore, or both")
    ids = []
    if mode in {"meshtastic", "both"}:
        ids.append("meshtastic-%s-LONG_FAST" % region)
    if mode in {"meshcore", "both"}:
        ids.append("meshcore-%s-NARROW" % region)
    return [PROFILES[key] for key in ids]


def validate_profile(profile):
    if not isinstance(profile, Profile) or profile not in PROFILES.values():
        raise ValueError("Use a verified receive profile")
    return profile
