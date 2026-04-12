"""Utility helpers for parsing Lynis /var/log/lynis-report.dat files."""
from __future__ import annotations

from typing import Dict, List, Tuple


ENTRY_KEYS: Tuple[str, ...] = ("code", "message", "detail", "remediation")
PLACEHOLDER_VALUES = {"-", ""}


def _cleanup(value: str) -> str:
    """Normalize placeholder values that Lynis uses for empty fields."""
    if value is None:
        return ""
    stripped = value.strip()
    return "" if stripped in PLACEHOLDER_VALUES else stripped


def _split_pipe_payload(payload: str) -> Dict[str, str]:
    parts = [part.strip() for part in payload.split("|")]
    # Extend the list so unpacking always works even if Lynis omits fields
    while len(parts) < len(ENTRY_KEYS):
        parts.append("")

    code, message, detail, remediation, *rest = parts + [""]
    return {
        "code": _cleanup(code),
        "message": _cleanup(message) or payload.strip(),
        "detail": _cleanup(detail),
        "remediation": _cleanup(remediation or (rest[0] if rest else "")),
        "raw": payload.strip()
    }


def _parse_vulnerable_package(payload: str) -> Dict[str, str]:
    parts = [part.strip() for part in payload.split("|")]
    while len(parts) < 4:
        parts.append("")

    package, version, status, reference, *rest = parts + [""]
    return {
        "package": _cleanup(package),
        "version": _cleanup(version),
        "status": _cleanup(status),
        "reference": _cleanup(reference or (rest[0] if rest else "")),
        "raw": payload.strip()
    }


def parse_lynis_dat(content: str) -> Dict[str, object]:
    """Parse the contents of lynis-report.dat into structured data."""
    data = {
        "metadata": {},
        "warnings": [],
        "suggestions": [],
        "vulnerable_packages": [],
    }

    if not content:
        return data

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()

        base_key = key.split("[", 1)[0]
        if base_key == "warning":
            data["warnings"].append(_split_pipe_payload(value))
        elif base_key == "suggestion":
            data["suggestions"].append(_split_pipe_payload(value))
        elif base_key == "vulnerable_package":
            data["vulnerable_packages"].append(_parse_vulnerable_package(value))
        else:
            data["metadata"][base_key] = value

    return data
