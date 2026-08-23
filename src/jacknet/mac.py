from __future__ import annotations

import re
from collections import Counter

from .models import Device, Evidence

_MAC_HEX = re.compile(r"^[0-9a-fA-F]{12}$")


def normalize_mac(mac: str | None) -> str | None:
    """Return a canonical lower-case colon-separated MAC address."""
    if not mac:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", mac)
    if not _MAC_HEX.fullmatch(compact):
        return None
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2)).lower()


def is_locally_administered(mac: str | None) -> bool:
    """True when the IEEE U/L bit indicates a locally administered address."""
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    return bool(int(normalized[0:2], 16) & 0x02)


def is_multicast(mac: str | None) -> bool:
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    return bool(int(normalized[0:2], 16) & 0x01)


def address_type(mac: str | None) -> str:
    normalized = normalize_mac(mac)
    if not normalized:
        return "unknown"
    if is_multicast(normalized):
        return "multicast"
    if is_locally_administered(normalized):
        return "locally_administered"
    return "globally_administered"


def annotate_mac_facts(devices: list[Device]) -> None:
    """Attach MAC-addressing facts and flag duplicate MAC observations."""
    counts = Counter(normalize_mac(d.mac) for d in devices if normalize_mac(d.mac))
    for device in devices:
        normalized = normalize_mac(device.mac)
        if not normalized:
            continue
        device.mac = normalized
        kind = address_type(normalized)
        if kind == "locally_administered":
            device.evidence.append(
                Evidence(
                    "mac",
                    "address_type",
                    "locally administered/private address; vendor OUI may be unavailable",
                    0,
                )
            )
        if counts[normalized] > 1:
            device.evidence.append(
                Evidence(
                    "arp",
                    "duplicate_mac",
                    f"same MAC observed at {counts[normalized]} IPv4 addresses in this scan",
                    0,
                )
            )
