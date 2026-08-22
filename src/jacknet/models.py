from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any

@dataclass
class Evidence:
    source: str
    fact: str
    value: str
    weight: int = 0

@dataclass
class Device:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    device_type: str | None = None
    os: str | None = None
    confidence: int = 0
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    mdns: list[dict[str, Any]] = field(default_factory=list)
    ssdp: list[dict[str, Any]] = field(default_factory=list)
    os_guesses: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d
