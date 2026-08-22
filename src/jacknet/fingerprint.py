from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from importlib.resources import files
from .models import Device, Evidence


@dataclass(frozen=True)
class Rule:
    field: str
    needle: str
    label: str
    kind: str
    score: int


def load_rules() -> list[Rule]:
    """Load built-in fingerprints from package data rather than Python code."""
    path = files("jacknet").joinpath("data/fingerprints.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [Rule(**row) for row in raw.get("rules", [])]


RULES = load_rules()

PORT_HINTS = {
    445: ("Windows/SMB host", "computer", 15),
    3389: ("Windows/RDP host", "computer", 20),
    548: ("Apple AFP host", "computer", 15),
    631: ("IPP printer", "printer", 25),
    9100: ("JetDirect printer", "printer", 30),
    22: ("SSH-capable host", "computer_or_appliance", 10),
}

DEVICE_TYPE_HINTS = {
    "printer": ("Network printer", "printer", 45),
    "print": ("Network printer", "printer", 35),
    "router": ("Network router", "router", 40),
    "switch": ("Network switch", "switch", 40),
    "wap": ("Wireless access point", "access_point", 40),
    "webcam": ("Network camera", "camera", 35),
    "camera": ("Network camera", "camera", 35),
    "media device": ("Media device", "media_device", 30),
    "game console": ("Game console", "game_console", 40),
}


def _add(scores, device, label, kind, score, source, fact, value):
    scores[(label, kind)] += score
    device.evidence.append(Evidence(source, fact, value, score))


def apply_fingerprint(device: Device) -> Device:
    scores: dict[tuple[str, str], int] = defaultdict(int)
    fields = {
        "manufacturer": device.manufacturer or "",
        "hostname": device.hostname or "",
        "model": device.model or "",
        "os": device.os or "",
    }
    for rule in RULES:
        value = fields.get(rule.field, "").lower()
        if rule.needle in value:
            _add(scores, device, rule.label, rule.kind, rule.score, "rule", rule.field, rule.needle)

    for rec in device.open_ports:
        port = int(rec.get("port", 0))
        if port in PORT_HINTS:
            label, kind, score = PORT_HINTS[port]
            _add(scores, device, label, kind, score, "port", str(port), label)

        blob = " ".join(str(rec.get(k, "")) for k in ("name", "product", "version", "extrainfo", "ostype", "devicetype")).lower()
        devtype = str(rec.get("devicetype", "")).lower()
        for needle, (label, kind, score) in DEVICE_TYPE_HINTS.items():
            if needle in devtype:
                _add(scores, device, label, kind, score, "nmap", "devicetype", devtype)
        for needle, label, kind, score in (
            ("playstation", "Sony PlayStation", "game_console", 55),
            ("xbox", "Microsoft Xbox", "game_console", 55),
            ("brother", "Brother printer", "printer", 45),
            ("hewlett-packard", "HP device", "computer_or_printer", 30),
            ("jetdirect", "Network printer", "printer", 45),
        ):
            if needle in blob:
                _add(scores, device, label, kind, score, "nmap", "service", needle)

    for guess in device.os_guesses:
        name = str(guess.get("name", ""))
        accuracy = int(guess.get("accuracy", 0))
        if name and accuracy >= 70:
            kind = "computer_or_appliance"
            label = name
            _add(scores, device, label, kind, max(8, min(25, accuracy // 4)), "nmap", "os", f"{name} ({accuracy}%)")

    for rec in device.ssdp:
        blob = " ".join(str(v) for v in rec.values()).lower()
        for needle, label, kind, score in (
            ("playstation", "Sony PlayStation", "game_console", 55),
            ("roku", "Roku", "streaming_device", 50),
            ("printer", "Network printer", "printer", 35),
            ("mediarenderer", "UPnP media renderer", "media_device", 25),
        ):
            if needle in blob:
                _add(scores, device, label, kind, score, "ssdp", needle, label)

    for rec in device.mdns:
        blob = " ".join(str(v) for v in rec.values()).lower()
        for needle, label, kind, score in (
            ("_googlecast", "Google Chromecast", "streaming_device", 55),
            ("_airplay", "AirPlay device", "media_device", 30),
            ("_ipp", "Network printer", "printer", 35),
            ("_printer", "Network printer", "printer", 35),
            ("_workstation", "Workstation", "computer", 20),
        ):
            if needle in blob:
                _add(scores, device, label, kind, score, "mdns", needle, label)

    if scores:
        (label, kind), raw = max(scores.items(), key=lambda kv: kv[1])
        if not device.model:
            device.model = label
        if not device.device_type:
            device.device_type = kind
        device.confidence = min(99, int(100 * (1 - (0.985 ** raw))))
    else:
        device.confidence = 10 if device.mac or device.hostname else 1
        device.device_type = device.device_type or "unknown"
    return device
