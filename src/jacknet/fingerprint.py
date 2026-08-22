from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from .models import Device, Evidence

@dataclass(frozen=True)
class Rule:
    field: str
    needle: str
    label: str
    kind: str
    score: int

RULES = [
    Rule("manufacturer", "sony interactive", "Sony PlayStation", "game_console", 45),
    Rule("manufacturer", "sony", "Sony device", "consumer_electronics", 20),
    Rule("hostname", "ps5", "Sony PlayStation 5", "game_console", 50),
    Rule("hostname", "ps4", "Sony PlayStation 4", "game_console", 50),
    Rule("hostname", "xbox", "Microsoft Xbox", "game_console", 50),
    Rule("manufacturer", "nintendo", "Nintendo console", "game_console", 45),
    Rule("manufacturer", "apple", "Apple device", "computer_or_mobile", 30),
    Rule("manufacturer", "lenovo", "Lenovo computer", "computer", 35),
    Rule("manufacturer", "dell", "Dell computer", "computer", 35),
    Rule("manufacturer", "hewlett", "HP computer/printer", "computer_or_printer", 30),
    Rule("manufacturer", "samsung", "Samsung device", "consumer_electronics", 25),
    Rule("manufacturer", "roku", "Roku", "streaming_device", 45),
    Rule("manufacturer", "raspberry", "Raspberry Pi", "single_board_computer", 45),
    Rule("hostname", "chromecast", "Google Chromecast", "streaming_device", 50),
    Rule("hostname", "iphone", "Apple iPhone", "phone", 45),
    Rule("hostname", "ipad", "Apple iPad", "tablet", 45),
    Rule("hostname", "printer", "Network printer", "printer", 35),
]

PORT_HINTS = {
    445: ("Windows/SMB host", "computer", 15),
    3389: ("Windows/RDP host", "computer", 20),
    548: ("Apple AFP host", "computer", 15),
    631: ("IPP printer", "printer", 25),
    9100: ("JetDirect printer", "printer", 30),
    22: ("SSH-capable host", "computer_or_appliance", 10),
}


def apply_fingerprint(device: Device) -> Device:
    scores: dict[tuple[str, str], int] = defaultdict(int)
    fields = {"manufacturer": device.manufacturer or "", "hostname": device.hostname or "", "model": device.model or "", "os": device.os or ""}
    for rule in RULES:
        value = fields.get(rule.field, "").lower()
        if rule.needle in value:
            scores[(rule.label, rule.kind)] += rule.score
            device.evidence.append(Evidence("rule", rule.field, rule.needle, rule.score))
    for p in device.open_ports:
        port = int(p.get("port", 0))
        if port in PORT_HINTS:
            label, kind, score = PORT_HINTS[port]; scores[(label, kind)] += score
            device.evidence.append(Evidence("port", str(port), label, score))
    for rec in device.ssdp:
        blob = " ".join(str(v) for v in rec.values()).lower()
        for needle, label, kind, score in [("playstation", "Sony PlayStation", "game_console", 55), ("roku", "Roku", "streaming_device", 50), ("printer", "Network printer", "printer", 35), ("mediarenderer", "UPnP media renderer", "media_device", 25)]:
            if needle in blob:
                scores[(label, kind)] += score; device.evidence.append(Evidence("ssdp", needle, label, score))
    for rec in device.mdns:
        blob = " ".join(str(v) for v in rec.values()).lower()
        for needle, label, kind, score in [("_googlecast", "Google Chromecast", "streaming_device", 55), ("_airplay", "AirPlay device", "media_device", 30), ("_ipp", "Network printer", "printer", 35), ("_workstation", "Workstation", "computer", 20)]:
            if needle in blob:
                scores[(label, kind)] += score; device.evidence.append(Evidence("mdns", needle, label, score))
    if scores:
        (label, kind), raw = max(scores.items(), key=lambda kv: kv[1])
        if not device.model: device.model = label
        if not device.device_type: device.device_type = kind
        device.confidence = min(99, int(100 * (1 - (0.985 ** raw))))
    else:
        device.confidence = 10 if device.mac or device.hostname else 1
        device.device_type = device.device_type or "unknown"
    return device
