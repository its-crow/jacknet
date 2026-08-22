from __future__ import annotations
import socket
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from .models import Device

MSEARCH = "\r\n".join([
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    'MAN: "ssdp:discover"',
    "MX: 2",
    "ST: ssdp:all",
    "", ""
]).encode()


def _headers(data: bytes) -> dict[str, str]:
    out = {}
    for line in data.decode(errors="replace").split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def _xml_metadata(url: str) -> dict[str, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "jacknet/0.1"})
        with urllib.request.urlopen(req, timeout=2) as r:
            body = r.read(512_000)
        root = ET.fromstring(body)
        def text(tag: str):
            e = root.find(f".//{{*}}{tag}")
            return e.text.strip() if e is not None and e.text else None
        return {k: v for k, v in {
            "friendly_name": text("friendlyName"), "manufacturer": text("manufacturer"),
            "manufacturer_url": text("manufacturerURL"), "model": text("modelName"),
            "model_number": text("modelNumber"), "model_description": text("modelDescription"),
            "serial_number": text("serialNumber"), "device_type": text("deviceType"),
            "udn": text("UDN"),
        }.items() if v}
    except Exception:
        return {}


def discover(devices: list[Device], timeout: float = 2.5) -> None:
    by_ip = {d.ip: d for d in devices}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    s.sendto(MSEARCH, ("239.255.255.250", 1900))
    seen = set()
    while True:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            break
        ip = addr[0]
        h = _headers(data)
        key = (ip, h.get("usn"), h.get("location"), h.get("st"))
        if key in seen:
            continue
        seen.add(key)
        rec = dict(h)
        if h.get("location"):
            rec.update(_xml_metadata(h["location"]))
        d = by_ip.get(ip)
        if d:
            d.ssdp.append(rec)
            d.manufacturer = d.manufacturer or rec.get("manufacturer")
            d.model = d.model or rec.get("model")
            d.device_type = d.device_type or rec.get("device_type")
