from __future__ import annotations
import socket
import time
from .models import Device

COMMON_TYPES = [
    "_workstation._tcp.local.", "_http._tcp.local.", "_https._tcp.local.",
    "_ssh._tcp.local.", "_smb._tcp.local.", "_airplay._tcp.local.",
    "_raop._tcp.local.", "_googlecast._tcp.local.", "_ipp._tcp.local.",
    "_ipps._tcp.local.", "_printer._tcp.local.", "_device-info._tcp.local.",
]

def discover(devices: list[Device], timeout: float = 2.5) -> None:
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except Exception:
        return
    by_ip = {d.ip: d for d in devices}
    zc = Zeroconf()

    class Listener(ServiceListener):
        def add_service(self, z, type_, name):
            try:
                info = z.get_service_info(type_, name, timeout=800)
                if not info:
                    return
                props = {}
                for k, v in (info.properties or {}).items():
                    try:
                        kk = k.decode(errors="replace") if isinstance(k, bytes) else str(k)
                        vv = v.decode(errors="replace") if isinstance(v, bytes) else str(v)
                        props[kk] = vv
                    except Exception:
                        pass
                for raw in info.addresses:
                    if len(raw) != 4:
                        continue
                    ip = socket.inet_ntoa(raw)
                    d = by_ip.get(ip)
                    if d:
                        rec = {"service": type_, "name": name, "server": info.server or "", "port": info.port, "properties": props}
                        if rec not in d.mdns:
                            d.mdns.append(rec)
                        if not d.hostname and info.server:
                            d.hostname = info.server.rstrip(".")
            except Exception:
                pass
        def update_service(self, z, type_, name):
            self.add_service(z, type_, name)
        def remove_service(self, z, type_, name):
            pass

    listener = Listener()
    browsers = [ServiceBrowser(zc, t, listener) for t in COMMON_TYPES]
    try:
        time.sleep(timeout)
    finally:
        zc.close()
