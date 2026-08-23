from __future__ import annotations
import ipaddress
import socket
import subprocess
import shutil
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Iterable
import psutil
from .models import Device
from .mac import annotate_mac_facts


def default_network() -> str:
    """Return the IPv4 network for the interface used by the default route.

    Prefer Scapy's route table so VPN/Hyper-V/Docker adapters are less likely to
    be selected accidentally. Fall back to a sane non-loopback interface.
    """
    try:
        from scapy.all import conf
        iface, src_ip, _ = conf.route.route("1.1.1.1")
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == src_ip and a.netmask:
                    return str(ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False))
    except Exception:
        pass
    for _, addrs in psutil.net_if_addrs().items():
        ipv4 = next((a for a in addrs if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254."))), None)
        if ipv4 and ipv4.netmask:
            return str(ipaddress.ip_network(f"{ipv4.address}/{ipv4.netmask}", strict=False))
    raise RuntimeError("Could not determine an active IPv4 network")


def arp_scan(network: str, timeout: float = 1.5) -> list[Device]:
    try:
        from scapy.all import ARP, Ether, srp
    except Exception as exc:
        raise RuntimeError(f"Scapy unavailable: {exc}") from exc
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=timeout, verbose=False)
    now = datetime.now(timezone.utc).isoformat()
    devices = [Device(ip=r.psrc, mac=r.hwsrc.lower(), first_seen=now, last_seen=now) for _, r in ans]
    annotate_mac_facts(devices)
    devices.sort(key=lambda d: ipaddress.ip_address(d.ip))
    return devices


def ptr_name(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, TimeoutError):
        return None


def enrich_ptr(devices: list[Device], workers: int = 32, stage_timeout: float = 3.0) -> None:
    """Resolve PTR names without allowing a broken resolver to stall JackNet.

    Windows resolver calls can block well beyond Python socket timeouts. We
    therefore bound the *whole stage* and deliberately do not wait for stuck
    worker threads during executor shutdown.
    """
    if not devices:
        return
    ex = ThreadPoolExecutor(max_workers=min(workers, max(1, len(devices))))
    futs = {ex.submit(ptr_name, d.ip): d for d in devices}
    done, pending = wait(futs, timeout=stage_timeout)
    for f in done:
        try:
            futs[f].hostname = f.result()
        except Exception:
            pass
    for f in pending:
        f.cancel()
    ex.shutdown(wait=False, cancel_futures=True)


def enrich_vendor(devices: list[Device]) -> None:
    try:
        from mac_vendor_lookup import MacLookup
        lookup = MacLookup()
    except Exception:
        return
    for d in devices:
        if not d.mac:
            continue
        try:
            d.manufacturer = lookup.lookup(d.mac)
        except Exception:
            pass


def nmap_enrich(devices: Iterable[Device], aggressive: bool = False, timeout: float = 90.0) -> None:
    """Enrich all targets in a single bounded Nmap process.

    One batch process is much faster than serially launching Nmap once per host,
    and the hard timeout prevents the CLI from appearing hung indefinitely.
    """
    nmap_path = shutil.which("nmap")
    device_list = list(devices)
    if not nmap_path or not device_list:
        return
    by_ip = {d.ip: d for d in device_list}
    args = [nmap_path, "-Pn", "-sV", "--version-light", "--host-timeout", "20s", "-oX", "-"]
    if aggressive:
        args.insert(2, "-O")
    args.extend(by_ip.keys())
    try:
        cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        root = ET.fromstring(cp.stdout)
    except Exception:
        return
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        d = by_ip.get(addr.attrib.get("addr", ""))
        if d is None:
            continue
        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                state = p.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                svc = p.find("service")
                rec = {"port": int(p.attrib["portid"]), "protocol": p.attrib.get("protocol", "tcp")}
                if svc is not None:
                    rec.update({k: v for k, v in svc.attrib.items() if k in {"name", "product", "version", "extrainfo", "ostype", "devicetype", "hostname"}})
                    d.hostname = d.hostname or svc.attrib.get("hostname")
                d.open_ports.append(rec)
        osnode = host.find("os")
        if osnode is not None:
            for m in osnode.findall("osmatch"):
                rec = {"name": m.attrib.get("name"), "accuracy": int(m.attrib.get("accuracy", "0"))}
                d.os_guesses.append(rec)
            if d.os_guesses:
                best = max(d.os_guesses, key=lambda x: x["accuracy"])
                d.os = best["name"]
