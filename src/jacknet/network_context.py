from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

import psutil

from .db import connect


@dataclass(frozen=True)
class NetworkContext:
    key: str
    name: str
    cidr: str | None
    gateway_ip: str | None
    gateway_mac: str | None
    ssid: str | None
    interface: str | None
    interface_description: str | None


def _run(cmd: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)
        return p.returncode, p.stdout
    except Exception:
        return 999, ""


def _windows_ipconfig() -> dict:
    script = (
        "Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up'} | "
        "Select-Object -First 1 InterfaceAlias,InterfaceDescription,InterfaceIndex,"
        "@{n='IPv4';e={$_.IPv4Address.IPAddress}},@{n='PrefixLength';e={$_.IPv4Address.PrefixLength}},"
        "@{n='Gateway';e={$_.IPv4DefaultGateway.NextHop}} | ConvertTo-Json -Compress"
    )
    rc, out = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
    if rc or not out.strip(): return {}
    try: return json.loads(out)
    except json.JSONDecodeError: return {}


def _windows_wifi(interface: str | None) -> tuple[str | None, str | None]:
    rc, out = _run(["netsh", "wlan", "show", "interfaces"])
    if rc or not out: return None, None
    blocks = re.split(r"\r?\n\s*\r?\n", out)
    for block in blocks:
        name = re.search(r"^\s*Name\s*:\s*(.+)$", block, re.I | re.M)
        if interface and name and name.group(1).strip().lower() != interface.lower(): continue
        ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", block, re.I | re.M)
        bssid = re.search(r"^\s*BSSID\s*:\s*([0-9a-f:-]+)$", block, re.I | re.M)
        if ssid: return ssid.group(1).strip(), bssid.group(1).strip().lower() if bssid else None
    return None, None


def _gateway_mac(gateway_ip: str | None) -> str | None:
    if not gateway_ip: return None
    _run(["ping", "-n", "1", "-w", "250", gateway_ip], timeout=2)
    rc, out = _run(["arp", "-a", gateway_ip])
    if rc: return None
    m = re.search(rf"{re.escape(gateway_ip)}\s+([0-9a-f-]{{17}})", out, re.I)
    return m.group(1).replace("-", ":").lower() if m else None


def detect_network() -> NetworkContext:
    interface = desc = ipv4 = gateway = cidr = ssid = None
    gateway_mac = None
    if os.name == "nt":
        info = _windows_ipconfig()
        interface = info.get("InterfaceAlias"); desc = info.get("InterfaceDescription"); ipv4 = info.get("IPv4"); gateway = info.get("Gateway")
        try:
            if ipv4 and info.get("PrefixLength") is not None: cidr = str(ipaddress.ip_network(f"{ipv4}/{int(info['PrefixLength'])}", strict=False))
        except Exception: pass
        ssid, _ = _windows_wifi(interface)
        gateway_mac = _gateway_mac(gateway)
    if not cidr:
        for name, addrs in psutil.net_if_addrs().items():
            ipv4_addr = next((a for a in addrs if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254."))), None)
            if ipv4_addr and ipv4_addr.netmask:
                interface = interface or name
                try: cidr = str(ipaddress.ip_network(f"{ipv4_addr.address}/{ipv4_addr.netmask}", strict=False))
                except ValueError: pass
                break
    identity = "|".join([gateway_mac or "", gateway or "", cidr or "", ssid or ""]).lower()
    if not identity.strip("|"): identity = f"unknown|{interface or 'network'}"
    key = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    name = ssid or cidr or gateway or interface or f"network-{key[:8]}"
    return NetworkContext(key, name, cidr, gateway, gateway_mac, ssid, interface, desc)


def ensure_network(context: NetworkContext | None = None) -> tuple[int, NetworkContext]:
    ctx = context or detect_network(); now = datetime.now(timezone.utc).isoformat()
    with connect() as con:
        row = con.execute("SELECT network_id FROM networks WHERE network_key=?", (ctx.key,)).fetchone()
        if row:
            network_id = int(row[0])
            con.execute("""UPDATE networks SET last_seen=?,name=?,cidr=?,gateway_ip=?,gateway_mac=?,ssid=?,interface=?,interface_description=? WHERE network_id=?""",
                (now, ctx.name, ctx.cidr, ctx.gateway_ip, ctx.gateway_mac, ctx.ssid, ctx.interface, ctx.interface_description, network_id))
        else:
            cur = con.execute("""INSERT INTO networks(network_key,name,cidr,gateway_ip,gateway_mac,ssid,interface,interface_description,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (ctx.key, ctx.name, ctx.cidr, ctx.gateway_ip, ctx.gateway_mac, ctx.ssid, ctx.interface, ctx.interface_description, now, now))
            network_id = int(cur.lastrowid)
    return network_id, ctx


def get_network(network_id: int) -> NetworkContext | None:
    with connect() as con:
        row = con.execute("SELECT network_key,name,cidr,gateway_ip,gateway_mac,ssid,interface,interface_description FROM networks WHERE network_id=?", (network_id,)).fetchone()
    if not row: return None
    return NetworkContext(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7])
