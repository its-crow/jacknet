from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from .db import connect, migrate
from .evidence import ingest_full_decode


TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "dns.qry.name",
    "dns.resp.name",
    "tls.handshake.extensions_server_name",
    "http.host",
    "dhcp.option.hostname",
    "bootp.option.hostname",
    "ssdp.server",
    "ssdp.usn",
    "wlan.sa",
    "wlan.da",
    "radiotap.dbm_antsignal",
]


@dataclass
class TrafficRecord:
    observed_at: str
    length: int = 0
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    dns_name: str | None = None
    tls_sni: str | None = None
    http_host: str | None = None
    hostname: str | None = None
    mdns_name: str | None = None
    ssdp_server: str | None = None
    ssdp_usn: str | None = None
    signal_dbm: int | None = None
    metadata: dict = field(default_factory=dict)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _find_wireshark_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        exe = name if name.lower().endswith(".exe") else f"{name}.exe"
        roots = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark",
        ]
        for root in roots:
            candidate = root / exe
            if candidate.is_file():
                return str(candidate)
    return None


def tshark_path() -> str | None:
    return _find_wireshark_tool("tshark")


def dumpcap_path() -> str | None:
    return _find_wireshark_tool("dumpcap")


def capture_ready() -> tuple[bool, str]:
    tshark = tshark_path()
    if not tshark:
        return False, "TShark was not found. Install Wireshark with TShark enabled."
    return True, tshark


def list_interfaces() -> list[tuple[str, str]]:
    exe = tshark_path()
    if not exe:
        return []
    proc = subprocess.run([exe, "-D"], capture_output=True, text=True, check=False, timeout=10)
    rows: list[tuple[str, str]] = []
    for raw in proc.stdout.splitlines():
        raw = raw.strip()
        if not raw or "." not in raw:
            continue
        num, desc = raw.split(".", 1)
        rows.append((num.strip(), desc.strip()))
    return rows


@lru_cache(maxsize=1)
def supported_tshark_fields() -> frozenset[str]:
    """Return display-filter field names supported by this installed TShark."""
    exe = tshark_path()
    if not exe:
        return frozenset()
    try:
        proc = subprocess.run(
            [exe, "-G", "fields"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return frozenset()
    fields: set[str] = set()
    for line in proc.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) >= 3 and cols[0] == "F":
            fields.add(cols[2].strip())
    return frozenset(fields)


def active_tshark_fields() -> list[str]:
    supported = supported_tshark_fields()
    if not supported:
        return [
            "frame.time_epoch", "frame.len", "eth.src", "eth.dst",
            "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
            "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
            "_ws.col.Protocol",
        ]
    return [field for field in TSHARK_FIELDS if field in supported]


def _first(*values: str | None) -> str | None:
    for value in values:
        value = (value or "").strip()
        if value:
            return value.split(",")[0].strip()
    return None


def _to_int(value: str | None) -> int | None:
    try:
        return int(float(value)) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _iso_from_epoch(value: str | None) -> str:
    try:
        return datetime.fromtimestamp(float(value or ""), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return _now()


def iter_capture(path: Path) -> Iterable[TrafficRecord]:
    exe = tshark_path()
    if not exe:
        raise RuntimeError("TShark is required to analyze capture files.")
    if not path.exists():
        raise FileNotFoundError(path)

    fields = active_tshark_fields()
    if not fields:
        raise RuntimeError("TShark is installed, but Jacknet could not discover any usable fields.")

    cmd = [exe, "-n", "-r", str(path), "-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"]
    for field_name in fields:
        cmd.extend(["-e", field_name])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        cols = line.rstrip("\r\n").split("\t")
        if len(cols) < len(fields):
            cols.extend([""] * (len(fields) - len(cols)))
        vals = [c.strip('"') for c in cols[: len(fields)]]
        d = dict(zip(fields, vals))

        src_ip = _first(d.get("ip.src"), d.get("ipv6.src"))
        dst_ip = _first(d.get("ip.dst"), d.get("ipv6.dst"))
        src_mac = _first(d.get("eth.src"), d.get("wlan.sa"))
        dst_mac = _first(d.get("eth.dst"), d.get("wlan.da"))
        src_port = _to_int(_first(d.get("tcp.srcport"), d.get("udp.srcport")))
        dst_port = _to_int(_first(d.get("tcp.dstport"), d.get("udp.dstport")))
        hostname = _first(d.get("dhcp.option.hostname"), d.get("bootp.option.hostname"))
        protocol = _first(d.get("_ws.col.Protocol"))
        dns_query = _first(d.get("dns.qry.name"))
        dns_response = _first(d.get("dns.resp.name"))
        mdns_name = _first(dns_response, dns_query) if (protocol or "").lower() == "mdns" else None

        yield TrafficRecord(
            observed_at=_iso_from_epoch(d.get("frame.time_epoch")),
            length=_to_int(d.get("frame.len")) or 0,
            src_mac=src_mac.lower() if src_mac else None,
            dst_mac=dst_mac.lower() if dst_mac else None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            dns_name=dns_query or dns_response,
            tls_sni=_first(d.get("tls.handshake.extensions_server_name")),
            http_host=_first(d.get("http.host")),
            hostname=hostname,
            mdns_name=mdns_name,
            ssdp_server=_first(d.get("ssdp.server")),
            ssdp_usn=_first(d.get("ssdp.usn")),
            signal_dbm=_to_int(d.get("radiotap.dbm_antsignal")),
        )

    stderr = proc.stderr.read() if proc.stderr else ""
    rc = proc.wait()
    if rc:
        raise RuntimeError(stderr.strip() or f"TShark exited with status {rc}")


def _is_local_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_link_local
    except ValueError:
        return False


def _find_or_create_device(con, mac: str | None, ip: str | None, observed_at: str) -> int | None:
    row = None
    if mac:
        row = con.execute("SELECT device_id FROM devices WHERE canonical_mac=?", (mac,)).fetchone()
    if not row and ip:
        row = con.execute(
            "SELECT device_id FROM device_addresses WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
            (ip,),
        ).fetchone()
    if row:
        did = int(row[0])
        con.execute("UPDATE devices SET last_seen=? WHERE device_id=?", (observed_at, did))
        if mac:
            con.execute("UPDATE devices SET canonical_mac=COALESCE(canonical_mac,?) WHERE device_id=?", (mac, did))
        return did
    if not (mac or _is_local_ip(ip)):
        return None
    cur = con.execute(
        "INSERT INTO devices(canonical_mac,first_seen,last_seen,confidence) VALUES(?,?,?,0)",
        (mac, observed_at, observed_at),
    )
    return int(cur.lastrowid)


def _touch_address(con, device_id: int, ip: str, when: str, source: str) -> None:
    row = con.execute("SELECT id,observation_count FROM device_addresses WHERE device_id=? AND ip=?", (device_id, ip)).fetchone()
    if row:
        con.execute("UPDATE device_addresses SET last_seen=?,observation_count=?,source=? WHERE id=?", (when, int(row[1]) + 1, source, row[0]))
    else:
        con.execute("INSERT INTO device_addresses(device_id,ip,first_seen,last_seen,observation_count,source) VALUES(?,?,?,?,1,?)", (device_id, ip, when, when, source))


def _touch_endpoint(con, device_id: int, endpoint: str, when: str, protocol: str | None) -> None:
    row = con.execute("SELECT id,hits FROM device_endpoints WHERE device_id=? AND endpoint=?", (device_id, endpoint)).fetchone()
    if row:
        con.execute("UPDATE device_endpoints SET last_seen=?,hits=?,protocol=COALESCE(?,protocol) WHERE id=?", (when, int(row[1]) + 1, protocol, row[0]))
    else:
        con.execute("INSERT INTO device_endpoints(device_id,endpoint,first_seen,last_seen,hits,protocol) VALUES(?,?,?,?,1,?)", (device_id, endpoint, when, when, protocol))


def ingest_capture(path: Path, source: str = "pcap", interface: str | None = None) -> dict:
    migrate()
    path = path.expanduser().resolve()
    started = _now()
    packet_count = 0
    devices: set[int] = set()
    local_ips: set[str] = set()
    external_endpoints: set[str] = set()
    protocol_counts: dict[str, int] = defaultdict(int)
    dns_names: set[str] = set()

    with connect() as con:
        cur = con.execute("INSERT INTO capture_sessions(started_at,source,capture_file,interface,packet_count) VALUES(?,?,?,?,0)", (started, source, str(path), interface))
        session_id = int(cur.lastrowid)

        for rec in iter_capture(path):
            packet_count += 1
            if rec.protocol:
                protocol_counts[rec.protocol] += 1
            if rec.dns_name:
                dns_names.add(rec.dns_name)

            src_did = _find_or_create_device(con, rec.src_mac, rec.src_ip if _is_local_ip(rec.src_ip) else None, rec.observed_at)
            dst_did = _find_or_create_device(con, rec.dst_mac, rec.dst_ip if _is_local_ip(rec.dst_ip) else None, rec.observed_at)

            for did, ip in ((src_did, rec.src_ip), (dst_did, rec.dst_ip)):
                if did is not None:
                    devices.add(did)
                    if ip and _is_local_ip(ip):
                        local_ips.add(ip)
                        _touch_address(con, did, ip, rec.observed_at, source)

            if src_did is not None and rec.dst_ip and not _is_local_ip(rec.dst_ip):
                external_endpoints.add(rec.dst_ip)
                _touch_endpoint(con, src_did, rec.dst_ip, rec.observed_at, rec.protocol)
            if dst_did is not None and rec.src_ip and not _is_local_ip(rec.src_ip):
                external_endpoints.add(rec.src_ip)
                _touch_endpoint(con, dst_did, rec.src_ip, rec.observed_at, rec.protocol)

            owner = src_did or dst_did
            metadata = {
                "hostname": rec.hostname,
                "mdns_name": rec.mdns_name,
                "ssdp_server": rec.ssdp_server,
                "ssdp_usn": rec.ssdp_usn,
                "signal_dbm": rec.signal_dbm,
            }
            con.execute(
                """INSERT INTO traffic_observations
                (device_id,session_id,observed_at,source,capture_file,src_ip,dst_ip,src_mac,dst_mac,protocol,src_port,dst_port,dns_name,tls_sni,http_host,bytes,metadata)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (owner, session_id, rec.observed_at, source, str(path), rec.src_ip, rec.dst_ip, rec.src_mac, rec.dst_mac,
                 rec.protocol, rec.src_port, rec.dst_port, rec.dns_name, rec.tls_sni, rec.http_host, rec.length, json.dumps(metadata)),
            )

            if owner is not None:
                features = []
                if rec.hostname: features.append(("traffic_hostname", rec.hostname))
                if rec.dns_name: features.append(("dns", rec.dns_name))
                if rec.tls_sni: features.append(("tls_sni", rec.tls_sni))
                if rec.http_host: features.append(("http_host", rec.http_host))
                if rec.mdns_name: features.append(("mdns_name", rec.mdns_name))
                if rec.ssdp_server: features.append(("ssdp_server", rec.ssdp_server))
                if rec.dst_port: features.append(("observed_port", str(rec.dst_port)))
                for ft, val in features:
                    con.execute("INSERT INTO device_features(device_id,observed_at,feature_type,feature_value,source) VALUES(?,?,?,?,?)", (owner, rec.observed_at, ft, val, source))

        ended = _now()
        con.execute("UPDATE capture_sessions SET ended_at=?,packet_count=? WHERE id=?", (ended, packet_count, session_id))

    decode_stats: dict[str, int | str] = {"decoded_packets": 0, "artifacts": 0, "relationships": 0}
    exe = tshark_path()
    if exe and packet_count:
        try:
            decode_stats.update(ingest_full_decode(path, session_id, exe))
        except Exception as exc:
            decode_stats["decode_error"] = str(exc)

    return {
        "session_id": session_id,
        "capture": str(path),
        "packets": packet_count,
        "devices": len(devices),
        "local_ips": len(local_ips),
        "external_endpoints": len(external_endpoints),
        "dns_names": len(dns_names),
        "protocols": dict(sorted(protocol_counts.items(), key=lambda kv: kv[1], reverse=True)[:20]),
        **decode_stats,
    }


def live_capture(interface: str, output: Path, duration: int = 60, monitor: bool = False) -> Path:
    exe = dumpcap_path() or tshark_path()
    if not exe:
        raise RuntimeError("Neither dumpcap nor TShark is available.")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "-i", str(interface), "-a", f"duration:{max(1, duration)}", "-w", str(output)]
    if monitor:
        cmd.insert(1, "-I")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"capture exited with {proc.returncode}")
    return output
