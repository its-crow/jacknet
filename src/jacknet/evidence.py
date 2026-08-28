from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db import connect


def _flatten(value: Any, prefix: str = "") -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            for name, vals in _flatten(child, child_prefix).items():
                out.setdefault(name, []).extend(vals)
    elif isinstance(value, list):
        for child in value:
            for name, vals in _flatten(child, prefix).items():
                out.setdefault(name, []).extend(vals)
    elif value is not None:
        out.setdefault(prefix, []).append(str(value))
    return out


def _values(flat: dict[str, list[str]], *needles: str) -> list[str]:
    found: list[str] = []
    wanted = tuple(n.lower().replace(".", "_") for n in needles)
    for key, vals in flat.items():
        normalized = key.lower().replace(".", "_")
        if any(normalized == n or normalized.endswith("_" + n) for n in wanted):
            for val in vals:
                if val and val not in found:
                    found.append(val)
    return found


def _first(flat: dict[str, list[str]], *needles: str) -> str | None:
    vals = _values(flat, *needles)
    return vals[0] if vals else None


def _iso_epoch(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return value


def _device_for_packet(con, flat: dict[str, list[str]]) -> int | None:
    src_mac = _first(flat, "eth.src", "wlan.sa")
    dst_mac = _first(flat, "eth.dst", "wlan.da")
    for mac in (src_mac, dst_mac):
        if mac:
            row = con.execute(
                "SELECT device_id FROM devices WHERE lower(canonical_mac)=lower(?) LIMIT 1", (mac,)
            ).fetchone()
            if row:
                return int(row[0])
    for ip in (_first(flat, "ip.src", "ipv6.src"), _first(flat, "ip.dst", "ipv6.dst")):
        if ip:
            row = con.execute(
                "SELECT device_id FROM device_addresses WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,)
            ).fetchone()
            if row:
                return int(row[0])
    return None


def _artifact_pairs(flat: dict[str, list[str]], protocol_stack: str | None) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []

    mapping = {
        "domain": ("dns.qry.name", "dns.resp.name"),
        "tls_sni": ("tls.handshake.extensions_server_name",),
        "http_host": ("http.host",),
        "http_method": ("http.request.method",),
        "http_uri": ("http.request.uri", "http.request.full_uri"),
        "http_user_agent": ("http.user_agent",),
        "http_referer": ("http.referer",),
        "http_content_type": ("http.content_type",),
        "hostname": ("dhcp.option.hostname", "bootp.option.hostname", "nbns.name"),
        "ssdp_server": ("ssdp.server",),
        "ssdp_usn": ("ssdp.usn",),
        "tls_version": ("tls.record.version", "tls.handshake.version"),
        "tls_alpn": ("tls.handshake.extensions_alpn_str",),
        "tls_cert_subject": ("x509sat.printableString", "x509sat.uTF8String"),
        "server_name": ("smb2.server_name", "smb.server",),
        "service": ("dns.srv.service", "dns.ptr.domain_name"),
    }
    for artifact_type, fields in mapping.items():
        for value in _values(flat, *fields):
            pairs.append((artifact_type, value))

    if protocol_stack:
        for proto in protocol_stack.split(":"):
            proto = proto.strip()
            if proto:
                pairs.append(("protocol", proto))

    if protocol_stack and "mdns" in protocol_stack.lower():
        for value in _values(flat, "dns.qry.name", "dns.resp.name"):
            pairs.append(("mdns_name", value))

    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            result.append(pair)
    return result


def _touch_relationship(
    con,
    device_id: int | None,
    relation: str,
    source_type: str,
    source_value: str,
    target_type: str,
    target_value: str,
    when: str,
    protocol: str | None,
) -> None:
    row = con.execute(
        """SELECT id,hits FROM network_relationships
        WHERE device_id IS ? AND relation=? AND source_type=? AND source_value=? AND target_type=? AND target_value=?""",
        (device_id, relation, source_type, source_value, target_type, target_value),
    ).fetchone()
    if row:
        con.execute(
            "UPDATE network_relationships SET last_seen=?,hits=?,protocol=COALESCE(?,protocol) WHERE id=?",
            (when, int(row[1]) + 1, protocol, row[0]),
        )
    else:
        con.execute(
            """INSERT INTO network_relationships
            (device_id,relation,source_type,source_value,target_type,target_value,first_seen,last_seen,hits,protocol,metadata)
            VALUES(?,?,?,?,?,?,?,?,1,?,NULL)""",
            (device_id, relation, source_type, source_value, target_type, target_value, when, when, protocol),
        )


def ingest_full_decode(path: Path, session_id: int, tshark: str) -> dict[str, int | str]:
    """Store TShark's complete JSON decode and normalized graph-ready evidence."""
    cmd = [tshark, "-n", "-r", str(path), "-T", "ek"]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None

    decoded = 0
    artifacts = 0
    relationships = 0
    packet_number = 0

    with connect() as con:
        for raw in proc.stdout:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if "layers" not in obj:
                continue

            packet_number += 1
            flat = _flatten(obj.get("layers", {}))
            observed_at = _iso_epoch(_first(flat, "frame.time_epoch"))
            protocol_stack = _first(flat, "frame.protocols")
            device_id = _device_for_packet(con, flat)

            con.execute(
                """INSERT OR REPLACE INTO packet_decodes
                (session_id,packet_number,observed_at,protocol_stack,raw_json)
                VALUES(?,?,?,?,?)""",
                (session_id, packet_number, observed_at, protocol_stack, json.dumps(obj, separators=(",", ":"))),
            )
            decoded += 1

            when = observed_at or datetime.now(timezone.utc).isoformat()
            proto = protocol_stack.split(":")[-1] if protocol_stack else None
            pairs = _artifact_pairs(flat, protocol_stack)
            for artifact_type, artifact_value in pairs:
                con.execute(
                    """INSERT INTO network_artifacts
                    (session_id,device_id,observed_at,artifact_type,artifact_value,source,protocol,metadata)
                    VALUES(?,?,?,?,?,'tshark-decode',?,NULL)""",
                    (session_id, device_id, when, artifact_type, artifact_value, proto),
                )
                artifacts += 1

                if device_id is not None and artifact_type in {"domain", "tls_sni", "http_host", "mdns_name", "service", "protocol"}:
                    relation = "uses" if artifact_type in {"service", "protocol"} else "contacts"
                    _touch_relationship(
                        con,
                        device_id,
                        relation,
                        "device",
                        str(device_id),
                        artifact_type,
                        artifact_value,
                        when,
                        proto,
                    )
                    relationships += 1

            dst_ip = _first(flat, "ip.dst", "ipv6.dst")
            if device_id is not None and dst_ip:
                _touch_relationship(
                    con,
                    device_id,
                    "connects_to",
                    "device",
                    str(device_id),
                    "ip",
                    dst_ip,
                    when,
                    proto,
                )
                relationships += 1

    stderr = proc.stderr.read() if proc.stderr else ""
    rc = proc.wait()
    if rc:
        raise RuntimeError(stderr.strip() or f"TShark full decode exited with status {rc}")

    return {"decoded_packets": decoded, "artifacts": artifacts, "relationships": relationships}
