from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel

from .capture import ingest_capture
from .config import paths
from .db import connect, migrate
from .network_context import ensure_network, get_network

console=Console()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _retained_capture_files() -> list[tuple[str, str | None, str | None, int | None]]:
    """Return registered captures plus orphan PCAPs still present in JackNet's cache.

    A capture process can successfully write a PCAP before database ingestion fails.
    Those files are valuable evidence and must remain recoverable.
    """
    files: list[tuple[str, str | None, str | None, int | None]] = []
    seen: set[str] = set()
    with connect() as con:
        for capture_file, source, interface, network_id in con.execute(
            "SELECT capture_file,source,interface,network_id FROM capture_sessions WHERE capture_file IS NOT NULL ORDER BY id"
        ):
            p = Path(capture_file)
            if not p.exists():
                continue
            key = str(p.resolve())
            if key not in seen:
                files.append((key, source, interface, network_id))
                seen.add(key)

    cache = paths()["cache"]
    if cache.exists():
        for pattern in ("*.pcapng", "*.pcap"):
            for p in sorted(cache.glob(pattern)):
                key = str(p.resolve())
                if key not in seen:
                    # No database session survived for this file, so its historical
                    # network is unknown. Rebuild will explicitly use current context.
                    files.append((key, "recovered", None, None))
                    seen.add(key)
    return files


def evidence_rebuild_cmd(yes: bool = typer.Option(False,"--yes",help="Confirm rebuilding passive evidence from retained capture files")):
    """Discard derived passive state and reconstruct it from retained PCAP/PCAPNG files."""
    migrate()
    files = _retained_capture_files()
    if not files:
        console.print(Panel("No retained capture files were found. Nothing was changed.",title="JACKNET / EVIDENCE REBUILD",style="yellow"));return
    console.print(Panel(f"Found {len(files)} retained capture file(s).\n\nThis will delete DERIVED passive evidence, relationships, traffic rows, and passive network-scoped addresses, then decode the captures again. Active scan observations, device records, confirmations, labels, corrections, fingerprints, and network identities are preserved.\n\nOrphan capture files that exist on disk without a surviving database session are recovered automatically.",title="JACKNET / EVIDENCE REBUILD"))
    if not yes and not typer.confirm("Rebuild passive evidence now?"):raise typer.Abort()

    # Do not delete devices here. A device can be referenced by several historical
    # tables that intentionally outlive passive evidence. Device cleanup belongs in
    # a separate, reference-aware maintenance operation.
    with connect() as con:
        con.execute("DELETE FROM packet_decodes")
        con.execute("DELETE FROM network_artifacts")
        con.execute("DELETE FROM network_relationships")
        con.execute("DELETE FROM traffic_observations")
        con.execute("DELETE FROM device_endpoints")
        con.execute("DELETE FROM device_features WHERE source IN ('live','pcap','recovered','tshark-decode')")
        con.execute("DELETE FROM device_network_addresses WHERE source IN ('live','pcap','recovered')")
        con.execute("DELETE FROM capture_sessions")

    total_packets=total_artifacts=0;failures=[]
    for i,(path,source,interface,network_id) in enumerate(files,1):
        stored_network = get_network(int(network_id)) if network_id is not None else None
        label = stored_network.name if stored_network else "current network (legacy/orphan capture)"
        console.print(f"[dim]Re-decoding {i}/{len(files)} [{label}]: {path}[/]")
        try:
            stats=ingest_capture(
                Path(path),
                source=source or "pcap",
                interface=interface,
                network_id_override=int(network_id) if network_id is not None else None,
            )
            total_packets+=int(stats.get("packets",0));total_artifacts+=int(stats.get("artifacts",0))
        except Exception as exc:failures.append(f"{path}: {exc}")
    body=f"Captures rebuilt: {len(files)-len(failures)}/{len(files)}\nPackets reprocessed: {total_packets:,}\nArtifacts rebuilt: {total_artifacts:,}"
    if failures:body+="\nFailures:\n"+"\n".join(failures[:10])
    console.print(Panel(body,title="JACKNET / EVIDENCE REBUILD COMPLETE",style="green" if not failures else "yellow"))


def reconcile_cmd(
    ip: str = typer.Argument(..., help="Trusted current IP address on the selected/current network"),
    mac: str = typer.Option(..., "--mac", help="Trusted device MAC address"),
    identity: str | None = typer.Option(None, "--identity", "--as", help="Trusted identity/model"),
    manufacturer: str | None = typer.Option(None, "--manufacturer", "--man"),
    device_type: str | None = typer.Option(None, "--type"),
    network_id: int | None = typer.Option(None,"--network-id",help="Stored network ID; default is the currently connected network"),
    yes: bool = typer.Option(False, "-y", "--yes"),
):
    """Apply trusted ground truth without treating an IP as globally unique."""
    migrate(); mac=mac.lower(); now=_now()
    if network_id is None:
        network_id,network=ensure_network()
    else:
        network=get_network(network_id)
        if network is None:raise typer.BadParameter(f"Unknown network ID {network_id}")
    console.print(Panel(f"Trusted mapping\nNetwork: {network.name} (id {network_id})\nNetwork key: {network.key}\nCIDR: {network.cidr or '—'}\nSSID: {network.ssid or '—'}\nIP: {ip}\nMAC: {mac}\nIdentity: {identity or '—'}\nManufacturer: {manufacturer or '—'}\nType: {device_type or '—'}\n\nThe IP is only authoritative inside this network scope. Device identity remains keyed by durable device_id/MAC evidence, not by IP address.",title="JACKNET / RECONCILE"))
    if not yes and not typer.confirm("Apply this trusted network-scoped mapping?"):raise typer.Abort()
    with connect() as con:
        row=con.execute("SELECT device_id FROM devices WHERE lower(canonical_mac)=? LIMIT 1",(mac,)).fetchone()
        if row:did=int(row[0])
        else:
            cur=con.execute("INSERT INTO devices(canonical_mac,first_seen,last_seen,manufacturer,model,device_type,confidence) VALUES(?,?,?,?,?,?,?)",(mac,now,now,manufacturer,identity,device_type,100));did=int(cur.lastrowid)
        # Only remove conflicting ownership for this same network. The same IP can legitimately exist on another network.
        con.execute("DELETE FROM device_network_addresses WHERE network_id=? AND ip=? AND device_id<>?",(network_id,ip,did))
        addr=con.execute("SELECT id,observation_count FROM device_network_addresses WHERE network_id=? AND device_id=? AND ip=?",(network_id,did,ip)).fetchone()
        if addr:con.execute("UPDATE device_network_addresses SET last_seen=?,observation_count=?,source='trusted' WHERE id=?",(now,int(addr[1])+1,addr[0]))
        else:con.execute("INSERT INTO device_network_addresses(network_id,device_id,ip,first_seen,last_seen,observation_count,source) VALUES(?,?,?,?,?,1,'trusted')",(network_id,did,ip,now,now))
        if any((identity,manufacturer,device_type)):
            con.execute("UPDATE devices SET last_seen=?,user_label=COALESCE(?,user_label),manufacturer=COALESCE(?,manufacturer),model=COALESCE(?,model),device_type=COALESCE(?,device_type),confidence=MAX(confidence,100) WHERE device_id=?",(now,identity,manufacturer,identity,device_type,did))
            con.execute("INSERT INTO labels(device_id,created_at,manufacturer,model,device_type,source) VALUES(?,?,?,?,?,'trusted_reconcile')",(did,now,manufacturer,identity,device_type))
        else:con.execute("UPDATE devices SET last_seen=? WHERE device_id=?",(now,did))
    console.print(Panel(f"Device {did} reconciled.\nNetwork: {network.name} (id {network_id})\nIP: {ip}\nMAC: {mac}\nConfidence: 100% trusted ground truth",title="JACKNET / RECONCILE COMPLETE",style="green"))
