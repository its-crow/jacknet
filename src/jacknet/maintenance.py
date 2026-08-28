from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel

from .capture import ingest_capture
from .db import connect, migrate

console=Console()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def evidence_rebuild_cmd(yes: bool = typer.Option(False,"--yes",help="Confirm rebuilding passive evidence from retained capture files")):
    """Discard derived passive state and reconstruct it from retained PCAP/PCAPNG files."""
    migrate()
    with connect() as con:
        files=[]
        for capture_file,source,interface in con.execute("SELECT capture_file,source,interface FROM capture_sessions WHERE capture_file IS NOT NULL ORDER BY id"):
            p=Path(capture_file); key=str(p.resolve()) if p.exists() else str(p)
            if p.exists() and key not in {x[0] for x in files}:files.append((key,source,interface))
    if not files:
        console.print(Panel("No retained capture files were found. Nothing was changed.",title="JACKNET / EVIDENCE REBUILD",style="yellow"));return
    console.print(Panel(f"Found {len(files)} retained capture file(s).\n\nThis will delete DERIVED passive evidence, relationships, traffic rows, passive addresses, and passive-only pseudo-devices, then decode the captures again. Active scan observations, confirmations, labels, corrections, and fingerprints are preserved.",title="JACKNET / EVIDENCE REBUILD"))
    if not yes and not typer.confirm("Rebuild passive evidence now?"):raise typer.Abort()
    with connect() as con:
        con.execute("DELETE FROM packet_decodes");con.execute("DELETE FROM network_artifacts");con.execute("DELETE FROM network_relationships");con.execute("DELETE FROM traffic_observations");con.execute("DELETE FROM device_endpoints")
        con.execute("DELETE FROM device_features WHERE source IN ('live','pcap','tshark-decode')")
        con.execute("DELETE FROM device_addresses WHERE source IN ('live','pcap')")
        con.execute("DELETE FROM capture_sessions")
        con.execute("""DELETE FROM devices WHERE device_id NOT IN (SELECT DISTINCT device_id FROM observations WHERE device_id IS NOT NULL) AND device_id NOT IN (SELECT DISTINCT device_id FROM labels) AND device_id NOT IN (SELECT DISTINCT device_id FROM device_addresses)""")
    total_packets=total_artifacts=0;failures=[]
    for i,(path,source,interface) in enumerate(files,1):
        console.print(f"[dim]Re-decoding {i}/{len(files)}: {path}[/]")
        try:
            stats=ingest_capture(Path(path),source=source or "pcap",interface=interface);total_packets+=int(stats.get("packets",0));total_artifacts+=int(stats.get("artifacts",0))
        except Exception as exc:failures.append(f"{path}: {exc}")
    body=f"Captures rebuilt: {len(files)-len(failures)}/{len(files)}\nPackets reprocessed: {total_packets:,}\nArtifacts rebuilt: {total_artifacts:,}"
    if failures:body+="\nFailures:\n"+"\n".join(failures[:10])
    console.print(Panel(body,title="JACKNET / EVIDENCE REBUILD COMPLETE",style="green" if not failures else "yellow"))


def reconcile_cmd(
    ip: str = typer.Argument(..., help="Trusted current IP address"),
    mac: str = typer.Option(..., "--mac", help="Trusted device MAC address"),
    identity: str | None = typer.Option(None, "--identity", "--as", help="Trusted identity/model"),
    manufacturer: str | None = typer.Option(None, "--manufacturer", "--man"),
    device_type: str | None = typer.Option(None, "--type"),
    yes: bool = typer.Option(False, "-y", "--yes"),
):
    """Apply trusted ground truth from a router/admin source and repair current IP/MAC ownership."""
    migrate(); mac=mac.lower(); now=_now()
    console.print(Panel(f"Trusted mapping\nIP: {ip}\nMAC: {mac}\nIdentity: {identity or '—'}\nManufacturer: {manufacturer or '—'}\nType: {device_type or '—'}\n\nJackNet will make this MAC authoritative for the current IP. Conflicting current address links are removed, while historical observations remain preserved.",title="JACKNET / RECONCILE"))
    if not yes and not typer.confirm("Apply this trusted mapping?"):raise typer.Abort()
    with connect() as con:
        row=con.execute("SELECT device_id FROM devices WHERE lower(canonical_mac)=? LIMIT 1",(mac,)).fetchone()
        if row: did=int(row[0])
        else:
            cur=con.execute("INSERT INTO devices(canonical_mac,first_seen,last_seen,manufacturer,model,device_type,confidence) VALUES(?,?,?,?,?,?,?)",(mac,now,now,manufacturer,identity,device_type,100));did=int(cur.lastrowid)
        # Trusted current ownership supersedes stale current mappings, but observations retain historical truth.
        con.execute("DELETE FROM device_addresses WHERE ip=? AND device_id<>?",(ip,did))
        addr=con.execute("SELECT id,observation_count FROM device_addresses WHERE device_id=? AND ip=?",(did,ip)).fetchone()
        if addr:con.execute("UPDATE device_addresses SET last_seen=?,observation_count=?,source='trusted' WHERE id=?",(now,int(addr[1])+1,addr[0]))
        else:con.execute("INSERT INTO device_addresses(device_id,ip,first_seen,last_seen,observation_count,source) VALUES(?,?,?,?,1,'trusted')",(did,ip,now,now))
        if any((identity,manufacturer,device_type)):
            con.execute("UPDATE devices SET last_seen=?,user_label=COALESCE(?,user_label),manufacturer=COALESCE(?,manufacturer),model=COALESCE(?,model),device_type=COALESCE(?,device_type),confidence=MAX(confidence,100) WHERE device_id=?",(now,identity,manufacturer,identity,device_type,did))
            con.execute("INSERT INTO labels(device_id,created_at,manufacturer,model,device_type,source) VALUES(?,?,?,?,?,'trusted_reconcile')",(did,now,manufacturer,identity,device_type))
        else:con.execute("UPDATE devices SET last_seen=? WHERE device_id=?",(now,did))
    console.print(Panel(f"Device {did} reconciled.\nCurrent IP: {ip}\nMAC: {mac}\nConfidence: 100% trusted ground truth",title="JACKNET / RECONCILE COMPLETE",style="green"))
