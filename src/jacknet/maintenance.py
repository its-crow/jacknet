from __future__ import annotations

from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel

from .capture import ingest_capture
from .db import connect, migrate

console=Console()


def evidence_rebuild_cmd(yes: bool = typer.Option(False,"--yes",help="Confirm rebuilding passive evidence from retained capture files")):
    """Discard derived passive state and reconstruct it from retained PCAP/PCAPNG files."""
    migrate()
    with connect() as con:
        files=[]
        for capture_file,source,interface in con.execute("SELECT capture_file,source,interface FROM capture_sessions WHERE capture_file IS NOT NULL ORDER BY id"):
            p=Path(capture_file)
            key=str(p.resolve()) if p.exists() else str(p)
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
        # Remove devices invented only by passive capture. Never remove anything backed by an active observation or user label.
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
