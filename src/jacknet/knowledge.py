from __future__ import annotations

import json
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .db import connect, migrate

console = Console()


def _device_id_for_ip(ip: str) -> int | None:
    migrate()
    with connect() as con:
        row = con.execute(
            "SELECT device_id FROM device_addresses WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
            (ip,),
        ).fetchone()
        if row:
            return int(row[0])
        row = con.execute(
            "SELECT device_id FROM observations WHERE ip=? AND device_id IS NOT NULL ORDER BY id DESC LIMIT 1",
            (ip,),
        ).fetchone()
        return int(row[0]) if row else None


def evidence_cmd(
    ip: str = typer.Argument(..., help="IP address associated with a stored device"),
    limit: int = typer.Option(100, "-n", "--limit", min=1, max=1000),
    json_out: bool = typer.Option(False, "--json"),
):
    """Show normalized passive evidence accumulated for a device."""
    did = _device_id_for_ip(ip)
    if did is None:
        console.print(f"[yellow]No stored device found for {ip}.[/]")
        raise typer.Exit(1)
    with connect() as con:
        rows = con.execute(
            """SELECT artifact_type,artifact_value,COUNT(*) AS hits,
                      COUNT(DISTINCT session_id) AS sessions,
                      MIN(observed_at),MAX(observed_at),GROUP_CONCAT(DISTINCT protocol)
               FROM network_artifacts
               WHERE device_id=?
               GROUP BY artifact_type,artifact_value
               ORDER BY sessions DESC,hits DESC,MAX(observed_at) DESC
               LIMIT ?""",
            (did, limit),
        ).fetchall()
    data = [
        {"type": r[0], "value": r[1], "hits": r[2], "sessions": r[3], "first_seen": r[4], "last_seen": r[5], "protocols": r[6]}
        for r in rows
    ]
    if json_out:
        typer.echo(json.dumps(data, indent=2))
        return
    t = Table(title=f"JACKNET / EVIDENCE • {ip} • device {did}")
    for c in ("Type", "Value", "Hits", "Sessions", "Last seen", "Protocol"):
        t.add_column(c, overflow="fold")
    for r in data:
        t.add_row(r["type"], r["value"], str(r["hits"]), str(r["sessions"]), r["last_seen"] or "—", r["protocols"] or "—")
    console.print(t)


def sites_cmd(
    ip: str = typer.Argument(..., help="IP address associated with a stored device"),
    limit: int = typer.Option(50, "-n", "--limit", min=1, max=500),
    json_out: bool = typer.Option(False, "--json"),
):
    """Show domains/hosts observed for a device from DNS, TLS SNI, and HTTP."""
    did = _device_id_for_ip(ip)
    if did is None:
        console.print(f"[yellow]No stored device found for {ip}.[/]")
        raise typer.Exit(1)
    with connect() as con:
        rows = con.execute(
            """SELECT artifact_value,
                      GROUP_CONCAT(DISTINCT artifact_type),
                      COUNT(*) AS hits,
                      COUNT(DISTINCT session_id) AS sessions,
                      MIN(observed_at),MAX(observed_at)
               FROM network_artifacts
               WHERE device_id=? AND artifact_type IN ('domain','tls_sni','http_host')
               GROUP BY lower(artifact_value)
               ORDER BY sessions DESC,hits DESC,MAX(observed_at) DESC
               LIMIT ?""",
            (did, limit),
        ).fetchall()
    data = [
        {"site": r[0], "evidence": r[1], "hits": r[2], "sessions": r[3], "first_seen": r[4], "last_seen": r[5]}
        for r in rows
    ]
    if json_out:
        typer.echo(json.dumps(data, indent=2))
        return
    t = Table(title=f"JACKNET / OBSERVED SITES • {ip} • device {did}")
    for c in ("Site/domain", "Evidence", "Hits", "Sessions", "Last seen"):
        t.add_column(c, overflow="fold")
    for r in data:
        t.add_row(r["site"], r["evidence"] or "—", str(r["hits"]), str(r["sessions"]), r["last_seen"] or "—")
    console.print(t)


def graph_cmd(
    ip: str = typer.Argument(..., help="IP address associated with a stored device"),
    limit: int = typer.Option(100, "-n", "--limit", min=1, max=1000),
    json_out: bool = typer.Option(False, "--json"),
):
    """Show graph-ready relationships accumulated for a device."""
    did = _device_id_for_ip(ip)
    if did is None:
        console.print(f"[yellow]No stored device found for {ip}.[/]")
        raise typer.Exit(1)
    with connect() as con:
        rows = con.execute(
            """SELECT relation,target_type,target_value,hits,first_seen,last_seen,protocol
               FROM network_relationships WHERE device_id=?
               ORDER BY hits DESC,last_seen DESC LIMIT ?""",
            (did, limit),
        ).fetchall()
    data = [
        {"relation": r[0], "target_type": r[1], "target": r[2], "hits": r[3], "first_seen": r[4], "last_seen": r[5], "protocol": r[6]}
        for r in rows
    ]
    if json_out:
        typer.echo(json.dumps(data, indent=2))
        return
    if not data:
        console.print(Panel("No relationships stored yet.", title=f"JACKNET / GRAPH • {ip}"))
        return
    t = Table(title=f"JACKNET / GRAPH • {ip} • device {did}")
    for c in ("Relation", "Target type", "Target", "Hits", "Protocol", "Last seen"):
        t.add_column(c, overflow="fold")
    for r in data:
        t.add_row(r["relation"], r["target_type"], r["target"], str(r["hits"]), r["protocol"] or "—", r["last_seen"] or "—")
    console.print(t)
