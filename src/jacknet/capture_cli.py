from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .capture import capture_ready, ingest_capture, list_interfaces, live_capture
from .config import paths
from .dossier import all_devices, dossier_for_ip
from .learning import learn as run_learning

capture_app = typer.Typer(help="Capture and analyze Wi-Fi/LAN traffic with Wireshark/TShark", no_args_is_help=True)
console = Console()


@capture_app.command("interfaces")
def interfaces_cmd():
    """Show capture interfaces visible to TShark."""
    ok, note = capture_ready()
    if not ok:
        console.print(Panel(note, title="JACKNET / CAPTURE", style="yellow")); raise typer.Exit(2)
    rows = list_interfaces()
    t=Table(title="JACKNET / CAPTURE INTERFACES"); t.add_column("ID"); t.add_column("Interface", overflow="fold")
    for num,desc in rows: t.add_row(num,desc)
    console.print(t)


@capture_app.command("analyze")
def analyze_cmd(path: Path = typer.Argument(..., exists=True, readable=True), json_out: bool = typer.Option(False,"--json")):
    """Analyze a .pcap/.pcapng file, attach traffic to devices, and learn from it."""
    ok,note=capture_ready()
    if not ok: console.print(f"[red]{note}[/]"); raise typer.Exit(2)
    try: stats=ingest_capture(path); learned=run_learning()
    except Exception as exc: console.print(Panel(str(exc),title="JACKNET / CAPTURE ERROR",style="red")); raise typer.Exit(2)
    stats["learning"]=learned
    if json_out: typer.echo(json.dumps(stats,indent=2)); return
    body=(f"Capture: {stats['capture']}\nPackets learned: {stats['packets']:,}\nDevices linked: {stats['devices']}\n"
          f"Local IPs: {stats['local_ips']}\nExternal endpoints: {stats['external_endpoints']}\nDNS names: {stats['dns_names']}\n"
          f"Learning examples: {learned['examples']} • fingerprints promoted: {learned['promoted']}")
    console.print(Panel(body,title="JACKNET / CAPTURE ANALYSIS"))
    if stats['protocols']:
        t=Table(title="Top protocols"); t.add_column("Protocol"); t.add_column("Packets",justify="right")
        for k,v in stats['protocols'].items(): t.add_row(k,str(v))
        console.print(t)


@capture_app.command("live")
def live_cmd(interface: str = typer.Option(...,"-i","--interface"), duration: int = typer.Option(60,"-d","--duration",min=1), monitor: bool = typer.Option(False,"--monitor",help="Request monitor mode from the capture backend"), output: Path | None = typer.Option(None,"-o","--output")):
    """Capture traffic, then immediately ingest it into JackNet's learning database."""
    stamp=datetime.now().strftime("%Y%m%d-%H%M%S")
    out=output or paths()["cache"] / f"capture-{stamp}.pcapng"
    try:
        console.print(f"[bold]JACKNET / CAPTURE[/] interface [cyan]{interface}[/] • {duration}s")
        live_capture(interface,out,duration,monitor); stats=ingest_capture(out,source="live",interface=interface); learned=run_learning()
    except Exception as exc: console.print(Panel(str(exc),title="JACKNET / CAPTURE ERROR",style="red")); raise typer.Exit(2)
    console.print(Panel(f"Packets: {stats['packets']:,}\nDevices linked: {stats['devices']}\nCapture: {out}\nFingerprints promoted: {learned['promoted']}",title="JACKNET / CAPTURE COMPLETE"))


def dossier_cmd(ip: str = typer.Argument(...), json_out: bool = typer.Option(False,"--json")):
    """Show everything JackNet has learned about the device associated with an IP."""
    d=dossier_for_ip(ip)
    if not d: console.print(f"[yellow]No dossier found for {ip}.[/]"); raise typer.Exit(1)
    if json_out: typer.echo(json.dumps(d,indent=2)); return
    console.print(Panel(f"Device ID: {d['device_id']}\nMAC: {d['canonical_mac'] or '—'}\nLabel: {d['user_label'] or d['model'] or 'Unknown'}\nManufacturer: {d['manufacturer'] or '—'}\nType: {d['device_type'] or 'unknown'}\nConfidence: {d['confidence'] or 0}%\nFirst seen: {d['first_seen']}\nLast seen: {d['last_seen']}",title=f"JACKNET / DOSSIER • {ip}"))
    t=Table(title="Known IP addresses"); t.add_column("IP"); t.add_column("First seen"); t.add_column("Last seen"); t.add_column("Seen"); t.add_column("Source")
    for x in d['addresses']: t.add_row(x['ip'],x['first_seen'],x['last_seen'],str(x['observations']),x['source'])
    console.print(t)
    tr=d['traffic']; console.print(f"[bold]Traffic:[/] {tr['packets']:,} packets • {tr['bytes']:,} bytes")
    if d['features']:
        f=Table(title="Learned evidence"); f.add_column("Type"); f.add_column("Value",overflow="fold"); f.add_column("Count"); f.add_column("Source")
        for x in d['features'][:50]: f.add_row(x['type'],x['value'],str(x['count']),x['source'])
        console.print(f)
    if d['endpoints']:
        e=Table(title="Observed external endpoints"); e.add_column("Endpoint"); e.add_column("Hits",justify="right"); e.add_column("Protocol"); e.add_column("Last seen")
        for x in d['endpoints'][:30]: e.add_row(x['endpoint'],str(x['hits']),x['protocol'] or '—',x['last_seen'])
        console.print(e)


def database_report_cmd(output: Path | None = typer.Option(None,"-o","--output"), json_out: bool = typer.Option(False,"--json")):
    """Generate an up-to-date inventory from accumulated database knowledge."""
    rows=all_devices()
    if json_out:
        text=json.dumps(rows,indent=2); typer.echo(text)
    else:
        t=Table(title="JACKNET / LEARNED NETWORK DATABASE")
        for c in ("ID","IPs","MAC","Identity","Type","Confidence","Traffic","Last seen"): t.add_column(c,overflow="fold")
        for r in rows: t.add_row(str(r['device_id']),r['ips'] or '—',r['mac'] or '—',r['label'] or r['model'] or 'Unknown',r['device_type'] or 'unknown',f"{r['confidence'] or 0}%",str(r['traffic_packets']),r['last_seen'])
        console.print(t)
    if output:
        output.write_text(json.dumps(rows,indent=2),encoding="utf-8"); console.print(f"[green]Wrote database report:[/] {output.resolve()}")
