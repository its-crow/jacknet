from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .capture import capture_ready, ingest_capture, list_interfaces, live_capture, tshark_path
from .config import paths
from .dossier import all_devices, dossier_for_ip
from .learning import learn as run_learning

capture_app = typer.Typer(help="Capture and analyze Wi-Fi/LAN traffic with Wireshark/TShark", no_args_is_help=True)
console = Console()


_BLOCKED_CAPTURE_NAMES = (
    "loopback", "npcap loopback", "local area connection*", "usbpcap",
    "ciscodump", "etwdump", "randpkt", "sshdump", "udpdump", "wifidump",
    "wi-fi direct", "wifi direct", "bluetooth", "virtual", "hyper-v", "vpn", "tunnel", "tap",
)


def _friendly_capture_name(description: str) -> str:
    matches = re.findall(r"\(([^()]*)\)", description)
    return matches[-1].strip() if matches else description.strip()


def _is_real_lan_interface(description: str) -> bool:
    """Accept only user-facing Ethernet or Wi-Fi interfaces, never loopback/extcap/virtual sources."""
    friendly = _friendly_capture_name(description)
    text = f"{description} {friendly}".lower()
    if any(token in text for token in _BLOCKED_CAPTURE_NAMES):
        return False
    normalized = friendly.lower().replace("_", "-")
    return (
        normalized == "wi-fi"
        or normalized == "wifi"
        or normalized.startswith("wi-fi ")
        or normalized.startswith("wifi ")
        or normalized == "ethernet"
        or normalized.startswith("ethernet ")
    )


def _capture_candidates() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for num, desc in list_interfaces():
        if not _is_real_lan_interface(desc):
            continue
        rows.append({
            "id": num,
            "capture": desc,
            "name": _friendly_capture_name(desc),
            "description": desc,
            "link_speed": "",
        })
    return rows


@capture_app.command("interfaces")
def interfaces_cmd():
    """Show Ethernet/Wi-Fi capture interfaces only."""
    ok, note = capture_ready()
    if not ok:
        console.print(Panel(note, title="JACKNET / CAPTURE", style="yellow")); raise typer.Exit(2)
    rows = _capture_candidates()
    t = Table(title="JACKNET / NETWORK CAPTURE INTERFACES")
    t.add_column("ID")
    t.add_column("Adapter")
    t.add_column("TShark interface", overflow="fold")
    for row in rows:
        t.add_row(row["id"], row["name"], row["capture"])
    console.print(t)
    if not rows:
        console.print(Panel(
            "TShark did not expose a usable Ethernet or Wi-Fi interface. Jacknet deliberately ignores loopback, "
            "Wi-Fi Direct, USBPcap, virtual adapters, and extcap sources.",
            title="JACKNET / CAPTURE",
            style="yellow",
        ))


@capture_app.command("probe")
def probe_cmd(duration: int = typer.Option(3, "-d", "--duration", min=1, max=10)):
    """Probe Ethernet/Wi-Fi adapters and find one receiving packets."""
    exe = tshark_path()
    if not exe:
        console.print(Panel("TShark was not found.", title="JACKNET / CAPTURE PROBE", style="red")); raise typer.Exit(2)

    rows = _capture_candidates()
    if not rows:
        console.print(Panel(
            "No Ethernet/Wi-Fi capture interfaces were found. Jacknet will not fall back to loopback or virtual adapters.",
            title="JACKNET / CAPTURE PROBE",
            style="red",
        ))
        raise typer.Exit(2)

    table = Table(title=f"JACKNET / NETWORK CAPTURE PROBE • {duration}s per interface")
    table.add_column("ID")
    table.add_column("Adapter")
    table.add_column("Packets", justify="right")
    table.add_column("Status")
    best: dict[str, str] | None = None
    best_packets = -1

    for row in rows:
        num = row["id"]
        console.print(f"[dim]Probing {row['name']} (interface {num})...[/]")
        stderr = ""
        try:
            proc = subprocess.run(
                [exe, "-n", "-i", num, "-a", f"duration:{duration}", "-T", "fields", "-e", "frame.number"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=duration + 8,
            )
            packets = sum(1 for line in proc.stdout.splitlines() if line.strip())
            stderr = proc.stderr.strip()
            if proc.returncode and packets == 0:
                status = "ERROR"
            elif packets:
                status = "ACTIVE"
            else:
                status = "NO TRAFFIC"
            if packets > best_packets:
                best_packets = packets
                best = row
        except (OSError, subprocess.TimeoutExpired) as exc:
            packets = 0
            status = "ERROR"
            stderr = str(exc)
        table.add_row(num, row["name"], str(packets), status)
        if status == "ERROR" and stderr:
            console.print(f"[red]  {stderr}[/]")

    console.print(table)
    if best is not None and best_packets > 0:
        console.print(Panel(
            f"Active adapter: [bold cyan]{best['name']}[/] • interface [bold cyan]{best['id']}[/] • "
            f"{best_packets:,} packets observed\n"
            f"Try: jacknet capture live -i {best['id']} --duration 30",
            title="JACKNET / RECOMMENDATION",
        ))
    else:
        console.print(Panel(
            "Jacknet found the real Ethernet/Wi-Fi adapter, but TShark received zero packets from it.\n\n"
            "This is a Windows/Npcap capture-backend problem, not an interface-selection problem. "
            "Jacknet will not substitute loopback traffic and call it success.",
            title="JACKNET / CAPTURE BACKEND FAILURE",
            style="red",
        ))
        raise typer.Exit(2)


@capture_app.command("analyze")
def analyze_cmd(path: Path = typer.Argument(..., exists=True, readable=True), json_out: bool = typer.Option(False,"--json")):
    """Analyze a .pcap/.pcapng file, attach traffic to devices, and learn from it."""
    ok,note=capture_ready()
    if not ok: console.print(f"[red]{note}[/]"); raise typer.Exit(2)
    try: stats=ingest_capture(path); learned=run_learning()
    except Exception as exc: console.print(Panel(str(exc),title="JACKNET / CAPTURE ERROR",style="red")); raise typer.Exit(2)
    stats["learning"]=learned
    if json_out: typer.echo(json.dumps(stats,indent=2)); return
    body=(f"Capture: {stats['capture']}\nPackets: {stats['packets']:,}\nFull decodes stored: {stats.get('decoded_packets',0):,}\n"
          f"Artifacts extracted: {stats.get('artifacts',0):,}\nGraph relationships: {stats.get('relationships',0):,}\n"
          f"Devices linked: {stats['devices']}\nLocal IPs: {stats['local_ips']}\nExternal endpoints: {stats['external_endpoints']}\n"
          f"DNS names: {stats['dns_names']}\nLearning examples: {learned['examples']} • fingerprints promoted: {learned['promoted']}")
    if stats.get("decode_error"):
        body += f"\nFull-decode warning: {stats['decode_error']}"
    console.print(Panel(body,title="JACKNET / CAPTURE ANALYSIS"))
    if stats['protocols']:
        t=Table(title="Top protocols"); t.add_column("Protocol"); t.add_column("Packets",justify="right")
        for k,v in stats['protocols'].items(): t.add_row(k,str(v))
        console.print(t)


@capture_app.command("live")
def live_cmd(interface: str = typer.Option(...,"-i","--interface"), duration: int = typer.Option(60,"-d","--duration",min=1), monitor: bool = typer.Option(False,"--monitor",help="Request monitor mode from the capture backend"), output: Path | None = typer.Option(None,"-o","--output")):
    """Capture traffic, then immediately ingest all decodable evidence into Jacknet."""
    valid_ids = {row["id"] for row in _capture_candidates()}
    if interface not in valid_ids:
        allowed = ", ".join(sorted(valid_ids)) or "none"
        console.print(Panel(
            f"Interface {interface} is not an Ethernet/Wi-Fi capture adapter. Allowed interfaces: {allowed}",
            title="JACKNET / CAPTURE ERROR",
            style="red",
        ))
        raise typer.Exit(2)
    stamp=datetime.now().strftime("%Y%m%d-%H%M%S")
    out=output or paths()["cache"] / f"capture-{stamp}.pcapng"
    try:
        console.print(f"[bold]JACKNET / CAPTURE[/] interface [cyan]{interface}[/] • {duration}s")
        live_capture(interface,out,duration,monitor)
        stats=ingest_capture(out,source="live",interface=interface)
        if stats["packets"] == 0:
            raise RuntimeError(
                f"Capture completed but network interface {interface} produced 0 packets. "
                "Jacknet will not mark this as success. Run 'jacknet capture probe' for backend diagnostics."
            )
        learned=run_learning()
    except Exception as exc: console.print(Panel(str(exc),title="JACKNET / CAPTURE ERROR",style="red")); raise typer.Exit(2)
    body=(f"Packets: {stats['packets']:,}\nFull decodes stored: {stats.get('decoded_packets',0):,}\n"
          f"Artifacts extracted: {stats.get('artifacts',0):,}\nGraph relationships: {stats.get('relationships',0):,}\n"
          f"Devices linked: {stats['devices']}\nCapture: {out}\nFingerprints promoted: {learned['promoted']}")
    if stats.get("decode_error"):
        body += f"\nFull-decode warning: {stats['decode_error']}"
    console.print(Panel(body,title="JACKNET / CAPTURE COMPLETE"))


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
