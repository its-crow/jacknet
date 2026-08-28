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
    friendly = _friendly_capture_name(description)
    text = f"{description} {friendly}".lower()
    if any(token in text for token in _BLOCKED_CAPTURE_NAMES): return False
    normalized = friendly.lower().replace("_", "-")
    return normalized in ("wi-fi", "wifi", "ethernet") or normalized.startswith(("wi-fi ", "wifi ", "ethernet "))


def _windows_adapter_info() -> dict[str, dict[str, str]]:
    script = "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress,InterfaceGuid | ConvertTo-Json -Compress"
    try:
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10, check=False)
        if proc.returncode or not proc.stdout.strip(): return {}
        data = json.loads(proc.stdout)
        if isinstance(data, dict): data = [data]
        return {str(x.get("Name", "")): {k: str(x.get(k) or "") for k in ("Name", "InterfaceDescription", "Status", "LinkSpeed", "MacAddress", "InterfaceGuid")} for x in data if x.get("Name")}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {}


def _capture_candidates() -> list[dict[str, str]]:
    win = _windows_adapter_info(); rows = []
    for num, desc in list_interfaces():
        if not _is_real_lan_interface(desc): continue
        name = _friendly_capture_name(desc); info = win.get(name, {})
        rows.append({"id": num, "capture": desc, "name": name, "description": info.get("InterfaceDescription", "") or desc,
                     "status": info.get("Status", ""), "link_speed": info.get("LinkSpeed", ""), "mac": info.get("MacAddress", ""), "guid": info.get("InterfaceGuid", "")})
    rows.sort(key=lambda r: (r["status"].lower() != "up", r["name"].lower())); return rows


def _run_diag(cmd: list[str], timeout: int = 12) -> tuple[int, str, str]:
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,encoding="utf-8",errors="replace",check=False,timeout=timeout); return p.returncode,p.stdout.strip(),p.stderr.strip()
    except (OSError,subprocess.TimeoutExpired) as exc: return 999,"",str(exc)


def _packet_probe(exe, interface, duration, monitor=False, no_promisc=False):
    cmd=[exe,"-n"]
    if monitor: cmd.append("-I")
    cmd += ["-i",interface]
    if no_promisc: cmd.append("-p")
    cmd += ["-a",f"duration:{duration}","-T","fields","-e","frame.number"]
    rc,out,err=_run_diag(cmd,duration+8); packets=sum(1 for x in out.splitlines() if x.strip()); return packets,err or (f"exit {rc}" if rc else "")


def _linktypes(exe,interface,monitor=False):
    cmd=[exe,"-i",interface]
    if monitor: cmd.append("-I")
    cmd.append("-L"); rc,out,err=_run_diag(cmd); return rc==0,out or err


def _windows_npcap_service():
    rc,out,err=_run_diag(["sc.exe","query","npcap"]); text=out or err
    if "RUNNING" in text.upper(): return "READY","Npcap service is running"
    if rc==0: return "WARN","Npcap service exists but is not running"
    return "WARN","Npcap service state could not be confirmed"


def _windows_wireless_capabilities():
    rc,out,err=_run_diag(["netsh","wlan","show","wirelesscapabilities"],15); text=out or err
    if rc!=0 or not text: return "WARN","Windows wireless monitor-mode capability could not be queried"
    m=re.search(r"Network monitor mode\s*:\s*(.+)",text,re.I)
    if m:
        v=m.group(1).strip(); return ("READY" if "yes" in v.lower() or "supported" in v.lower() else "INFO",f"Network monitor mode: {v}")
    return "INFO","Windows returned wireless capabilities, but monitor-mode support was not clearly reported"


def _capture_backend_diagnostics(interface,duration=3):
    exe=tshark_path()
    if not exe: return [("TShark","FAIL","TShark not found")]
    rows=[]; s,n=_windows_npcap_service(); rows.append(("Npcap service",s,n)); ok,x=_linktypes(exe,interface); rows.append(("Managed link types","READY" if ok else "WARN",x or "No link-layer types reported"))
    p,d=_packet_probe(exe,interface,duration); rows.append(("Managed capture","READY" if p else "FAIL",f"{p} packets"+(f" • {d}" if d else "")))
    p,d=_packet_probe(exe,interface,duration,no_promisc=True); rows.append(("Managed no-promisc","READY" if p else "FAIL",f"{p} packets"+(f" • {d}" if d else "")))
    ok,x=_linktypes(exe,interface,True); rows.append(("Monitor link types","READY" if ok else "INFO",x or "Monitor mode not exposed by this adapter/driver"))
    if ok:
        p,d=_packet_probe(exe,interface,duration,True); rows.append(("Monitor capture","READY" if p else "FAIL",f"{p} packets"+(f" • {d}" if d else "")))
    s,n=_windows_wireless_capabilities(); rows.append(("Windows WLAN",s,n)); return rows


@capture_app.command("interfaces")
def interfaces_cmd():
    ok,note=capture_ready()
    if not ok: console.print(Panel(note,title="JACKNET / CAPTURE",style="yellow")); raise typer.Exit(2)
    rows=_capture_candidates(); t=Table(title="JACKNET / NETWORK CAPTURE INTERFACES")
    for c in ("ID","Adapter","Hardware","Status","Link speed","MAC"): t.add_column(c,overflow="fold")
    for r in rows: t.add_row(r["id"],r["name"],r["description"],r["status"] or "—",r["link_speed"] or "—",r["mac"] or "—")
    console.print(t)


@capture_app.command("diagnose")
def diagnose_cmd(interface: str=typer.Option(...,"-i","--interface"),duration:int=typer.Option(3,"-d","--duration",min=1,max=10)):
    candidates=_capture_candidates(); valid={r["id"] for r in candidates}
    if interface not in valid: console.print(Panel(f"Interface {interface} is not usable. Allowed: {', '.join(sorted(valid)) or 'none'}",title="JACKNET / CAPTURE DIAGNOSE",style="red")); raise typer.Exit(2)
    adapter=next((r for r in candidates if r["id"]==interface),None); rows=_capture_backend_diagnostics(interface,duration)
    title=f"JACKNET / CAPTURE DIAGNOSTICS • {adapter['name'] if adapter else interface} • {adapter['description'] if adapter else ''}"
    t=Table(title=title); t.add_column("Check"); t.add_column("Status"); t.add_column("Details",overflow="fold")
    for x in rows:t.add_row(*x)
    console.print(t); ready=[r for r in rows if r[0] in ("Managed capture","Managed no-promisc","Monitor capture") and r[1]=="READY"]
    if ready:
        best=ready[0][0]; suffix=" --monitor" if best=="Monitor capture" else ""; console.print(Panel(f"Capture backend is working via: {best}\nTry: jacknet capture live -i {interface} --duration 30{suffix}",title="JACKNET / CAPTURE DIAGNOSIS")); return
    raise typer.Exit(2)


@capture_app.command("probe")
def probe_cmd(duration:int=typer.Option(3,"-d","--duration",min=1,max=10)):
    exe=tshark_path()
    if not exe: console.print(Panel("TShark was not found.",title="JACKNET / CAPTURE PROBE",style="red")); raise typer.Exit(2)
    rows=_capture_candidates(); t=Table(title=f"JACKNET / NETWORK CAPTURE PROBE • {duration}s per interface")
    for c in ("ID","Adapter","Hardware","Status","Packets","Capture"):t.add_column(c,overflow="fold")
    best=None; best_packets=-1
    for r in rows:
        p,d=_packet_probe(exe,r["id"],duration);status="ACTIVE" if p else "NO TRAFFIC";t.add_row(r["id"],r["name"],r["description"],r["status"] or "—",str(p),status)
        if p>best_packets:best_packets=p;best=r
    console.print(t)
    if best and best_packets>0: console.print(Panel(f"Active adapter: {best['name']} • {best['description']} • interface {best['id']} • {best_packets:,} packets observed",title="JACKNET / RECOMMENDATION")); return
    raise typer.Exit(2)


@capture_app.command("analyze")
def analyze_cmd(path:Path=typer.Argument(...,exists=True,readable=True),json_out:bool=typer.Option(False,"--json")):
    ok,note=capture_ready()
    if not ok:console.print(f"[red]{note}[/]");raise typer.Exit(2)
    stats=ingest_capture(path);learned=run_learning();stats["learning"]=learned
    if json_out:typer.echo(json.dumps(stats,indent=2));return
    console.print(Panel(f"Capture: {stats['capture']}\nPackets: {stats['packets']:,}\nFull decodes stored: {stats.get('decoded_packets',0):,}\nArtifacts extracted: {stats.get('artifacts',0):,}\nGraph relationships: {stats.get('relationships',0):,}\nDevices linked: {stats['devices']}\nDNS names: {stats['dns_names']}\nFingerprints promoted: {learned['promoted']}",title="JACKNET / CAPTURE ANALYSIS"))


@capture_app.command("live")
def live_cmd(interface:str=typer.Option(...,"-i","--interface"),duration:int=typer.Option(60,"-d","--duration",min=1),monitor:bool=typer.Option(False,"--monitor"),output:Path|None=typer.Option(None,"-o","--output")):
    valid={r["id"] for r in _capture_candidates()}
    if interface not in valid:raise typer.BadParameter(f"Allowed interfaces: {', '.join(sorted(valid)) or 'none'}")
    out=output or paths()["cache"]/f"capture-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcapng"
    console.print(f"[bold]JACKNET / CAPTURE[/] interface [cyan]{interface}[/] • {duration}s");live_capture(interface,out,duration,monitor);stats=ingest_capture(out,source="live",interface=interface)
    if stats["packets"]==0:raise RuntimeError(f"Capture completed but interface {interface} produced 0 packets")
    learned=run_learning();console.print(Panel(f"Packets: {stats['packets']:,}\nFull decodes stored: {stats.get('decoded_packets',0):,}\nArtifacts extracted: {stats.get('artifacts',0):,}\nGraph relationships: {stats.get('relationships',0):,}\nDevices linked: {stats['devices']}\nCapture: {out}\nFingerprints promoted: {learned['promoted']}",title="JACKNET / CAPTURE COMPLETE"))


def dossier_cmd(ip:str=typer.Argument(...),json_out:bool=typer.Option(False,"--json")):
    d=dossier_for_ip(ip)
    if not d:console.print(f"[yellow]No dossier found for {ip}.[/]");raise typer.Exit(1)
    if json_out:typer.echo(json.dumps(d,indent=2));return
    console.print(Panel(f"Device ID: {d['device_id']}\nMAC: {d['canonical_mac'] or '—'} ({d.get('mac_type','unknown')})\nLabel: {d['user_label'] or d['model'] or 'Unknown'}\nManufacturer: {d['manufacturer'] or '—'}\nType: {d['device_type'] or 'unknown'}\nConfidence: {d['confidence'] or 0}%\nFirst seen: {d['first_seen']}\nLast seen: {d['last_seen']}",title=f"JACKNET / DOSSIER • {ip}"))


def database_report_cmd(output:Path|None=typer.Option(None,"-o","--output"),json_out:bool=typer.Option(False,"--json")):
    rows=all_devices()
    if json_out:typer.echo(json.dumps(rows,indent=2))
    else:
        t=Table(title="JACKNET / LEARNED NETWORK DATABASE")
        for c in ("ID","Current IP","MAC","MAC type","Identity","Type","Confidence","Traffic","Addr hist","Last seen"):t.add_column(c,overflow="fold")
        for r in rows:t.add_row(str(r['device_id']),r['current_ip'] or '—',r['mac'] or '—',r['mac_type'],r['label'] or r['model'] or 'Unknown',r['device_type'] or 'unknown',f"{r['confidence'] or 0}%",str(r['traffic_packets']),str(r['address_count']),r['last_seen'])
        console.print(t)
    if output:output.write_text(json.dumps(rows,indent=2),encoding="utf-8");console.print(f"[green]Wrote database report:[/] {output.resolve()}")
