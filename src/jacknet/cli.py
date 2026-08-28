from __future__ import annotations
import json
import sys
import ipaddress
import socket
import subprocess
from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from .discovery import default_network, arp_scan, enrich_ptr, enrich_vendor, nmap_enrich
from .fingerprint import apply_fingerprint, RULES
from .learning import apply_learned, confirm as confirm_identity, learn as run_learning, find_latest
from .reporting import write_report
from .ssdp import discover as ssdp_discover
from .mdns import discover as mdns_discover
from .history import record as record_history, latest as latest_history
from .config import data_dir, paths, ensure_layout, save_config, relocate_data, CONFIG_FILE
from .db import migrate, integrity, backup as backup_db, recover_to_new_db

app=typer.Typer(help="JackNet — LAN inventory and device fingerprinting",no_args_is_help=True,rich_markup_mode="rich"); console=Console(); err_console=Console(stderr=True)

def render(devices,verbose=False):
 t=Table(title="JACKNET / NETWORK INVENTORY"); [t.add_column(c,overflow="fold") for c in ["IP","Hostname","MAC","Manufacturer","Identity","Type","Confidence"]]
 for d in devices:t.add_row(d.ip,d.hostname or "—",d.mac or "—",d.manufacturer or "—",d.model or "Unknown",d.device_type or "unknown",f"{d.confidence}%")
 console.print(t)

def _stdin_targets():
 if sys.stdin.isatty():return []
 return [x.strip() for line in sys.stdin for x in line.replace(","," ").split() if x.strip()]
def _expand_targets(values):
 out=[]
 for v in values:
  try: out.extend(str(x) for x in ipaddress.ip_network(v,strict=False).hosts()) if "/" in v else out.append(str(ipaddress.ip_address(v)))
  except ValueError:
   try:out.append(socket.gethostbyname(v))
   except socket.gaierror:err_console.print(f"[yellow]Skipping unresolved target:[/] {v}")
 return list(dict.fromkeys(out))
def run_scan(network,target_ip,nmap,aggressive,ssdp,mdns,stdin=False,progress=True):
 targets=_expand_targets(([target_ip] if target_ip else [])+(_stdin_targets() if (stdin or not sys.stdin.isatty()) else [])); net=network or default_network()
 if progress:err_console.print(f"[bold]JACKNET / SCAN[/] network [cyan]{net}[/]");err_console.print("[dim]• ARP discovery...[/]")
 devices=arp_scan(net)
 if progress:err_console.print(f"[green]✓[/] ARP: {len(devices)} device(s)")
 if targets:
  found={d.ip for d in devices};from .models import Device;devices.extend(Device(ip=x) for x in targets if x not in found);devices=[d for d in devices if d.ip in set(targets)]
 if progress:err_console.print("[dim]• PTR hostnames (3s max)...[/]")
 enrich_ptr(devices,stage_timeout=3.0);enrich_vendor(devices)
 if ssdp:ssdp_discover(devices)
 if mdns:mdns_discover(devices)
 if nmap:nmap_enrich(devices,aggressive=aggressive)
 for d in devices:apply_fingerprint(d);apply_learned(d)
 return devices

@app.command()
def scan(ip:str|None=typer.Option(None,"-i","-ip","--ip"),network:str|None=typer.Option(None,"-n","--network"),verbose:bool=False,nmap:bool=typer.Option(True,"--nmap/--no-nmap"),aggressive:bool=typer.Option(False,"--deep"),ssdp:bool=typer.Option(True,"--ssdp/--no-ssdp"),mdns:bool=typer.Option(True,"--mdns/--no-mdns"),history:bool=typer.Option(True,"--history/--no-history"),manufacturer:str|None=typer.Option(None,"--manufacturer","--man"),device_type:str|None=typer.Option(None,"--type"),confidence:int=typer.Option(0,"-c","--confidence"),report:bool=False,output:Path|None=typer.Option(None,"-o","--output"),format_:str|None=typer.Option(None,"--format"),json_out:bool=typer.Option(False,"--json"),raw:bool=False,stdin:bool=False):
 devices=run_scan(network,ip,nmap,aggressive,ssdp,mdns,stdin,not(json_out or raw));devices=[d for d in devices if d.confidence>=confidence]
 if manufacturer:devices=[d for d in devices if manufacturer.lower() in ((d.manufacturer or "")+(d.model or "")).lower()]
 if device_type:devices=[d for d in devices if device_type.lower() in (d.device_type or "").lower()]
 if raw:[typer.echo(d.ip) for d in devices]
 elif json_out:typer.echo(json.dumps([d.to_dict() for d in devices],indent=2))
 else:render(devices,verbose)
 if history:record_history(devices)
 if report:
  out=output or Path(f"jacknet-report.{format_ or 'jnet'}");write_report(devices,out,format_);console.print(f"[bold]Report:[/] {out.resolve()}")

@app.command()
def manual(output:Path|None=typer.Option(None,"-o","--output"),search:str|None=typer.Option(None,"-s","--search")):
 rows=RULES
 if search:rows=[r for r in rows if search.lower() in (r.needle+r.label+r.kind).lower()]
 t=Table(title="JACKNET / FINGERPRINT MANUAL");[t.add_column(c) for c in ["Field","Match","Identity","Type","Weight"]]
 for r in rows:t.add_row(r.field,r.needle,r.label,r.kind,str(r.score))
 console.print(t)

@app.command("history")
def history_cmd(limit:int=typer.Option(50,"-n","--limit")):
 rows=latest_history(limit=limit);t=Table(title=f"JACKNET / HISTORY • {paths()['db']}");[t.add_column(c,overflow="fold") for c in ["Observed","IP","MAC","Hostname","Manufacturer","Identity","Type","Confidence"]]
 for r in rows:t.add_row(*(str(x) if x is not None else "—" for x in r[:-1]),f"{r[-1]}%")
 console.print(t)

@app.command("init")
def init_cmd(data:Path|None=typer.Option(None,"--data-dir","-d"),move_existing:bool=False,force:bool=False):
 target=(data or data_dir()).expanduser().resolve()
 if CONFIG_FILE.exists() and data is None and not force:console.print(Panel.fit(f"JackNet is already initialized.\nData: [bold]{data_dir()}[/]",title="JACKNET / INIT"));return
 if data is not None: target=relocate_data(target,copy_existing=True) if move_existing else (save_config(target) or target)
 p=ensure_layout(target);version=migrate(p["db"]);console.print(Panel.fit(f"[bold green]READY[/]\nData directory: {target}\nDatabase: {p['db']}\nSchema: v{version}\nConfig: {CONFIG_FILE}",title="JACKNET / INIT"))

@app.command("config")
def config_cmd(data:Path|None=typer.Option(None,"--data-dir","-d"),move_existing:bool=True):
 if data is not None:target=relocate_data(data,copy_existing=move_existing);migrate(paths(target)["db"])
 p=paths();t=Table(title="JACKNET / CONFIG");t.add_column("Setting");t.add_column("Value",overflow="fold")
 for a,b in [("Config file",CONFIG_FILE),("Data directory",p["root"]),("Database",p["db"]),("Reports",p["reports"]),("Backups",p["backups"]),("Environment override","JACKNET_DATA_DIR")]:t.add_row(str(a),str(b))
 console.print(t)

@app.command("backup")
def backup_cmd(output:Path|None=typer.Option(None,"-o","--output")):migrate();console.print(f"[bold green]Backup created:[/] {backup_db(destination=output)}")
@app.command("repair")
def repair_cmd(yes:bool=False):
 p=ensure_layout();ok,msg=integrity(p["db"])
 if ok:migrate(p["db"]);console.print(Panel("Database integrity OK; migrations and app-data layout verified",title="JACKNET / REPAIR"));return
 if yes:_,action=recover_to_new_db(p["db"]);console.print(action);return
 console.print(Panel(f"Database integrity check failed: {msg}",title="JACKNET / REPAIR",style="red"));raise typer.Exit(2)

@app.command("confirm")
def confirm_cmd(ip:str=typer.Argument(...),manufacturer:str|None=typer.Option(None,"--manufacturer","--man"),identity:str|None=typer.Option(None,"--identity","--as"),custom_id:str|None=typer.Option(None,"--custom-id","--ci"),device_type:str|None=typer.Option(None,"--type"),yes:bool=False):
 if identity and custom_id:raise typer.BadParameter("Use either identity or custom-id")
 identity=custom_id or identity;row=find_latest(ip)
 if not row:raise typer.BadParameter(f"No stored observation for {ip}")
 if not yes and not typer.confirm("Confirm this identification?"):raise typer.Abort()
 result=confirm_identity(ip,manufacturer,identity,device_type,False);stats=run_learning();console.print(f"[green]✓ Identity confirmed[/] for {result['mac']} ({stats['promoted']} promoted)")
@app.command("correct")
def correct_cmd(ip:str,identity:str|None=typer.Option(None,"--identity","--as"),custom_id:str|None=typer.Option(None,"--custom-id","--ci"),device_type:str|None=typer.Option(None,"--type"),manufacturer:str|None=typer.Option(None,"--manufacturer","--man")):
 identity=custom_id or identity;confirm_identity(ip,manufacturer,identity,device_type,True);run_learning();console.print("[green]✓ Correction stored[/]")
@app.command("learn")
def learn_cmd():console.print(run_learning())
@app.command("fingerprints")
def fingerprints_cmd():
 migrate();from .db import connect
 with connect() as con:rows=con.execute("SELECT name,model,device_type,status,support_count,COALESCE(precision,0) FROM fingerprints ORDER BY status,name").fetchall()
 t=Table(title="JACKNET / LEARNED FINGERPRINTS");[t.add_column(c) for c in ["Name","Identity","Type","Status","Support","Precision"]]
 for r in rows:t.add_row(str(r[0]),str(r[1] or '—'),str(r[2] or '—'),str(r[3]),str(r[4]),f"{float(r[5])*100:.0f}%" if r[5] else "—")
 console.print(t)

def _version(path):
 if not path:return "—"
 try:
  p=subprocess.run([path,"--version"],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=5,check=False);return (p.stdout or p.stderr).splitlines()[0].strip()
 except Exception:return "version unavailable"
def _npcap_info():
 try:
  p=subprocess.run(["sc.exe","query","npcap"],capture_output=True,text=True,timeout=5,check=False);running="RUNNING" in (p.stdout or "").upper()
  candidates=[Path(r"C:\Program Files\Npcap\NPFInstall.exe"),Path(r"C:\Program Files\Npcap\npcap.cat")];install=next((x.parent for x in candidates if x.exists()),None)
  return ("READY" if running else "WARN",f"service {'running' if running else 'not running'}"+(f" • {install}" if install else ""))
 except Exception:return "WARN","service state unavailable"

@app.command()
def doctor(fix:bool=typer.Option(False,"--fix")):
 import shutil,platform
 from importlib.util import find_spec
 from .capture import tshark_path,dumpcap_path
 t=Table(title="JACKNET / CAPABILITY CHECK");t.add_column("Capability");t.add_column("Status");t.add_column("Details",overflow="fold")
 nmap=shutil.which("nmap");tshark=tshark_path();dumpcap=dumpcap_path();wireshark=shutil.which("wireshark")
 if not wireshark:
  p=Path(r"C:\Program Files\Wireshark\Wireshark.exe");wireshark=str(p) if p.exists() else None
 for name,ok,note in [("Nmap",bool(nmap),nmap or "Not found"),("Wireshark",bool(wireshark),f"{wireshark or 'Not found'} • {_version(wireshark) if wireshark else 'install Wireshark'}"),("TShark",bool(tshark),f"{tshark or 'Not found'} • {_version(tshark) if tshark else 'required for packet decoding'}"),("dumpcap",bool(dumpcap),f"{dumpcap or 'Not found'} • {_version(dumpcap) if dumpcap else 'required for capture'}"),("Scapy",bool(find_spec("scapy")),"ARP discovery"),("Zeroconf",bool(find_spec("zeroconf")),"mDNS/DNS-SD support"),("MAC OUI",bool(find_spec("mac_vendor_lookup")),"Manufacturer lookup")]:t.add_row(name,"READY" if ok else "MISSING",note)
 ns,nn=_npcap_info();t.add_row("Npcap",ns,nn)
 p=paths();ok_db,db_msg=integrity(p["db"]);t.add_row("App data","READY" if p["root"].exists() else "MISSING",str(p["root"]));t.add_row("Database","READY" if ok_db else "MISSING/BAD",db_msg);t.add_row("Platform","INFO",platform.platform());console.print(t)
 if fix:
  ensure_layout();migrate(p["db"]);console.print("[green]Fixed/verified:[/] Jacknet-owned schema and app-data layout")
 if not nmap:console.print("[yellow]Action required:[/] install Nmap and add it to PATH for service/OS fingerprinting.")
 if not tshark or not dumpcap:console.print("[yellow]Action required:[/] install Wireshark with TShark/Npcap capture components.")

if __name__=="__main__":app()
