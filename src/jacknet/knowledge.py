from __future__ import annotations
import json,typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from .db import connect,migrate
from .network_context import ensure_network
console=Console()

def _device_for_ip(ip):
 migrate();network_id,network=ensure_network()
 with connect() as con:
  row=con.execute("SELECT device_id FROM device_network_addresses WHERE network_id=? AND ip=? ORDER BY last_seen DESC LIMIT 1",(network_id,ip)).fetchone()
  if row:return int(row[0]),network_id,network
  rows=con.execute("SELECT device_id,network_id FROM device_network_addresses WHERE ip=? ORDER BY last_seen DESC",(ip,)).fetchall()
  if len(rows)==1:return int(rows[0][0]),int(rows[0][1]),network
  if rows:return int(rows[0][0]),int(rows[0][1]),network
 return None,network_id,network

def evidence_cmd(ip:str=typer.Argument(...),limit:int=typer.Option(100,"-n","--limit",min=1,max=1000),json_out:bool=typer.Option(False,"--json")):
 did,nid,network=_device_for_ip(ip)
 if did is None:console.print(f"[yellow]No stored device found for {ip} on network {network.name}.[/]");raise typer.Exit(1)
 with connect() as con:rows=con.execute("""SELECT artifact_type,artifact_value,COUNT(*) AS hits,COUNT(DISTINCT session_id) AS sessions,MIN(observed_at),MAX(observed_at),GROUP_CONCAT(DISTINCT protocol) FROM network_artifacts WHERE device_id=? AND network_id IS ? GROUP BY artifact_type,artifact_value ORDER BY sessions DESC,hits DESC,MAX(observed_at) DESC LIMIT ?""",(did,nid,limit)).fetchall()
 data=[{"type":r[0],"value":r[1],"hits":r[2],"sessions":r[3],"first_seen":r[4],"last_seen":r[5],"protocols":r[6],"network_id":nid} for r in rows]
 if json_out:typer.echo(json.dumps(data,indent=2));return
 if not data:console.print(Panel("No decoded identity/application evidence is stored for this device on this network yet.",title=f"JACKNET / EVIDENCE • {ip} • {network.name}"));return
 t=Table(title=f"JACKNET / EVIDENCE • {ip} • device {did} • {network.name}");[t.add_column(c,overflow="fold") for c in ("Type","Value","Hits","Sessions","Last seen","Protocol")]
 for r in data:t.add_row(r["type"],r["value"],str(r["hits"]),str(r["sessions"]),r["last_seen"] or "—",r["protocols"] or "—")
 console.print(t)
def sites_cmd(ip:str=typer.Argument(...),limit:int=typer.Option(50,"-n","--limit",min=1,max=500),json_out:bool=typer.Option(False,"--json")):
 did,nid,network=_device_for_ip(ip)
 if did is None:console.print(f"[yellow]No stored device found for {ip} on network {network.name}.[/]");raise typer.Exit(1)
 with connect() as con:rows=con.execute("""SELECT artifact_value,GROUP_CONCAT(DISTINCT artifact_type),COUNT(*) AS hits,COUNT(DISTINCT session_id) AS sessions,MIN(observed_at),MAX(observed_at) FROM network_artifacts WHERE device_id=? AND network_id IS ? AND artifact_type IN ('domain','domain_query','domain_answer','tls_sni','http_host') GROUP BY lower(artifact_value) ORDER BY sessions DESC,hits DESC,MAX(observed_at) DESC LIMIT ?""",(did,nid,limit)).fetchall()
 data=[{"site":r[0],"evidence":r[1],"hits":r[2],"sessions":r[3],"first_seen":r[4],"last_seen":r[5],"network_id":nid} for r in rows]
 if json_out:typer.echo(json.dumps(data,indent=2));return
 t=Table(title=f"JACKNET / OBSERVED SITES • {ip} • device {did} • {network.name}");[t.add_column(c,overflow="fold") for c in ("Site/domain","Evidence","Hits","Sessions","Last seen")]
 for r in data:t.add_row(r["site"],r["evidence"] or "—",str(r["hits"]),str(r["sessions"]),r["last_seen"] or "—")
 console.print(t)
def graph_cmd(ip:str=typer.Argument(...),limit:int=typer.Option(100,"-n","--limit",min=1,max=1000),json_out:bool=typer.Option(False,"--json")):
 did,nid,network=_device_for_ip(ip)
 if did is None:console.print(f"[yellow]No stored device found for {ip} on network {network.name}.[/]");raise typer.Exit(1)
 with connect() as con:rows=con.execute("SELECT relation,target_type,target_value,hits,first_seen,last_seen,protocol FROM network_relationships WHERE device_id=? AND network_id IS ? ORDER BY hits DESC,last_seen DESC LIMIT ?",(did,nid,limit)).fetchall()
 data=[{"relation":r[0],"target_type":r[1],"target":r[2],"hits":r[3],"first_seen":r[4],"last_seen":r[5],"protocol":r[6],"network_id":nid} for r in rows]
 if json_out:typer.echo(json.dumps(data,indent=2));return
 if not data:console.print(Panel("No meaningful relationships stored yet on this network.",title=f"JACKNET / GRAPH • {ip} • {network.name}"));return
 t=Table(title=f"JACKNET / GRAPH • {ip} • device {did} • {network.name}");[t.add_column(c,overflow="fold") for c in ("Relation","Target type","Target","Hits","Protocol","Last seen")]
 for r in data:t.add_row(r["relation"],r["target_type"],r["target"],str(r["hits"]),r["protocol"] or "—",r["last_seen"] or "—")
 console.print(t)
