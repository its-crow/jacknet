from __future__ import annotations

import json
import typer
from rich.console import Console
from rich.table import Table

from .db import connect, migrate
from .network_context import ensure_network

console = Console()


def network_cmd(json_out: bool = typer.Option(False, "--json")):
    """Show the current logical network and previously observed networks."""
    migrate(); current_id, current = ensure_network()
    with connect() as con:
        rows = con.execute("""SELECT network_id,network_key,name,cidr,gateway_ip,gateway_mac,ssid,interface,first_seen,last_seen
                              FROM networks ORDER BY network_id""").fetchall()
    data = [{"network_id":r[0],"network_key":r[1],"name":r[2],"cidr":r[3],"gateway_ip":r[4],"gateway_mac":r[5],"ssid":r[6],"interface":r[7],"first_seen":r[8],"last_seen":r[9],"current":r[0]==current_id} for r in rows]
    if json_out:
        typer.echo(json.dumps(data, indent=2)); return
    t=Table(title=f"JACKNET / NETWORKS • current: {current.name} (id {current_id})")
    for c in ("ID","Current","Name/SSID","CIDR","Gateway","Gateway MAC","Interface","Key"): t.add_column(c, overflow="fold")
    for r in data:
        t.add_row(str(r["network_id"]),"YES" if r["current"] else "",r["name"] or "—",r["cidr"] or "—",r["gateway_ip"] or "—",r["gateway_mac"] or "—",r["interface"] or "—",r["network_key"])
    console.print(t)
