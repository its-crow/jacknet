from __future__ import annotations

import ipaddress
import json
import socket
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import CONFIG_FILE, data_dir, ensure_layout, paths, relocate_data, save_config
from .db import backup as backup_db
from .db import integrity, migrate, recover_to_new_db
from .discovery import arp_scan, default_network, enrich_ptr, enrich_vendor, nmap_enrich
from .fingerprint import RULES, apply_fingerprint
from .history import latest as latest_history
from .history import record as record_history
from .learning import apply_learned, confirm as confirm_identity, find_latest, learn as run_learning
from .mac import address_type
from .mdns import discover as mdns_discover
from .reporting import write_report
from .ssdp import discover as ssdp_discover

app = typer.Typer(
    help="JackNet — LAN inventory and device fingerprinting",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()
err_console = Console(stderr=True)


def _sort_devices(devices):
    return sorted(devices, key=lambda d: ipaddress.ip_address(d.ip))


def render(devices, verbose=False):
    devices = _sort_devices(devices)
    table = Table(title="JACKNET / NETWORK INVENTORY", header_style="bold", show_lines=False)
    for c in ["IP", "Hostname", "MAC", "Manufacturer", "Identity", "Type", "Confidence"]:
        table.add_column(c, overflow="fold")
    for d in devices:
        table.add_row(
            d.ip,
            d.hostname or "—",
            d.mac or "—",
            d.manufacturer or "—",
            d.model or "Unknown",
            d.device_type or "unknown",
            f"{d.confidence}%",
        )
    console.print(table)

    if verbose:
        for d in devices:
            body = []
            if d.mac:
                body.append(f"[bold]MAC type:[/] {address_type(d.mac).replace('_', ' ')}")
            if d.os:
                body.append(f"[bold]OS:[/] {d.os}")
            if d.open_ports:
                body.append(
                    "[bold]Open ports:[/] "
                    + ", ".join(
                        f"{p['port']}/{p.get('protocol', 'tcp')} {p.get('product') or p.get('name') or ''}".strip()
                        for p in d.open_ports
                    )
                )
            if d.ssdp:
                body.append(f"[bold]SSDP/UPnP:[/] {len(d.ssdp)} response(s)")
            if d.mdns:
                body.append(f"[bold]mDNS:[/] {len(d.mdns)} service(s)")
            if d.os_guesses:
                body.append(
                    "[bold]OS guesses:[/] "
                    + ", ".join(f"{x['name']} ({x['accuracy']}%)" for x in d.os_guesses[:3])
                )
            if d.evidence:
                body.append(
                    "[bold]Evidence:[/] "
                    + "; ".join(
                        f"{e.source}:{e.fact}={e.value} (+{e.weight})" for e in d.evidence
                    )
                )
            console.print(
                Panel(
                    "\n".join(body) or "No enrichment data",
                    title=f"{d.ip} • {d.model or 'Unknown device'}",
                    subtitle=f"confidence {d.confidence}%",
                )
            )


def _stdin_targets() -> list[str]:
    if sys.stdin.isatty():
        return []
    return [x.strip() for line in sys.stdin for x in line.replace(",", " ").split() if x.strip()]


def _expand_targets(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        try:
            if "/" in value:
                out.extend(str(x) for x in ipaddress.ip_network(value, strict=False).hosts())
            else:
                out.append(str(ipaddress.ip_address(value)))
        except ValueError:
            try:
                out.append(socket.gethostbyname(value))
            except socket.gaierror:
                err_console.print(f"[yellow]Skipping unresolved target:[/] {value}")
    return list(dict.fromkeys(out))


def run_scan(
    network: str | None,
    target_ip: str | None,
    nmap: bool,
    aggressive: bool,
    ssdp: bool,
    mdns: bool,
    stdin: bool = False,
    progress: bool = True,
):
    piped = _stdin_targets() if (stdin or not sys.stdin.isatty()) else []
    targets = _expand_targets(([target_ip] if target_ip else []) + piped)
    net = network or default_network()

    if progress:
        err_console.print(f"[bold]JACKNET / SCAN[/]  network [cyan]{net}[/]")
        err_console.print("[dim]• ARP discovery...[/]")
    devices = arp_scan(net)
    if progress:
        err_console.print(f"[green]✓[/] ARP: {len(devices)} device(s)")

    if targets:
        found = {d.ip for d in devices}
        from .models import Device
        devices.extend(Device(ip=x) for x in targets if x not in found)
        target_set = set(targets)
        devices = [d for d in devices if d.ip in target_set]

    if progress:
        err_console.print("[dim]• PTR hostnames (3s max)...[/]")
    enrich_ptr(devices, stage_timeout=3.0)
    if progress:
        err_console.print("[green]✓[/] PTR complete")

    enrich_vendor(devices)
    if progress:
        err_console.print("[green]✓[/] OUI/vendor lookup complete")

    if ssdp:
        if progress:
            err_console.print("[dim]• SSDP/UPnP...[/]")
        ssdp_discover(devices)
        if progress:
            err_console.print("[green]✓[/] SSDP complete")

    if mdns:
        if progress:
            err_console.print("[dim]• mDNS/DNS-SD...[/]")
        mdns_discover(devices)
        if progress:
            err_console.print("[green]✓[/] mDNS complete")

    if nmap:
        if progress:
            err_console.print(
                f"[dim]• Nmap service{'/OS' if aggressive else ''} fingerprinting (bounded)...[/]"
            )
        nmap_enrich(devices, aggressive=aggressive)
        if progress:
            err_console.print("[green]✓[/] Nmap complete")

    for d in devices:
        apply_fingerprint(d)
        apply_learned(d)
    return _sort_devices(devices)


@app.command()
def scan(
    all_: bool = typer.Option(True, "-A", "--all", help="Scan all discovered LAN devices"),
    ip: str | None = typer.Option(None, "-i", "-ip", "--ip", help="Only show one IPv4 address"),
    network: str | None = typer.Option(None, "-n", "--network", help="CIDR to scan; default = active LAN"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
    nmap: bool = typer.Option(True, "--nmap/--no-nmap", help="Use Nmap service detection when installed"),
    aggressive: bool = typer.Option(False, "--deep", help="Add Nmap OS fingerprinting"),
    ssdp: bool = typer.Option(True, "--ssdp/--no-ssdp"),
    mdns: bool = typer.Option(True, "--mdns/--no-mdns"),
    history: bool = typer.Option(True, "--history/--no-history", help="Store observations in JackNet's database"),
    manufacturer: str | None = typer.Option(None, "--manufacturer", "--man", help="Filter manufacturer substring"),
    device_type: str | None = typer.Option(None, "--type", help="Filter inferred device type"),
    confidence: int = typer.Option(0, "-c", "--confidence", min=0, max=100, help="Minimum confidence"),
    report: bool = typer.Option(False, "--report", help="Write a report"),
    output: Path | None = typer.Option(None, "-o", "--output", help="Report output file"),
    format_: str | None = typer.Option(None, "--format", help="json|txt|csv|html|jnet"),
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
    raw: bool = typer.Option(False, "--raw", help="Print matching IP addresses only (pipeline-friendly)"),
    stdin: bool = typer.Option(False, "--stdin", help="Read targets from stdin (also auto-detected when piped)"),
):
    devices = run_scan(network, ip, nmap, aggressive, ssdp, mdns, stdin=stdin, progress=not (json_out or raw))
    if manufacturer:
        q = manufacturer.lower()
        devices = [d for d in devices if q in (d.manufacturer or "").lower() or q in (d.model or "").lower()]
    if device_type:
        devices = [d for d in devices if device_type.lower() in (d.device_type or "").lower()]
    devices = [d for d in devices if d.confidence >= confidence]
    devices = _sort_devices(devices)

    if raw:
        for d in devices:
            typer.echo(d.ip)
    elif json_out:
        typer.echo(json.dumps([d.to_dict() for d in devices], indent=2))
    else:
        render(devices, verbose)

    if history:
        record_history(devices)
    if report:
        out = output or Path(f"jacknet-report.{format_ or 'jnet'}")
        write_report(devices, out, format_)
        console.print(f"[bold]Report:[/] {out.resolve()}")


@app.command("explain")
def explain_cmd(
    ip: str = typer.Argument(..., help="IPv4 address to identify and explain"),
    deep: bool = typer.Option(True, "--deep/--no-deep", help="Use Nmap OS fingerprinting"),
    history: bool = typer.Option(True, "--history/--no-history", help="Store this observation"),
):
    """Probe one device and explain exactly what JackNet knows and inferred."""
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        console.print(f"[red]Invalid IP address:[/] {ip}")
        raise typer.Exit(2)

    devices = run_scan(None, ip, True, deep, True, True, progress=True)
    if not devices:
        console.print(f"[red]No result for {ip}.[/]")
        raise typer.Exit(2)
    d = devices[0]

    summary = Table(title=f"JACKNET / EXPLAIN • {d.ip}", show_header=False)
    summary.add_column("Field", style="bold")
    summary.add_column("Value", overflow="fold")
    summary.add_row("Identity", d.model or "Unknown")
    summary.add_row("Type", d.device_type or "unknown")
    summary.add_row("Confidence", f"{d.confidence}%")
    summary.add_row("Hostname", d.hostname or "—")
    summary.add_row("MAC", d.mac or "—")
    summary.add_row("MAC type", address_type(d.mac).replace("_", " "))
    summary.add_row("Manufacturer/OUI", d.manufacturer or "unavailable")
    summary.add_row("OS", d.os or "—")
    console.print(summary)

    evidence = Table(title="EVIDENCE", show_lines=False)
    for c in ["Source", "Fact", "Observed value", "Weight"]:
        evidence.add_column(c, overflow="fold")
    if d.evidence:
        for e in d.evidence:
            evidence.add_row(e.source, e.fact, e.value, f"+{e.weight}" if e.weight else "info")
    else:
        evidence.add_row("—", "—", "No identifying evidence collected", "—")
    console.print(evidence)

    if d.open_ports:
        ports = Table(title="NMAP SERVICES")
        for c in ["Port", "Protocol", "Service", "Product", "Device type"]:
            ports.add_column(c, overflow="fold")
        for p in d.open_ports:
            ports.add_row(
                str(p.get("port", "—")),
                str(p.get("protocol", "tcp")),
                str(p.get("name", "—")),
                str(p.get("product", "—")),
                str(p.get("devicetype", "—")),
            )
        console.print(ports)

    if history:
        record_history([d])


@app.command()
def manual(
    output: Path | None = typer.Option(None, "-o", "--output"),
    search: str | None = typer.Option(None, "-s", "--search"),
):
    rows = RULES
    if search:
        q = search.lower()
        rows = [r for r in rows if q in r.needle.lower() or q in r.label.lower() or q in r.kind.lower()]
    t = Table(title="JACKNET / FINGERPRINT MANUAL")
    for c in ["Field", "Match", "Identity", "Type", "Weight"]:
        t.add_column(c)
    for r in rows:
        t.add_row(r.field, r.needle, r.label, r.kind, str(r.score))
    console.print(t)
    if output:
        output.write_text(
            "\n".join(f"{r.field}\t{r.needle}\t{r.label}\t{r.kind}\t{r.score}" for r in rows),
            encoding="utf-8",
        )
        console.print(f"Wrote {output}")


@app.command("history")
def history_cmd(limit: int = typer.Option(50, "-n", "--limit", min=1, max=500)):
    rows = latest_history(limit=limit)
    t = Table(title=f"JACKNET / HISTORY • {paths()['db']}")
    for c in ["Observed", "IP", "MAC", "Hostname", "Manufacturer", "Identity", "Type", "Confidence"]:
        t.add_column(c, overflow="fold")
    for r in rows:
        t.add_row(*(str(x) if x is not None else "—" for x in r[:-1]), f"{r[-1]}%")
    console.print(t)


@app.command("init")
def init_cmd(
    data: Path | None = typer.Option(None, "--data-dir", "-d", help="Directory for JackNet databases, reports, cache, logs, and fingerprints"),
    move_existing: bool = typer.Option(False, "--move-existing", help="Copy existing JackNet data into the selected directory"),
    force: bool = typer.Option(False, "--force", help="Reinitialize layout and rerun migrations"),
):
    """Initialize JackNet's persistent application data and database."""
    target = (data or data_dir()).expanduser().resolve()
    if CONFIG_FILE.exists() and data is None and not force:
        console.print(Panel.fit(f"JackNet is already initialized.\nData: [bold]{data_dir()}[/]", title="JACKNET / INIT"))
        return
    if data is not None:
        if move_existing:
            target = relocate_data(target, copy_existing=True)
        else:
            save_config(target)
    p = ensure_layout(target)
    version = migrate(p["db"])
    console.print(
        Panel.fit(
            f"[bold green]READY[/]\nData directory: {target}\nDatabase: {p['db']}\nSchema: v{version}\nConfig: {CONFIG_FILE}",
            title="JACKNET / INIT",
        )
    )


@app.command("config")
def config_cmd(
    data: Path | None = typer.Option(None, "--data-dir", "-d", help="Move future JackNet app data to this directory"),
    move_existing: bool = typer.Option(True, "--move-existing/--no-move-existing", help="Copy current app data when changing directories"),
):
    """Show or change JackNet's persistent data directory."""
    if data is not None:
        target = relocate_data(data, copy_existing=move_existing)
        migrate(paths(target)["db"])
        console.print(f"[bold green]Data directory updated:[/] {target}")
    p = paths()
    t = Table(title="JACKNET / CONFIG")
    t.add_column("Setting")
    t.add_column("Value", overflow="fold")
    t.add_row("Config file", str(CONFIG_FILE))
    t.add_row("Data directory", str(p["root"]))
    t.add_row("Database", str(p["db"]))
    t.add_row("Reports", str(p["reports"]))
    t.add_row("Backups", str(p["backups"]))
    t.add_row("Environment override", "JACKNET_DATA_DIR")
    console.print(t)


@app.command("backup")
def backup_cmd(output: Path | None = typer.Option(None, "-o", "--output", help="Optional backup database path")):
    """Create a transactionally consistent SQLite backup."""
    migrate()
    dest = backup_db(destination=output)
    console.print(f"[bold green]Backup created:[/] {dest}")


@app.command("repair")
def repair_cmd(yes: bool = typer.Option(False, "-y", "--yes", help="Allow safe automatic repairs without prompting")):
    """Inspect JackNet state and safely repair missing or damaged local files."""
    p = ensure_layout()
    actions: list[str] = []
    if not p["db"].exists():
        migrate(p["db"])
        actions.append("Created missing database and schema")
    else:
        ok, msg = integrity(p["db"])
        if ok:
            migrate(p["db"])
            actions.append("Database integrity OK; migrations verified")
        elif yes:
            _, action = recover_to_new_db(p["db"])
            actions.append(action)
        else:
            console.print(
                Panel(
                    f"Database integrity check failed: [bold red]{msg}[/]\n\nJackNet will not overwrite it automatically. Run [bold]jacknet backup[/] if possible, then [bold]jacknet repair --yes[/] to preserve the damaged file and create a clean database.",
                    title="JACKNET / REPAIR",
                )
            )
            raise typer.Exit(2)
    for name in ("reports", "backups", "cache", "logs", "exports", "fingerprints"):
        if p[name].exists():
            actions.append(f"{name}/ ready")
    console.print(Panel("\n".join(f"• {x}" for x in actions), title="JACKNET / REPAIR", subtitle=str(p["root"])))


@app.command("confirm")
def confirm_cmd(
    ip: str = typer.Argument(..., help="IP address from a stored observation"),
    manufacturer: str | None = typer.Option(None, "--manufacturer", "--man"),
    identity: str | None = typer.Option(None, "--identity", "--as", help="Confirmed identity/model"),
    custom_id: str | None = typer.Option(None, "--custom-id", "--ci", help="Your own identity/name for this device"),
    device_type: str | None = typer.Option(None, "--type", help="Confirmed device type"),
    yes: bool = typer.Option(False, "-y", "--yes", help="Confirm without prompting"),
):
    """Confirm JackNet's latest identification and teach the learner."""
    if identity and custom_id:
        console.print("[red]Use either --identity/--as or --custom-id/--ci, not both.[/]")
        raise typer.Exit(2)
    identity = custom_id or identity
    row = find_latest(ip)
    if not row:
        console.print(f"[red]No stored observation for {ip}.[/] Run `jacknet scan -ip {ip}` first.")
        raise typer.Exit(2)
    _, _, _, mac, hostname, old_man, old_model, old_type, confidence, _ = row
    console.print(
        Panel.fit(
            f"IP: [bold]{ip}[/]\nMAC: {mac or '—'}\nHostname: {hostname or '—'}\nManufacturer: {manufacturer or old_man or '—'}\nIdentity: {identity or old_model or 'Unknown'}\nType: {device_type or old_type or 'unknown'}\nConfidence: {confidence or 0}%",
            title="JACKNET / CONFIRM",
        )
    )
    if not yes and not typer.confirm("Confirm this identification?"):
        raise typer.Abort()
    try:
        result = confirm_identity(ip, manufacturer, identity, device_type, correction=False)
        stats = run_learning()
    except LookupError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2)
    console.print(
        f"[bold green]✓ Identity confirmed[/] for {result['mac']}. Learning updated ({stats['promoted']} fingerprint(s) promoted)."
    )


@app.command("correct")
def correct_cmd(
    ip: str = typer.Argument(...),
    identity: str | None = typer.Option(None, "--identity", "--as"),
    custom_id: str | None = typer.Option(None, "--custom-id", "--ci", help="Your own corrected identity/name for this device"),
    device_type: str | None = typer.Option(None, "--type"),
    manufacturer: str | None = typer.Option(None, "--manufacturer", "--man"),
):
    """Correct a stored identification and teach JackNet the replacement."""
    if identity and custom_id:
        console.print("[red]Use either --identity/--as or --custom-id/--ci, not both.[/]")
        raise typer.Exit(2)
    identity = custom_id or identity
    if not any((identity, device_type, manufacturer)):
        console.print("[red]Supply --identity/--as, --custom-id/--ci, --type, or --manufacturer.[/]")
        raise typer.Exit(2)
    try:
        result = confirm_identity(ip, manufacturer, identity, device_type, correction=True)
        stats = run_learning()
    except LookupError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2)
    console.print(
        f"[bold green]✓ Correction stored[/] for {result['mac']}. Learning updated ({stats['promoted']} fingerprint(s) promoted)."
    )


@app.command("learn")
def learn_cmd():
    """Mine history for reusable candidate/active fingerprints."""
    stats = run_learning()
    console.print(
        Panel.fit(
            f"Examples considered: {stats['examples']}\nCreated: {stats['created']}\nUpdated: {stats['updated']}\nPromoted active: {stats['promoted']}",
            title="JACKNET / LEARN",
        )
    )


@app.command("fingerprints")
def fingerprints_cmd():
    """Show fingerprints JackNet has learned locally."""
    migrate()
    from .db import connect
    with connect() as con:
        rows = con.execute(
            "SELECT name,model,device_type,status,support_count,COALESCE(precision,0) FROM fingerprints ORDER BY status,name"
        ).fetchall()
    t = Table(title="JACKNET / LEARNED FINGERPRINTS")
    for c in ["Name", "Identity", "Type", "Status", "Support", "Precision"]:
        t.add_column(c, overflow="fold")
    for r in rows:
        t.add_row(
            str(r[0]),
            str(r[1] or "—"),
            str(r[2] or "—"),
            str(r[3]),
            str(r[4]),
            f"{float(r[5]) * 100:.0f}%" if r[5] else "—",
        )
    console.print(t)


@app.command()
def doctor(fix: bool = typer.Option(False, "--fix", help="Repair JackNet-owned files/directories when safe")):
    import platform
    import shutil
    from importlib.util import find_spec

    t = Table(title="JACKNET / CAPABILITY CHECK")
    t.add_column("Capability")
    t.add_column("Status")
    t.add_column("Notes")
    checks = [
        ("Nmap", bool(shutil.which("nmap")), shutil.which("nmap") or "Install Nmap for service/OS fingerprints"),
        ("Scapy", bool(find_spec("scapy")), "ARP discovery"),
        ("Zeroconf", bool(find_spec("zeroconf")), "mDNS/DNS-SD support"),
        ("MAC OUI", bool(find_spec("mac_vendor_lookup")), "Manufacturer lookup"),
    ]
    for name, ok, note in checks:
        t.add_row(name, "READY" if ok else "MISSING", note)
    p = paths()
    ok_db, db_msg = integrity(p["db"])
    t.add_row("App data", "READY" if p["root"].exists() else "MISSING", str(p["root"]))
    t.add_row("Database", "READY" if ok_db else "MISSING/BAD", db_msg)
    t.add_row("Platform", "INFO", platform.platform())
    console.print(t)

    if fix:
        ensure_layout()
        if not p["db"].exists():
            migrate(p["db"])
            console.print("[green]Fixed:[/] created database and schema")
        elif ok_db:
            migrate(p["db"])
            console.print("[green]Fixed/verified:[/] schema migrations and app-data layout")
        else:
            console.print("[yellow]Action required:[/] database is damaged; use `jacknet repair --yes` to preserve it and create a clean DB.")
    if not shutil.which("nmap"):
        console.print("[yellow]Action required:[/] install Nmap and ensure `nmap` is on PATH for service/OS fingerprinting.")


if __name__ == "__main__":
    app()
