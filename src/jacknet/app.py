from __future__ import annotations

from .cli import app
from .capture_cli import capture_app, database_report_cmd, dossier_cmd
from .knowledge import evidence_cmd, graph_cmd, sites_cmd

app.add_typer(capture_app, name="capture")
app.command("dossier")(dossier_cmd)
app.command("db-report")(database_report_cmd)
app.command("evidence")(evidence_cmd)
app.command("sites")(sites_cmd)
app.command("graph")(graph_cmd)

__all__ = ["app"]
