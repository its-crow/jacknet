from __future__ import annotations

from .cli import app
from .capture_cli import capture_app, database_report_cmd, dossier_cmd

app.add_typer(capture_app, name="capture")
app.command("dossier")(dossier_cmd)
app.command("db-report")(database_report_cmd)

__all__ = ["app"]
