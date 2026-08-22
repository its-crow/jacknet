from __future__ import annotations
import csv
import html
import json
from pathlib import Path
from .models import Device


def write_report(devices: list[Device], path: Path, fmt: str | None = None) -> Path:
    fmt = (fmt or path.suffix.lstrip(".") or "json").lower()
    if fmt == "jnet":
        payload = {"format": "jacknet-report", "version": 1, "devices": [d.to_dict() for d in devices]}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif fmt == "json":
        path.write_text(json.dumps([d.to_dict() for d in devices], indent=2), encoding="utf-8")
    elif fmt == "txt":
        lines = []
        for d in devices:
            lines += [f"{d.ip}  {d.hostname or '-'}", f"  MAC: {d.mac or '-'}", f"  Manufacturer: {d.manufacturer or '-'}", f"  Model: {d.model or '-'}", f"  Type: {d.device_type or '-'}", f"  OS: {d.os or '-'}", f"  Confidence: {d.confidence}%", f"  Ports: {', '.join(str(p['port']) for p in d.open_ports) or '-'}", ""]
        path.write_text("\n".join(lines), encoding="utf-8")
    elif fmt == "csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ip","mac","hostname","manufacturer","model","device_type","os","confidence"])
            w.writeheader()
            for d in devices:
                w.writerow({k: getattr(d, k) for k in w.fieldnames})
    elif fmt == "html":
        rows = "".join(f"<tr><td>{html.escape(str(d.ip))}</td><td>{html.escape(str(d.hostname or ''))}</td><td>{html.escape(str(d.manufacturer or ''))}</td><td>{html.escape(str(d.model or ''))}</td><td>{html.escape(str(d.device_type or ''))}</td><td>{d.confidence}%</td></tr>" for d in devices)
        path.write_text(f"<!doctype html><meta charset='utf-8'><title>JackNet Report</title><style>body{{font-family:system-ui;background:#111;color:#eee;padding:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #333;padding:.6rem;text-align:left}}</style><h1>JackNet Report</h1><table><tr><th>IP</th><th>Hostname</th><th>Manufacturer</th><th>Model</th><th>Type</th><th>Confidence</th></tr>{rows}</table>", encoding="utf-8")
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
    return path
