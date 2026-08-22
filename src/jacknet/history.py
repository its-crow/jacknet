from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from .models import Device
from .db import connect, migrate
from .config import paths


def record(devices: list[Device], path: Path | None = None):
    db_path = path or paths()["db"]
    migrate(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as con:
        for d in devices:
            device_id = None
            if d.mac:
                row = con.execute("SELECT device_id FROM devices WHERE canonical_mac=?", (d.mac,)).fetchone()
                if row:
                    device_id = row[0]
                    con.execute("UPDATE devices SET last_seen=?, manufacturer=?, model=?, device_type=?, confidence=? WHERE device_id=?",
                                (now, d.manufacturer, d.model, d.device_type, d.confidence, device_id))
                else:
                    cur = con.execute("INSERT INTO devices(canonical_mac,first_seen,last_seen,manufacturer,model,device_type,confidence) VALUES(?,?,?,?,?,?,?)",
                                      (d.mac, now, now, d.manufacturer, d.model, d.device_type, d.confidence))
                    device_id = cur.lastrowid
            cur = con.execute("""INSERT INTO observations
                (device_id, observed_at, ip, mac, hostname, manufacturer, model, device_type, os, confidence, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (device_id, now, d.ip, d.mac, d.hostname, d.manufacturer, d.model, d.device_type, d.os, d.confidence, json.dumps(d.to_dict())))
            observation_id = cur.lastrowid
            for e in d.evidence:
                con.execute("INSERT INTO features(observation_id,feature_type,feature_value,source) VALUES(?,?,?,?)",
                            (observation_id, e.source, e.fact, e.source))


def latest(path: Path | None = None, limit: int = 100):
    db_path = path or paths()["db"]
    migrate(db_path)
    with connect(db_path) as con:
        return con.execute("""SELECT observed_at,ip,mac,hostname,manufacturer,model,device_type,confidence
            FROM observations ORDER BY id DESC LIMIT ?""", (limit,)).fetchall()
