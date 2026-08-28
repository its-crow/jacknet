from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from .models import Device
from .db import connect, migrate
from .config import paths
from .network_context import ensure_network


def record(devices: list[Device], path: Path | None = None):
    db_path = path or paths()["db"]
    migrate(db_path)
    network_id, _ = ensure_network()
    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as con:
        for d in devices:
            device_id = None
            if d.mac:
                row = con.execute("SELECT device_id FROM devices WHERE canonical_mac=?", (d.mac.lower(),)).fetchone()
                if row:
                    device_id = row[0]
                    con.execute("UPDATE devices SET last_seen=?, manufacturer=COALESCE(?,manufacturer), model=COALESCE(?,model), device_type=COALESCE(?,device_type), confidence=MAX(confidence,?) WHERE device_id=?",
                                (now, d.manufacturer, d.model, d.device_type, d.confidence, device_id))
                else:
                    cur = con.execute("INSERT INTO devices(canonical_mac,first_seen,last_seen,manufacturer,model,device_type,confidence) VALUES(?,?,?,?,?,?,?)",
                                      (d.mac.lower(), now, now, d.manufacturer, d.model, d.device_type, d.confidence))
                    device_id = cur.lastrowid
            elif d.ip:
                row = con.execute("SELECT device_id FROM device_network_addresses WHERE network_id=? AND ip=? ORDER BY last_seen DESC LIMIT 1", (network_id, d.ip)).fetchone()
                if row: device_id = row[0]

            cur = con.execute("""INSERT INTO observations
                (device_id, observed_at, ip, mac, hostname, manufacturer, model, device_type, os, confidence, payload, network_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (device_id, now, d.ip, d.mac, d.hostname, d.manufacturer, d.model, d.device_type, d.os, d.confidence, json.dumps(d.to_dict()), network_id))
            observation_id = cur.lastrowid

            if device_id is not None and d.ip:
                row = con.execute("SELECT id,observation_count FROM device_network_addresses WHERE network_id=? AND device_id=? AND ip=?", (network_id, device_id, d.ip)).fetchone()
                if row:
                    con.execute("UPDATE device_network_addresses SET last_seen=?,observation_count=?,source='scan' WHERE id=?", (now, int(row[1])+1, row[0]))
                else:
                    con.execute("INSERT INTO device_network_addresses(network_id,device_id,ip,first_seen,last_seen,observation_count,source) VALUES(?,?,?,?,?,1,'scan')", (network_id, device_id, d.ip, now, now))

            for e in d.evidence:
                con.execute("INSERT INTO features(observation_id,feature_type,feature_value,source) VALUES(?,?,?,?)",
                            (observation_id, e.fact, e.value, e.source))
                if device_id is not None:
                    con.execute("INSERT INTO device_features(device_id,observed_at,feature_type,feature_value,source) VALUES(?,?,?,?,?)",
                                (device_id,now,e.fact,str(e.value),e.source))
            if device_id is not None:
                if d.hostname:
                    con.execute("INSERT INTO device_features(device_id,observed_at,feature_type,feature_value,source) VALUES(?,?,?,?,?)",(device_id,now,'hostname',d.hostname,'scan'))
                for p in d.open_ports:
                    if p.get('port'):
                        con.execute("INSERT INTO device_features(device_id,observed_at,feature_type,feature_value,source) VALUES(?,?,?,?,?)",(device_id,now,'open_port',str(p['port']),'nmap'))


def latest(path: Path | None = None, limit: int = 100):
    db_path = path or paths()["db"]
    migrate(db_path)
    with connect(db_path) as con:
        return con.execute("""SELECT observed_at,ip,mac,hostname,manufacturer,model,device_type,confidence
            FROM observations ORDER BY id DESC LIMIT ?""", (limit,)).fetchall()
