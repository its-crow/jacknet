from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .config import paths, ensure_layout, SCHEMA_VERSION

MIGRATIONS: list[tuple[int, str]] = [
    (1, """
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS devices (
        device_id INTEGER PRIMARY KEY,
        canonical_mac TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        user_label TEXT,
        manufacturer TEXT,
        model TEXT,
        device_type TEXT,
        confidence INTEGER DEFAULT 0
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac ON devices(canonical_mac) WHERE canonical_mac IS NOT NULL;

    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY,
        device_id INTEGER,
        observed_at TEXT NOT NULL,
        ip TEXT NOT NULL,
        mac TEXT,
        hostname TEXT,
        manufacturer TEXT,
        model TEXT,
        device_type TEXT,
        os TEXT,
        confidence INTEGER,
        payload TEXT NOT NULL,
        FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );
    CREATE INDEX IF NOT EXISTS idx_obs_mac ON observations(mac);
    CREATE INDEX IF NOT EXISTS idx_obs_ip ON observations(ip);
    CREATE INDEX IF NOT EXISTS idx_obs_device ON observations(device_id);

    CREATE TABLE IF NOT EXISTS labels (
        id INTEGER PRIMARY KEY,
        device_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        manufacturer TEXT,
        model TEXT,
        device_type TEXT,
        source TEXT NOT NULL DEFAULT 'user',
        FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );

    CREATE TABLE IF NOT EXISTS features (
        id INTEGER PRIMARY KEY,
        observation_id INTEGER NOT NULL,
        feature_type TEXT NOT NULL,
        feature_value TEXT NOT NULL,
        source TEXT,
        FOREIGN KEY(observation_id) REFERENCES observations(id)
    );
    CREATE INDEX IF NOT EXISTS idx_features_value ON features(feature_type, feature_value);

    CREATE TABLE IF NOT EXISTS fingerprints (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        manufacturer TEXT,
        model TEXT,
        device_type TEXT,
        status TEXT NOT NULL DEFAULT 'candidate',
        support_count INTEGER NOT NULL DEFAULT 0,
        precision REAL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fingerprint_features (
        id INTEGER PRIMARY KEY,
        fingerprint_id INTEGER NOT NULL,
        feature_type TEXT NOT NULL,
        pattern TEXT NOT NULL,
        weight REAL NOT NULL,
        positive_count INTEGER NOT NULL DEFAULT 0,
        negative_count INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(fingerprint_id) REFERENCES fingerprints(id)
    );

    CREATE TABLE IF NOT EXISTS hypotheses (
        id INTEGER PRIMARY KEY,
        observation_id INTEGER NOT NULL,
        label TEXT NOT NULL,
        confidence REAL NOT NULL,
        explanation TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(observation_id) REFERENCES observations(id)
    );

    CREATE TABLE IF NOT EXISTS corrections (
        id INTEGER PRIMARY KEY,
        device_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        previous_label TEXT,
        corrected_label TEXT NOT NULL,
        notes TEXT,
        FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );
    """),
    (2, """
    CREATE INDEX IF NOT EXISTS idx_labels_device ON labels(device_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprints_name ON fingerprints(name);
    CREATE INDEX IF NOT EXISTS idx_fp_features_lookup ON fingerprint_features(feature_type, pattern);
    """),
]


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = path or paths()["db"]
    ensure_layout(p.parent)
    con = sqlite3.connect(p)
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con


def migrate(path: Path | None = None) -> int:
    with connect(path) as con:
        con.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = {r[0] for r in con.execute("SELECT version FROM schema_migrations")}
        for version, sql in MIGRATIONS:
            if version in applied:
                continue
            con.executescript(sql)
            con.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", (version, datetime.now(timezone.utc).isoformat()))
        con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
    return SCHEMA_VERSION


def integrity(path: Path | None = None) -> tuple[bool, str]:
    p = path or paths()["db"]
    if not p.exists():
        return False, "database missing"
    try:
        with sqlite3.connect(p) as con:
            row = con.execute("PRAGMA integrity_check").fetchone()
            msg = row[0] if row else "unknown"
            return msg == "ok", msg
    except sqlite3.DatabaseError as exc:
        return False, str(exc)


def backup(path: Path | None = None, destination: Path | None = None) -> Path:
    src = path or paths()["db"]
    if not src.exists():
        raise FileNotFoundError(src)
    ensure_layout(src.parent)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = destination or paths(src.parent)["backups"] / f"jacknet-{stamp}.db"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(src) as source, sqlite3.connect(dest) as target:
        source.backup(target)
    return dest


def recover_to_new_db(path: Path | None = None) -> tuple[bool, str]:
    p = path or paths()["db"]
    if not p.exists():
        migrate(p)
        return True, "created missing database"
    ok, msg = integrity(p)
    if ok:
        migrate(p)
        return True, "database healthy"
    broken = p.with_suffix(f".corrupt-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db")
    p.replace(broken)
    migrate(p)
    return True, f"corrupt database preserved as {broken.name}; created a clean database"
