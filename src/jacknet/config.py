from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

APP_NAME = "jacknet"
CONFIG_DIR = Path.home() / ".config" / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_DATA_DIR = Path.home() / ".jacknet"
SCHEMA_VERSION = 4


def load_config() -> dict:
    if not CONFIG_FILE.exists(): return {}
    try: return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception: return {}


def save_config(data_dir: Path) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"data_dir": str(data_dir.expanduser().resolve()), "schema_version": SCHEMA_VERSION}
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_FILE)


def data_dir() -> Path:
    env = os.getenv("JACKNET_DATA_DIR")
    if env: return Path(env).expanduser().resolve()
    cfg = load_config(); raw = cfg.get("data_dir")
    return Path(raw).expanduser().resolve() if raw else DEFAULT_DATA_DIR


def paths(root: Path | None = None) -> dict[str, Path]:
    root = (root or data_dir()).expanduser().resolve()
    return {"root": root, "db": root / "jacknet.db", "reports": root / "reports", "backups": root / "backups", "cache": root / "cache", "logs": root / "logs", "exports": root / "exports", "fingerprints": root / "fingerprints"}


def ensure_layout(root: Path | None = None) -> dict[str, Path]:
    p = paths(root); p["root"].mkdir(parents=True, exist_ok=True)
    for key in ("reports", "backups", "cache", "logs", "exports", "fingerprints"): p[key].mkdir(parents=True, exist_ok=True)
    return p


def relocate_data(new_root: Path, copy_existing: bool = True) -> Path:
    old = data_dir(); new_root = new_root.expanduser().resolve(); new_root.mkdir(parents=True, exist_ok=True)
    if copy_existing and old.exists() and old != new_root:
        for item in old.iterdir():
            dest = new_root / item.name
            if dest.exists(): continue
            if item.is_dir(): shutil.copytree(item, dest)
            else: shutil.copy2(item, dest)
    save_config(new_root); ensure_layout(new_root); return new_root
