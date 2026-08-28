from __future__ import annotations

import os
from pathlib import Path

__version__ = "0.4.0"


def _add_windows_wireshark_to_path() -> None:
    """Make standard Wireshark CLI installs discoverable without manual PATH edits."""
    if os.name != "nt":
        return

    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark",
    ]
    current = os.environ.get("PATH", "")
    entries = {p.casefold() for p in current.split(os.pathsep) if p}

    for directory in candidates:
        if not ((directory / "tshark.exe").exists() or (directory / "dumpcap.exe").exists()):
            continue
        value = str(directory)
        if value.casefold() not in entries:
            os.environ["PATH"] = value + os.pathsep + current
        break


_add_windows_wireshark_to_path()
