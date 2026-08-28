from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import typer

import jacknet.capture_cli as capture_cli


def test_windows_physical_adapters_filters_to_up_ethernet_wifi(monkeypatch):
    payload = [
        {
            "Name": "Wi-Fi",
            "InterfaceDescription": "Intel(R) Wi-Fi 6E AX211",
            "InterfaceGuid": "{03600568-03EC-4516-9ECC-403049EC5DFD}",
            "MediaType": "Native 802.11",
            "LinkSpeed": "866 Mbps",
        },
        {
            "Name": "Ethernet",
            "InterfaceDescription": "Realtek PCIe GbE Family Controller",
            "InterfaceGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "MediaType": "802.3",
            "LinkSpeed": "1 Gbps",
        },
    ]

    monkeypatch.setattr(capture_cli.os, "name", "nt")
    monkeypatch.setattr(
        capture_cli.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr=""),
    )

    rows = capture_cli._windows_physical_adapters()
    assert [row["name"] for row in rows] == ["Wi-Fi", "Ethernet"]
    assert rows[0]["guid"] == "03600568-03EC-4516-9ECC-403049EC5DFD"


def test_capture_candidates_matches_physical_guid_and_excludes_loopback(monkeypatch):
    monkeypatch.setattr(capture_cli.os, "name", "nt")
    monkeypatch.setattr(
        capture_cli,
        "_windows_physical_adapters",
        lambda: [
            {
                "name": "Wi-Fi",
                "description": "Intel(R) Wi-Fi 6E AX211",
                "guid": "03600568-03EC-4516-9ECC-403049EC5DFD",
                "media": "Native 802.11",
                "link_speed": "866 Mbps",
            }
        ],
    )
    monkeypatch.setattr(
        capture_cli,
        "list_interfaces",
        lambda: [
            ("3", r"\Device\NPF_{03600568-03EC-4516-9ECC-403049EC5DFD} (Wi-Fi)"),
            ("5", r"\Device\NPF_{4DB939BB-A22E-4621-B928-998D18F8A004} (Npcap Loopback Adapter)"),
            ("8", r"\\.\USBPcap1 (USBPcap1)"),
        ],
    )

    rows = capture_cli._capture_candidates()
    assert len(rows) == 1
    assert rows[0]["id"] == "3"
    assert rows[0]["name"] == "Wi-Fi"


def test_live_rejects_nonphysical_interface(monkeypatch):
    monkeypatch.setattr(
        capture_cli,
        "_capture_candidates",
        lambda: [{"id": "3", "name": "Wi-Fi", "description": "", "capture": "", "link_speed": ""}],
    )

    with pytest.raises(typer.Exit) as exc:
        capture_cli.live_cmd(interface="5", duration=1, monitor=False, output=None)
    assert exc.value.exit_code == 2


def test_live_zero_packets_is_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        capture_cli,
        "_capture_candidates",
        lambda: [{"id": "3", "name": "Wi-Fi", "description": "", "capture": "", "link_speed": ""}],
    )
    monkeypatch.setattr(capture_cli, "live_capture", lambda *args, **kwargs: tmp_path / "capture.pcapng")
    monkeypatch.setattr(
        capture_cli,
        "ingest_capture",
        lambda *args, **kwargs: {
            "packets": 0,
            "devices": 0,
            "capture": str(tmp_path / "capture.pcapng"),
        },
    )
    monkeypatch.setattr(capture_cli, "run_learning", lambda: {"promoted": 0})

    with pytest.raises(typer.Exit) as exc:
        capture_cli.live_cmd(
            interface="3",
            duration=1,
            monitor=False,
            output=tmp_path / "capture.pcapng",
        )
    assert exc.value.exit_code == 2
