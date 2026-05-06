import json

import pytest

from main import build_parser, compare_scans, save_to_history
from reporting.report_json import save_json_report
from utils.helpers import InputValidationError, load_json_file


def test_json_report_is_written_and_contains_expected_metadata(tmp_path):
    network = {
        "ssid": "Lab[WiFi]",
        "bssid": "AA:BB:CC:11:22:33",
        "signal": -50,
        "signal_quality": "Excellent",
        "channel": 6,
        "frequency": 2.437,
        "encryption": "WPA2",
        "hidden": False,
        "wps": False,
        "risk": {"score": 25, "label": "Moderate", "top_risk": "WPA2", "breakdown": {}},
        "encryption_analysis": {"recommendation": "Use WPA3.", "penalty_score": 25},
        "config_findings": [],
        "rogue_findings": [],
    }
    output = tmp_path / "report.json"

    path = save_json_report([network], {"interface": "wlan0", "duration": 1, "demo_mode": True}, str(output))
    data = json.loads(output.read_text(encoding="utf-8"))

    assert path == str(output)
    assert data["report_metadata"]["demo_mode"] is True
    assert data["networks"][0]["ssid"] == "Lab[WiFi]"
    assert "penalty_score" not in data["networks"][0]["vulnerabilities"]["encryption"]


def test_compare_scans_handles_invalid_json_extension(tmp_path, capsys):
    bad = tmp_path / "report.txt"
    bad.write_text("{}", encoding="utf-8")

    compare_scans(str(bad), str(bad))

    assert "Failed to load reports" in capsys.readouterr().out


def test_load_json_file_rejects_oversized_input(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")

    with pytest.raises(InputValidationError):
        load_json_file(report, max_bytes=1)


def test_cli_rejects_unsafe_interface_name():
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--scan", "--interface", "wlan0;rm"])

    assert exc.value.code == 2


def test_save_to_history_bounds_entries(tmp_path, monkeypatch):
    history_file = tmp_path / "scan_history.json"
    monkeypatch.setattr("main.HISTORY_FILE", str(history_file))
    monkeypatch.setattr("main.OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr("main.MAX_HISTORY_ENTRIES", 2)

    network = {"risk": {"label": "Critical", "score": 80}}
    for index in range(3):
        save_to_history([network], {"timestamp": str(index), "interface": "wlan0", "demo_mode": True})

    history = json.loads(history_file.read_text(encoding="utf-8"))
    assert len(history) == 2
    assert history[0]["timestamp"] == "1"
    assert history[1]["timestamp"] == "2"
