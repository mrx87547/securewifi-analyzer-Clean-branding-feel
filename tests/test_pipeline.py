import scanner.scan as scan_module
from main import run_analysis
from scanner.scan import scan_networks


def test_scan_networks_requires_explicit_demo_mode(monkeypatch):
    monkeypatch.setattr(scan_module, "check_tool", lambda _tool: False)

    assert scan_networks("wlan0", timeout=1) == []


def test_scan_networks_demo_mode_returns_deduplicated_networks(monkeypatch):
    monkeypatch.setattr(scan_module, "check_tool", lambda _tool: False)

    networks = scan_networks("wlan0", timeout=1, demo_mode=True)

    assert len(networks) == 8
    assert networks[0]["signal"] >= networks[-1]["signal"]


def test_run_analysis_demo_populates_findings_and_risk():
    networks, metadata = run_analysis("wlan0", 1, demo_mode=True)

    assert metadata["demo_mode"] is True
    assert len(networks) == 8
    assert all("risk" in network for network in networks)
    assert networks[0]["risk"]["score"] >= networks[-1]["risk"]["score"]
