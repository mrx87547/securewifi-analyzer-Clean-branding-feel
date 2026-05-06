"""
Structured JSON report generation.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from config.settings import OUTPUT_DIR, TOOL_NAME, TOOL_VERSION
from utils.helpers import atomic_write_text, ensure_dir, unique_filename

logger = logging.getLogger(__name__)


def save_json_report(
    networks: list[dict],
    scan_meta: dict,
    output_path: str | None = None,
) -> str:
    """Serialise analysis results to a JSON file."""
    ensure_dir(OUTPUT_DIR)
    path = output_path or unique_filename(OUTPUT_DIR, "wsa_report", ".json")
    target = Path(path)
    ensure_dir(target.parent if target.parent != Path("") else Path("."))

    report = _build_report(networks, scan_meta)
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    atomic_write_text(target, payload)
    logger.info("JSON report saved", extra={"event": "json_report_saved", "path": str(target)})
    return str(target)


def _build_report(networks: list[dict], scan_meta: dict) -> dict:
    stats = _compute_stats(networks)
    return {
        "report_metadata": {
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "generated_at": datetime.now().isoformat(),
            "interface": scan_meta.get("interface", "unknown"),
            "scan_started": scan_meta.get("timestamp", ""),
            "duration_seconds": scan_meta.get("duration", 0),
            "demo_mode": bool(scan_meta.get("demo_mode", False)),
            "total_networks_found": len(networks),
        },
        "statistics": stats,
        "networks": [_serialise_network(network) for network in networks],
        "recommendations": _global_recommendations(networks),
    }


def _serialise_network(network: dict) -> dict:
    risk = network.get("risk", {})
    return {
        "ssid": network.get("ssid", "<hidden>"),
        "bssid": network.get("bssid", ""),
        "signal_dbm": network.get("signal", -100),
        "signal_quality": network.get("signal_quality", "Unknown"),
        "channel": network.get("channel", 0),
        "frequency_ghz": network.get("frequency", 0.0),
        "encryption": network.get("encryption", "UNKNOWN"),
        "hidden": network.get("hidden", False),
        "wps": network.get("wps", False),
        "risk": {
            "score": risk.get("score", 0),
            "label": risk.get("label", "Unknown"),
            "top_risk": risk.get("top_risk", ""),
            "breakdown": risk.get("breakdown", {}),
        },
        "vulnerabilities": {
            "encryption": _clean_finding(network.get("encryption_analysis", {})),
            "configuration": [_clean_finding(finding) for finding in network.get("config_findings", [])],
            "rogue_ap": [_clean_finding(finding) for finding in network.get("rogue_findings", [])],
        },
    }


def _clean_finding(finding: dict) -> dict:
    drop_keys = {"penalty_score", "raw_caps"}
    return {key: value for key, value in finding.items() if key not in drop_keys}


def _compute_stats(networks: list[dict]) -> dict:
    enc_counts: dict[str, int] = {}
    label_counts: dict[str, int] = {}
    total_score = 0

    for network in networks:
        encryption = network.get("encryption", "UNKNOWN")
        label = network.get("risk", {}).get("label", "Unknown")
        score = network.get("risk", {}).get("score", 0)

        enc_counts[encryption] = enc_counts.get(encryption, 0) + 1
        label_counts[label] = label_counts.get(label, 0) + 1
        total_score += score

    average = round(total_score / len(networks), 1) if networks else 0
    return {
        "total_networks": len(networks),
        "average_risk_score": average,
        "by_encryption": enc_counts,
        "by_risk_label": label_counts,
        "open_networks": enc_counts.get("OPEN", 0),
        "wep_networks": enc_counts.get("WEP", 0),
        "wps_enabled_count": sum(1 for network in networks if network.get("wps")),
        "hidden_ssid_count": sum(1 for network in networks if network.get("hidden")),
        "critical_count": label_counts.get("Critical", 0),
        "vulnerable_count": label_counts.get("Vulnerable", 0),
    }


def _global_recommendations(networks: list[dict]) -> list[str]:
    seen: set[str] = set()
    recommendations: list[str] = []

    for network in networks:
        findings = [
            network.get("encryption_analysis", {}),
            *network.get("config_findings", []),
            *network.get("rogue_findings", []),
        ]
        for finding in findings:
            recommendation = finding.get("recommendation", "")
            if recommendation and recommendation not in seen:
                seen.add(recommendation)
                recommendations.append(recommendation)

    return recommendations
