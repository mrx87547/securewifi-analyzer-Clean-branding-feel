"""
reporting/report_json.py
Serialises a full scan analysis to a structured JSON report file.
"""

import json
import logging
import os
from datetime import datetime

from utils.helpers import ensure_dir, unique_filename
from config.settings import OUTPUT_DIR, TOOL_NAME, TOOL_VERSION

logger = logging.getLogger(__name__)


# ── Public API ─────────────────────────────────────────────────────────────────

def save_json_report(
    networks:  list[dict],
    scan_meta: dict,
    output_path: str | None = None,
) -> str:
    """Serialise the analysis results to a JSON file.

    Args:
        networks:    List of fully-analysed network dicts.
        scan_meta:   Scan metadata (interface, timestamp, etc.).
        output_path: Optional explicit file path.  If None, a timestamped
                     filename inside OUTPUT_DIR is generated.

    Returns:
        Path of the written JSON file.
    """
    ensure_dir(OUTPUT_DIR)
    path = output_path or unique_filename(OUTPUT_DIR, "wsa_report", ".json")

    report = _build_report(networks, scan_meta)

    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        logger.info("JSON report saved → %s", path)
    except OSError as exc:
        logger.error("Failed to write JSON report: %s", exc)
        raise

    return path


# ── Report Builder ─────────────────────────────────────────────────────────────

def _build_report(networks: list[dict], scan_meta: dict) -> dict:
    """Construct the full JSON report structure.

    Args:
        networks:  Analysed networks.
        scan_meta: Scan metadata.

    Returns:
        Serialisable dict.
    """
    stats = _compute_stats(networks)

    return {
        "report_metadata": {
            "tool_name":    TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "generated_at": datetime.now().isoformat(),
            "interface":    scan_meta.get("interface", "unknown"),
            "scan_started": scan_meta.get("timestamp", ""),
            "total_networks_found": len(networks),
        },
        "statistics": stats,
        "networks":   [_serialise_network(n) for n in networks],
        "recommendations": _global_recommendations(networks),
    }


def _serialise_network(net: dict) -> dict:
    """Convert one analysed network dict to a JSON-safe structure.

    Args:
        net: Fully-analysed network dict.

    Returns:
        Clean serialisable dict.
    """
    risk = net.get("risk", {})
    return {
        "ssid":       net.get("ssid", "<hidden>"),
        "bssid":      net.get("bssid", ""),
        "signal_dbm": net.get("signal", -100),
        "channel":    net.get("channel", 0),
        "frequency_ghz": net.get("frequency", 0.0),
        "encryption": net.get("encryption", "UNKNOWN"),
        "hidden":     net.get("hidden", False),
        "wps":        net.get("wps", False),
        "risk": {
            "score":    risk.get("score", 0),
            "label":    risk.get("label", "Unknown"),
            "top_risk": risk.get("top_risk", ""),
            "breakdown": risk.get("breakdown", {}),
        },
        "vulnerabilities": {
            "encryption": _clean_finding(net.get("encryption_analysis", {})),
            "configuration": [_clean_finding(f) for f in net.get("config_findings", [])],
            "rogue_ap":  [_clean_finding(f) for f in net.get("rogue_findings", [])],
        },
    }


def _clean_finding(finding: dict) -> dict:
    """Strip internal-only keys from a finding dict.

    Args:
        finding: Raw finding dict.

    Returns:
        Clean dict suitable for JSON output.
    """
    drop_keys = {"penalty_score", "raw_caps"}
    return {k: v for k, v in finding.items() if k not in drop_keys}


def _compute_stats(networks: list[dict]) -> dict:
    """Compute aggregate statistics across all networks.

    Args:
        networks: Analysed network list.

    Returns:
        Statistics dict.
    """
    enc_counts: dict[str, int] = {}
    label_counts: dict[str, int] = {}
    total_score = 0

    for net in networks:
        enc   = net.get("encryption", "UNKNOWN")
        label = net.get("risk", {}).get("label", "Unknown")
        score = net.get("risk", {}).get("score", 0)

        enc_counts[enc]     = enc_counts.get(enc, 0) + 1
        label_counts[label] = label_counts.get(label, 0) + 1
        total_score += score

    avg = round(total_score / len(networks), 1) if networks else 0

    return {
        "total_networks":      len(networks),
        "average_risk_score":  avg,
        "by_encryption":       enc_counts,
        "by_risk_label":       label_counts,
        "open_networks":       enc_counts.get("OPEN", 0),
        "wep_networks":        enc_counts.get("WEP", 0),
        "wps_enabled_count":   sum(1 for n in networks if n.get("wps")),
        "hidden_ssid_count":   sum(1 for n in networks if n.get("hidden")),
        "critical_count":      label_counts.get("Critical", 0),
        "vulnerable_count":    label_counts.get("Vulnerable", 0),
    }


def _global_recommendations(networks: list[dict]) -> list[str]:
    """Derive top-level recommendations from all network findings.

    Args:
        networks: Analysed networks.

    Returns:
        Deduplicated list of recommendation strings.
    """
    seen:  set[str]  = set()
    recs:  list[str] = []

    for net in networks:
        for source_key in ("encryption_analysis",):
            finding = net.get(source_key, {})
            rec = finding.get("recommendation", "")
            if rec and rec not in seen:
                seen.add(rec)
                recs.append(rec)

        for finding in net.get("config_findings", []) + net.get("rogue_findings", []):
            rec = finding.get("recommendation", "")
            if rec and rec not in seen:
                seen.add(rec)
                recs.append(rec)

    return recs
