"""
Rogue access point and evil-twin indicators.
"""

from __future__ import annotations

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def detect_rogue_aps(networks: list[dict]) -> dict[str, list[dict]]:
    """Analyse all scanned networks for rogue AP indicators."""
    ssid_groups: dict[str, list[dict]] = defaultdict(list)
    for network in networks:
        ssid = str(network.get("ssid", "<hidden>"))
        ssid_groups[ssid].append(network)

    rogue_findings: dict[str, list[dict]] = {}

    for ssid, group in ssid_groups.items():
        if ssid == "<hidden>" or len(group) < 2:
            continue

        encryption_types = {str(item.get("encryption", "UNKNOWN")) for item in group}
        for network in group:
            bssid = str(network.get("bssid", ""))
            findings = [_finding_duplicate_ssid(ssid, group, network)]

            if len(encryption_types) > 1:
                findings.append(_finding_enc_mismatch(ssid, encryption_types))

            if network.get("encryption") == "OPEN":
                encrypted_siblings = [
                    item
                    for item in group
                    if item.get("encryption") not in {"OPEN", "UNKNOWN"} and item.get("bssid") != bssid
                ]
                if encrypted_siblings:
                    findings.append(_finding_evil_twin(ssid, network, encrypted_siblings))

            if findings and bssid:
                rogue_findings[bssid] = findings
                logger.warning(
                    "Rogue AP indicators detected",
                    extra={
                        "event": "rogue_ap_detected",
                        "ssid": ssid,
                        "bssid": bssid,
                        "finding_count": len(findings),
                    },
                )

    return rogue_findings


def _finding_duplicate_ssid(ssid: str, group: list[dict], network: dict) -> dict:
    other_bssids = [str(item.get("bssid", "")) for item in group if item.get("bssid") != network.get("bssid")]
    bssids = [str(network.get("bssid", "")), *other_bssids]
    return {
        "category": "Rogue AP",
        "check": "Duplicate SSID",
        "risk_level": "High",
        "description": (
            f"The SSID '{ssid}' is broadcast by {len(group)} access points "
            f"(BSSIDs: {', '.join(bssids)}). This may be normal in managed enterprise "
            "deployments, but it is suspicious on small or unmanaged networks."
        ),
        "unauthorized_access_scenario": (
            "An attacker can clone a legitimate SSID with a stronger signal. Clients "
            "configured to auto-connect may associate with the rogue AP."
        ),
        "recommendation": (
            "Verify each BSSID against a known AP inventory. Remove unapproved devices "
            "and use 802.1X or wireless intrusion monitoring for managed environments."
        ),
        "penalty_score": 30,
    }


def _finding_enc_mismatch(ssid: str, enc_types: set[str]) -> dict:
    return {
        "category": "Rogue AP",
        "check": "Encryption Mismatch",
        "risk_level": "Critical",
        "description": (
            f"APs broadcasting SSID '{ssid}' use inconsistent encryption types: {', '.join(sorted(enc_types))}."
        ),
        "unauthorized_access_scenario": (
            "A rogue AP may advertise the same SSID with weaker security to encourage "
            "clients to downgrade or connect without the expected protection."
        ),
        "recommendation": (
            "Audit all APs broadcasting this SSID. Standardise encryption settings and remove unrecognised hardware."
        ),
        "penalty_score": 40,
    }


def _finding_evil_twin(ssid: str, rogue_candidate: dict, encrypted_siblings: list[dict]) -> dict:
    sibling_bssids = [str(item.get("bssid", "")) for item in encrypted_siblings]
    return {
        "category": "Rogue AP",
        "check": "Probable Evil-Twin AP",
        "risk_level": "Critical",
        "description": (
            f"OPEN network '{ssid}' (BSSID: {rogue_candidate.get('bssid', '')}) coexists "
            f"with encrypted APs using the same SSID ({', '.join(sibling_bssids)})."
        ),
        "unauthorized_access_scenario": (
            "Clients may connect to the open clone and expose traffic to interception or man-in-the-middle attacks."
        ),
        "recommendation": (
            "Treat this as a security incident. Do not connect to the open clone, locate "
            "the transmitting AP, and enable management frame protection where available."
        ),
        "penalty_score": 50,
    }
