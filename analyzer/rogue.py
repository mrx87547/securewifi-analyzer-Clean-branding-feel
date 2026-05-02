"""
analyzer/rogue.py
Detects potential rogue access points by looking for:
  - Duplicate SSIDs with different BSSIDs
  - Mismatched encryption for the same SSID
  - Evil-twin indicators (same SSID, similar signal, open encryption)
"""

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


# ── Public API ─────────────────────────────────────────────────────────────────

def detect_rogue_aps(networks: list[dict]) -> dict[str, list[dict]]:
    """Analyse all scanned networks for rogue / evil-twin AP indicators.

    Args:
        networks: Full list of normalised network dicts from the scanner.

    Returns:
        Dict mapping BSSID → list of rogue findings for that network.
        Networks with no rogue indicators will not appear in the dict.
    """
    # Group networks by SSID
    ssid_groups: dict[str, list[dict]] = defaultdict(list)
    for net in networks:
        ssid = net.get("ssid", "<hidden>")
        ssid_groups[ssid].append(net)

    rogue_findings: dict[str, list[dict]] = {}

    for ssid, group in ssid_groups.items():
        if ssid == "<hidden>" or len(group) < 2:
            continue   # Single network per SSID → no rogue concern

        # Multiple APs sharing this SSID — inspect each pair
        for net in group:
            bssid    = net["bssid"]
            findings = []

            # Duplicate SSID (always flag)
            findings.append(_finding_duplicate_ssid(ssid, group, net))

            # Encryption mismatch within same SSID
            enc_types = {n["encryption"] for n in group}
            if len(enc_types) > 1:
                findings.append(_finding_enc_mismatch(ssid, enc_types, net))

            # Open network with same name as encrypted siblings → strong evil-twin signal
            if net["encryption"] == "OPEN":
                encrypted_siblings = [
                    n for n in group
                    if n["encryption"] not in ("OPEN", "UNKNOWN") and n["bssid"] != bssid
                ]
                if encrypted_siblings:
                    findings.append(_finding_evil_twin(ssid, net, encrypted_siblings))

            if findings:
                rogue_findings[bssid] = findings
                logger.warning(
                    "Rogue/evil-twin indicators for SSID '%s' at BSSID %s: %d finding(s)",
                    ssid,
                    bssid,
                    len(findings),
                )

    return rogue_findings


# ── Finding Builders ──────────────────────────────────────────────────────────

def _finding_duplicate_ssid(
    ssid: str,
    group: list[dict],
    network: dict,
) -> dict:
    """Build a duplicate-SSID finding.

    Args:
        ssid:    The shared SSID string.
        group:   All networks sharing this SSID.
        network: The specific network being flagged.

    Returns:
        Finding dict.
    """
    other_bssids = [n["bssid"] for n in group if n["bssid"] != network["bssid"]]
    return {
        "category":    "Rogue AP",
        "check":       "Duplicate SSID",
        "risk_level":  "High",
        "description": (
            f"The SSID '{ssid}' is broadcast by {len(group)} different access points "
            f"(BSSIDs: {', '.join([network['bssid']] + other_bssids)}).  "
            f"While this is normal for enterprise mesh networks or large deployments, "
            f"on residential or small-business networks it often indicates a rogue AP."
        ),
        "unauthorized_access_scenario": (
            "An attacker can set up a 'evil-twin' access point that clones the SSID "
            "of a legitimate network.  Clients configured to auto-connect will "
            "associate with whichever AP has the strongest signal — often the rogue. "
            "Once connected, all traffic flows through the attacker's device, "
            "enabling credential theft, session hijacking, and malware injection."
        ),
        "recommendation": (
            "Investigate all access points broadcasting this SSID and verify each "
            "BSSID against your known hardware inventory.  Implement 802.1X "
            "(RADIUS) authentication to prevent unauthorised APs from accepting "
            "client connections.  Deploy a Wireless Intrusion Prevention System (WIPS)."
        ),
        "penalty_score": 30,
    }


def _finding_enc_mismatch(
    ssid:      str,
    enc_types: set[str],
    network:   dict,
) -> dict:
    """Build an encryption-mismatch finding.

    Args:
        ssid:      The shared SSID.
        enc_types: All encryption types seen for this SSID.
        network:   The specific network being flagged.

    Returns:
        Finding dict.
    """
    return {
        "category":    "Rogue AP",
        "check":       "Encryption Mismatch",
        "risk_level":  "Critical",
        "description": (
            f"APs broadcasting SSID '{ssid}' use inconsistent encryption types: "
            f"{', '.join(sorted(enc_types))}.  Legitimate access points in the same "
            f"network should use identical security settings."
        ),
        "unauthorized_access_scenario": (
            "A rogue AP operator frequently uses weaker or no encryption on their "
            "evil-twin to avoid needing the real password.  Clients that auto-connect "
            "to the SSID may negotiate a downgraded security handshake, exposing "
            "their traffic.  WPA2-downgrade attacks can force clients to connect to "
            "WPA or even open networks."
        ),
        "recommendation": (
            "Immediately audit all physical access points.  Remove any unrecognised "
            "hardware.  Standardise encryption to WPA3 across all APs.  Enable "
            "802.11w Management Frame Protection to prevent disassociation attacks "
            "used to push clients to rogue APs."
        ),
        "penalty_score": 40,
    }


def _finding_evil_twin(
    ssid:               str,
    rogue_candidate:    dict,
    encrypted_siblings: list[dict],
) -> dict:
    """Build an evil-twin finding for an open AP cloning an encrypted SSID.

    Args:
        ssid:               The shared SSID.
        rogue_candidate:    The open (potentially rogue) network.
        encrypted_siblings: Encrypted networks sharing the same SSID.

    Returns:
        Finding dict.
    """
    sibling_bssids = [n["bssid"] for n in encrypted_siblings]
    return {
        "category":    "Rogue AP",
        "check":       "Probable Evil-Twin AP",
        "risk_level":  "Critical",
        "description": (
            f"OPEN network '{ssid}' (BSSID: {rogue_candidate['bssid']}) coexists "
            f"with encrypted AP(s) using the same SSID "
            f"({', '.join(sibling_bssids)}).  This is a strong indicator of a "
            f"deliberate evil-twin attack."
        ),
        "unauthorized_access_scenario": (
            "The attacker broadcasts an open AP with the same SSID as a legitimate "
            "encrypted network.  Clients that connect to the rogue AP transmit all "
            "data unencrypted.  The attacker can capture login credentials, session "
            "tokens, API keys, and any other data transmitted over the connection.  "
            "SSL stripping tools can additionally downgrade HTTPS connections on "
            "browsers that don't enforce HSTS."
        ),
        "recommendation": (
            "Treat this as a security incident.  Do not connect to this network. "
            "Report the rogue AP to the venue's IT/security team.  Use a VPN on "
            "all devices.  Enable 802.11w MFP on legitimate APs to harden against "
            "de-authentication attacks used to push clients onto rogue APs."
        ),
        "penalty_score": 50,
    }
