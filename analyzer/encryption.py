"""
Encryption posture analysis.
"""

from __future__ import annotations

import logging

from config.settings import ENCRYPTION_SCORES

logger = logging.getLogger(__name__)

_ENCRYPTION_FINDINGS: dict[str, dict] = {
    "OPEN": {
        "vulnerability": "Open / Unencrypted Network",
        "risk_level": "Critical",
        "description": (
            "The network broadcasts without encryption or authentication. Traffic can "
            "be captured or modified by anyone within radio range."
        ),
        "unauthorized_access_scenario": (
            "A nearby attacker can join the AP without credentials and observe DNS, "
            "HTTP, and other clear-text traffic. They may also attempt man-in-the-middle "
            "attacks against connected clients."
        ),
        "recommendation": (
            "Enable WPA3 Personal. If unsupported, use WPA2-AES with a strong random "
            "passphrase. Avoid transmitting sensitive data on open hotspots without a VPN."
        ),
    },
    "WEP": {
        "vulnerability": "WEP Encryption (Broken Protocol)",
        "risk_level": "Critical",
        "description": (
            "WEP was deprecated in 2004 and is cryptographically broken. Its RC4-based "
            "design allows key recovery from captured traffic."
        ),
        "unauthorized_access_scenario": (
            "An attacker can passively capture enough WEP frames and recover the network "
            "key with public tooling, then access the network as an authenticated client."
        ),
        "recommendation": (
            "Replace WEP with WPA3 immediately. Retire devices that only support WEP and "
            "avoid sending sensitive data over this network."
        ),
    },
    "WPA": {
        "vulnerability": "WPA-TKIP (Deprecated Protocol)",
        "risk_level": "High",
        "description": (
            "WPA-TKIP was a transitional replacement for WEP and is deprecated. It does "
            "not meet modern wireless security requirements."
        ),
        "unauthorized_access_scenario": (
            "Attackers may exploit protocol weaknesses or capture authentication handshakes "
            "for offline password guessing, especially when passphrases are weak or reused."
        ),
        "recommendation": (
            "Disable WPA and TKIP. Use WPA3 Personal or WPA2-AES with a long random passphrase and current AP firmware."
        ),
    },
    "WPA2": {
        "vulnerability": "WPA2-PSK (Passphrase Dependent)",
        "risk_level": "Moderate",
        "description": (
            "WPA2-AES is broadly secure when paired with a strong passphrase, but captured "
            "handshakes can be attacked offline if passwords are weak."
        ),
        "unauthorized_access_scenario": (
            "An attacker who captures a 4-way handshake can run offline dictionary attacks. "
            "WPS, default passwords, and short passphrases greatly increase compromise risk."
        ),
        "recommendation": (
            "Use at least 16 random characters, disable WPS, enable Management Frame "
            "Protection where supported, and plan a WPA3 upgrade."
        ),
    },
    "WPA3": {
        "vulnerability": "WPA3 (Secure Configuration Detected)",
        "risk_level": "Low",
        "description": (
            "WPA3 uses SAE to resist offline dictionary attacks and is the current best "
            "practice for personal wireless networks."
        ),
        "unauthorized_access_scenario": (
            "WPA3 materially raises attack cost, but outdated firmware or transition mode "
            "can still expose downgrade or implementation risks."
        ),
        "recommendation": (
            "Keep AP firmware current, prefer WPA3-only mode where compatible, and require Management Frame Protection."
        ),
    },
    "UNKNOWN": {
        "vulnerability": "Unidentified Encryption",
        "risk_level": "Medium",
        "description": ("The scanner could not determine the network's encryption from available data."),
        "unauthorized_access_scenario": (
            "Unknown security posture prevents reliable risk assessment and may indicate a "
            "non-standard or unsupported configuration."
        ),
        "recommendation": (
            "Manually verify AP security settings, update firmware, and confirm WPA2-AES or WPA3 is enforced."
        ),
    },
}


def analyse_encryption(network: dict) -> dict:
    """Build an encryption analysis finding for one network."""
    encryption = str(network.get("encryption", "UNKNOWN")).upper()
    template = _ENCRYPTION_FINDINGS.get(encryption, _ENCRYPTION_FINDINGS["UNKNOWN"])

    finding = {
        "category": "Encryption",
        "encryption_type": encryption,
        "vulnerability": template["vulnerability"],
        "risk_level": template["risk_level"],
        "description": template["description"],
        "unauthorized_access_scenario": template["unauthorized_access_scenario"],
        "recommendation": template["recommendation"],
        "penalty_score": ENCRYPTION_SCORES.get(encryption, 60),
        "wps_enabled": bool(network.get("wps", False)),
    }

    if finding["wps_enabled"] and encryption in {"WPA", "WPA2"}:
        finding["wps_warning"] = (
            "WPS is enabled. PIN mode drastically reduces authentication search space "
            "and should be disabled on production networks."
        )
        finding["penalty_score"] = min(100, int(finding["penalty_score"]) + 10)

    logger.debug(
        "Encryption analysis completed",
        extra={
            "event": "encryption_analysed",
            "bssid": network.get("bssid", ""),
            "encryption": encryption,
            "penalty": finding["penalty_score"],
        },
    )
    return finding
