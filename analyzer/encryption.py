"""
analyzer/encryption.py
Analyses the encryption configuration of each scanned network and maps it
to a structured finding with risk level and educational recommendations.
"""

import logging
from config.settings import ENCRYPTION_SCORES

logger = logging.getLogger(__name__)


# ── Encryption Finding Templates ──────────────────────────────────────────────

_ENCRYPTION_FINDINGS: dict[str, dict] = {
    "OPEN": {
        "vulnerability":               "Open / Unencrypted Network",
        "risk_level":                  "Critical",
        "description": (
            "The network broadcasts without any encryption or authentication. "
            "All data transmitted over this network is sent in plain-text and "
            "can be captured by anyone within radio range."
        ),
        "unauthorized_access_scenario": (
            "Any device within wireless range can associate with this AP without "
            "providing credentials.  An attacker could passively capture all "
            "traffic (HTTP requests, DNS queries, unencrypted emails) using a "
            "standard packet-capture tool, or perform a man-in-the-middle (MitM) "
            "attack to intercept or modify data in transit."
        ),
        "recommendation": (
            "Enable WPA3 Personal encryption immediately.  If WPA3 is not supported "
            "by the access point, use WPA2-AES.  Never transmit sensitive information "
            "over an open network — use a VPN when on public hotspots."
        ),
    },
    "WEP": {
        "vulnerability":               "WEP Encryption (Broken Protocol)",
        "risk_level":                  "Critical",
        "description": (
            "WEP (Wired Equivalent Privacy) was deprecated in 2004 and is "
            "cryptographically broken.  Its RC4 key-stream can be fully "
            "recovered by statistical analysis of a few thousand captured frames."
        ),
        "unauthorized_access_scenario": (
            "An attacker can capture WEP-encrypted frames passively and use "
            "publicly available statistical attacks to recover the WEP key.  "
            "The time to crack a 64-bit or 128-bit WEP key is typically "
            "under one minute once sufficient IVs are collected, after which "
            "the attacker gains full network access as if they knew the password."
        ),
        "recommendation": (
            "Replace WEP with WPA3 immediately.  Any device so old that it only "
            "supports WEP should be retired.  Do not store or transmit any "
            "sensitive data on WEP-protected networks."
        ),
    },
    "WPA": {
        "vulnerability":               "WPA-TKIP (Deprecated Protocol)",
        "risk_level":                  "High",
        "description": (
            "WPA with TKIP (Temporal Key Integrity Protocol) was introduced as a "
            "patch for WEP and shares several of its weaknesses.  TKIP has been "
            "deprecated since 2012 (IEEE 802.11-2012) and is no longer considered "
            "secure for protecting sensitive data."
        ),
        "unauthorized_access_scenario": (
            "While a full WPA-TKIP key recovery requires more frames than WEP, "
            "practical attacks such as the Beck–Tews and Ohigashi–Morii attacks "
            "can forge short packets and, in some configurations, recover the MIC "
            "key.  Dictionary and rule-based attacks against the WPA handshake "
            "remain highly effective if the passphrase is weak."
        ),
        "recommendation": (
            "Upgrade to WPA3 Personal (or at minimum WPA2-AES).  Disable TKIP "
            "and WPA on the access point settings panel.  Ensure the passphrase "
            "is at least 12 characters with mixed case, digits, and symbols."
        ),
    },
    "WPA2": {
        "vulnerability":               "WPA2-PSK (Moderate Risk — Passphrase Dependent)",
        "risk_level":                  "Moderate",
        "description": (
            "WPA2 with AES-CCMP is currently the most widely deployed wireless "
            "security standard and is considered secure when a strong passphrase "
            "is used.  However, the 4-way handshake can be captured and subjected "
            "to offline dictionary or brute-force attacks."
        ),
        "unauthorized_access_scenario": (
            "An attacker who captures a WPA2 4-way authentication handshake "
            "(which is broadcast in the clear during association) can run it "
            "against wordlists or GPU-accelerated brute-force tools offline, "
            "with no further interaction with the AP.  Common or default passphrases "
            "are typically found within seconds to minutes.  WPS PIN mode (if enabled) "
            "additionally reduces the effective key-space to ~11,000 guesses."
        ),
        "recommendation": (
            "Use a passphrase of at least 16 random characters.  Disable WPS. "
            "Consider upgrading to WPA3 which is resistant to offline dictionary "
            "attacks through Simultaneous Authentication of Equals (SAE).  "
            "Enable Management Frame Protection (802.11w)."
        ),
    },
    "WPA3": {
        "vulnerability":               "WPA3 (Secure Configuration Detected)",
        "risk_level":                  "Low",
        "description": (
            "WPA3 uses Simultaneous Authentication of Equals (SAE) to provide "
            "forward secrecy and resistance to offline dictionary attacks.  "
            "This is the current best-practice for wireless security."
        ),
        "unauthorized_access_scenario": (
            "WPA3 SAE prevents offline dictionary attacks because each connection "
            "attempt requires real-time interaction with the AP, making large-scale "
            "brute-force impractical.  Side-channel attacks against early WPA3 "
            "implementations (Dragonblood, 2019) have been patched in modern firmware."
        ),
        "recommendation": (
            "Keep AP firmware up to date.  Ensure SAE-only mode is selected "
            "(not WPA3-Transition which also allows WPA2).  Enable Management "
            "Frame Protection (802.11w) in required mode."
        ),
    },
    "UNKNOWN": {
        "vulnerability":               "Unidentified Encryption",
        "risk_level":                  "Medium",
        "description": (
            "The encryption type could not be determined from available scan data. "
            "This may indicate a non-standard configuration or tool limitation."
        ),
        "unauthorized_access_scenario": (
            "Without knowing the encryption type it is impossible to assess the "
            "exact risk.  Treat unknown encryption networks with caution."
        ),
        "recommendation": (
            "Manually inspect the access point's admin panel to confirm the "
            "encryption standard and update firmware if needed."
        ),
    },
}


# ── Public API ─────────────────────────────────────────────────────────────────

def analyse_encryption(network: dict) -> dict:
    """Build an encryption analysis finding for a single network.

    Args:
        network: Normalised network dict from the scanner.

    Returns:
        Dict containing vulnerability details, risk level, scenario, and
        recommendation, plus a numeric penalty score (0–100).
    """
    enc = network.get("encryption", "UNKNOWN").upper()
    template = _ENCRYPTION_FINDINGS.get(enc, _ENCRYPTION_FINDINGS["UNKNOWN"])

    finding = {
        "category":                    "Encryption",
        "encryption_type":             enc,
        "vulnerability":               template["vulnerability"],
        "risk_level":                  template["risk_level"],
        "description":                 template["description"],
        "unauthorized_access_scenario": template["unauthorized_access_scenario"],
        "recommendation":              template["recommendation"],
        "penalty_score":               ENCRYPTION_SCORES.get(enc, 60),
        "wps_enabled":                 network.get("wps", False),
    }

    # WPS adds additional risk to WPA/WPA2 networks
    if finding["wps_enabled"] and enc in ("WPA", "WPA2"):
        finding["wps_warning"] = (
            "WPS (Wi-Fi Protected Setup) is enabled.  The WPS PIN attack reduces "
            "the effective authentication key-space from billions of possibilities "
            "to approximately 11,000 guesses, allowing an attacker to recover "
            "the network password in hours without a GPU."
        )
        # Increase penalty slightly
        finding["penalty_score"] = min(100, finding["penalty_score"] + 10)

    logger.debug(
        "Encryption analysis for %s: %s → penalty=%d",
        network.get("ssid"),
        enc,
        finding["penalty_score"],
    )
    return finding
