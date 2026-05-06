"""
Configuration vulnerability checks.
"""

from __future__ import annotations

import logging

from config.settings import DEFAULT_SSID_PREFIXES, SIGNAL_STRONG_THRESHOLD

logger = logging.getLogger(__name__)


def analyse_configuration(network: dict) -> list[dict]:
    """Run configuration checks against a single network."""
    findings: list[dict] = []
    findings.extend(_check_default_ssid(network))
    findings.extend(_check_hidden_ssid(network))
    findings.extend(_check_signal_leakage(network))
    findings.extend(_check_wps(network))
    findings.extend(_check_weak_channel(network))

    logger.debug(
        "Configuration analysis completed",
        extra={
            "event": "configuration_analysed",
            "bssid": network.get("bssid", ""),
            "finding_count": len(findings),
        },
    )
    return findings


def _check_default_ssid(network: dict) -> list[dict]:
    ssid = str(network.get("ssid", "")).lower()
    if ssid in {"<hidden>", ""}:
        return []

    matched_prefix = next((prefix for prefix in DEFAULT_SSID_PREFIXES if ssid.startswith(prefix)), None)
    if not matched_prefix:
        return []

    display_ssid = network.get("ssid", "")
    return [
        {
            "category": "Configuration",
            "check": "Default / Vendor SSID",
            "risk_level": "High",
            "description": (
                f"The SSID '{display_ssid}' matches a vendor or generic default naming "
                f"pattern (prefix: '{matched_prefix}'). Default naming can reveal device "
                "type and may indicate other factory defaults remain unchanged."
            ),
            "unauthorized_access_scenario": (
                "An attacker can infer router vendor or model family, look up common "
                "default credentials, and attempt administrative access against the AP."
            ),
            "recommendation": (
                "Use a unique SSID that does not reveal vendor or model details. Change "
                "the router admin password and keep firmware updated."
            ),
            "penalty_score": 30,
        }
    ]


def _check_hidden_ssid(network: dict) -> list[dict]:
    if not network.get("hidden", False):
        return []

    return [
        {
            "category": "Configuration",
            "check": "Hidden SSID",
            "risk_level": "Low",
            "description": (
                "The network suppresses its SSID in beacon frames. This offers little "
                "practical protection and can increase client probing privacy leakage."
            ),
            "unauthorized_access_scenario": (
                "A passive observer can still identify the hidden network when clients connect or probe for it."
            ),
            "recommendation": (
                "Do not rely on hidden SSIDs as a security control. Use WPA3 or WPA2-AES with a strong passphrase."
            ),
            "penalty_score": 10,
        }
    ]


def _check_signal_leakage(network: dict) -> list[dict]:
    rssi = _safe_int(network.get("signal", -100), -100)
    if rssi < SIGNAL_STRONG_THRESHOLD:
        return []

    return [
        {
            "category": "Signal / RF",
            "check": "Excessive Signal Strength",
            "risk_level": "Medium",
            "description": (
                f"The detected signal strength is {rssi} dBm, above the strong-signal "
                f"threshold of {SIGNAL_STRONG_THRESHOLD} dBm. Coverage may extend beyond "
                "the intended premises."
            ),
            "unauthorized_access_scenario": (
                "A wider RF footprint increases the number of locations from which an "
                "attacker can attempt authentication or capture traffic."
            ),
            "recommendation": (
                "Reduce transmit power if appropriate and perform a site survey to verify "
                "that coverage matches business needs."
            ),
            "penalty_score": 20,
        }
    ]


def _check_wps(network: dict) -> list[dict]:
    if not network.get("wps", False):
        return []

    return [
        {
            "category": "Configuration",
            "check": "WPS Enabled",
            "risk_level": "High",
            "description": (
                "Wi-Fi Protected Setup is enabled. WPS PIN mode has design weaknesses "
                "that reduce the practical authentication search space."
            ),
            "unauthorized_access_scenario": (
                "An attacker may attempt online WPS PIN guessing or exploit weak vendor "
                "PIN generation to recover the wireless passphrase."
            ),
            "recommendation": ("Disable WPS. Replace APs that do not allow WPS to be disabled."),
            "penalty_score": 25,
        }
    ]


def _check_weak_channel(network: dict) -> list[dict]:
    channel = _safe_int(network.get("channel", 0), 0)
    frequency = _safe_float(network.get("frequency", 0.0), 0.0)
    if not (2.4 <= frequency < 2.5):
        return []
    if channel in {0, 1, 6, 11}:
        return []

    return [
        {
            "category": "Configuration",
            "check": "Non-Standard 2.4 GHz Channel",
            "risk_level": "Low",
            "description": (
                f"The network is operating on channel {channel} in the 2.4 GHz band. "
                "Channels 1, 6, and 11 are the standard non-overlapping choices."
            ),
            "unauthorized_access_scenario": (
                "Heavy interference can increase retransmissions and reduce wireless "
                "reliability, which is a useful operational risk signal."
            ),
            "recommendation": ("Use channels 1, 6, or 11 on 2.4 GHz, or prefer 5 GHz / 6 GHz where available."),
            "penalty_score": 5,
        }
    ]


def _safe_int(value: object, default: int) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return default


def _safe_float(value: object, default: float) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default
