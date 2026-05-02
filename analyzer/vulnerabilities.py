"""
analyzer/vulnerabilities.py
Detects configuration-based vulnerabilities: default SSIDs, hidden networks,
signal leakage, WPS exposure, and weak naming conventions.
"""

import logging
from config.settings import (
    DEFAULT_SSID_PREFIXES,
    SIGNAL_STRONG_THRESHOLD,
    SIGNAL_WEAK_THRESHOLD,
)

logger = logging.getLogger(__name__)


# ── Public API ─────────────────────────────────────────────────────────────────

def analyse_configuration(network: dict) -> list[dict]:
    """Run all configuration checks against a single network.

    Args:
        network: Normalised network dict from the scanner.

    Returns:
        List of vulnerability finding dicts (may be empty if network is clean).
    """
    findings: list[dict] = []

    findings.extend(_check_default_ssid(network))
    findings.extend(_check_hidden_ssid(network))
    findings.extend(_check_signal_leakage(network))
    findings.extend(_check_wps(network))
    findings.extend(_check_weak_channel(network))

    logger.debug(
        "Configuration analysis for '%s': %d finding(s)",
        network.get("ssid"),
        len(findings),
    )
    return findings


# ── Individual Checks ─────────────────────────────────────────────────────────

def _check_default_ssid(network: dict) -> list[dict]:
    """Flag networks broadcasting a vendor-default or generic SSID.

    Args:
        network: Network dict.

    Returns:
        List with one finding if the SSID matches a default prefix, else [].
    """
    ssid = network.get("ssid", "").lower()
    if ssid in ("<hidden>", ""):
        return []

    matched_prefix = next(
        (pfx for pfx in DEFAULT_SSID_PREFIXES if ssid.startswith(pfx)),
        None,
    )
    if not matched_prefix:
        return []

    return [
        {
            "category":    "Configuration",
            "check":       "Default / Vendor SSID",
            "risk_level":  "High",
            "description": (
                f"The SSID '{network['ssid']}' matches the default naming convention "
                f"for vendor equipment (prefix: '{matched_prefix}').  Default SSIDs "
                f"indicate the router may still be using factory-default credentials."
            ),
            "unauthorized_access_scenario": (
                "When a router retains its default SSID, it frequently also retains "
                "its default admin password.  An attacker can look up the default "
                "credentials for the identified vendor online and attempt to log in "
                "to the router's web admin panel, potentially gaining full network "
                "control: port-forwarding changes, DNS hijacking, and disabling "
                "firewall rules."
            ),
            "recommendation": (
                "Change the SSID to a unique name that does not reveal the router "
                "model or vendor.  Immediately change the admin password to a strong, "
                "unique value.  Update the router firmware."
            ),
            "penalty_score": 30,
        }
    ]


def _check_hidden_ssid(network: dict) -> list[dict]:
    """Flag networks that suppress their SSID broadcast.

    Hidden SSIDs provide a false sense of security — they are trivially
    revealed when any client connects.

    Args:
        network: Network dict.

    Returns:
        List with one finding if SSID is hidden, else [].
    """
    if not network.get("hidden", False):
        return []

    return [
        {
            "category":    "Configuration",
            "check":       "Hidden SSID",
            "risk_level":  "Low",
            "description": (
                "The network is configured to suppress its SSID in beacon frames "
                "(hidden network).  This is a security-through-obscurity measure "
                "that provides minimal practical protection."
            ),
            "unauthorized_access_scenario": (
                "Passive wireless scanners can detect hidden networks from beacon "
                "frames even without an SSID.  When a legitimate client connects, "
                "the SSID is transmitted in the probe request in plain-text, "
                "instantly revealing it to any passive observer.  The hidden SSID "
                "can also cause connected clients to broadcast probe requests for "
                "the network everywhere they go, leaking the SSID even when away "
                "from home."
            ),
            "recommendation": (
                "Do not rely on SSID hiding as a security control.  Instead, use "
                "strong encryption (WPA3), a unique passphrase, and optionally "
                "MAC-address filtering as a secondary (not primary) control."
            ),
            "penalty_score": 10,
        }
    ]


def _check_signal_leakage(network: dict) -> list[dict]:
    """Flag networks with an unusually strong signal that may extend beyond intended premises.

    Args:
        network: Network dict.

    Returns:
        List with one finding if signal exceeds threshold, else [].
    """
    rssi = network.get("signal", -100)
    if rssi < SIGNAL_STRONG_THRESHOLD:
        return []

    return [
        {
            "category":    "Signal / RF",
            "check":       "Excessive Signal Strength",
            "risk_level":  "Medium",
            "description": (
                f"The detected signal strength is {rssi} dBm, which exceeds the "
                f"'strong signal' threshold of {SIGNAL_STRONG_THRESHOLD} dBm.  "
                f"This may indicate the transmit power is set too high, causing RF "
                f"coverage to extend well beyond the intended premises."
            ),
            "unauthorized_access_scenario": (
                "A very strong signal means the network is reachable from car parks, "
                "pavements, or neighbouring buildings.  This significantly increases "
                "the pool of potential attackers who can attempt to authenticate "
                "or capture traffic without needing to be inside the premises."
            ),
            "recommendation": (
                "Reduce transmit power in the AP admin settings to limit coverage to "
                "the intended area.  Conduct a site survey to verify the coverage "
                "boundary.  Consider directional antennas to focus coverage inward."
            ),
            "penalty_score": 20,
        }
    ]


def _check_wps(network: dict) -> list[dict]:
    """Flag networks with WPS enabled.

    Args:
        network: Network dict.

    Returns:
        List with one finding if WPS is enabled, else [].
    """
    if not network.get("wps", False):
        return []

    return [
        {
            "category":    "Configuration",
            "check":       "WPS Enabled",
            "risk_level":  "High",
            "description": (
                "Wi-Fi Protected Setup (WPS) is enabled on this access point.  "
                "The WPS PIN method has a fundamental design flaw — the 8-digit PIN "
                "is verified in two halves, reducing the effective key-space from "
                "100,000,000 to approximately 11,000 attempts."
            ),
            "unauthorized_access_scenario": (
                "An attacker can use the Pixie Dust attack (offline WPS attack) or "
                "a standard online PIN brute-force to recover the WPS PIN and "
                "subsequently the WPA2 passphrase.  Even with rate-limiting, the "
                "attack is usually feasible within hours.  Many ISP-provided routers "
                "are known to have predictable PINs derivable from the BSSID."
            ),
            "recommendation": (
                "Disable WPS in the router admin panel.  If the router does not "
                "allow WPS to be disabled, replace it.  WPS-PBC (push-button) mode "
                "is safer than PIN mode but still carries some risk."
            ),
            "penalty_score": 25,
        }
    ]


def _check_weak_channel(network: dict) -> list[dict]:
    """Flag 2.4 GHz networks on highly congested channels (not 1, 6, or 11).

    Congestion on non-standard channels indicates poor configuration; it does
    not directly create a security vulnerability but is a quality signal.

    Args:
        network: Network dict.

    Returns:
        List with one finding if channel is non-optimal, else [].
    """
    channel = network.get("channel", 0)
    freq    = network.get("frequency", 0.0)

    # Only applies to 2.4 GHz band
    if not (2.4 <= freq < 2.5):
        return []

    # Channels 1, 6, 11 are the standard non-overlapping channels
    if channel in (0, 1, 6, 11):
        return []

    return [
        {
            "category":    "Configuration",
            "check":       "Non-Standard 2.4 GHz Channel",
            "risk_level":  "Low",
            "description": (
                f"The network is operating on channel {channel} in the 2.4 GHz band. "
                f"Channels 1, 6, and 11 are the only non-overlapping choices; "
                f"other channels overlap with neighbours, increasing interference "
                f"and potentially reducing encryption reliability."
            ),
            "unauthorized_access_scenario": (
                "Elevated RF interference can cause retransmissions that increase "
                "the volume of capturable frames.  Some older implementations "
                "exposed IVs (initialisation vectors) more frequently under "
                "high-collision conditions — a historically important factor in "
                "WEP attacks."
            ),
            "recommendation": (
                "Set the AP to use channels 1, 6, or 11 in the 2.4 GHz band, "
                "or migrate to the 5 GHz / 6 GHz band which has many more "
                "non-overlapping channels."
            ),
            "penalty_score": 5,
        }
    ]
