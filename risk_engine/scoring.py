"""
risk_engine/scoring.py
Calculates a composite risk score (0–100) for each network and applies
a label.  Higher score = higher risk.
"""

import logging
from config.settings import (
    WEIGHT_ENCRYPTION,
    WEIGHT_CONFIG,
    WEIGHT_SIGNAL,
    WEIGHT_ROGUE,
)

logger = logging.getLogger(__name__)


# ── Score labels ───────────────────────────────────────────────────────────────

def _label(score: int) -> str:
    """Map a numeric risk score to a categorical label.

    Args:
        score: Integer score in [0, 100].

    Returns:
        One of "Secure", "Moderate", "Vulnerable", or "Critical".
    """
    if score < 20:
        return "Secure"
    if score < 40:
        return "Moderate"
    if score < 65:
        return "Vulnerable"
    return "Critical"


# ── Public API ─────────────────────────────────────────────────────────────────

def calculate_risk_score(
    network:           dict,
    encryption_result: dict,
    config_findings:   list[dict],
    rogue_findings:    list[dict],
) -> dict:
    """Compute a weighted composite risk score for a single network.

    Score formula (all sub-scores are on a 0–100 scale where 100 = worst):

        total = (encryption_sub × WEIGHT_ENCRYPTION)
              + (config_sub    × WEIGHT_CONFIG)
              + (signal_sub    × WEIGHT_SIGNAL)
              + (rogue_sub     × WEIGHT_ROGUE)

    Args:
        network:           Normalised network dict.
        encryption_result: Output of analyzer.encryption.analyse_encryption().
        config_findings:   Output of analyzer.vulnerabilities.analyse_configuration().
        rogue_findings:    List of rogue AP findings for this network.

    Returns:
        Dict containing:
            - ``score``       (int, 0–100)
            - ``label``       (str)
            - ``breakdown``   (dict of component scores)
            - ``top_risk``    (str, description of the highest-risk finding)
    """
    # ── Encryption sub-score (0–100) ──────────────────────────────────────────
    enc_penalty = encryption_result.get("penalty_score", 60)

    # ── Configuration sub-score (0–100) ──────────────────────────────────────
    config_penalties = [f.get("penalty_score", 0) for f in config_findings]
    config_penalty   = min(100, sum(config_penalties))

    # ── Signal leakage sub-score (0–100) ──────────────────────────────────────
    signal_penalty = _signal_penalty(network.get("signal", -100))

    # ── Rogue AP sub-score (0–100) ────────────────────────────────────────────
    rogue_penalties = [f.get("penalty_score", 0) for f in rogue_findings]
    rogue_penalty   = min(100, sum(rogue_penalties))

    # ── Weighted total ────────────────────────────────────────────────────────
    raw_score = (
        enc_penalty    * WEIGHT_ENCRYPTION
        + config_penalty * WEIGHT_CONFIG
        + signal_penalty * WEIGHT_SIGNAL
        + rogue_penalty  * WEIGHT_ROGUE
    )
    score = min(100, max(0, int(round(raw_score))))

    # ── Top risk identifier ───────────────────────────────────────────────────
    all_findings = [encryption_result] + config_findings + rogue_findings
    top_risk = _top_risk_description(all_findings)

    result = {
        "score":  score,
        "label":  _label(score),
        "breakdown": {
            "encryption_penalty": enc_penalty,
            "config_penalty":     config_penalty,
            "signal_penalty":     signal_penalty,
            "rogue_penalty":      rogue_penalty,
        },
        "top_risk": top_risk,
    }

    logger.debug(
        "Risk score for '%s': %d (%s)",
        network.get("ssid"),
        score,
        result["label"],
    )
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _signal_penalty(rssi: int) -> int:
    """Convert signal strength to a leakage penalty score (0–100).

    Very strong signals (high positive) → high penalty.
    Very weak signals → low penalty.

    Args:
        rssi: Signal level in dBm (typically negative).

    Returns:
        Penalty integer in [0, 100].
    """
    # Map roughly:  -40 dBm → 80  |  -70 dBm → 20  |  -90 dBm → 0
    if rssi >= -40:
        return 80
    if rssi >= -50:
        return 60
    if rssi >= -60:
        return 40
    if rssi >= -70:
        return 20
    return 5


def _top_risk_description(findings: list[dict]) -> str:
    """Return the description of the highest-severity finding.

    Priority order: Critical > High > Medium > Moderate > Low.

    Args:
        findings: All finding dicts for the network.

    Returns:
        Vulnerability description string, or "No critical findings."
    """
    priority = {"Critical": 4, "High": 3, "Medium": 2, "Moderate": 1, "Low": 0}
    best = None
    best_score = -1
    for f in findings:
        lvl   = f.get("risk_level", "Low")
        score = priority.get(lvl, 0)
        if score > best_score:
            best_score = score
            best = f
    if best:
        return best.get("vulnerability") or best.get("check") or "Unknown"
    return "No critical findings."


# ── Batch Scoring ──────────────────────────────────────────────────────────────

def rank_networks(analysed_networks: list[dict]) -> list[dict]:
    """Sort a list of fully-analysed networks by risk score (highest first).

    Args:
        analysed_networks: Networks with a ``risk`` sub-dict populated.

    Returns:
        Sorted list, most vulnerable first.
    """
    return sorted(
        analysed_networks,
        key=lambda n: n.get("risk", {}).get("score", 0),
        reverse=True,
    )
