"""
Composite WiFi risk scoring.
"""

from __future__ import annotations

import logging

from config.settings import WEIGHT_CONFIG, WEIGHT_ENCRYPTION, WEIGHT_ROGUE, WEIGHT_SIGNAL

logger = logging.getLogger(__name__)

_LABEL_PRIORITY = {"Critical": 4, "High": 3, "Medium": 2, "Moderate": 1, "Low": 0}


def calculate_risk_score(
    network: dict,
    encryption_result: dict,
    config_findings: list[dict],
    rogue_findings: list[dict],
) -> dict:
    """Compute a weighted composite risk score for a single network."""
    enc_penalty = _clamp_score(encryption_result.get("penalty_score", 60))
    config_penalty = _sum_penalties(config_findings)
    signal_penalty = _signal_penalty(network.get("signal", -100))
    rogue_penalty = _sum_penalties(rogue_findings)

    raw_score = (
        enc_penalty * WEIGHT_ENCRYPTION
        + config_penalty * WEIGHT_CONFIG
        + signal_penalty * WEIGHT_SIGNAL
        + rogue_penalty * WEIGHT_ROGUE
    )
    score = _clamp_score(round(raw_score))

    result = {
        "score": score,
        "label": _label(score),
        "breakdown": {
            "encryption_penalty": enc_penalty,
            "config_penalty": config_penalty,
            "signal_penalty": signal_penalty,
            "rogue_penalty": rogue_penalty,
        },
        "top_risk": _top_risk_description([encryption_result, *config_findings, *rogue_findings]),
    }

    logger.debug(
        "Risk score calculated",
        extra={
            "event": "risk_scored",
            "bssid": network.get("bssid", ""),
            "score": score,
            "label": result["label"],
        },
    )
    return result


def rank_networks(analysed_networks: list[dict]) -> list[dict]:
    """Sort analysed networks by risk score, highest first."""
    return sorted(
        analysed_networks,
        key=lambda item: item.get("risk", {}).get("score", 0),
        reverse=True,
    )


def _label(score: int) -> str:
    if score < 20:
        return "Secure"
    if score < 40:
        return "Moderate"
    if score < 65:
        return "Vulnerable"
    return "Critical"


def _signal_penalty(rssi: object) -> int:
    try:
        value = int(float(str(rssi)))
    except (TypeError, ValueError):
        return 5

    if value >= -40:
        return 80
    if value >= -50:
        return 60
    if value >= -60:
        return 40
    if value >= -70:
        return 20
    return 5


def _sum_penalties(findings: list[dict]) -> int:
    return _clamp_score(sum(_clamp_score(finding.get("penalty_score", 0)) for finding in findings))


def _clamp_score(value: object) -> int:
    try:
        score = int(float(str(value)))
    except (TypeError, ValueError):
        return 0
    return min(100, max(0, score))


def _top_risk_description(findings: list[dict]) -> str:
    best: dict | None = None
    best_score = -1
    for finding in findings:
        level = finding.get("risk_level", "Low")
        score = _LABEL_PRIORITY.get(level, 0)
        if score > best_score:
            best_score = score
            best = finding

    if best:
        return best.get("vulnerability") or best.get("check") or "Unknown"
    return "No critical findings."
