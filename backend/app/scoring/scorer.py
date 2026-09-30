"""
scorer.py — Composite priority scoring engine.

  priority_score = W_cvss * (cvss_base_score / 10)
                 + W_epss * epss_probability
                 + W_kev  * (1 if in_kev else 0)

Labels:
  CRITICAL  >= 0.75
  HIGH      >= 0.50
  MEDIUM    >= 0.25
  LOW       <  0.25

Weights and thresholds are configurable via environment.
Missing CVSS or EPSS counts as 0 and is recorded in missing_signals.
Returns each term's weighted contribution (breakdown).
"""
from __future__ import annotations

import json
from typing import Any

from app.config import (
    CVSS_MAX,
    CVSS_WEIGHT,
    EPSS_WEIGHT,
    KEV_WEIGHT,
    THRESHOLD_CRITICAL,
    THRESHOLD_HIGH,
    THRESHOLD_MEDIUM,
)

THRESHOLDS = [
    (THRESHOLD_CRITICAL, "CRITICAL"),
    (THRESHOLD_HIGH, "HIGH"),
    (THRESHOLD_MEDIUM, "MEDIUM"),
    (0.00, "LOW"),
]


def _normalize_cvss(score: float | None) -> float:
    if score is None:
        return 0.0
    return max(0.0, min(score, CVSS_MAX)) / CVSS_MAX


def _build_reasons(
    cvss_score: float | None,
    cvss_norm: float,
    epss_score: float,
    in_kev: bool,
    priority_label: str,
) -> list[str]:
    """Build deterministic reason strings from the data."""
    reasons: list[str] = []

    if in_kev:
        reasons.append("Listed in CISA KEV: confirmed exploited in the wild")
    if epss_score >= 0.5:
        reasons.append(f"EPSS probability {epss_score:.2f} — high exploitation likelihood")
    elif epss_score >= 0.1:
        reasons.append(f"EPSS probability {epss_score:.2f} — moderate exploitation likelihood")
    elif epss_score > 0:
        reasons.append(f"EPSS probability {epss_score:.2f}")

    if cvss_score is not None:
        if cvss_score >= 9.0:
            reasons.append(f"CVSS {cvss_score:.1f} (Critical), network-exploitable" if cvss_norm >= 0.9 else f"CVSS {cvss_score:.1f} (Critical)")
        elif cvss_score >= 7.0:
            reasons.append(f"CVSS {cvss_score:.1f} (High)")
        elif cvss_score >= 4.0:
            reasons.append(f"CVSS {cvss_score:.1f} (Medium)")
        else:
            reasons.append(f"CVSS {cvss_score:.1f} (Low)")

    if not reasons:
        reasons.append(f"Composite priority: {priority_label}")

    return reasons


def prioritize(record: dict[str, Any]) -> dict[str, Any]:
    """
    Compute and attach priority_score, priority_label, breakdown, missing_signals,
    and reasons to a parsed record. Returns a new dict (does not mutate the original).
    """
    cvss_base_score = record.get("cvss_base_score")
    epss_score = float(record.get("epss_score") or 0.0)
    in_kev = bool(record.get("in_kev"))

    # Track missing signals
    missing_signals: list[str] = []
    if cvss_base_score is None:
        missing_signals.append("cvss")
    if epss_score == 0.0:
        missing_signals.append("epss")

    cvss_norm = _normalize_cvss(cvss_base_score)
    kev_component = 1.0 if in_kev else 0.0

    # Compute weighted contributions
    cvss_contribution = round(CVSS_WEIGHT * cvss_norm, 4)
    epss_contribution = round(EPSS_WEIGHT * epss_score, 4)
    kev_contribution = round(KEV_WEIGHT * kev_component, 4)

    priority_score = cvss_contribution + epss_contribution + kev_contribution
    priority_score = round(min(priority_score, 1.0), 4)

    # Determine label
    label = "LOW"
    for threshold, lbl in THRESHOLDS:
        if priority_score >= threshold:
            label = lbl
            break

    reasons = _build_reasons(cvss_base_score, cvss_norm, epss_score, in_kev, label)

    breakdown = {
        "cvss_contribution": cvss_contribution,
        "epss_contribution": epss_contribution,
        "kev_contribution": kev_contribution,
    }

    return {
        **record,
        "priority_score": priority_score,
        "priority_label": label,
        "priority_breakdown": breakdown,
        "missing_signals": missing_signals,
        "reasons": reasons,
    }
