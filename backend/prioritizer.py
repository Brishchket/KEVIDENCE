"""
prioritizer.py — Composite priority scoring engine.

  priority_score = 0.3 * normalize(cvss_base_score)
                 + 0.3 * epss_score
                 + 0.4 * (1 if in_kev else 0)

Labels:
  CRITICAL  >= 0.75
  HIGH      >= 0.50
  MEDIUM    >= 0.25
  LOW       <  0.25
"""
from __future__ import annotations

from typing import Any

CVSS_MAX = 10.0

THRESHOLDS = [
    (0.75, "CRITICAL"),
    (0.50, "HIGH"),
    (0.25, "MEDIUM"),
    (0.00, "LOW"),
]


def _normalize_cvss(score: float | None) -> float:
    if score is None:
        return 0.0
    return max(0.0, min(score, CVSS_MAX)) / CVSS_MAX


def _build_reasons(
    cvss_norm: float,
    epss_score: float,
    in_kev: bool,
    priority_label: str,
) -> list[str]:
    reasons: list[str] = []

    if in_kev:
        reasons.append("Actively exploited (in CISA KEV catalog)")
    if epss_score >= 0.5:
        reasons.append(f"High exploitation probability (EPSS {epss_score:.2%})")
    elif epss_score >= 0.1:
        reasons.append(f"Moderate exploitation probability (EPSS {epss_score:.2%})")

    if cvss_norm >= 0.9:
        reasons.append(f"Critical CVSS base score ({cvss_norm * CVSS_MAX:.1f}/10)")
    elif cvss_norm >= 0.7:
        reasons.append(f"High CVSS base score ({cvss_norm * CVSS_MAX:.1f}/10)")
    elif cvss_norm >= 0.4:
        reasons.append(f"Moderate CVSS base score ({cvss_norm * CVSS_MAX:.1f}/10)")

    if not reasons:
        reasons.append(f"Composite priority: {priority_label}")

    return reasons


def prioritize(record: dict[str, Any]) -> dict[str, Any]:
    """
    Compute and attach priority_score, priority_label, and reasons to a parsed record.
    Returns a new dict (does not mutate the original).
    """
    cvss_base_score = record.get("cvss_base_score")
    epss_score = float(record.get("epss_score") or 0.0)
    in_kev = bool(record.get("in_kev"))

    cvss_norm = _normalize_cvss(cvss_base_score)
    kev_component = 1.0 if in_kev else 0.0

    priority_score = (
        0.3 * cvss_norm
        + 0.3 * epss_score
        + 0.4 * kev_component
    )
    priority_score = round(min(priority_score, 1.0), 4)

    label = "LOW"
    for threshold, lbl in THRESHOLDS:
        if priority_score >= threshold:
            label = lbl
            break

    reasons = _build_reasons(cvss_norm, epss_score, in_kev, label)

    return {
        **record,
        "priority_score": priority_score,
        "priority_label": label,
        "reasons": reasons,
    }
