"""
vmc_chain.py — Vulnerability Management Chaining (VMC) scoring model (v1.0.0).

RESEARCH BASIS:
- Primary: N. Shimizu and M. Hashimoto, "Vulnerability Management Chaining: An Integrated Framework for Efficient Cybersecurity Risk Prioritization," IEEE Access, vol. 14, pp. 31407-31424, 2026, doi:10.1109/ACCESS.2026.3665768. Thresholds below are taken from the arXiv preprint 2506.01220v3; note in docs that final IEEE-version figures may differ.
- Supporting: P. Mell, K. Scarfone, S. Romanosky, "Common Vulnerability Scoring System," IEEE Security & Privacy, 2006. J. M. Spring et al., "Time to Change the CVSS?," IEEE Security & Privacy 19(2), 2021. J. Jacobs et al., "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights," IEEE EuroS&PW 2023. J. Jacobs et al., "Exploit Prediction Scoring System (EPSS)," ACM Digital Threats: Research and Practice 2(3), 2021 (ACM, not IEEE — label it so).

The paper presents a pure decision tree to assign priority tiers (CRITICAL, HIGH, MEDIUM, LOW).
The continuous score mapped within per-tier bands is OUR design to fit the PhantomPatch UI.
"""
from __future__ import annotations

from typing import Any

from app.config import (
    SCORING_MODEL,
    VMC_CVSS_THRESHOLD,
    VMC_EPSS_THRESHOLD,
    VMC_TIEBREAK_EPSS_W,
    VMC_UNKNOWN_CVSS,
    THRESHOLD_CRITICAL,
    THRESHOLD_HIGH,
    THRESHOLD_MEDIUM,
)
from app.scoring.base import ScoringModel


class VmcChainV1(ScoringModel):
    name = "vmc_chain_v1"
    version = "1.0.0"

    def score(self, record: dict[str, Any]) -> dict[str, Any]:
        cvss_base_score = record.get("cvss_base_score")
        epss_score = float(record.get("epss_score") or 0.0)
        epss_percentile = float(record.get("epss_percentile") or 0.0)
        in_kev = bool(record.get("in_kev"))

        missing_signals: list[str] = []
        if cvss_base_score is None:
            missing_signals.append("cvss")
        if epss_score == 0.0:
            missing_signals.append("epss")

        gates = []
        decision_path = []
        reasons = []

        # Stage 1: Threat Gate (KEV OR EPSS >= VMC_EPSS_THRESHOLD)
        # Note: If EPSS is missing, it counts as 0, which means threat gate fails unless in KEV
        threat_gate_passed = in_kev or (epss_score >= VMC_EPSS_THRESHOLD)
        gates.append({"name": "Threat Gate", "passed": threat_gate_passed})
        if in_kev:
            decision_path.append("Listed in CISA KEV (Confirmed Exploited)")
            reasons.append("Listed in CISA KEV: confirmed exploited in the wild")
        elif epss_score >= VMC_EPSS_THRESHOLD:
            decision_path.append(f"EPSS Probability ({epss_score:.3f}) >= Threshold ({VMC_EPSS_THRESHOLD})")
            reasons.append(f"EPSS probability {epss_score:.2f} indicates high exploitation likelihood")
        else:
            decision_path.append(f"Not in KEV and EPSS ({epss_score:.3f}) < Threshold ({VMC_EPSS_THRESHOLD})")
            if epss_score == 0:
                reasons.append("No EPSS score available, and not listed in KEV")
            else:
                reasons.append(f"Low threat likelihood based on KEV/EPSS ({epss_score:.3f})")

        # Stage 2: Severity Gate
        severity_gate_passed = False
        if threat_gate_passed:
            if cvss_base_score is None:
                if VMC_UNKNOWN_CVSS == "escalate":
                    severity_gate_passed = True
                    decision_path.append("Severity Gate Passed (Missing CVSS defaulted to escalate)")
                    reasons.append("Missing CVSS score escalated per VMC policy due to threat gate passage")
                else:
                    severity_gate_passed = False
                    decision_path.append("Severity Gate Failed (Missing CVSS defaulted to monitor)")
                    reasons.append("Missing CVSS score deprioritized per VMC policy")
            else:
                severity_gate_passed = cvss_base_score >= VMC_CVSS_THRESHOLD
                gates.append({"name": "Severity Gate", "passed": severity_gate_passed})
                if severity_gate_passed:
                    decision_path.append(f"CVSS ({cvss_base_score:.1f}) >= Threshold ({VMC_CVSS_THRESHOLD})")
                    reasons.append(f"CVSS base score {cvss_base_score:.1f} meets severity threshold")
                else:
                    decision_path.append(f"CVSS ({cvss_base_score:.1f}) < Threshold ({VMC_CVSS_THRESHOLD})")
                    reasons.append(f"CVSS base score {cvss_base_score:.1f} is below severity threshold")

        # Determine explicit label (Decision Tree)
        if in_kev and (cvss_base_score is None and VMC_UNKNOWN_CVSS == "escalate" or (cvss_base_score is not None and cvss_base_score >= VMC_CVSS_THRESHOLD)):
            label = "CRITICAL"
        elif threat_gate_passed and severity_gate_passed:
            # in_kev and cvss >= 7 is caught above
            if in_kev:
                 label = "CRITICAL"
            else:
                 label = "HIGH"
        elif threat_gate_passed and not severity_gate_passed:
            label = "MEDIUM"
        else:
            label = "LOW"

        # Continuous Score (Tiebreak within Band)
        # BANDS: CRITICAL [0.75, 1.0], HIGH [0.50, 0.7499], MEDIUM [0.25, 0.4999], LOW [0.0, 0.2499]
        if label == "CRITICAL":
            lo, hi = THRESHOLD_CRITICAL, 1.00
        elif label == "HIGH":
            lo, hi = THRESHOLD_HIGH, THRESHOLD_CRITICAL - 0.0001
        elif label == "MEDIUM":
            lo, hi = THRESHOLD_MEDIUM, THRESHOLD_HIGH - 0.0001
        else:
            lo, hi = 0.0, THRESHOLD_MEDIUM - 0.0001

        safe_cvss = cvss_base_score if cvss_base_score is not None else 0.0
        p = (VMC_TIEBREAK_EPSS_W * epss_percentile) + ((1 - VMC_TIEBREAK_EPSS_W) * (safe_cvss / 10.0))
        priority_score = round(lo + ((hi - lo) * p), 4)

        breakdown = {
            "components": [
                {"name": "CVSS", "value": safe_cvss, "type": "severity"},
                {"name": "EPSS", "value": epss_score, "type": "threat"},
                {"name": "KEV", "value": 1.0 if in_kev else 0.0, "type": "threat"},
            ],
            "gates": gates,
            "decision_path": decision_path,
        }

        return {
            **record,
            "priority_score": priority_score,
            "priority_label": label,
            "priority_breakdown": breakdown,
            "missing_signals": missing_signals,
            "reasons": reasons,
            "score_model": self.name,
            "score_version": self.version,
        }
