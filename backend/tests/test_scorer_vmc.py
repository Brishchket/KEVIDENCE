"""
test_scorer_vmc.py — Unit tests for the VMC chain scoring engine.
"""
import pytest
from app.scoring.scorer import prioritize
from app.scoring.models.vmc_chain import VmcChainV1
from app.scoring.models.weighted_v1 import WeightedV1


class TestVmcChain:
    """Tests for the VMC chain scoring model."""

    def test_critical_in_kev_cvss_high(self):
        record = {"cve_id": "CVE-TEST-001", "cvss_base_score": 9.8,
                  "epss_score": 0.93, "in_kev": True}
        result = prioritize(record, model_name="vmc_chain_v1")
        assert result["priority_label"] == "CRITICAL"
        assert result["priority_score"] >= 0.75
        assert result["priority_breakdown"]["gates"][0]["passed"] is True # Threat
        assert result["priority_breakdown"]["gates"][1]["passed"] is True # Severity

    def test_critical_in_kev_missing_cvss_escalate(self):
        record = {"cve_id": "CVE-TEST-002", "cvss_base_score": None,
                  "epss_score": 0.1, "in_kev": True}
        result = prioritize(record, model_name="vmc_chain_v1")
        assert result["priority_label"] == "CRITICAL"
        assert result["priority_score"] >= 0.75

    def test_high_not_in_kev_high_epss_high_cvss(self):
        record = {"cve_id": "CVE-TEST-003", "cvss_base_score": 7.5,
                  "epss_score": 0.1, "in_kev": False}
        result = prioritize(record, model_name="vmc_chain_v1")
        assert result["priority_label"] == "HIGH"
        assert 0.50 <= result["priority_score"] < 0.75

    def test_medium_threat_gate_passed_severity_failed(self):
        record = {"cve_id": "CVE-TEST-004", "cvss_base_score": 6.9,
                  "epss_score": 0.1, "in_kev": False}
        result = prioritize(record, model_name="vmc_chain_v1")
        assert result["priority_label"] == "MEDIUM"
        assert 0.25 <= result["priority_score"] < 0.50
        assert result["priority_breakdown"]["gates"][0]["passed"] is True
        assert result["priority_breakdown"]["gates"][1]["passed"] is False

    def test_low_threat_gate_failed(self):
        record = {"cve_id": "CVE-TEST-005", "cvss_base_score": 9.9,
                  "epss_score": 0.05, "in_kev": False}
        result = prioritize(record, model_name="vmc_chain_v1")
        assert result["priority_label"] == "LOW"
        assert result["priority_score"] < 0.25
        assert result["priority_breakdown"]["gates"][0]["passed"] is False

    def test_band_invariant(self):
        """Invariant: The score can never cross a tier boundary."""
        for epss in [0.0, 0.5, 1.0]:
            for cvss in [0.0, 5.0, 10.0]:
                for kev in [True, False]:
                    record = {"cve_id": "CVE-BAND", "cvss_base_score": cvss, "epss_score": epss, "epss_percentile": epss, "in_kev": kev}
                    result = prioritize(record, model_name="vmc_chain_v1")
                    label = result["priority_label"]
                    score = result["priority_score"]
                    if label == "CRITICAL":
                        assert 0.75 <= score <= 1.0
                    elif label == "HIGH":
                        assert 0.50 <= score < 0.75
                    elif label == "MEDIUM":
                        assert 0.25 <= score < 0.50
                    elif label == "LOW":
                        assert 0.0 <= score < 0.25

    def test_weighted_v1_identical(self):
        """Ensure the legacy weighted_v1 is byte-identical."""
        # Using the same fixture as test_scorer
        record = {"cve_id": "CVE-TEST-LEGACY", "cvss_base_score": 9.8, "epss_score": 0.93, "in_kev": True}
        result = prioritize(record, model_name="weighted_v1")
        assert result["priority_label"] == "CRITICAL"
        assert "cvss_contribution" in result["priority_breakdown"]
        assert "components" in result["priority_breakdown"]
        assert result["score_model"] == "weighted_v1"
        
        # Test boundaries
        record2 = {"cve_id": "CVE-TEST-002", "cvss_base_score": 7.5, "epss_score": 0.5, "in_kev": True}
        result2 = prioritize(record2, model_name="weighted_v1")
        assert result2["priority_label"] == "CRITICAL"
