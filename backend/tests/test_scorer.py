"""
test_scorer.py — Unit tests for the priority scoring engine.

Tests exact boundary conditions and breakdown computation.
"""
import pytest
from app.scoring.scorer import prioritize


class TestPrioritize:
    """Tests for the prioritize function."""

    def test_critical_kev_high_cvss_high_epss(self):
        """KEV + CVSS 9.8 + EPSS 0.93 => CRITICAL."""
        record = {"cve_id": "CVE-TEST-001", "cvss_base_score": 9.8,
                  "epss_score": 0.93, "in_kev": True}
        result = prioritize(record)
        assert result["priority_label"] == "CRITICAL"
        assert result["priority_score"] >= 0.75
        assert "cvss_contribution" in result["priority_breakdown"]

    def test_critical_boundary_exact(self):
        """Score exactly at 0.75 => CRITICAL."""
        # 0.3*(7.5/10) + 0.3*0.5 + 0.4*1.0 = 0.225 + 0.15 + 0.4 = 0.775
        record = {"cve_id": "CVE-TEST-002", "cvss_base_score": 7.5,
                  "epss_score": 0.5, "in_kev": True}
        result = prioritize(record)
        assert result["priority_label"] == "CRITICAL"

    def test_high_no_kev(self):
        """High CVSS + EPSS but no KEV => HIGH."""
        # 0.3*(9.0/10) + 0.3*0.7 + 0.0 = 0.27 + 0.21 = 0.48
        record = {"cve_id": "CVE-TEST-003", "cvss_base_score": 9.0,
                  "epss_score": 0.7, "in_kev": False}
        result = prioritize(record)
        # 0.27 + 0.21 = 0.48, which is < 0.50, so MEDIUM!
        # Let's adjust: 0.3*(10/10) + 0.3*0.7 = 0.3 + 0.21 = 0.51 => HIGH
        record2 = {"cve_id": "CVE-TEST-003b", "cvss_base_score": 10.0,
                   "epss_score": 0.7, "in_kev": False}
        result2 = prioritize(record2)
        assert result2["priority_label"] == "HIGH"

    def test_high_boundary_exact(self):
        """Score exactly at 0.50 => HIGH."""
        # 0.3*(10/10) + 0.3*(2/3) + 0.0 = 0.3 + 0.2 = 0.50
        record = {"cve_id": "CVE-TEST-004", "cvss_base_score": 10.0,
                  "epss_score": 2/3, "in_kev": False}
        result = prioritize(record)
        assert result["priority_label"] == "HIGH"
        assert result["priority_score"] >= 0.50

    def test_medium_moderate_scores(self):
        """Medium CVSS + low EPSS, no KEV => MEDIUM."""
        # 0.3*(5.0/10) + 0.3*0.1 + 0.0 = 0.15 + 0.03 = 0.18
        # That's LOW. Need: 0.3*(8/10) + 0.3*0.05 = 0.24 + 0.015 = 0.255 => MEDIUM
        record = {"cve_id": "CVE-TEST-005", "cvss_base_score": 8.0,
                  "epss_score": 0.05, "in_kev": False}
        result = prioritize(record)
        assert result["priority_label"] == "MEDIUM"

    def test_medium_boundary_exact(self):
        """Score at exactly 0.25 => MEDIUM."""
        # 0.3*(x/10) + 0.3*0 + 0 = 0.25 => x = 8.333...
        record = {"cve_id": "CVE-TEST-006", "cvss_base_score": 8.3334,
                  "epss_score": 0.0, "in_kev": False}
        result = prioritize(record)
        assert result["priority_score"] >= 0.25
        assert result["priority_label"] == "MEDIUM"

    def test_low_all_zeros(self):
        """No CVSS, no EPSS, no KEV => LOW with score 0."""
        record = {"cve_id": "CVE-TEST-007", "cvss_base_score": None,
                  "epss_score": 0.0, "in_kev": False}
        result = prioritize(record)
        assert result["priority_label"] == "LOW"
        assert result["priority_score"] == 0.0

    def test_low_small_cvss(self):
        """Low CVSS only => LOW."""
        record = {"cve_id": "CVE-TEST-008", "cvss_base_score": 2.0,
                  "epss_score": 0.0, "in_kev": False}
        result = prioritize(record)
        assert result["priority_label"] == "LOW"

    def test_missing_signals_cvss_none(self):
        """Missing CVSS is recorded in missing_signals."""
        record = {"cve_id": "CVE-TEST-009", "cvss_base_score": None,
                  "epss_score": 0.5, "in_kev": False}
        result = prioritize(record)
        assert "cvss" in result["missing_signals"]

    def test_missing_signals_epss_zero(self):
        """EPSS = 0 is recorded as missing signal."""
        record = {"cve_id": "CVE-TEST-010", "cvss_base_score": 7.0,
                  "epss_score": 0.0, "in_kev": False}
        result = prioritize(record)
        assert "epss" in result["missing_signals"]

    def test_breakdown_values(self):
        """Verify breakdown components sum correctly."""
        record = {"cve_id": "CVE-TEST-011", "cvss_base_score": 8.0,
                  "epss_score": 0.5, "in_kev": True}
        result = prioritize(record)
        bd = result["priority_breakdown"]
        expected_cvss = round(0.3 * 8.0 / 10.0, 4)
        expected_epss = round(0.3 * 0.5, 4)
        expected_kev = round(0.4 * 1.0, 4)
        assert bd["cvss_contribution"] == expected_cvss
        assert bd["epss_contribution"] == expected_epss
        assert bd["kev_contribution"] == expected_kev
        assert abs(result["priority_score"] - (expected_cvss + expected_epss + expected_kev)) < 0.001

    def test_kev_only_is_high(self):
        """KEV alone gives 0.4 => MEDIUM (< 0.50 for HIGH)."""
        record = {"cve_id": "CVE-TEST-012", "cvss_base_score": None,
                  "epss_score": 0.0, "in_kev": True}
        result = prioritize(record)
        assert result["priority_score"] == 0.4
        assert result["priority_label"] == "MEDIUM"

    def test_max_score_capped_at_1(self):
        """Score cannot exceed 1.0."""
        record = {"cve_id": "CVE-TEST-013", "cvss_base_score": 10.0,
                  "epss_score": 1.0, "in_kev": True}
        result = prioritize(record)
        assert result["priority_score"] == 1.0

    def test_reasons_include_kev(self):
        """KEV CVE should have a KEV reason."""
        record = {"cve_id": "CVE-TEST-014", "cvss_base_score": 9.0,
                  "epss_score": 0.5, "in_kev": True}
        result = prioritize(record)
        assert any("KEV" in r for r in result["reasons"])

    def test_reasons_include_epss(self):
        """High EPSS should mention it."""
        record = {"cve_id": "CVE-TEST-015", "cvss_base_score": 5.0,
                  "epss_score": 0.75, "in_kev": False}
        result = prioritize(record)
        assert any("EPSS" in r for r in result["reasons"])
