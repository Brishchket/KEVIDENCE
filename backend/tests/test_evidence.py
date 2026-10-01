"""
test_evidence.py — Tests for Evidence builder and verbalizer.
"""
import json
import pytest
from app.evidence.builder import build_evidence_from_record
from app.evidence.verbalizer import verbalize


def _make_cve_record(**overrides):
    """Create a base CVE record with overrides."""
    base = {
        "cve_id": "CVE-2024-TEST",
        "description": "Test vulnerability in test product.",
        "cvss_base_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "attack_vector": "NETWORK",
        "cwe_ids": json.dumps(["CWE-787"]),
        "published_date": "2024-01-01T00:00:00",
        "last_modified_date": "2024-01-02T00:00:00",
        "affected_cpes": "[]",
        "vendors": json.dumps(["Testvendor"]),
        "products": json.dumps(["Testproduct"]),
        "reference_urls": json.dumps(["https://example.com"]),
        "patch_references": json.dumps(["https://example.com/patch"]),
        "epss_score": 0.93,
        "epss_percentile": 0.99,
        "in_kev": True,
        "priority_score": 0.919,
        "priority_label": "CRITICAL",
        "priority_breakdown": json.dumps({
            "cvss_contribution": 0.294,
            "epss_contribution": 0.279,
            "kev_contribution": 0.4,
        }),
        "missing_signals": json.dumps([]),
        "reasons": json.dumps([
            "Listed in CISA KEV: confirmed exploited in the wild",
            "EPSS probability 0.93 — high exploitation likelihood",
            "CVSS 9.8 (Critical), network-exploitable",
        ]),
    }
    base.update(overrides)
    return base


class TestEvidenceBuilder:
    def test_full_evidence(self):
        """Build evidence from a complete record."""
        record = _make_cve_record()
        kev = {"date_added": "2024-01-15", "due_date": "2024-02-15",
               "required_action": "Apply update", "known_ransomware_use": "Known"}
        evidence = build_evidence_from_record(record, kev_row=kev)

        assert evidence.cve_id == "CVE-2024-TEST"
        assert evidence.cvss.score == 9.8
        assert evidence.cvss.attack_vector == "NETWORK"
        assert evidence.epss.probability == 0.93
        assert evidence.kev.in_kev is True
        assert evidence.kev.date_added == "2024-01-15"
        assert evidence.affected.vendor == "Testvendor"
        assert evidence.priority.label == "CRITICAL"
        assert len(evidence.reasons) == 3
        assert evidence.recommended_action is not None

    def test_null_fields_stay_null(self):
        """Null CVE fields should produce null evidence fields."""
        record = _make_cve_record(
            cvss_base_score=None, cvss_vector=None, severity="UNKNOWN",
            attack_vector=None, epss_score=0.0, epss_percentile=None,
            in_kev=False, vendors="[]", products="[]",
            patch_references="[]"
        )
        evidence = build_evidence_from_record(record)

        assert evidence.cvss.score is None
        assert evidence.cvss.vector is None
        assert evidence.cvss.severity is None
        assert evidence.affected.vendor is None
        assert evidence.affected.product is None
        assert evidence.kev.in_kev is False
        assert evidence.kev.date_added is None

    def test_reasons_are_deterministic(self):
        """Same record should always produce the same reasons."""
        record = _make_cve_record()
        ev1 = build_evidence_from_record(record)
        ev2 = build_evidence_from_record(record)
        assert ev1.reasons == ev2.reasons

    def test_recommended_action_by_label(self):
        """Recommended action maps from priority label."""
        for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            record = _make_cve_record(priority_label=label)
            evidence = build_evidence_from_record(record)
            assert evidence.recommended_action is not None
            assert len(evidence.recommended_action) > 10

    def test_recommended_action_uses_kev_action_and_deadline(self):
        record = _make_cve_record()
        kev = {
            "date_added": "2024-01-15",
            "due_date": "2024-02-15",
            "required_action": "Apply the vendor update",
            "known_ransomware_use": "Known",
        }

        evidence = build_evidence_from_record(record, kev_row=kev)

        assert "Apply the vendor update" in evidence.recommended_action
        assert "2024-02-15" in evidence.recommended_action
        assert "https://example.com/patch" in evidence.recommended_action

    def test_recommended_action_targets_product_without_kev(self):
        record = _make_cve_record(in_kev=False)

        evidence = build_evidence_from_record(record)

        assert "Testproduct" in evidence.recommended_action
        assert "https://example.com/patch" in evidence.recommended_action


class TestVerbalizer:
    def test_verbalize_produces_sentences(self):
        """Verbalize should produce a non-empty list of sentences."""
        record = _make_cve_record()
        kev = {"date_added": "2024-01-15", "due_date": "2024-02-15",
               "required_action": "Apply update", "known_ransomware_use": "Known"}
        evidence = build_evidence_from_record(record, kev_row=kev)
        sentences = verbalize(evidence)

        assert len(sentences) > 5
        assert any("CVE-2024-TEST" in s for s in sentences)
        assert any("9.8" in s for s in sentences)
        assert any("CISA" in s or "KEV" in s for s in sentences)
        assert any("0.93" in s for s in sentences)

    def test_verbalize_null_fields_omitted(self):
        """Null fields should not appear in verbalized sentences."""
        record = _make_cve_record(
            cvss_base_score=None, cvss_vector=None, severity="UNKNOWN",
            attack_vector=None, in_kev=False, vendors="[]", products="[]"
        )
        evidence = build_evidence_from_record(record)
        sentences = verbalize(evidence)

        # No CVSS score sentence, no KEV sentence, no vendor/product
        assert not any("CVSS base score" in s for s in sentences)
        assert not any("CISA Known" in s for s in sentences)
        assert not any("affected vendor" in s for s in sentences)

    def test_verbalize_one_fact_per_sentence(self):
        """Each sentence should be about one fact."""
        record = _make_cve_record()
        evidence = build_evidence_from_record(record)
        sentences = verbalize(evidence)

        # Each sentence should end with a period or be a reasonable claim
        for s in sentences:
            assert len(s) > 10, f"Sentence too short: {s}"
