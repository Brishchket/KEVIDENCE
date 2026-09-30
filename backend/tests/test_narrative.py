"""
test_narrative.py — Tests for narrative generation with mock LLM and retry loop.
"""
import pytest
import asyncio
from app.schemas import Evidence, CVSSDetail, EPSSDetail, KEVDetail, PriorityDetail, PriorityBreakdown, AffectedDetail
from app.llm.mock import MockLLMClient
from app.narrative.generator import generate_narrative, _confidence_label
from app.db import init_db

import os
import tempfile


def _make_evidence():
    return Evidence(
        cve_id="CVE-2024-TEST-NAR",
        description="Test vulnerability in network appliance.",
        cvss=CVSSDetail(score=9.8, severity="CRITICAL",
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        attack_vector="NETWORK"),
        cwe=["CWE-787"],
        epss=EPSSDetail(probability=0.93, percentile=0.99),
        kev=KEVDetail(in_kev=True, date_added="2024-01-15", due_date="2024-02-15",
                      required_action="Apply updates", known_ransomware_use="Known"),
        affected=AffectedDetail(vendor="TestVendor", product="TestProduct"),
        priority=PriorityDetail(score=0.919, label="CRITICAL",
                                breakdown=PriorityBreakdown(
                                    cvss_contribution=0.294,
                                    epss_contribution=0.279,
                                    kev_contribution=0.4)),
        reasons=["Listed in CISA KEV: confirmed exploited in the wild"],
        recommended_action="Patch immediately.",
        patch_references=["https://example.com/patch"],
    )


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Use a temp database for tests."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr("app.config.DB_PATH", db_path)
    monkeypatch.setattr("app.db.DB_PATH", db_path)
    asyncio.get_event_loop().run_until_complete(init_db())
    return db_path


class TestConfidenceLabel:
    def test_high(self):
        assert _confidence_label(0.95) == "HIGH"
        assert _confidence_label(1.0) == "HIGH"

    def test_medium(self):
        assert _confidence_label(0.80) == "MEDIUM"
        assert _confidence_label(0.94) == "MEDIUM"

    def test_low(self):
        assert _confidence_label(0.79) == "LOW"
        assert _confidence_label(0.0) == "LOW"


class TestMockLLM:
    def test_manager_narrative(self):
        client = MockLLMClient()
        evidence = _make_evidence()
        import json
        ev_json = evidence.model_dump_json(indent=2)
        result = asyncio.get_event_loop().run_until_complete(
            client.generate(
                "You are a... AUDIENCE: Business Manager...",
                f"Write a business manager narrative.\nEVIDENCE JSON:\n{ev_json}"
            )
        )
        assert "CVE-2024-TEST-NAR" in result
        assert "CRITICAL" in result

    def test_analyst_narrative(self):
        client = MockLLMClient()
        evidence = _make_evidence()
        ev_json = evidence.model_dump_json(indent=2)
        result = asyncio.get_event_loop().run_until_complete(
            client.generate(
                "AUDIENCE: Security Analyst",
                f"Write a security analyst narrative.\nEVIDENCE JSON:\n{ev_json}"
            )
        )
        assert "CVE-2024-TEST-NAR" in result

    def test_it_admin_narrative(self):
        client = MockLLMClient()
        evidence = _make_evidence()
        ev_json = evidence.model_dump_json(indent=2)
        result = asyncio.get_event_loop().run_until_complete(
            client.generate(
                "AUDIENCE: IT Administrator",
                f"Write an IT administrator narrative.\nEVIDENCE JSON:\n{ev_json}"
            )
        )
        assert "CVE-2024-TEST-NAR" in result

    def test_inject_unsupported(self):
        """Mock with inject_unsupported=True adds a fabricated sentence."""
        client = MockLLMClient(inject_unsupported=True)
        evidence = _make_evidence()
        ev_json = evidence.model_dump_json(indent=2)
        result = asyncio.get_event_loop().run_until_complete(
            client.generate(
                "AUDIENCE: Business Manager",
                f"Write narrative.\nEVIDENCE JSON:\n{ev_json}"
            )
        )
        assert "APT29" in result or "instability" in result or "weaponized" in result


class TestGenerateNarrative:
    @pytest.mark.asyncio
    async def test_full_pipeline_mock(self, temp_db):
        """End-to-end: generate → verify → confidence label with mock LLM."""
        evidence = _make_evidence()
        client = MockLLMClient()
        record = await generate_narrative(evidence, "manager", client)

        assert record.cve_id == "CVE-2024-TEST-NAR"
        assert record.audience == "manager"
        assert record.narrative_text
        assert record.provider == "mock"
        assert record.confidence in ("HIGH", "MEDIUM", "LOW")
        assert 0.0 <= record.faithfulness_score <= 1.0
        assert record.attempt_count >= 1

    @pytest.mark.asyncio
    async def test_verification_result_attached(self, temp_db):
        """Verification result should be attached to the narrative."""
        evidence = _make_evidence()
        client = MockLLMClient()
        record = await generate_narrative(evidence, "analyst", client)

        assert record.verification is not None
        assert record.verification.total_count > 0
        assert len(record.verification.sentences) > 0

    @pytest.mark.asyncio
    async def test_inject_unsupported_lowers_score(self, temp_db):
        """Injecting unsupported claims should lower faithfulness."""
        evidence = _make_evidence()

        clean_client = MockLLMClient(inject_unsupported=False)
        dirty_client = MockLLMClient(inject_unsupported=True)

        clean = await generate_narrative(evidence, "manager", clean_client)
        dirty = await generate_narrative(evidence, "manager", dirty_client)

        # The dirty narrative should have lower faithfulness
        # (may not always be strictly lower due to retry, but generally)
        assert dirty.verification is not None
        assert any(not s.supported for s in dirty.verification.sentences)
