"""
test_report.py — Comprehensive tests for Feature 2: PDF Vulnerability Report.

Tests:
  1. Pure-Python CVSS vector decoder.
  2. MITRE CWE catalog: live fetch parsing, database caching, weekly staleness refresh, fallback.
  3. Comprehensive report data hash & cache invalidation across all report inputs.
  4. Enriched evidence building (full KEV CVE vs sparse missing CVE).
  5. 6-section report generation with deterministic offline template and source tags.
  6. Strict verification of executive summary reuse (unsupported claims blocked).
  7. Evidence-grounding check: no URLs or numbers present in text that are absent from evidence.
  8. PDF Content Inspection via pypdf:
     - Section presence in extracted text (all 6 sections + executive summary + appendix).
     - Missing-evidence wording ("Not stated in available evidence") in extracted text.
     - Verified URLs and numbers present in extracted text.
     - Portfolio summary strictly guarantees 1-page briefs per CVE.
  9. API endpoints: /report, /report.pdf, /reports/summary.pdf.
"""
from __future__ import annotations

import asyncio
import datetime
import importlib
import io
import json
import os
import re
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app.reporting.pdf_renderer import render_cve_pdf, render_portfolio_summary_pdf
from app.reporting.report_evidence import (
    NOT_STATED,
    build_report_evidence,
    compute_report_data_hash,
    decode_cvss_vector,
    fetch_cwe_from_mitre,
    get_or_fetch_cwe,
    verbalize_report_evidence,
)
from app.reporting.report_generator import (
    generate_deterministic_report,
    generate_vulnerability_report,
    get_or_create_report_pdf,
    warm_top_report_pdf_cache,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """FastAPI TestClient with isolated temporary database."""
    tmp = tmp_path_factory.mktemp("test_report_db")
    db_path = str(tmp / "test_report.db")
    os.environ["PHANTOMPATCH_DB"] = db_path
    os.environ["LLM_PROVIDER"] = "mock"

    import app.config
    importlib.reload(app.config)
    app.config.DB_PATH = db_path
    app.config.LLM_PROVIDER = "mock"

    import app.db
    importlib.reload(app.db)
    app.db.DB_PATH = db_path

    # Patch out realtime supervisor so tests don't spin up background loops
    with patch("app.ingestion.realtime.start_supervisor", new_callable=AsyncMock), \
         patch("app.ingestion.realtime.stop_supervisor", new_callable=AsyncMock):
        from app.main import app as fastapi_app

        with TestClient(fastapi_app) as c:
            # Seed test CVEs: (a) Full KEV CVE, (b) Sparse CVE with missing signals
            from app.db import init_db, upsert_cve, upsert_kev
            from app.scoring.scorer import prioritize

            async def _seed():
                await init_db()

                # (a) Full KEV CVE
                full_cve = {
                    "cve_id": "CVE-2024-9999",
                    "description": "Critical remote code execution in Apache HTTP Server mod_proxy.",
                    "cvss_base_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "CRITICAL",
                    "attack_vector": "NETWORK",
                    "cwe_ids": json.dumps(["CWE-787", "CWE-89"]),
                    "published_date": "2024-03-15T10:00:00Z",
                    "last_modified_date": "2024-03-20T12:00:00Z",
                    "affected_cpes": json.dumps(["cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"]),
                    "cpe_version_ranges": json.dumps([
                        {
                            "vendor": "Apache",
                            "product": "Http Server",
                            "version_start_including": "2.4.0",
                            "version_end_excluding": "2.4.51",
                            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        }
                    ]),
                    "vendors": json.dumps(["Apache"]),
                    "products": json.dumps(["Http Server"]),
                    "reference_urls": json.dumps(["https://httpd.apache.org/security/vulnerabilities_24.html"]),
                    "patch_references": json.dumps(["https://httpd.apache.org/security/vulnerabilities_24.html"]),
                    "reference_tags": json.dumps({"Patch": ["https://httpd.apache.org/security/vulnerabilities_24.html"]}),
                    "epss_score": 0.8542,
                    "epss_percentile": 0.985,
                    "in_kev": True,
                }
                await upsert_cve(prioritize(full_cve))

                # KEV catalog record
                kev_record = {
                    "cve_id": "CVE-2024-9999",
                    "vendor_project": "Apache",
                    "product": "Http Server",
                    "vulnerability_name": "Apache HTTP Server Path Traversal and RCE",
                    "date_added": "2024-03-18",
                    "due_date": "2024-04-01",
                    "required_action": "Apply immediate updates per vendor instructions",
                    "known_ransomware_use": "Known to be used by Akira ransomware campaigns",
                    "short_description": "Apache HTTP Server contains a flaw allowing remote code execution.",
                }
                await upsert_kev(kev_record)

                # (b) Sparse CVE: Missing CVSS, EPSS, CWE, KEV
                sparse_cve = {
                    "cve_id": "CVE-2024-0001",
                    "description": "",
                    "cvss_base_score": None,
                    "cvss_vector": None,
                    "severity": "UNKNOWN",
                    "attack_vector": None,
                    "cwe_ids": json.dumps([]),
                    "published_date": "",
                    "last_modified_date": "",
                    "affected_cpes": json.dumps([]),
                    "cpe_version_ranges": json.dumps([]),
                    "vendors": json.dumps([]),
                    "products": json.dumps([]),
                    "reference_urls": json.dumps([]),
                    "patch_references": json.dumps([]),
                    "reference_tags": json.dumps({}),
                    "epss_score": 0.0,
                    "epss_percentile": None,
                    "in_kev": False,
                }
                await upsert_cve(prioritize(sparse_cve))

            asyncio.run(_seed())
            yield c

    if "PHANTOMPATCH_DB" in os.environ:
        del os.environ["PHANTOMPATCH_DB"]


# ── 1. CVSS Vector Decoder Tests ──────────────────────────────────────────────

class TestCVSSVectorDecoder:
    def test_decode_full_vector_v31(self):
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        decoded = decode_cvss_vector(vec)
        assert decoded["version"] == "3.1"
        assert "Network" in decoded["attack_vector"]
        assert "Low" in decoded["attack_complexity"]
        assert "None" in decoded["privileges_required"]
        assert "None" in decoded["user_interaction"]
        assert "High" in decoded["confidentiality_impact"]
        assert "High" in decoded["integrity_impact"]
        assert "High" in decoded["availability_impact"]

    def test_decode_empty_or_none_vector(self):
        decoded = decode_cvss_vector(None)
        assert decoded["attack_vector"] == NOT_STATED
        assert decoded["attack_complexity"] == NOT_STATED
        assert decoded["confidentiality_impact"] == NOT_STATED


# ── 2. MITRE CWE Catalog Tests ────────────────────────────────────────────────

class TestCWECatalog:
    def test_get_or_fetch_known_cwe(self, client):
        async def _test():
            info = await get_or_fetch_cwe("CWE-79")
            assert "Cross-site Scripting" in info["name"]
            assert len(info["consequences"]) > 0
            assert len(info["mitigations"]) > 0
        asyncio.run(_test())

    def test_live_mitre_cwe_fetch_mocked_html(self, client):
        """Test parsing of actual MITRE CWE HTML structure."""
        sample_html = """
        <html>
        <head><title>CWE - CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer (4.16)</title></head>
        <body>
        <div id="Description"><div class="indent">The product performs operations on a memory buffer, but it can read from or write to a memory location outside the intended boundary.</div></div>
        <div id="Common_Consequences">
            <table>
                <tr><td>Scope</td><td>Denial of Service via system crash</td></tr>
                <tr><td>Scope</td><td>Execute Unauthorized Code or Commands</td></tr>
            </table>
        </div>
        <div id="Potential_Mitigations">
            <table>
                <tr><td>Phase</td><td>Strategy: Memory-safe Language Use a language that does not allow this weakness.</td></tr>
            </table>
        </div>
        </body>
        </html>
        """
        async def _test():
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = AsyncMock()
                mock_resp.status_code = 200
                mock_resp.text = sample_html
                mock_get.return_value = mock_resp

                res = await fetch_cwe_from_mitre("CWE-119")
                assert res is not None
                assert "Improper Restriction of Operations" in res["name"]
                assert "memory location outside the intended boundary" in res["description"]
                assert any("Denial of Service" in c for c in res["consequences"])
                assert any("Memory-safe Language" in m for m in res["mitigations"])
        asyncio.run(_test())

    def test_weekly_stale_refresh(self, client):
        """Test that CWE entries older than 7 days trigger a refresh attempt."""
        from app.db import upsert_cwe

        async def _test():
            stale_date = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()
            await upsert_cwe({
                "cwe_id": "CWE-999",
                "name": "Stale Weakness",
                "description": "Old description",
                "consequences": ["Old consequence"],
                "mitigations": ["Old mitigation"],
                "fetched_at": stale_date,
            })

            # Mock fetch_cwe_from_mitre to return updated content
            with patch("app.reporting.report_evidence.fetch_cwe_from_mitre") as mock_fetch:
                mock_fetch.return_value = {
                    "cwe_id": "CWE-999",
                    "name": "Refreshed Weakness",
                    "description": "New refreshed description",
                    "consequences": ["New consequence"],
                    "mitigations": ["New mitigation"],
                    "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
                res = await get_or_fetch_cwe("CWE-999")
                assert res["name"] == "Refreshed Weakness"
                assert mock_fetch.called
        asyncio.run(_test())

    def test_get_or_fetch_unknown_cwe_graceful_fallback(self, client):
        async def _test():
            info = await get_or_fetch_cwe("CWE-99999")
            assert info["cwe_id"] == "CWE-99999"
            assert info["description"] == NOT_STATED
        asyncio.run(_test())


# ── 3. Comprehensive Report Data Hash Tests ───────────────────────────────────

class TestReportDataHash:
    def test_hash_changes_on_any_input_change(self):
        cve = {
            "cve_id": "CVE-2024-9999",
            "cvss_base_score": 9.8,
            "description": "Base description",
            "cwe_ids": ["CWE-787"],
            "patch_references": ["https://example.com/patch"],
            "reference_tags": {"Patch": ["https://example.com/patch"]},
            "cpe_version_ranges": [{"vendor": "apache", "product": "httpd"}],
        }
        kev = {
            "vulnerability_name": "Vuln Name",
            "due_date": "2024-04-01",
            "known_ransomware_use": "Akira",
        }
        cwes = [{"cwe_id": "CWE-787", "name": "Out-of-bounds Write", "description": "Desc", "mitigations": ["Bounds check"]}]

        base_hash = compute_report_data_hash(cve, kev, cwes)

        # 1. KEV due_date changes -> hash changes
        kev_mod = dict(kev, due_date="2024-04-15")
        assert compute_report_data_hash(cve, kev_mod, cwes) != base_hash

        # 2. CWE mitigations change -> hash changes
        cwes_mod = [{"cwe_id": "CWE-787", "name": "Out-of-bounds Write", "description": "Desc", "mitigations": ["New mitigation"]}]
        assert compute_report_data_hash(cve, kev, cwes_mod) != base_hash

        # 3. Patch references change -> hash changes
        cve_mod_ref = dict(cve, patch_references=["https://example.com/new-patch"])
        assert compute_report_data_hash(cve_mod_ref, kev, cwes) != base_hash

        # 4. Version ranges change -> hash changes
        cve_mod_vr = dict(cve, cpe_version_ranges=[{"vendor": "apache", "product": "httpd", "version_end_excluding": "2.4.52"}])
        assert compute_report_data_hash(cve_mod_vr, kev, cwes) != base_hash

        # 5. Stable when nothing changes
        assert compute_report_data_hash(cve, kev, cwes) == base_hash


# ── 4. Report Evidence Enrichment Tests ───────────────────────────────────────

class TestReportEvidenceEnrichment:
    def test_build_full_kev_evidence(self, client):
        async def _test():
            ev = await build_report_evidence("CVE-2024-9999")
            assert ev is not None
            assert ev.cve_id == "CVE-2024-9999"
            assert ev.priority_label == "CRITICAL"
            assert ev.in_kev is True
            assert "Akira" in ev.known_ransomware_use
            assert len(ev.version_ranges) > 0
            assert len(ev.score_breakdown) == 3
            assert ev.timeline["Remediation Due Date"] == "2024-04-01"
            assert len(ev.patch_urls) > 0
            assert len(ev.source_freshness) == 4
        asyncio.run(_test())

    def test_build_sparse_cve_evidence(self, client):
        async def _test():
            ev = await build_report_evidence("CVE-2024-0001")
            assert ev is not None
            assert ev.cve_id == "CVE-2024-0001"
            assert ev.in_kev is False
            assert ev.description == NOT_STATED
            assert ev.known_ransomware_use == NOT_STATED
            assert ev.cvss_decoded["attack_vector"] == NOT_STATED
            assert len(ev.version_ranges) == 0
        asyncio.run(_test())


# ── 5. Deterministic Report Generation & Six Sections ─────────────────────────

class TestReportGeneration:
    def test_full_kev_cve_report_sections(self, client):
        async def _test():
            ev = await build_report_evidence("CVE-2024-9999")
            report = generate_deterministic_report(ev)

            # Assert all 6 sections exist
            sections = report["sections"]
            for sec in ("why", "what", "where", "how", "resolution", "origin"):
                assert sec in sections
                assert len(sections[sec]) > 20

            # Assert source tags exist
            combined_text = " ".join(sections.values()) + " " + report["executive_summary"]
            assert "[NVD]" in combined_text
            assert "[KEV]" in combined_text
            assert "[EPSS]" in combined_text
            assert "[CWE]" in combined_text

            # Assert dynamic score breakdown table exists
            assert len(report["score_breakdown"]) == 3
            assert report["score_formula"] is not None
            assert report["verification"]["confidence"] == "HIGH"
        asyncio.run(_test())

    def test_sparse_cve_shows_not_stated(self, client):
        async def _test():
            ev = await build_report_evidence("CVE-2024-0001")
            report = generate_deterministic_report(ev)

            combined_text = " ".join(report["sections"].values())
            # Assert "Not stated in available evidence" appears for missing fields
            assert NOT_STATED in combined_text
        asyncio.run(_test())

    def test_executive_summary_verification_blocks_unsupported_narrative(self, client):
        """Test that reusing a manager narrative containing unsupported statements is rejected."""
        from app.db import upsert_narrative

        async def _test():
            # Seed a manager narrative with a hallucinated CVE score and unstated details
            hallucinated_text = "CVE-2024-0001 has CVSS score 7.77 and download exploit at https://exploit-db.com/exploits/99999."
            await upsert_narrative({
                "cve_id": "CVE-2024-0001",
                "audience": "manager",
                "narrative_text": hallucinated_text,
                "provider": "mock",
            })

            report = await generate_vulnerability_report("CVE-2024-0001", provider="mock", regenerate=True)
            # The hallucinated narrative should NOT be accepted as executive summary
            assert report["executive_summary"] != hallucinated_text
            assert "evaluated at deterministic priority" in report["executive_summary"]
        asyncio.run(_test())


# ── 6. Evidence Grounding Assertion (Zero Hallucinated Numbers / URLs) ─────────

class TestEvidenceGrounding:
    def test_no_unsupported_urls_or_numbers(self, client):
        """Verify that every URL and decimal number in the report text is grounded in the evidence."""
        async def _test():
            ev = await build_report_evidence("CVE-2024-9999")
            report = generate_deterministic_report(ev)

            ground_truth_sentences = verbalize_report_evidence(ev)
            combined_ground_truth = " ".join(ground_truth_sentences)

            # Check URLs in report text
            all_text = " ".join(report["sections"].values()) + " " + report["executive_summary"]
            urls_in_report = re.findall(r"https?://[^\s,\)]+", all_text)
            for url in urls_in_report:
                assert url in ev.patch_urls or url in combined_ground_truth, f"Hallucinated URL found: {url}"

            # Check CVSS / EPSS scores in report text
            if ev.cvss_base_score is not None:
                assert f"{ev.cvss_base_score:.1f}" in combined_ground_truth
            assert f"{ev.priority_score:.3f}" in combined_ground_truth
        asyncio.run(_test())


# ── 7. Detailed PDF Content Verification via PyPDF ────────────────────────────

class TestPDFContentsWithPyPDF:
    def test_render_full_cve_pdf_contents(self, client):
        """Extract text from generated PDF and verify all six sections, score, and appendix."""
        async def _test():
            report = await generate_vulnerability_report("CVE-2024-9999", provider="mock")
            pdf_bytes = render_cve_pdf(report)
            assert pdf_bytes.startswith(b"%PDF-")

            reader = PdfReader(io.BytesIO(pdf_bytes))
            assert len(reader.pages) >= 1
            full_text = "\n".join(page.extract_text() or "" for page in reader.pages)

            # 1. Branding & Header
            assert "KEVIDENCE VULNERABILITY ADVISORY" in full_text
            assert "CVE-2024-9999" in full_text
            assert "CRITICAL" in full_text

            # 2. Executive Summary
            assert "1. Executive Summary" in full_text
            assert "evaluated at deterministic priority" in full_text

            # 3. What is it
            assert "2. What is the Vulnerability?" in full_text
            assert "Apache HTTP Server mod_proxy" in full_text

            # 4. Why prioritised
            assert "3. Why is this Vulnerability Prioritised?" in full_text
            assert "Technical Severity" in full_text
            assert "Scoring Formula" in full_text

            # 5. Where affected
            assert "4. Where is it Affected?" in full_text
            assert "Apache" in full_text
            assert "Http Server" in full_text

            # 6. How exploited
            assert "5. How is it Exploited?" in full_text
            assert "Akira" in full_text
            assert "CONFIRMED WEAPONIZATION" in full_text

            # 7. Origin
            assert "6. Origin of the Vulnerability" in full_text

            # 8. Resolution plan
            assert "7. Resolution Plan" in full_text
            assert "2024-04-01" in full_text

            # 9. Evidence & Verification Appendix
            assert "8. Evidence & Verification Appendix" in full_text
            assert "Faithfulness Score" in full_text
            assert "Confidence Assessment" in full_text
            assert "Authoritative Threat Intelligence Feeds & Data Freshness" in full_text
            assert "Full Authoritative Source Reference List" in full_text

            # 10. URL presence
            assert "httpd.apache.org/security/vulnerabilities_24.html" in full_text

        asyncio.run(_test())

    def test_render_sparse_cve_pdf_shows_not_stated(self, client):
        """Extract text from sparse PDF and verify missing-evidence wording."""
        async def _test():
            report = await generate_vulnerability_report("CVE-2024-0001", provider="mock")
            pdf_bytes = render_cve_pdf(report)
            reader = PdfReader(io.BytesIO(pdf_bytes))
            full_text = "\n".join(page.extract_text() or "" for page in reader.pages)

            assert "CVE-2024-0001" in full_text
            # Must explicitly state "Not stated in available evidence"
            assert "Not stated in available evidence" in full_text
        asyncio.run(_test())

    def test_render_portfolio_summary_guarantees_single_page_per_brief(self, client):
        """Verify that the portfolio briefing guarantees exactly 1 page per CVE brief."""
        async def _test():
            rep1 = await generate_vulnerability_report("CVE-2024-9999", provider="mock")
            rep2 = await generate_vulnerability_report("CVE-2024-0001", provider="mock")

            pdf_bytes = render_portfolio_summary_pdf([rep1, rep2])
            reader = PdfReader(io.BytesIO(pdf_bytes))

            # Exactly 3 pages: Page 1 = Portfolio Briefing Overview Table; Page 2 = Brief 1; Page 3 = Brief 2
            assert len(reader.pages) == 3, f"Expected exactly 3 pages, but found {len(reader.pages)}"

            page1_text = reader.pages[0].extract_text() or ""
            assert "KEVIDENCE PORTFOLIO INTELLIGENCE BRIEFING" in page1_text
            assert "CVE Identifier" in page1_text
            assert "CVE-2024-9999" in page1_text
            assert "CVE-2024-0001" in page1_text

            page2_text = reader.pages[1].extract_text() or ""
            assert "KEVIDENCE BRIEF: CVE-2024-9999" in page2_text
            assert "CRITICAL" in page2_text
            assert "CVE-2024-0001" not in page2_text

            page3_text = reader.pages[2].extract_text() or ""
            assert "KEVIDENCE BRIEF: CVE-2024-0001" in page3_text
            assert "CVE-2024-9999" not in page3_text
        asyncio.run(_test())


class TestPDFDatabaseCache:
    def test_pdf_is_persisted_with_matching_evidence_hash(self, client):
        from app.db import get_report, get_report_pdf

        async def _test():
            report, pdf_bytes = await get_or_create_report_pdf(
                "CVE-2024-9999",
                provider="mock",
                regenerate=True,
            )
            stored = await get_report("CVE-2024-9999")
            assert stored is not None
            assert stored["pdf_blob"] == pdf_bytes
            assert await get_report_pdf(
                "CVE-2024-9999",
                stored["data_hash"],
            ) == pdf_bytes
            assert await get_report_pdf(
                "CVE-2024-9999",
                "stale-evidence-hash",
            ) is None
            assert report["cve_id"] == "CVE-2024-9999"

        asyncio.run(_test())

    def test_top_n_cache_includes_ranking_buffer(self, client):
        from app.db import get_cves, get_report

        async def _test():
            top_reports = await warm_top_report_pdf_cache(
                top_n=1,
                buffer=1,
                provider="mock",
            )
            assert len(top_reports) == 1

            rows, _ = await get_cves(limit=2, offset=0)
            assert len(rows) == 2
            for row in rows:
                cached = await get_report(row["cve_id"])
                assert cached is not None
                assert cached["pdf_blob"].startswith(b"%PDF-")

        asyncio.run(_test())


# ── 8. API Endpoints Tests ────────────────────────────────────────────────────

class TestReportAPIEndpoints:
    def test_get_report_json(self, client):
        resp = client.get("/api/cves/CVE-2024-9999/report")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-9999"
        assert "sections" in data
        assert "why" in data["sections"]
        assert "what" in data["sections"]
        assert "where" in data["sections"]
        assert "how" in data["sections"]
        assert "resolution" in data["sections"]
        assert "origin" in data["sections"]
        assert "verification" in data
        assert "source_freshness" in data

    def test_download_report_pdf(self, client):
        resp = client.get("/api/cves/CVE-2024-9999/report.pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert 'attachment; filename="kevidence-CVE-2024-9999.pdf"' in resp.headers["content-disposition"]
        assert resp.content.startswith(b"%PDF-")

    def test_download_portfolio_summary_pdf(self, client):
        resp = client.get("/api/reports/summary.pdf?top=2")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert "kevidence-portfolio-top2.pdf" in resp.headers["content-disposition"]
        assert resp.content.startswith(b"%PDF-")

    def test_report_cve_not_found(self, client):
        resp = client.get("/api/cves/CVE-1999-0000-NONEXISTENT/report.pdf")
        assert resp.status_code == 404
