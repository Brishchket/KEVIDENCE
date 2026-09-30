"""
test_api.py — API integration tests using FastAPI TestClient.
"""
import json
import asyncio
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """Create a test client with a temp database."""
    import os
    tmp = tmp_path_factory.mktemp("testdb")
    db_path = str(tmp / "test_api.db")

    # Patch DB_PATH before importing app
    os.environ["PHANTOMPATCH_DB"] = db_path

    # Need to reload modules to pick up new DB_PATH
    import importlib
    import app.config
    importlib.reload(app.config)
    app.config.DB_PATH = db_path

    import app.db
    importlib.reload(app.db)
    app.db.DB_PATH = db_path

    from app.main import app as fastapi_app
    with TestClient(fastapi_app) as c:
        # Seed some demo data
        from app.scoring.scorer import prioritize
        demo_cves = [
            {"cve_id": "CVE-2024-API-001", "description": "Test critical vuln",
             "cvss_base_score": 9.8, "severity": "CRITICAL", "epss_score": 0.9, "in_kev": True,
             "cwe_ids": '["CWE-787"]', "vendors": '["TestVendor"]', "products": '["TestProd"]',
             "reference_urls": "[]", "patch_references": "[]", "affected_cpes": "[]"},
            {"cve_id": "CVE-2024-API-002", "description": "Test low vuln",
             "cvss_base_score": 2.0, "severity": "LOW", "epss_score": 0.01, "in_kev": False,
             "cwe_ids": "[]", "vendors": "[]", "products": "[]",
             "reference_urls": "[]", "patch_references": "[]", "affected_cpes": "[]"},
        ]
        async def seed():
            from app.db import init_db, upsert_cve
            await init_db()
            for cve in demo_cves:
                scored = prioritize(cve)
                await upsert_cve(scored)
        asyncio.run(seed())
        yield c

    # Cleanup
    if "PHANTOMPATCH_DB" in os.environ:
        del os.environ["PHANTOMPATCH_DB"]


class TestHealthEndpoint:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestCVEEndpoints:
    def test_list_cves(self, client):
        resp = client.get("/api/cves")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert data["total"] >= 2

    def test_list_cves_with_priority_filter(self, client):
        resp = client.get("/api/cves?priority=CRITICAL")
        assert resp.status_code == 200
        data = resp.json()
        for item in data["items"]:
            assert item["priority_label"] == "CRITICAL"

    def test_list_cves_pagination(self, client):
        resp = client.get("/api/cves?limit=1&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) <= 1

    def test_get_cve_detail(self, client):
        resp = client.get("/api/cves/CVE-2024-API-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-API-001"
        assert "cvss" in data
        assert "priority" in data

    def test_get_cve_not_found(self, client):
        resp = client.get("/api/cves/CVE-NONEXISTENT")
        assert resp.status_code == 404


class TestStatsEndpoint:
    def test_stats(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_cves" in data
        assert "critical_count" in data
        assert "kev_count" in data
        assert data["total_cves"] >= 2


class TestNarrativeEndpoints:
    def test_generate_narrative(self, client):
        resp = client.post("/api/cves/CVE-2024-API-001/narratives?audience=manager")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-API-001"
        assert data["audience"] == "manager"
        assert data["narrative_text"]
        assert data["confidence"] in ("HIGH", "MEDIUM", "LOW")

    def test_get_narratives(self, client):
        # First generate one
        client.post("/api/cves/CVE-2024-API-001/narratives?audience=manager")
        resp = client.get("/api/cves/CVE-2024-API-001/narratives")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["narratives"]) >= 1

    def test_narrative_for_nonexistent_cve(self, client):
        resp = client.post("/api/cves/CVE-NONEXISTENT/narratives?audience=manager")
        assert resp.status_code == 404


class TestEvaluationEndpoint:
    def test_evaluation_summary(self, client):
        resp = client.get("/api/evaluation/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "baseline_comparison" in data
