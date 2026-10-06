"""
test_realtime.py — Tests for the realtime supervisor, event hub, SSE endpoints,
sync_state DB helpers, and the /api/sync/status and /api/events endpoints.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import importlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """FastAPI TestClient with a temp DB and realtime supervisor DISABLED."""
    tmp = tmp_path_factory.mktemp("testdb_rt")
    db_path = str(tmp / "test_rt.db")
    os.environ["PHANTOMPATCH_DB"] = db_path

    import app.config
    importlib.reload(app.config)
    app.config.DB_PATH = db_path

    import app.db
    importlib.reload(app.db)
    app.db.DB_PATH = db_path

    # Patch out the realtime supervisor so tests don't spin up live network loops
    with patch("app.ingestion.realtime.start_supervisor", new_callable=AsyncMock), \
         patch("app.ingestion.realtime.stop_supervisor", new_callable=AsyncMock):
        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app

        with TestClient(fastapi_app) as c:
            # Seed some data
            from app.scoring.scorer import prioritize
            demo_cves = [
                {
                    "cve_id": "CVE-2025-RT-001",
                    "description": "Realtime test CVE critical",
                    "cvss_base_score": 9.8, "severity": "CRITICAL",
                    "epss_score": 0.85, "in_kev": True,
                    "cwe_ids": '["CWE-79"]', "vendors": '["VendorA"]',
                    "products": '["ProductA"]', "reference_urls": "[]",
                    "patch_references": "[]", "affected_cpes": "[]",
                },
                {
                    "cve_id": "CVE-2025-RT-002",
                    "description": "Realtime test CVE low",
                    "cvss_base_score": 2.1, "severity": "LOW",
                    "epss_score": 0.01, "in_kev": False,
                    "cwe_ids": "[]", "vendors": "[]", "products": "[]",
                    "reference_urls": "[]", "patch_references": "[]", "affected_cpes": "[]",
                },
            ]
            async def seed():
                from app.db import init_db, upsert_cve
                await init_db()
                for cve in demo_cves:
                    await upsert_cve(prioritize(cve))
            asyncio.run(seed())
            yield c

    if "PHANTOMPATCH_DB" in os.environ:
        del os.environ["PHANTOMPATCH_DB"]


class TestCveJsonPersistence:
    def test_upsert_serializes_json_fields_after_read_modify_write(self, client):
        """Realtime-style updates must accept fields deserialized from SQLite."""
        from app.db import get_cve, upsert_cve
        from app.scoring.scorer import prioritize

        async def _run():
            cve = await get_cve("CVE-2025-RT-001")
            assert cve is not None
            assert cve["cwe_ids"] == ["CWE-79"]

            cve["in_kev"] = True
            await upsert_cve(prioritize(cve))

            updated = await get_cve("CVE-2025-RT-001")
            assert updated is not None
            assert updated["cwe_ids"] == ["CWE-79"]
            assert updated["vendors"] == ["VendorA"]
            assert updated["products"] == ["ProductA"]
            assert isinstance(updated["priority_breakdown"], dict)
            assert isinstance(updated["reasons"], list)

        asyncio.run(_run())


# ── EventHub tests ────────────────────────────────────────────────────────────

class TestEventHub:
    def test_subscribe_and_publish(self):
        """Hub delivers published events to all subscribers."""
        from app.ingestion.hub import EventHub
        hub = EventHub(max_buffer=50)

        async def _run():
            q = await hub.subscribe()
            await hub.publish({"id": 1, "event_type": "CVE_ADDED", "cve_id": "CVE-1"})
            ev = await asyncio.wait_for(q.get(), timeout=1.0)
            assert ev["event_type"] == "CVE_ADDED"
            await hub.unsubscribe(q)

        asyncio.run(_run())

    def test_buffer_catchup(self):
        """Hub.get_since returns buffered events after since_id."""
        from app.ingestion.hub import EventHub
        hub = EventHub(max_buffer=50)

        async def _run():
            await hub.publish({"id": 1, "event_type": "A"})
            await hub.publish({"id": 2, "event_type": "B"})
            await hub.publish({"id": 5, "event_type": "C"})
            result = hub.get_since(1)
            assert len(result) == 2
            types = {e["event_type"] for e in result}
            assert "B" in types and "C" in types

        asyncio.run(_run())

    def test_multiple_subscribers(self):
        """All subscribers receive the same event."""
        from app.ingestion.hub import EventHub
        hub = EventHub(max_buffer=50)

        async def _run():
            q1 = await hub.subscribe()
            q2 = await hub.subscribe()
            await hub.publish({"id": 10, "event_type": "TEST"})
            ev1 = await asyncio.wait_for(q1.get(), timeout=1.0)
            ev2 = await asyncio.wait_for(q2.get(), timeout=1.0)
            assert ev1["id"] == ev2["id"] == 10
            await hub.unsubscribe(q1)
            await hub.unsubscribe(q2)

        asyncio.run(_run())

    def test_buffer_maxlen(self):
        """Buffer does not exceed max_buffer."""
        from app.ingestion.hub import EventHub
        hub = EventHub(max_buffer=3)

        async def _run():
            for i in range(10):
                await hub.publish({"id": i, "event_type": "X"})
            # Only last 3 should be in buffer
            result = hub.get_since(0)
            assert len(result) == 3
            assert result[-1]["id"] == 9

        asyncio.run(_run())


# ── Sync-state DB tests ───────────────────────────────────────────────────────

class TestSyncStateDB:
    def test_upsert_and_get(self, client):
        """Can write and read back sync_state."""
        async def _run():
            import app.db as db
            importlib.reload(db)
            db.DB_PATH = os.environ["PHANTOMPATCH_DB"]
            await db.upsert_sync_state(
                "nvd",
                last_success_at="2026-10-01T00:00:00+00:00",
                last_cursor="2026-10-01T00:00:00+00:00",
                consecutive_failures=0,
            )
            state = await db.get_sync_state("nvd")
            assert state is not None
            assert state["source"] == "nvd"
            assert state["last_success_at"] == "2026-10-01T00:00:00+00:00"
            assert state["consecutive_failures"] == 0

        asyncio.run(_run())

    def test_upsert_increments_failures(self, client):
        """Updating consecutive_failures only changes that field."""
        async def _run():
            import app.db as db
            db.DB_PATH = os.environ["PHANTOMPATCH_DB"]
            await db.upsert_sync_state("epss", consecutive_failures=3,
                                       last_error="timeout")
            state = await db.get_sync_state("epss")
            assert state["consecutive_failures"] == 3
            assert state["last_error"] == "timeout"

        asyncio.run(_run())

    def test_get_all_sync_states(self, client):
        """get_all_sync_states returns all sources."""
        async def _run():
            import app.db as db
            db.DB_PATH = os.environ["PHANTOMPATCH_DB"]
            await db.upsert_sync_state("kev", last_success_at="2026-10-01T12:00:00+00:00")
            states = await db.get_all_sync_states()
            sources = {s["source"] for s in states}
            assert "kev" in sources

        asyncio.run(_run())


# ── /api/sync/status endpoint ─────────────────────────────────────────────────

class TestSyncStatusEndpoint:
    def test_sync_status_shape(self, client):
        resp = client.get("/api/sync/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "sources" in data
        assert "checked_at" in data
        # All three sources should be present
        for src in ("nvd", "kev", "epss"):
            assert src in data["sources"]
            entry = data["sources"][src]
            assert "health" in entry
            assert entry["health"] in ("live", "degraded", "down")
            assert "consecutive_failures" in entry
            assert "lag_seconds" in entry

    def test_sync_status_health_live_after_write(self, client):
        """After writing a fresh last_success_at, health should be live."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()

        async def _seed():
            import app.db as db
            db.DB_PATH = os.environ["PHANTOMPATCH_DB"]
            await db.upsert_sync_state("nvd", last_success_at=now,
                                       consecutive_failures=0, last_error=None)
        asyncio.run(_seed())

        resp = client.get("/api/sync/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["sources"]["nvd"]["health"] == "live"
        assert data["sources"]["nvd"]["lag_seconds"] is not None
        assert data["sources"]["nvd"]["lag_seconds"] < 10


# ── /api/events endpoint ──────────────────────────────────────────────────────

class TestEventsEndpoint:
    def test_get_events_empty(self, client):
        resp = client.get("/api/events?since_id=999999")
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_get_events_with_data(self, client):
        # Write an event first
        async def _write():
            import app.db as db
            db.DB_PATH = os.environ["PHANTOMPATCH_DB"]
            event_id = await db.log_event("CVE_ADDED", "CVE-2025-RT-001", "Test event")
            return event_id
        event_id = asyncio.run(_write())

        resp = client.get(f"/api/events?since_id={event_id - 1}&limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        cve_ids = [e["cve_id"] for e in data["events"]]
        assert "CVE-2025-RT-001" in cve_ids

    def test_get_events_limit(self, client):
        resp = client.get("/api/events?since_id=0&limit=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) <= 2


# ── /api/stream SSE endpoint ──────────────────────────────────────────────────

class TestSSEEndpoint:
    def test_format_event(self):
        from app.routers.stream import _format_event
        ev = {"id": 42, "event_type": "CVE_ADDED", "cve_id": "CVE-2025-RT-001", "detail": "Test"}
        formatted = _format_event(ev)
        assert "id: 42" in formatted
        assert "event: CVE_ADDED" in formatted
        assert "CVE-2025-RT-001" in formatted

    @pytest.mark.asyncio
    async def test_sse_generator_initial_ping_and_exit(self):
        """SSE generator yields connected ping immediately and exits cleanly on disconnect."""
        from unittest.mock import AsyncMock, MagicMock
        from app.routers.stream import _sse_generator

        req = MagicMock()
        # Returns False on first check, then True (client disconnected)
        req.is_disconnected = AsyncMock(side_effect=[False, True])

        gen = _sse_generator(req, since_id=0)
        first_chunk = await gen.__anext__()
        assert ": connected" in first_chunk
        await gen.aclose()


# ── /api/stats no hardcoded dates ────────────────────────────────────────────

class TestStatsNoHardcodes:
    def test_stats_last_updated_no_hardcoded_2026(self, client):
        """Stats endpoint should not return hardcoded 2026-09-29 dates."""
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        last_updated = data.get("last_updated", {})
        for key, val in last_updated.items():
            if val is not None:
                # Should not be the old hardcoded fallback strings
                assert val != "2026-09-29T15:38:16+00:00", f"{key} has hardcoded date"
                assert val != "2026-09-29T15:38:13+00:00", f"{key} has hardcoded date"
                assert val != "2026-09-29", f"{key} has hardcoded date"


# ── Content hash helper ───────────────────────────────────────────────────────

class TestContentHash:
    def test_same_content_same_hash(self):
        from app.ingestion.realtime import _content_hash
        a = {"cvss_base_score": 9.8, "epss_score": 0.5, "in_kev": True,
             "cvss_vector": "AV:N", "severity": "CRITICAL", "attack_vector": "NETWORK",
             "epss_percentile": 0.98, "last_modified_date": "2025-01-01", "description": "X"}
        b = dict(a)
        assert _content_hash(a) == _content_hash(b)

    def test_different_content_different_hash(self):
        from app.ingestion.realtime import _content_hash
        a = {"cvss_base_score": 9.8, "epss_score": 0.5, "in_kev": True,
             "cvss_vector": "AV:N", "severity": "CRITICAL", "attack_vector": "NETWORK",
             "epss_percentile": 0.98, "last_modified_date": "2025-01-01", "description": "X"}
        b = dict(a)
        b["cvss_base_score"] = 7.0
        assert _content_hash(a) != _content_hash(b)
