"""
main.py — FastAPI application for PhantomPatch Phase 1.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import aiosqlite
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pipeline import run_pipeline
from storage import DB_PATH, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="PhantomPatch API",
    description="Evidence-grounded vulnerability risk pipeline — Phase 1",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helper ──────────────────────────────────────────────────────────────────

async def _query(sql: str, params: tuple = ()) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(sql, params)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def _scalar(sql: str, params: tuple = (), default: Any = 0) -> Any:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(sql, params)
        row = await cur.fetchone()
        return row[0] if row and row[0] is not None else default


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/api/summary")
async def get_summary(days: int = Query(7, ge=1, le=90)):
    total = await _scalar("SELECT COUNT(*) FROM cves")
    critical = await _scalar("SELECT COUNT(*) FROM cves WHERE priority_label='CRITICAL'")
    high = await _scalar("SELECT COUNT(*) FROM cves WHERE priority_label='HIGH'")
    medium = await _scalar("SELECT COUNT(*) FROM cves WHERE priority_label='MEDIUM'")
    low = await _scalar("SELECT COUNT(*) FROM cves WHERE priority_label='LOW'")
    below_medium = await _scalar(
        "SELECT COUNT(*) FROM cves WHERE priority_label IN ('LOW','MEDIUM')"
    )
    pct_below_medium = round((below_medium / total * 100) if total else 0, 1)

    # Ingestion trend: CVEs ingested per day for last N days
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = await _query(
        """
        SELECT date(ingested_at) as day, COUNT(*) as count
        FROM cves
        WHERE ingested_at >= ?
        GROUP BY day
        ORDER BY day ASC
        """,
        (cutoff,),
    )

    # Last run info
    last_run = await _query(
        "SELECT finished_at FROM pipeline_runs WHERE status='COMPLETE' ORDER BY id DESC LIMIT 1"
    )
    last_run_ts = last_run[0]["finished_at"] if last_run else None

    last_cve = await _query(
        "SELECT cve_id, ingested_at FROM cves ORDER BY ingested_at DESC LIMIT 1"
    )
    last_cve_ts = last_cve[0]["ingested_at"] if last_cve else None
    last_cve_id = last_cve[0]["cve_id"] if last_cve else None

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "pct_below_medium": pct_below_medium,
        "trend": rows,
        "last_ingestion_run": last_run_ts,
        "last_cve_added": last_cve_ts,
        "last_cve_id": last_cve_id,
    }


@app.get("/api/cves")
async def get_cves(
    priority: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    where = ""
    params: tuple = ()
    if priority:
        where = "WHERE priority_label = ?"
        params = (priority.upper(),)

    rows = await _query(
        f"""
        SELECT cve_id, description, cvss_base_score, cvss_vector, severity,
               cwe_ids, published_date, last_modified_date, affected_cpes,
               vendors, reference_urls, epss_score, in_kev,
               priority_score, priority_label, reasons, ingested_at
        FROM cves {where}
        ORDER BY priority_score DESC, ingested_at DESC
        LIMIT ? OFFSET ?
        """,
        params + (limit, offset),
    )
    total = await _scalar(
        f"SELECT COUNT(*) FROM cves {where}", params
    )

    # Deserialise JSON fields
    for r in rows:
        for field in ("cwe_ids", "affected_cpes", "vendors", "reference_urls", "reasons"):
            try:
                r[field] = json.loads(r[field] or "[]")
            except Exception:
                r[field] = []

    return {"total": total, "offset": offset, "limit": limit, "items": rows}


@app.get("/api/sources")
async def get_sources():
    total_nvd = await _scalar("SELECT COUNT(*) FROM cves")
    epss_enriched = await _scalar("SELECT COUNT(*) FROM cves WHERE epss_score > 0")
    kev_flagged = await _scalar("SELECT COUNT(*) FROM cves WHERE in_kev = 1")
    return {
        "nvd": {"label": "NVD", "count": total_nvd},
        "epss": {"label": "FIRST.org EPSS", "count": epss_enriched},
        "kev": {"label": "CISA KEV", "count": kev_flagged},
    }


@app.get("/api/vendors")
async def get_vendors(limit: int = Query(10, ge=1, le=50)):
    rows = await _query(
        """
        SELECT vendors, priority_label, priority_score
        FROM cves
        WHERE vendors IS NOT NULL AND vendors != '[]'
        """
    )
    vendor_map: dict[str, dict] = {}
    for r in rows:
        try:
            vendors: list[str] = json.loads(r["vendors"] or "[]")
        except Exception:
            continue
        for v in vendors:
            if not v:
                continue
            if v not in vendor_map:
                vendor_map[v] = {"vendor": v, "count": 0, "worst_label": "LOW", "worst_score": 0.0}
            vendor_map[v]["count"] += 1
            score = r.get("priority_score") or 0.0
            if score > vendor_map[v]["worst_score"]:
                vendor_map[v]["worst_score"] = score
                vendor_map[v]["worst_label"] = r["priority_label"]

    sorted_vendors = sorted(vendor_map.values(), key=lambda x: x["count"], reverse=True)
    return {"vendors": sorted_vendors[:limit]}


@app.get("/api/feed")
async def get_feed(limit: int = Query(10, ge=1, le=50)):
    rows = await _query(
        """
        SELECT id, event_type, cve_id, detail, created_at
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    return {"events": rows}


class IngestRequest(BaseModel):
    start_date: str  # ISO date string e.g. "2026-08-15"
    end_date: str    # ISO date string e.g. "2026-08-22"


_active_run: bool = False


@app.post("/api/ingest")
async def trigger_ingest(body: IngestRequest, background_tasks: BackgroundTasks):
    global _active_run
    if _active_run:
        raise HTTPException(status_code=409, detail="A pipeline run is already in progress")

    try:
        start_dt = datetime.fromisoformat(body.start_date).replace(tzinfo=timezone.utc)
        end_dt = datetime.fromisoformat(body.end_date).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    async def _run():
        global _active_run
        _active_run = True
        try:
            await run_pipeline(start_dt, end_dt)
        finally:
            _active_run = False

    background_tasks.add_task(_run)
    return {"status": "accepted", "start_date": body.start_date, "end_date": body.end_date}


@app.get("/api/pipeline-runs")
async def get_pipeline_runs(limit: int = Query(10)):
    rows = await _query(
        "SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT ?", (limit,)
    )
    return {"runs": rows}


@app.get("/health")
async def health():
    return {"status": "ok"}
