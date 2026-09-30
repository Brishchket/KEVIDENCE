"""
ingest.py — Ingestion API endpoints.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["ingest"])

# Simple in-memory status tracking
_ingest_status = {
    "status": "idle",
    "run_id": None,
    "cves_fetched": 0,
    "inserted": 0,
    "updated": 0,
    "parse_failures": 0,
    "parse_rate": 0.0,
}


class IngestRequest(BaseModel):
    start_date: str | None = None
    end_date: str | None = None
    target: int = 600
    days: int = 30


@router.post("/ingest")
async def trigger_ingest(body: IngestRequest, background_tasks: BackgroundTasks):
    global _ingest_status
    if _ingest_status["status"] == "running":
        raise HTTPException(status_code=409, detail="An ingestion is already in progress")

    from app.ingestion.pipeline import run_pipeline

    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=body.days)
    if body.start_date:
        start_dt = datetime.fromisoformat(body.start_date).replace(tzinfo=timezone.utc)
    if body.end_date:
        end_dt = datetime.fromisoformat(body.end_date).replace(tzinfo=timezone.utc)

    async def _run():
        global _ingest_status
        _ingest_status = {"status": "running", "run_id": None, "cves_fetched": 0,
                          "inserted": 0, "updated": 0, "parse_failures": 0, "parse_rate": 0.0}
        try:
            result = await run_pipeline(start_dt, end_dt, target=body.target)
            _ingest_status = {"status": "complete", **result}
        except Exception as exc:
            logger.error("Ingestion failed: %s", exc)
            _ingest_status = {"status": "error", "error": str(exc),
                              "run_id": None, "cves_fetched": 0, "inserted": 0,
                              "updated": 0, "parse_failures": 0, "parse_rate": 0.0}

    background_tasks.add_task(_run)
    _ingest_status["status"] = "running"
    return {"status": "accepted", "target": body.target}


@router.get("/ingest/status")
async def ingest_status():
    return _ingest_status
