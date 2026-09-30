"""
pipeline.py — Orchestrates NVD → EPSS → KEV → parse → prioritize → store.
"""
from __future__ import annotations

import logging
from datetime import datetime

from epss_client import fetch_epss_scores
from kev_client import fetch_kev_ids
from nvd_client import fetch_cves
from parser import parse_cve
from prioritizer import prioritize
from storage import create_run, finish_run, upsert_cve

logger = logging.getLogger(__name__)


async def run_pipeline(start_date: datetime, end_date: datetime) -> dict:
    """
    Full ingestion pipeline for the given date range.
    Returns a summary dict.
    """
    run_id = await create_run(start_date.isoformat(), end_date.isoformat())
    logger.info("Pipeline run #%d started: %s -> %s", run_id, start_date.date(), end_date.date())

    # Step 1: KEV catalog (single download, cheap)
    logger.info("Fetching CISA KEV catalog...")
    kev_ids = await fetch_kev_ids()

    # Step 2: NVD CVEs (streaming)
    logger.info("Fetching NVD CVEs...")
    raw_cves: list[dict] = []
    async for raw in fetch_cves(start_date, end_date):
        raw_cves.append(raw)

    logger.info("Fetched %d raw CVEs from NVD", len(raw_cves))

    if not raw_cves:
        await finish_run(run_id, 0, "COMPLETE")
        return {"run_id": run_id, "cves_fetched": 0, "inserted": 0, "updated": 0}

    # Step 3: EPSS enrichment (batch by IDs collected above)
    cve_ids = [r.get("id", "") for r in raw_cves if r.get("id")]
    logger.info("Fetching EPSS scores for %d CVEs...", len(cve_ids))
    epss_scores = await fetch_epss_scores(cve_ids)

    # Step 4: Parse + prioritize + store
    inserted = 0
    updated = 0
    for raw in raw_cves:
        cve_id = raw.get("id", "")
        epss = epss_scores.get(cve_id, 0.0)
        in_kev = cve_id in kev_ids

        parsed = parse_cve(raw, epss_score=epss, in_kev=in_kev)
        scored = prioritize(parsed)
        is_new = await upsert_cve(scored)
        if is_new:
            inserted += 1
        else:
            updated += 1

    await finish_run(run_id, len(raw_cves), "COMPLETE")
    logger.info("Pipeline run #%d done: %d inserted, %d updated", run_id, inserted, updated)
    return {
        "run_id": run_id,
        "cves_fetched": len(raw_cves),
        "inserted": inserted,
        "updated": updated,
    }
