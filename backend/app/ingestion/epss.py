"""
epss.py — Batch-fetch EPSS scores and percentiles from FIRST.org API.
Endpoint: https://api.first.org/data/v1/epss?cve=CVE-XXXX,...
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import EPSS_BASE_URL, EPSS_BATCH_SIZE

logger = logging.getLogger(__name__)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=30))
async def _fetch_batch(
    client: httpx.AsyncClient, batch: list[str]
) -> list[dict[str, Any]]:
    params = {"cve": ",".join(batch)}
    resp = await client.get(EPSS_BASE_URL, params=params, timeout=60)
    resp.raise_for_status()
    data: dict[str, Any] = resp.json()
    return data.get("data", [])


async def fetch_epss_scores(
    cve_ids: list[str],
) -> dict[str, dict[str, float]]:
    """
    Return a dict mapping CVE-ID -> {probability, percentile}.
    Missing CVEs are not included in the result.
    """
    if not cve_ids:
        return {}

    scores: dict[str, dict[str, float]] = {}

    async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
        total_batches = -(-len(cve_ids) // EPSS_BATCH_SIZE)
        for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
            batch = cve_ids[i : i + EPSS_BATCH_SIZE]
            batch_num = i // EPSS_BATCH_SIZE + 1
            logger.info("EPSS fetch batch %d/%d (%d CVEs)", batch_num, total_batches, len(batch))

            try:
                items = await _fetch_batch(client, batch)
                for item in items:
                    cve_id = item.get("cve", "")
                    if cve_id:
                        scores[cve_id] = {
                            "probability": float(item.get("epss", 0.0)),
                            "percentile": float(item.get("percentile", 0.0)),
                        }
            except Exception as exc:
                logger.error("EPSS fetch error for batch %d: %s", batch_num, exc)

    logger.info("EPSS: retrieved scores for %d / %d CVEs", len(scores), len(cve_ids))
    return scores
